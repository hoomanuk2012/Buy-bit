# app.py  —  FULL VERSION

import os, io, csv, base64, sqlite3
from datetime import datetime, timedelta
from collections import deque
from functools import wraps
from typing import Optional, List, Tuple
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import TemplateNotFound


from flask import (
    Flask, request, redirect, url_for, render_template, session,
    jsonify, flash, abort, Response
)
from flask_wtf.csrf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from functools import wraps
from pathlib import Path
from collections import defaultdict

# ========================= App & Config =========================
APP_NAME = "BUYBIT"
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-change-me")
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Env
DB_PATH = os.getenv("DB_PATH", os.path.join(os.getcwd(), "buybit.db"))
PAYPAL_ENV = os.getenv("PAYPAL_ENV", "sandbox").strip()
USE_PAYPAL_API = os.getenv("USE_PAYPAL_API", "1").strip() in ("1", "true", "yes")
PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "")
PAYPAL_SECRET = os.getenv("PAYPAL_SECRET", "")
BASE_CURRENCY = "GBP"
PRICE_GBP = float(os.getenv("PRICE_GBP", "50.0"))  # LIVE price lock
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin").strip()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "StrongAdmin@^)").strip()  # change in prod
SHOW_DEV_TOOLS = os.getenv("SHOW_DEV_TOOLS", "0").strip() in ("1","true","yes")
CSP_FOR_PAY = "default-src 'self'; script-src 'self' https://www.paypal.com https://www.sandbox.paypal.com; style-src 'self' 'unsafe-inline';"
# ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
# SMTP_HOST   = os.getenv("SMTP_HOST")
# SMTP_PORT   = int(os.getenv("SMTP_PORT", 587))
# SMTP_USER   = os.getenv("SMTP_USER")
# SMTP_PASS   = os.getenv("SMTP_PASS")
# SMTP_TLS    = os.getenv("SMTP_TLS", "true").lower() == "true"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

print("=== BUYBIT START ===")
print(f"PAYPAL_ENV: {PAYPAL_ENV} | USE_PAYPAL_API: {USE_PAYPAL_API}")
print(f"CLIENT_ID set?: {bool(PAYPAL_CLIENT_ID)}")
print(f"DB_PATH: {DB_PATH}")
print("="*80)

csrf = CSRFProtect(app)

# ========================= DB =========================
def get_db():
    con = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    con.row_factory = sqlite3.Row
    return con

def _table_has_column(con, table, col) -> bool:
    cur = con.cursor()
    info = cur.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r["name"] == col for r in info)

def _ensure_tables():
    con = get_db(); cur = con.cursor()
    # users
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        email TEXT,
        paypal_email TEXT,
        is_admin INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    # purchases
    cur.execute("""
    CREATE TABLE IF NOT EXISTS purchases(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        buyer TEXT NOT NULL,
        amount REAL NOT NULL,
        source TEXT,            -- 'paypal' or others
        tx_ref TEXT,            -- PayPal order id or local id
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    # referrals (single tree; parent -> child)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS referrals(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parent TEXT NOT NULL,
        child TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_ref_parent_child ON referrals(parent, child)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_ref_child ON referrals(child)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_ref_parent ON referrals(parent)")

    # withdrawals
    cur.execute("""
        CREATE TABLE IF NOT EXISTS withdrawals(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            status TEXT DEFAULT 'pending',  -- pending, approved, rejected
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)

    # earnings (who earns from whose purchase)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS earnings(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT NOT NULL,                 -- who receives money
        source_purchase_id INTEGER NOT NULL,
        level INTEGER NOT NULL,
        percent REAL NOT NULL,
        amount REAL NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    # Columns may have been missing in old DBs; ensure presence
    # (in case of legacy DBs without 'user' or columns)
    if not _table_has_column(con, "earnings", "user"):
        cur.execute("ALTER TABLE earnings ADD COLUMN user TEXT")
    if not _table_has_column(con, "earnings", "source_purchase_id"):
        cur.execute("ALTER TABLE earnings ADD COLUMN source_purchase_id INTEGER")
    if not _table_has_column(con, "earnings", "level"):
        cur.execute("ALTER TABLE earnings ADD COLUMN level INTEGER DEFAULT 0")
    if not _table_has_column(con, "earnings", "percent"):
        cur.execute("ALTER TABLE earnings ADD COLUMN percent REAL DEFAULT 0")
    if not _table_has_column(con, "earnings", "amount"):
        cur.execute("ALTER TABLE earnings ADD COLUMN amount REAL DEFAULT 0")

    con.commit()

    # ensure admin
    row = cur.execute("SELECT username FROM users WHERE username=?", (ADMIN_USERNAME,)).fetchone()
    if not row:
        cur.execute("INSERT INTO users(username,password,email,is_admin) VALUES (?,?,?,1)",
                    (ADMIN_USERNAME, ADMIN_PASSWORD, f"{ADMIN_USERNAME}@gmail.com"))
        con.commit()

    # ensure tree root exists (admin has no parent; children connect to admin via BFS)
    # (No action needed; we ensure the BFS will start from admin when attaching others.)

    con.close()

_ensure_tables()

# ========================= Earnings helpers =========================
def _table_cols(con, table):
    cur = con.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in cur.fetchall()}

def _earnings_recipient_col(con):
    cols = _table_cols(con, "earnings")
    for c in ("user", "recipient", "username"):
        if c in cols: return c
    # اگر هیچ‌کدام نبود، برمی‌گردیم None تا صفحه خالی نشود
    return None

def fetch_earnings_for(username):
    with get_db() as con:
        rec_col = _earnings_recipient_col(con)
        cols = _table_cols(con, "earnings")
        if not rec_col:
            return [], 0.0
        # ستون‌های اختیاری
        opt = [c for c in ("id","purchase_id","level","source","created_at","note") if c in cols]
        sel = ", ".join(["amount"] + opt)
        rows = con.execute(
            f"SELECT {sel} FROM earnings WHERE {rec_col}=? ORDER BY "
            + ("created_at DESC" if "created_at" in cols else "rowid DESC"),
            (username,)
        ).fetchall()
        total = sum(float(r["amount"]) for r in rows)
        return rows, total

# ========================= Auth helpers =========================
def current_user() -> Optional[str]:
    return session.get("username")

def is_logged_in() -> bool:
    return "username" in session

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            # اگر آدرس مقصد لازم داری، next هم پاس می‌دیم
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

# ========================= Graphic Services =========================
# منبع قیمت‌ها/تخفیف‌ها: Graphic price.txt
SERVICES = [
    # Branding
    {"slug": "logo",               "title": "Logo Design",              "base": 180.0, "discount": 30, "group": "Branding"},
    {"slug": "brand-identity",     "title": "Brand Identity Package",   "base": 400.0, "discount": 40, "group": "Branding"},
    {"slug": "business-card",      "title": "Business Card Design",     "base": 60.0,  "discount": 40, "group": "Branding"},

    # Social Media
    {"slug": "social-post",        "title": "Social Media Post",        "base": 35.0,  "discount": 20, "group": "Social Media"},
    {"slug": "social-bundle-10",   "title": "Social Media Bundle (10)", "base": 300.0, "discount": 40, "group": "Social Media"},

    # Print
    {"slug": "flyer-poster",       "title": "Flyer / Poster Design",    "base": 90.0,  "discount": 30, "group": "Print"},
    {"slug": "brochure-bi-fold",   "title": "Brochure Design (Bi-Fold)","base": 150.0, "discount": 35, "group": "Print"},
    {"slug": "presentation",       "title": "Presentation Design",      "base": 120.0, "discount": 30, "group": "Print"},
    {"slug": "certificate",        "title": "Certificate",              "base": 60.0,  "discount": 25, "group": "Print"},
    {"slug": "book-cover",         "title": "Book Cover",               "base": 130.0, "discount": 30, "group": "Print"},
    {"slug": "product-mockup",     "title": "Product Mockup",           "base": 65.0,  "discount": 30, "group": "Print"},

    # Web / Email / Ads
    {"slug": "web-banner",         "title": "Website Banner / Header",  "base": 70.0,  "discount": 25, "group": "Web & Ads"},
    {"slug": "email-newsletter",   "title": "Email Newsletter",         "base": 85.0,  "discount": 25, "group": "Web & Ads"},

    # Other
    {"slug": "packaging",          "title": "Packaging Design",         "base": 220.0, "discount": 30, "group": "Other"},
    {"slug": "infographic",        "title": "Infographic",              "base": 110.0, "discount": 30, "group": "Other"},
    {"slug": "menu",               "title": "Restaurant Menu",          "base": 95.0,  "discount": 35, "group": "Other"},
]

def _group_services():
    groups = {}
    for s in SERVICES:
        s["final"] = round(s["base"] * (100 - s["discount"]) / 100, 2)
        groups.setdefault(s["group"], []).append(s)
    # برای نمایش مرتب:
    return dict(sorted(groups.items(), key=lambda kv: kv[0].lower()))


PORTFOLIO_DIR = Path(app.root_path) / "static" / "portfolio"
def list_samples_for(slug: str):
    d = PORTFOLIO_DIR / slug
    if not d.exists() or not d.is_dir():
        return []
    exts = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
    files = [f.name for f in sorted(d.iterdir()) if f.suffix.lower() in exts]
    return [f"portfolio/{slug}/{name}" for name in files]

GROUP_ORDER = ["Branding", "Other", "Print", "Social Media", "Web & Ads"]

def build_service_groups():
    """groups = { group_name: [items...] }  ordered by GROUP_ORDER"""
    groups = defaultdict(list)
    for s in SERVICES:
        g = s.get("group") or "Other"
        groups[g].append(s)
    # مرتب‌سازی بر اساس ترتیب دلخواه
    ordered = {}
    for g in GROUP_ORDER:
        if g in groups:
            # مرتب‌سازی داخلی بر اساس name
            ordered[g] = sorted(groups[g], key=lambda x: x.get("name","").lower())
    # گروه‌های باقی‌مانده (اگر بود)
    for g in sorted(set(groups.keys()) - set(GROUP_ORDER)):
        ordered[g] = sorted(groups[g], key=lambda x: x.get("name","").lower())
    return ordered
# ========================= Password hashing =========================
try:
    from argon2 import PasswordHasher
    ph = PasswordHasher()
except Exception:
    class _PH:
        def hash(self, p): return p
        def verify(self, h, p):
            if h != p: raise Exception("bad password")
    ph = _PH()

# ========================= Game Logic (single tree, 10 levels) =========================
LEVEL_PERCENTS = [10,9,8,7,6,5,4,3,2,1]  # level 1..10

def _children_of(username: str) -> List[str]:
    with get_db() as con:
        cur = con.cursor()
        rows = cur.execute("SELECT child FROM referrals WHERE parent=? ORDER BY ROWID", (username,)).fetchall()
    return [r["child"] for r in rows]

def _parent_of(username: str) -> Optional[str]:
    with get_db() as con:
        cur = con.cursor()
        r = cur.execute("SELECT parent FROM referrals WHERE child=?", (username,)).fetchone()
    return r["parent"] if r else None

def _attach_to_tree_bfs(new_user: str, start_parent: str = ADMIN_USERNAME):
    if new_user == ADMIN_USERNAME:
        return
    with get_db() as con:
        cur = con.cursor()
        r = cur.execute("SELECT 1 FROM referrals WHERE child=?", (new_user,)).fetchone()
        if r:
            return
        queue = deque([start_parent])
        while queue:
            p = queue.popleft()
            kids = _children_of(p)
            if len(kids) < 2:
                cur.execute(
                    "INSERT OR IGNORE INTO referrals(parent, child) VALUES (?, ?)",
                    (p, new_user)
                )
                con.commit()
                return
            queue.extend(kids)
        # fallback
        cur.execute(
            "INSERT OR IGNORE INTO referrals(parent, child) VALUES (?, ?)",
            (ADMIN_USERNAME, new_user)
        )
        con.commit()

def _ancestors(username: str, max_levels: int = 10) -> List[str]:
    """Get up to 10 ancestors upward (level1 is immediate parent)."""
    result = []
    cur_u = username
    for _ in range(max_levels):
        par = _parent_of(cur_u)
        if not par: break
        result.append(par)
        cur_u = par
    return result  # len <= 10

def distribute_commissions(buyer: str, purchase_id: int, amount: float):
    """
    On each successful £50 purchase: pay ancestors up to 10 levels by LEVEL_PERCENTS.
    """
    ancestors = _ancestors(buyer, 10)
    with get_db() as con:
        cur = con.cursor()
        for idx, u in enumerate(ancestors, start=1):
            if idx > 10: break
            percent = LEVEL_PERCENTS[idx-1]
            earn_amount = round(amount * (percent/100.0), 2)
            if earn_amount <= 0: continue
            cur.execute("""
            INSERT INTO earnings(user, source_purchase_id, level, percent, amount)
            VALUES (?,?,?,?,?)
            """, (u, purchase_id, idx, percent, earn_amount))
        con.commit()

# ========================= App utils =========================
def send_email(to: str, subject: str, body: str):
    app.logger.info("EMAIL -> to=%s | subject=%s\n%s", to, subject, body)

def calc_balance(username: str) -> float:
    with get_db() as con:
        cur = con.cursor()
        row = cur.execute("SELECT COALESCE(SUM(amount),0) AS s FROM earnings WHERE user=?", (username,)).fetchone()
    try:
        return float(row["s"] or 0.0)
    except Exception:
        return 0.0

def total_balance(username: str) -> float:
    with get_db() as con:
        cur = con.cursor()
        row = cur.execute("SELECT COALESCE(SUM(amount),0) AS s FROM earnings WHERE user=?", (username,)).fetchone()
    try:
        # return float(row["s"] or 0.0)
        total_earnings = float(row["s"] or 0.0)
        # Get total approved withdrawals
        withdrawal_row = cur.execute("""
            SELECT COALESCE(SUM(amount), 0) AS total_withdrawn
            FROM withdrawals w
            JOIN users u ON w.user_id = u.id
            WHERE u.username = ? AND w.status = 'approved'
        """, (username,)).fetchone()
        total_withdrawn = float(withdrawal_row["total_withdrawn"] or 0.0)

        # Subtract approved withdrawals
        balance = total_earnings - total_withdrawn
        return balance
    except Exception:
        return 0.0

def get_user_info(username: str) -> dict:
    info = {"username": username, "email": "", "paypal_email": "", "is_admin": False, "created_at": None}
    with get_db() as con:
        cur = con.cursor()
        row = cur.execute("""
            SELECT username, email, paypal_email, is_admin, created_at
              FROM users WHERE username=?
        """, (username,)).fetchone()
    if row:
        info.update(dict(row))
        info["is_admin"] = bool(info.get("is_admin", 0))
    # info["balance"] = calc_balance(username)
    info["balance"] = total_balance(username)
    return info

def get_user_purchases(username: str, limit: int = 50) -> List[dict]:
    with get_db() as con:
        cur = con.cursor()
        rows = cur.execute("""
            SELECT id,buyer,amount,source,tx_ref,created_at
              FROM purchases WHERE buyer=? ORDER BY id DESC LIMIT ?
        """, (username, limit)).fetchall()
    return [dict(r) for r in rows]

def current_price() -> float:
    return float(PRICE_GBP or 50.0)

def is_safe_next(url: Optional[str]) -> bool:
    return bool(url) and url.startswith("/")

# ========================= PayPal REST =========================
import requests

def _paypal_api_base() -> str:
    return "https://api-m.sandbox.paypal.com" if PAYPAL_ENV == "sandbox" else "https://api-m.paypal.com"

def _paypal_get_access_token() -> Optional[str]:
    try:
        auth = base64.b64encode(f"{PAYPAL_CLIENT_ID}:{PAYPAL_SECRET}".encode()).decode()
        r = requests.post(
            _paypal_api_base() + "/v1/oauth2/token",
            headers={"Authorization": f"Basic {auth}"},
            data={"grant_type":"client_credentials"},
            timeout=30
        )
        r.headers["Content-Security-Policy"] = CSP_FOR_PAY
        if r.ok:
            return r.json().get("access_token")
        app.logger.warning("PayPal token error: %s %s", r.status_code, r.text)
    except Exception as e:
        app.logger.warning("PayPal token exception: %s", e, exc_info=True)
    return None

def create_paypal_order_v2(amount: float, currency: str = BASE_CURRENCY) -> Optional[str]:
    at = _paypal_get_access_token()
    if not at:
        print("PayPal token failed — check client ID/secret and sandbox/live environment")
    # if not at: return None
    try:
        r = requests.post(
            _paypal_api_base() + "/v2/checkout/orders",
            headers={"Authorization": f"Bearer {at}", "Content-Type": "application/json"},
            json={
                "intent":"CAPTURE",
                "purchase_units":[{"amount":{"currency_code":currency, "value": f"{amount:.2f}"}}]
            },
            timeout=30
        )
        if r.ok:
            return r.json().get("id")
        app.logger.warning("Create order error: %s %s", r.status_code, r.text)
    except Exception as e:
        app.logger.warning("Create order exception: %s", e, exc_info=True)
    return None

def capture_paypal_order_v2(order_id: str) -> dict:
    at = _paypal_get_access_token()
    if not at: return {"error": "token_error"}
    try:
        r = requests.post(
            _paypal_api_base() + f"/v2/checkout/orders/{order_id}/capture",
            headers={"Authorization": f"Bearer {at}","Content-Type": "application/json"},
            timeout=30
        )
        if r.ok:
            return r.json()
        return {"error":"capture_failed","status":r.status_code,"body":r.text}
    except Exception as e:
        return {"error":"capture_exception","detail":str(e)}

# ========================= Context (bg / back button / price) =========================
@app.context_processor
def inject_bg_defaults():
    return {
        "bg_video_url": os.getenv("BG_VIDEO_URL") or None,
        "bg_image_url": url_for("static", filename="img/bg.jpg"),
        "bg_dim": os.getenv("BG_DIM", ".35"),
        "show_dev_tools": SHOW_DEV_TOOLS,
        "PRICE_GBP": PRICE_GBP,
        "back_to_dashboard_url": url_for("dashboard") if is_logged_in() else url_for("login")
    }

@app.context_processor
def _back_link_ctx():
    return {"back_to_dashboard_url": url_for("dashboard")}

# ========================= Routes: auth =========================
@app.get("/")
def home():
    return redirect(url_for("dashboard") if is_logged_in() else url_for("login"))

@app.get("/login")
def login():
    return render_template("login.html")

@csrf.exempt
@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    if not username or not password:
        flash("Username & password required", "danger")
        return redirect(url_for("login"))
    with get_db() as con:
        cur = con.cursor()
        row = cur.execute("SELECT username, password FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        flash("Invalid credentials", "danger"); return redirect(url_for("login"))
    try:
        ph.verify(row["password"], password)
    except Exception:
        if row["password"] != password:  # fallback for plan-text legacy
            flash("Invalid credentials", "danger"); return redirect(url_for("login"))
    session["username"] = username
    nxt = request.args.get("next")
    return redirect(nxt if is_safe_next(nxt) else url_for("dashboard"))

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.get("/register")
def register():
    return render_template("register.html")

@csrf.exempt
@app.post("/register")
def register_post():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    confirmPass  = (request.form.get("confirm") or "").strip()
    email    = (request.form.get("email") or "").strip().lower()
    referral = (request.form.get("ref_code") or "").strip()  # NEW

    if not username or not password:
        flash("Username & password required", "danger")
        return redirect(url_for("register"))

    if password != confirmPass:
        flash("Passwords do not match", "danger")
        return redirect(url_for("register"))
   
    if not re.fullmatch(r"[A-Za-z0-9!#$^&()\=+]{8,12}", password):
        flash("Password must be 8-12 characters and can only contain letters, numbers, and !#$%^&()=+", "danger")
        return redirect(url_for("register"))
    
    with get_db() as con:
        cur = con.cursor()

        # Check if username already exists
        r = cur.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
        if r:
            flash("Username already exists", "danger")
            return redirect(url_for("register"))
        
        if email:
            r = cur.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone()
            if r:
                flash("Email already registered", "danger")
                return redirect(url_for("register"))
            
        # Insert new user
        cur.execute("INSERT INTO users(username,password,email,is_admin) VALUES (?,?,?,0)",
                    (username, ph.hash(password), email))
        con.commit()

    # Attach to tree
    parent = ADMIN_USERNAME
    if referral:
        with get_db() as con:
            cur = con.cursor()
            r = cur.execute("SELECT username FROM users WHERE username=?", (referral,)).fetchone()
            if r:  # valid referral
                parent = referral
            else:
                flash("Referral not found, attaching under ADMIN", "warning")

    _attach_to_tree_bfs(username, parent)

    flash("Registered successfully. Please login.", "success")
    return redirect(url_for("login"))


# ========================= Password Reset =========================
def _reset_serializer(): return URLSafeTimedSerializer(app.secret_key, salt="pw-reset")
def make_reset_token(username:str)->str: return _reset_serializer().dumps({"u":username})
def verify_reset_token(token:str, max_age:int=3600)->Optional[str]:
    try:
        data=_reset_serializer().loads(token, max_age=max_age)
        return data.get("u")
    except (BadSignature, SignatureExpired):
        return None

@app.get("/forgot-password")
def forgot_password(): return render_template("forgot_password.html")

@csrf.exempt
@app.post("/forgot-password")
def forgot_password_submit():
    email=(request.form.get("email") or "").strip().lower()
    if not email: flash("Email required","danger"); return redirect(url_for("forgot_password"))
    with get_db() as con:
        cur=con.cursor()
        r=cur.execute("SELECT username FROM users WHERE email=?", (email,)).fetchone()
    if not r: flash("Email not found","danger"); return redirect(url_for("forgot_password"))
    token = make_reset_token(r["username"])
    link = url_for("reset_password", token=token, _external=True)
    send_email(email, "Reset your password", f"Click to reset: {link}")
    flash("Reset link sent (if email exists).","success")
    return redirect(url_for("login"))

@app.get("/reset-password/<token>")
def reset_password(token):
    u = verify_reset_token(token)
    if not u: flash("Invalid/expired token","danger"); return redirect(url_for("forgot_password"))
    return render_template("reset_password.html", token=token)

@csrf.exempt
@app.post("/reset-password/<token>")
def reset_password_submit(token):
    u = verify_reset_token(token)
    if not u: flash("Invalid/expired token","danger"); return redirect(url_for("forgot_password"))
    newp=(request.form.get("password") or "").strip()
    if not newp: flash("Password required","danger"); return redirect(url_for("reset_password", token=token))
    with get_db() as con:
        cur=con.cursor()
        cur.execute("UPDATE users SET password=? WHERE username=?", (ph.hash(newp), u))
        con.commit()
    flash("Password updated.","success")
    return redirect(url_for("login"))

# ========================= Dashboard & pages =========================
@app.get("/dashboard")
def dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))
    u = current_user()

    # اطلاعات کاربر برای نمایش
    info = get_user_info(u)  # همان تابع خودت
    bal = float(info.get("balance") or 0)

    # آیا ادمین است؟
    with get_db() as con:
        cur = con.cursor()
        row = cur.execute("SELECT is_admin FROM users WHERE username=?", (u,)).fetchone()
    show_admin = bool(row and row["is_admin"])

    return render_template(
        "dashboard.html",
        username=u,
        bal=bal,
        show_admin=show_admin,
        # مسیرها را دقیق پاس بده تا BuildError نگیری
        url_pay=url_for("go_to_pay"),
        url_services=url_for("services"),
        url_profile=url_for("profile"),                 # ← دقت: profile_page نداریم، profile است
        url_tree=url_for("referral_tree_page"),
        url_profit=url_for("profit_details_page"),
        url_withdraw=url_for("withdraw_page"),
        url_admin=(url_for("admin_home") if show_admin else None),
    )


# ===== Services (table view) =====
@app.get("/services", endpoint="services")
def services():
    if not is_logged_in():
        return redirect(url_for("login"))
    groups = build_service_groups()
    return render_template("services.html", groups=groups)


ALLOWED_IMG_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}

@app.get("/services/<slug>", endpoint="service_samples")
def service_samples(slug):
    if not is_logged_in():
        return redirect(url_for("login"))

    # عنوان سرویس از روی SERVICES
    title = next((s["title"] for s in SERVICES if s.get("slug")==slug), slug.replace("-", " ").title())
    folder = os.path.join(app.static_folder, "portfolio", slug)
    if not os.path.isdir(folder):
        # اگر فولدر نبود، 404
        abort(404)

    exts = (".jpg",".jpeg",".png",".gif",".webp")
    files = [f for f in os.listdir(folder) if f.lower().endswith(exts)]
    files.sort()
    imgs = [ url_for("static", filename=f"portfolio/{slug}/{f}") for f in files ]

    return render_template("service_samples.html", title=title, images=imgs)


@app.get("/profile", endpoint="profile")
def profile_page():
    if not is_logged_in():
        return redirect(url_for("login"))
    u = current_user()
    info = get_user_info(u)

    # تولید کد و لینک رفرال
    ref_code = u
    ref_link = url_for("register", ref=ref_code, _external=True)

    return render_template(
        "profile.html",
        username=info["username"],
        email=info.get("email"),
        paypal_email=info.get("paypal_email"),
        ref_code=ref_code,
        ref_link=ref_link,
        balance=info.get("balance", 0.0),
        is_admin=info.get("is_admin", False),
    )

# ---------- Referral tree (fixed: compute levels in Python; no "level" column required) ----------
@app.get("/referral-tree", endpoint="referral_tree_page")
def referral_tree_page():
    if not is_logged_in():
        return redirect(url_for("login"))
    u = current_user()
    with get_db() as con:
        cur = con.cursor()
        try:
            # مدل مبتنی بر جدول referrals(parent, child, created_at)
            rows = cur.execute("""
                WITH RECURSIVE t(child, lvl, joined_at) AS (
                    SELECT child, 1 AS lvl, created_at FROM referrals WHERE parent=?
                    UNION ALL
                    SELECT r.child, t.lvl+1, r.created_at
                      FROM referrals r
                      JOIN t ON r.parent = t.child
                )
                SELECT child AS username, lvl AS level, joined_at FROM t
                ORDER BY lvl, joined_at
            """, (u,)).fetchall()
        except sqlite3.OperationalError:
            # اگر جدول referrals موجود نبود، از users(parent) استفاده کن
            rows = cur.execute("""
                WITH RECURSIVE t(username, lvl, joined_at) AS (
                    SELECT username, 1 AS lvl, created_at
                      FROM users WHERE parent=?
                    UNION ALL
                    SELECT u.username, t.lvl+1, u.created_at
                      FROM users u
                      JOIN t ON u.parent = t.username
                )
                SELECT username, lvl AS level, joined_at FROM t
                ORDER BY lvl, joined_at
            """, (u,)).fetchall()

        # لینک دعوت
        ref_code = cur.execute("SELECT ref_code FROM users WHERE username=?", (u,)).fetchone()
        ref_code = (ref_code["ref_code"] if ref_code and ref_code["ref_code"] else u)
    invite_link = url_for("register", _external=True) + f"?ref={ref_code}"
    return render_template("tree.html", referrals=rows, invite_link=invite_link)


@app.get("/referral-tree/view", endpoint="tree_view")
def referral_tree_view():
    if not is_logged_in():
        return redirect(url_for("login"))
    return render_template("tree_view.html")

@app.get("/profit-details", endpoint="profit_details_page")
def profit_details_page():
    if not is_logged_in():
        return redirect(url_for("login"))
    u = current_user()
    rows, total = fetch_earnings_for(u)
    return render_template("profit_details.html", rows=rows, total=total)

@app.get("/withdraw", endpoint="withdraw_page")
def withdraw_page():
    if not is_logged_in():
        return redirect(url_for("login"))

    u = current_user()
    with get_db() as con:
        cur = con.cursor()
        # Get PayPal email
        row = cur.execute("SELECT id, paypal_email FROM users WHERE username=?", (u,)).fetchone()
        user_id = row["id"]
        paypal_email = row["paypal_email"] or ""

        # Get user's withdrawal requests
        withdrawals = cur.execute("""
            SELECT id, amount, status, created_at
            FROM withdrawals
            WHERE user_id = ?
            ORDER BY created_at DESC
        """, (user_id,)).fetchall()

    # Get current balance
    try:
        bal = total_balance(u)
    except Exception:
        bal = 0.0

    return render_template("withdraw.html", balance=bal, paypal_email=paypal_email,
                           username=u, withdrawals=withdrawals)

@csrf.exempt
@app.post("/withdraw", endpoint="withdraw_submit")
def withdraw_submit():
    if not is_logged_in():
        return redirect(url_for("login"))
    
    username = (request.form.get("username") or "").strip()
    try:
        amount = float((request.form.get("amount") or "").strip())
    except ValueError:
        flash("Invalid withdrawal amount", "danger")
        return redirect(url_for("withdraw_page"))

    if amount <= 0:
        flash("Amount must be greater than 0", "danger")
        return redirect(url_for("withdraw_page"))

    # Get user ID from username
    with get_db() as con:
        cur = con.cursor()
        user = cur.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if not user:
            flash("User not found", "danger")
            return redirect(url_for("withdraw_page"))
        user_id = user["id"]

        # Insert withdrawal request into DB
        cur.execute(
            "INSERT INTO withdrawals(user_id, amount, status) VALUES (?, ?, ?)",
            (user_id, amount, "pending")
        )
        con.commit()

    # Optional: Send email to admin
    # try:
    #     subject = "New Withdrawal Request"
    #     body = "A user named %s has submitted a withdrawal of £%.2f request. Please check the admin panel." % (username, amount)

    #     msg = MIMEMultipart()
    #     msg['From'] = SMTP_USER
    #     msg['To'] = ADMIN_EMAIL
    #     msg['Subject'] = subject
    #     msg.attach(MIMEText(body, 'plain'))

    #     server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
    #     server.starttls()
    #     server.login(SMTP_USER, SMTP_PASS)
    #     server.sendmail(SMTP_USER, ADMIN_EMAIL, msg.as_string())
    #     server.quit()
    # except Exception as e:
    #     print("Failed to send email:", e)
    #     flash("Could not send email to admin.", "warning")

    flash("Your withdrawal request has been received.", "success")
    return redirect(url_for("withdraw_page"))

# no game logic exposed page
@app.get("/how-it-works")
def how_it_works():
    return redirect(url_for("services"))

# no game logic exposed page
@app.get("/info")
def info():
    # return redirect(url_for("services"))
    return render_template("info.html")
# ========================= Payment flow =========================
PRICE_GBP = float(os.getenv("PRICE_GBP", "50.0"))

@app.get("/go-to-pay", endpoint="go_to_pay")
def go_to_pay():
    if not is_logged_in():
        return redirect(url_for("login"))
    session["pending_amount"] = PRICE_GBP   # مبلغ را قفل کن
    return redirect(url_for("pay_paypal"))

@app.get("/pay/paypal", endpoint="pay_paypal")
def pay_paypal():
    if not is_logged_in():
        return redirect(url_for("login"))
    amount = float(session.get("pending_amount", PRICE_GBP) or PRICE_GBP)
    return render_template(
        "pay_paypal.html",
        amount=amount,
        currency="GBP",
        paypal_client_id=os.getenv("PAYPAL_CLIENT_ID","")
    )

@csrf.exempt
@app.post("/paypal/create-order")
def paypal_create_order():
    if not is_logged_in(): return ("", 401)
    amount = session.get("pending_amount", PRICE_GBP)
    try: amount = float(amount)
    except: amount = PRICE_GBP

    if not USE_PAYPAL_API:
        # local fake id (dev fallback)
        import secrets
        oid = secrets.token_hex(12)
        return (oid, 200, {"Content-Type":"text/plain; charset=utf-8"})

    oid = create_paypal_order_v2(amount, BASE_CURRENCY) or ""
    app.logger.info(f"Order ID::::: {oid}")
    if oid:
        return jsonify({"id": oid})
    return jsonify({"error": "could_not_create_order"}), 400
    # return (oid, 200, {"Content-Type":"text/plain; charset=utf-8"})

@csrf.exempt
@app.post("/paypal/capture-order")
def paypal_capture_order():
    if not is_logged_in(): return jsonify({"error":"not_authenticated"}), 401
    data = request.get_json(silent=True) or {}
    order_id = (data.get("orderID") or "").strip()
    app.logger.info(f"Order ID::::: {order_id}")
    if not order_id:
        return jsonify({"error":"order_id_missing"}), 400

    amount = session.get("pending_amount", PRICE_GBP)
    try: amount = float(amount)
    except: amount = PRICE_GBP

    ok = True
    if USE_PAYPAL_API:
        res = capture_paypal_order_v2(order_id)
        ok = not res.get("error") and (res.get("status") in ("COMPLETED","APPROVED","PAYER_ACTION_REQUIRED")
              or any((c.get("status")=="COMPLETED") for c in (res.get("purchase_units") or [])))

    if ok:
        buyer = current_user()
        with get_db() as con:
            cur = con.cursor()
            cur.execute("INSERT INTO purchases(buyer,amount,source,tx_ref) VALUES (?,?,?,?)",
                        (buyer, amount, "paypal", order_id))
            pid = cur.lastrowid
            con.commit()
        # Distribute earnings
        distribute_commissions(buyer, pid, amount)
        session.pop("pending_amount", None)
        return jsonify({"status":"COMPLETED","order_id":order_id,"amount":amount})
    return jsonify({"status":"FAILED","order_id":order_id}), 400

# ========================= Admin =========================
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for("login", next=request.path))
        con = get_db(); cur = con.cursor()
        row = cur.execute("SELECT is_admin FROM users WHERE username=?", (current_user(),)).fetchone()
        con.close()
        if not row or not row["is_admin"]:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

@app.get("/admin")
@admin_required
def admin_home():
    con = get_db(); cur = con.cursor()
    users = cur.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    total = cur.execute("SELECT COALESCE(SUM(amount),0) s FROM purchases").fetchone()["s"]
    con.close()
    try:
        return render_template("admin.html", users=users, total=total)
    except TemplateNotFound:
        return f"<h1>Admin Dashboard</h1><p>Users: {users}</p><p>Total purchases: £{total:.2f}</p>", 200


@app.get("/admin/users")
@admin_required
def admin_users():
    q = (request.args.get("q") or "").strip().lower()
    con = get_db(); cur = con.cursor()
    if q:
        users = cur.execute("""
            SELECT username,email,paypal_email,is_admin,created_at
              FROM users
             WHERE LOWER(username) LIKE ? OR LOWER(email) LIKE ?
             ORDER BY created_at DESC
        """, (f"%{q}%", f"%{q}%")).fetchall()
    else:
        users = cur.execute("""
            SELECT username,email,paypal_email,is_admin,created_at
              FROM users ORDER BY created_at DESC
        """).fetchall()
    con.close()
    try:
        return render_template("admin_users.html", users=users, q=q)
    except:
        rows = "".join(
            f"<tr><td>{u['username']}</td><td>{u['email'] or ''}</td><td>{u['paypal_email'] or ''}</td>"
            f"<td>{'✅' if u['is_admin'] else '—'}</td><td>{u['created_at']}</td></tr>" for u in users
        )
        return f"""
        <h1>Admin / Users</h1>
        <form method="get"><input name="q" value="{q}" placeholder="search"><button>Search</button></form>
        <table border=1 cellpadding=6>
          <tr><th>Username</th><th>Email</th><th>PayPal</th><th>Admin</th><th>Created</th></tr>
          {rows or '<tr><td colspan=5>No users</td></tr>'}
        </table>""".strip()

@app.get("/admin/purchases")
@admin_required
def admin_purchases():
    q = (request.args.get("q") or "").strip().lower()
    con = get_db(); cur = con.cursor()
    if q:
        rows = cur.execute("""
            SELECT id,buyer,amount,source,tx_ref,created_at
              FROM purchases
             WHERE LOWER(buyer) LIKE ? OR LOWER(tx_ref) LIKE ?
             ORDER BY id DESC
        """, (f"%{q}%", f"%{q}%")).fetchall()
    else:
        rows = cur.execute("SELECT id,buyer,amount,source,tx_ref,created_at FROM purchases ORDER BY id DESC").fetchall()
    con.close()
    try:
        return render_template("admin_purchases.html", purchases=rows, q=q)
    except:
        trs = "".join(
            f"<tr><td>{r['id']}</td><td>{r['buyer']}</td><td>{r['amount']}</td><td>{r['source']}</td>"
            f"<td>{r['tx_ref']}</td><td>{r['created_at']}</td></tr>" for r in rows
        )
        return f"""
        <h1>Admin / Purchases</h1>
        <p><a href="/admin/purchases/export">Export CSV</a></p>
        <table border=1 cellpadding=6>
          <tr><th>ID</th><th>Buyer</th><th>Amount</th><th>Source</th><th>Tx</th><th>Created</th></tr>
          {trs or '<tr><td colspan=6>No purchases</td></tr>'}
        </table>""".strip()

@app.get("/admin/purchases/export")
@admin_required
def admin_export_csv():
    con = get_db(); cur = con.cursor()
    rows = cur.execute("SELECT id,buyer,amount,source,tx_ref,created_at FROM purchases ORDER BY id").fetchall()
    con.close()
    out = io.StringIO(); w = csv.writer(out)
    w.writerow(["id","buyer","amount","source","tx_ref","created_at"])
    for r in rows:
        w.writerow([r["id"], r["buyer"], r["amount"], r["source"], r["tx_ref"], r["created_at"]])
    data = out.getvalue().encode("utf-8")
    return Response(data, mimetype="text/csv",
                    headers={"Content-Disposition":"attachment; filename=purchases.csv"})

@csrf.exempt
@app.post("/admin/purchases/delete")
@admin_required
def admin_delete_purchase():
    data = request.get_json(silent=True) or {}
    pid = int(data.get("id") or 0)
    if not pid:
        return jsonify({"ok":False,"error":"id_required"}), 400
    con = get_db(); cur = con.cursor()
    cur.execute("DELETE FROM purchases WHERE id=?", (pid,))
    con.commit(); con.close()
    return jsonify({"ok":True})

# rebuild earnings from historical purchases
@app.get("/admin/earnings/rebuild")
@admin_required
def admin_earnings_rebuild():
    con = get_db(); cur = con.cursor()
    cur.execute("DELETE FROM earnings")
    con.commit()
    rows = cur.execute("SELECT id,buyer,amount FROM purchases ORDER BY id").fetchall()
    con.close()
    for r in rows:
        distribute_commissions(r["buyer"], r["id"], float(r["amount"]))
    return "Earnings rebuilt from purchases.", 200

# ========================= Cron/Webhooks =========================
def _cron_secret(): return os.getenv("CRON_SECRET") or ""
def _verify_cron_token():
    tok = request.args.get("token") or request.headers.get("X-CRON-TOKEN","")
    if tok != _cron_secret(): abort(403)

@app.get("/cron/refresh-processing")
def cron_refresh_processing():
    _verify_cron_token(); return {"ok":True}

@app.get("/cron/auto-create")
def cron_auto_create():
    _verify_cron_token(); return {"ok":True}

@app.get("/cron/run-batch")
def cron_run_batch():
    _verify_cron_token(); return {"ok":True}

@csrf.exempt
@app.post("/webhooks/paypal")
def paypal_webhook():
    return {"ok": True}

# ========================= Aliases & legacy =========================
@app.get("/_alias/login")
def _alias_login(): return redirect(url_for("login"))

@app.get("/_alias/register")
def _alias_register(): return redirect(url_for("register"))

@app.get("/_alias/dashboard")
def _alias_dashboard(): return redirect(url_for("dashboard"))

@app.get("/_alias/paypal")
def _alias_paypal(): return redirect(url_for("pay_paypal"))

@app.get("/services/page", endpoint="services_page")
def _alias_services_page():
    return redirect(url_for("services"))

@app.get("/referral-tree", endpoint="referral_tree")
def _alias_ref_tree():
    return redirect(url_for("referral_tree_page"))

@app.before_request
def _legacy_safe_login_catcher():
    if request.path == "/_alias/safeLogin":
        if "username" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

@app.route("/_alias/safeLogin", methods=["GET","POST","HEAD","OPTIONS"])
def alias_safe_login():
    if request.method == "POST" and request.is_json:
        return jsonify({"ok": True})
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.get("/favicon.ico")
def _favicon_quiet(): return ("", 204)

# ========================= Errors =========================
@app.errorhandler(400)
def err_400(e): return render_template("error.html", code=400, message=getattr(e,"description","Bad Request")), 400
@app.errorhandler(404)
def err_404(e): return render_template("error.html", code=404, message="Page not found."), 404
@app.errorhandler(429)
def err_429(e): return render_template("error.html", code=429, message="Too many requests."), 429

# ========================= Main =========================
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT","8000")), debug=True)

def is_admin() -> bool:
    """
    Check if the currently logged-in user is an admin.
    Returns True if 'is_admin' column is 1, else False.
    """
    username = session.get("username")
    if not username:
        return False

    with get_db() as con:
        cur = con.cursor()
        row = cur.execute(
            "SELECT is_admin FROM users WHERE username = ?", (username,)
        ).fetchone()
    
    if row:
        return row["is_admin"] == 1
    return False

@app.get("/admin/profit")
@admin_required
def admin_users_profits():
    if not is_admin():
        flash("Access denied", "danger")
        return redirect(url_for("login"))

    q = request.args.get("q", "").strip().lower()  # search query
    page = int(request.args.get("page", 1))
    per_page = 10

    with get_db() as con:
        cur = con.cursor()
        users = cur.execute(
            "SELECT id, username, parent_id, paypal_email, is_admin, created_at FROM users ORDER BY username"
        ).fetchall()

    # Calculate total and weekly profits
    profit_dict = {
        u['username']: {
            "total": calc_balance(u['username']),
            "weekly": calc_weekly_balance(u['username'])
        }
        for u in users
    }

    # Filter users by username or total/weekly profit
    if q:
        def matches(u):
            username_match = q in u['username'].lower()
            paypal_match = u['paypal_email'] and q in u['paypal_email'].lower()
            try:
                # check if query is number and matches total or weekly profit
                q_num = float(q)
                profit_match = (
                    q_num == profit_dict[u['username']]['total'] or
                    q_num == profit_dict[u['username']]['weekly']
                )
            except ValueError:
                profit_match = False
            return username_match or paypal_match or profit_match

        users = [u for u in users if matches(u)]

    # Sort users by total profit descending
    users_sorted = sorted(users, key=lambda u: profit_dict[u['username']]['total'], reverse=True)

    # Pagination
    total_users = len(users_sorted)
    start = (page - 1) * per_page
    end = start + per_page
    users_paginated = users_sorted[start:end]
    total_pages = (total_users + per_page - 1) // per_page

    return render_template(
        "admin_users_profit.html",
        users=users_paginated,
        profit_dict=profit_dict,
        page=page,
        total_pages=total_pages,
        q=q
    )

def calc_weekly_balance(username: str) -> float:
    """Weekly balance for a user (Monday 00:00 → next Monday 00:00)."""
    # Get this week's Monday 00:00
    today = datetime.now()
    # Find this week's Monday
    this_monday = today - timedelta(days=today.weekday())
    this_monday = this_monday.replace(hour=0, minute=0, second=0, microsecond=0)
    # Last week's Monday
    last_monday = this_monday - timedelta(days=7)

    with get_db() as con:
        cur = con.cursor()
        row = cur.execute(
            """
            SELECT COALESCE(SUM(amount),0) AS s
            FROM earnings
            WHERE user=? AND created_at >= ? AND created_at < ?
            """,
            (username, last_monday, this_monday)
        ).fetchone()

    try:
        return float(row["s"] or 0.0)
    except Exception:
        return 0.0

@app.get("/admin/withdrawls")
@admin_required
def admin_users_withdrawls():
    if not is_admin():
        flash("Access denied", "danger")
        return redirect(url_for("login"))
    
    with get_db() as con:
        cur = con.cursor()
        # Join withdrawals with users to get username
        requests = cur.execute("""
            SELECT w.id, w.user_id, w.amount, w.status, w.created_at,
                   u.username, u.email
            FROM withdrawals w
            JOIN users u ON w.user_id = u.id
            ORDER BY w.created_at DESC
        """).fetchall()

    return render_template("admin_users_withdrawls.html", requests=requests)

@app.post("/admin/withdrawals/approve", endpoint="approve_withdrawal")
@admin_required
def approve_withdrawal():
    withdrawal_id = request.form.get("withdrawal_id")
    if not withdrawal_id:
        flash("Invalid request", "danger")
        return redirect(url_for("admin_withdrawals"))

    with get_db() as con:
        cur = con.cursor()
        # Check if withdrawal exists and is pending
        withdrawal = cur.execute(
            "SELECT * FROM withdrawals WHERE id=? AND status='pending'", (withdrawal_id,)
        ).fetchone()
        if not withdrawal:
            flash("Withdrawal request not found or already approved", "warning")
            return redirect(url_for("admin_withdrawals"))

        # Update status to approved
        cur.execute(
            "UPDATE withdrawals SET status='approved' WHERE id=?", (withdrawal_id,)
        )

        # Add a negative entry in earnings table
        # user = username of the person who withdraws
        user_row = cur.execute("SELECT username FROM users WHERE id=?", (withdrawal["user_id"],)).fetchone()
        username = user_row["username"]

        # amount = -float(withdrawal["amount"])
        # cur.execute(
        #     """
        #     INSERT INTO earnings(user, source_purchase_id, level, percent, amount)
        #     VALUES (?, ?, ?, ?, ?)
        #     """,
        #     (username, 0, 0, 0.0, amount)  # negative amount
        # )
        # con.commit()

    flash("Withdrawal request approved and balance updated.", "success")
    return redirect(url_for("admin_users_withdrawls"))

@app.route('/get_users')
def get_users():
    conn = get_db()
    cur = conn.cursor()
    admin_username = "admin"
    # cur.execute(
    #         "UPDATE withdrawals SET status=? WHERE id=?",
    #         ("pending", "2")
    #     )
    # cur.execute("DELETE FROM earnings WHERE id = ?", (19,))
    # conn.commit()
    cur.execute("SELECT * FROM withdrawals")
    admin = cur.fetchall()
    columns = [column[0] for column in cur.description]
    admin_list = [dict(zip(columns, row)) for row in admin]

    return jsonify(admin_list)
