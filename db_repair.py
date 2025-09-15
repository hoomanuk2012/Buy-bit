# db_repair.py -- make the SQLite schema match what app.py expects

import os, sqlite3, sys, argparse, secrets
from datetime import datetime
try:
    from argon2 import PasswordHasher
except Exception:
    PasswordHasher = None

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "buybit.db")

def has_table(cur, name):
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return cur.fetchone() is not None

def has_column(cur, table, col):
    cur.execute(f"PRAGMA table_info({table})")
    return any(r[1] == col for r in cur.fetchall())

def run():
    p = argparse.ArgumentParser()
    p.add_argument("--ensure-admin", nargs=3, metavar=("USERNAME","EMAIL","PASSWORD"),
                   help="Create admin user if none exists (or if username doesn't exist).")
    args = p.parse_args()

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    # USERS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email    TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        ref_code TEXT UNIQUE,
        parent_id INTEGER,
        paypal_email TEXT,
        is_admin INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );""")
    for col, ddl in [
        ("ref_code", "ALTER TABLE users ADD COLUMN ref_code TEXT"),
        ("parent_id", "ALTER TABLE users ADD COLUMN parent_id INTEGER"),
        ("paypal_email", "ALTER TABLE users ADD COLUMN paypal_email TEXT"),
        ("is_admin", "ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0"),
    ]:
        if not has_column(cur, "users", col):
            cur.execute(ddl)
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_username ON users(username)")
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email ON users(email)")
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_ref_code ON users(ref_code)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_users_parent_id ON users(parent_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_users_is_admin ON users(is_admin)")

    # REFERRALS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS referrals(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parent_id INTEGER NOT NULL,
        child_id  INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(parent_id) REFERENCES users(id),
        FOREIGN KEY(child_id) REFERENCES users(id)
    );""")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_ref_parent ON referrals(parent_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_ref_child  ON referrals(child_id)")

    # PURCHASES
    cur.execute("""
    CREATE TABLE IF NOT EXISTS purchases(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        buyer TEXT NOT NULL,
        amount REAL NOT NULL,
        source TEXT NOT NULL,
        tx_ref TEXT,
        receipt_file TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );""")
    if not has_column(cur, "purchases", "tx_ref"):
        cur.execute("ALTER TABLE purchases ADD COLUMN tx_ref TEXT")
    if not has_column(cur, "purchases", "receipt_file"):
        cur.execute("ALTER TABLE purchases ADD COLUMN receipt_file TEXT")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_purch_buyer ON purchases(buyer)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_purch_created ON purchases(created_at)")
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_purch_txref ON purchases(tx_ref) WHERE tx_ref IS NOT NULL")

    # PROFITS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS profits(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username  TEXT NOT NULL,
        from_user TEXT NOT NULL,
        level     INTEGER NOT NULL,
        amount    REAL NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );""")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_profit_user ON profits(username)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_profit_from ON profits(from_user)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_profit_level ON profits(level)")

    # ADMIN REVENUE
    cur.execute("""
    CREATE TABLE IF NOT EXISTS admin_revenue(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_purchase_id INTEGER,
        buyer TEXT NOT NULL,
        gross_amount REAL NOT NULL,
        admin_share REAL NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );""")

    # PAYOUTS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS payouts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        amount REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        method TEXT DEFAULT 'paypal',
        pay_ref TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        paid_at DATETIME
    );""")
    for col, ddl in [
        ("status",   "ALTER TABLE payouts ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'"),
        ("method",   "ALTER TABLE payouts ADD COLUMN method TEXT DEFAULT 'paypal'"),
        ("pay_ref",  "ALTER TABLE payouts ADD COLUMN pay_ref TEXT"),
        ("paid_at",  "ALTER TABLE payouts ADD COLUMN paid_at DATETIME"),
    ]:
        if not has_column(cur, "payouts", col):
            cur.execute(ddl)
    cur.execute("CREATE INDEX IF NOT EXISTS ix_payouts_user ON payouts(username)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_payouts_status ON payouts(status)")

    # Backfill ref_code
    cur.execute("SELECT id, username FROM users WHERE ref_code IS NULL OR ref_code=''")
    for row in cur.fetchall():
        code = f"{row['username']}-{row['id']}"
        try:
            cur.execute("UPDATE users SET ref_code=? WHERE id=?", (code, row["id"]))
        except sqlite3.IntegrityError:
            cur.execute("UPDATE users SET ref_code=? WHERE id=?", (f"{row['username']}-{row['id']}-{secrets.token_hex(3)}", row["id"]))

    # Ensure admin
    if args.ensure_admin:
        username, email, password = args.ensure_admin
        if PasswordHasher is None:
            print("[!] argon2-cffi not installed; cannot hash password.")
        else:
            cur.execute("SELECT id FROM users WHERE username=?", (username,))
            user = cur.fetchone()
            ph = PasswordHasher()
            pwd_hash = ph.hash(password)
            if user is None:
                cur.execute("INSERT INTO users(username,email,password,is_admin) VALUES (?,?,?,1)", (username,email,pwd_hash))
                print(f"[+] Created admin user '{username}'")
            else:
                cur.execute("UPDATE users SET is_admin=1, email=?, password=? WHERE username=?", (email, pwd_hash, username))
                print(f"[+] Updated existing user '{username}' to admin.")

    con.commit()

    cur.execute("SELECT COUNT(*) FROM users")
    n_users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM users WHERE is_admin=1")
    n_admins = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
    n_tables = cur.fetchone()[0]
    print(f"Done. Tables: {n_tables} • Users: {n_users} • Admins: {n_admins}")
    con.close()

if __name__ == "__main__":
    run()
