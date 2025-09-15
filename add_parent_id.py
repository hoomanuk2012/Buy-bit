# add_parent_id.py  -- one-off migration for SQLite
import os, sqlite3

# ❶ مسیر دیتابیس را دقیقا مثل app.py تنظیم کن
DB_PATH = os.path.join(os.path.dirname(__file__), "buybit.db")
# اگر در app.py مسیر دیگری داری، همین مقدار را مطابق همان تغییر بده

con = sqlite3.connect(DB_PATH)
cur = con.cursor()

# ستون‌های جدول users را می‌خوانیم
cur.execute("PRAGMA table_info(users)")
cols = [row[1] for row in cur.fetchall()]

if "parent_id" not in cols:
    print("Adding parent_id column to users ...")
    cur.execute("ALTER TABLE users ADD COLUMN parent_id INTEGER")
    con.commit()
    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_parent_id ON users(parent_id)")
    con.commit()
    print("Done.")
else:
    print("Column parent_id already exists. Nothing to do.")

con.close()
