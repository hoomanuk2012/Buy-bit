# add_ref_columns.py
import sqlite3

DB_PATH = "buybit.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

def column_exists(table, col):
    cur.execute(f"PRAGMA table_info({table})")
    return any(r[1] == col for r in cur.fetchall())

# 1) اضافه‌کردن ref_code اگر وجود ندارد
if not column_exists("users", "ref_code"):
    print("Adding ref_code to users ...")
    cur.execute("ALTER TABLE users ADD COLUMN ref_code TEXT")
    # اگر خواستید یکتا باشد، در SQLite قدیمی ایندکس یکتا بسازید:
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_ref_code ON users(ref_code)")

# 2) اضافه‌کردن parent_id اگر نبود (برای اطمینان؛ شما قبلاً اضافه کرده‌اید)
if not column_exists("users", "parent_id"):
    print("Adding parent_id to users ...")
    cur.execute("ALTER TABLE users ADD COLUMN parent_id INTEGER")

conn.commit()
conn.close()
print("Done.")
