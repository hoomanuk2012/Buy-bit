import sqlite3
conn = sqlite3.connect("buybit.db")
cur = conn.cursor()
cur.execute("PRAGMA table_info(users)")
for r in cur.fetchall():
    print(r)
conn.close()
