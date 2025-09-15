# reset_users.py
import sqlite3

conn = sqlite3.connect('database.db')
c = conn.cursor()

# حذف تمام کاربران (اما جدول باقی می‌ماند)
c.execute("DELETE FROM users")
conn.commit()

print("✅ All users have been deleted.")
conn.close()
