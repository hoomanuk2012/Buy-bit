# create_admin.py
import sqlite3

conn = sqlite3.connect('database.db')
c = conn.cursor()

# بررسی وجود کاربر admin
c.execute("SELECT * FROM users WHERE username = 'admin'")
if c.fetchone():
    print("⚠️ Admin already exists.")
else:
    c.execute("INSERT INTO users (full_name, email, username, password, referrer) VALUES (?, ?, ?, ?, ?)",
              ('Admin User', 'admin@example.com', 'admin', 'adminpass', None))
    conn.commit()
    print("✅ Admin user created successfully.")

conn.close()
