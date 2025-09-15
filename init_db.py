import sqlite3
from datetime import datetime

conn = sqlite3.connect('buybit.db')
cursor = conn.cursor()

# Users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    referral_code TEXT,
    join_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

# Profits table
cursor.execute("""
CREATE TABLE IF NOT EXISTS profits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    from_user TEXT,
    level INTEGER,
    amount REAL,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
""")

# Purchases table
cursor.execute("""
CREATE TABLE IF NOT EXISTS purchases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    amount REAL,
    source TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
""")

# Discount codes table
cursor.execute("""
CREATE TABLE IF NOT EXISTS discount_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    code TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
""")

conn.commit()
conn.close()

print("✅ All tables created successfully.")
