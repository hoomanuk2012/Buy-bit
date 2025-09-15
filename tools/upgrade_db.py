import sqlite3

DB_PATH = DB_PATH = DB_PATH = DB_PATH = 'buybit.db'  # اگه اسم دیتابیس تو فرق داره، همینجا اصلاحش کن

def add_discount_code_column():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # چک می‌کنه آیا ستون discount_code وجود داره یا نه
    cur.execute("PRAGMA table_info(users);")
    columns = [column[1] for column in cur.fetchall()]

    if 'discount_code' not in columns:
        print("در حال افزودن ستون discount_code به جدول users ...")
        cur.execute("ALTER TABLE users ADD COLUMN discount_code TEXT;")
        conn.commit()
        print("ستون discount_code با موفقیت اضافه شد.")
    else:
        print("ستون discount_code قبلاً وجود داشته.")

    conn.close()

if __name__ == '__main__':
    add_discount_code_column()
