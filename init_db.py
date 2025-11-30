import sqlite3

def init_db():
    conn = sqlite3.connect("example.db")
    cur = conn.cursor()

    # Create table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT
    )
    """)

    # Reset table (important)
    cur.execute("DELETE FROM users")

    # Insert sample users
    cur.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
    cur.execute("INSERT INTO users (username, password) VALUES ('alice', 'alice123')")
    cur.execute("INSERT INTO users (username, password) VALUES ('bob', 'bob123')")

    conn.commit()
    conn.close()

    print("[+] example.db initialized with test users")

if __name__ == "__main__":
    init_db()
