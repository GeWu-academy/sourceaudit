import sqlite3
def get(conn, uid):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s" % uid)
    return cur.fetchall()
