def get(conn, uid):
    return conn.cursor().execute(f"SELECT * FROM users WHERE id = {uid}")
