from sqlalchemy import text

def find(session, uid):
    return session.execute(text(f"SELECT * FROM t WHERE id = {uid}")).fetchall()
