import sqlite3
from flask import request
def q():
    uid = request.args['id']
    cur = sqlite3.connect('a.db').cursor()
    cur.execute(f"SELECT * FROM u WHERE id={uid}")
    return cur.fetchall()
