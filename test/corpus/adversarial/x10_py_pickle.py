import pickle, base64
from flask import request
def load():
    raw = request.cookies.get('state')
    return pickle.loads(base64.b64decode(raw))
