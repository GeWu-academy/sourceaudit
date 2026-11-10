import pickle, base64
def load(raw):
    return pickle.loads(base64.b64decode(raw))
