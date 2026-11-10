import os
def read(fn):
    with open(os.path.join("/data", fn)) as f:
        return f.read()
