import os
def read(fn):
    p = os.path.join('/data', fn)
    return open(p).read()
