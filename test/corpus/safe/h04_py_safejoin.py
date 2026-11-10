import os
ROOT = os.path.realpath('/data')
def read(fn):
    p = os.path.realpath(os.path.join(ROOT, fn))
    if not p.startswith(ROOT + os.sep):
        raise ValueError('bad path')
    with open(p) as f:
        return f.read()
