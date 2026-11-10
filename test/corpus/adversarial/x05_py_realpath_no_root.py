import os
from flask import request
def get():
    f = request.args['f']
    real = os.path.realpath(f)
    return open(f, 'rb').read()
