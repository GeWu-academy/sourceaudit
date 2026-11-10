from flask import request
import os
def dl():
    p = request.args['p']
    safe = os.path.basename(p)
    return open(p).read()
