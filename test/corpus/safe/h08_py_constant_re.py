import re
SKIP_EXT = re.compile(r"\.(png|jpg|gif|css|woff2?)$", re.I)
def keep(name):
    return not SKIP_EXT.search(name)
