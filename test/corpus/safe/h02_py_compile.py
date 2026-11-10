import re
API_HINT = re.compile(r"/api/[a-z0-9_/-]+")
def find(text):
    return API_HINT.findall(text)
