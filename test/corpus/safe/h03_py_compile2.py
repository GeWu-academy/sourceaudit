import re
def find(text, pattern):
    rx = re.compile(pattern)
    return rx.findall(text)
