import yaml
from flask import request
def parse():
    return yaml.load(request.data, Loader=yaml.Loader)
