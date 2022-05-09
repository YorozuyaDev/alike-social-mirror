import requests
import json

def notify(name_service):
    headers = {'Content-type': 'application/json'}
    body = json.dumps({"service": name_service})
    r = requests.post("http://dashboard:1880/notify", data=body, headers=headers)
