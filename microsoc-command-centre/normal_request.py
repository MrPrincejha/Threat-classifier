import requests

URL = "http://127.0.0.1:8000/security/decision"

data = {
    "ip": "192.168.1.100",
    "path": "/",
    "method": "GET",
    "user_agent": "Mozilla/5.0"
}

resp = requests.post(URL, json=data)
print(resp.json())