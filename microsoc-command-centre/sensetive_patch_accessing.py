import requests  

URL = "http://127.0.0.1:8000/security/decision"   

data = {
    "ip": "192.168.1.103",
    "path": "/.env"
}

resp = requests.post(URL, json=data)
print(resp.json())
