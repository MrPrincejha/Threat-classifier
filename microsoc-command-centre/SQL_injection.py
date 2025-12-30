import requests   

URL = "http://127.0.0.1:8000/security/decision"

data = {
    "ip": "192.168.1.101",
    "path": "/login",
    "method": "POST",
    "payload": "admin' OR 1=1;--"
}

response = requests.post(URL, json=data)
print(response.json())
