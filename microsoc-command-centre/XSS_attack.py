import requests  

URL = "http://127.0.0.1:8000/security/decision"   

data = {
    "ip": "192.168.1.102",
    "path": "/search?q=<script>alert('hack')</script>",
    "method": "GET",
    "payload": "<script>alert('XSS')</script>"
}

response = requests.post(URL, json=data)
print(response.json())