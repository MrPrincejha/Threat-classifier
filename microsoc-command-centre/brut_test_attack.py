import requests
import time

url = "http://127.0.0.1:8000/security/decision"

for i in range(12):
    payload = {
        "ip": "192.168.1.90",
        "path": "/login",
        "method": "POST",
        "payload": {
            "src_ip": "192.168.1.90",
            "dst_ip": "10.0.0.1",
            "port": 443,
            "protocol": "TCP",
            "packet_size": 600,
            "status": "failed"
        }
    }

    response = requests.post(url, json=payload)
    print(i + 1, response.json())
    time.sleep(0.5)
