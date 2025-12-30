# threat_intel.py
import os, requests
from dotenv import load_dotenv
load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")

def check_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return None
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": ABUSEIPDB_KEY
        }
        params = {"ipAddress": ip}
        r = requests.get(url, headers=headers, params=params, timeout=3)
        if r.status_code == 200:
            data = r.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            return {"is_malicious": score >= 50, "confidence": score}
        else:
            return None
    except Exception:
        return None
