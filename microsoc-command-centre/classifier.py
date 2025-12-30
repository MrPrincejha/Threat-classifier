import time
import re
import redis
import json
import os
from rate_limiter import count_requests, count_unique_paths
from threat_intel import check_abuseipdb
from ml.predict import predict_payload
from ml.Hybrid_recommend import hybrid_remediation
from dotenv import load_dotenv

load_dotenv()

# ----------------- REDIS CONFIG -----------------
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
LOG_QUEUE = "attack_logs_queue"
REDIS_BLOCK_TTL = int(os.getenv("REDIS_BLOCK_TTL", 300))

# Try to connect to Redis, fallback to in-memory block list if unavailable
try:
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True, socket_connect_timeout=2)
    r.ping()  # Test connection
    REDIS_AVAILABLE = True
except Exception as e:
    print(f"[Classifier] Redis not available, using in-memory fallback: {e}")
    r = None
    REDIS_AVAILABLE = False
    # In-memory block list fallback
    BLOCKED_IPS_MEMORY = {}

# In-memory log queue fallback (shared with app.py)
LOG_QUEUE_MEMORY = []

# ----------------- HELPER FUNCTIONS -----------------
def push_log(log):
    if REDIS_AVAILABLE and r:
        try:
            r.lpush(LOG_QUEUE, json.dumps(log))
        except Exception as e:
            print(f"Failed to push log to Redis: {e}")
            LOG_QUEUE_MEMORY.append(json.dumps(log))
    else:
        LOG_QUEUE_MEMORY.append(json.dumps(log))

def block_ip(ip, reason, source, severity="HIGH"):
    record = {
        "ip": ip,
        "reason": reason,
        "source": source,
        "severity": severity,
        "timestamp": int(time.time())
    }
    if REDIS_AVAILABLE and r:
        try:
            r.set(f"block:{ip}", json.dumps(record), ex=REDIS_BLOCK_TTL)
        except Exception as e:
            print(f"Failed to block IP in Redis: {e}")
            BLOCKED_IPS_MEMORY[ip] = time.time() + REDIS_BLOCK_TTL
    else:
        BLOCKED_IPS_MEMORY[ip] = time.time() + REDIS_BLOCK_TTL
    push_log(record)

def is_blocked(ip):
    if REDIS_AVAILABLE and r:
        try:
            return r.exists(f"block:{ip}")
        except Exception as e:
            print(f"Failed to check Redis block: {e}")
    
    # Check in-memory blocklist
    if ip in BLOCKED_IPS_MEMORY:
        if time.time() < BLOCKED_IPS_MEMORY[ip]:
            return True
        else:
            del BLOCKED_IPS_MEMORY[ip]
    return False

# ----------------- PATTERNS -----------------
SQLI = re.compile(r"(union|select|information_schema|--|;|'\s*or\s*1=1|drop)", re.IGNORECASE)
XSS = re.compile(r"(<script|onerror=|onload=|javascript:)", re.IGNORECASE)
SENSITIVE_PATHS = {"/admin", "/phpmyadmin", "/backup.zip", "/.git"}

# ----------------- CLASSIFIER -----------------
def classify_request(ip, path, method, ua, payload=None, timestamp=None):
    timestamp = int(timestamp or time.time())
    ua = (ua or "").lower()
    path = path or "/"

    # --- Check if IP is blocked in Redis ---
    if is_blocked(ip):
        log = {
            "status": "BLOCK",
            "attack_type": "previous_block",
            "severity": "CRITICAL",
            "reason": "IP already blocked",
            "suggestion": "Wait TTL",
            "ip": ip,
            "path": path,
            "method": method,
            "timestamp": timestamp,
            "is_blocked_now": True
        }
        push_log(log)
        return log

    # --- SQL Injection ---
    if (payload and SQLI.search(str(payload))) or SQLI.search(path):
        block_ip(ip, "SQL Injection", "RuleEngine", "HIGH")
        log = {
            "status": "BLOCK",
            "attack_type": "sql_injection",
            "severity": "HIGH",
            "reason": "SQL injection detected",
            "suggestion": "Sanitize input",
            "ip": ip,
            "path": path,
            "method": method,
            "timestamp": timestamp,
            "is_blocked_now": True
        }
        push_log(log)
        return log

    # --- XSS Attempt ---
    if payload and XSS.search(str(payload)):
        log = {
            "status": "WARN",
            "attack_type": "xss_attempt",
            "severity": "MEDIUM",
            "reason": "Possible XSS attempt",
            "suggestion": "Escape output",
            "ip": ip,
            "path": path,
            "method": method,
            "timestamp": timestamp,
            "is_blocked_now": False
        }
        push_log(log)
        return log

    # --- Sensitive Paths ---
    if path.lower() in SENSITIVE_PATHS:
        block_ip(ip, "Sensitive Path Access", "RuleEngine")
        log = {
            "status": "BLOCK",
            "attack_type": "sensitive_path_access",
            "severity": "HIGH",
            "reason": f"Accessed sensitive path {path}",
            "suggestion": "Restrict access",
            "ip": ip,
            "path": path,
            "method": method,
            "timestamp": timestamp,
            "is_blocked_now": True
        }
        push_log(log)
        return log

    # --- ML / AI Prediction ---
    if payload:
        try:
            src = payload.get("src_ip")
            dst = payload.get("dst_ip")
            port = payload.get("port")
            protocol = payload.get("protocol")
            size = payload.get("packet_size")

            if None not in (src, dst, port, protocol, size):
                label, conf = predict_payload(src, dst, port, protocol, size)
                if label != "normal" and conf > 0.85:
                    status = "BLOCK"
                    log = {
                        "status": status,
                        "attack_type": f"ML_{label}",
                        "severity": "HIGH",
                        "reason": f"AI detected {label}",
                        "suggestion": "Investigate",
                        "ip": ip,
                        "path": path,
                        "method": method,
                        "timestamp": timestamp,
                        "confidence": conf,
                        "is_blocked_now": True
                    }
                    push_log(log)
                    return log
        except Exception as e:
            print("ML prediction failed:", e)

    # --- Normal Request ---
    rec = hybrid_remediation("normal")
    allow_log = {
        "status": "ALLOW",
        "attack_type": "normal",
        "severity": rec["severity"],
        "reason": "Hybrid passed",
        "suggestion": rec["suggestion"],
        "ip": ip,
        "path": path,
        "method": method,
        "timestamp": timestamp,
        "is_blocked_now": False
    }
    push_log(allow_log)
    return allow_log
