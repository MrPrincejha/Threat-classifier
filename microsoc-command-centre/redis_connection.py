# redis_connection.py
import redis
import json
import time

REDIS_HOST = "localhost"
REDIS_PORT = 6379
BLOCK_EXPIRY = 3600  # 1 hour

redis_client = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)


# ---------------- BLOCK IP ----------------
def block_ip(ip, reason="Manual/Auto Block", source="Engine", severity="HIGH"):
    record = {
        "ip": ip,
        "reason": reason,
        "source": source,
        "severity": severity,
        "timestamp": int(time.time())
    }
    redis_client.set(f"block:{ip}", json.dumps(record), ex=BLOCK_EXPIRY)


# ---------------- CHECK BLOCKED ----------------
def is_redis_blocked(ip):
    return redis_client.exists(f"block:{ip}")


# ---------------- MANUAL UNBLOCK ----------------
def unblock_ip(ip):
    return redis_client.delete(f"block:{ip}")


# ---------------- LIST ALL BLOCKED ----------------
def get_all_blocked():
    keys = redis_client.keys("block:*")
    result = []
    for key in keys:
        data = redis_client.get(key)
        ttl = redis_client.ttl(key)
        try:
            record = json.loads(data)
            record["ip"] = key.replace("block:", "")
            record["ttl_remaining"] = ttl
            result.append(record)
        except:
            pass
    return result
