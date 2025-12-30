# app.py
from fastapi import FastAPI
import asyncio, time, json, os, requests
from classifier import classify_request
from blocklist import add_block
from dotenv import load_dotenv
from pymongo import MongoClient, UpdateOne
import redis

load_dotenv()
app = FastAPI(title="P3 Threat Detection Engine (Decision API)")

# ---------------- CONFIG ----------------
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
LOG_QUEUE = "attack_logs_queue"
BACKEND_API_URL = os.getenv("BACKEND_API_URL", "http://localhost:3000/api/logs/ingest")

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")

# Try to connect to MongoDB
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
    client.server_info()  # Force connection attempt
    db = client["threat_engine"]
    attack_logs = db["attack_logs"]
    MONGODB_AVAILABLE = True
    print("[MongoDB] Connected successfully")
except Exception as e:
    print(f"[MongoDB] Connection failed ({e}), using memory-only mode")
    client = None
    db = None
    attack_logs = None
    MONGODB_AVAILABLE = False

# Try to connect to Redis, fallback to in-memory queue if unavailable
try:
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True, socket_connect_timeout=2)
    r.ping()  # Test connection
    REDIS_AVAILABLE = True
    print("[Redis] Connected successfully")
except Exception as e:
    print(f"[Redis] Connection failed ({e}), using in-memory queue fallback")
    r = None
    REDIS_AVAILABLE = False
    # In-memory queue fallback
    MEMORY_LOG_QUEUE = []

BLOCK_DURATION = int(os.getenv("BLOCK_DURATION", "600"))

# ---------------- RESPONSE MAKER ----------------
def make_response(ip, path, method, status, result):
    return {
        "ip": ip,
        "path": path,
        "method": method,
        "status": status,
        "attack_type": result.get("attack_type", "normal"),
        "severity": result.get("severity"),
        "timestamp": int(time.time()),
        "reason": result.get("reason"),
        "suggestion": result.get("suggestion", ""),
        "is_blocked_now": result.get("is_blocked_now", False)
    }

# ---------------- API ROUTES ----------------
@app.get("/")
def home():
    return {"message": "P3 Threat Detection Engine Running"}

@app.post("/security/decision")
async def security_decision(data: dict):
    ip = data.get("ip")
    path = data.get("path", "/")
    method = data.get("method", "GET")
    ua = data.get("user_agent", "")
    payload = data.get("payload", None)

    if not ip:
        return make_response("", path, method, "WARN", result={"reason": "Missing ip"})

    # Classify request
    result = classify_request(ip, path, method, ua, payload=payload)
    status = result.get("status", "ALLOW")

    # Block IP if needed
    if status == "BLOCK":
        add_block(ip, duration=BLOCK_DURATION)

    resp = make_response(ip, path, method, status, result)

    # ---------------- LOG HANDLING ----------------
    if REDIS_AVAILABLE and r:
        try:
            r.lpush(LOG_QUEUE, json.dumps(resp))
        except Exception as e:
            print(f"Failed to push log to Redis: {e}")
            MEMORY_LOG_QUEUE.append(json.dumps(resp))
    else:
        MEMORY_LOG_QUEUE.append(json.dumps(resp))

    # ALLOW requests can also be written immediately (if MongoDB available)
    if status == "ALLOW" and MONGODB_AVAILABLE and attack_logs:
        try:
            doc_id = f"{resp['ip']}_{resp.get('attack_type','normal')}_{int(resp['timestamp']/60)}"
            attack_logs.update_one({"_id": doc_id}, {"$set": resp}, upsert=True)
        except Exception as e:
            print(f"[MongoDB] Write failed: {e}")

    return resp

# ---------------- BACKGROUND WORKER ----------------
async def mongo_writer_worker():
    print("🔥 Mongo Writer Worker started")
    while True:
        batch = []
        backend_batch = []

        # Pull from Redis or memory queue
        for _ in range(100):
            log_json = None
            
            if REDIS_AVAILABLE and r:
                try:
                    log_json = r.rpop(LOG_QUEUE)
                except Exception as e:
                    print(f"[Redis] Error pulling log: {e}")
                    break
            elif MEMORY_LOG_QUEUE:
                log_json = MEMORY_LOG_QUEUE.pop(0)
            
            if not log_json:
                break
            
            log = json.loads(log_json)
            # Use .get() to avoid KeyError
            log["_id"] = f"{log['ip']}_{log.get('attack_type','normal')}_{int(log['timestamp']/60)}"

            batch.append(UpdateOne({"_id": log["_id"]}, {"$set": log}, upsert=True))
            backend_batch.append(log)

        if batch and MONGODB_AVAILABLE and attack_logs:
            # Save to MongoDB
            try:
                attack_logs.bulk_write(batch)
                print(f"[MongoDB] Batch saved: {len(batch)}")
            except Exception as e:
                print(f"[MongoDB] Bulk write failed: {e}")

            # Send to backend API
            try:
                response = requests.post(
                    BACKEND_API_URL,
                    json=backend_batch,
                    timeout=5
                )
                print(f"[Backend] Sent {len(backend_batch)} logs | Status: {response.status_code}")
                if response.status_code >= 400:
                    print(f"[Backend] Error: {response.text}")
            except requests.exceptions.ConnectionError as ce:
                print(f"[Backend] Connection failed to {BACKEND_API_URL}")
        elif batch and not MONGODB_AVAILABLE:
            # No MongoDB, just send to backend
            try:
                response = requests.post(
                    BACKEND_API_URL,
                    json=backend_batch,
                    timeout=5
                )
                print(f"[Backend] Sent {len(backend_batch)} logs | Status: {response.status_code}")
                if response.status_code >= 400:
                    print(f"[Backend] Error: {response.text}")
            except requests.exceptions.ConnectionError as ce:
                print(f"[Backend] Connection failed to {BACKEND_API_URL}")
            except requests.exceptions.Timeout:
                print(f"[Backend] Timeout sending to {BACKEND_API_URL}")
            except Exception as e:
                print(f"[Backend] Error: {e}")

        await asyncio.sleep(1)

@app.on_event("startup")
async def startup_event():
    print("🔥 Starting Mongo Writer Worker...")
    asyncio.create_task(mongo_writer_worker())
