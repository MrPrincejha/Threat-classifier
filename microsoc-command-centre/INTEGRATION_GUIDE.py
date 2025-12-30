#!/usr/bin/env python3
"""
Complete Setup Guide - P3 Threat Engine + Teammate's Backend Integration
"""

print("""
╔════════════════════════════════════════════════════════════════════════════╗
║  P3 THREAT ENGINE - INTEGRATION WITH TEAMMATE'S BACKEND                    ║
╚════════════════════════════════════════════════════════════════════════════╝

TEAMMATE'S BACKEND CONFIGURATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

From their .env file:
├─ Backend API: http://localhost:3000
├─ MongoDB: mongodb+srv://abcranger:abcranger@cluster0.eredb3u.mongodb.net/microsoc
├─ Redis: redis://localhost:6379
├─ NextAuth: http://localhost:3000
└─ WebSocket: ws://localhost:3001

THREAT ENGINE CONFIGURATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Your threat engine will:
✓ Listen on: http://localhost:8000
✓ Send attack logs to: http://localhost:3000/api/logs/ingest
✓ Use in-memory queue if Redis unavailable
✓ Skip MongoDB (not required for your setup)

═════════════════════════════════════════════════════════════════════════════

SETUP STEPS:
═════════════════════════════════════════════════════════════════════════════

STEP 1: Make sure teammate's backend is running
┌─────────────────────────────────────────────────────────────────────────────┐
│ They should have these services running on their machine:                    │
│ • Node.js backend at http://localhost:3000                                  │
│ • Redis at localhost:6379 (if they configured it)                           │
│ • MongoDB Atlas connection (already configured in their .env)               │
└─────────────────────────────────────────────────────────────────────────────┘

To test if backend is running:
  curl http://localhost:3000/api/logs/ingest -X POST -H "Content-Type: application/json" -d '{}'


STEP 2: Start your Threat Engine
┌─────────────────────────────────────────────────────────────────────────────┐
│ Terminal 1:                                                                  │
│                                                                              │
│ $ cd d:\\p3-threat-engine\\microsoc-command-centre                          │
│ $ python -m uvicorn app:app --port 8000                                     │
│                                                                              │
│ You should see:                                                              │
│ INFO:     Application startup complete.                                     │
│ INFO:     Uvicorn running on http://0.0.0.0:8000                            │
└─────────────────────────────────────────────────────────────────────────────┘


STEP 3: Send Attack Requests to Your Threat Engine
┌─────────────────────────────────────────────────────────────────────────────┐
│ Terminal 2:                                                                  │
│                                                                              │
│ $ cd d:\\p3-threat-engine\\microsoc-command-centre                          │
│ $ python test_no_redis.py                                                   │
│                                                                              │
│ This will send:                                                              │
│ • Normal request                                                             │
│ • SQL Injection attack                                                       │
│ • XSS attack                                                                 │
│ • Sensitive path access                                                      │
└─────────────────────────────────────────────────────────────────────────────┘


STEP 4: Verify Logs Reached Backend
┌─────────────────────────────────────────────────────────────────────────────┐
│ Check these indicators:                                                      │
│                                                                              │
│ In Threat Engine Terminal (Step 2):                                          │
│ You should see messages like:                                                │
│   [Backend] Sent 4 logs | Status: 200                                       │
│   [Backend] Sent 1 logs | Status: 200                                       │
│                                                                              │
│ In Backend/Database:                                                         │
│ Your teammate can check MongoDB to see attack logs recorded:                 │
│   - IP addresses blocked                                                     │
│   - Attack types detected                                                    │
│   - Severity levels assigned                                                 │
│   - Timestamps of attacks                                                    │
└─────────────────────────────────────────────────────────────────────────────┘

═════════════════════════════════════════════════════════════════════════════

DATA FLOW DIAGRAM:
═════════════════════════════════════════════════════════════════════════════

┌──────────────────────────────────────────────────────────────────────────┐
│                      THREAT REQUEST                                       │
│  POST http://localhost:8000/security/decision                             │
│  {                                                                         │
│    "ip": "192.168.1.100",                                                │
│    "path": "/api/users",                                                  │
│    "method": "POST",                                                      │
│    "payload": {"user": "admin' OR '1'='1"}                               │
│  }                                                                         │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│              THREAT ENGINE (Your Machine - Port 8000)                    │
│                                                                           │
│  classify_request() → Detects SQL Injection                              │
│  Severity: HIGH                                                           │
│  Status: BLOCK                                                            │
│                                                                           │
│  Adds to memory queue:                                                    │
│  {                                                                         │
│    "ip": "192.168.1.100",                                                │
│    "attack_type": "sql_injection",                                        │
│    "severity": "HIGH",                                                    │
│    "status": "BLOCK",                                                     │
│    "reason": "SQL injection pattern detected",                            │
│    "timestamp": 1733750000                                               │
│  }                                                                         │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│              BACKGROUND WORKER (Every 1 Second)                          │
│                                                                           │
│  1. Pulls logs from memory queue (or Redis if available)                 │
│  2. Saves to local MongoDB (if available)                                │
│  3. POSTs to: http://localhost:3000/api/logs/ingest                      │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│         TEAMMATE'S BACKEND (Localhost Port 3000)                         │
│                                                                           │
│  POST /api/logs/ingest                                                   │
│  ✓ Receives attack logs                                                  │
│  ✓ Stores in MongoDB Atlas                                               │
│  ✓ Can trigger notifications/alerts                                      │
│  ✓ Can update dashboards                                                 │
│  ✓ Can log to security system                                            │
└──────────────────────────────────────────────────────────────────────────┘

═════════════════════════════════════════════════════════════════════════════

ATTACK RESPONSE FORMAT:
═════════════════════════════════════════════════════════════════════════════

Your threat engine sends this JSON to backend:

{
  "ip": "192.168.1.100",
  "path": "/api/users",
  "method": "POST",
  "status": "BLOCK",
  "attack_type": "sql_injection",
  "severity": "HIGH",
  "timestamp": 1733750000,
  "reason": "SQL injection pattern detected",
  "suggestion": "Apply input sanitization, WAF SQL filter, block for 30 min.",
  "is_blocked_now": true
}

Your teammate can use this data to:
✓ Log attacks to MongoDB
✓ Send alerts to security team
✓ Update IP reputation database
✓ Trigger honeypot responses
✓ Generate security reports

═════════════════════════════════════════════════════════════════════════════

SUPPORTED ATTACK TYPES:
═════════════════════════════════════════════════════════════════════════════

Status    Attack Type              Severity  Auto-Block   Details
─────────────────────────────────────────────────────────────────────────
BLOCK     sql_injection            HIGH      Yes          SQL patterns
WARN      xss_attempt              MEDIUM    No           Script tags
BLOCK     sensitive_path_access    HIGH      Yes          /.env, /admin
BLOCK     brute_force_login        HIGH      Yes          10+ failed logins
BLOCK     dos_flood                CRITICAL  Yes          200+ req/10s
BLOCK     directory_scan           HIGH      Yes          20+ unique paths
WARN      automated_bot            MEDIUM    No           Bot user agents
BLOCK     threat_intel             CRITICAL  Yes          AbuseIPDB hit
ALLOW     normal                   LOW       No           Clean request

═════════════════════════════════════════════════════════════════════════════

ENVIRONMENT VARIABLES (Optional):
═════════════════════════════════════════════════════════════════════════════

Create a .env file in d:\\p3-threat-engine\\microsoc-command-centre\\

BACKEND_API_URL=http://localhost:3000/api/logs/ingest    # Where to send logs
REDIS_HOST=localhost                                      # Redis server (optional)
REDIS_PORT=6379                                           # Redis port (optional)
MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net    # MongoDB (optional)
BLOCK_DURATION=600                                        # How long to block IP

═════════════════════════════════════════════════════════════════════════════

TROUBLESHOOTING:
═════════════════════════════════════════════════════════════════════════════

Issue: [Backend] Connection failed to http://localhost:3000/api/logs/ingest
──────────────────────────────────────────────────────────────────────────
Solution: Make sure teammate's backend is running
  $ Check if they started: npm run dev (or whatever their start command is)
  $ Check: curl http://localhost:3000/api/health
  $ Verify port 3000 is accessible

Issue: Tests timeout or can't connect to threat engine
──────────────────────────────────────────────────────
Solution: Wait 10+ seconds for TensorFlow to load
  $ TensorFlow takes time on first request
  $ Try: curl http://localhost:8000/
  $ Should return: {"message":"P3 Threat Detection Engine Running"}

Issue: Logs queued but not reaching backend
──────────────────────────────────────────
Solution: Check firewall and network
  $ Can threat engine machine reach teammate's machine on port 3000?
  $ Check Windows Firewall: allow Python through firewall
  $ Try direct curl: curl -X POST http://localhost:3000/api/logs/ingest -d '{}'

Issue: "[Redis] Connection failed" - is this a problem?
───────────────────────────────────────────────────────
Solution: NO! This is fine. You have fallback:
  $ Threat engine uses in-memory queue instead
  $ If teammate later adds Redis, it will auto-detect and use it
  $ Same with MongoDB - optional, not required

═════════════════════════════════════════════════════════════════════════════

ADVANCED: MANUAL ATTACK SIMULATION
═════════════════════════════════════════════════════════════════════════════

Test SQL Injection:
──────────────────
curl -X POST http://localhost:8000/security/decision \\
  -H "Content-Type: application/json" \\
  -d '{
    "ip":"192.168.1.100",
    "path":"/api/users",
    "method":"POST",
    "payload":{"username":"admin'"'"' OR '"'"'1'"'"'='"'"'1"}
  }'

Expected Response: status: "BLOCK", attack_type: "sql_injection"


Test XSS Attack:
───────────────
curl -X POST http://localhost:8000/security/decision \\
  -H "Content-Type: application/json" \\
  -d '{
    "ip":"10.0.0.50",
    "path":"/search",
    "method":"GET",
    "payload":{"q":"<script>alert(1)</script>"}
  }'

Expected Response: status: "WARN", attack_type: "xss_attempt"


Test Sensitive Path:
────────────────────
curl -X POST http://localhost:8000/security/decision \\
  -H "Content-Type: application/json" \\
  -d '{
    "ip":"172.16.0.1",
    "path":"/admin",
    "method":"GET"
  }'

Expected Response: status: "BLOCK", attack_type: "sensitive_path_access"

═════════════════════════════════════════════════════════════════════════════


═════════════════════════════════════════════════════════════════════════════



═════════════════════════════════════════════════════════════════════════════



═════════════════════════════════════════════════════════════════════════════
""")

if __name__ == "__main__":
    print("\nSetup guide complete! Follow the steps above to integrate your threat engine.")
