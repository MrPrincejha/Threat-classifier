# blocklist.py - Redis Free Version
import time
import os

BLOCK_DURATION = int(os.getenv("BLOCK_DURATION", 600))  # Default 10 min

# In-memory store (IP -> expiry timestamp)
BLOCKED_IPS = {}

def add_block(ip, duration=BLOCK_DURATION):
    BLOCKED_IPS[ip] = time.time() + duration

def remove_block(ip):
    if ip in BLOCKED_IPS:
        del BLOCKED_IPS[ip]

def is_blocked(ip):
    if ip in BLOCKED_IPS:
        # Check if block expired
        if time.time() < BLOCKED_IPS[ip]:
            return True
        else:
            remove_block(ip)
    return False

# Alias (keep compatibility)
def block_ip(ip, duration=BLOCK_DURATION):
    add_block(ip, duration)
