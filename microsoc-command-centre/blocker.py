import time

BLOCK_DURATION = 300  
blocklist = {}

def block_ip(ip):
    r.setex(f"blocked:{ip}", BLOCK_DURATION, "1")


def is_blocked(ip):
    if ip in blocklist:
        if time.time() < blocklist[ip]:
            return True
        else:
            del blocklist[ip]
    return False
