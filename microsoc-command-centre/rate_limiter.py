import time
from collections import defaultdict

requests_log = defaultdict(list)
path_log = defaultdict(list)
same_path_hits_log = defaultdict(list)

def add_request(ip, timestamp):
    requests_log[ip].append(timestamp)

def count_requests(ip, window=60):
    now = time.time()
    requests_log[ip] = [t for t in requests_log[ip] if now - t <= window]
    return len(requests_log[ip])

def count_unique_paths(ip, window=30):
    now = time.time()
    path_log[ip] = [t for t in path_log[ip] if now - t[1] <= window]
    return len(set([p[0] for p in path_log[ip]]))

def add_path(ip, path, timestamp):
    path_log[ip].append((path, timestamp))

def count_same_path_hits(ip, path, window=60):
    now = time.time()
    same_path_hits_log[ip] = [t for t in same_path_hits_log[ip] if now - t[1] <= window]
    hits = len([1 for p, ts in same_path_hits_log[ip] if p == path])
    return hits

def add_same_path(ip, path, timestamp):
    same_path_hits_log[ip].append((path, timestamp))
