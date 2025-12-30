#!/usr/bin/env python3
"""
Test script to send attack requests to the threat engine without Redis
"""
import requests
import json
import time

BASE_URL = "http://localhost:8000"
BACKEND_URL = "http://localhost:3000/api/logs/ingest"

def test_attack(name, payload):
    """Send a test attack"""
    print(f"\n{'='*70}")
    print(f"TEST: {name}")
    print(f"{'='*70}")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(f"{BASE_URL}/security/decision", json=payload, timeout=5)
        print(f"\n✓ Response Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.json()
    except Exception as e:
        print(f"✗ Error: {e}")
        return None

def main():
    print("\n" + "="*70)
    print("P3 THREAT ENGINE - TEST SUITE (NO REDIS REQUIRED)")
    print("="*70)
    print(f"Engine: {BASE_URL}")
    print(f"Backend: {BACKEND_URL}")
    print("="*70)
    
    # Test 1: Normal request
    test_attack("Normal Request", {
        "ip": "8.8.8.8",
        "path": "/api/products",
        "method": "GET",
        "user_agent": "Mozilla/5.0"
    })
    time.sleep(1)
    
    # Test 2: SQL Injection
    test_attack("SQL Injection", {
        "ip": "192.168.1.100",
        "path": "/api/users",
        "method": "POST",
        "user_agent": "curl/7.68.0",
        "payload": {
            "username": "admin' OR '1'='1",
            "password": "anything"
        }
    })
    time.sleep(1)
    
    # Test 3: XSS Attack
    test_attack("XSS Attack", {
        "ip": "10.0.0.50",
        "path": "/search",
        "method": "GET",
        "user_agent": "Mozilla/5.0",
        "payload": {
            "q": "<script>alert('xss')</script>"
        }
    })
    time.sleep(1)
    
    # Test 4: Sensitive Path
    test_attack("Sensitive Path Access", {
        "ip": "172.16.0.1",
        "path": "/admin",
        "method": "GET",
        "user_agent": "curl/7.68.0"
    })
    time.sleep(1)
    
    print("\n" + "="*70)
    print("✓ All tests completed!")
    print(f"Check {BACKEND_URL} to see if logs were received")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
