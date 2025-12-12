"""
login_with_totp.py
Client script to test /login_totp endpoint with username, password, and TOTP.
"""

import requests
import json
from totp_utilities import get_current_token

BASE_URL = "http://127.0.0.1:5000"

def login_with_totp(username: str, password: str, secret: str):
    """Attempt login with password + TOTP."""
    token = get_current_token(secret)
    payload = {
        "username": username,
        "password": password,
        "totp": token,
    }
    resp = requests.post(f"{BASE_URL}/login_totp", json=payload)
    print(f"Status: {resp.status_code}, Response: {resp.text}")

if __name__ == "__main__":
    username = "user21_strong"
    password = "X9!b$7kLm@Qz2#Rt"
    secret = "JBSWY3DPEHPK3PXP"  

    login_with_totp(username, password, secret)
