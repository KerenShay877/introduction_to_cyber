# register_users.py
# Script to register users into the Flask server's SQLite database (auth.db)

import json
import sqlite3
import sys, os
import hashlib
import bcrypt
from argon2 import PasswordHasher

# allow imports from project root
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from config import DB_PATH, PEPPER
from totp_utilities import generate_totp_secret


def hash_password(password, salt, method="sha256"):
    """Hash a password with salt and optional pepper using the chosen method."""
    pwd = password + PEPPER

    if method == "sha256":
        return hashlib.sha256((pwd + salt).encode()).hexdigest()

    elif method == "bcrypt":
        return bcrypt.hashpw((pwd + salt).encode(), bcrypt.gensalt(rounds=12)).decode()

    elif method == "argon2id":
        ph = PasswordHasher(time_cost=1, memory_cost=65536, parallelism=1)
        return ph.hash(pwd + salt)

    else:
        raise ValueError(f"Unsupported hash method: {method}")


def main():
    with open("data/users.json", "r") as f:
        users = json.load(f)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            salt TEXT,
            password_hash TEXT,
            hash_mode TEXT,
            totp_secret TEXT
        )
    """)

    for user in users:
        username = user["username"]
        password = user["password"]
        method = user["hash_mode"]

        salt = os.urandom(16).hex()
        hashed = hash_password(password, salt, method)

        totp_secret = user.get("totp_secret") or generate_totp_secret()

        cur.execute(
            "INSERT OR REPLACE INTO users VALUES (?, ?, ?, ?, ?)",
            (username, salt, hashed, method, totp_secret)
        )

    conn.commit()
    conn.close()
    print(f"Registered all users into the database at {DB_PATH}")


if __name__ == "__main__":
    main()
