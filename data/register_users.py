# script to register users to the flask server and into the auth.db
import json
import sqlite3
import sys, os
import hashlib
import bcrypt
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from config import DB_PATH, PEPPER
from argon2 import PasswordHasher

def hash_password(password, salt, method="sha256"):
    pwd = password + PEPPER  # pepper is added only if enabled in advance
    if method == "sha256":
        return hashlib.sha256((pwd + salt).encode()).hexdigest()
    elif method == "bcrypt":
        return bcrypt.hashpw((pwd + salt).encode(), bcrypt.gensalt()).decode()
    elif method == "argon2id":
        ph = PasswordHasher()
        return ph.hash(pwd + salt)
    else:
        raise ValueError("Hash method is unsupported")

def main():
    with open("data/users.json", "r") as f:
        users = json.load(f)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            salt TEXT,
            hash TEXT,
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
        totp_secret = user.get("totp_secret")

        cur.execute("INSERT OR REPLACE INTO users VALUES (?, ?, ?, ?, ?)",
                    (username, salt, hashed, method, totp_secret))

    conn.commit()
    conn.close()
    print("Registered all users into the database ", DB_PATH)

if __name__ == "__main__":
    main()
