"""
Authentication utilities for users
"""

import bcrypt
import hashlib
import logging
from datetime import datetime
from flask import jsonify
from argon2 import PasswordHasher
from app.config import PEPPER, GROUP_SEED, DEFENSE_METHODS
from app.exceptions import AppError
from app.db import get_db
from app.protections import check_lockout, register_failure

logger = logging.getLogger("app_logger")

def password_hash(password: str, salt: str, method: str = "sha256") -> str:
    """
    Hash a password according to the chosen method.
    PEPPER is only added if it's set (empty string disables it).
    """
    pwd = password + PEPPER

    if method == "sha256":
        return hashlib.sha256((pwd + salt).encode()).hexdigest()

    elif method == "bcrypt":
        return bcrypt.hashpw((pwd + salt).encode(), bcrypt.gensalt(rounds=12)).decode()

    elif method == "argon2id":
        ph = PasswordHasher(time_cost=1, memory_cost=65536, parallelism=1)
        return ph.hash(pwd + salt)

    else:
        raise ValueError(f"Hash method not supported: {method}")


def _is_password_matching(password: str, salt: str, hash_stored: str, method: str = "sha256") -> bool:
    """
    Verify a password against the stored hash using the same method.
    """
    pwd = password + PEPPER

    if method == "sha256":
        candidate_hash = hashlib.sha256((pwd + salt).encode()).hexdigest()
        return candidate_hash == hash_stored

    elif method == "bcrypt":
        try:
            return bcrypt.checkpw((pwd + salt).encode(), hash_stored.encode())
        except Exception:
            return False

    elif method == "argon2id":
        ph = PasswordHasher(time_cost=1, memory_cost=65536, parallelism=1)
        try:
            ph.verify(hash_stored, pwd + salt)
            return True
        except Exception:
            return False

    else:
        raise ValueError(f"Hash method not supported: {method}")
    

def _log_login_attempt(username, hash_mode, result, latency_ms):
    entry = {
        "group_seed": GROUP_SEED,
        "username": username,
        "hash_mode": hash_mode,
        "protection_flags": [k for k, v in DEFENSE_METHODS.items() if v],
        "result": result,
        "latency_ms": latency_ms,
    }
    logger.info("Login attempt recorded", extra={"payload": entry})


def login_user(username: str, password: str):
    start = datetime.utcnow()

    if DEFENSE_METHODS.get("lockout", False) and not check_lockout(username):
        latency = (datetime.utcnow() - start).microseconds // 1000
        _log_login_attempt(username, "bcrypt", "LOCKED", latency)
        raise AppError("Account locked due to too many failures", 403)

    db = get_db()
    c = db.cursor()
    c.execute(
        "SELECT password_hash, salt, hash_mode, totp_secret FROM users WHERE username=?",
        (username,),
    )
    row = c.fetchone()

    if not row:
        latency = (datetime.utcnow() - start).microseconds // 1000
        _log_login_attempt(username, "sha256", "FAILED", latency)
        raise AppError("Invalid credentials", 401)

    stored_hash, salt, hash_mode, totp_secret = row
    if _is_password_matching(password, salt, stored_hash, method=hash_mode):
        latency = (datetime.utcnow() - start).microseconds // 1000
        _log_login_attempt(username, hash_mode, "SUCCESS", latency)
        return jsonify({"status": "login success"}), 200
    else:
        latency = (datetime.utcnow() - start).microseconds // 1000
        _log_login_attempt(username, hash_mode, "FAILED", latency)
        register_failure(username)
        raise AppError("Invalid credentials", 401)
