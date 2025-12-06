"""
Authentictation utils for the demo app.
"""

import bcrypt
import hashlib
from argon2 import PasswordHasher
from app.config import PEPPER

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


def verification_password(password: str, salt: str, hash_stored: str, method: str = "sha256") -> bool:
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