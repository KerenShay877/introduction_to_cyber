# rate limit, captcha, lockout, pepper

import time
import uuid
from collections import defaultdict
from app.config import (
    DEFENSE_METHODS,
    RATE_LIMIT_MAX_ATTEMPTS,
    RATE_LIMIT_WINDOW_SEC,
    LOCKOUT_THRESHOLD,
    LOCKOUT_DURATION_SEC,
    CAPTCHA_SECRET,
    PEPPER,
)

_rate_limit_tracker = defaultdict(list)     
_lockout_tracker = defaultdict(lambda: {"fails": 0, "locked_until": 0})
_captcha_tracker = defaultdict(int)           
_captcha_tokens = {}                          

def check_rate_limit(ip: str) -> bool:
    """Return False if IP exceeded rate limit, True otherwise."""
    if not DEFENSE_METHODS.get("rate_limit", False):
        return True

    now = time.time()
    attempts = [t for t in _rate_limit_tracker[ip] if now - t < RATE_LIMIT_WINDOW_SEC]
    _rate_limit_tracker[ip] = attempts

    if len(attempts) >= RATE_LIMIT_MAX_ATTEMPTS:
        return False

    _rate_limit_tracker[ip].append(now)
    return True

def check_lockout(username: str) -> bool:
    """Return False if account is locked, True otherwise."""
    if not DEFENSE_METHODS.get("lockout", False):
        return True

    now = time.time()
    info = _lockout_tracker[username]
    return now >= info["locked_until"]

def register_failure(username: str):
    """Increment failure count and lock account if threshold exceeded."""
    if not DEFENSE_METHODS.get("lockout", False):
        return

    info = _lockout_tracker[username]
    info["fails"] += 1
    if info["fails"] >= LOCKOUT_THRESHOLD:
        info["locked_until"] = time.time() + LOCKOUT_DURATION_SEC
        info["fails"] = 0

def require_captcha(username: str) -> bool:
    """
    Return True if captcha is required for this user.
    After threshold of failures, captcha_required is triggered.
    """
    if not DEFENSE_METHODS.get("captcha", False):
        return False

    _captcha_tracker[username] += 1
    return _captcha_tracker[username] >= LOCKOUT_THRESHOLD 

def get_captcha_token(group_seed: int, username: str) -> str:
    """Generate a fresh captcha token each time."""
    token = f"captcha_{group_seed}_{CAPTCHA_SECRET}_{uuid.uuid4().hex}"
    _captcha_tokens[username] = token
    return token

def validate_captcha_token(username: str, token: str) -> bool:
    """Check if the provided token matches the stored one."""
    return _captcha_tokens.get(username) == token

def apply_pepper(password: str) -> str:
    """
    Append global pepper to password if enabled.
    """
    if DEFENSE_METHODS.get("pepper", False) and PEPPER:
        return password + PEPPER
    return password
