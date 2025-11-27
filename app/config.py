# configuration file
import os

GROUP_SEED = int(os.environ.get("GROUP_SEED", "532645069"))
# PEPPER = os.environ.get("PEPPER", "Qz@N2oY#rN8wP!1qT0s^Rtl9Z%6nLqZ") # pepper for protection
PEPPER = os.environ.get("PEPPER", "") # pepper for basic defences
HASH_METHOD = os.environ.get("HASH_METHOD", "sha256")

DB_PATH = os.environ.get("DB_PATH", "data/registered_users.db")
LOG_PATH = os.environ.get("LOG_PATH", "logs/attempts.log")

DEFENSE_METHODS = {
    "totp": False,
    "captcha": False,
    "lockout": False, 
    "rate_limit": False,
    "pepper": False,
}

# Defence methods limits
TOTP_TIMEOUT = int(os.environ.get("TOTP_TIMEOUT", "30"))
RATE_LIMIT_MAX_ATTEMPTS = int(os.environ.get("RATE_LIMIT_MAX_ATTEMPTS", "5"))
RATE_LIMIT_WINDOW_SEC = int(os.environ.get("RATE_LIMIT_WINDOW_SEC", "60"))
LOCKOUT_THRESHOLD = int(os.environ.get("LOCKOUT_THRESHOLD", "3"))
LOCKOUT_DURATION_SEC = int(os.environ.get("LOCKOUT_DURATION_SEC", "300"))
CAPTCHA_SECRET = os.environ.get("CAPTCHA_SECRET", str(GROUP_SEED))