"""
Helper functions for generating and verifying TOTP secrets and codes
"""

import pyotp

def generate_totp_secret() -> str:
    """Generate a new random base32 secret for a user."""
    return pyotp.random_base32()

def get_current_token(secret: str) -> str:
    """Return the current valid TOTP token for a given secret."""
    totp = pyotp.TOTP(secret)
    return totp.now()

def verify_token(secret: str, code: str) -> bool:
    """Verify a given TOTP code against the secret."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)
