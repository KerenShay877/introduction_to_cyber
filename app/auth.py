# hashing functions and verification
# yotam and shay
import bcrypt
import hashlib
from argon2 import PasswordHasher
from config import PEPPER

def password_hash(password: str, salt: str, method: str = "sha256") -> str:
    """
        Take a password and hash it according to each hashing method
        PEPPER is only added if it's on
    """
    pwd = password + PEPPER
    
    if method == "sha256":
        return hashlib.sha256((pwd + salt).encode()).hexdigest()

    elif method == "bcrypt":
        return bcrypt.hashpw((pwd + salt).encode(), bcrypt.gensalt()).decode()

    elif method == "argon2id":
        ph = PasswordHasher()
        return ph.hash(pwd + salt)

    else:
        raise ValueError(f"Hash method not supported: {method}")
    
def verification_password(password: str, salt: str, hash_stored: str, method: str = "sha256") -> bool:
    """
       Verify a password with hash that is already stored according to each hashing method 
    """
    pwd = password + PEPPER
    
    if method == "sha256":
        return hashlib.sha256((pwd + salt).encode()).hexdigest() == hash_stored

    elif method == "bcrypt":
        try:
            return bcrypt.checkpw((pwd + salt).encode(), hash_stored.encode())
        except Exception:
            return False

    elif method == "argon2id":
        ph = PasswordHasher()
        try:
            ph.verify(hash_stored, pwd + salt)
            return True
        except Exception:
            return False

    else:
        raise ValueError(f"Hash method not supported: {method}")