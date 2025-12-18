"""
Registration functions
"""
from app.db import get_db
from app.exceptions import AppError
import logging
import sqlite3
import os
from flask import jsonify

from app.config import HASH_METHOD
from .auth import password_hash
logger = logging.getLogger("app_logger")
class Registration:
    """
    User registration endpoint
    """
    def __init__(self, username: str, password: str, enable_totp: bool = False):
        self._username = username
        self._password = password
        self._enable_totp = enable_totp
    def apply_to_db(self, db):
        salt = os.urandom(16).hex()
        password_hashed = password_hash(self._password, salt, method=HASH_METHOD)
        totp_secret = os.urandom(16).hex() if self._enable_totp else None
        c = db.cursor()
        c.execute(
            "INSERT INTO users (username, password_hash, salt, hash_mode, totp_secret) VALUES (?,?,?,?,?)",
            (self._username, password_hashed, salt, HASH_METHOD, totp_secret)
        )
        db.commit()
        return totp_secret
        
        
def register_new_user(request_data):

    username = request_data.get("username")
    password = request_data.get("password")
    enable_totp = request_data.get("enable_totp", False)

    if not username or not password:
        raise AppError("Missing username or password", status_code=400)

    db = get_db()
    
    try:
        registration = Registration(username, password, enable_totp)
        totp_secret = registration.apply_to_db(db)
        
    except sqlite3.IntegrityError:
        raise AppError("Username already exists", 400)

    logger.info(f"New user registered: {username}", extra={"username": username, "enable_totp": enable_totp})
    return jsonify({"status": "registered", "username": username, "totp_secret": totp_secret}), 201
