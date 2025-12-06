import sqlite3
from flask import g
from app.config import DB_PATH


def init_db(db: sqlite3.Connection):
    c = db.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            salt TEXT,
            hash_mode TEXT,
            totp_secret TEXT
        )
    """
    )
    db.commit()


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        print("Connecting to DB at", DB_PATH)
        db = g._database = sqlite3.connect(DB_PATH)
        
    return db


def close_db():
    """Close db gracefully"""
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()
