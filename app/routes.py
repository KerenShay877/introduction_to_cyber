"""
Flask routes for demo app
"""

from flask import Flask, request, jsonify, render_template, g
import sqlite3, json, os, sys
from datetime import datetime
import logging
from app.config import (
    GROUP_SEED,
    HASH_METHOD,
    DEFENSE_METHODS,
    PEPPER,
    DB_PATH,
    LOG_PATH,
)
from app.auth.auth import password_hash, verification_password
from app.db import get_db, close_db, init_db
from app.exceptions import AppError, handle_app_error
from app.logger_setup import configure_logging
from app.auth.register import register_new_user

configure_logging()
logger = logging.getLogger("app_logger")
app = Flask(__name__)
app.register_error_handler(AppError, handle_app_error)


@app.teardown_appcontext
def close_db_connection(exception):
    """Close db gracefully"""
    close_db()


def log_attempt(username, hash_mode, protection_flags, result, latency_ms):
    entry = {
        "group_seed": GROUP_SEED,
        "username": username,
        "hash_mode": hash_mode,
        "protection_flags": protection_flags,
        "result": result,
        "latency_ms": latency_ms,
    }
    logger.info("Login attempt recorded", extra={"payload": entry})


@app.route("/")
def home_page():
    return render_template("index.html")


@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    enable_totp = data.get("enable_totp", False)

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    salt = os.urandom(16).hex()
    password_hashed = password_hash(password, salt, method=HASH_METHOD)
    totp_secret = os.urandom(16).hex() if enable_totp else None

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO users (username, password_hash, salt, hash_mode, totp_secret) VALUES (?,?,?,?,?)",
            (username, password_hashed, salt, HASH_METHOD, totp_secret)
        )
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400

    return jsonify({"status": "registered", "username": username, "totp_secret": totp_secret}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    start = datetime.utcnow()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT hash, salt, hash_mode, totp_secret FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if not row:
        latency = (datetime.utcnow() - start).microseconds // 1000
        log_attempt(username, "sha256", [], "FAILED", latency)
        return jsonify({"error": "Invalid credentials"}), 401

    stored_hash, salt, hash_mode, totp_secret = row
    if verification_password(password, salt, stored_hash, method=hash_mode):
        latency = (datetime.utcnow() - start).microseconds // 1000
        log_attempt(username, hash_mode, [], "SUCCESS", latency)
        return jsonify({"status": "login success"}), 200
    else:
        latency = (datetime.utcnow() - start).microseconds // 1000
        log_attempt(username, hash_mode, [], "FAILED", latency)
        return jsonify({"error": "Invalid credentials"}), 401

@app.route("/login_totp", methods=["POST"])
def login_totp():
    return jsonify({"status": "not implemented"}), 501


if __name__ == "__main__":
    with app.app_context():
        db = get_db()
        init_db(db)
    app.run(debug=False)
