from flask import Flask, request, jsonify, render_template, g
import sqlite3
import logging
import pyotp
from datetime import datetime
from app.config import GROUP_SEED, DEFENSE_METHODS, DB_PATH
from app.auth.auth import login_user, _is_password_matching
from app.db import get_db, close_db, init_db
from app.exceptions import AppError, handle_app_error
from app.logger_setup import configure_logging
from app.auth.register import register_new_user
from app import protections

configure_logging()
logger = logging.getLogger("app_logger")
app = Flask(__name__)
app.register_error_handler(AppError, handle_app_error)


@app.teardown_appcontext
def close_db_connection(exception):
    close_db()


@app.route("/")
def home_page():
    return render_template("index.html")


@app.route("/register", methods=["POST"])
def register():
    data = request.json
    return register_new_user(data)


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not protections.check_rate_limit(request.remote_addr):
        return jsonify({"error": "Rate limit exceeded"}), 429

    if not protections.check_lockout(username):
        return jsonify({"error": "Account locked"}), 403

    if protections.require_captcha(username):
        token = protections.get_captcha_token(GROUP_SEED)
        return jsonify({"captcha_required": True, "captcha_token": token}), 403

    result = login_user(username, password)
    if result.status_code != 200:
        protections.register_failure(username)
    return result


@app.route("/login_totp", methods=["POST"])
def login_totp():
    start = datetime.utcnow()
    data = request.json
    username = data.get("username")
    password = data.get("password")
    totp_code = data.get("totp")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash, salt, hash_mode, totp_secret FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if not row:
        protections.register_failure(username)
        return jsonify({"error": "Invalid credentials"}), 401

    stored_hash, salt, hash_mode, totp_secret = row
    if _is_password_matching(password, salt, stored_hash, method=hash_mode):
        if DEFENSE_METHODS.get("totp", False) and totp_secret:
            totp = pyotp.TOTP(totp_secret)
            if not totp.verify(totp_code):
                return jsonify({"error": "Invalid TOTP"}), 401
        latency = (datetime.utcnow() - start).microseconds // 1000
        logger.info("Login attempt", extra={"payload": {
            "group_seed": GROUP_SEED,
            "username": username,
            "hash_mode": hash_mode,
            "protection_flags": [k for k,v in DEFENSE_METHODS.items() if v],
            "result": "SUCCESS",
            "latency_ms": latency
        }})
        return jsonify({"status": "login success"}), 200

    protections.register_failure(username)
    latency = (datetime.utcnow() - start).microseconds // 1000
    logger.info("Login attempt", extra={"payload": {
        "group_seed": GROUP_SEED,
        "username": username,
        "hash_mode": hash_mode,
        "protection_flags": [k for k,v in DEFENSE_METHODS.items() if v],
        "result": "FAILED",
        "latency_ms": latency
    }})
    return jsonify({"error": "Invalid credentials"}), 401


if __name__ == "__main__":
    with app.app_context():
        db = get_db()
        init_db(db)
    app.run(debug=False)
