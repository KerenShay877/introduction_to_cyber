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
from app.auth.auth import login_user
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
    return login_user(username, password)


@app.route("/login_totp", methods=["POST"])
def login_totp():
    return jsonify({"status": "not implemented"}), 501


if __name__ == "__main__":
    with app.app_context():
        db = get_db()
        init_db(db)
    app.run(debug=False)
