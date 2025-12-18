"""
Logs setup
"""

from flask import jsonify
import logging

logger = logging.getLogger("app_logger")
class AppError(Exception):
    def __init__(self, message: str, status_code: int = 400, user_data: dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.user_data = user_data
        self.message = message
        
    def to_dict(self):
        return {"error": self.message}


def handle_app_error(error: AppError):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    if error.user_data:
        logger.error(f"AppError: {error.message}, status: {error.status_code}\nExtra Info:\n{error.user_data}")
    else:
        logger.error(f"AppError: {error.message}, status: {error.status_code}")
    return response