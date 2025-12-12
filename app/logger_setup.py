"""Set up global logger
"""

import logging
import json
import os
from datetime import datetime
from app.config import LOG_PATH, GROUP_SEED

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "group_seed": GROUP_SEED,
        }
        if hasattr(record, 'payload'):
            log_record.update(record.payload)
        return json.dumps(log_record)

def configure_logging():
    """Log Info to file in json format and errors to screen and file 
    """
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    logger = logging.getLogger("app_logger")
    logger.setLevel(logging.INFO)

    if logger.hasHandlers():
        logger.handlers.clear()

    file_handler = logging.FileHandler(LOG_PATH)
    file_handler.setFormatter(JsonFormatter())
    file_handler.setLevel(logging.INFO)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logger.addHandler(console_handler)

    return logger
