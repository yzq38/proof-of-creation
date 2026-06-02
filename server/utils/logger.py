import logging
import os
from datetime import datetime

_logger = None


def setup_logger(log_dir: str, level: str = "INFO"):
    global _logger
    os.makedirs(log_dir, exist_ok=True)

    _logger = logging.getLogger("PoC")
    _logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    _logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    _logger.addHandler(console_handler)

    log_file = os.path.join(log_dir, f"poc-{datetime.now().strftime('%Y%m%d')}.log")
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    _logger.addHandler(file_handler)

    return _logger


def get_logger():
    return _logger or logging.getLogger("PoC")
