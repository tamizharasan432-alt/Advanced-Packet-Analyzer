"""
utils/logger_config.py

Centralized logging configuration for the Advanced Packet Analyzer.

All application modules log through the "packet_analyzer" logger
namespace instead of using print(), so log output is timestamped,
leveled, and captured to both the console and a rotating log file.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_logging(
    log_dir: str | Path = "logs",
    log_filename: str = "analyzer.log",
    level: int = logging.INFO,
) -> logging.Logger:
    """
    Configure and return the root application logger.

    Sets up two handlers:
        - A console (stream) handler for real-time feedback.
        - A rotating file handler that writes to logs/analyzer.log,
          capped at 2 MB per file with 3 backups kept.

    Args:
        log_dir: Directory in which to create the log file. Created if
            it does not already exist.
        log_filename: Name of the log file.
        level: The minimum logging level to capture.

    Returns:
        The configured "packet_analyzer" Logger instance.
    """
    log_dir_path = Path(log_dir)
    log_dir_path.mkdir(parents=True, exist_ok=True)
    log_file_path = log_dir_path / log_filename

    logger = logging.getLogger("packet_analyzer")
    logger.setLevel(level)
    logger.propagate = False

    # Avoid adding duplicate handlers if setup_logging is called twice
    # (e.g. during tests).
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    file_handler = RotatingFileHandler(
        log_file_path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    logger.debug("Logging initialized. Writing to %s", log_file_path)
    return logger
