"""
Logging configuration for OmicsOracle.

This module provides structured logging capabilities with:
- JSON formatted logs for production
- Console logging for development
- Configurable log levels and outputs
"""

import json
import logging
import logging.handlers
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception information if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data, default=str)


def setup_logging(
    level: str = "INFO", log_file: Optional[str] = None, use_json: bool = False
) -> None:
    """Set up logging configuration.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        use_json: Whether to use JSON formatting
    """
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Clear existing handlers
    root_logger.handlers.clear()

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)

    if use_json:
        console_handler.setFormatter(JSONFormatter())
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        console_handler.setFormatter(formatter)

    root_logger.addHandler(console_handler)

    # Add file handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=10 * 1024 * 1024, backupCount=5  # 10MB
        )
        file_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(file_handler)

    # Reduce noise from third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get logger instance.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    return logging.getLogger(name or __name__)


# Initialize basic logging
setup_logging()
