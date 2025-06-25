"""
Logging configuration for OmicsOracle modern interface
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional


def setup_logging(
    log_level: str = "INFO",
    log_dir: Optional[Path] = None,
    app_name: str = "omics_oracle",
) -> logging.Logger:
    """
    Set up logging configuration for the application

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory for log files (if None, logs to stdout only)
        app_name: Name of the application for log file naming

    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger(app_name)
    logger.setLevel(getattr(logging, log_level.upper()))

    # Clear existing handlers to avoid duplicates
    logger.handlers.clear()

    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, log_level.upper()))
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (if log_dir provided)
    if log_dir:
        log_dir.mkdir(exist_ok=True)

        # Main log file
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / f"{app_name}.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
        )
        file_handler.setLevel(getattr(logging, log_level.upper()))
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # Error log file
        error_handler = logging.handlers.RotatingFileHandler(
            log_dir / f"{app_name}_errors.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        logger.addHandler(error_handler)

    # Prevent propagation to root logger
    logger.propagate = False

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the specified name"""
    return logging.getLogger(f"omics_oracle.{name}")


# Specialized loggers for different components
def get_api_logger() -> logging.Logger:
    """Get logger for API components"""
    return get_logger("api")


def get_search_logger() -> logging.Logger:
    """Get logger for search components"""
    return get_logger("search")


def get_service_logger() -> logging.Logger:
    """Get logger for service components"""
    return get_logger("service")


def get_model_logger() -> logging.Logger:
    """Get logger for model components"""
    return get_logger("model")
