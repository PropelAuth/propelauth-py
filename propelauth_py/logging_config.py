"""
Logging configuration for the PropelAuth library.

This module provides functionality to control the logging behavior of the PropelAuth library.
"""

import logging

# Create a default logger for the library
logger = logging.getLogger("propelauth")

# Default configuration
_config = {
    "log_exceptions": False,  # Whether to log exceptions with logger.exception
}


def configure_logging(log_exceptions=None):
    """
    Configure the logging behavior of the PropelAuth library.

    Args:
        log_exceptions: Boolean, whether to log exceptions with logger.exception
                        (defaults to None, which means don't change the current setting)
    """
    if log_exceptions is not None:
        _config["log_exceptions"] = bool(log_exceptions)


def should_log_exceptions():
    """
    Check if exceptions should be logged.

    Returns:
        Boolean indicating whether exceptions should be logged.
    """
    return _config["log_exceptions"]


def get_logger():
    """
    Get the PropelAuth logger.

    Returns:
        The logger instance for the PropelAuth library.
    """
    return logger
