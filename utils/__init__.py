"""
Utils package.

Shared, cross-cutting helpers used across the application, such as
logging configuration.
"""

from .logger_config import setup_logging

__all__ = ["setup_logging"]
