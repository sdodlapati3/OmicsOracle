"""
Dependency injection container for the application.

This module provides a centralized way to configure and manage
application dependencies following the dependency injection pattern.
"""

from .container import Container
from .providers import create_container

# Alias for backward compatibility
DIContainer = Container

__all__ = ["Container", "DIContainer", "create_container"]
