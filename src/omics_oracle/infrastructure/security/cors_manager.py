"""
CORS Manager

Provides CORS (Cross-Origin Resource Sharing) management:
- Origin validation
- Headers configuration
- Preflight handling
- Security-focused CORS policies
"""

import logging
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class CORSConfig:
    """Configuration for CORS policies."""

    allowed_origins: List[str] = None
    allowed_methods: List[str] = None
    allowed_headers: List[str] = None
    expose_headers: List[str] = None
    allow_credentials: bool = False
    max_age: int = 86400  # 24 hours

    def __post_init__(self):
        if self.allowed_origins is None:
            self.allowed_origins = ["*"]
        if self.allowed_methods is None:
            self.allowed_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        if self.allowed_headers is None:
            self.allowed_headers = ["*"]
        if self.expose_headers is None:
            self.expose_headers = []


class CORSManager:
    """CORS management system."""

    def __init__(self, config: Optional[CORSConfig] = None):
        self.config = config or CORSConfig()

    def is_origin_allowed(self, origin: str) -> bool:
        """Check if origin is allowed."""
        if "*" in self.config.allowed_origins:
            return True
        return origin in self.config.allowed_origins

    def get_cors_headers(self, origin: Optional[str] = None) -> dict:
        """Get CORS headers for response."""
        headers = {}

        if origin and self.is_origin_allowed(origin):
            headers["Access-Control-Allow-Origin"] = origin
        elif "*" in self.config.allowed_origins:
            headers["Access-Control-Allow-Origin"] = "*"

        headers["Access-Control-Allow-Methods"] = ", ".join(
            self.config.allowed_methods
        )
        headers["Access-Control-Allow-Headers"] = ", ".join(
            self.config.allowed_headers
        )

        if self.config.expose_headers:
            headers["Access-Control-Expose-Headers"] = ", ".join(
                self.config.expose_headers
            )

        if self.config.allow_credentials:
            headers["Access-Control-Allow-Credentials"] = "true"

        headers["Access-Control-Max-Age"] = str(self.config.max_age)

        return headers
