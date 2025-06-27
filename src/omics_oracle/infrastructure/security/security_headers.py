"""
Security Headers Middleware

Provides comprehensive security headers management:
- Content Security Policy (CSP)
- HSTS (HTTP Strict Transport Security)
- XSS protection headers
- Clickjacking protection
"""

import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware:
    """Middleware for adding security headers to responses."""

    def __init__(
        self,
        enable_csp: bool = True,
        enable_hsts: bool = True,
        enable_xss_protection: bool = True,
        enable_clickjacking_protection: bool = True,
        custom_headers: Optional[Dict[str, str]] = None,
    ):
        self.enable_csp = enable_csp
        self.enable_hsts = enable_hsts
        self.enable_xss_protection = enable_xss_protection
        self.enable_clickjacking_protection = enable_clickjacking_protection
        self.custom_headers = custom_headers or {}

    def get_security_headers(self) -> Dict[str, str]:
        """Get all security headers."""
        headers = {}

        if self.enable_csp:
            headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' https:; "
                "connect-src 'self' https:; "
                "frame-ancestors 'none'"
            )

        if self.enable_hsts:
            headers[
                "Strict-Transport-Security"
            ] = "max-age=31536000; includeSubDomains"

        if self.enable_xss_protection:
            headers["X-XSS-Protection"] = "1; mode=block"
            headers["X-Content-Type-Options"] = "nosniff"

        if self.enable_clickjacking_protection:
            headers["X-Frame-Options"] = "DENY"

        # Add referrer policy
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Add permissions policy
        headers[
            "Permissions-Policy"
        ] = "camera=(), microphone=(), geolocation=(), payment=()"

        # Add custom headers
        headers.update(self.custom_headers)

        return headers

    async def __call__(self, request, call_next):
        """Apply security headers to response."""
        response = await call_next(request)

        security_headers = self.get_security_headers()

        if hasattr(response, "headers"):
            for header, value in security_headers.items():
                response.headers[header] = value

        return response
