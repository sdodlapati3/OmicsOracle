"""
Middleware setup for FastAPI application.

This module configures all middleware layers including security,
logging, error handling, and performance monitoring.
"""

import logging
import time
import uuid
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from ....core.config import Config

logger = logging.getLogger(__name__)


def setup_middleware(app: FastAPI, config: Config) -> None:
    """Setup all middleware for the application."""

    # Add request ID middleware
    app.middleware("http")(add_request_id_middleware)

    # Add API versioning middleware
    app.middleware("http")(api_versioning_middleware)

    # Add logging middleware
    app.middleware("http")(logging_middleware)

    # Add security headers middleware
    app.middleware("http")(security_headers_middleware)

    # Add performance monitoring middleware
    app.middleware("http")(performance_monitoring_middleware)

    # Add error handling middleware
    app.middleware("http")(error_handling_middleware)

    logger.info("All middleware configured successfully")


async def add_request_id_middleware(request: Request, call_next: Callable) -> Response:
    """Add unique request ID to each request."""
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id

    return response


async def api_versioning_middleware(request: Request, call_next: Callable) -> Response:
    """Handle API versioning logic and add version headers."""
    # Extract version from URL path or headers
    version = "1.0"  # Default version

    if request.url.path.startswith("/api/v2/"):
        version = "2.0"
    elif request.url.path.startswith("/api/v1/"):
        version = "1.0"
    elif "X-API-Version" in request.headers:
        version = request.headers.get("X-API-Version", "1.0")

    # Store version in request state
    request.state.api_version = version

    response = await call_next(request)

    # Add version headers to response
    response.headers["X-API-Version"] = version
    response.headers["X-API-Supported-Versions"] = "1.0,2.0"

    # Add deprecation warnings for old versions
    if version == "1.0":
        response.headers[
            "X-API-Deprecation-Warning"
        ] = "API v1.0 will be deprecated in 6 months. Please migrate to v2.0"
        response.headers["X-API-Migration-Guide"] = "/docs/migration/v1-to-v2"

    return response


async def logging_middleware(request: Request, call_next: Callable) -> Response:
    """Log request and response information."""
    start_time = time.time()
    request_id = getattr(request.state, "request_id", "unknown")

    # Log request
    logger.info(
        f"Request started - ID: {request_id}, Method: {request.method}, "
        f"URL: {request.url}, Client: {request.client.host if request.client else 'unknown'}"
    )

    try:
        response = await call_next(request)
        process_time = time.time() - start_time

        # Log response
        logger.info(
            f"Request completed - ID: {request_id}, Status: {response.status_code}, "
            f"Time: {process_time:.3f}s"
        )

        return response

    except Exception as e:
        process_time = time.time() - start_time
        logger.error(f"Request failed - ID: {request_id}, Error: {str(e)}, " f"Time: {process_time:.3f}s")
        raise


async def security_headers_middleware(request: Request, call_next: Callable) -> Response:
    """Add security headers to responses."""
    response = await call_next(request)

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "connect-src 'self' ws: wss:; "
        "font-src 'self'"
    )

    # HSTS header for HTTPS
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


async def performance_monitoring_middleware(request: Request, call_next: Callable) -> Response:
    """Monitor performance and add timing headers."""
    start_time = time.time()

    response = await call_next(request)

    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)

    # Log slow requests
    if process_time > 2.0:  # 2 seconds threshold
        request_id = getattr(request.state, "request_id", "unknown")
        logger.warning(
            f"Slow request detected - ID: {request_id}, "
            f"URL: {request.url.path}, Time: {process_time:.3f}s"
        )

    return response


# Error handling middleware
async def error_handling_middleware(request: Request, call_next: Callable) -> Response:
    """Global error handling middleware."""
    try:
        return await call_next(request)
    except Exception as e:
        request_id = getattr(request.state, "request_id", "unknown")
        logger.exception(f"Unhandled error - ID: {request_id}, Error: {str(e)}")

        # Return generic error response
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error",
                "request_id": request_id,
            },
        )
