"""
API monitoring module for OmicsOracle.

This module provides middleware and utilities for monitoring API requests and responses.
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class APIMonitoringMiddleware(BaseHTTPMiddleware):
    """Middleware for monitoring API requests and responses."""
    
    def __init__(
        self, 
        app: FastAPI, 
        log_to_file: bool = True, 
        log_dir: str = "logs",
        exclude_paths: List[str] = None
    ):
        """Initialize the middleware."""
        super().__init__(app)
        self.log_to_file = log_to_file
        self.log_dir = Path(log_dir)
        self.exclude_paths = exclude_paths or ["/static", "/favicon.ico"]
        
        # Statistics
        self.request_count = 0
        self.error_count = 0
        self.start_time = time.time()
        self.endpoint_stats: Dict[str, Dict[str, Any]] = {}
        
        # Ensure log directory exists
        if self.log_to_file:
            self.log_dir.mkdir(exist_ok=True)
            self.request_log_file = self.log_dir / "api_requests.jsonl"
            self.stats_file = self.log_dir / "api_stats.json"
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request and log data."""
        # Skip static files and excluded paths
        path = request.url.path
        if any(path.startswith(excluded) for excluded in self.exclude_paths):
            return await call_next(request)
        
        # Start timing
        start_time = time.time()
        request_id = f"{int(start_time)}-{self.request_count}"
        self.request_count += 1
        
        # Extract request information
        request_info = {
            "request_id": request_id,
            "method": request.method,
            "path": path,
            "query_params": dict(request.query_params),
            "client": request.client.host if request.client else None,
            "timestamp": start_time,
            "timestamp_readable": datetime.fromtimestamp(start_time).strftime("%Y-%m-%d %H:%M:%S.%f")
        }
        
        # Log request body for POST/PUT requests, but handle with care
        if request.method in ["POST", "PUT"]:
            try:
                # Clone the request to avoid consuming it
                body = await request.body()
                request_info["body_size"] = len(body)
                
                # Try to parse as JSON
                try:
                    # Limit body size for logging
                    max_body_size = 1024 * 10  # 10KB
                    if len(body) <= max_body_size:
                        body_str = body.decode("utf-8")
                        try:
                            json_body = json.loads(body_str)
                            # Only log specific fields or truncate large objects
                            if isinstance(json_body, dict):
                                safe_body = {}
                                for key, value in json_body.items():
                                    # Skip large values or sensitive fields
                                    if key.lower() in ["password", "token", "secret", "key"]:
                                        safe_body[key] = "***REDACTED***"
                                    elif isinstance(value, str) and len(value) > 100:
                                        safe_body[key] = value[:100] + "... [truncated]"
                                    else:
                                        safe_body[key] = value
                                request_info["body"] = safe_body
                        except json.JSONDecodeError:
                            # Not JSON, just truncate if needed
                            if len(body_str) > 100:
                                request_info["body"] = body_str[:100] + "... [truncated]"
                            else:
                                request_info["body"] = body_str
                except Exception as e:
                    request_info["body_error"] = str(e)
            except Exception as e:
                request_info["body_error"] = str(e)
        
        # Process the request
        try:
            response = await call_next(request)
            status_code = response.status_code
            
            # Update endpoint stats
            if path not in self.endpoint_stats:
                self.endpoint_stats[path] = {
                    "count": 0,
                    "error_count": 0,
                    "total_time": 0,
                    "min_time": float("inf"),
                    "max_time": 0,
                    "status_codes": {}
                }
            
            # Calculate response time
            response_time = time.time() - start_time
            
            # Update stats
            endpoint_stat = self.endpoint_stats[path]
            endpoint_stat["count"] += 1
            endpoint_stat["total_time"] += response_time
            endpoint_stat["min_time"] = min(endpoint_stat["min_time"], response_time)
            endpoint_stat["max_time"] = max(endpoint_stat["max_time"], response_time)
            
            # Track status codes
            status_str = str(status_code)
            if status_str not in endpoint_stat["status_codes"]:
                endpoint_stat["status_codes"][status_str] = 0
            endpoint_stat["status_codes"][status_str] += 1
            
            # Count errors
            if status_code >= 400:
                endpoint_stat["error_count"] += 1
                self.error_count += 1
            
            # Create response info
            response_info = {
                "status_code": status_code,
                "response_time": response_time,
            }
            
            # Try to get response headers
            try:
                response_info["headers"] = dict(response.headers)
            except Exception as e:
                response_info["headers_error"] = str(e)
            
            # Combine request and response info
            log_entry = {
                **request_info,
                "response": response_info,
                "error": status_code >= 400
            }
            
            # Log to file
            if self.log_to_file:
                with open(self.request_log_file, "a") as f:
                    f.write(json.dumps(log_entry) + "\n")
                
                # Update stats file occasionally
                if self.request_count % 10 == 0:
                    self.update_stats_file()
            
            # Log to console for errors
            if status_code >= 400:
                logger.warning(f"API Error: {path} - {status_code}")
            
            return response
        except Exception as e:
            # Handle errors in middleware
            logger.error(f"Middleware Error: {str(e)}")
            
            # Count error
            self.error_count += 1
            
            # Update endpoint stats
            if path in self.endpoint_stats:
                self.endpoint_stats[path]["error_count"] += 1
            
            # Log error
            log_entry = {
                **request_info,
                "error": True,
                "error_message": str(e),
                "error_type": type(e).__name__
            }
            
            # Log to file
            if self.log_to_file:
                with open(self.request_log_file, "a") as f:
                    f.write(json.dumps(log_entry) + "\n")
            
            # Re-raise to let FastAPI handle it
            raise
    
    def update_stats_file(self) -> None:
        """Update the stats file with current statistics."""
        if not self.log_to_file:
            return
        
        # Calculate overall stats
        total_time = time.time() - self.start_time
        avg_response_time = sum(
            stat["total_time"] for stat in self.endpoint_stats.values()
        ) / max(1, self.request_count)
        
        # Create stats object
        stats = {
            "request_count": self.request_count,
            "error_count": self.error_count,
            "uptime": total_time,
            "uptime_readable": str(datetime.fromtimestamp(time.time()) - datetime.fromtimestamp(self.start_time)),
            "avg_response_time": avg_response_time,
            "endpoints": {
                path: {
                    **stat,
                    "avg_time": stat["total_time"] / stat["count"] if stat["count"] > 0 else 0
                }
                for path, stat in self.endpoint_stats.items()
            },
            "timestamp": time.time(),
            "timestamp_readable": datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Write to file
        with open(self.stats_file, "w") as f:
            json.dump(stats, f, indent=2)


def setup_api_monitoring(app: FastAPI, log_dir: str = "logs") -> None:
    """Set up API monitoring for a FastAPI app."""
    app.add_middleware(
        APIMonitoringMiddleware,
        log_to_file=True,
        log_dir=log_dir
    )
    logger.info(f"API monitoring set up with logs in {log_dir}")


def get_api_stats(log_dir: str = "logs") -> Dict[str, Any]:
    """Get API stats from the stats file."""
    stats_file = Path(log_dir) / "api_stats.json"
    
    if not stats_file.exists():
        return {
            "request_count": 0,
            "error_count": 0,
            "uptime": 0,
            "uptime_readable": "0:00:00",
            "avg_response_time": 0,
            "endpoints": {},
            "timestamp": time.time(),
            "timestamp_readable": datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M:%S")
        }
    
    try:
        with open(stats_file, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error reading API stats: {e}")
        return {
            "error": str(e),
            "timestamp": time.time(),
            "timestamp_readable": datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M:%S")
        }
