"""
Enhanced Logging Service for Futuristic Interface

Provides structured logging with different levels, file rotation,
and real-time updates for the futuristic interface
"""

import logging
import logging.handlers
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List


class LogLevel(str, Enum):
    """Log levels"""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class FuturisticLogger:
    """Enhanced logger with real-time updates and structured logging"""

    def __init__(self, name: str = "FuturisticInterface"):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)

        # Real-time update callbacks
        self.update_callbacks: List[Callable] = []

        # Log statistics
        self.log_stats = {"info": 0, "warning": 0, "error": 0, "critical": 0}

        self._setup_handlers()

    def _setup_handlers(self):
        """Setup file and console handlers"""

        # Create logs directory if it doesn't exist
        log_dir = Path(__file__).parent.parent.parent.parent / "logs"
        log_dir.mkdir(exist_ok=True)

        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / "futuristic_interface.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
        )
        file_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(file_formatter)

        # Console handler
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter("%(levelname)s: %(message)s")
        console_handler.setFormatter(console_formatter)

        # Add handlers if not already added
        if not self.logger.handlers:
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)

    def add_update_callback(self, callback: Callable):
        """Add callback for real-time log updates"""
        self.update_callbacks.append(callback)

    async def _send_update(self, level: str, message: str, extra: Dict = None):
        """Send real-time update to all callbacks"""
        update_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": message,
            "logger": self.name,
            "extra": extra or {},
        }

        for callback in self.update_callbacks:
            try:
                await callback(update_data)
            except Exception as e:
                # Avoid infinite recursion by using standard logger
                logging.error(f"Error sending log update: {e}")

    def info(self, message: str, extra: Dict = None):
        """Log info message"""
        self.logger.info(message)
        self.log_stats["info"] += 1
        # Send async update (fire and forget)
        try:
            import asyncio

            loop = asyncio.get_event_loop()
            loop.create_task(self._send_update("INFO", message, extra))
        except Exception:
            pass

    def warning(self, message: str, extra: Dict = None):
        """Log warning message"""
        self.logger.warning(message)
        self.log_stats["warning"] += 1
        try:
            import asyncio

            loop = asyncio.get_event_loop()
            loop.create_task(self._send_update("WARNING", message, extra))
        except Exception:
            pass

    def error(self, message: str, extra: Dict = None):
        """Log error message"""
        self.logger.error(message)
        self.log_stats["error"] += 1
        try:
            import asyncio

            loop = asyncio.get_event_loop()
            loop.create_task(self._send_update("ERROR", message, extra))
        except Exception:
            pass

    def critical(self, message: str, extra: Dict = None):
        """Log critical message"""
        self.logger.critical(message)
        self.log_stats["critical"] += 1
        try:
            import asyncio

            loop = asyncio.get_event_loop()
            loop.create_task(self._send_update("CRITICAL", message, extra))
        except Exception:
            pass

    def debug(self, message: str, extra: Dict = None):
        """Log debug message"""
        self.logger.debug(message)
        try:
            import asyncio

            loop = asyncio.get_event_loop()
            loop.create_task(self._send_update("DEBUG", message, extra))
        except Exception:
            pass

    def get_stats(self) -> Dict:
        """Get logging statistics"""
        return {
            "total_logs": sum(self.log_stats.values()),
            "by_level": self.log_stats.copy(),
            "logger_name": self.name,
        }

    def create_child(self, name: str) -> "FuturisticLogger":
        """Create child logger"""
        return FuturisticLogger(f"{self.name}.{name}")


# Global logger instance
futuristic_logger = FuturisticLogger("OmicsOracle.Futuristic")


class PerformanceMonitor:
    """Performance monitoring for the futuristic interface"""

    def __init__(self):
        self.metrics = {
            "api_requests": 0,
            "search_queries": 0,
            "websocket_connections": 0,
            "errors": 0,
        }
        self.response_times = []
        self.error_log = []

    def record_api_request(self, response_time: float, endpoint: str):
        """Record API request metrics"""
        self.metrics["api_requests"] += 1
        self.response_times.append(
            {
                "time": response_time,
                "endpoint": endpoint,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )

        # Keep only last 1000 entries
        if len(self.response_times) > 1000:
            self.response_times = self.response_times[-1000:]

    def record_search_query(self, query: str, results_count: int, processing_time: float):
        """Record search query metrics"""
        self.metrics["search_queries"] += 1
        futuristic_logger.info(
            f"Search completed: {results_count} results in {processing_time:.2f}s",
            {
                "query": query[:50],
                "results": results_count,
                "time": processing_time,
            },
        )

    def record_websocket_connection(self, connected: bool):
        """Record WebSocket connection changes"""
        if connected:
            self.metrics["websocket_connections"] += 1
        else:
            self.metrics["websocket_connections"] = max(0, self.metrics["websocket_connections"] - 1)

    def record_error(self, error: str, context: Dict = None):
        """Record error occurrence"""
        self.metrics["errors"] += 1
        error_entry = {
            "error": error,
            "context": context or {},
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.error_log.append(error_entry)

        # Keep only last 100 errors
        if len(self.error_log) > 100:
            self.error_log = self.error_log[-100:]

        futuristic_logger.error(f"Error recorded: {error}", context)

    def get_metrics(self) -> Dict:
        """Get current performance metrics"""
        avg_response_time = 0
        if self.response_times:
            avg_response_time = sum(rt["time"] for rt in self.response_times) / len(self.response_times)

        return {
            "metrics": self.metrics.copy(),
            "avg_response_time": avg_response_time,
            "total_requests": len(self.response_times),
            "recent_errors": self.error_log[-10:] if self.error_log else [],
        }


# Global performance monitor
performance_monitor = PerformanceMonitor()
