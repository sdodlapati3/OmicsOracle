"""
Production configuration management for the futuristic interface
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class SecurityConfig:
    """Security-related configuration"""

    secret_key: str = field(
        default_factory=lambda: os.getenv("SECRET_KEY", "development-key-change-in-production")
    )
    cors_origins: list = field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://localhost:8001",
        ]
    )
    cors_credentials: bool = True
    cors_methods: list = field(default_factory=lambda: ["*"])
    cors_headers: list = field(default_factory=lambda: ["*"])
    max_request_size: int = 16777216  # 16MB
    rate_limit_requests: int = 100
    rate_limit_period: int = 60  # seconds


@dataclass
class DatabaseConfig:
    """Database configuration"""

    url: Optional[str] = None
    pool_size: int = 5
    max_overflow: int = 10
    pool_timeout: int = 30
    pool_recycle: int = 3600
    echo: bool = False


@dataclass
class CacheConfig:
    """Caching configuration"""

    enabled: bool = True
    backend: str = "memory"  # memory, redis, memcached
    ttl_seconds: int = 3600
    max_size: int = 1000
    redis_url: Optional[str] = None


@dataclass
class LoggingConfig:
    """Logging configuration"""

    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: Optional[str] = None
    max_file_size: int = 10485760  # 10MB
    backup_count: int = 5
    json_format: bool = False


@dataclass
class MonitoringConfig:
    """Monitoring and metrics configuration"""

    enabled: bool = True
    metrics_endpoint: str = "/metrics"
    health_check_interval: int = 30
    performance_tracking: bool = True
    error_tracking: bool = True
    slow_query_threshold: float = 1.0


@dataclass
class AgentConfig:
    """Agent system configuration"""

    max_concurrent_jobs: int = 10
    job_timeout_seconds: int = 300
    retry_attempts: int = 3
    retry_delay_seconds: int = 5
    cache_enabled: bool = True
    cache_ttl_seconds: int = 1800


@dataclass
class ProductionConfig:
    """Production-ready configuration"""

    # Environment
    environment: str = field(default_factory=lambda: os.getenv("ENVIRONMENT", "development"))
    debug: bool = field(default_factory=lambda: os.getenv("DEBUG", "False").lower() == "true")

    # Server
    host: str = field(default_factory=lambda: os.getenv("HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(os.getenv("PORT", "8001")))
    workers: int = field(default_factory=lambda: int(os.getenv("WORKERS", "1")))

    # Application
    app_name: str = "OmicsOracle Futuristic Interface"
    version: str = "2.0.0"
    description: str = "Next-generation research platform with AI-powered agents"

    # Sub-configurations
    security: SecurityConfig = field(default_factory=SecurityConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    agents: AgentConfig = field(default_factory=AgentConfig)

    @classmethod
    def from_env(cls) -> "ProductionConfig":
        """Create configuration from environment variables"""
        config = cls()

        # Load environment-specific overrides
        if config.environment == "production":
            config._apply_production_overrides()
        elif config.environment == "testing":
            config._apply_testing_overrides()
        elif config.environment == "development":
            config._apply_development_overrides()

        return config

    def _apply_production_overrides(self):
        """Apply production-specific settings"""
        self.debug = False
        self.security.cors_origins = [os.getenv("FRONTEND_URL", "https://omicsoracle.com")]
        self.logging.level = "WARNING"
        self.logging.json_format = True
        self.database.echo = False
        self.cache.enabled = False  # CACHE DISABLED for fresh results
        self.monitoring.enabled = True

    def _apply_testing_overrides(self):
        """Apply testing-specific settings"""
        self.debug = True
        self.logging.level = "DEBUG"
        self.database.url = "sqlite:///test.db"
        self.cache.enabled = False  # CACHE DISABLED for fresh results
        self.monitoring.enabled = False

    def _apply_development_overrides(self):
        """Apply development-specific settings"""
        self.debug = True
        self.logging.level = "DEBUG"
        self.database.echo = True
        self.cache.enabled = False  # CACHE DISABLED for fresh results (use only for debugging)
        self.monitoring.enabled = True

    def validate(self) -> bool:
        """Validate configuration"""
        errors = []

        # Security validation
        if self.environment == "production":
            if self.security.secret_key == "development-key-change-in-production":
                errors.append("SECRET_KEY must be set in production")

            if "localhost" in str(self.security.cors_origins):
                errors.append("CORS origins should not include localhost in production")

        # Database validation
        if self.database.url and not self.database.url.startswith(("sqlite://", "postgresql://", "mysql://")):
            errors.append("Invalid database URL format")

        # Port validation
        if not 1024 <= self.port <= 65535:
            errors.append(f"Port {self.port} is out of valid range")

        if errors:
            for error in errors:
                logger.error(f"Configuration validation error: {error}")
            return False

        return True

    def get_database_url(self) -> str:
        """Get database URL with fallback"""
        if self.database.url:
            return self.database.url

        # Default to SQLite for development
        if self.environment in ["development", "testing"]:
            db_path = Path(__file__).parent.parent / "data" / f"{self.environment}.db"
            db_path.parent.mkdir(exist_ok=True)
            return f"sqlite:///{db_path}"

        raise ValueError("Database URL must be configured for production")

    def get_log_config(self) -> Dict[str, Any]:
        """Get logging configuration dict"""
        config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {"standard": {"format": self.logging.format}},
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "level": self.logging.level,
                    "formatter": "standard",
                    "stream": "ext://sys.stdout",
                }
            },
            "loggers": {
                "": {
                    "handlers": ["console"],
                    "level": self.logging.level,
                    "propagate": False,
                }
            },
        }

        # Add file handler if configured
        if self.logging.file_path:
            config["handlers"]["file"] = {
                "class": "logging.handlers.RotatingFileHandler",
                "level": self.logging.level,
                "formatter": "standard",
                "filename": self.logging.file_path,
                "maxBytes": self.logging.max_file_size,
                "backupCount": self.logging.backup_count,
            }
            config["loggers"][""]["handlers"].append("file")

        return config

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            "environment": self.environment,
            "debug": self.debug,
            "host": self.host,
            "port": self.port,
            "workers": self.workers,
            "app_name": self.app_name,
            "version": self.version,
            "description": self.description,
            "security": {
                "cors_origins": self.security.cors_origins,
                "cors_credentials": self.security.cors_credentials,
                "max_request_size": self.security.max_request_size,
                "rate_limit_requests": self.security.rate_limit_requests,
            },
            "database": {
                "url": self.get_database_url(),
                "pool_size": self.database.pool_size,
                "echo": self.database.echo,
            },
            "cache": {
                "enabled": self.cache.enabled,
                "backend": self.cache.backend,
                "ttl_seconds": self.cache.ttl_seconds,
            },
            "monitoring": {
                "enabled": self.monitoring.enabled,
                "health_check_interval": self.monitoring.health_check_interval,
                "performance_tracking": self.monitoring.performance_tracking,
            },
            "agents": {
                "max_concurrent_jobs": self.agents.max_concurrent_jobs,
                "job_timeout_seconds": self.agents.job_timeout_seconds,
                "retry_attempts": self.agents.retry_attempts,
            },
        }


# Global configuration instance
_config: Optional[ProductionConfig] = None


def get_config() -> ProductionConfig:
    """Get the global configuration instance"""
    global _config
    if _config is None:
        _config = ProductionConfig.from_env()
        if not _config.validate():
            raise ValueError("Invalid configuration")
    return _config


def reload_config():
    """Reload configuration from environment"""
    global _config
    _config = None
    return get_config()
