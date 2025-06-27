"""
Centralized configuration management for OmicsOracle.

This module provides a robust configuration system supporting:
- Environment-based configuration (dev/test/prod)
- Type validation and conversion
- Configuration validation and defaults
- Environment variable substitution
"""

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...shared.exceptions.domain_exceptions import ConfigurationError

logger = logging.getLogger(__name__)


class Environment(str, Enum):
    """Supported environments."""

    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass
class DatabaseConfig:
    """Database configuration."""

    url: str = "sqlite:///omics_oracle.db"
    echo: bool = False
    pool_size: int = 5
    max_overflow: int = 10
    pool_timeout: int = 30
    pool_recycle: int = 3600

    def __post_init__(self):
        """Validate database configuration."""
        if not self.url:
            raise ConfigurationError("database.url", "Database URL is required")

        if self.pool_size <= 0:
            raise ConfigurationError(
                "database.pool_size", "Pool size must be positive"
            )


@dataclass
class GEOConfig:
    """GEO API configuration."""

    base_url: str = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/"
    email: str = field(default_factory=lambda: os.getenv("NCBI_EMAIL", ""))
    api_key: Optional[str] = field(
        default_factory=lambda: os.getenv("NCBI_API_KEY")
    )
    tool_name: str = "OmicsOracle"

    # Rate limiting
    requests_per_second: float = 3.0
    max_retries: int = 3
    timeout_seconds: int = 30

    # Caching
    cache_ttl: int = 3600  # 1 hour
    enable_cache: bool = True

    def __post_init__(self):
        """Validate GEO configuration."""
        if not self.email:
            raise ConfigurationError(
                "geo.email",
                "NCBI email is required. Set NCBI_EMAIL environment variable.",
            )

        if "@" not in self.email:
            raise ConfigurationError("geo.email", "Invalid email format")

        if self.requests_per_second <= 0:
            raise ConfigurationError(
                "geo.requests_per_second",
                "Requests per second must be positive",
            )


@dataclass
class RedisConfig:
    """Redis configuration for caching."""

    url: str = field(
        default_factory=lambda: os.getenv(
            "REDIS_URL", "redis://localhost:6379/0"
        )
    )
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = field(
        default_factory=lambda: os.getenv("REDIS_PASSWORD")
    )

    # Connection settings
    max_connections: int = 20
    socket_connect_timeout: int = 5
    socket_timeout: int = 5
    retry_on_timeout: bool = True

    # Key prefixes
    key_prefix: str = "omics_oracle:"
    search_cache_prefix: str = "search:"
    dataset_cache_prefix: str = "dataset:"

    def __post_init__(self):
        """Validate Redis configuration."""
        if self.port <= 0 or self.port > 65535:
            raise ConfigurationError(
                "redis.port", "Port must be between 1 and 65535"
            )


@dataclass
class LoggingConfig:
    """Logging configuration."""

    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: Optional[str] = None
    max_file_size: int = 10 * 1024 * 1024  # 10 MB
    backup_count: int = 5

    # Specific logger levels
    geo_client_level: str = "INFO"
    search_level: str = "INFO"
    pipeline_level: str = "INFO"

    def __post_init__(self):
        """Validate logging configuration."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.level.upper() not in valid_levels:
            raise ConfigurationError(
                "logging.level",
                f"Level must be one of: {', '.join(valid_levels)}",
            )


@dataclass
class SecurityConfig:
    """Security configuration."""

    secret_key: str = field(default_factory=lambda: os.getenv("SECRET_KEY", ""))
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # CORS settings
    cors_origins: List[str] = field(default_factory=list)
    cors_allow_credentials: bool = True
    cors_allow_methods: List[str] = field(
        default_factory=lambda: ["GET", "POST"]
    )
    cors_allow_headers: List[str] = field(default_factory=lambda: ["*"])

    # Rate limiting
    rate_limit_per_minute: int = 100
    rate_limit_per_hour: int = 1000

    def __post_init__(self):
        """Validate security configuration."""
        if not self.secret_key:
            logger.warning("SECRET_KEY not set. Using default (insecure).")
            self.secret_key = (
                "insecure-default-key-change-in-production"  # nosec B105
            )


@dataclass
class MonitoringConfig:
    """Monitoring and metrics configuration."""

    enable_metrics: bool = True
    metrics_port: int = 9090
    enable_health_checks: bool = True
    health_check_interval: int = 30

    # Performance monitoring
    enable_performance_tracking: bool = True
    slow_query_threshold: float = 5.0  # seconds

    # Error tracking
    enable_error_tracking: bool = True
    sentry_dsn: Optional[str] = field(
        default_factory=lambda: os.getenv("SENTRY_DSN")
    )


@dataclass
class OpenAIConfig:
    """OpenAI API configuration."""

    api_key: str = field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY", "")
    )
    model: str = field(
        default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4")
    )
    max_tokens: int = field(
        default_factory=lambda: int(os.getenv("OPENAI_MAX_TOKENS", "4000"))
    )
    temperature: float = field(
        default_factory=lambda: float(os.getenv("OPENAI_TEMPERATURE", "0.3"))
    )

    # Request settings
    timeout_seconds: int = 60
    max_retries: int = 3

    def __post_init__(self):
        """Validate OpenAI configuration."""
        if not self.api_key:
            logger.warning(
                "OPENAI_API_KEY not set. AI features will be disabled."
            )
        elif not self.api_key.startswith("sk-"):
            logger.warning("OPENAI_API_KEY appears to be invalid format.")

        if self.max_tokens <= 0:
            raise ConfigurationError(
                "openai.max_tokens",
                "Max tokens must be positive",
            )

        if not 0.0 <= self.temperature <= 2.0:
            raise ConfigurationError(
                "openai.temperature",
                "Temperature must be between 0.0 and 2.0",
            )


@dataclass
class AppConfig:
    """Main application configuration."""

    # Environment
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False

    # Application settings
    app_name: str = "OmicsOracle"
    app_version: str = "3.0.0"
    api_prefix: str = "/api/v1"

    # Server settings
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1

    # Processing settings
    max_concurrent_requests: int = 10
    request_timeout: int = 300
    max_search_results: int = 1000
    default_search_results: int = 10

    # Feature flags
    enable_caching: bool = True
    enable_ai_summarization: bool = True
    enable_batch_processing: bool = True
    enable_websockets: bool = True

    # Sub-configurations
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    geo: GEOConfig = field(default_factory=GEOConfig)
    redis: RedisConfig = field(default_factory=RedisConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    openai: OpenAIConfig = field(default_factory=OpenAIConfig)

    def __post_init__(self):
        """Validate and finalize configuration."""
        # Adjust settings based on environment
        if self.environment == Environment.PRODUCTION:
            self.debug = False
            self.logging.level = "WARNING"
            self.workers = max(2, self.workers)
        elif self.environment == Environment.DEVELOPMENT:
            self.debug = True
            self.logging.level = "DEBUG"
        elif self.environment == Environment.TESTING:
            self.debug = True
            self.logging.level = "DEBUG"
            self.database.url = "sqlite:///:memory:"
            self.enable_caching = False

        # Validate port ranges
        if self.port <= 0 or self.port > 65535:
            raise ConfigurationError(
                "app.port", "Port must be between 1 and 65535"
            )

        # Validate worker count
        if self.workers <= 0:
            raise ConfigurationError(
                "app.workers", "Worker count must be positive"
            )

    @classmethod
    def from_env(cls, env_file: Optional[str] = None) -> "AppConfig":
        """
        Create configuration from environment variables.

        Args:
            env_file: Optional path to .env file

        Returns:
            Configured AppConfig instance
        """
        # Load environment file if specified
        if env_file and Path(env_file).exists():
            from dotenv import load_dotenv

            load_dotenv(env_file)

        # Determine environment
        env_name = os.getenv("ENVIRONMENT", "development").lower()
        try:
            environment = Environment(env_name)
        except ValueError:
            logger.warning(
                f"Invalid environment '{env_name}', defaulting to development"
            )
            environment = Environment.DEVELOPMENT

        # Create configuration
        config = cls(
            environment=environment,
            debug=os.getenv("DEBUG", "false").lower() == "true",
            app_name=os.getenv("APP_NAME", "OmicsOracle"),
            app_version=os.getenv("APP_VERSION", "3.0.0"),
            host=os.getenv("HOST", "0.0.0.0"),
            port=int(os.getenv("PORT", "8000")),
            workers=int(os.getenv("WORKERS", "1")),
            max_concurrent_requests=int(
                os.getenv("MAX_CONCURRENT_REQUESTS", "10")
            ),
            request_timeout=int(os.getenv("REQUEST_TIMEOUT", "300")),
            enable_caching=os.getenv("ENABLE_CACHING", "true").lower()
            == "true",
            enable_ai_summarization=os.getenv(
                "ENABLE_AI_SUMMARIZATION", "true"
            ).lower()
            == "true",
        )

        return config

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        result = {}
        for key, value in self.__dict__.items():
            if hasattr(value, "__dict__"):
                result[key] = value.__dict__
            else:
                result[key] = value
        return result

    def validate(self) -> List[str]:
        """
        Validate configuration and return list of issues.

        Returns:
            List of configuration issues (empty if valid)
        """
        issues = []

        try:
            # Validate required settings
            if not self.app_name:
                issues.append("Application name is required")

            if not self.app_version:
                issues.append("Application version is required")

            # Validate sub-configurations
            for config_name, config_obj in [
                ("database", self.database),
                ("geo", self.geo),
                ("redis", self.redis),
                ("logging", self.logging),
                ("security", self.security),
                ("monitoring", self.monitoring),
                ("openai", self.openai),
            ]:
                try:
                    # Re-run post_init validation
                    config_obj.__post_init__()
                except ConfigurationError as e:
                    issues.append(f"{config_name}: {e.message}")

        except Exception as e:
            issues.append(f"Configuration validation error: {e}")

        return issues

    def get_database_url(self) -> str:
        """Get formatted database URL."""
        return self.database.url

    def get_redis_url(self) -> str:
        """Get formatted Redis URL."""
        if self.redis.password:
            return f"redis://:{self.redis.password}@{self.redis.host}:{self.redis.port}/{self.redis.db}"
        return f"redis://{self.redis.host}:{self.redis.port}/{self.redis.db}"

    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.environment == Environment.DEVELOPMENT

    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment == Environment.PRODUCTION

    def is_testing(self) -> bool:
        """Check if running in testing mode."""
        return self.environment == Environment.TESTING


# Global configuration instance
_config: Optional[AppConfig] = None


def get_config() -> AppConfig:
    """
    Get the global configuration instance.

    Returns:
        Global AppConfig instance
    """
    global _config
    if _config is None:
        _config = AppConfig.from_env()
    return _config


def set_config(config: AppConfig) -> None:
    """
    Set the global configuration instance.

    Args:
        config: AppConfig instance to set as global
    """
    global _config
    _config = config


def reload_config(env_file: Optional[str] = None) -> AppConfig:
    """
    Reload configuration from environment.

    Args:
        env_file: Optional path to .env file

    Returns:
        Reloaded AppConfig instance
    """
    global _config
    _config = AppConfig.from_env(env_file)
    return _config
