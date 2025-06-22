"""
Configuration management for OmicsOracle.

This module provides a robust configuration system supporting:
- Environment-based configuration (dev/test/prod)
- Environment variable substitution
- Type validation and conversion
- Configuration validation
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass, field
from enum import Enum

from .exceptions import ConfigurationError


class Environment(str, Enum):
    """Supported environments."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


@dataclass
class DatabaseConfig:
    """Database configuration."""
    url: str
    pool_size: int = 10
    pool_timeout: int = 30
    pool_recycle: int = 3600
    echo: bool = False


@dataclass
class NCBIConfig:
    """NCBI API configuration."""
    api_key: Optional[str] = None
    email: Optional[str] = None
    rate_limit: int = 3
    timeout: int = 30
    retries: int = 3


@dataclass
class NLPConfig:
    """NLP processing configuration."""
    model: str = "en_core_sci_sm"
    batch_size: int = 32
    max_tokens: int = 512
    enable_gpu: bool = False
    cache_models: bool = True


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    format: str = "json"
    file: Optional[str] = None
    max_file_size: str = "10MB"
    backup_count: int = 5


@dataclass
class APIConfig:
    """API server configuration."""
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1
    reload: bool = False
    debug: bool = False


@dataclass
class CacheConfig:
    """Cache configuration."""
    enabled: bool = True
    backend: str = "memory"  # memory, redis
    redis_url: Optional[str] = None
    default_ttl: int = 3600


@dataclass
class Config:
    """Main configuration class."""
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    
    # Service configurations
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    ncbi: NCBIConfig = field(default_factory=NCBIConfig)
    nlp: NLPConfig = field(default_factory=NLPConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    api: APIConfig = field(default_factory=APIConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate()
    
    def _validate(self) -> None:
        """Validate configuration values."""
        # Validate NCBI configuration
        if self.environment == Environment.PRODUCTION:
            if not self.ncbi.api_key:
                raise ConfigurationError(
                    "NCBI API key is required in production"
                )
            if not self.ncbi.email:
                raise ConfigurationError(
                    "NCBI email is required in production"
                )
        
        # Validate database URL
        if not self.database.url:
            raise ConfigurationError("Database URL is required")
        
        # Validate logging level
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.logging.level.upper() not in valid_levels:
            raise ConfigurationError(
                f"Invalid logging level: {self.logging.level}"
            )


class ConfigManager:
    """Configuration manager for loading and managing configuration."""
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize configuration manager.
        
        Args:
            config_dir: Path to configuration directory
        """
        if config_dir:
            self.config_dir = config_dir
        else:
            # Look for config directory in project root
            current_file = Path(__file__)
            project_root = current_file.parent.parent.parent.parent
            self.config_dir = project_root / "config"
        self._config: Optional[Config] = None
    
    def load_config(self, environment: Optional[str] = None) -> Config:
        """Load configuration for specified environment.
        
        Args:
            environment: Environment name (dev/test/prod)
            
        Returns:
            Loaded configuration
            
        Raises:
            ConfigurationError: If configuration cannot be loaded
        """
        env = environment or os.getenv("OMICS_ORACLE_ENV", "development")
        
        try:
            env_enum = Environment(env)
        except ValueError as exc:
            raise ConfigurationError(f"Invalid environment: {env}") from exc
        
        # Load configuration file
        config_file = self.config_dir / f"{env}.yml"
        if not config_file.exists():
            raise ConfigurationError(
                f"Configuration file not found: {config_file}"
            )
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConfigurationError(
                f"Invalid YAML in {config_file}: {e}"
            ) from e
        
        # Substitute environment variables
        config_data = self._substitute_env_vars(config_data)
        
        # Create configuration object
        try:
            self._config = self._create_config(config_data, env_enum)
            return self._config
        except Exception as e:
            raise ConfigurationError(
                f"Failed to create configuration: {e}"
            ) from e
    
    def get_config(self) -> Config:
        """Get current configuration.
        
        Returns:
            Current configuration
            
        Raises:
            ConfigurationError: If no configuration is loaded
        """
        if self._config is None:
            raise ConfigurationError(
                "No configuration loaded. Call load_config() first."
            )
        return self._config
    
    def _substitute_env_vars(self, data: Any) -> Any:
        """Substitute environment variables in configuration data.
        
        Args:
            data: Configuration data
            
        Returns:
            Data with environment variables substituted
        """
        if isinstance(data, dict):
            return {k: self._substitute_env_vars(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._substitute_env_vars(item) for item in data]
        elif (isinstance(data, str) and
              data.startswith("${") and
              data.endswith("}")):
            env_var = data[2:-1]
            default_value = None
            
            # Handle default values: ${VAR:default}
            if ":" in env_var:
                env_var, default_value = env_var.split(":", 1)
            
            return os.getenv(env_var, default_value)
        else:
            return data
    
    def _create_config(
        self,
        config_data: Dict[str, Any],
        environment: Environment
    ) -> Config:
        """Create configuration object from data.
        
        Args:
            config_data: Configuration data
            environment: Environment enum
            
        Returns:
            Configuration object
        """
        # Create sub-configurations
        database_config = DatabaseConfig(**config_data.get("database", {}))
        ncbi_config = NCBIConfig(**config_data.get("ncbi", {}))
        nlp_config = NLPConfig(**config_data.get("nlp", {}))
        logging_config = LoggingConfig(**config_data.get("logging", {}))
        api_config = APIConfig(**config_data.get("api", {}))
        cache_config = CacheConfig(**config_data.get("cache", {}))
        
        # Create main configuration
        return Config(
            environment=environment,
            debug=config_data.get("debug", False),
            database=database_config,
            ncbi=ncbi_config,
            nlp=nlp_config,
            logging=logging_config,
            api=api_config,
            cache=cache_config
        )


# Global configuration manager instance
_config_manager = ConfigManager()


def load_config(environment: Optional[str] = None) -> Config:
    """Load configuration for specified environment.
    
    Args:
        environment: Environment name
        
    Returns:
        Loaded configuration
    """
    return _config_manager.load_config(environment)


def get_config() -> Config:
    """Get current configuration.
    
    Returns:
        Current configuration
    """
    return _config_manager.get_config()


def is_development() -> bool:
    """Check if running in development environment."""
    try:
        config = get_config()
        return config.environment == Environment.DEVELOPMENT
    except ConfigurationError:
        return True  # Default to development if no config loaded


def is_production() -> bool:
    """Check if running in production environment."""
    try:
        config = get_config()
        return config.environment == Environment.PRODUCTION
    except ConfigurationError:
        return False
