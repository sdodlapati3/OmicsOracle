"""
Configuration management for OmicsOracle modern interface
"""

import os
from pathlib import Path
from typing import Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from flask import Flask


class Config:
    """Base configuration class"""
    
    # App settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DEBUG = False
    TESTING = False
    
    # Server settings
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 5000))
    
    # OmicsOracle specific settings
    OMICS_ORACLE_ROOT = Path(__file__).parent.parent.parent.parent  # Back to project root
    DATA_DIR = OMICS_ORACLE_ROOT / 'data'
    CACHE_DIR = DATA_DIR / 'cache'
    EXPORTS_DIR = DATA_DIR / 'exports'
    
    # Search settings
    MAX_SEARCH_RESULTS = int(os.environ.get('MAX_SEARCH_RESULTS', 100))
    SEARCH_TIMEOUT = int(os.environ.get('SEARCH_TIMEOUT', 30))
    DEFAULT_PAGE_SIZE = int(os.environ.get('DEFAULT_PAGE_SIZE', 20))
    
    # Caching
    CACHE_ENABLED = os.environ.get('CACHE_ENABLED', 'true').lower() == 'true'
    CACHE_TTL = int(os.environ.get('CACHE_TTL', 3600))  # 1 hour
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_DIR = OMICS_ORACLE_ROOT / 'logs'
    
    # CORS settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000,http://localhost:5173').split(',')
    
    @classmethod
    def init_app(cls, app: 'Flask') -> None:
        """Initialize application with this config"""
        # Create necessary directories
        cls.DATA_DIR.mkdir(exist_ok=True)
        cls.CACHE_DIR.mkdir(exist_ok=True)
        cls.EXPORTS_DIR.mkdir(exist_ok=True)
        cls.LOG_DIR.mkdir(exist_ok=True)


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'
    
    # More permissive CORS for development
    CORS_ORIGINS = ['*']


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    LOG_LEVEL = 'INFO'
    
    def __init__(self):
        super().__init__()
        # Use environment-specific values
        secret_key = os.environ.get('SECRET_KEY')
        if not secret_key:
            raise ValueError('SECRET_KEY environment variable must be set in production')
        self.SECRET_KEY = secret_key
        
        # Stricter CORS
        cors_origins = os.environ.get('CORS_ORIGINS', '').split(',')
        if not cors_origins or cors_origins == ['']:
            raise ValueError('CORS_ORIGINS must be set in production')
        self.CORS_ORIGINS = cors_origins


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    LOG_LEVEL = 'DEBUG'
    
    # Use in-memory or temporary directories for testing
    CACHE_ENABLED = False
    SEARCH_TIMEOUT = 5  # Shorter timeout for tests


# Configuration mapping
config_map: Dict[str, type[Config]] = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config(environment: Optional[str] = None) -> Config:
    """Get configuration for the specified environment"""
    if environment is None:
        environment = os.environ.get('FLASK_ENV', 'default')
    
    config_class = config_map.get(environment, DevelopmentConfig)
    return config_class()
