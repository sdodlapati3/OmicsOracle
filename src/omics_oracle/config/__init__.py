"""
Configuration management for OmicsOracle.
"""

import os
from typing import List, Optional
from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    """Application settings."""
    
    # Application settings
    debug: bool = Field(default=False, env="DEBUG")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    environment: str = Field(default="development", env="ENVIRONMENT")
    
    # API settings
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")
    api_workers: int = Field(default=4, env="API_WORKERS")
    api_reload: bool = Field(default=True, env="API_RELOAD")
    
    # OpenAI settings
    openai_api_key: str = Field(..., env="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4", env="OPENAI_MODEL")
    openai_max_tokens: int = Field(default=4000, env="OPENAI_MAX_TOKENS")
    openai_temperature: float = Field(default=0.3, env="OPENAI_TEMPERATURE")
    
    # Database settings
    mongodb_url: str = Field(default="mongodb://localhost:27017", env="MONGODB_URL")
    mongodb_database: str = Field(default="omics_oracle", env="MONGODB_DATABASE")
    mongodb_collection_prefix: str = Field(default="omics_", env="MONGODB_COLLECTION_PREFIX")
    
    # Redis settings
    redis_url: str = Field(default="redis://localhost:6379", env="REDIS_URL")
    redis_db: int = Field(default=0, env="REDIS_DB")
    redis_password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    redis_ttl: int = Field(default=3600, env="REDIS_TTL")
    
    # ChromaDB settings
    chromadb_path: str = Field(default="./data/chromadb", env="CHROMADB_PATH")
    chromadb_collection: str = Field(default="omics_vectors", env="CHROMADB_COLLECTION")
    
    # File storage settings
    upload_dir: str = Field(default="./data/uploads", env="UPLOAD_DIR")
    temp_dir: str = Field(default="./data/temp", env="TEMP_DIR")
    max_file_size: int = Field(default=100000000, env="MAX_FILE_SIZE")  # 100MB
    
    # Security settings
    secret_key: str = Field(..., env="SECRET_KEY")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    algorithm: str = Field(default="HS256", env="ALGORITHM")
    
    # Rate limiting
    rate_limit_requests: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    rate_limit_window: int = Field(default=60, env="RATE_LIMIT_WINDOW")
    
    # GEO API settings
    geo_base_url: str = Field(
        default="https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi",
        env="GEO_BASE_URL"
    )
    geo_api_key: Optional[str] = Field(default=None, env="GEO_API_KEY")
    geo_batch_size: int = Field(default=10, env="GEO_BATCH_SIZE")
    geo_request_delay: float = Field(default=1.0, env="GEO_REQUEST_DELAY")
    
    # Processing settings
    max_concurrent_jobs: int = Field(default=5, env="MAX_CONCURRENT_JOBS")
    batch_size: int = Field(default=50, env="BATCH_SIZE")
    processing_timeout: int = Field(default=3600, env="PROCESSING_TIMEOUT")
    
    # Monitoring and logging
    sentry_dsn: Optional[str] = Field(default=None, env="SENTRY_DSN")
    log_file: str = Field(default="./logs/omics_oracle.log", env="LOG_FILE")
    metrics_enabled: bool = Field(default=True, env="METRICS_ENABLED")
    
    # Email settings
    smtp_host: Optional[str] = Field(default=None, env="SMTP_HOST")
    smtp_port: int = Field(default=587, env="SMTP_PORT")
    smtp_user: Optional[str] = Field(default=None, env="SMTP_USER")
    smtp_password: Optional[str] = Field(default=None, env="SMTP_PASSWORD")
    smtp_tls: bool = Field(default=True, env="SMTP_TLS")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
settings = Settings()
