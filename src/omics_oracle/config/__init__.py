"""
Configuration management for OmicsOracle.

This module is deprecated. Use omics_oracle.core.config instead.
"""

# Deprecated - use omics_oracle.core.config instead
import warnings

warnings.warn(
    "omics_oracle.config is deprecated. Use omics_oracle.core.config instead.",
    DeprecationWarning,
    stacklevel=2,
)


# Placeholder for backward compatibility
class Settings:
    debug = False
    log_level = "INFO"


settings = Settings()
