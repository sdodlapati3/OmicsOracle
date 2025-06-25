"""
Main application entry point for OmicsOracle modern interface
"""

import os
import sys
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import get_config
from core.app_factory import create_app
from core.logging_config import setup_logging


def main():
    """Main application entry point"""
    
    # Get configuration
    config_name = os.environ.get('FLASK_ENV', 'development')
    config = get_config(config_name)
    
    # Setup logging
    logger = setup_logging(
        log_level=config.LOG_LEVEL,
        log_dir=config.LOG_DIR,
        app_name='omics_oracle_web'
    )
    
    # Create Flask application
    app = create_app(config_name)
    
    logger.info(f"Starting OmicsOracle web interface on {config.HOST}:{config.PORT}")
    logger.info(f"Configuration: {config.__class__.__name__}")
    logger.info(f"Debug mode: {config.DEBUG}")
    
    # Run the application
    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG,
        threaded=True
    )


if __name__ == '__main__':
    main()
