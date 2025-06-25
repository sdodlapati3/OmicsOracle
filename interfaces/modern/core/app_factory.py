"""
Application factory for OmicsOracle modern interface
"""

from flask import Flask
from flask_cors import CORS
from typing import Optional

from .config import Config, get_config
from .logging_config import setup_logging
from .exceptions import OmicsOracleException


def create_app(config_name: Optional[str] = None) -> Flask:
    """
    Create and configure Flask application
    
    Args:
        config_name: Configuration environment name
    
    Returns:
        Configured Flask application
    """
    # Get the directory path for templates and static files
    import os
    current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_dir = os.path.join(current_dir, 'templates')
    static_dir = os.path.join(current_dir, 'static')
    
    app = Flask(__name__,
                template_folder=template_dir,
                static_folder=static_dir)
    
    # Load configuration
    config = get_config(config_name)
    app.config.from_object(config)
    
    # Initialize configuration
    config.init_app(app)
    
    # Setup logging
    logger = setup_logging(
        log_level=config.LOG_LEVEL,
        log_dir=config.LOG_DIR,
        app_name='omics_oracle_web'
    )
    
    # Setup CORS
    CORS(app, origins=config.CORS_ORIGINS)
    
    # Register blueprints
    try:
        from api.search_api import search_bp
        from api.health_api import health_bp
        from api.export_api import export_bp
        from api.main_routes import main_bp
        from api.enhanced_api import enhanced_bp
        
        # Register main web interface (HTML pages)
        app.register_blueprint(main_bp)
        
        # Register API blueprints
        app.register_blueprint(search_bp, url_prefix='/api/v1')
        app.register_blueprint(health_bp, url_prefix='/api/v1')
        app.register_blueprint(export_bp, url_prefix='/api/v1')
        app.register_blueprint(enhanced_bp, url_prefix='/api')
        
        logger.info("All blueprints registered successfully")
    except ImportError as e:
        logger.error(f"Failed to import blueprints: {e}")
        # Register basic health check at app level
        
        @app.route('/api/v1/health')
        def basic_health():
            return {'status': 'healthy', 'service': 'omics-oracle-modern'}
    
    # Error handlers
    @app.errorhandler(OmicsOracleException)
    def handle_omics_oracle_exception(e: OmicsOracleException):
        """Handle custom OmicsOracle exceptions"""
        logger.error(f"OmicsOracle exception: {e.message}", exc_info=True)
        return e.to_dict(), 400
    
    @app.errorhandler(404)
    def handle_not_found(e):
        """Handle 404 errors"""
        return {'error': 'NotFound', 'message': 'Resource not found'}, 404
    
    @app.errorhandler(500)
    def handle_internal_error(e):
        """Handle 500 errors"""
        logger.error(f"Internal server error: {str(e)}", exc_info=True)
        return {'error': 'InternalServerError', 'message': 'Internal server error'}, 500
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        """Basic health check endpoint"""
        return {'status': 'healthy', 'service': 'omics-oracle-web'}
    
    logger.info(f"OmicsOracle web application created with config: {config.__class__.__name__}")
    
    return app
