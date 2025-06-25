"""
Health check API endpoints for OmicsOracle modern interface
"""

import sys
from datetime import datetime

from core.config import get_config
from core.logging_config import get_api_logger
from flask import Blueprint, jsonify
from models import HealthStatus

# Create blueprint
health_bp = Blueprint("health", __name__)

logger = get_api_logger()
config = get_config()


@health_bp.route("/health", methods=["GET"])
def health_check():
    """Basic health check endpoint"""
    try:
        health_status = HealthStatus(
            status="healthy",
            timestamp=datetime.now(),
            version="1.0.0",  # TODO: Get from package version
            database_status="unknown",  # TODO: Check database connection
            cache_status="healthy",
            search_engine_status="unknown",  # TODO: Check search engine
        )

        return jsonify(health_status.to_dict())

    except Exception as e:
        logger.error(f"Health check failed: {str(e)}", exc_info=True)
        return (
            jsonify(
                {
                    "status": "unhealthy",
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e),
                }
            ),
            500,
        )


@health_bp.route("/health/detailed", methods=["GET"])
def detailed_health_check():
    """Detailed health check with component status"""
    try:
        # Check various components
        components = {}
        overall_status = "healthy"

        # Check Python version
        components["python"] = {
            "status": "healthy",
            "version": sys.version,
            "version_info": sys.version_info[:3],
        }

        # Check configuration
        try:
            components["configuration"] = {
                "status": "healthy",
                "debug": config.DEBUG,
                "cache_enabled": config.CACHE_ENABLED,
            }
        except Exception as e:
            components["configuration"] = {
                "status": "unhealthy",
                "error": str(e),
            }
            overall_status = "degraded"

        # Check cache directory
        try:
            cache_accessible = (
                config.CACHE_DIR.exists() and config.CACHE_DIR.is_dir()
            )
            components["cache"] = {
                "status": "healthy" if cache_accessible else "unhealthy",
                "cache_dir": str(config.CACHE_DIR),
                "accessible": cache_accessible,
            }
            if not cache_accessible:
                overall_status = "degraded"
        except Exception as e:
            components["cache"] = {"status": "unhealthy", "error": str(e)}
            overall_status = "degraded"

        # Check data directory
        try:
            data_accessible = (
                config.DATA_DIR.exists() and config.DATA_DIR.is_dir()
            )
            components["data"] = {
                "status": "healthy" if data_accessible else "unhealthy",
                "data_dir": str(config.DATA_DIR),
                "accessible": data_accessible,
            }
            if not data_accessible:
                overall_status = "degraded"
        except Exception as e:
            components["data"] = {"status": "unhealthy", "error": str(e)}
            overall_status = "degraded"

        # TODO: Add more component checks
        # - Database connectivity
        # - Search engine status
        # - External service dependencies

        health_info = {
            "status": overall_status,
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0",
            "components": components,
            "uptime": "unknown",  # TODO: Track application uptime
            "system_info": {
                "platform": sys.platform,
                "python_version": sys.version,
            },
        }

        status_code = 200 if overall_status == "healthy" else 503
        return jsonify(health_info), status_code

    except Exception as e:
        logger.error(f"Detailed health check failed: {str(e)}", exc_info=True)
        return (
            jsonify(
                {
                    "status": "unhealthy",
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e),
                }
            ),
            500,
        )


@health_bp.route("/health/ready", methods=["GET"])
def readiness_check():
    """Readiness check for deployment orchestration"""
    try:
        # Check if application is ready to serve requests
        checks = []
        ready = True

        # Check configuration
        try:
            _ = config.SECRET_KEY
            checks.append({"component": "configuration", "status": "ready"})
        except Exception as e:
            checks.append(
                {
                    "component": "configuration",
                    "status": "not_ready",
                    "error": str(e),
                }
            )
            ready = False

        # Check required directories
        required_dirs = [config.DATA_DIR, config.CACHE_DIR, config.EXPORTS_DIR]
        for dir_path in required_dirs:
            try:
                dir_path.mkdir(exist_ok=True)
                if dir_path.exists():
                    checks.append(
                        {
                            "component": f"directory_{dir_path.name}",
                            "status": "ready",
                        }
                    )
                else:
                    checks.append(
                        {
                            "component": f"directory_{dir_path.name}",
                            "status": "not_ready",
                        }
                    )
                    ready = False
            except Exception as e:
                checks.append(
                    {
                        "component": f"directory_{dir_path.name}",
                        "status": "not_ready",
                        "error": str(e),
                    }
                )
                ready = False

        # TODO: Add more readiness checks
        # - Database connection
        # - Required services availability

        response = {
            "ready": ready,
            "timestamp": datetime.now().isoformat(),
            "checks": checks,
        }

        status_code = 200 if ready else 503
        return jsonify(response), status_code

    except Exception as e:
        logger.error(f"Readiness check failed: {str(e)}", exc_info=True)
        return (
            jsonify(
                {
                    "ready": False,
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e),
                }
            ),
            500,
        )


@health_bp.route("/health/live", methods=["GET"])
def liveness_check():
    """Liveness check for deployment orchestration"""
    try:
        # Simple check that the application is alive
        return jsonify(
            {
                "alive": True,
                "timestamp": datetime.now().isoformat(),
                "service": "omics-oracle-web",
            }
        )

    except Exception as e:
        logger.error(f"Liveness check failed: {str(e)}", exc_info=True)
        return (
            jsonify(
                {
                    "alive": False,
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e),
                }
            ),
            500,
        )
