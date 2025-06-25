"""
Export API endpoints for OmicsOracle modern interface
"""

from flask import Blueprint, request, jsonify, send_file
from typing import Optional

from models import ExportRequest
from services import ExportService, SearchService
from core.logging_config import get_api_logger
from core.exceptions import ValidationException, ExportException
from core.config import get_config

# Create blueprint
export_bp = Blueprint('export', __name__)

# Initialize services
config = get_config()
export_service = ExportService(config.EXPORTS_DIR)
search_service = SearchService()
logger = get_api_logger()


@export_bp.route('/export/search', methods=['POST'])
def export_search_results():
    """
    Export search results to specified format
    
    Expected JSON payload:
    {
        "query": "search terms",
        "format": "csv|json|tsv",
        "include_fields": ["id", "title", "abstract"],
        "filters": {},
        "max_results": 1000
    }
    """
    try:
        # Parse request data
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON payload'}), 400
        
        # Validate required fields
        if 'query' not in data:
            return jsonify({'error': 'Missing required field: query'}), 400
        
        # Create export request
        export_request = ExportRequest(
            query=data['query'],
            format=data.get('format', 'csv'),
            include_fields=data.get('include_fields', []),
            filters=data.get('filters', {}),
            max_results=int(data.get('max_results', 1000))
        )
        
        logger.info(f"Export request: {export_request.query} -> {export_request.format}")
        
        # First perform search to get results
        # TODO: This should be refactored to share code with search API
        from ..models import SearchQuery, SearchType
        
        search_query = SearchQuery(
            query=export_request.query,
            search_type=SearchType.BASIC,
            page=1,
            page_size=min(export_request.max_results, 100),  # Limit page size
            filters=export_request.filters
        )
        
        # Get search results (this will need to be synchronous or handled differently)
        # For now, we'll need to mock this
        search_results = []  # TODO: Get actual search results
        
        # Perform export (remove await since we're not in async context)
        export_response = export_service.export_search_results(search_results, export_request)
        
        return jsonify(export_response.to_dict())
        
    except ValidationException as e:
        logger.warning(f"Export validation error: {e.message}")
        return jsonify(e.to_dict()), 400
    
    except ExportException as e:
        logger.error(f"Export error: {e.message}")
        return jsonify(e.to_dict()), 500
    
    except ValueError as e:
        logger.warning(f"Export parameter error: {str(e)}")
        return jsonify({
            'error': 'ValidationError',
            'message': f'Invalid parameter value: {str(e)}'
        }), 400
    
    except Exception as e:
        logger.error(f"Unexpected export error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'InternalServerError',
            'message': 'An unexpected error occurred'
        }), 500


@export_bp.route('/exports/download/<filename>', methods=['GET'])
def download_export_file(filename: str):
    """Download an export file"""
    try:
        # Validate filename format
        if not filename.startswith('omics_oracle_export_'):
            return jsonify({'error': 'Invalid filename'}), 400
        
        # Get export file
        file_path = export_service.get_export_file(filename)
        
        if not file_path:
            return jsonify({'error': 'File not found or expired'}), 404
        
        # Determine MIME type based on extension
        if filename.endswith('.csv'):
            mimetype = 'text/csv'
        elif filename.endswith('.json'):
            mimetype = 'application/json'
        elif filename.endswith('.tsv'):
            mimetype = 'text/tab-separated-values'
        else:
            mimetype = 'application/octet-stream'
        
        logger.info(f"Serving export file: {filename}")
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=filename,
            mimetype=mimetype
        )
        
    except Exception as e:
        logger.error(f"Download error for {filename}: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'InternalServerError',
            'message': 'Failed to download file'
        }), 500


@export_bp.route('/exports/stats', methods=['GET'])
def get_export_stats():
    """Get export statistics"""
    try:
        stats = export_service.get_export_stats()
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Export stats error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'InternalServerError',
            'message': 'Failed to get export statistics'
        }), 500


@export_bp.route('/exports/cleanup', methods=['POST'])
def cleanup_expired_exports():
    """Clean up expired export files"""
    try:
        cleaned_count = export_service.cleanup_expired_exports()
        
        logger.info(f"Export cleanup completed: {cleaned_count} files removed")
        
        return jsonify({
            'message': f'Cleanup completed: {cleaned_count} files removed',
            'cleaned_count': cleaned_count
        })
        
    except Exception as e:
        logger.error(f"Export cleanup error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'InternalServerError',
            'message': 'Failed to cleanup exports'
        }), 500


@export_bp.route('/export/formats', methods=['GET'])
def get_supported_formats():
    """Get list of supported export formats"""
    try:
        formats = {
            'csv': {
                'name': 'Comma Separated Values',
                'extension': 'csv',
                'mime_type': 'text/csv',
                'description': 'Tabular data format compatible with Excel and other spreadsheet applications'
            },
            'tsv': {
                'name': 'Tab Separated Values',
                'extension': 'tsv',
                'mime_type': 'text/tab-separated-values',
                'description': 'Tabular data format with tab delimiters'
            },
            'json': {
                'name': 'JavaScript Object Notation',
                'extension': 'json',
                'mime_type': 'application/json',
                'description': 'Structured data format ideal for programmatic processing'
            }
        }
        
        return jsonify({
            'supported_formats': formats,
            'default_format': 'csv'
        })
        
    except Exception as e:
        logger.error(f"Format info error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'InternalServerError',
            'message': 'Failed to get format information'
        }), 500
