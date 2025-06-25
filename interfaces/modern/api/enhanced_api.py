"""
Enhanced API endpoints for the modern interface
Provides additional features like quick filters, suggestions, and history
"""

from flask import Blueprint, jsonify, request, current_app

enhanced_bp = Blueprint('enhanced', __name__)

# Sample data for enhanced features
QUICK_FILTERS = [
    "BRCA1 breast cancer",
    "RNA-seq brain tumor",
    "COVID-19 plasma",
    "Alzheimer's disease",
    "cancer biomarkers",
    "heart disease",
    "diabetes mellitus",
    "lung cancer",
    "immune response",
    "gene expression"
]

EXAMPLE_SEARCHES = [
    "BRCA1 breast cancer mutations",
    "RNA-seq brain tumor samples",
    "COVID-19 patient plasma analysis",
    "Alzheimer's disease biomarkers",
    "lung cancer genomics study",
    "diabetes gene expression",
    "heart disease risk factors",
    "immune system response",
    "cancer drug resistance",
    "neurological disorder genes"
]

# In-memory storage for search history (in production, use a database)
search_history = []


@enhanced_bp.route('/quick-filters')
def get_quick_filters():
    """Get quick filter suggestions for the search interface"""
    try:
        return jsonify({
            'filters': QUICK_FILTERS,
            'count': len(QUICK_FILTERS)
        })
    except Exception as e:
        current_app.logger.error(f"Error getting quick filters: {str(e)}")
        return jsonify({'error': 'Failed to load quick filters'}), 500


@enhanced_bp.route('/search-suggestions')
def get_search_suggestions():
    """Get search suggestions based on partial query"""
    try:
        query = request.args.get('q', '').lower().strip()
        
        if not query or len(query) < 2:
            return jsonify({'suggestions': []})
        
        # Filter suggestions based on query
        suggestions = []
        
        # Match against quick filters
        for filter_text in QUICK_FILTERS:
            if query in filter_text.lower():
                suggestions.append(filter_text)
        
        # Match against example searches
        for example in EXAMPLE_SEARCHES:
            if query in example.lower() and example not in suggestions:
                suggestions.append(example)
        
        # Match against recent search history
        for history_item in search_history[-10:]:  # Last 10 searches
            if query in history_item.lower() and history_item not in suggestions:
                suggestions.append(history_item)
        
        # Limit to top 8 suggestions
        suggestions = suggestions[:8]
        
        return jsonify({
            'suggestions': suggestions,
            'query': query,
            'count': len(suggestions)
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting search suggestions: {str(e)}")
        return jsonify({'error': 'Failed to load suggestions'}), 500


@enhanced_bp.route('/example-searches')
def get_example_searches():
    """Get example search queries"""
    try:
        return jsonify({
            'examples': EXAMPLE_SEARCHES,
            'count': len(EXAMPLE_SEARCHES)
        })
    except Exception as e:
        current_app.logger.error(f"Error getting example searches: {str(e)}")
        return jsonify({'error': 'Failed to load examples'}), 500


@enhanced_bp.route('/search-history')
def get_search_history():
    """Get recent search history"""
    try:
        # Return last 10 unique searches
        recent_history = list(dict.fromkeys(search_history[-10:]))
        
        return jsonify({
            'history': recent_history,
            'count': len(recent_history)
        })
    except Exception as e:
        current_app.logger.error(f"Error getting search history: {str(e)}")
        return jsonify({'error': 'Failed to load search history'}), 500


@enhanced_bp.route('/search-history', methods=['POST'])
def add_search_to_history():
    """Add a search query to history"""
    try:
        data = request.get_json()
        if not data or 'query' not in data:
            return jsonify({'error': 'Query is required'}), 400
        
        query = data['query'].strip()
        if query and query not in search_history:
            search_history.append(query)
            
            # Keep only last 50 searches
            if len(search_history) > 50:
                search_history.pop(0)
        
        return jsonify({
            'message': 'Query added to history',
            'query': query
        })
        
    except Exception as e:
        current_app.logger.error(f"Error adding to search history: {str(e)}")
        return jsonify({'error': 'Failed to add to search history'}), 500


@enhanced_bp.route('/analytics/search-stats')
def get_search_analytics():
    """Get basic search analytics"""
    try:
        # Basic analytics based on search history
        total_searches = len(search_history)
        unique_searches = len(set(search_history))
        
        # Most common terms
        term_counts = {}
        for query in search_history:
            words = query.lower().split()
            for word in words:
                if len(word) > 3:  # Skip short words
                    term_counts[word] = term_counts.get(word, 0) + 1
        
        popular_terms = sorted(term_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return jsonify({
            'total_searches': total_searches,
            'unique_searches': unique_searches,
            'popular_terms': [{'term': term, 'count': count} for term, count in popular_terms],
            'recent_searches': search_history[-5:]
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting search analytics: {str(e)}")
        return jsonify({'error': 'Failed to load analytics'}), 500
