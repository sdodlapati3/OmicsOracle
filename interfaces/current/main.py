#!/usr/bin/env python3
"""
OmicsOracle - STABLE Web Interface
==================================

A minimalist, reliable web interface that actually works.
No mock data, no complex dependencies, just functionality.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "src"))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="OmicsOracle - Working Interface", version="1.0.0")

# In-memory storage for search analytics
search_analytics = {
    "total_searches": 0,
    "recent_queries": [],
    "popular_terms": {},
    "search_history": [],
}

# Enhanced search suggestions for auto-complete
SEARCH_SUGGESTIONS = {
    "cancer": [
        "breast cancer BRCA1",
        "lung cancer RNA-seq",
        "colorectal cancer genomics",
        "cancer biomarkers",
        "tumor suppressor genes",
        "ovarian cancer BRCA",
        "prostate cancer genomics",
        "pancreatic cancer KRAS",
        "liver cancer HCC",
    ],
    "rna": [
        "RNA-seq differential expression",
        "RNA-seq breast cancer",
        "RNA sequencing data",
        "microRNA cancer",
        "long non-coding RNA",
        "single-cell RNA-seq",
        "RNA splicing variants",
        "RNA expression profiling",
    ],
    "brain": [
        "brain tumor genomics",
        "brain cancer methylation",
        "neuroblastoma RNA-seq",
        "glioblastoma expression",
        "brain development transcriptome",
        "alzheimer's disease pathology",
        "parkinson's disease genetics",
        "autism spectrum disorder",
    ],
    "diabetes": [
        "diabetes insulin resistance",
        "type 2 diabetes genomics",
        "diabetic nephropathy",
        "pancreatic beta cells",
        "glucose metabolism",
        "type 1 diabetes genetics",
        "insulin signaling pathway",
    ],
    "heart": [
        "cardiac hypertrophy",
        "heart failure genomics",
        "cardiovascular disease",
        "myocardial infarction",
        "cardiac development",
        "atherosclerosis",
        "arrhythmia genetics",
    ],
    "immune": [
        "immune system response",
        "autoimmune disease genetics",
        "T cell activation",
        "immunotherapy biomarkers",
        "inflammation genomics",
        "cytokine signaling",
    ],
}

# Popular search terms for quick filters
QUICK_FILTER_TERMS = [
    "Cancer",
    "RNA-seq",
    "Brain",
    "Diabetes",
    "Heart Disease",
    "Immune System",
    "BRCA1",
    "Transcriptome",
]

# Example searches to show users
EXAMPLE_SEARCHES = [
    "BRCA1 breast cancer",
    "RNA-seq brain tumor",
    "diabetes insulin resistance",
    "heart failure genomics",
    "immune system COVID-19",
    "alzheimer's disease pathology",
]

# Try to import OmicsOracle components
OMICS_AVAILABLE = False
try:
    from omics_oracle.core.config import Config
    from omics_oracle.pipeline import OmicsOracle

    logger.info("✅ OmicsOracle modules loaded successfully")
    OMICS_AVAILABLE = True

    # Initialize pipeline
    config = Config()
    pipeline = OmicsOracle(config)
    logger.info("✅ Pipeline initialized")

except Exception as e:
    logger.error(f"❌ Failed to load OmicsOracle: {e}")
    logger.info("Will create a basic interface without full functionality")
    pipeline = None
    config = None

# Simple HTML template (no external dependencies)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OmicsOracle - Working Interface</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        .status {
            padding: 15px 30px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }
        .status.available { background: #d4edda; color: #155724; }
        .status.unavailable { background: #f8d7da; color: #721c24; }
        .content {
            padding: 30px;
        }
        .search-form {
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #2c3e50;
        }
        input[type="text"], input[type="number"], select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input:focus, select:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
        }
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        .results {
            margin-top: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
            display: none;
        }
        .results.show {
            display: block;
        }
        .loading {
            text-align: center;
            padding: 40px;
            color: #6c757d;
        }
        .result-item {
            background: white;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            position: relative;
        }
        .result-number {
            position: absolute;
            top: 15px;
            right: 20px;
            background: #667eea;
            color: white;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .result-title {
            font-size: 1.2rem;
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 10px;
        }
        .result-meta {
            color: #6c757d;
            font-size: 0.9rem;
            margin-bottom: 10px;
        }
        .result-summary {
            color: #495057;
            line-height: 1.6;
        }
        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .success {
            background: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 10px;
            margin-top: 20px;
            padding: 20px;
        }
        .pagination button {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 8px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s;
        }
        .pagination button:hover:not(:disabled) {
            background: #e9ecef;
        }
        .pagination button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .pagination button.active {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }
        .pagination-info {
            color: #6c757d;
            font-size: 14px;
            margin: 0 15px;
        }

        /* Enhanced Search Interface Styles */
        .search-container {
            position: relative;
        }

        .search-suggestions {
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: white;
            border: 1px solid #ddd;
            border-top: none;
            border-radius: 0 0 6px 6px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            max-height: 200px;
            overflow-y: auto;
            z-index: 1000;
            display: none;
        }

        .suggestion-item {
            padding: 10px 15px;
            cursor: pointer;
            border-bottom: 1px solid #f0f0f0;
            transition: background-color 0.2s;
        }

        .suggestion-item:hover, .suggestion-item.active {
            background-color: #f8f9fa;
        }

        .suggestion-item:last-child {
            border-bottom: none;
        }

        .quick-filters {
            margin: 15px 0;
        }

        .quick-filters-label {
            font-size: 14px;
            color: #6c757d;
            margin-bottom: 8px;
            display: block;
        }

        .filter-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .filter-tag {
            background: #e9ecef;
            color: #495057;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 13px;
            cursor: pointer;
            transition: all 0.2s;
            border: 1px solid #dee2e6;
        }

        .filter-tag:hover {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }

        .search-helpers {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin: 10px 0;
            font-size: 13px;
            color: #6c757d;
        }

        .example-searches, .search-history {
            cursor: pointer;
            text-decoration: underline;
        }

        .example-searches:hover, .search-history:hover {
            color: #667eea;
        }

        .search-dropdown {
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: white;
            border: 1px solid #ddd;
            border-radius: 6px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            max-height: 150px;
            overflow-y: auto;
            z-index: 1000;
            display: none;
        }

        .dropdown-item {
            padding: 8px 15px;
            cursor: pointer;
            border-bottom: 1px solid #f0f0f0;
            font-size: 14px;
        }

        .dropdown-item:hover {
            background-color: #f8f9fa;
        }

        .dropdown-item:last-child {
            border-bottom: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🧬 OmicsOracle</h1>
            <p>Stable Web Interface</p>
        </div>

        <div class="status {{ 'available' if omics_available else 'unavailable' }}">
            {% if omics_available %}
                ✅ <strong>Fully Functional</strong> - Connected to OmicsOracle pipeline
            {% else %}
                ⚠️ <strong>Limited Mode</strong> - OmicsOracle pipeline not available
            {% endif %}
        </div>

        <div class="content">
            <form class="search-form" id="searchForm" method="post" action="/search">
                <div class="form-group">
                    <label for="query">Search Query</label>
                    <div class="search-container">
                        <input type="text" id="query" name="query"
                               placeholder="e.g., BRCA1 breast cancer, RNA-seq brain tumor..."
                               autocomplete="off"
                               required>
                        <div id="searchSuggestions" class="search-suggestions"></div>
                    </div>
                </div>

                <!-- Quick Filters -->
                <div class="quick-filters">
                    <span class="quick-filters-label">Quick search topics:</span>
                    <div class="filter-tags" id="quickFilters">
                        <!-- Quick filter tags will be loaded here -->
                    </div>
                </div>

                <!-- Search Helpers -->
                <div class="search-helpers">
                    <span class="example-searches" id="showExamples">View example searches</span>
                    <span class="search-history" id="showHistory">Recent searches</span>
                </div>

                <!-- Hidden fields for pagination -->
                <input type="hidden" id="max_results" name="max_results" value="10">
                <input type="hidden" id="page" name="page" value="1">
                <input type="hidden" id="page_size" name="page_size" value="10">

                <button type="submit" class="btn" id="searchBtn">
                    🔍 Search Datasets
                </button>
            </form>

            <div id="results" class="results">
                <!-- Results will be displayed here -->
            </div>
        </div>
    </div>

    <script>
        // Enhanced Search Interface JavaScript
        let suggestionIndex = -1;
        let suggestions = [];

        // Initialize enhanced search features when page loads
        document.addEventListener('DOMContentLoaded', function() {
            loadQuickFilters();
            setupSearchInput();
            setupSearchHelpers();
        });

        // Load quick filter tags
        async function loadQuickFilters() {
            try {
                const response = await fetch('/api/quick-filters');
                const data = await response.json();
                const filtersContainer = document.getElementById('quickFilters');

                data.filters.forEach(filter => {
                    const tag = document.createElement('span');
                    tag.className = 'filter-tag';
                    tag.textContent = filter;
                    tag.onclick = () => {
                        document.getElementById('query').value = filter;
                        document.getElementById('query').focus();
                    };
                    filtersContainer.appendChild(tag);
                });
            } catch (error) {
                console.log('Quick filters not available');
            }
        }

        // Setup search input with autocomplete
        function setupSearchInput() {
            const queryInput = document.getElementById('query');
            const suggestionsDiv = document.getElementById('searchSuggestions');

            queryInput.addEventListener('input', async function(e) {
                const query = e.target.value;
                if (query.length < 2) {
                    hideSuggestions();
                    return;
                }

                try {
                    const response = await fetch(`/api/search-suggestions?q=${encodeURIComponent(query)}`);
                    const data = await response.json();
                    suggestions = data.suggestions || [];
                    showSuggestions(suggestions);
                } catch (error) {
                    console.log('Suggestions not available');
                }
            });

            queryInput.addEventListener('keydown', function(e) {
                if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    suggestionIndex = Math.min(suggestionIndex + 1, suggestions.length - 1);
                    highlightSuggestion();
                } else if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    suggestionIndex = Math.max(suggestionIndex - 1, -1);
                    highlightSuggestion();
                } else if (e.key === 'Enter' && suggestionIndex >= 0) {
                    e.preventDefault();
                    selectSuggestion(suggestions[suggestionIndex]);
                } else if (e.key === 'Escape') {
                    hideSuggestions();
                }
            });

            queryInput.addEventListener('blur', function() {
                // Delay hiding to allow clicks on suggestions
                setTimeout(hideSuggestions, 200);
            });
        }

        function showSuggestions(suggestions) {
            const suggestionsDiv = document.getElementById('searchSuggestions');
            if (suggestions.length === 0) {
                hideSuggestions();
                return;
            }

            suggestionsDiv.innerHTML = '';
            suggestions.forEach((suggestion, index) => {
                const item = document.createElement('div');
                item.className = 'suggestion-item';
                item.textContent = suggestion;
                item.onclick = () => selectSuggestion(suggestion);
                suggestionsDiv.appendChild(item);
            });

            suggestionsDiv.style.display = 'block';
            suggestionIndex = -1;
        }

        function hideSuggestions() {
            document.getElementById('searchSuggestions').style.display = 'none';
            suggestionIndex = -1;
        }

        function highlightSuggestion() {
            const items = document.querySelectorAll('.suggestion-item');
            items.forEach((item, index) => {
                item.classList.toggle('active', index === suggestionIndex);
            });
        }

        function selectSuggestion(suggestion) {
            document.getElementById('query').value = suggestion;
            hideSuggestions();
            document.getElementById('query').focus();
        }

        // Setup search helper links
        function setupSearchHelpers() {
            document.getElementById('showExamples').addEventListener('click', showExampleSearches);
            document.getElementById('showHistory').addEventListener('click', showSearchHistory);
        }

        async function showExampleSearches() {
            try {
                const response = await fetch('/api/example-searches');
                const data = await response.json();
                showDropdown(data.examples, 'Example Searches');
            } catch (error) {
                console.log('Examples not available');
            }
        }

        async function showSearchHistory() {
            try {
                const response = await fetch('/api/search-history');
                const data = await response.json();
                if (data.history.length > 0) {
                    showDropdown(data.history, 'Recent Searches');
                } else {
                    alert('No recent searches found');
                }
            } catch (error) {
                console.log('Search history not available');
            }
        }

        function showDropdown(items, title) {
            // Remove existing dropdown
            const existing = document.querySelector('.search-dropdown');
            if (existing) existing.remove();

            const dropdown = document.createElement('div');
            dropdown.className = 'search-dropdown';
            dropdown.style.display = 'block';

            items.forEach(item => {
                const div = document.createElement('div');
                div.className = 'dropdown-item';
                div.textContent = item;
                div.onclick = () => {
                    document.getElementById('query').value = item;
                    dropdown.remove();
                    document.getElementById('query').focus();
                };
                dropdown.appendChild(div);
            });

            // Position dropdown near the helpers
            const helpers = document.querySelector('.search-helpers');
            helpers.style.position = 'relative';
            helpers.appendChild(dropdown);

            // Auto-hide after 5 seconds
            setTimeout(() => {
                if (dropdown.parentNode) dropdown.remove();
            }, 5000);

            // Hide on click outside
            document.addEventListener('click', function hideDropdown(e) {
                if (!dropdown.contains(e.target) && !helpers.contains(e.target)) {
                    dropdown.remove();
                    document.removeEventListener('click', hideDropdown);
                }
            });
        }

        // Original search form handler
        document.getElementById('searchForm').addEventListener('submit', async function(e) {
            e.preventDefault();

            const searchBtn = document.getElementById('searchBtn');
            const results = document.getElementById('results');

            // Show loading state
            searchBtn.disabled = true;
            searchBtn.textContent = '🔄 Searching...';
            results.innerHTML = '<div class="loading">🔍 Searching datasets... Please wait.</div>';
            results.classList.add('show');

            try {
                const formData = new FormData(this);
                const response = await fetch('/search', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (response.ok) {
                    displayResults(data);
                } else {
                    displayError(data.error || 'Search failed');
                }

            } catch (error) {
                displayError('Network error: ' + error.message);
            } finally {
                searchBtn.disabled = false;
                searchBtn.textContent = '🔍 Search Datasets';
            }
        });

        function displayResults(data) {
            const results = document.getElementById('results');

            if (data.results && data.results.length > 0) {
                // Extract pagination info
                const pagination = data.pagination || {};
                const totalCount = pagination.total_results || data.total_count || data.results.length;
                const displayedCount = data.results.length;
                const currentPage = pagination.current_page || 1;
                const totalPages = pagination.total_pages || 1;

                // Improved count display with pagination info
                let countMessage;
                if (totalPages > 1) {
                    countMessage = `✅ Showing ${pagination.start_index || 1}-${pagination.end_index || displayedCount} of ${totalCount} datasets (Page ${currentPage} of ${totalPages})`;
                } else if (totalCount === displayedCount) {
                    countMessage = `✅ Found ${totalCount} dataset${totalCount !== 1 ? 's' : ''}`;
                } else {
                    countMessage = `✅ Showing ${displayedCount} of ${totalCount} datasets`;
                }

                let html = `<div class="success">${countMessage}</div>`;

                data.results.forEach((result, index) => {
                    const globalIndex = ((currentPage - 1) * (pagination.page_size || 10)) + index + 1;
                    const aiIndicator = result.ai_enhanced ? '<span style="color: #28a745; font-weight: bold;">🤖 AI Enhanced</span> | ' : '';
                    const samplesBtn = result.id !== 'unknown' ?
                        `<button class="btn-samples" onclick="showSamples('${result.id}')">📋 View Samples</button>` : '';

                    html += `
                        <div class="result-item">
                            <div class="result-number">${globalIndex}</div>
                            <div class="result-title">${result.title}</div>
                            <div class="result-meta">
                                ${aiIndicator}ID: ${result.id} |
                                Organism: ${result.organism || 'Unknown'} |
                                Samples: ${result.sample_count || 'Unknown'}
                                ${samplesBtn}
                            </div>
                            <div class="result-summary">${result.summary}</div>
                        </div>
                    `;
                });

                // Add pagination controls if more than one page
                if (totalPages > 1) {
                    html += createPaginationControls(pagination);
                }

                results.innerHTML = html;
            } else {
                results.innerHTML = '<div class="error">No datasets found for your query. Try different keywords.</div>';
            }
        }

        function createPaginationControls(pagination) {
            const currentPage = pagination.current_page || 1;
            const totalPages = pagination.total_pages || 1;
            const hasPrevious = pagination.has_previous || false;
            const hasNext = pagination.has_next || false;

            let paginationHtml = '<div class="pagination">';

            // Previous button
            paginationHtml += `<button onclick="goToPage(${currentPage - 1})" ${!hasPrevious ? 'disabled' : ''}>← Previous</button>`;

            // Page numbers (show current page and nearby pages)
            const startPage = Math.max(1, currentPage - 2);
            const endPage = Math.min(totalPages, currentPage + 2);

            if (startPage > 1) {
                paginationHtml += `<button onclick="goToPage(1)">1</button>`;
                if (startPage > 2) {
                    paginationHtml += '<span class="pagination-info">...</span>';
                }
            }

            for (let i = startPage; i <= endPage; i++) {
                const activeClass = i === currentPage ? 'active' : '';
                paginationHtml += `<button class="${activeClass}" onclick="goToPage(${i})">${i}</button>`;
            }

            if (endPage < totalPages) {
                if (endPage < totalPages - 1) {
                    paginationHtml += '<span class="pagination-info">...</span>';
                }
                paginationHtml += `<button onclick="goToPage(${totalPages})">${totalPages}</button>`;
            }

            // Next button
            paginationHtml += `<button onclick="goToPage(${currentPage + 1})" ${!hasNext ? 'disabled' : ''}>Next →</button>`;

            // Page info
            paginationHtml += `<span class="pagination-info">Page ${currentPage} of ${totalPages}</span>`;

            paginationHtml += '</div>';

            return paginationHtml;
        }

        function goToPage(page) {
            document.getElementById('page').value = page;
            document.getElementById('searchForm').dispatchEvent(new Event('submit'));
        }

        function displayError(message) {
            const results = document.getElementById('results');
            results.innerHTML = `<div class="error">❌ Error: ${message}</div>`;
        }
    </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def home():
    """Serve the main interface"""
    from jinja2 import Template

    template = Template(HTML_TEMPLATE)
    return template.render(omics_available=OMICS_AVAILABLE)


@app.post("/search")
async def search(
    query: str = Form(...),
    max_results: int = Form(10),
    page: int = Form(1),
    page_size: int = Form(10),
):
    """Handle search requests with pagination support"""
    try:
        # Calculate pagination parameters
        offset = (page - 1) * page_size

        logger.info(
            f"Search request: '{query}' (page: {page}, page_size: {page_size}, offset: {offset})"
        )

        # Update search analytics
        update_search_analytics(query)

        if OMICS_AVAILABLE and pipeline:
            # Use real OmicsOracle pipeline
            try:
                # Run the search with extended results for pagination
                total_results_requested = max(max_results, page * page_size)
                results = await pipeline.process_query(
                    query, max_results=total_results_requested
                )

                # Process results with AI-enhanced summaries
                processed_results = []
                total_count = 0

                if hasattr(results, "metadata") and results.metadata:
                    total_count = len(results.metadata)
                    ai_summaries = getattr(results, "ai_summaries", {})
                    individual_summaries = ai_summaries.get(
                        "individual_summaries", []
                    )

                    # Debug logging
                    logger.info(f"AI summaries available: {bool(ai_summaries)}")
                    logger.info(
                        f"Individual summaries count: {len(individual_summaries)}"
                    )
                    logger.info(
                        f"AI summaries keys: {list(ai_summaries.keys())}"
                    )

                    # Apply pagination to results
                    start_idx = offset
                    end_idx = offset + page_size
                    paginated_metadata = results.metadata[start_idx:end_idx]

                    for i, result in enumerate(paginated_metadata):
                        # First, try to get the AI summary to potentially extract metadata from it
                        ai_summary = None
                        if i < len(individual_summaries):
                            potential_summary = individual_summaries[i].get(
                                "summary"
                            )
                            if potential_summary:
                                ai_summary = potential_summary

                        # If no individual summary, try brief overview
                        if not ai_summary:
                            ai_summary = ai_summaries.get("brief_overview")

                        # Enhanced metadata extraction
                        geo_id = "unknown"
                        organism = "Unknown"
                        sample_count = "Unknown"

                        # Approach 1: Try dictionary access (primary method)
                        if hasattr(result, "get"):
                            try:
                                # Extract each field individually with explicit checking
                                extracted_geo_id = result.get("geo_id")
                                extracted_organism = result.get("organism")
                                extracted_sample_count = result.get(
                                    "sample_count"
                                )

                                # Only use non-empty values
                                if extracted_geo_id:
                                    geo_id = extracted_geo_id
                                if extracted_organism:
                                    organism = extracted_organism
                                if extracted_sample_count:
                                    sample_count = extracted_sample_count
                            except Exception as e:
                                logger.warning(f"Dict access failed: {e}")

                        # Approach 2: Try direct attribute access if dict access failed
                        if not geo_id or geo_id == "unknown":
                            try:
                                geo_id = (
                                    getattr(result, "geo_id", None)
                                    or getattr(result, "id", None)
                                    or getattr(result, "accession", None)
                                )
                            except Exception as e:
                                logger.warning(f"Attr access failed: {e}")

                        # Approach 3: Extract organism and sample_count if not found
                        if not organism or organism == "Unknown":
                            try:
                                organism = (
                                    getattr(result, "organism", None)
                                    or getattr(result, "species", None)
                                    or getattr(result, "taxon", None)
                                )
                            except Exception:
                                pass

                        if not sample_count or sample_count == "Unknown":
                            try:
                                sample_count = (
                                    getattr(result, "sample_count", None)
                                    or getattr(result, "n_samples", None)
                                    or getattr(result, "samples", None)
                                )
                            except Exception:
                                pass

                        # Approach 4: Extract from AI summary ONLY if direct extraction completely failed
                        if ai_summary and (
                            not geo_id or geo_id == "unknown" or geo_id == ""
                        ):
                            import re

                            summary_text = str(ai_summary)
                            # Look for GEO accession patterns (GSE followed by digits)
                            geo_match = re.search(r"GSE\d+", summary_text)
                            if geo_match:
                                extracted_geo = geo_match.group()
                                logger.info(
                                    f"AI FALLBACK: Extracted GEO ID from AI summary: {extracted_geo} (current geo_id: {geo_id})"
                                )
                                # Only use it if we don't have a valid geo_id already
                                if (
                                    not geo_id
                                    or geo_id == "unknown"
                                    or geo_id == ""
                                ):
                                    geo_id = extracted_geo
                                    logger.info(
                                        f"AI FALLBACK: Using AI-extracted GEO ID: {geo_id}"
                                    )
                            else:
                                logger.info(
                                    "AI FALLBACK: No GEO ID found in AI summary"
                                )

                        # Approach 4: Extract from original summary/title if still unknown
                        if not geo_id or geo_id == "unknown":
                            import re

                            original_text = (
                                result.get("summary", "")
                                + " "
                                + result.get("title", "")
                            )
                            geo_match = re.search(r"GSE\d+", original_text)
                            if geo_match:
                                geo_id = geo_match.group()
                                logger.info(
                                    f"Extracted GEO ID from original text: {geo_id}"
                                )

                        # Ensure we have string values, not None
                        geo_id = geo_id or "unknown"
                        organism = organism or "Unknown"
                        sample_count = sample_count or "Unknown"

                        logger.info(
                            f"Final result {i}: geo_id='{geo_id}', organism='{organism}', samples='{sample_count}'"
                        )

                        # Process AI summary and original summary
                        original_summary = result.get(
                            "summary",
                            result.get(
                                "description", "No description available"
                            ),
                        )

                        # Try to find the correct AI summary for this specific dataset
                        ai_summary = None

                        # First, try to find individual summary by matching accession/ID
                        if individual_summaries:
                            for summary_item in individual_summaries:
                                summary_accession = summary_item.get(
                                    "accession", ""
                                )
                                if summary_accession and (
                                    summary_accession == geo_id
                                    or summary_accession in str(result)
                                    or geo_id in summary_accession
                                ):
                                    ai_summary = summary_item.get("summary")
                                    logger.info(
                                        f"Dataset {geo_id}: Found matching AI summary by accession"
                                    )
                                    break

                        # Fallback: try positional matching only if we have enough summaries
                        if not ai_summary and i < len(individual_summaries):
                            potential_summary = individual_summaries[i].get(
                                "summary"
                            )
                            # Validate that this summary isn't generic for a different dataset
                            if potential_summary and isinstance(
                                potential_summary, dict
                            ):
                                summary_text = str(potential_summary)
                                # Check if summary mentions a different specific GEO ID
                                other_geo_ids = [
                                    "GSE297209",
                                    "GSE284759",
                                    "GSE289246",
                                ]
                                mentions_other_geo = any(
                                    other_id in summary_text
                                    and other_id != geo_id
                                    for other_id in other_geo_ids
                                )
                                if not mentions_other_geo:
                                    ai_summary = potential_summary
                                    logger.info(
                                        f"Dataset {geo_id}: Using positional AI summary"
                                    )
                                else:
                                    logger.warning(
                                        f"Dataset {geo_id}: Rejecting positional summary mentioning {[oid for oid in other_geo_ids if oid in summary_text]}"
                                    )

                        # Final fallback: use brief overview only if no individual summaries worked
                        if not ai_summary and not individual_summaries:
                            ai_summary = ai_summaries.get("brief_overview")
                            if ai_summary:
                                logger.info(
                                    f"Dataset {geo_id}: Using brief overview as fallback"
                                )

                        # Process the AI summary safely
                        if ai_summary:
                            if isinstance(ai_summary, dict):
                                # Use overview as primary summary, fallback to first available field
                                display_summary = (
                                    ai_summary.get("overview")
                                    or ai_summary.get("methodology")
                                    or ai_summary.get("significance")
                                    or str(ai_summary)
                                )
                            else:
                                display_summary = str(ai_summary)

                            # Enhanced generic summary detection
                            generic_indicators = [
                                "GSE297209",
                                "GSE284759",
                                "GSE289246",
                                "does not specifically address",
                                "does not directly address",
                            ]

                            is_generic = False
                            if ai_summary and isinstance(
                                ai_summary, (dict, str)
                            ):
                                summary_text = str(ai_summary)
                                is_generic = any(
                                    indicator in summary_text
                                    for indicator in generic_indicators
                                )

                                # Also check if it mentions a different GEO ID
                                for indicator in generic_indicators[
                                    :3
                                ]:  # GEO IDs
                                    if (
                                        indicator in summary_text
                                        and geo_id != indicator
                                        and geo_id != "unknown"
                                    ):
                                        is_generic = True
                                        break

                            if is_generic:
                                logger.warning(
                                    f"Generic AI summary detected for {geo_id}, using original abstract"
                                )
                                display_summary = original_summary
                                ai_summary = None

                        else:
                            display_summary = original_summary

                        processed_results.append(
                            {
                                "id": geo_id,
                                "title": result.get("title", "No title"),
                                "summary": display_summary,
                                "original_summary": original_summary,
                                "ai_summary_full": ai_summary
                                if isinstance(ai_summary, dict)
                                else None,
                                "organism": organism,
                                "sample_count": sample_count,
                                "platform": result.get("platform", "Unknown"),
                                "ai_enhanced": bool(
                                    ai_summary
                                ),  # Flag to indicate AI enhancement
                            }
                        )

                # Calculate pagination metadata
                total_available = total_count
                has_more = (offset + page_size) < total_count
                current_page = page
                total_pages = (
                    total_count + page_size - 1
                ) // page_size  # Ceiling division

                return JSONResponse(
                    {
                        "results": processed_results,
                        "pagination": {
                            "current_page": current_page,
                            "page_size": page_size,
                            "total_results": total_available,
                            "total_pages": total_pages,
                            "has_next": has_more,
                            "has_previous": current_page > 1,
                            "start_index": offset + 1,
                            "end_index": min(
                                offset + page_size, total_available
                            ),
                        },
                        "total_count": total_available,  # Keep for backward compatibility
                        "displayed_count": len(processed_results),
                        "query": query,
                        "status": "success",
                        "mode": "real_data",
                    }
                )

            except Exception as e:
                logger.error(f"Pipeline search failed: {e}")
                return JSONResponse(
                    {"error": f"Search failed: {str(e)}", "status": "error"},
                    status_code=500,
                )
        else:
            # Return informative message instead of mock data
            return JSONResponse(
                {
                    "results": [],
                    "total_count": 0,
                    "query": query,
                    "status": "unavailable",
                    "message": "OmicsOracle pipeline is not available. Please ensure it's properly installed and configured.",
                    "mode": "limited",
                }
            )

    except Exception as e:
        logger.error(f"Search error: {e}")
        return JSONResponse(
            {"error": str(e), "status": "error"}, status_code=500
        )


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "omics_available": OMICS_AVAILABLE,
        "interface": "working",
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/api/stats")
async def get_stats():
    """Get search statistics and analytics"""
    return {
        "total_searches": search_analytics["total_searches"],
        "recent_query_count": len(search_analytics["recent_queries"]),
        "popular_terms": dict(
            list(search_analytics["popular_terms"].items())[:10]
        ),
        "omics_available": OMICS_AVAILABLE,
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/api/search-suggestions")
async def get_search_suggestions(q: str = ""):
    """Enhanced search suggestions with smart matching"""
    suggestions = []
    query_lower = q.lower()

    # Find matching suggestions from predefined categories
    for term, term_suggestions in SEARCH_SUGGESTIONS.items():
        if term in query_lower or query_lower in term:
            suggestions.extend(term_suggestions)

    # Also check for partial matches in suggestions themselves
    for category_suggestions in SEARCH_SUGGESTIONS.values():
        for suggestion in category_suggestions:
            if (
                query_lower in suggestion.lower()
                and suggestion not in suggestions
            ):
                suggestions.append(suggestion)

    # If no specific matches, provide example searches
    if len(suggestions) == 0:
        suggestions = EXAMPLE_SEARCHES

    # Limit to top 8 suggestions
    return {"query": q, "suggestions": suggestions[:8], "status": "success"}


@app.get("/api/quick-filters")
async def get_quick_filters():
    """Get quick filter terms for search interface"""
    return {"filters": QUICK_FILTER_TERMS, "status": "success"}


@app.get("/api/search-history")
async def get_search_history():
    """Get recent search history"""
    recent_searches = search_analytics.get("recent_queries", [])
    # Return last 10 unique searches
    unique_searches = []
    seen = set()
    for search in reversed(recent_searches):
        query = search.get("query", "")
        if query not in seen and len(unique_searches) < 10:
            unique_searches.append(query)
            seen.add(query)

    return {"history": unique_searches, "status": "success"}


@app.get("/api/example-searches")
async def get_example_searches():
    """Get example search queries for user guidance"""
    return {"examples": EXAMPLE_SEARCHES, "status": "success"}


@app.get("/api/samples/{geo_id}")
async def get_samples(geo_id: str):
    """Get detailed sample information for a GEO dataset"""
    try:
        # Example implementation - replace with your actual database connection
        if OMICS_AVAILABLE and pipeline:
            # Try to get samples from GEO first (as fallback)
            geo_samples = []
            try:
                if hasattr(pipeline, "geo_client") and pipeline.geo_client:
                    # Get basic sample info from GEO
                    geo_data = await pipeline.geo_client.get_series_metadata(
                        geo_id
                    )
                    if (
                        geo_data
                        and hasattr(geo_data, "samples")
                        and geo_data.samples
                    ):
                        geo_samples = [
                            {
                                "sample_id": sample.get(
                                    "geo_accession", "unknown"
                                ),
                                "sample_name": sample.get("title", "Unknown"),
                                "tissue_type": sample.get(
                                    "source_name_ch1", "Unknown"
                                ),
                                "treatment": sample.get(
                                    "treatment_protocol_ch1", "Unknown"
                                ),
                                "platform": sample.get(
                                    "platform_id", "Unknown"
                                ),
                                "source": "GEO",
                            }
                            for sample in geo_data.samples.values()
                        ]
            except Exception as e:
                logger.warning(f"Could not fetch GEO samples for {geo_id}: {e}")

            # TODO: Replace this section with your internal database query
            internal_samples = []
            """
            # Example for PostgreSQL:
            internal_samples = await get_internal_samples(geo_id)

            # Example for REST API:
            internal_samples = await fetch_samples_from_internal_api(geo_id)
            """

            # Combine both sources
            all_samples = internal_samples + geo_samples

            return JSONResponse(
                {
                    "geo_id": geo_id,
                    "samples": all_samples[
                        :50
                    ],  # Limit to first 50 for performance
                    "total_count": len(all_samples),
                    "has_internal_data": len(internal_samples) > 0,
                    "sources": {
                        "internal": len(internal_samples),
                        "geo": len(geo_samples),
                    },
                    "status": "success",
                }
            )
        else:
            return JSONResponse(
                {
                    "geo_id": geo_id,
                    "samples": [],
                    "message": "Sample details not available - pipeline not loaded",
                    "status": "unavailable",
                }
            )
    except Exception as e:
        logger.error(f"Error getting samples for {geo_id}: {e}")
        return JSONResponse(
            {"error": str(e), "status": "error"}, status_code=500
        )


async def get_internal_samples(geo_id: str):
    """
    Replace this function with your actual internal database query

    Example implementations:
    """
    # Option 1: Direct database query (PostgreSQL example)
    """
    import psycopg2
    conn = psycopg2.connect(
        host="your-db-host",
        database="your-db-name",
        user="your-username",
        password="your-password"
    )
    cursor = conn.cursor()
    cursor.execute(\"\"\"
        SELECT sample_id, sample_name, tissue_type, treatment,
               patient_id, age, gender, platform
        FROM samples WHERE geo_series_id = %s
    \"\"\", (geo_id,))

    rows = cursor.fetchall()
    return [
        {
            "sample_id": row[0],
            "sample_name": row[1],
            "tissue_type": row[2],
            "treatment": row[3],
            "patient_id": row[4],
            "age": row[5],
            "gender": row[6],
            "platform": row[7],
            "source": "internal"
        }
        for row in rows
    ]
    """

    # Option 2: REST API call
    """
    import httpx
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"https://your-internal-api.com/datasets/{geo_id}/samples",
            headers={"Authorization": "Bearer YOUR_API_KEY"}
        )
        if response.status_code == 200:
            data = response.json()
            return data.get('samples', [])
    """

    # For now, return empty list - replace with your implementation
    return []


async def fetch_samples_from_internal_api(geo_id: str):
    """Example REST API integration"""
    # Replace with your actual API endpoint
    return []


# Helper function for search analytics
def update_search_analytics(query: str):
    """Update search analytics with the new query"""
    search_analytics["total_searches"] += 1
    search_analytics["recent_queries"].append(
        {"query": query, "timestamp": datetime.now().isoformat()}
    )

    # Keep only recent queries (last 100)
    if len(search_analytics["recent_queries"]) > 100:
        search_analytics["recent_queries"] = search_analytics["recent_queries"][
            -100:
        ]

    # Update popular terms
    terms = query.lower().split()
    for term in terms:
        if len(term) > 2:  # Ignore very short terms
            search_analytics["popular_terms"][term] = (
                search_analytics["popular_terms"].get(term, 0) + 1
            )


@app.post("/debug-search")
async def debug_search(query: str = Form(...), max_results: int = Form(2)):
    """Debug endpoint to inspect result object structure"""
    try:
        if OMICS_AVAILABLE and pipeline:
            results = await pipeline.process_query(
                query, max_results=max_results
            )

            debug_info = {
                "results_type": str(type(results)),
                "has_metadata": hasattr(results, "metadata"),
                "metadata_count": len(results.metadata)
                if hasattr(results, "metadata")
                else 0,
                "first_result_keys": [],
                "first_result_sample": {},
                "first_result_type": "",
                "ai_summaries_available": bool(
                    getattr(results, "ai_summaries", {})
                ),
            }

            if hasattr(results, "metadata") and results.metadata:
                first_result = results.metadata[0]
                debug_info["first_result_type"] = str(type(first_result))

                # If it's a dict, get keys
                if hasattr(first_result, "keys"):
                    debug_info["first_result_keys"] = list(first_result.keys())
                    debug_info["first_result_sample"] = {
                        k: str(v)[:100] for k, v in first_result.items()
                    }

                # If it has attributes, get them
                if hasattr(first_result, "__dict__"):
                    debug_info["first_result_attributes"] = list(
                        first_result.__dict__.keys()
                    )
                    debug_info["first_result_attr_sample"] = {
                        k: str(v)[:100]
                        for k, v in first_result.__dict__.items()
                    }

            return JSONResponse(debug_info)

        return JSONResponse({"error": "Pipeline not available"})

    except Exception as e:
        return JSONResponse({"error": str(e)})


if __name__ == "__main__":
    print("🚀 Starting OmicsOracle Web Interface...")
    print("🌐 Interface will be available at: http://localhost:8888")
    print("🔍 Health check: http://localhost:8888/health")
    print("=" * 50)

    # Run the server on localhost:8888 instead of 0.0.0.0:8888
    uvicorn.run(
        app,
        host="127.0.0.1",  # Use localhost instead of 0.0.0.0 for better browser compatibility
        port=8888,
        log_level="info",
        access_log=True,
    )
