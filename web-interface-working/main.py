#!/usr/bin/env python3
"""
OmicsOracle - WORKING Web Interface
==================================

A minimalist, reliable web interface that actually works.
No mock data, no complex dependencies, just functionality.
"""

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "src"))

import uvicorn
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="OmicsOracle - Working Interface", version="1.0.0")

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
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🧬 OmicsOracle</h1>
            <p>Working Web Interface</p>
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
                    <input type="text" id="query" name="query"
                           placeholder="e.g., BRCA1 breast cancer, RNA-seq brain tumor..."
                           required>
                </div>

                <div class="form-group">
                    <label for="max_results">Maximum Results</label>
                    <select id="max_results" name="max_results">
                        <option value="5">5 results</option>
                        <option value="10" selected>10 results</option>
                        <option value="20">20 results</option>
                        <option value="50">50 results</option>
                    </select>
                </div>

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
                let html = `<div class="success">✅ Found ${data.results.length} datasets</div>`;

                data.results.forEach(result => {
                    html += `
                        <div class="result-item">
                            <div class="result-title">${result.title}</div>
                            <div class="result-meta">
                                ID: ${result.id} |
                                Organism: ${result.organism || 'Unknown'} |
                                Samples: ${result.sample_count || 'Unknown'}
                            </div>
                            <div class="result-summary">${result.summary}</div>
                        </div>
                    `;
                });

                results.innerHTML = html;
            } else {
                results.innerHTML = '<div class="error">No datasets found for your query. Try different keywords.</div>';
            }
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
async def search(query: str = Form(...), max_results: int = Form(10)):
    """Handle search requests"""
    try:
        logger.info(f"Search request: '{query}' (max_results: {max_results})")

        if OMICS_AVAILABLE and pipeline:
            # Use real OmicsOracle pipeline
            try:
                # Run the search
                results = await pipeline.process_query(
                    query, max_results=max_results
                )

                # Process results
                processed_results = []
                if hasattr(results, "metadata") and results.metadata:
                    for result in results.metadata[:max_results]:
                        processed_results.append(
                            {
                                "id": result.get(
                                    "id", result.get("accession", "unknown")
                                ),
                                "title": result.get("title", "No title"),
                                "summary": result.get(
                                    "summary",
                                    result.get(
                                        "description",
                                        "No description available",
                                    ),
                                ),
                                "organism": result.get("organism", None),
                                "sample_count": result.get(
                                    "sample_count", None
                                ),
                                "platform": getattr(result, "platform", None),
                            }
                        )

                return JSONResponse(
                    {
                        "results": processed_results,
                        "total_count": len(processed_results),
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


if __name__ == "__main__":
    print("🧬 Starting OmicsOracle - WORKING Web Interface")
    print("=" * 50)
    print(f"✅ Interface: http://localhost:8080")
    print(f"✅ OmicsOracle Available: {OMICS_AVAILABLE}")
    print("=" * 50)

    uvicorn.run(
        "main:app", host="0.0.0.0", port=8080, reload=False, log_level="info"
    )
