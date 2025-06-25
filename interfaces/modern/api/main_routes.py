"""
Main web interface blueprint for OmicsOracle modern interface
Serves HTML templates and handles basic web routes
"""

import asyncio

from flask import Blueprint, current_app, render_template, request
from models import SearchQuery, SearchType
from services.search_service import SearchService

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """Serve the main interface"""
    try:
        # Simple availability check - just create service instance
        search_service = SearchService()
        omics_available = True  # Assume available if service can be created

        current_app.logger.info(
            f"Main interface loaded, pipeline available: {omics_available}"
        )

        return render_template(
            "index.html",
            omics_available=omics_available,
            title_suffix="Modern Interface",
            subtitle="Modern Interface",
        )
    except Exception as e:
        current_app.logger.error(f"Error loading main interface: {str(e)}")
        return render_template(
            "index.html",
            omics_available=False,
            title_suffix="Modern Interface (Error)",
            subtitle="Modern Interface - Error Loading Pipeline",
        )


@main_bp.route("/search", methods=["GET", "POST"])
def search_web():
    """Handle web-based search requests (for non-JS fallback)"""
    if request.method == "GET":
        return render_template("index.html", omics_available=True)

    try:
        # Extract form data
        query = request.form.get("query", "").strip()
        max_results = int(request.form.get("max_results", 10))
        page = int(request.form.get("page", 1))
        page_size = int(request.form.get("page_size", 10))

        if not query:
            return render_template(
                "index.html",
                error="Please enter a search query",
                omics_available=True,
            )

        # Create search query object
        search_query = SearchQuery(
            query=query,
            search_type=SearchType.BASIC,
            page=page,
            page_size=page_size,
        )

        # Use search service
        search_service = SearchService()
        results = asyncio.run(search_service.search(search_query))

        current_app.logger.info(
            f"Web search completed: {len(results.results)} results"
        )

        return render_template(
            "index.html",
            omics_available=True,
            query=query,
            max_results=max_results,
            page=page,
            page_size=page_size,
            results=results.to_dict(),
        )

    except Exception as e:
        current_app.logger.error(f"Web search error: {str(e)}")
        return render_template(
            "index.html",
            error=f"Search error: {str(e)}",
            omics_available=True,
            query=request.form.get("query", ""),
        )


@main_bp.route("/about")
def about():
    """About page"""
    return render_template(
        "index.html",
        omics_available=True,
        title_suffix="About",
        subtitle="About OmicsOracle",
    )
