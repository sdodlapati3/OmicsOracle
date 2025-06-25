#!/bin/bash
#
# OmicsOracle BACKEND API Startup Script
#

echo "🚀 Starting OmicsOracle BACKEND API..."
echo "======================================="

# Get the project root directory
PROJECT_ROOT="$(dirname "$(pwd)")"

echo "🔧 Activating virtual environment (venv)..."
source "$PROJECT_ROOT/venv/bin/activate"

echo "📦 Installing dependencies..."
pip install -r "$PROJECT_ROOT/requirements.txt" -q

echo ""
echo "🌐 Starting BACKEND API on http://localhost:8000"
echo "   Pure REST API for programmatic access"
echo ""

# Add current directory to Python path
export PYTHONPATH="$PROJECT_ROOT/src:$PYTHONPATH"

# Change to project root before starting
cd "$PROJECT_ROOT"

# Start the API server
python -m omics_oracle.web.main
