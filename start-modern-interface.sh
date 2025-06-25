#!/bin/bash

# OmicsOracle Modern Interface Startup Script
# This script activates the virtual environment and starts the modern interface

set -e  # Exit on any error

echo "🚀 Starting OmicsOracle Modern Interface..."

# Define paths
PROJECT_ROOT="/Users/sanjeevadodlapati/Downloads/Repos/OmicsOracle"
MODERN_DIR="$PROJECT_ROOT/interfaces/modern"

# Check if we're in the right directory
if [ ! -d "$PROJECT_ROOT" ]; then
    echo "❌ Error: Project root directory not found: $PROJECT_ROOT"
    exit 1
fi

cd "$PROJECT_ROOT"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Error: Virtual environment not found. Please run setup-modern-interface.sh first"
    exit 1
fi

echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Verify Python environment
echo "🐍 Python version: $(python --version)"
echo "📦 Pip location: $(which pip)"

# Check if Flask is available
if ! python -c "import flask" 2>/dev/null; then
    echo "❌ Error: Flask not found. Installing dependencies..."
    pip install -r "$MODERN_DIR/requirements.txt"
fi

# Load environment variables
if [ -f ".env" ]; then
    echo "🔧 Loading environment variables from .env"
    set -a  # Mark variables for export
    source .env
    set +a  # Unmark variables for export
else
    echo "⚠️  Warning: .env file not found, using defaults"
    export FLASK_ENV=development
    export PORT=5001
    export HOST=0.0.0.0
fi

# Set Python path to include modern interface
export PYTHONPATH="$MODERN_DIR:$PYTHONPATH"

echo "📁 Working directory: $(pwd)"
echo "🌐 Starting server on $HOST:$PORT"
echo "🔧 Environment: $FLASK_ENV"
echo ""

# Change to modern interface directory
cd "$MODERN_DIR"

# Start the Flask application
echo "🚀 Launching OmicsOracle Modern Interface..."
echo "   • Health check: http://localhost:$PORT/api/v1/health"
echo "   • Search API: http://localhost:$PORT/api/v1/search"
echo "   • Detailed health: http://localhost:$PORT/api/v1/health/detailed"
echo ""
echo "Press Ctrl+C to stop the server"
echo "=" * 50

# Run the application
python main.py
