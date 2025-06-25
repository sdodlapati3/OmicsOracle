#!/bin/bash
#
# Startup script for OmicsOracle Original Web Interface
#

echo "🧬 Starting OmicsOracle - Original Web Interface"
echo "================================================"

# Check if we're in the right directory
if [ ! -f "main.py" ]; then
    echo "❌ Error: main.py not found. Please run this script from the web-interface-original directory."
    exit 1
fi

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python3 is not installed or not in PATH"
    exit 1
fi

# Get the project root directory (parent of web-interface-original)
PROJECT_ROOT="$(dirname "$(pwd)")"
VENV_PATH="$PROJECT_ROOT/venv"

# Check if virtual environment exists
if [ ! -d "$VENV_PATH" ]; then
    echo "❌ Virtual environment not found at $VENV_PATH"
    echo "Please run 'python3 -m venv venv' from the project root directory first"
    exit 1
fi

# Activate virtual environment
echo "🔧 Activating virtual environment (venv)..."
source "$VENV_PATH/bin/activate"

# Install dependencies if needed
if [ -f "requirements.txt" ]; then
    echo "📦 Installing dependencies..."
    pip install -r requirements.txt
fi

echo ""
echo "🚀 Starting server..."
echo "   Interface URL: http://localhost:8001"
echo "   Health Check: http://localhost:8001/health"
echo ""
echo "   This is the ORIGINAL web interface for OmicsOracle"
echo "   It runs independently on port 8001"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Start the server
python main.py
