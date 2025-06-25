#!/bin/bash
#
# Simple activation and run script for OmicsOracle Original Web Interface
#

# Get the project root directory (parent of web-interface-original)
PROJECT_ROOT="$(dirname "$(pwd)")"
VENV_PATH="$PROJECT_ROOT/venv"

echo "🧬 OmicsOracle Original Web Interface - Quick Start"
echo "=================================================="

# Check if virtual environment exists
if [ ! -d "$VENV_PATH" ]; then
    echo "❌ Virtual environment not found at $VENV_PATH"
    echo ""
    echo "Creating virtual environment..."
    cd "$PROJECT_ROOT"
    python3 -m venv venv
    cd - > /dev/null
fi

# Activate virtual environment
echo "🔧 Activating virtual environment (venv)..."
source "$VENV_PATH/bin/activate"

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Start the server
echo ""
echo "🚀 Starting OmicsOracle Original Web Interface..."
echo "   URL: http://localhost:8001"
echo ""
python main.py
