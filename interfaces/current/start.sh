#!/bin/bash
#
# OmicsOracle STABLE Web Interface Startup Script
#

echo "🚀 Starting OmicsOracle STABLE Web Interface..."
echo "================================================"

# Get the project root directory (go up two levels from interfaces/current/)
PROJECT_ROOT="$(dirname "$(dirname "$(pwd)")")"
VENV_PATH="$PROJECT_ROOT/venv"

# Activate virtual environment
if [ -d "$VENV_PATH" ]; then
    echo "🔧 Activating virtual environment (venv)..."
    source "$VENV_PATH/bin/activate"
else
    echo "❌ Virtual environment not found at $VENV_PATH"
    echo "Please ensure you have a virtual environment set up"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Start the interface
echo ""
echo "🌐 Starting STABLE interface on http://localhost:8888"
echo "   This interface will actually work or clearly tell you why it doesn't!"
echo ""
python main.py
