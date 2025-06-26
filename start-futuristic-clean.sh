#!/bin/bash

# OmicsOracle Futuristic Interface - Clean Startup Script
# This script starts the futuristic interface with the modular OmicsOracle pipeline

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR" && pwd)"

echo "🧬 OmicsOracle Futuristic Interface - Clean Version"
echo "=================================================="

# Check if we're in the right directory
if [ ! -f "$PROJECT_ROOT/src/omics_oracle/core/config.py" ]; then
    echo "❌ Error: Not in the correct OmicsOracle project directory"
    echo "Please run this script from the project root directory"
    exit 1
fi

# Stop any existing servers on port 8001
echo "🔄 Stopping any existing servers on port 8001..."
lsof -ti:8001 | xargs kill -9 2>/dev/null || true
sleep 1

# Set environment variables
export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"
export OMICS_ORACLE_ENV="development"

# Activate virtual environment from root folder
echo "🐍 Activating virtual environment..."
if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
    source "$PROJECT_ROOT/venv/bin/activate"
    echo "   ✅ Virtual environment activated: $(which python)"
    python_version=$(python --version 2>&1 | cut -d' ' -f2)
    echo "   Python version: $python_version"
elif [ -f "$PROJECT_ROOT/.venv/bin/activate" ]; then
    source "$PROJECT_ROOT/.venv/bin/activate"
    echo "   ✅ Virtual environment activated: $(which python)"
    python_version=$(python --version 2>&1 | cut -d' ' -f2)
    echo "   Python version: $python_version"
else
    echo "   ⚠️  No virtual environment found, using system Python"
    if ! command -v python3 &> /dev/null; then
        echo "❌ Error: Python 3 is not installed or not in PATH"
        exit 1
    fi
    python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
    echo "   Python version: $python_version"
fi

echo "   ✅ Python environment ready"

# Start the FastAPI server directly
echo "🚀 Starting main FastAPI server..."
echo "   URL: http://localhost:8001"
echo "   Press Ctrl+C to stop"
echo ""

cd interfaces/futuristic
python main.py
