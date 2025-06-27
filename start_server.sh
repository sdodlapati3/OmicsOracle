#!/bin/bash

# OmicsOracle FastAPI Server Startup Script
# Complete self-contained startup script

# Get the script's directory (works even if called from elsewhere)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Change to the project root directory
cd "$SCRIPT_DIR"

echo "🚀 Starting OmicsOracle FastAPI Server..."
echo "📁 Working directory: $(pwd)"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment 'venv' not found!"
    echo "Creating virtual environment..."
    python -m venv venv
    if [ $? -ne 0 ]; then
        echo "❌ Failed to create virtual environment!"
        exit 1
    fi
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Check if activation was successful
if [ -z "$VIRTUAL_ENV" ]; then
    echo "❌ Failed to activate virtual environment!"
    exit 1
fi

echo "✅ Virtual environment activated: $VIRTUAL_ENV"

# Load environment variables (prioritize .env.local for real API keys)
if [ -f ".env.local" ]; then
    echo "📋 Loading environment variables from .env.local..."
    set -a  # automatically export all variables
    source .env.local
    set +a  # stop automatically exporting
elif [ -f ".env.development" ]; then
    echo "📋 Loading environment variables from .env.development..."
    set -a  # automatically export all variables
    source .env.development
    set +a  # stop automatically exporting
fi

# Set NCBI_EMAIL if not already set (fallback)
if [ -z "$NCBI_EMAIL" ]; then
    export NCBI_EMAIL=omicsoracle@example.com
    echo "📧 Set fallback NCBI_EMAIL to: $NCBI_EMAIL"
fi

# Add src to Python path
export PYTHONPATH="$(pwd)/src:$PYTHONPATH"
echo "🐍 Python path updated"

# Install/upgrade dependencies
echo "📦 Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Check if uvicorn is installed
if ! command -v uvicorn &> /dev/null; then
    echo "📦 Installing uvicorn..."
    pip install uvicorn
fi

# Check if port 8000 is already in use
if lsof -Pi :8000 -sTCP:LISTEN -t >/dev/null ; then
    echo "⚠️  Port 8000 is already in use!"
    echo "🔍 Finding process using port 8000..."
    PROCESS_ID=$(lsof -ti:8000)
    if [ ! -z "$PROCESS_ID" ]; then
        echo "📝 Process ID: $PROCESS_ID"
        echo "🛑 Killing existing process..."
        kill $PROCESS_ID
        sleep 2
        echo "✅ Port 8000 is now available"
    fi
fi

# Start the FastAPI server
echo ""
echo "🌟 Starting FastAPI server on http://localhost:8000"
echo "📖 API documentation: http://localhost:8000/docs"
echo "🔍 Health check: http://localhost:8000/health"
echo "🎯 v1 API: http://localhost:8000/api/v1/"
echo "🚀 v2 API: http://localhost:8000/api/v2/"
echo ""
echo "Press Ctrl+C to stop the server"
echo "================================="
echo ""

# Run the FastAPI server using uvicorn directly
exec uvicorn src.omics_oracle.presentation.web.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --log-level info \
    --reload \
    --reload-dir src
