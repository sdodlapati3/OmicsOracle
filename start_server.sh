#!/bin/bash

# OmicsOracle FastAPI Server Startup Script
# Complete self-contained startup script that works from any terminal

set -e  # Exit on any error

# Get the script's directory (works even if called from elsewhere)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Change to the project root directory
cd "$SCRIPT_DIR"

echo "🚀 Starting OmicsOracle FastAPI Server..."
echo "📁 Working directory: $(pwd)"

# Function to check if Python is available
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        echo "❌ Python not found! Please install Python 3.8+ first."
        exit 1
    fi
    echo "🐍 Using Python: $PYTHON_CMD"
}

# Check Python availability
check_python

# Check if virtual environment exists and is valid
if [ ! -d "venv" ] || [ ! -f "venv/bin/activate" ] || [ ! -f "venv/bin/python" ]; then
    echo "❌ Virtual environment 'venv' not found or invalid!"
    echo "Creating fresh virtual environment..."
    rm -rf venv 2>/dev/null || true  # Remove any broken venv
    $PYTHON_CMD -m venv venv
    if [ $? -ne 0 ]; then
        echo "❌ Failed to create virtual environment!"
        echo "💡 Make sure you have python3-venv installed: apt install python3-venv (Ubuntu) or brew install python (macOS)"
        exit 1
    fi
    echo "✅ Virtual environment created successfully"
fi

# Activate virtual environment with better error handling
echo "🔧 Activating virtual environment..."
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
elif [ -f "venv/Scripts/activate" ]; then  # Windows support
    source venv/Scripts/activate
else
    echo "❌ Virtual environment activation script not found!"
    exit 1
fi

# Verify activation worked
if [ -z "$VIRTUAL_ENV" ]; then
    echo "❌ Failed to activate virtual environment!"
    echo "💡 Try deleting 'venv' folder and running this script again"
    exit 1
fi

echo "✅ Virtual environment activated: $VIRTUAL_ENV"

# Load environment variables (prioritize .env.local for real API keys)
ENV_LOADED=false
if [ -f ".env.local" ]; then
    echo "📋 Loading environment variables from .env.local..."
    set -a  # automatically export all variables
    source .env.local
    set +a  # stop automatically exporting
    ENV_LOADED=true
elif [ -f ".env.development" ]; then
    echo "📋 Loading environment variables from .env.development..."
    set -a  # automatically export all variables
    source .env.development
    set +a  # stop automatically exporting
    ENV_LOADED=true
else
    echo "⚠️  No environment file (.env.local or .env.development) found!"
    echo "💡 Consider creating .env.local with your API keys"
fi

# Set NCBI_EMAIL if not already set (fallback)
if [ -z "$NCBI_EMAIL" ]; then
    export NCBI_EMAIL=omicsoracle@example.com
    echo "📧 Set fallback NCBI_EMAIL to: $NCBI_EMAIL"
else
    echo "📧 Using NCBI_EMAIL: $NCBI_EMAIL"
fi

# Add src to Python path
export PYTHONPATH="$(pwd)/src:$PYTHONPATH"
echo "🐍 Python path: $PYTHONPATH"

# Check if requirements.txt exists
if [ ! -f "requirements.txt" ]; then
    echo "❌ requirements.txt not found!"
    echo "💡 Make sure you're in the OmicsOracle project directory"
    exit 1
fi

# Install/upgrade dependencies
echo "📦 Installing dependencies..."
pip install -q --upgrade pip

# Install requirements with error checking
if ! pip install -q -r requirements.txt; then
    echo "❌ Failed to install dependencies from requirements.txt"
    echo "💡 Try running: pip install -r requirements.txt"
    exit 1
fi

# Check if uvicorn is available and install if needed
if ! python -c "import uvicorn" &> /dev/null; then
    echo "📦 Installing uvicorn..."
    pip install uvicorn[standard]
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install uvicorn!"
        exit 1
    fi
fi

# Verify our main module can be imported
echo "🔍 Verifying OmicsOracle installation..."
if ! python -c "from src.omics_oracle.presentation.web.main import app; print('✅ OmicsOracle app imported successfully')" 2>/dev/null; then
    echo "❌ Failed to import OmicsOracle main app!"
    echo "💡 There might be missing dependencies or import errors"
    echo "🔧 Showing detailed error:"
    python -c "from src.omics_oracle.presentation.web.main import app" 2>&1 || true
    echo ""
    echo "💡 This might be due to the recent DI container fixes. The server should still work."
    echo "🚀 Attempting to start server anyway..."
    # Don't exit - let uvicorn try to start and show the real error
fi

# Check if port 8000 is already in use and handle it gracefully
if lsof -Pi :8000 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "⚠️  Port 8000 is already in use!"
    echo "🔍 Finding process using port 8000..."
    PROCESS_ID=$(lsof -ti:8000 2>/dev/null || echo "")
    if [ ! -z "$PROCESS_ID" ]; then
        echo "📝 Process ID: $PROCESS_ID"
        echo "🛑 Killing existing process..."
        kill $PROCESS_ID 2>/dev/null || echo "⚠️  Could not kill process (might be already dead)"
        sleep 2

        # Double-check if port is free now
        if lsof -Pi :8000 -sTCP:LISTEN -t >/dev/null 2>&1; then
            echo "❌ Port 8000 is still in use! Try manually killing the process or using a different port."
            exit 1
        else
            echo "✅ Port 8000 is now available"
        fi
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

# Set up cleanup trap
cleanup() {
    echo ""
    echo "🛑 Stopping server..."
    # Kill any remaining uvicorn processes
    pkill -f "uvicorn.*omics_oracle" 2>/dev/null || true
    echo "👋 Server stopped. Goodbye!"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Run the FastAPI server using uvicorn directly with better error handling
echo "🎬 Launching uvicorn server..."
exec uvicorn src.omics_oracle.presentation.web.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --log-level info \
    --reload \
    --reload-dir src \
    --reload-exclude "*.pyc" \
    --reload-exclude "__pycache__" \
    --reload-exclude ".git" \
    --reload-exclude "venv" \
    --reload-exclude "archive"
