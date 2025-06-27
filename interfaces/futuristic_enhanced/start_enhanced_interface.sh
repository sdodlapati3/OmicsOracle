#!/bin/bash

# Enhanced Futuristic Interface Startup Script
# Starts the enhanced interface with Clean Architecture backend integration

set -e  # Exit on any error

# Get the script's directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

echo "🚀 Starting Enhanced Futuristic Interface..."
echo "📁 Working directory: $(pwd)"

# Check if main backend is running
echo "🔍 Checking backend connectivity..."
if ! curl -s http://localhost:8000/api/v2/health > /dev/null 2>&1; then
    echo "⚠️  Clean Architecture backend not detected on port 8000"
    echo "💡 Please start the main backend first:"
    echo "   cd ../../"
    echo "   ./start_server.sh"
    echo ""
    echo "🔄 Continuing anyway - interface will attempt to connect..."
fi

# Check if Node.js is available for development tools
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo "🟢 Node.js detected: $NODE_VERSION"
    
    # Check if dependencies are installed
    if [ ! -d "node_modules" ]; then
        echo "📦 Installing Node.js dependencies..."
        npm install
    fi
    
    # Start development mode if package.json exists
    if [ -f "package.json" ]; then
        echo "🛠️  Development mode available"
        echo "💡 Run 'npm run dev' in another terminal for hot reload"
    fi
else
    echo "⚠️  Node.js not found - development features disabled"
    echo "💡 Install Node.js 18+ for enhanced development experience"
fi

# Load environment variables
if [ -f ".env" ]; then
    echo "📋 Loading environment variables..."
    set -a
    source .env
    set +a
fi

# Set default configuration
export INTERFACE_PORT=${INTERFACE_PORT:-8001}
export BACKEND_URL=${BACKEND_URL:-http://localhost:8000}
export DEBUG_MODE=${DEBUG_MODE:-true}

echo "🔧 Configuration:"
echo "   Interface Port: $INTERFACE_PORT"
echo "   Backend URL: $BACKEND_URL"
echo "   Debug Mode: $DEBUG_MODE"

# Check if port is already in use
if lsof -Pi :$INTERFACE_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "⚠️  Port $INTERFACE_PORT is already in use!"
    PROCESS_ID=$(lsof -ti:$INTERFACE_PORT 2>/dev/null || echo "")
    if [ ! -z "$PROCESS_ID" ]; then
        echo "🛑 Killing existing process..."
        kill $PROCESS_ID 2>/dev/null || echo "⚠️  Could not kill process"
        sleep 2
    fi
fi

# Ensure Python path includes the main project
export PYTHONPATH="$(pwd)/../../src:$PYTHONPATH"

echo ""
echo "🌟 Starting Enhanced Futuristic Interface on http://localhost:$INTERFACE_PORT"
echo "🔗 Backend API: $BACKEND_URL"
echo "📖 Interface docs: http://localhost:$INTERFACE_PORT/docs"
echo ""
echo "Press Ctrl+C to stop the interface"
echo "====================================="
echo ""

# Set up cleanup trap
cleanup() {
    echo ""
    echo "🛑 Stopping Enhanced Futuristic Interface..."
    pkill -f "uvicorn.*futuristic" 2>/dev/null || true
    echo "👋 Interface stopped. Goodbye!"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start the enhanced interface
echo "🎬 Launching enhanced interface server..."
python -m uvicorn main:app \
    --host 0.0.0.0 \
    --port $INTERFACE_PORT \
    --log-level info \
    --reload \
    --reload-dir . \
    --reload-exclude "*.pyc" \
    --reload-exclude "__pycache__" \
    --reload-exclude "node_modules" \
    --reload-exclude "dist"
