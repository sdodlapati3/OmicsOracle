#!/bin/bash

# Enhanced Futuristic Interface Startup Script
# Comprehensive setup and launch script for the enhanced interface

set -e

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

echo "🚀 Starting OmicsOracle Enhanced Futuristic Interface..."
echo "📁 Working directory: $(pwd)"

# Color functions for better output
print_success() { echo -e "\033[32m✅ $1\033[0m"; }
print_error() { echo -e "\033[31m❌ $1\033[0m"; }
print_info() { echo -e "\033[34mℹ️  $1\033[0m"; }
print_warning() { echo -e "\033[33m⚠️  $1\033[0m"; }

# Check if we're in the right directory
if [[ ! -f "main_enhanced.py" && ! -f "main.py" ]]; then
    print_error "Enhanced interface files not found!"
    print_info "Make sure you're in the interfaces/futuristic_enhanced/ directory"
    exit 1
fi

# Check Python
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    print_error "Python not found! Please install Python 3.8+"
    exit 1
fi

PYTHON_CMD=$(command -v python3 2>/dev/null || command -v python)
print_info "Using Python: $PYTHON_CMD"

# Check Node.js (optional but recommended)
if command -v node &> /dev/null && command -v npm &> /dev/null; then
    print_info "Node.js detected: $(node --version)"
    print_info "npm detected: $(npm --version)"
    NODE_AVAILABLE=true
else
    print_warning "Node.js/npm not found - frontend build tools unavailable"
    NODE_AVAILABLE=false
fi

# Set up environment variables
export BACKEND_URL="http://localhost:8000"  # Clean Architecture backend
export INTERFACE_PORT="8001"                # Enhanced interface port
export DEBUG_MODE="true"                    # Development mode
export NCBI_EMAIL="${NCBI_EMAIL:-omicsoracle@example.com}"

print_info "Backend URL: $BACKEND_URL"
print_info "Interface Port: $INTERFACE_PORT"
print_info "Debug Mode: $DEBUG_MODE"

# Check if main backend is running
print_info "Checking if Clean Architecture backend is running..."
if curl -s "$BACKEND_URL/api/v2/health" > /dev/null 2>&1; then
    print_success "Clean Architecture backend is running at $BACKEND_URL"
else
    print_warning "Clean Architecture backend not detected at $BACKEND_URL"
    print_info "Starting backend first is recommended for full functionality"
    print_info "Run './start_server.sh' from the project root to start the backend"

    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Install Python dependencies if needed
print_info "Setting up Python environment..."

# Check for virtual environment in parent directories
VENV_PATH=""
for dir in "." ".." "../.."; do
    if [[ -d "$dir/venv" ]]; then
        VENV_PATH="$dir/venv"
        break
    fi
done

if [[ -n "$VENV_PATH" ]]; then
    print_info "Found virtual environment at: $VENV_PATH"
    source "$VENV_PATH/bin/activate" || {
        print_error "Failed to activate virtual environment"
        exit 1
    }
    print_success "Virtual environment activated"
else
    print_warning "No virtual environment found - using system Python"
fi

# Install Node.js dependencies if available
if [[ "$NODE_AVAILABLE" == "true" && -f "package.json" ]]; then
    print_info "Installing/updating Node.js dependencies..."

    if [[ ! -d "node_modules" || "package.json" -nt "node_modules" ]]; then
        npm install
        print_success "Node.js dependencies installed"
    else
        print_info "Node.js dependencies are up to date"
    fi
fi

# Check for port conflicts
check_port() {
    local port=$1
    if lsof -Pi ":$port" -sTCP:LISTEN -t >/dev/null 2>&1; then
        print_warning "Port $port is already in use"
        local pid=$(lsof -ti:$port)
        if [[ -n "$pid" ]]; then
            print_info "Process using port $port: PID $pid"
            print_info "Attempting to stop existing process..."
            kill "$pid" 2>/dev/null || print_warning "Could not stop process"
            sleep 2

            if lsof -Pi ":$port" -sTCP:LISTEN -t >/dev/null 2>&1; then
                print_error "Port $port is still in use after cleanup attempt"
                return 1
            else
                print_success "Port $port is now available"
            fi
        fi
    fi
    return 0
}

# Check and clean up ports
if ! check_port "$INTERFACE_PORT"; then
    print_error "Could not free up port $INTERFACE_PORT"
    exit 1
fi

# Determine which main file to use
MAIN_FILE=""
if [[ -f "main_enhanced.py" ]]; then
    MAIN_FILE="main_enhanced.py"
    print_info "Using enhanced main file: $MAIN_FILE"
elif [[ -f "main.py" ]]; then
    MAIN_FILE="main.py"
    print_info "Using standard main file: $MAIN_FILE"
else
    print_error "No main Python file found!"
    exit 1
fi

# Start development mode if Node.js is available
if [[ "$NODE_AVAILABLE" == "true" && -f "package.json" ]]; then
    print_info "Starting in enhanced development mode with build tools..."
    print_info "Frontend assets will be built and watched for changes"

    # Start frontend build in background
    npm run build:watch &
    BUILD_PID=$!

    # Give build process time to start
    sleep 3

    # Function to cleanup background processes
    cleanup() {
        print_info "Shutting down enhanced interface..."
        if [[ -n "$BUILD_PID" ]]; then
            kill "$BUILD_PID" 2>/dev/null || true
        fi
        # Kill any remaining processes
        pkill -f "npm run build:watch" 2>/dev/null || true
        pkill -f "$MAIN_FILE" 2>/dev/null || true
        print_success "Cleanup complete"
        exit 0
    }

    trap cleanup SIGINT SIGTERM

    print_success "Frontend build process started (PID: $BUILD_PID)"
fi

# Final startup message
echo ""
print_success "🌟 Starting Enhanced Futuristic Interface..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print_info "🌐 Interface URL: http://localhost:$INTERFACE_PORT"
print_info "📚 API Documentation: http://localhost:$INTERFACE_PORT/docs"
print_info "🔌 WebSocket: ws://localhost:$INTERFACE_PORT/ws/{client_id}"
print_info "⚙️  Health Check: http://localhost:$INTERFACE_PORT/api/v2/health"
print_info "🎯 Enhanced Search: http://localhost:$INTERFACE_PORT/api/v2/search/enhanced"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print_info "💡 Features: Clean Architecture integration, Real-time WebSocket, Enhanced search"
print_info "🔧 Debug Mode: $DEBUG_MODE"
print_info "🔗 Backend: $BACKEND_URL"
echo ""
print_info "Press Ctrl+C to stop the server"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Start the enhanced interface
if command -v uvicorn &> /dev/null; then
    print_info "Using uvicorn directly..."
    exec uvicorn "$(basename "$MAIN_FILE" .py):app" \
        --host 0.0.0.0 \
        --port "$INTERFACE_PORT" \
        --reload \
        --log-level info \
        --reload-dir . \
        --reload-exclude "node_modules" \
        --reload-exclude "dist" \
        --reload-exclude "__pycache__"
else
    print_info "Using Python directly..."
    exec "$PYTHON_CMD" "$MAIN_FILE"
fi
