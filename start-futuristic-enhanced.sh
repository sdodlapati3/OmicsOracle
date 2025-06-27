#!/bin/bash

# OmicsOracle Futuristic Enhanced Interface - Unified Startup Script
# This script starts both backend and frontend components

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
START_BACKEND=true
START_FRONTEND=true
BACKEND_PORT=8000
FRONTEND_PORT=8001
SHOW_HELP=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --backend-only)
            START_BACKEND=true
            START_FRONTEND=false
            shift
            ;;
        --frontend-only)
            START_BACKEND=false
            START_FRONTEND=true
            shift
            ;;
        --backend-port)
            BACKEND_PORT="$2"
            shift 2
            ;;
        --frontend-port)
            FRONTEND_PORT="$2"
            shift 2
            ;;
        --help|-h)
            SHOW_HELP=true
            shift
            ;;
        *)
            echo -e "${RED}[ERROR] Unknown option: $1${NC}"
            SHOW_HELP=true
            shift
            ;;
    esac
done

# Show help if requested
if [ "$SHOW_HELP" = true ]; then
    echo -e "${CYAN}[STARTUP] OmicsOracle Futuristic Enhanced Interface Startup${NC}"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --backend-only         Start only the backend server"
    echo "  --frontend-only        Start only the frontend interface"
    echo "  --backend-port PORT    Backend port (default: 8000)"
    echo "  --frontend-port PORT   Frontend port (default: 8001)"
    echo "  --help, -h            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                     # Start both backend and frontend"
    echo "  $0 --backend-only      # Start only backend"
    echo "  $0 --frontend-only     # Start only frontend"
    echo ""
    exit 0
fi

echo -e "${PURPLE}[STARTUP] OmicsOracle Futuristic Enhanced Interface${NC}"
echo -e "${PURPLE}=============================================${NC}"

# Check if we're in the correct directory
if [ ! -f "interfaces/futuristic_enhanced/main.py" ]; then
    echo -e "${RED}[ERROR] Please run this script from the OmicsOracle root directory${NC}"
    echo -e "${YELLOW}   Current directory: $(pwd)${NC}"
    echo -e "${YELLOW}   Expected to find: interfaces/futuristic_enhanced/main.py${NC}"
    exit 1
fi

# Function to check if port is in use
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        return 0  # Port is in use
    else
        return 1  # Port is free
    fi
}

# Function to start backend
start_backend() {
    echo -e "${BLUE}[CONFIG] Starting Backend Server...${NC}"

    if check_port $BACKEND_PORT; then
        echo -e "${YELLOW}[WARN]  Backend port $BACKEND_PORT is already in use${NC}"
        echo -e "${GREEN}[OK] Backend appears to be already running${NC}"
        return 0
    fi

    echo -e "${CYAN}[BUILD] Starting backend on port $BACKEND_PORT...${NC}"

    # Start backend in background
    nohup ./start_server.sh > backend.log 2>&1 &
    BACKEND_PID=$!

    # Wait for backend to start
    echo -e "${YELLOW}[WAIT] Waiting for backend to start...${NC}"
    for i in {1..30}; do
        if check_port $BACKEND_PORT; then
            echo -e "${GREEN}[OK] Backend started successfully on port $BACKEND_PORT${NC}"
            echo -e "${CYAN}[DOCS] API Documentation: http://localhost:$BACKEND_PORT/docs${NC}"
            echo -e "${CYAN}[CHECK] Health Check: http://localhost:$BACKEND_PORT/health${NC}"
            return 0
        fi
        sleep 1
        echo -n "."
    done

    echo -e "\n${RED}[ERROR] Backend failed to start within 30 seconds${NC}"
    return 1
}

# Function to start frontend
start_frontend() {
    echo -e "${BLUE}[UI] Starting Frontend Interface...${NC}"

    if check_port $FRONTEND_PORT; then
        echo -e "${YELLOW}[WARN]  Frontend port $FRONTEND_PORT is already in use${NC}"
        echo -e "${YELLOW}[RESTART] Stopping existing frontend...${NC}"
        lsof -ti:$FRONTEND_PORT | xargs kill -9 2>/dev/null || true
        sleep 2
    fi

    echo -e "${CYAN}[BUILD]  Building frontend assets...${NC}"
    cd interfaces/futuristic_enhanced

    # Build frontend
    if ! npm run build; then
        echo -e "${RED}[ERROR] Frontend build failed${NC}"
        cd ../..
        return 1
    fi

    echo -e "${CYAN}[START] Starting frontend server on port $FRONTEND_PORT...${NC}"

    # Start frontend
    ./start_enhanced.sh --port $FRONTEND_PORT &
    FRONTEND_PID=$!

    cd ../..

    # Wait for frontend to start
    echo -e "${YELLOW}[WAIT] Waiting for frontend to start...${NC}"
    for i in {1..20}; do
        if check_port $FRONTEND_PORT; then
            echo -e "${GREEN}[OK] Frontend started successfully on port $FRONTEND_PORT${NC}"
            echo -e "${CYAN}[WEB] Interface: http://localhost:$FRONTEND_PORT${NC}"
            return 0
        fi
        sleep 1
        echo -n "."
    done

    echo -e "\n${RED}[ERROR] Frontend failed to start within 20 seconds${NC}"
    return 1
}

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}[CLEANUP] Cleaning up...${NC}"
    if [ -n "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null || true
    fi
    if [ -n "$FRONTEND_PID" ]; then
        kill $FRONTEND_PID 2>/dev/null || true
    fi
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Start components based on options
if [ "$START_BACKEND" = true ]; then
    start_backend
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR] Failed to start backend${NC}"
        exit 1
    fi
fi

if [ "$START_FRONTEND" = true ]; then
    start_frontend
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR] Failed to start frontend${NC}"
        exit 1
    fi
fi

echo ""
echo -e "${GREEN}[SUCCESS] OmicsOracle Futuristic Enhanced Interface is ready!${NC}"
echo -e "${PURPLE}=============================================${NC}"

if [ "$START_BACKEND" = true ]; then
    echo -e "${CYAN}[CONFIG] Backend:      http://localhost:$BACKEND_PORT${NC}"
    echo -e "${CYAN}[DOCS] API Docs:     http://localhost:$BACKEND_PORT/docs${NC}"
fi

if [ "$START_FRONTEND" = true ]; then
    echo -e "${CYAN}[UI] Frontend:     http://localhost:$FRONTEND_PORT${NC}"
fi

echo ""
echo -e "${YELLOW}[INFO] Press Ctrl+C to stop all services${NC}"
echo ""

# Keep script running to maintain background processes
if [ "$START_BACKEND" = true ] || [ "$START_FRONTEND" = true ]; then
    wait
fi
