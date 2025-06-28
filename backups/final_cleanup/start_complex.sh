#!/bin/bash

# OmicsOracle Universal Startup Script
# One script to rule them all - backend, frontend, or full-stack

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Load environment variables from .env file
if [ -f ".env" ]; then
    echo -e "${BLUE}[CONFIG] Loading environment from .env${NC}"
    set -a
    source .env
    set +a
else
    echo -e "${YELLOW}[WARNING] .env file not found, using defaults${NC}"
fi

# Default configuration
START_BACKEND=true
START_FRONTEND=true
BACKEND_PORT=${BACKEND_PORT:-8000}
FRONTEND_PORT=${FRONTEND_PORT:-8001}
SHOW_HELP=false
DEV_MODE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --backend-only|--backend|--api)
            START_BACKEND=true
            START_FRONTEND=false
            shift
            ;;
        --frontend-only|--frontend|--ui)
            START_BACKEND=false
            START_FRONTEND=true
            shift
            ;;
        --dev|--development)
            DEV_MODE=true
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
    echo -e "${CYAN}[STARTUP] OmicsOracle Universal Startup Script${NC}"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --backend-only         Start only the backend server"
    echo "  --frontend-only        Start only the frontend interface"
    echo "  --dev                  Enable development mode (hot reload, build tools)"
    echo "  --backend-port PORT    Backend port (default: 8000)"
    echo "  --frontend-port PORT   Frontend port (default: 8001)"
    echo "  --help, -h            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                     # Start both backend and frontend"
    echo "  $0 --backend-only      # Start only backend"
    echo "  $0 --frontend-only     # Start only frontend"
    echo "  $0 --dev               # Full-stack with development tools"
    echo ""
    exit 0
fi

echo -e "${PURPLE}[STARTUP] OmicsOracle Universal Launcher${NC}"
echo -e "${PURPLE}=========================================${NC}"

# Validate critical environment variables
validate_environment() {
    echo -e "${BLUE}[CONFIG] Validating environment configuration...${NC}"

    local missing_vars=()

    if [ -z "$NCBI_EMAIL" ]; then
        missing_vars+=("NCBI_EMAIL")
    fi

    if [ -z "$NCBI_API_KEY" ]; then
        missing_vars+=("NCBI_API_KEY")
    fi

    if [ -z "$OPENAI_API_KEY" ] || [ "$OPENAI_API_KEY" = "your-openai-api-key-here" ]; then
        missing_vars+=("OPENAI_API_KEY")
    fi

    if [ ${#missing_vars[@]} -gt 0 ]; then
        echo -e "${RED}[ERROR] Missing required environment variables:${NC}"
        for var in "${missing_vars[@]}"; do
            echo -e "${RED}   - $var${NC}"
        done
        echo -e "${YELLOW}[INFO] Please update your .env file with the required values${NC}"
        exit 1
    fi

    echo -e "${GREEN}[OK] Environment validation passed${NC}"
}

validate_environment

# Check if we're in the correct directory
if [ ! -f "src/omics_oracle/presentation/web/main.py" ]; then
    echo -e "${RED}[ERROR] Please run this script from the OmicsOracle root directory${NC}"
    echo -e "${YELLOW}   Current directory: $(pwd)${NC}"
    echo -e "${YELLOW}   Expected to find: src/omics_oracle/presentation/web/main.py${NC}"
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

# Function to check Python
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        echo -e "${RED}[ERROR] Python not found! Please install Python 3.8+ first.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[OK] Using Python: $PYTHON_CMD${NC}"
}

# Function to start backend
start_backend() {
    echo -e "${BLUE}[CONFIG] Starting Backend Server...${NC}"

    if check_port $BACKEND_PORT; then
        echo -e "${YELLOW}[WARN] Backend port $BACKEND_PORT is already in use${NC}"
        echo -e "${GREEN}[OK] Backend appears to be already running${NC}"
        return 0
    fi

    check_python

    # Check and activate virtual environment
    if [ -d "venv" ]; then
        echo -e "${CYAN}[CONFIG] Activating virtual environment...${NC}"
        source venv/bin/activate
    else
        echo -e "${YELLOW}[WARN] No virtual environment found (venv)${NC}"
    fi

    # Set up environment
    export PYTHONPATH="$(pwd)/src:$PYTHONPATH"

    echo -e "${CYAN}[BUILD] Starting backend on port $BACKEND_PORT...${NC}"

    # Start backend in background
    nohup $PYTHON_CMD -m uvicorn src.omics_oracle.presentation.web.main:app \
        --host 0.0.0.0 \
        --port $BACKEND_PORT \
        --reload \
        --log-level info > backend.log 2>&1 &
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
        echo -e "${YELLOW}[WARN] Frontend port $FRONTEND_PORT is already in use${NC}"
        echo -e "${YELLOW}[RESTART] Stopping existing frontend...${NC}"
        lsof -ti:$FRONTEND_PORT | xargs kill -9 2>/dev/null || true
        sleep 2
    fi

    check_python

    # Check and activate virtual environment
    if [ -d "venv" ]; then
        echo -e "${CYAN}[CONFIG] Activating virtual environment...${NC}"
        source venv/bin/activate
    else
        echo -e "${YELLOW}[WARN] No virtual environment found (venv)${NC}"
    fi

    # Set up environment
    export PYTHONPATH="$(pwd)/src:$PYTHONPATH"

    # Check if backend is running (unless we're starting it ourselves)
    if [ "$START_BACKEND" = false ]; then
        echo -e "${CYAN}[CHECK] Verifying backend connectivity...${NC}"
        if ! check_port $BACKEND_PORT; then
            echo -e "${YELLOW}[WARN] Backend not detected on port $BACKEND_PORT${NC}"
            echo -e "${CYAN}[INFO] You may need to start the backend first${NC}"
        fi
    fi

    if [ "$DEV_MODE" = true ]; then
        echo -e "${CYAN}[BUILD] Building frontend assets with development tools...${NC}"

        # Check if package.json exists in the interface directory
        if [ ! -f "interfaces/futuristic_enhanced/package.json" ]; then
            echo -e "${YELLOW}[WARN] No package.json found, skipping npm build${NC}"
        else
            cd interfaces/futuristic_enhanced

            # Install npm dependencies if needed
            if [ ! -d "node_modules" ] || [ "package.json" -nt "node_modules" ]; then
                echo -e "${CYAN}[BUILD] Installing npm dependencies...${NC}"
                npm install
            fi

            # Build frontend
            if ! npm run build; then
                echo -e "${RED}[ERROR] Frontend build failed${NC}"
                cd ../..
                return 1
            fi

            cd ../..
        fi

        # Start with enhanced development features
        INTERFACE_PORT=$FRONTEND_PORT ./interfaces/futuristic_enhanced/start_enhanced.sh &
        FRONTEND_PID=$!
    else
        echo -e "${CYAN}[START] Starting frontend server on port $FRONTEND_PORT...${NC}"

        # Ensure Python is available for frontend
        check_python

        # Simple start without development tools - run from project root for proper imports
        $PYTHON_CMD -m uvicorn interfaces.futuristic_enhanced.main:app \
            --host 0.0.0.0 \
            --port $FRONTEND_PORT \
            --log-level info &
        FRONTEND_PID=$!
    fi

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
    echo -e "\n${YELLOW}[CLEANUP] Stopping services...${NC}"
    if [ -n "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null || true
    fi
    if [ -n "$FRONTEND_PID" ]; then
        kill $FRONTEND_PID 2>/dev/null || true
    fi
    # Kill any remaining processes
    pkill -f "uvicorn.*omics_oracle" 2>/dev/null || true
    pkill -f "uvicorn.*main:app" 2>/dev/null || true
    echo -e "${GREEN}[OK] Cleanup complete${NC}"
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
echo -e "${GREEN}[SUCCESS] OmicsOracle is ready!${NC}"
echo -e "${PURPLE}=========================================${NC}"

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
