#!/bin/bash

# OmicsOracle Unified Startup Script
# Starts the FastAPI application with web interface and API

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
fi

# Default configuration
PORT=${PORT:-8000}
DEV_MODE=false
SHOW_HELP=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dev)
            DEV_MODE=true
            shift
            ;;
        --port)
            PORT="$2"
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
    echo -e "${CYAN}[STARTUP] OmicsOracle Startup Script${NC}"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --dev                  Enable development mode (hot reload)"
    echo "  --port PORT           Server port (default: 8000)"
    echo "  --help, -h            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                     # Start server on default port 8000"
    echo "  $0 --port 8080        # Start server on port 8080"
    echo "  $0 --dev              # Start with development/reload mode"
    echo ""
    echo "Access:"
    echo "  Web Interface: http://localhost:$PORT"
    echo "  API Docs:      http://localhost:$PORT/docs"
    echo "  Health Check:  http://localhost:$PORT/health"
    echo ""
    exit 0
fi

echo -e "${PURPLE}[STARTUP] OmicsOracle Unified Server${NC}"
echo -e "${PURPLE}====================================${NC}"

# Validate critical environment variables
echo -e "${BLUE}[CONFIG] Validating environment configuration...${NC}"

missing_vars=()

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

# Check if port is already in use
if check_port $PORT; then
    echo -e "${YELLOW}[WARN] Port $PORT is already in use${NC}"
    echo -e "${GREEN}[OK] OmicsOracle appears to be already running${NC}"
    echo -e "${CYAN}[ACCESS] Web Interface: http://localhost:$PORT${NC}"
    echo -e "${CYAN}[ACCESS] API Docs: http://localhost:$PORT/docs${NC}"
    exit 0
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

echo -e "${CYAN}[BUILD] Starting OmicsOracle on port $PORT...${NC}"

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}[CLEANUP] Stopping server...${NC}"
    pkill -f "uvicorn.*omics_oracle" 2>/dev/null || true
    echo -e "${GREEN}[OK] Cleanup complete${NC}"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Start the unified FastAPI application
if [ "$DEV_MODE" = true ]; then
    echo -e "${CYAN}[DEV] Starting in development mode with hot reload...${NC}"
    $PYTHON_CMD -m uvicorn src.omics_oracle.presentation.web.main:app \
        --host 0.0.0.0 \
        --port $PORT \
        --reload \
        --log-level info
else
    echo -e "${CYAN}[PROD] Starting in production mode...${NC}"
    $PYTHON_CMD -m uvicorn src.omics_oracle.presentation.web.main:app \
        --host 0.0.0.0 \
        --port $PORT \
        --log-level info
fi
