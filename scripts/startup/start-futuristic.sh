#!/bin/bash

# OmicsOracle Futuristic Interface Startup Script
# Simple, focused startup for the futuristic web interface

echo "🚀 Starting OmicsOracle Futuristic Interface"
echo "============================================="

# Check if we're in the correct directory
if [ ! -f "interfaces/futuristic/main.py" ]; then
    echo "❌ Error: Please run this script from the OmicsOracle root directory"
    echo "   Current directory: $(pwd)"
    echo "   Expected to find: interfaces/futuristic/main.py"
    exit 1
fi

# Stop any existing servers on port 8001
echo "🔄 Checking for existing servers on port 8001..."
lsof -ti:8001 | xargs kill -9 2>/dev/null || true

# Check Python environment
echo "🐍 Checking Python environment..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Please install Python 3.7+ and try again."
    exit 1
fi
        --help|-h)
            SHOW_HELP=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

if [ "$SHOW_HELP" = true ]; then
    echo "[LAUNCH] OmicsOracle Futuristic Interface Startup Script"
    echo ""
    echo "Usage:"
    echo "  ./start-futuristic.sh           # Normal startup (skip install if packages exist)"
    echo "  ./start-futuristic.sh --install # Force package installation"
    echo "  ./start-futuristic.sh --help    # Show this help"
    echo ""
    echo "The script will:"
    echo "  * Activate virtual environment from root folder"
    echo "  * Check/install dependencies as needed"
    echo "  * Start the futuristic interface on port 8001"
    echo ""
    exit 0
fi

echo "[LAUNCH] Starting OmicsOracle Futuristic Interface..."
echo "=================================================="

# Get the script directory (should be root folder)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR"

echo "[FOLDER] Script location: $SCRIPT_DIR"
echo "[FOLDER] Root directory: $ROOT_DIR"

# Ensure we're in the root directory
cd "$ROOT_DIR"
echo "[OPEN_FOLDER] Working from: $(pwd)"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "[WARNING]  Virtual environment not found. Creating one..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to create virtual environment"
        exit 1
    fi
fi

# Activate virtual environment
echo "[CONNECT] Activating virtual environment..."
source venv/bin/activate

if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to activate virtual environment"
    exit 1
fi

echo "[OK] Virtual environment activated"

# Install/update requirements only if needed
if [ -f "requirements.txt" ]; then
    echo "[PACKAGE] Checking dependencies..."

    # Check if key packages are installed (or force install requested)
    if [ "$FORCE_INSTALL" = true ]; then
        echo "[REFRESH] Force installing all dependencies..."
        pip install -r requirements.txt
        if [ $? -ne 0 ]; then
            echo "[ERROR] Failed to install some dependencies"
            echo "[REFRESH] Trying to install essential packages only..."
            pip install fastapi uvicorn[standard] websockets
        fi
    else
        # Quick check for essential packages without full dependency check
        echo "[SEARCH] Checking for essential packages..."
        if python -c "import fastapi, uvicorn, websockets" >/dev/null 2>&1; then
            echo "[OK] Core dependencies already installed (use --install to force reinstall)"
        else
            echo "[WARNING]  Required packages missing. Installing dependencies..."
            pip install -r requirements.txt
            if [ $? -ne 0 ]; then
                echo "[ERROR] Failed to install some dependencies"
                echo "[REFRESH] Trying to install essential packages only..."
                pip install fastapi uvicorn[standard] websockets
            fi
        fi
    fi
else
    echo "[WARNING]  requirements.txt not found. Installing essential packages..."
    pip install fastapi uvicorn[standard] websockets
fi

# Set environment variables
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src:$(pwd)"
export ORACLEDB_LIB="/opt/oracle/instantclient_19_8"

echo "[WEB] Environment variables set:"
echo "   PYTHONPATH: $PYTHONPATH"

# Check if legacy interface is running
echo "[SEARCH] Checking for legacy interface..."
if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "[OK] Legacy interface detected on port 8000 (available as fallback)"
else
    echo "[INFO]  Legacy interface not running on port 8000 (internal fallback will be used)"
fi

# Navigate to futuristic interface directory
FUTURISTIC_DIR="$ROOT_DIR/interfaces/futuristic"

if [ ! -d "$FUTURISTIC_DIR" ]; then
    echo "[ERROR] Futuristic interface directory not found at: $FUTURISTIC_DIR"
    echo "[IDEA] Make sure you're running this script from the OmicsOracle root directory"
    exit 1
fi

echo "[OPEN_FOLDER] Navigating to futuristic interface directory..."
cd "$FUTURISTIC_DIR"

# Check if port 8001 is available
if lsof -Pi :8001 -sTCP:LISTEN -t >/dev/null ; then
    echo "[WARNING]  Port 8001 is already in use. Stopping existing process..."
    lsof -ti:8001 | xargs kill -9 2>/dev/null
    sleep 2
fi

echo ""
echo "[STAR] Starting Futuristic Interface on http://localhost:8001"
echo "[TARGET] Features:"
echo "   * AI-powered search agents"
echo "   * Real-time WebSocket updates"
echo "   * Advanced visualizations"
echo "   * Legacy fallback support"
echo ""
echo "[LINK] Access points:"
echo "   * Main Interface: http://localhost:8001"
echo "   * Health Check: http://localhost:8001/api/v2/health"
echo "   * API Docs: http://localhost:8001/docs"
echo ""
echo "[STOP] Press Ctrl+C to stop the server"
echo "=================================================="

# Start the server with proper error handling
echo "[OPEN_FOLDER] Starting server from: $(pwd)"

# Try to start with main.py first, then enhanced_server.py, then fallback to test_server.py
if [ -f "enhanced_server.py" ]; then
    echo "[STAR] Starting with enhanced futuristic interface (safe & maintainable)..."
    python -m uvicorn enhanced_server:app --host 0.0.0.0 --port 8001 --log-level info
elif [ -f "main.py" ]; then
    echo "[BIOMEDICAL] Attempting full futuristic interface..."
    if python -c "from main import app" >/dev/null 2>&1; then
        python -m uvicorn main:app --host 0.0.0.0 --port 8001 --reload --log-level info
    else
        echo "[WARNING]  Import issues detected with main.py, falling back to test server..."
        if [ -f "test_server.py" ]; then
            echo "[TEST] Starting with test server (simplified mode)..."
            python -m uvicorn test_server:app --host 0.0.0.0 --port 8001 --log-level info
        else
            echo "[ERROR] No working server files found!"
            exit 1
        fi
    fi
elif [ -f "test_server.py" ]; then
    echo "[TEST] Starting with test server (simplified mode)..."
    python -m uvicorn test_server:app --host 0.0.0.0 --port 8001 --log-level info
else
    echo "[ERROR] No server files found!"
    exit 1
fi

echo ""
echo "[HELLO] Futuristic interface stopped"
echo "[REFRESH] To restart, run: ./start-futuristic.sh"
