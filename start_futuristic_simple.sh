#!/bin/bash

# OmicsOracle Futuristic Interface - Simple Clean Startup
# Starts the interface with proper modular integration

echo "🧬 OmicsOracle Futuristic Interface - Clean Version"
echo "=================================================="

# Check if we're in the project root
if [ ! -f "src/omics_oracle/core/config.py" ]; then
    echo "❌ Error: Please run from the OmicsOracle project root directory"
    exit 1
fi

# Stop any existing servers
echo "🔄 Stopping any existing servers on port 8001..."
lsof -ti:8001 | xargs kill -9 2>/dev/null || true
sleep 1

# Set environment
export PYTHONPATH="$(pwd):$PYTHONPATH"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found"
    exit 1
fi

# Check packages
python3 -c "import fastapi, uvicorn" 2>/dev/null || {
    echo "❌ Missing packages. Please run: pip install fastapi uvicorn"
    exit 1
}

# Start server
echo "🚀 Starting server on http://localhost:8001"
echo "Press Ctrl+C to stop"
echo ""

cd interfaces/futuristic
exec python3 -m uvicorn main:app --host 0.0.0.0 --port 8001 --reload
