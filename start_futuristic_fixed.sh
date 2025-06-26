#!/bin/bash

# OmicsOracle Futuristic Interface - Fixed Version
# Uses the proper venv and ensures all dependencies are available

echo "🧬 OmicsOracle Futuristic Interface - Fixed Version"
echo "================================================="

# Check if we're in the project root
if [ ! -f "src/omics_oracle/core/config.py" ]; then
    echo "❌ Error: Please run from the OmicsOracle project root directory"
    exit 1
fi

# Stop any existing servers
echo "🔄 Stopping any existing servers on port 8001..."
lsof -ti:8001 | xargs kill -9 2>/dev/null || true
sleep 1

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please create one first:"
    echo "   python3 -m venv venv"
    echo "   source venv/bin/activate"
    echo "   pip install -r requirements.txt"
    exit 1
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Set environment variables
export PYTHONPATH="$(pwd):$PYTHONPATH"

# Check if required dependencies are installed
echo "📦 Checking dependencies..."
python -c "import fastapi, uvicorn, python_dotenv" 2>/dev/null || {
    echo "❌ Missing dependencies. Installing..."
    pip install fastapi uvicorn python-dotenv
}

# Navigate to futuristic interface directory
cd interfaces/futuristic

echo "🚀 Starting server on http://localhost:8001"
echo "Press Ctrl+C to stop"

# Start the server
python -m uvicorn main:app --host 0.0.0.0 --port 8001 --reload
