#!/bin/bash

# OmicsOracle FastAPI Server Startup Script (Simple Version)
# This script starts the server without reload mode to avoid configuration issues

echo "🚀 Starting OmicsOracle FastAPI Server (Simple Mode)..."
echo "📁 Working directory: $(pwd)"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment 'venv' not found!"
    echo "Please create a virtual environment first: python -m venv venv"
    exit 1
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

# Load environment variables from .env.development
if [ -f ".env.development" ]; then
    echo "📋 Loading environment variables from .env.development..."
    export $(grep -v '^#' .env.development | xargs)
fi

# Set NCBI_EMAIL if not already set
if [ -z "$NCBI_EMAIL" ]; then
    export NCBI_EMAIL=omicsoracle@example.com
    echo "📧 Set NCBI_EMAIL to: $NCBI_EMAIL"
fi

# Add src to Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
echo "🐍 Python path: $PYTHONPATH"

# Install dependencies if needed
echo "📦 Checking dependencies..."
pip install -q -r requirements.txt

# Start the FastAPI server without reload
echo "🌟 Starting FastAPI server on http://localhost:8000"
echo "📖 API documentation available at: http://localhost:8000/docs"
echo "🔍 Health check: http://localhost:8000/health"
echo "🎯 v1 API: http://localhost:8000/api/v1/"
echo "🚀 v2 API: http://localhost:8000/api/v2/"
echo ""
echo "Press Ctrl+C to stop the server"
echo "================================="

# Run the FastAPI server using uvicorn without reload
uvicorn src.omics_oracle.presentation.web.main:app --host 0.0.0.0 --port 8000 --log-level info
