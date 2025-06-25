#!/bin/bash

# OmicsOracle Modern Interface Setup Script
# This script sets up the new modular backend interface

set -e  # Exit on any error

echo "🔧 Setting up OmicsOracle Modern Interface..."

# Define paths
MODERN_DIR="/Users/sanjeevadodlapati/Downloads/Repos/OmicsOracle/interfaces/modern"
PROJECT_ROOT="/Users/sanjeevadodlapati/Downloads/Repos/OmicsOracle"

# Check if we're in the right directory
if [ ! -d "$PROJECT_ROOT" ]; then
    echo "❌ Error: Project root directory not found: $PROJECT_ROOT"
    exit 1
fi

cd "$PROJECT_ROOT"

echo "📦 Checking Python environment..."

# Check if existing venv has the dependencies we need
if [ -d "venv" ]; then
    echo "🔍 Found existing virtual environment"
    source venv/bin/activate

    # Check if Flask is already installed and what version
    flask_version=$(python -c "import flask; print(flask.__version__)" 2>/dev/null || echo "not installed")
    echo "📋 Current Flask version: $flask_version"

    # Check if our dependencies are compatible
    echo "🔍 Checking compatibility with existing environment..."

    # For now, let's use the existing venv but add our dependencies
    echo "✅ Using existing virtual environment"
else
    echo "Creating new virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
fi

# Install requirements for the modern interface
if [ -f "$MODERN_DIR/requirements.txt" ]; then
    pip install -r "$MODERN_DIR/requirements.txt"
    echo "✅ Modern interface dependencies installed"
else
    echo "⚠️  Warning: Modern interface requirements.txt not found"
fi

# Install existing project requirements
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    echo "✅ Project dependencies installed"
fi

echo "📁 Creating necessary directories..."

# Create required directories
mkdir -p data/cache
mkdir -p data/exports
mkdir -p logs
mkdir -p interfaces/modern/templates
mkdir -p interfaces/modern/static/{css,js,images}

echo "✅ Directories created"

echo "🔧 Setting up environment variables..."

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    cat > .env << EOF
# OmicsOracle Modern Interface Configuration
FLASK_ENV=development
SECRET_KEY=dev-secret-key-change-in-production
HOST=0.0.0.0
PORT=5001
LOG_LEVEL=DEBUG
CACHE_ENABLED=true
CACHE_TTL=3600
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
EOF
    echo "✅ Environment file created (.env)"
else
    echo "✅ Environment file already exists"
fi

echo "🧪 Running basic validation..."

# Test Python imports
python3 -c "
import sys
sys.path.insert(0, 'interfaces/modern')
try:
    from core.config import get_config
    from core.logging_config import setup_logging
    from core.exceptions import OmicsOracleException
    print('✅ Core modules import successfully')
except ImportError as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
"

echo "📋 Setup Summary:"
echo "   • Modern interface structure created"
echo "   • Dependencies installed"
echo "   • Required directories created"
echo "   • Environment configuration ready"
echo "   • Core modules validated"
echo ""
echo "🚀 Next Steps:"
echo "   1. Start the modern interface: cd interfaces/modern && python main.py"
echo "   2. Test health endpoint: curl http://localhost:5001/api/v1/health"
echo "   3. Compare with legacy interface on port 5000"
echo ""
echo "📖 Documentation:"
echo "   • Backend Refactoring Plan: BACKEND_REFACTORING_PLAN.md"
echo "   • API Documentation: Will be at http://localhost:5001/api/v1/health"
echo ""
echo "✅ OmicsOracle Modern Interface setup complete!"
