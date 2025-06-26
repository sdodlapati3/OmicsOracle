#!/bin/zsh
# Simple script to activate the virtual environment
# Usage: source activate_env.sh

# Detect if we're already in the virtual environment
if [[ -z "$VIRTUAL_ENV" ]]; then
    echo "🔄 Activating OmicsOracle virtual environment..."

    # Check if venv directory exists
    if [[ -d "./venv" ]]; then
        source ./venv/bin/activate
    elif [[ -d "./.venv" ]]; then
        source ./.venv/bin/activate
    else
        echo "❌ Virtual environment not found in ./venv or ./.venv"
        echo "Please create a virtual environment first with:"
        echo "python -m venv venv"
        return 1
    fi

    echo "✅ Virtual environment activated!"
else
    echo "✅ Already in virtual environment: $VIRTUAL_ENV"
fi

# Print Python version and path for verification
echo "📊 Using Python: $(which python)"
echo "📊 Python version: $(python --version)"
