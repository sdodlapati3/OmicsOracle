#!/bin/bash

# OmicsOracle Futuristic Interface Launcher
# Run this from the root directory to start the futuristic interface

echo "[LAUNCH] OmicsOracle Futuristic Interface Launcher"
echo "============================================="

# Check if we're in the root directory
if [ ! -f "pyproject.toml" ] || [ ! -d "interfaces/futuristic" ]; then
    echo "[ERROR] Please run this script from the OmicsOracle root directory"
    echo "[IDEA] The root directory should contain pyproject.toml and interfaces/futuristic/"
    exit 1
fi

# Execute the futuristic interface startup script
exec ./interfaces/futuristic/start-futuristic.sh
