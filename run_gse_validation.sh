#!/bin/bash
# Manual GSE Content Validation Script
# This script helps run validation checks on specific GSE IDs
# Usage: ./run_gse_validation.sh [gse_id|query]

set -e

echo "======================================================"
echo "OmicsOracle GSE Content Validation Tool"
echo "======================================================"
echo

# Check for command line argument
if [ -z "$1" ]; then
    echo "Please provide a GSE ID or search query."
    echo
    echo "Usage examples:"
    echo "  ./run_gse_validation.sh GSE278726"
    echo "  ./run_gse_validation.sh --query \"cancer\""
    echo "  ./run_gse_validation.sh --file-path results.json"
    exit 1
fi

# Function to check if the API server is running
check_api_server() {
    echo "Checking if API server is running..."
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/health 2>/dev/null | grep -q "200"; then
        echo "✅ API server is running"
        return 0
    else
        echo "❌ API server is not running at http://localhost:8000"
        echo "Please start the server before running validation."
        return 1
    fi
}

# Main execution
echo "Starting validation process..."

# Check server status first
if ! check_api_server; then
    echo
    echo "Would you like to:"
    echo "1) Continue anyway (direct GSE validation doesn't require server)"
    echo "2) Abort"
    read -p "Enter choice [1/2]: " choice

    if [ "$choice" != "1" ]; then
        echo "Aborting validation."
        exit 1
    fi

    echo "Continuing with limited validation..."
fi

# Run the appropriate validation based on input
if [[ "$1" == "--query" ]]; then
    echo "Running query-based validation for: $2"
    python validate_gse_content.py --query "$2" --max-results 20
elif [[ "$1" == "--file-path" ]]; then
    echo "Running file-based validation for: $2"
    python validate_gse_content.py --file-path "$2"
else
    echo "Running GSE ID validation for: $1"
    python validate_gse_content.py --gse-id "$1"
fi

echo
echo "======================================================"
echo "Validation complete. Check results in the validation_reports directory."
echo "======================================================"
