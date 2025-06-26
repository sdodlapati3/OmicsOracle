#!/bin/bash
# OmicsOracle Pipeline Monitor and Results Limit Fix
# This script diagnoses pipeline issues and fixes the results limit problem

set -e

# Default values
MAX_RESULTS=50
QUERY="ATAC-seq human"
API_URL="http://localhost:8000"
DIAGNOSE_MAPPING=false
COMPARE_VERSIONS=false
COMPARE_URL="http://localhost:5000"

# Text formatting
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

# Function to ensure the virtual environment is activated
ensure_venv_activated() {
    if [[ -z "${VIRTUAL_ENV}" ]]; then
        echo -e "${YELLOW}Virtual environment not activated. Activating now...${RESET}"
        if [ -d "venv" ]; then
            source venv/bin/activate
            if [ $? -ne 0 ]; then
                echo -e "${RED}Failed to activate virtual environment.${RESET}"
                return 1
            fi
            echo -e "${GREEN}Virtual environment activated.${RESET}"
        else
            echo -e "${RED}Virtual environment directory (venv) not found.${RESET}"
            return 1
        fi
    fi
    return 0
}

# Help function
function show_help {
    echo -e "${BOLD}OmicsOracle Pipeline Monitor and Results Limit Fix${RESET}"
    echo
    echo "Usage: ./diagnose_and_fix_results.sh [options]"
    echo
    echo "Options:"
    echo "  -q, --query QUERY       Search query to use (default: 'ATAC-seq human')"
    echo "  -m, --max-results NUM   Maximum results to request (default: 50)"
    echo "  -u, --api-url URL       API URL to test (default: http://localhost:8000)"
    echo "  -d, --diagnose-mapping  Perform in-depth mapping diagnosis"
    echo "  -c, --compare           Compare with alternate endpoint"
    echo "  -a, --compare-url URL   Alternate API URL for comparison (default: http://localhost:5000)"
    echo "  -h, --help              Show this help message"
    echo
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -q|--query)
            QUERY="$2"
            shift 2
            ;;
        -m|--max-results)
            MAX_RESULTS="$2"
            shift 2
            ;;
        -u|--api-url)
            API_URL="$2"
            shift 2
            ;;
        -d|--diagnose-mapping)
            DIAGNOSE_MAPPING=true
            shift
            ;;
        -c|--compare)
            COMPARE_VERSIONS=true
            shift
            ;;
        -a|--compare-url)
            COMPARE_URL="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${RESET}"
            show_help
            exit 1
            ;;
    esac
done

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required but not installed.${RESET}"
    exit 1
fi

# Check if pipeline_monitor.py exists
if [ ! -f "pipeline_monitor.py" ]; then
    echo -e "${RED}Error: pipeline_monitor.py not found in current directory.${RESET}"
    echo -e "${YELLOW}Please run this script from the OmicsOracle root directory.${RESET}"
    exit 1
fi

# Check if we're in the right directory by looking for key OmicsOracle files
if [ ! -d "interfaces" ] || [ ! -f "README.md" ]; then
    echo -e "${YELLOW}Warning: This doesn't appear to be the OmicsOracle root directory.${RESET}"
    echo -e "${BLUE}Current directory: $(pwd)${RESET}"
    echo -e "${YELLOW}Please navigate to the OmicsOracle root directory and try again.${RESET}"
    exit 1
fi

# Activate virtual environment
echo -e "${BLUE}Activating virtual environment...${RESET}"
ensure_venv_activated

# Make sure required packages are installed
echo -e "${BLUE}Checking for required Python packages...${RESET}"
python -c "import requests" 2>/dev/null || python -m pip install requests
python -c "import matplotlib" 2>/dev/null || python -m pip install matplotlib
python -c "import rich" 2>/dev/null || python -m pip install rich

# Build the command
CMD="python pipeline_monitor.py --query \"$QUERY\" --max-results $MAX_RESULTS --api-url $API_URL"

if $DIAGNOSE_MAPPING; then
    CMD="$CMD --diagnose-mapping"
fi

if $COMPARE_VERSIONS; then
    CMD="$CMD --compare-versions --compare-url $COMPARE_URL"
fi

# Run the pipeline monitor
echo -e "${BOLD}${GREEN}Running OmicsOracle Pipeline Monitor${RESET}"
echo -e "${BLUE}Query:${RESET} $QUERY"
echo -e "${BLUE}Max Results:${RESET} $MAX_RESULTS"
echo -e "${BLUE}API URL:${RESET} $API_URL"
echo

# Ensure virtual environment is activated before running Python commands
ensure_venv_activated

eval $CMD

# Check if we need to fix the results limit issue
echo
echo -e "${BOLD}${YELLOW}Do you want to update the frontend to fix the results limit issue? (y/n)${RESET}"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo -e "${GREEN}Great! Let's make the changes to improve the interface.${RESET}"

    # Check if the frontend JavaScript file exists
    JS_FILE="interfaces/futuristic/static/js/main_clean.js"
    if [ ! -f "$JS_FILE" ]; then
        echo -e "${RED}Error: Frontend JavaScript file not found at $JS_FILE${RESET}"
        exit 1
    fi

    # Check if the fix has already been applied
    if grep -q "parseInt(document.getElementById('max-results')" "$JS_FILE"; then
        echo -e "${YELLOW}JavaScript fix has already been applied!${RESET}"
        echo -e "${GREEN}The max_results parameter is already using dynamic value from UI.${RESET}"
    else
        # Backup the original file
        cp "$JS_FILE" "${JS_FILE}.bak"
        echo -e "${BLUE}Original file backed up as ${JS_FILE}.bak${RESET}"

        # Update the max_results parameter in the JavaScript
        # Use a more robust sed command that works on both macOS and Linux
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            sed -i '' 's/max_results: 10,/max_results: parseInt(document.getElementById('\''max-results'\'').value || '\''10'\''),/g' "$JS_FILE"
        else
            # Linux
            sed -i 's/max_results: 10,/max_results: parseInt(document.getElementById('\''max-results'\'').value || '\''10'\''),/g' "$JS_FILE"
        fi
        echo -e "${GREEN}Updated max_results parameter in JavaScript to use dynamic value from UI${RESET}"
    fi

    # Check if we need to update the HTML template too
    HTML_FILE="interfaces/futuristic/main.py"
    if [ -f "$HTML_FILE" ]; then
        # Check if the HTML fix has already been applied
        if grep -q "max-results" "$HTML_FILE"; then
            echo -e "${YELLOW}HTML template fix has already been applied!${RESET}"
            echo -e "${GREEN}UI control for max results is already present in the interface.${RESET}"
        else
            # Backup the original file
            cp "$HTML_FILE" "${HTML_FILE}.bak"
            echo -e "${BLUE}Original HTML template backed up as ${HTML_FILE}.bak${RESET}"

            echo -e "${YELLOW}Note: HTML template needs manual update to add the max results selector.${RESET}"
            echo -e "${BLUE}Please add the following HTML after the search button:${RESET}"
            echo -e '<div class="flex justify-between items-center mt-4">'
            echo -e '    <div class="flex items-center">'
            echo -e '        <label for="max-results" class="mr-2 text-gray-300">Max Results:</label>'
            echo -e '        <select id="max-results" class="bg-gray-800 text-white border border-gray-600 rounded p-2">'
            echo -e '            <option value="10">10</option>'
            echo -e '            <option value="20">20</option>'
            echo -e '            <option value="50">50</option>'
            echo -e '            <option value="100">100</option>'
            echo -e '        </select>'
            echo -e '    </div>'
            echo -e '    <div class="text-gray-400 text-xs">Higher values may increase search time</div>'
            echo -e '</div>'
        fi
    fi

    echo
    echo -e "${BOLD}${GREEN}Changes applied successfully!${RESET}"
    echo -e "${YELLOW}You'll need to restart the server for changes to take effect.${RESET}"
    echo -e "Restart command: ${BOLD}source venv/bin/activate && python interfaces/futuristic/main.py${RESET}"
else
    echo -e "${BLUE}No changes made. You can manually update the code as needed.${RESET}"
fi

echo
echo -e "${BOLD}${GREEN}Diagnosis complete!${RESET}"
echo -e "Check the pipeline_reports directory for detailed reports."
