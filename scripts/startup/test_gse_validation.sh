#!/bin/bash
# GSE Content Validation Test Script
# This script tests the GSE content validator with known problematic GSE IDs

echo "===== GSE CONTENT VALIDATION TEST ====="
echo "Testing GSE content validation with known problematic IDs"
echo ""

# Create output directory
REPORT_DIR="validation_reports"
mkdir -p $REPORT_DIR

# Format current date for report naming
DATE=$(date +"%Y%m%d_%H%M%S")

# Function to run a test and log results
run_test() {
    local gse_id=$1
    local description=$2

    echo "🔍 Testing GSE ID: $gse_id - $description"
    echo "   Running: python validate_gse_content.py --gse-id $gse_id"

    # Run the validator
    python validate_gse_content.py --gse-id $gse_id

    echo "   Report saved to $REPORT_DIR/content_validation_single_${gse_id}_*.json"
    echo ""
}

# Test with known problematic GSE IDs
run_test "GSE278726" "Reported as showing incorrect COVID-19 content"
run_test "GSE183281" "Known COVID-19 dataset for comparison"
run_test "GSE134809" "Random control dataset"

# Test a query that might return problematic results
echo "🔎 Testing search query: 'covid-19 transcriptome'"
echo "   Running: python validate_gse_content.py --query 'covid-19 transcriptome' --max-results 5"
python validate_gse_content.py --query "covid-19 transcriptome" --max-results 5

echo "   Report saved to $REPORT_DIR/content_validation_*.json"
echo ""

# Test the data integrity analyzer
echo "🔍 Running data integrity analysis on key files"
echo "   Running: python analyze_data_integrity.py --check-file interfaces/futuristic/static/js/main_clean.js"
python analyze_data_integrity.py --check-file interfaces/futuristic/static/js/main_clean.js

echo ""
echo "✅ Tests completed. Please review the reports in $REPORT_DIR directory"
echo "======================================"
