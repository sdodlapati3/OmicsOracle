#!/usr/bin/env bash
# OmicsOracle Comprehensive Test and Validation Suite
# This script runs all the comprehensive tests and validations

set -e

echo "🧪 OmicsOracle Comprehensive Test and Validation Suite"
echo "====================================================="
echo

# Create directories if they don't exist
mkdir -p test_reports query_traces performance_reports error_analysis

# Check if server is running
echo "Checking if server is running..."
if ! curl -s "http://localhost:8000/health" > /dev/null; then
    echo "⚠️ Server is not running. Starting server..."
    echo "Starting server in background..."
    ./start_server.sh &

    # Wait for server to start
    echo "Waiting for server to start..."
    for i in {1..10}; do
        if curl -s "http://localhost:8000/health" > /dev/null; then
            echo "✅ Server started successfully"
            break
        fi
        echo "Waiting... ($i/10)"
        sleep 3
    done

    if ! curl -s "http://localhost:8000/health" > /dev/null; then
        echo "❌ Failed to start server. Please start it manually and try again."
        exit 1
    fi
else
    echo "✅ Server is already running"
fi

# Run comprehensive endpoint tests
echo
echo "📝 Running comprehensive endpoint tests..."
python3 test_endpoints_comprehensive.py

# Run enhanced query validation
echo
echo "📝 Running enhanced query validation..."
python3 validate_enhanced_query_handler.py

# Run performance monitoring
echo
echo "📈 Running search performance monitoring..."
python3 search_performance_monitor.py

# Run error analysis if log files exist
echo
echo "🔍 Running search error analysis..."
if [ -f "server.log" ]; then
    python3 search_error_analyzer.py --logs server.log
else
    echo "⚠️ No log files found for error analysis. Skipping..."
fi

# Run comprehensive tests and traces
echo
echo "📝 Running comprehensive tests and traces..."
python3 run_comprehensive_tests_and_traces.py

echo
echo "✅ All tests completed!"
echo "Test reports available in the test_reports directory"
echo "Query traces available in the query_traces directory"
