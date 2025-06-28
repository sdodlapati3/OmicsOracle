#!/usr/bin/env python
"""
API Endpoint Test Script

This script tests the FastAPI endpoints of the OmicsOracle futuristic interface,
verifying their functionality and response formats.
"""

import asyncio
import json
import logging
import os
import sys
import time
import traceback
from pathlib import Path

import requests
import websockets

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("api_endpoint_test.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("api_endpoint_test")

# Default API URL
DEFAULT_API_URL = "http://localhost:8001"


def test_health_endpoint(api_url=DEFAULT_API_URL):
    """Test the health check endpoint"""
    try:
        logger.info("Testing health check endpoint...")
        response = requests.get(f"{api_url}/api/health")

        if response.status_code == 200:
            logger.info(f"✓ Health endpoint returned status code {response.status_code}")
            data = response.json()
            logger.info(f"Health check response: {json.dumps(data, indent=2)}")

            # Check key fields
            if data.get("pipeline_available"):
                logger.info("✓ Pipeline is reported as available")
            else:
                logger.warning("✗ Pipeline is reported as unavailable")

            return True, data
        else:
            logger.error(f"✗ Health endpoint returned status code {response.status_code}")
            return False, None
    except Exception as e:
        logger.error(f"✗ Error testing health endpoint: {e}")
        logger.error(traceback.format_exc())
        return False, None


def test_search_endpoint(query, max_results=5, api_url=DEFAULT_API_URL):
    """Test the search endpoint"""
    try:
        logger.info(f"Testing search endpoint with query: '{query}'")

        payload = {
            "query": query,
            "max_results": max_results,
            "search_type": "comprehensive",
        }

        start_time = time.time()
        response = requests.post(f"{api_url}/api/search", json=payload)
        request_time = time.time() - start_time

        logger.info(
            f"Search request completed in {request_time:.2f}s with status code {response.status_code}"
        )

        if response.status_code == 200:
            data = response.json()
            logger.info(f"✓ Search endpoint returned {len(data['results'])} results")

            # Log some details about the results
            logger.info(f"Total found: {data['total_found']}")
            logger.info(f"Search time: {data['search_time']:.2f}s")

            if data["results"]:
                # Log details of first result
                first_result = data["results"][0]
                logger.info("First result details:")
                logger.info(f"  GEO ID: {first_result.get('geo_id', 'N/A')}")
                logger.info(f"  Title: {first_result.get('title', 'N/A')}")
                logger.info(f"  Has GEO summary: {first_result.get('geo_summary') is not None}")
                logger.info(f"  Has AI summary: {first_result.get('ai_summary') is not None}")

            return True, data
        else:
            logger.error(f"✗ Search endpoint returned status code {response.status_code}")
            logger.error(f"Response: {response.text}")
            return False, None
    except Exception as e:
        logger.error(f"✗ Error testing search endpoint: {e}")
        logger.error(traceback.format_exc())
        return False, None


async def test_websocket(api_url=DEFAULT_API_URL):
    """Test the WebSocket connection"""
    ws_url = api_url.replace("http://", "ws://").replace("https://", "wss://")
    ws_url = f"{ws_url}/ws/monitor"

    logger.info(f"Testing WebSocket connection to {ws_url}")

    try:
        async with websockets.connect(ws_url) as websocket:
            logger.info("✓ WebSocket connection established")

            # Send a ping message
            await websocket.send("ping")
            logger.info("Sent ping message")

            # Wait for a message with a timeout
            try:
                message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                logger.info(f"Received message: {message}")
            except asyncio.TimeoutError:
                logger.info("No message received within timeout period (this is normal)")

            # Keep connection open for a few seconds to receive any broadcasts
            logger.info("Listening for broadcasts for 5 seconds...")
            start_time = time.time()
            message_count = 0

            while time.time() - start_time < 5:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=0.5)
                    message_count += 1
                    logger.info(f"Received broadcast: {message}")
                except asyncio.TimeoutError:
                    # No message received in this iteration
                    pass

            logger.info(f"Received {message_count} broadcast messages")
            return True
    except Exception as e:
        logger.error(f"✗ Error testing WebSocket: {e}")
        logger.error(traceback.format_exc())
        return False


def test_frontend_serving(api_url=DEFAULT_API_URL):
    """Test that the frontend is being served correctly"""
    try:
        logger.info("Testing frontend serving...")
        response = requests.get(api_url)

        if response.status_code == 200:
            logger.info(f"✓ Frontend endpoint returned status code {response.status_code}")

            # Check for key HTML elements
            html = response.text
            checks = [
                ("OmicsOracle", "title or header"),
                ("Intelligent Search", "search section"),
                ("Search NCBI GEO Database", "search button"),
                ("main_clean.js", "JavaScript file"),
                ("main_clean.css", "CSS file"),
            ]

            all_passed = True
            for term, description in checks:
                if term in html:
                    logger.info(f"✓ Found {description} in HTML")
                else:
                    logger.warning(f"✗ Could not find {description} in HTML")
                    all_passed = False

            return all_passed
        else:
            logger.error(f"✗ Frontend endpoint returned status code {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"✗ Error testing frontend serving: {e}")
        logger.error(traceback.format_exc())
        return False


def test_static_files(api_url=DEFAULT_API_URL):
    """Test that static files are being served correctly"""
    try:
        logger.info("Testing static file serving...")

        files_to_check = [
            "/static/css/main_clean.css",
            "/static/js/main_clean.js",
        ]

        all_passed = True
        for file_path in files_to_check:
            response = requests.get(f"{api_url}{file_path}")

            if response.status_code == 200:
                logger.info(f"✓ Successfully retrieved {file_path}")
            else:
                logger.error(f"✗ Failed to retrieve {file_path}, status code {response.status_code}")
                all_passed = False

        return all_passed
    except Exception as e:
        logger.error(f"✗ Error testing static files: {e}")
        logger.error(traceback.format_exc())
        return False


async def run_tests(api_url=DEFAULT_API_URL):
    """Run all API endpoint tests"""
    logger.info("=" * 50)
    logger.info("API ENDPOINT TESTS")
    logger.info("=" * 50)
    logger.info(f"Testing API at: {api_url}")

    # Dictionary to store test results
    results = {}

    # Test health endpoint
    results["health_endpoint"] = test_health_endpoint(api_url)

    # Test frontend serving
    results["frontend_serving"] = test_frontend_serving(api_url)

    # Test static files
    results["static_files"] = test_static_files(api_url)

    # Test WebSocket connection
    results["websocket"] = await test_websocket(api_url)

    # Test search endpoint with a simple query
    results["search_endpoint"] = test_search_endpoint("cancer RNA-seq", 3, api_url)

    # Test search endpoint with the user's query
    results["user_query"] = test_search_endpoint("dna methylation of immune cells", 5, api_url)

    # Print summary
    logger.info("\n\n" + "=" * 50)
    logger.info("TEST SUMMARY")
    logger.info("=" * 50)

    for test_name, result in results.items():
        if isinstance(result, tuple):
            status = "✓ PASS" if result[0] else "✗ FAIL"
        else:
            status = "✓ PASS" if result else "✗ FAIL"
        logger.info(f"{status}: {test_name}")

    # Determine overall status
    all_passed = all(result[0] if isinstance(result, tuple) else result for result in results.values())
    logger.info(f"\nOverall status: {'PASS' if all_passed else 'FAIL'}")

    # Provide additional analysis and recommendations
    if not all_passed:
        logger.info("\n" + "=" * 50)
        logger.info("RECOMMENDATIONS")
        logger.info("=" * 50)

        if not results.get("health_endpoint", (False,))[0]:
            logger.info("- Check if the FastAPI server is running")
            logger.info("- Verify the health endpoint implementation")
            logger.info("- Check server logs for startup errors")

        if not results.get("frontend_serving", False):
            logger.info("- Verify the HTML template in main.py")
            logger.info("- Check for syntax errors in the template")

        if not results.get("static_files", False):
            logger.info("- Check if the static directory exists and contains the required files")
            logger.info("- Verify the static files mounting in FastAPI")

        if not results.get("websocket", False):
            logger.info("- Check WebSocket implementation in main.py")
            logger.info("- Verify WebSocket handler is registered correctly")

        if not results.get("search_endpoint", (False,))[0]:
            logger.info("- Check pipeline initialization in main.py")
            logger.info("- Verify NCBI email configuration")
            logger.info("- Run the debug_pipeline_init.py script to diagnose pipeline issues")
            logger.info("- Check for errors in process_search_query function")

        if not results.get("user_query", (False,))[0]:
            logger.info("- The specific user query failed - check if it's valid for GEO")
            logger.info("- Check server logs for query processing errors")


if __name__ == "__main__":
    # Get API URL from command line argument or use default
    api_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_API_URL

    # Create and run the async event loop
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(run_tests(api_url))
    except Exception as e:
        logger.error(f"Unhandled exception in tests: {e}")
        logger.error(traceback.format_exc())
    finally:
        loop.close()
