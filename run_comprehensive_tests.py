#!/usr/bin/env python
"""
OmicsOracle Comprehensive Test Runner

This script orchestrates running all test scripts and aggregates the results,
providing a complete picture of system health and functionality.
"""

import argparse
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("comprehensive_test_run.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("test_runner")

def run_script(script_path, description, args=None):
    """Run a script and capture output"""
    logger.info("=" * 80)
    logger.info(f"Running: {description}")
    logger.info(f"Script: {script_path}")
    logger.info("=" * 80)
    
    cmd = [sys.executable, script_path]
    if args:
        cmd.extend(args)
        
    start_time = time.time()
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        
        duration = time.time() - start_time
        
        # Print output
        if result.stdout:
            logger.info("STDOUT:")
            for line in result.stdout.splitlines():
                logger.info(f"  {line}")
                
        if result.stderr:
            logger.info("STDERR:")
            for line in result.stderr.splitlines():
                logger.info(f"  {line}")
        
        success = result.returncode == 0
        logger.info(f"Result: {'✓ SUCCESS' if success else '✗ FAILURE'}")
        logger.info(f"Duration: {duration:.2f}s")
        logger.info(f"Return code: {result.returncode}")
        
        return {
            "description": description,
            "script": script_path,
            "success": success,
            "return_code": result.returncode,
            "duration": duration,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except Exception as e:
        logger.error(f"Error running script: {e}")
        duration = time.time() - start_time
        
        return {
            "description": description,
            "script": script_path,
            "success": False,
            "return_code": -1,
            "duration": duration,
            "stdout": "",
            "stderr": str(e)
        }

def check_server_running(api_url="http://localhost:8001"):
    """Check if the server is running"""
    import requests
    try:
        response = requests.get(f"{api_url}/api/health", timeout=5)
        return response.status_code == 200
    except:
        return False

def start_server():
    """Start the FastAPI server in a separate process"""
    logger.info("Starting FastAPI server...")
    
    server_path = Path("interfaces/futuristic/main.py")
    if not server_path.exists():
        logger.error(f"Server file not found: {server_path}")
        return None
    
    cmd = [sys.executable, str(server_path)]
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Give the server time to start
        logger.info("Waiting for server to start...")
        time.sleep(5)
        
        # Check if server is running
        if check_server_running():
            logger.info("Server started successfully")
            return process
        else:
            logger.error("Server failed to start")
            process.terminate()
            return None
    except Exception as e:
        logger.error(f"Error starting server: {e}")
        return None

def get_test_scripts():
    """Get list of test scripts to run"""
    # Define scripts to run in order
    return [
        {
            "path": "debug_pipeline_init.py",
            "description": "Pipeline Initialization Diagnostics",
            "args": None
        },
        {
            "path": "test_geo_client.py",
            "description": "GEO Client Functionality Test",
            "args": None
        },
        {
            "path": "test_api_endpoints.py",
            "description": "API Endpoints Test",
            "args": ["http://localhost:8001"]
        }
    ]

def run_all_tests(start_server_flag=False):
    """Run all test scripts"""
    logger.info("=" * 80)
    logger.info("OMICSORACLE COMPREHENSIVE TEST RUN")
    logger.info("=" * 80)
    
    # Start server if requested
    server_process = None
    if start_server_flag:
        server_process = start_server()
        if not server_process:
            logger.error("Failed to start server, continuing with tests anyway")
    else:
        logger.info("Skipping server start, assuming server is already running")
    
    # Get list of test scripts
    test_scripts = get_test_scripts()
    
    # Run each script
    results = []
    for script in test_scripts:
        result = run_script(script["path"], script["description"], script["args"])
        results.append(result)
    
    # If we started the server, terminate it
    if server_process:
        logger.info("Terminating server process...")
        server_process.terminate()
        try:
            server_process.wait(timeout=5)
            logger.info("Server process terminated")
        except subprocess.TimeoutExpired:
            logger.warning("Server process did not terminate gracefully, forcing...")
            server_process.kill()
    
    # Generate summary
    logger.info("\n\n" + "=" * 80)
    logger.info("TEST SUMMARY")
    logger.info("=" * 80)
    
    success_count = sum(1 for r in results if r["success"])
    logger.info(f"Ran {len(results)} tests, {success_count} succeeded, {len(results) - success_count} failed")
    
    for i, result in enumerate(results, 1):
        status = "✓ PASS" if result["success"] else "✗ FAIL"
        logger.info(f"{i}. {status} - {result['description']} ({result['duration']:.2f}s)")
    
    # Generate detailed report
    report = {
        "timestamp": time.time(),
        "summary": {
            "total_tests": len(results),
            "passed": success_count,
            "failed": len(results) - success_count,
            "success_rate": success_count / len(results) if results else 0
        },
        "results": results
    }
    
    # Save report to file
    report_path = f"test_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Detailed report saved to: {report_path}")
    
    # Provide recommendations based on results
    if success_count < len(results):
        logger.info("\n\n" + "=" * 80)
        logger.info("RECOMMENDATIONS")
        logger.info("=" * 80)
        
        # Find failed tests
        failed_tests = [r for r in results if not r["success"]]
        
        for test in failed_tests:
            logger.info(f"Failed test: {test['description']}")
            
            # Specific recommendations based on which test failed
            if "Pipeline Initialization" in test["description"]:
                logger.info("- Check NCBI email configuration")
                logger.info("- Verify Bio.Entrez is properly installed")
                logger.info("- Check for exceptions during pipeline initialization")
            
            elif "GEO Client" in test["description"]:
                logger.info("- Verify network connectivity to NCBI")
                logger.info("- Check NCBI email settings")
                logger.info("- Look for Bio.Entrez.email configuration issues")
            
            elif "API Endpoints" in test["description"]:
                logger.info("- Ensure the FastAPI server is running")
                logger.info("- Check for errors in the API implementation")
                logger.info("- Verify pipeline is properly initialized in the server")
        
        logger.info("\nGeneral recommendations:")
        logger.info("1. Run each failed test script individually for more detailed diagnostics")
        logger.info("2. Check the comprehensive_test_run.log file for detailed error messages")
        logger.info("3. Fix the most fundamental issues first (pipeline initialization, GEO client)")
        logger.info("4. After fixing issues, run this comprehensive test again")
    
    return success_count == len(results)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run comprehensive tests for OmicsOracle")
    parser.add_argument("--start-server", action="store_true", help="Start the FastAPI server before running tests")
    args = parser.parse_args()
    
    success = run_all_tests(args.start_server)
    sys.exit(0 if success else 1)
