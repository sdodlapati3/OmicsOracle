#!/usr/bin/env python
"""
OmicsOracle Testing and Monitoring Suite Launcher

This script serves as a central entry point for launching various testing,
monitoring, and diagnostic tools for the OmicsOracle platform.
"""

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("omics_toolbox.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("omics_toolbox")

# Script paths
script_path = Path(__file__).resolve()
project_root = script_path.parent

TOOLS = {
    "pipeline-debug": {
        "script": "debug_pipeline_init.py",
        "description": "Diagnose pipeline initialization issues",
        "args": [],
    },
    "geo-test": {
        "script": "test_geo_client.py",
        "description": "Test GEO client functionality",
        "args": [],
    },
    "api-test": {
        "script": "test_api_endpoints.py",
        "description": "Test API endpoints",
        "args": ["http://localhost:8001"],
    },
    "comprehensive-test": {
        "script": "run_comprehensive_tests.py",
        "description": "Run comprehensive test suite",
        "args": [],
    },
    "dashboard": {
        "script": "monitoring_dashboard.py",
        "description": "Start monitoring dashboard",
        "args": [],
    },
}


def ensure_executable(script_path):
    """Make sure the script is executable"""
    try:
        os.chmod(script_path, 0o755)
        logger.info(f"Made {script_path} executable")
    except Exception as e:
        logger.warning(f"Failed to make {script_path} executable: {e}")


def list_tools():
    """List available tools"""
    print("\nAvailable Tools:")
    print("=" * 50)
    for name, tool in TOOLS.items():
        print(f"{name:20} - {tool['description']}")
    print("\nUsage: ./omics_toolbox.py [tool_name] [additional_args]")
    print("\nExamples:")
    print("  ./omics_toolbox.py pipeline-debug")
    print("  ./omics_toolbox.py api-test http://localhost:8001")
    print("  ./omics_toolbox.py dashboard")
    print("  ./omics_toolbox.py --make-executable")


def make_scripts_executable():
    """Make all scripts executable"""
    for tool in TOOLS.values():
        script_path = project_root / tool["script"]
        if script_path.exists():
            ensure_executable(script_path)
        else:
            logger.warning(f"Script not found: {script_path}")

    # Make this script executable too
    ensure_executable(script_path)


def run_tool(tool_name, additional_args=None):
    """Run the specified tool"""
    if tool_name not in TOOLS:
        logger.error(f"Unknown tool: {tool_name}")
        list_tools()
        return 1

    tool = TOOLS[tool_name]
    script_path = project_root / tool["script"]

    if not script_path.exists():
        logger.error(f"Script not found: {script_path}")
        return 1

    # Make the script executable
    ensure_executable(script_path)

    # Build the command
    cmd = [sys.executable, str(script_path)]

    # Add default args
    if tool["args"]:
        cmd.extend(tool["args"])

    # Add additional args if provided
    if additional_args:
        cmd.extend(additional_args)

    logger.info(f"Running: {' '.join(cmd)}")

    try:
        return subprocess.call(cmd)
    except Exception as e:
        logger.error(f"Error running tool: {e}")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OmicsOracle Testing and Monitoring Suite Launcher")
    parser.add_argument("tool", nargs="?", help="Tool to run")
    parser.add_argument("--list", action="store_true", help="List available tools")
    parser.add_argument(
        "--make-executable",
        action="store_true",
        help="Make all scripts executable",
    )
    parser.add_argument("args", nargs="*", help="Additional arguments to pass to the tool")

    args = parser.parse_args()

    if args.make_executable:
        make_scripts_executable()
        sys.exit(0)

    if args.list or not args.tool:
        list_tools()
        sys.exit(0)

    sys.exit(run_tool(args.tool, args.args))
