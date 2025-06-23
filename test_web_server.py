#!/usr/bin/env python3
"""
Test script to verify FastAPI web server startup.

This script tests that the web interface can be initialized properly.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    # Test imports
    print("Testing imports...")
    from omics_oracle.web.models import QueryStatus, SearchRequest

    print("+ Models imported successfully")

    from omics_oracle.web.main import app

    print("+ FastAPI app imported successfully")

    print("\n*** Web interface imports successful!")
    print("Ready to start FastAPI development server")
    print("\nTo run the server:")
    print("  cd /path/to/OmicsOracle")
    print("  python -m uvicorn src.omics_oracle.web.main:app --reload")
    print("  or")
    print("  python src/omics_oracle/web/main.py")

except ImportError as e:
    print(f"[ERROR] Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"[ERROR] Error: {e}")
    sys.exit(1)
