#!/usr/bin/env python3
"""
Simple Web Server Starter

This script starts the web server with proper path setup.
"""

import os
import sys
from pathlib import Path

# Add the src directory to the Python path
current_dir = Path(__file__).parent
src_dir = current_dir / "src"
sys.path.insert(0, str(src_dir))

# Change to the root directory for proper config loading
os.chdir(current_dir)

# Import and run the web server
try:
    import uvicorn

    from omics_oracle.web.main import app

    print("🚀 Starting OmicsOracle Web Server with AI Integration")
    print("=" * 60)
    print("🌐 Server will be available at: http://127.0.0.1:8000")
    print("🤖 AI Summarization features are enabled")
    print("💡 Try searching with AI Summarization enabled!")
    print("=" * 60)

    uvicorn.run(
        app, host="127.0.0.1", port=8000, log_level="info", reload=False
    )

except Exception as e:
    print(f"❌ Error starting web server: {e}")
    import traceback

    traceback.print_exc()
    sys.exit(1)
