"""
Enhanced Server Entry Point
Coordinates modular components in a clean, maintainable way
"""

import sys
from pathlib import Path

# Add paths for imports
current_dir = Path(__file__).parent
root_dir = current_dir.parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir / "src"))
sys.path.insert(0, str(current_dir))

try:
    import uvicorn
    from core.application import create_app
    from core.config import EnhancedConfig

    print("[OK] Enhanced server imports successful")

    # Create app instance at module level for uvicorn
    config = EnhancedConfig()
    app = create_app(config)

    def main():
        """Main entry point for enhanced server"""

        print("[STAR] Starting OmicsOracle Enhanced Interface")
        print("[TARGET] Modular, maintainable architecture")
        print("[LINK] Access at: http://localhost:8001")
        print("[LIBRARY] API docs: http://localhost:8001/docs")
        print("[HEARTBEAT] Health: http://localhost:8001/health")
        print("[STOP] Press Ctrl+C to stop")

        try:
            uvicorn.run(app, host="0.0.0.0", port=8001, reload=False, log_level="info")
        except KeyboardInterrupt:
            print("\n[HELLO] Enhanced server stopped by user")
        except Exception as e:
            print(f"[ERROR] Server error: {e}")

    if __name__ == "__main__":
        main()

except ImportError as e:
    print(f"[ERROR] Import error: {e}")
    print("[IDEA] Make sure FastAPI and uvicorn are installed")
    sys.exit(1)
except Exception as e:
    print(f"[ERROR] Startup error: {e}")
    sys.exit(1)
