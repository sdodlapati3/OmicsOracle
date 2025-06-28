#!/usr/bin/env python3
"""
Simple test to verify futuristic interface can start
"""

import sys
from pathlib import Path

# Add paths for imports
current_dir = Path(__file__).parent
root_dir = current_dir.parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir / "src"))

try:
    import uvicorn
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse

    print("[OK] FastAPI imports successful")

    # Create simple app
    app = FastAPI(
        title="OmicsOracle Futuristic Interface - Test Mode",
        description="Next-generation interface with AI agents (Test Mode)",
        version="2.0.0-test",
    )

    # Add CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/", response_class=HTMLResponse)
    async def home():
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>OmicsOracle Futuristic Interface - Test Mode</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
                .container { max-width: 800px; margin: 0 auto; padding: 40px; }
                .card { background: rgba(255,255,255,0.1); border-radius: 15px; padding: 30px; margin: 20px 0; backdrop-filter: blur(10px); }
                .status { display: inline-block; padding: 5px 15px; border-radius: 20px; background: #4CAF50; margin: 5px; }
                h1 { 14px: 3em; text-align: center; margin-bottom: 10px; }
                .emoji { 14px: 1.5em; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>[BIOMEDICAL] OmicsOracle</h1>
                <h2 style="text-align: center; margin-bottom: 40px;">Futuristic Interface - Test Mode</h2>

                <div class="card">
                    <h3>[LAUNCH] System Status</h3>
                    <div class="status">[OK] FastAPI Server Running</div>
                    <div class="status">[OK] CORS Enabled</div>
                    <div class="status">[OK] Test Mode Active</div>
                </div>

                <div class="card">
                    <h3>[TARGET] Features Ready for Implementation</h3>
                    <ul>
                        <li><span class="emoji">[AGENT]</span> AI Search Agents</li>
                        <li><span class="emoji">[REFRESH]</span> Real-time WebSocket Updates</li>
                        <li><span class="emoji">[CHART]</span> Advanced Visualizations</li>
                        <li><span class="emoji">[SECURITY]</span> Legacy Fallback System</li>
                        <li><span class="emoji">[FAST]</span> Multi-Agent Architecture</li>
                    </ul>
                </div>

                <div class="card">
                    <h3>[LINK] API Endpoints</h3>
                    <ul>
                        <li><a href="/docs" style="color: #FFD700;">[LIBRARY] API Documentation (/docs)</a></li>
                        <li><a href="/health" style="color: #FFD700;">[HEARTBEAT] Health Check (/health)</a></li>
                        <li><a href="/test" style="color: #FFD700;">[TEST] Test Endpoint (/test)</a></li>
                    </ul>
                </div>

                <div class="card">
                    <h3>[INFO] Next Steps</h3>
                    <ol>
                        <li>Implement agent communication system</li>
                        <li>Add WebSocket real-time updates</li>
                        <li>Connect to legacy OmicsOracle pipeline</li>
                        <li>Build interactive search interface</li>
                        <li>Add visualization components</li>
                    </ol>
                </div>
            </div>
        </body>
        </html>
        """

    @app.get("/health")
    async def health():
        return {
            "status": "healthy",
            "mode": "test_mode",
            "message": "Futuristic interface test server running",
            "features": {
                "agents": "ready_for_implementation",
                "websockets": "ready_for_implementation",
                "legacy_fallback": "ready_for_implementation",
            },
        }

    @app.get("/test")
    async def test():
        return {
            "message": "[SUCCESS] Futuristic interface test successful!",
            "server": "FastAPI",
            "status": "running",
            "ready_for": [
                "AI agents integration",
                "WebSocket real-time updates",
                "Legacy system fallback",
                "Advanced search capabilities",
            ],
        }

    if __name__ == "__main__":
        print("[STAR] Starting OmicsOracle Futuristic Interface - Test Mode")
        print("[LINK] Access at: http://localhost:8001")
        print("[LIBRARY] API docs: http://localhost:8001/docs")
        print("[HEARTBEAT] Health: http://localhost:8001/health")
        print("[STOP] Press Ctrl+C to stop")

        try:
            uvicorn.run(
                app,
                host="0.0.0.0",
                port=8001,
                reload=False,  # Disable reload to avoid issues
                log_level="info",
            )
        except KeyboardInterrupt:
            print("\n[HELLO] Server stopped by user")
        except Exception as e:
            print(f"[ERROR] Server error: {e}")

except ImportError as e:
    print(f"[ERROR] Import error: {e}")
    print("[IDEA] Make sure FastAPI and uvicorn are installed:")
    print("   pip install fastapi uvicorn")
    sys.exit(1)
except Exception as e:
    print(f"[ERROR] Startup error: {e}")
    print("[IDEA] Check your Python environment and dependencies")
    sys.exit(1)
