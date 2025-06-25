"""
UI routes for the enhanced interface - Clean version with static files
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse


def create_ui_router() -> APIRouter:
    """Create UI router with frontend routes"""

    router = APIRouter()

    @router.get("/", response_class=HTMLResponse)
    async def home() -> str:
        """Main UI page with proper static file separation"""
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>OmicsOracle Enhanced Interface</title>
            <link rel="stylesheet" href="/static/css/main.css">
        </head>
        <body>
            <!-- Agent Status Sidebar -->
            <div class="agent-sidebar" id="agent-sidebar">
                <div class="agent-sidebar-header">
                    <h3>[AGENT] Agent Status</h3>
                    <button class="close-sidebar" onclick="toggleAgentSidebar()">[X]</button>
                </div>
                <div id="agent-status-container">
                    <div class="agent-status">
                        <div class="agent-info">
                            <div class="status-indicator"></div>
                            <span>Loading agents...</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Sidebar Toggle Button -->
            <button class="agent-sidebar-toggle" id="sidebar-toggle" onclick="toggleAgentSidebar()">
                [AGENT]
            </button>

            <div class="websocket-status" id="ws-status">[CONNECT] Connecting...</div>

            <div class="main-content" id="main-content">
                <div class="header">
                    <h1>[LAUNCH] OmicsOracle Enhanced Interface</h1>
                    <p>Modular, maintainable next-generation research platform</p>
                    <span class="status-badge status-healthy">Modular Architecture</span>
                </div>

                <div class="container">
                    <div class="main-interface-grid">
                        <div class="card">
                            <h3>[SEARCH] Intelligent Search</h3>
                            <input type="text" class="search-box" id="search-input"
                                   placeholder="Enter your research query..." />
                            <button class="btn" onclick="performSearch()">[LAUNCH] Search with AI</button>
                            <div id="search-results"></div>
                        </div>
                    </div>

                <div class="card">
                    <h3>[TARGET] Enhanced Features</h3>
                    <div class="feature-grid">
                        <div class="feature">
                            <div class="feature-icon">[AI]</div>
                            <h4>AI-Powered Analysis</h4>
                            <p>Smart interpretation of omics data</p>
                        </div>
                        <div class="feature">
                            <div class="feature-icon">[FAST]</div>
                            <h4>Real-time Updates</h4>
                            <p>Live progress via WebSockets</p>
                        </div>
                        <div class="feature">
                            <div class="feature-icon">[CHART]</div>
                            <h4>Advanced Visualizations</h4>
                            <p>Interactive plots and networks</p>
                        </div>
                        <div class="feature">
                            <div class="feature-icon">[BUILD]</div>
                            <h4>Modular Architecture</h4>
                            <p>Clean, maintainable codebase</p>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h3>[CHART] Advanced Visualizations</h3>
                    <div class="feature-grid">
                        <button class="btn" onclick="createDemoVisualization('scatter_plot')">[GRAPH] Scatter Plot</button>
                        <button class="btn" onclick="createDemoVisualization('network_graph')">[NETWORK] Network Graph</button>
                        <button class="btn" onclick="createDemoVisualization('heatmap')">[HEATMAP] Heatmap</button>
                        <button class="btn" onclick="createDemoVisualization('volcano_plot')">[VOLCANO] Volcano Plot</button>
                    </div>
                    <div id="visualization-container" style="margin-top: 20px; min-height: 400px; border: 1px solid rgba(255,255,255,0.2); border-radius: 10px; position: relative;">
                        <div style="padding: 20px; text-align: center; color: rgba(255,255,255,0.7);">
                            <p>[TARGET] Click buttons above to create interactive visualizations</p>
                            <p>[CHART] Visualizations will appear here with real-time updates</p>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h3>[GRAPH] Performance Monitor</h3>
                    <div id="performance-metrics">
                        <div class="metrics-grid">
                            <div class="metric-item">
                                <div class="metric-value" id="api-requests">0</div>
                                <div class="metric-label">API Requests</div>
                            </div>
                            <div class="metric-item">
                                <div class="metric-value" id="search-queries">0</div>
                                <div class="metric-label">Search Queries</div>
                            </div>
                            <div class="metric-item">
                                <div class="metric-value" id="websocket-connections">0</div>
                                <div class="metric-label">WebSocket Connections</div>
                            </div>
                            <div class="metric-item">
                                <div class="metric-value" id="avg-response-time">0ms</div>
                                <div class="metric-label">Avg Response Time</div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h3>[CHART] System Monitor</h3>
                    <div class="demo-area" id="demo-area">
                        <p>[TARGET] Enhanced interface ready! Modular components loaded successfully.</p>
                        <div id="live-updates"></div>
                    </div>
                </div>
            </div> <!-- End main-content -->

            <script src="/static/js/main.js"></script>
            <script>
                function toggleAgentSidebar() {
                    const sidebar = document.getElementById('agent-sidebar');
                    const mainContent = document.getElementById('main-content');
                    const toggleBtn = document.getElementById('sidebar-toggle');

                    sidebar.classList.toggle('open');
                    mainContent.classList.toggle('sidebar-open');

                    // Update toggle button
                    if (sidebar.classList.contains('open')) {
                        toggleBtn.innerHTML = '[VIEW]'; // Eye icon when open
                    } else {
                        toggleBtn.innerHTML = '[AGENT]'; // Robot icon when closed
                    }
                }
            </script>
        </body>
        </html>
        """

    return router
