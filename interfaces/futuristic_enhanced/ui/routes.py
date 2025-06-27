"""
UI routes for the enhanced interface
"""

from core.config import UI_THEME
from fastapi import APIRouter
from fastapi.responses import HTMLResponse


def create_ui_router() -> APIRouter:
    """Create UI router with frontend routes"""

    router = APIRouter()

    @router.get("/", response_class=HTMLResponse)
    async def home():
        """Main UI page"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>OmicsOracle Enhanced Interface</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: {UI_THEME['primary_gradient']};
                    color: white; min-height: 100vh; overflow-x: hidden;
                }}
                .header {{
                    background: {UI_THEME['card_background']}; backdrop-filter: blur(10px);
                    padding: 20px; text-align: center; border-bottom: 1px solid rgba(255,255,255,0.2);
                }}
                .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
                .card {{
                    background: {UI_THEME['card_background']}; border-radius: 15px;
                    padding: 25px; margin: 20px 0; backdrop-filter: blur(10px);
                    border: 1px solid rgba(255,255,255,0.2); transition: all 0.3s ease;
                }}
                .card:hover {{ transform: translateY(-5px); box-shadow: 0 10px 30px rgba(0,0,0,0.3); }}
                .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
                .agent-status {{
                    display: flex; align-items: center; margin: 10px 0;
                    padding: 10px; border-radius: 8px; background: {UI_THEME['card_background']};
                }}
                .status-indicator {{
                    width: 12px; height: 12px; border-radius: 50%;
                    background: {UI_THEME['success_color']}; margin-right: 10px; animation: pulse 2s infinite;
                }}
                @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}
                .search-box {{
                    width: 100%; padding: 15px; border: none; border-radius: 10px;
                    background: rgba(255,255,255,0.2); color: white; 14px: 16px;
                    margin: 15px 0;
                }}
                .search-box::placeholder {{ color: rgba(255,255,255,0.7); }}
                .btn {{
                    background: linear-gradient(45deg, #FF6B6B, {UI_THEME['accent_color']});
                    border: none; padding: 12px 24px; border-radius: 25px;
                    color: white; cursor: pointer; 14px: 14px; font-weight: bold;
                    transition: all 0.3s ease;
                }}
                .btn:hover {{ transform: scale(1.05); box-shadow: 0 5px 15px rgba(0,0,0,0.3); }}
                .feature-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }}
                .feature {{
                    text-align: center; padding: 20px; border-radius: 10px;
                    background: {UI_THEME['card_background']};
                }}
                .feature-icon {{ 14px: 2em; margin-bottom: 10px; }}
                .demo-area {{
                    min-height: 200px; background: rgba(0,0,0,0.2);
                    border-radius: 10px; padding: 20px; margin-top: 20px;
                }}
                #search-results {{ margin-top: 20px; }}
                .result-item {{
                    background: {UI_THEME['card_background']}; padding: 15px;
                    border-radius: 8px; margin: 10px 0; border-left: 4px solid {UI_THEME['accent_color']};
                }}
                .websocket-status {{
                    position: fixed; top: 20px; right: 20px;
                    padding: 10px 15px; border-radius: 20px;
                    background: rgba(0,0,0,0.7); 14px: 12px;
                }}
                .status-badge {{ padding: 4px 8px; border-radius: 12px; 14px: 11px; font-weight: bold; }}
                .status-healthy {{ background: {UI_THEME['success_color']}; }}
                .status-warning {{ background: {UI_THEME['warning_color']}; }}
                .metric-item {{
                    text-align: center; padding: 15px; border-radius: 8px;
                    background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2);
                }}
                .metric-value {{
                    14px: 1.8em; font-weight: bold; color: {UI_THEME['accent_color']};
                    margin-bottom: 5px;
                }}
                .metric-label {
                    14px: 0.9em; color: rgba(255,255,255,0.8);
                }
            </style>
        </head>
        <body>
            <div class="websocket-status" id="ws-status">[CONNECT] Connecting...</div>

            <div class="header">
                <h1>[LAUNCH] OmicsOracle Enhanced Interface</h1>
                <p>Modular, maintainable next-generation research platform</p>
                <span class="status-badge status-healthy">Modular Architecture</span>
            </div>

            <div class="container">
                <div class="grid">
                    <div class="card">
                        <h3>[AGENT] Agent Status</h3>
                        <div id="agent-status-container">
                            <div class="agent-status">
                                <div class="status-indicator"></div>
                                <span>Loading agents...</span>
                            </div>
                        </div>
                    </div>

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
                        <div class="metrics-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px;">
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
            </div>

            <script>
                // WebSocket connection for real-time updates
                let ws = null;

                function connectWebSocket() {{
                    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                    ws = new WebSocket(`${{protocol}}//${{window.location.host}}/ws`);

                    ws.onopen = function() {{
                        document.getElementById('ws-status').innerHTML = '[GREEN] Connected';
                        addLiveUpdate('[CONNECT] WebSocket connected - Real-time updates active');
                        loadAgentStatus();
                    }};

                    ws.onmessage = function(event) {{
                        const data = JSON.parse(event.data);
                        addLiveUpdate(`[MESSAGE] ${{data.message || data.status || 'Update received'}}`);
                    }};

                    ws.onclose = function() {{
                        document.getElementById('ws-status').innerHTML = '[RED] Disconnected';
                        setTimeout(connectWebSocket, 3000);
                    }};
                }}

                async function loadAgentStatus() {{
                    try {{
                        const response = await fetch('/api/agents');
                        const data = await response.json();
                        displayAgentStatus(data.agents || []);
                    }} catch (error) {{
                        console.error('Failed to load agent status:', error);
                    }}
                }}

                function displayAgentStatus(agents) {{
                    const container = document.getElementById('agent-status-container');
                    container.innerHTML = '';

                    agents.forEach(agent => {{
                        const div = document.createElement('div');
                        div.className = 'agent-status';
                        div.innerHTML = `
                            <div class="status-indicator"></div>
                            <span>${{agent.name}} - ${{agent.status}}</span>
                        `;
                        container.appendChild(div);
                    }});
                }}

                function addLiveUpdate(message) {{
                    const updates = document.getElementById('live-updates');
                    const div = document.createElement('div');
                    div.style.cssText = 'margin: 5px 0; padding: 8px; background: rgba(255,255,255,0.1); border-radius: 5px; 14px: 13px;';
                    div.innerHTML = `${{new Date().toLocaleTimeString()}} - ${{message}}`;
                    updates.insertBefore(div, updates.firstChild);

                    while (updates.children.length > 5) {{
                        updates.removeChild(updates.lastChild);
                    }}
                }}

                async function performSearch() {{
                    const query = document.getElementById('search-input').value;
                    if (!query) return;

                    const resultsDiv = document.getElementById('search-results');
                    resultsDiv.innerHTML = '<p>[SEARCH] Searching with AI agents...</p>';

                    try {{
                        const response = await fetch('/api/search', {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ query: query, search_type: 'enhanced' }})
                        }});

                        const data = await response.json();
                        displaySearchResults(data.results || []);

                    }} catch (error) {{
                        resultsDiv.innerHTML = '<p>[ERROR] Search error. Please try again.</p>';
                    }}
                }}

                function displaySearchResults(results) {{
                    const resultsDiv = document.getElementById('search-results');
                    if (results.length === 0) {{
                        resultsDiv.innerHTML = '<p>No results found.</p>';
                        return;
                    }}

                    let html = '<h4>[CLIPBOARD] Search Results:</h4>';
                    results.forEach(result => {{
                        html += `
                            <div class="result-item">
                                <strong>${{result.title}}</strong><br>
                                <small>Source: ${{result.source}} | Score: ${{result.relevance_score}}</small><br>
                                ${{result.description}}
                            </div>
                        `;
                    }});
                    resultsDiv.innerHTML = html;
                }}

                // Visualization functions
                async function createDemoVisualization(type) {{
                    const container = document.getElementById('visualization-container');
                    container.innerHTML = '<div style="padding: 20px; text-align: center;"><p>[REFRESH] Creating ' + type + ' visualization...</p></div>';

                    try {{
                        const response = await fetch('/api/visualize', {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{
                                type: type,
                                title: 'Demo ' + type.replace('_', ' ').toUpperCase(),
                                data: getDemoData(type)
                            }})
                        }});

                        const result = await response.json();

                        if (result.status === 'success') {{
                            displayVisualization(result.visualization);
                        }} else {{
                            container.innerHTML = '<div style="padding: 20px; color: #FF6B6B;"><p>[ERROR] Error creating visualization: ' + (result.message || 'Unknown error') + '</p></div>';
                        }}

                    }} catch (error) {{
                        container.innerHTML = '<div style="padding: 20px; color: #FF6B6B;"><p>[ERROR] Network error: ' + error.message + '</p></div>';
                    }}
                }}

                function getDemoData(type) {{
                    switch(type) {{
                        case 'scatter_plot':
                            return {{
                                points: Array.from({{length: 50}}, (_, i) => ({
                                    x: Math.random() * 100,
                                    y: Math.random() * 100,
                                    label: 'Point ' + i,
                                    size: Math.random() * 10 + 5
                                }))
                            }};
                        case 'network_graph':
                            const nodes = Array.from({{length: 10}}, (_, i) => ({
                                id: 'node_' + i,
                                label: 'Node ' + i,
                                group: Math.floor(Math.random() * 3) + 1
                            }));
                            const edges = Array.from({{length: 15}}, () => {{
                                const source = nodes[Math.floor(Math.random() * nodes.length)].id;
                                const target = nodes[Math.floor(Math.random() * nodes.length)].id;
                                return {{ source, target, weight: Math.random() }};
                            }});
                            return { nodes, edges };
                        case 'volcano_plot':
                            return {{
                                fold_changes: Array.from({{length: 100}}, () => Math.random() * 10 - 5),
                                p_values: Array.from({{length: 100}}, () => Math.random() * 0.1),
                                gene_names: Array.from({{length: 100}}, (_, i) => 'Gene_' + i)
                            }};
                        case 'heatmap':
                            return {{
                                matrix: Array.from({{length: 10}}, () => Array.from({{length: 15}}, () => Math.random() * 4 - 2)),
                                row_labels: Array.from({{length: 10}}, (_, i) => 'Gene_' + i),
                                col_labels: Array.from({{length: 15}}, (_, i) => 'Sample_' + i)
                            }};
                        default:
                            return {{}};
                    }}
                }}

                function displayVisualization(vizData) {{
                    const container = document.getElementById('visualization-container');

                    let content = '<div style="padding: 20px;">';
                    content += '<h4 style="margin-bottom: 15px;">[CHART] ' + (vizData.config?.title || 'Visualization') + '</h4>';
                    content += '<div style="background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; 14px: 12px;">';
                    content += '<strong>Type:</strong> ' + vizData.type + '<br>';
                    content += '<strong>ID:</strong> ' + vizData.id + '<br>';
                    content += '<strong>Data Points:</strong> ' + (vizData.data?.length || 'N/A') + '<br>';
                    content += '<strong>Created:</strong> ' + new Date(vizData.timestamp).toLocaleString() + '<br>';

                    if (vizData.type === 'network') {{
                        content += '<strong>Nodes:</strong> ' + (vizData.nodes?.length || 0) + '<br>';
                        content += '<strong>Edges:</strong> ' + (vizData.edges?.length || 0) + '<br>';
                    }}

                    content += '</div>';
                    content += '<div style="margin-top: 15px; padding: 10px; background: rgba(76, 175, 80, 0.2); border-radius: 5px;">';
                    content += '[OK] Visualization created successfully! In a full implementation, this would render an interactive chart using D3.js or similar.';
                    content += '</div>';
                    content += '</div>';

                    container.innerHTML = content;

                    addLiveUpdate('[CHART] Created ' + vizData.type + ' visualization: ' + (vizData.config?.title || 'Untitled'));
                }}

                // Performance monitoring
                async function updatePerformanceMetrics() {{
                    try {{
                        const response = await fetch('/api/performance');
                        const metrics = await response.json();

                        if (metrics && metrics.metrics) {{
                            document.getElementById('api-requests').textContent = metrics.metrics.api_requests || 0;
                            document.getElementById('search-queries').textContent = metrics.metrics.search_queries || 0;
                            document.getElementById('websocket-connections').textContent = metrics.metrics.websocket_connections || 0;
                            document.getElementById('avg-response-time').textContent =
                                (metrics.avg_response_time ? Math.round(metrics.avg_response_time * 1000) + 'ms' : '0ms');
                        }}
                    }} catch (error) {{
                        console.error('Failed to update performance metrics:', error);
                    }}
                }}

                // Initialize and start periodic updates
                connectWebSocket();

                // Update performance metrics every 5 seconds
                setInterval(updatePerformanceMetrics, 5000);
                updatePerformanceMetrics(); // Initial load

                // Demo updates
                setInterval(() => {{
                    const messages = [
                        '[BUILD] Modular components operating normally',
                        '[CHART] API router processing requests',
                        '[CONNECT] WebSocket manager active',
                        '[FAST] Configuration loaded successfully'
                    ];
                    addLiveUpdate(messages[Math.floor(Math.random() * messages.length)]);
                }}, 15000);
            </script>
        </body>
        </html>
        """

    return router
