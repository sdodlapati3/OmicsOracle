// OmicsOracle Futuristic Interface JavaScript

class FuturisticInterface {
    constructor() {
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.init();
    }

    init() {
        this.connectWebSocket();
        this.setupEventListeners();
        this.startPerformanceMonitoring();
        this.startDemoUpdates();
    }

    // WebSocket Management
    connectWebSocket() {
        try {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            this.ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

            this.ws.onopen = () => {
                this.updateConnectionStatus('[GREEN] Connected', 'success');
                this.addLiveUpdate('[CONNECT] WebSocket connected - Real-time updates active');
                this.loadAgentStatus();
                this.reconnectAttempts = 0;
            };

            this.ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleWebSocketMessage(data);
                } catch (error) {
                    console.error('Error parsing WebSocket message:', error);
                }
            };

            this.ws.onclose = () => {
                this.updateConnectionStatus('[RED] Disconnected', 'error');
                this.scheduleReconnect();
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateConnectionStatus('[WARNING] Error', 'warning');
            };

        } catch (error) {
            console.error('Failed to create WebSocket connection:', error);
            this.updateConnectionStatus('[ERROR] Failed', 'error');
        }
    }

    scheduleReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);

            this.updateConnectionStatus(`[REFRESH] Reconnecting in ${delay/1000}s...`, 'warning');
            setTimeout(() => this.connectWebSocket(), delay);
        } else {
            this.updateConnectionStatus('[ERROR] Connection failed', 'error');
        }
    }

    updateConnectionStatus(message, type) {
        const statusElement = document.getElementById('ws-status');
        if (statusElement) {
            statusElement.innerHTML = message;
            statusElement.className = `websocket-status status-${type}`;
        }
    }

    handleWebSocketMessage(data) {
        this.addLiveUpdate(`[MESSAGE] ${data.message || data.status || 'Update received'}`);

        // Handle specific message types
        if (data.type === 'agent_update') {
            this.updateAgentStatus(data.agent_id, data.status);
        } else if (data.type === 'visualization_update') {
            this.updateVisualization(data.viz_id, data.data);
        }
    }

    // Agent Management
    async loadAgentStatus() {
        try {
            const response = await fetch('/api/agents');
            const data = await response.json();
            this.displayAgentStatus(data.agents || []);
        } catch (error) {
            console.error('Failed to load agent status:', error);
            this.showError('Failed to load agent status');
        }
    }

    displayAgentStatus(agents) {
        const container = document.getElementById('agent-status-container');
        if (!container) return;

        container.innerHTML = '';

        agents.forEach(agent => {
            const div = document.createElement('div');
            div.className = 'agent-status';
            div.innerHTML = `
                <div class="status-indicator"></div>
                <span>${agent.name} - ${agent.status}</span>
            `;
            container.appendChild(div);
        });
    }

    updateAgentStatus(agentId, status) {
        // Update specific agent status in real-time
        const container = document.getElementById('agent-status-container');
        if (container) {
            const agentElements = container.querySelectorAll('.agent-status');
            // Find and update the specific agent
            // Implementation would depend on agent ID tracking
        }
    }

    // Search Functionality
    async performSearch() {
        const query = document.getElementById('search-input')?.value;
        if (!query) return;

        const resultsDiv = document.getElementById('search-results');
        if (!resultsDiv) return;

        resultsDiv.innerHTML = '<p class="loading">[SEARCH] Searching with AI agents...</p>';

        try {
            const response = await fetch('/api/search', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    query: query,
                    search_type: 'enhanced'
                })
            });

            const data = await response.json();
            this.displaySearchResults(data.results || []);

        } catch (error) {
            console.error('Search error:', error);
            resultsDiv.innerHTML = '<p class="error">[ERROR] Search error. Please try again.</p>';
        }
    }

    displaySearchResults(results) {
        const resultsDiv = document.getElementById('search-results');
        if (!resultsDiv) return;

        if (results.length === 0) {
            resultsDiv.innerHTML = '<p>No results found.</p>';
            return;
        }

        let html = '<h4>[CLIPBOARD] Search Results:</h4>';
        results.forEach(result => {
            html += `
                <div class="result-item">
                    <strong>${this.escapeHtml(result.title)}</strong><br>
                    <small>Source: ${this.escapeHtml(result.source)} | Score: ${result.relevance_score}</small><br>
                    ${this.escapeHtml(result.description)}
                </div>
            `;
        });
        resultsDiv.innerHTML = html;
    }

    // Visualization Functions
    async createDemoVisualization(type) {
        const container = document.getElementById('visualization-container');
        if (!container) return;

        container.innerHTML = '<div style="padding: 20px; text-align: center;"><p class="loading">[REFRESH] Creating ' + type + ' visualization...</p></div>';

        try {
            const response = await fetch('/api/visualize', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    type: type,
                    title: 'Demo ' + type.replace('_', ' ').toUpperCase(),
                    data: this.getDemoData(type)
                })
            });

            const result = await response.json();

            if (result.status === 'success') {
                this.displayVisualization(result.visualization);
            } else {
                container.innerHTML = `<div class="error">[ERROR] Error creating visualization: ${result.message || 'Unknown error'}</div>`;
            }

        } catch (error) {
            console.error('Visualization error:', error);
            container.innerHTML = `<div class="error">[ERROR] Network error: ${error.message}</div>`;
        }
    }

    getDemoData(type) {
        switch(type) {
            case 'scatter_plot':
                return {
                    points: Array.from({length: 50}, (_, i) => ({
                        x: Math.random() * 100,
                        y: Math.random() * 100,
                        label: 'Point ' + i,
                        size: Math.random() * 10 + 5
                    }))
                };
            case 'network_graph':
                const nodes = Array.from({length: 10}, (_, i) => ({
                    id: 'node_' + i,
                    label: 'Node ' + i,
                    group: Math.floor(Math.random() * 3) + 1
                }));
                const edges = Array.from({length: 15}, () => {
                    const source = nodes[Math.floor(Math.random() * nodes.length)].id;
                    const target = nodes[Math.floor(Math.random() * nodes.length)].id;
                    return { source, target, weight: Math.random() };
                });
                return { nodes, edges };
            case 'volcano_plot':
                return {
                    fold_changes: Array.from({length: 100}, () => Math.random() * 10 - 5),
                    p_values: Array.from({length: 100}, () => Math.random() * 0.1),
                    gene_names: Array.from({length: 100}, (_, i) => 'Gene_' + i)
                };
            case 'heatmap':
                return {
                    matrix: Array.from({length: 10}, () => Array.from({length: 15}, () => Math.random() * 4 - 2)),
                    row_labels: Array.from({length: 10}, (_, i) => 'Gene_' + i),
                    col_labels: Array.from({length: 15}, (_, i) => 'Sample_' + i)
                };
            default:
                return {};
        }
    }

    displayVisualization(vizData) {
        const container = document.getElementById('visualization-container');
        if (!container) return;

        let content = '<div style="padding: 20px;">';
        content += '<h4 style="margin-bottom: 15px;">[CHART] ' + this.escapeHtml(vizData.config?.title || 'Visualization') + '</h4>';
        content += '<div style="background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; font-family: monospace; font-size: 12px;">';
        content += '<strong>Type:</strong> ' + this.escapeHtml(vizData.type) + '<br>';
        content += '<strong>ID:</strong> ' + this.escapeHtml(vizData.id) + '<br>';
        content += '<strong>Data Points:</strong> ' + (vizData.data?.length || 'N/A') + '<br>';
        content += '<strong>Created:</strong> ' + new Date(vizData.timestamp).toLocaleString() + '<br>';

        if (vizData.type === 'network') {
            content += '<strong>Nodes:</strong> ' + (vizData.nodes?.length || 0) + '<br>';
            content += '<strong>Edges:</strong> ' + (vizData.edges?.length || 0) + '<br>';
        }

        content += '</div>';
        content += '<div class="success" style="margin-top: 15px;">';
        content += '[OK] Visualization created successfully! In a full implementation, this would render an interactive chart using D3.js or similar.';
        content += '</div>';
        content += '</div>';

        container.innerHTML = content;

        this.addLiveUpdate('[CHART] Created ' + vizData.type + ' visualization: ' + (vizData.config?.title || 'Untitled'));
    }

    // Performance Monitoring
    async updatePerformanceMetrics() {
        try {
            const response = await fetch('/api/performance');
            const metrics = await response.json();

            if (metrics && metrics.metrics) {
                this.updateMetric('api-requests', metrics.metrics.api_requests || 0);
                this.updateMetric('search-queries', metrics.metrics.search_queries || 0);
                this.updateMetric('websocket-connections', metrics.metrics.websocket_connections || 0);
                this.updateMetric('avg-response-time',
                    metrics.avg_response_time ? Math.round(metrics.avg_response_time * 1000) + 'ms' : '0ms');
            }
        } catch (error) {
            console.error('Failed to update performance metrics:', error);
        }
    }

    updateMetric(id, value) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    }

    startPerformanceMonitoring() {
        // Update performance metrics every 5 seconds
        setInterval(() => this.updatePerformanceMetrics(), 5000);
        this.updatePerformanceMetrics(); // Initial load
    }

    // Live Updates
    addLiveUpdate(message) {
        const updates = document.getElementById('live-updates');
        if (!updates) return;

        const div = document.createElement('div');
        div.style.cssText = 'margin: 5px 0; padding: 8px; background: rgba(255,255,255,0.1); border-radius: 5px; font-size: 13px;';
        div.innerHTML = `${new Date().toLocaleTimeString()} - ${this.escapeHtml(message)}`;
        updates.insertBefore(div, updates.firstChild);

        // Keep only last 5 updates
        while (updates.children.length > 5) {
            updates.removeChild(updates.lastChild);
        }
    }

    startDemoUpdates() {
        // Demo updates every 15 seconds
        setInterval(() => {
            const messages = [
                '[BUILD] Modular components operating normally',
                '[CHART] API router processing requests',
                '[CONNECT] WebSocket manager active',
                '[FAST] Configuration loaded successfully'
            ];
            this.addLiveUpdate(messages[Math.floor(Math.random() * messages.length)]);
        }, 15000);
    }

    // Event Listeners
    setupEventListeners() {
        // Search on Enter key
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.performSearch();
                }
            });
        }

        // Visualization buttons
        const vizButtons = document.querySelectorAll('[onclick*="createDemoVisualization"]');
        vizButtons.forEach(button => {
            const type = button.getAttribute('onclick').match(/'([^']+)'/)[1];
            button.addEventListener('click', (e) => {
                e.preventDefault();
                this.createDemoVisualization(type);
            });
            // Remove inline onclick
            button.removeAttribute('onclick');
        });

        // Search button
        const searchButton = document.querySelector('[onclick="performSearch()"]');
        if (searchButton) {
            searchButton.addEventListener('click', (e) => {
                e.preventDefault();
                this.performSearch();
            });
            searchButton.removeAttribute('onclick');
        }
    }

    // Utility Functions
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    showError(message) {
        this.addLiveUpdate(`[ERROR] Error: ${message}`);
    }

    showSuccess(message) {
        this.addLiveUpdate(`[OK] ${message}`);
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.futuristicInterface = new FuturisticInterface();
});

// Global functions for backward compatibility (if needed)
window.createDemoVisualization = (type) => {
    if (window.futuristicInterface) {
        window.futuristicInterface.createDemoVisualization(type);
    }
};

window.performSearch = () => {
    if (window.futuristicInterface) {
        window.futuristicInterface.performSearch();
    }
};
