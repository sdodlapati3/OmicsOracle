/**
 * Futuristic Interface JavaScript
 *
 * Advanced client-side functionality for the next-generation OmicsOracle interface
 * Features:
 * - Real-time WebSocket communication
 * - Dynamic visualization updates
 * - Intelligent search with agent feedback
 * - Fallback to legacy system
 */

class FuturisticInterface {
    constructor() {
        this.websocket = null;
        this.clientId = this.generateClientId();
        this.currentJob = null;
        this.isConnected = false;
        this.fallbackMode = false;
        this.searchHistory = [];

        // Chart.js instances
        this.charts = new Map();

        // Initialize interface
        this.init();
    }

    generateClientId() {
        return 'client_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
    }

    init() {
        console.log('[LAUNCH] Initializing Futuristic Interface');

        // Setup event listeners
        this.setupEventListeners();

        // Connect WebSocket
        this.connectWebSocket();

        // Setup UI components
        this.setupUI();

        // Check system status
        this.checkSystemStatus();
    }

    setupEventListeners() {
        // Search button
        const searchBtn = document.getElementById('search-btn');
        if (searchBtn) {
            searchBtn.addEventListener('click', () => this.performSearch());
        }

        // Fallback button
        const fallbackBtn = document.getElementById('fallback-btn');
        if (fallbackBtn) {
            fallbackBtn.addEventListener('click', () => this.performFallbackSearch());
        }

        // Search input (Enter key)
        const searchInput = document.getElementById('smart-search');
        if (searchInput) {
            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.performSearch();
                }
            });

            // Real-time search suggestions (debounced)
            searchInput.addEventListener('input', this.debounce((e) => {
                this.getSearchSuggestions(e.target.value);
            }, 300));
        }
    }

    connectWebSocket() {
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/ws/${this.clientId}`;

        console.log('[CONNECT] Connecting to WebSocket:', wsUrl);

        try {
            this.websocket = new WebSocket(wsUrl);

            this.websocket.onopen = (event) => {
                console.log('[OK] WebSocket connected');
                this.isConnected = true;
                this.updateConnectionStatus(true);
            };

            this.websocket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleWebSocketMessage(data);
                } catch (error) {
                    console.error('[ERROR] Error parsing WebSocket message:', error);
                }
            };

            this.websocket.onclose = (event) => {
                console.log('[CONNECT] WebSocket disconnected');
                this.isConnected = false;
                this.updateConnectionStatus(false);

                // Attempt to reconnect after delay
                setTimeout(() => {
                    console.log('[REFRESH] Attempting to reconnect...');
                    this.connectWebSocket();
                }, 3000);
            };

            this.websocket.onerror = (error) => {
                console.error('[ERROR] WebSocket error:', error);
                this.fallbackMode = true;
                this.updateConnectionStatus(false);
            };

        } catch (error) {
            console.error('[ERROR] Failed to create WebSocket connection:', error);
            this.fallbackMode = true;
            this.updateConnectionStatus(false);
        }
    }

    handleWebSocketMessage(data) {
        console.log('[MESSAGE] WebSocket message:', data.type);

        switch (data.type) {
            case 'connection_established':
                this.handleConnectionEstablished(data);
                break;
            case 'search_started':
                this.handleSearchStarted(data);
                break;
            case 'search_results':
                this.handleSearchResults(data);
                break;
            case 'job_progress':
                this.handleJobProgress(data);
                break;
            case 'agent_status_update':
                this.handleAgentStatusUpdate(data);
                break;
            case 'visualization_update':
                this.handleVisualizationUpdate(data);
                break;
            case 'error_notification':
                this.handleErrorNotification(data);
                break;
            case 'system_notification':
                this.handleSystemNotification(data);
                break;
            default:
                console.log('[INFO] Unknown message type:', data.type);
        }
    }

    handleConnectionEstablished(data) {
        console.log('[SUCCESS] Connection established with capabilities:', data.capabilities);
        this.showNotification('Connected to AI-powered research platform', 'success');
        this.updateAgentStatus();
    }

    handleSearchStarted(data) {
        this.currentJob = data.job_id;
        this.showSearchProgress(0, 'AI agents are processing your search...');
        this.addToSearchHistory(data);
    }

    handleSearchResults(data) {
        this.displaySearchResults(data.results);
        this.showSearchProgress(100, 'Search complete');

        // Hide progress after delay
        setTimeout(() => {
            this.hideSearchProgress();
        }, 2000);
    }

    handleJobProgress(data) {
        if (data.job_id === this.currentJob) {
            this.showSearchProgress(data.progress, `Processing... ${Math.round(data.progress)}%`);
        }
    }

    handleAgentStatusUpdate(data) {
        this.updateAgentDisplay(data.agent_id, data.status);
    }

    handleVisualizationUpdate(data) {
        this.renderVisualization(data.visualization);
    }

    handleErrorNotification(data) {
        this.showNotification(data.message, 'error');
        console.error('[ALERT] Error notification:', data.message);
    }

    handleSystemNotification(data) {
        this.showNotification(data.message, data.level || 'info');
    }

    sendWebSocketMessage(message) {
        if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
            this.websocket.send(JSON.stringify(message));
            return true;
        }
        return false;
    }

    async performSearch() {
        const searchInput = document.getElementById('smart-search');
        const query = searchInput.value.trim();

        if (!query) {
            this.showNotification('Please enter a search query', 'warning');
            return;
        }

        console.log('[SEARCH] Performing AI search:', query);

        if (this.isConnected && !this.fallbackMode) {
            // Use WebSocket for real-time search
            const searchMessage = {
                type: 'search',
                query: query,
                search_type: 'intelligent',
                filters: {},
                timestamp: new Date().toISOString()
            };

            if (this.sendWebSocketMessage(searchMessage)) {
                this.showSearchProgress(5, 'Initializing AI search...');
                return;
            }
        }

        // Fallback to HTTP API
        await this.performFallbackSearch();
    }

    async performFallbackSearch() {
        const searchInput = document.getElementById('smart-search');
        const query = searchInput.value.trim();

        if (!query) {
            this.showNotification('Please enter a search query', 'warning');
            return;
        }

        console.log('[SECURITY] Performing fallback search:', query);
        this.showSearchProgress(10, 'Using legacy search system...');

        try {
            const response = await fetch('/api/v2/search', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    query: query,
                    search_type: 'basic',
                    filters: {},
                    max_results: 50
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const data = await response.json();

            if (data.status === 'processing') {
                // Poll for results
                this.pollForResults(data.job_id);
            } else if (data.results) {
                this.displaySearchResults(data.results);
                this.showSearchProgress(100, 'Search complete (legacy mode)');
            }

        } catch (error) {
            console.error('[ERROR] Fallback search failed:', error);
            this.showNotification('Search failed. Please try again.', 'error');
            this.hideSearchProgress();
        }
    }

    async pollForResults(jobId, maxAttempts = 30) {
        let attempts = 0;

        const poll = async () => {
            try {
                const response = await fetch(`/api/v2/search/${jobId}`);
                const data = await response.json();

                if (data.results) {
                    this.displaySearchResults(data.results);
                    this.showSearchProgress(100, `Search complete (${data.mode || 'legacy'} mode)`);
                    return;
                }

                attempts++;
                if (attempts < maxAttempts) {
                    this.showSearchProgress(30 + (attempts * 2), `Processing... (${attempts}/${maxAttempts})`);
                    setTimeout(poll, 1000); // Poll every second
                } else {
                    this.showNotification('Search timeout. Please try again.', 'warning');
                    this.hideSearchProgress();
                }

            } catch (error) {
                console.error('[ERROR] Error polling for results:', error);
                this.showNotification('Error retrieving results', 'error');
                this.hideSearchProgress();
            }
        };

        setTimeout(poll, 1000); // Start polling after 1 second
    }

    displaySearchResults(results) {
        const container = document.getElementById('live-results');
        if (!container) return;

        container.innerHTML = '';

        if (!results || results.length === 0) {
            container.innerHTML = `
                <div class="text-gray-300 text-center py-8">
                    <div class="text-4xl mb-4">[SEARCH]</div>
                    <div>No results found</div>
                </div>
            `;
            return;
        }

        results.forEach((result, index) => {
            const resultElement = document.createElement('div');
            resultElement.className = 'bg-white/10 rounded-lg p-4 mb-4 backdrop-blur-sm border border-white/20';
            resultElement.innerHTML = `
                <div class="flex justify-between items-start mb-2">
                    <h3 class="text-white font-semibold text-sm leading-tight">${this.escapeHtml(result.title || 'Unknown Title')}</h3>
                    <span class="text-xs bg-blue-500/30 text-blue-200 px-2 py-1 rounded ml-2 flex-shrink-0">
                        ${Math.round((result.confidence_score || 0.8) * 100)}%
                    </span>
                </div>
                <p class="text-gray-300 text-xs mb-2 line-clamp-2">
                    ${this.escapeHtml(result.abstract || result.summary || 'No abstract available')}
                </p>
                <div class="flex flex-wrap gap-1 mb-2">
                    ${(result.tags || []).slice(0, 3).map(tag =>
                        `<span class="text-xs bg-purple-500/30 text-purple-200 px-1 py-0.5 rounded">${this.escapeHtml(tag)}</span>`
                    ).join('')}
                </div>
                <div class="text-xs text-gray-400">
                    ${(result.authors || []).slice(0, 2).join(', ')}${(result.authors || []).length > 2 ? ' et al.' : ''}
                    ${result.source ? ` * ${result.source}` : ''}
                </div>
            `;

            // Add click handler for result expansion
            resultElement.addEventListener('click', () => {
                this.showResultDetails(result);
            });

            container.appendChild(resultElement);
        });

        // Update stats
        this.updateSearchStats(results.length);
    }

    showResultDetails(result) {
        // Create modal or expanded view for result details
        console.log('[DOCUMENT] Showing details for:', result.title);

        // For now, just show a simple alert with details
        const details = `
Title: ${result.title}

Abstract: ${result.abstract || 'No abstract available'}

Authors: ${(result.authors || []).join(', ')}

Source: ${result.source || 'Unknown'}

Confidence: ${Math.round((result.confidence_score || 0.8) * 100)}%

Tags: ${(result.tags || []).join(', ')}
        `;

        alert(details);
    }

    renderVisualization(vizData) {
        const container = document.getElementById('visualization-container');
        if (!container) return;

        container.innerHTML = '';

        if (vizData.type === 'charts') {
            this.renderCharts(vizData.data.charts, container);
        } else if (vizData.type === 'network') {
            this.renderNetworkGraph(vizData.data, container);
        } else if (vizData.type === 'timeline') {
            this.renderTimeline(vizData.data, container);
        }
    }

    renderCharts(charts, container) {
        charts.forEach((chart, index) => {
            const canvas = document.createElement('canvas');
            canvas.id = `chart-${index}`;
            canvas.className = 'mb-4';
            container.appendChild(canvas);

            const ctx = canvas.getContext('2d');
            const chartInstance = new Chart(ctx, {
                type: chart.type,
                data: chart.data,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        title: {
                            display: true,
                            text: chart.title,
                            color: 'white'
                        },
                        legend: {
                            labels: {
                                color: 'white'
                            }
                        }
                    },
                    scales: {
                        x: {
                            ticks: { color: 'white' },
                            grid: { color: 'rgba(255, 255, 255, 0.1)' }
                        },
                        y: {
                            ticks: { color: 'white' },
                            grid: { color: 'rgba(255, 255, 255, 0.1)' }
                        }
                    }
                }
            });

            this.charts.set(`chart-${index}`, chartInstance);
        });
    }

    renderNetworkGraph(data, container) {
        // Simplified D3.js network graph
        const width = container.clientWidth;
        const height = 400;

        const svg = d3.select(container)
            .append('svg')
            .attr('width', width)
            .attr('height', height);

        const simulation = d3.forceSimulation(data.nodes)
            .force('link', d3.forceLink(data.links).id(d => d.id))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(width / 2, height / 2));

        const link = svg.append('g')
            .selectAll('line')
            .data(data.links)
            .enter().append('line')
            .attr('stroke', '#999')
            .attr('stroke-opacity', 0.6)
            .attr('stroke-width', d => Math.sqrt(d.value || 1));

        const node = svg.append('g')
            .selectAll('circle')
            .data(data.nodes)
            .enter().append('circle')
            .attr('r', d => Math.sqrt(d.value || 5) * 2)
            .attr('fill', d => this.getNodeColor(d.group))
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));

        node.append('title')
            .text(d => d.title);

        simulation.on('tick', () => {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            node
                .attr('cx', d => d.x)
                .attr('cy', d => d.y);
        });

        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }

        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }

        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }
    }

    getNodeColor(group) {
        const colors = {
            'covid': '#ff6b6b',
            'cancer': '#4ecdc4',
            'genetics': '#45b7d1',
            'therapeutics': '#96ceb4',
            'general': '#ffeaa7'
        };
        return colors[group] || colors.general;
    }

    showSearchProgress(progress, message) {
        // Create or update progress indicator
        let progressContainer = document.getElementById('search-progress');
        if (!progressContainer) {
            progressContainer = document.createElement('div');
            progressContainer.id = 'search-progress';
            progressContainer.className = 'fixed top-4 right-4 bg-blue-600 text-white p-4 rounded-lg shadow-lg z-50';
            document.body.appendChild(progressContainer);
        }

        progressContainer.innerHTML = `
            <div class="flex items-center space-x-3">
                <div class="animate-spin rounded-full h-6 w-6 border-b-2 border-white"></div>
                <div>
                    <div class="font-semibold">${message}</div>
                    <div class="w-48 bg-blue-800 rounded-full h-2 mt-1">
                        <div class="bg-white h-2 rounded-full transition-all duration-300" style="width: ${progress}%"></div>
                    </div>
                </div>
            </div>
        `;
    }

    hideSearchProgress() {
        const progressContainer = document.getElementById('search-progress');
        if (progressContainer) {
            progressContainer.remove();
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `fixed top-4 left-4 p-4 rounded-lg shadow-lg z-50 transition-opacity duration-300 ${this.getNotificationClass(type)}`;
        notification.innerHTML = `
            <div class="flex items-center space-x-2">
                <span class="text-lg">${this.getNotificationIcon(type)}</span>
                <span>${this.escapeHtml(message)}</span>
            </div>
        `;

        document.body.appendChild(notification);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            notification.style.opacity = '0';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 5000);
    }

    getNotificationClass(type) {
        const classes = {
            'success': 'bg-green-600 text-white',
            'error': 'bg-red-600 text-white',
            'warning': 'bg-yellow-600 text-white',
            'info': 'bg-blue-600 text-white'
        };
        return classes[type] || classes.info;
    }

    getNotificationIcon(type) {
        const icons = {
            'success': '[OK]',
            'error': '[ERROR]',
            'warning': '[WARNING]',
            'info': '[INFO]'
        };
        return icons[type] || icons.info;
    }

    updateConnectionStatus(connected) {
        const futuristicStatus = document.getElementById('futuristic-status');
        const indicator = futuristicStatus?.querySelector('.w-3');
        const text = futuristicStatus?.querySelector('span');

        if (indicator && text) {
            if (connected && !this.fallbackMode) {
                indicator.className = 'w-3 h-3 rounded-full bg-green-400 agent-pulse mr-2';
                text.textContent = 'Futuristic Mode Active';
            } else {
                indicator.className = 'w-3 h-3 rounded-full bg-red-400 mr-2';
                text.textContent = this.fallbackMode ? 'Fallback Mode Only' : 'Connecting...';
            }
        }
    }

    updateAgentStatus() {
        // Request agent status update
        if (this.isConnected) {
            this.sendWebSocketMessage({
                type: 'status',
                timestamp: new Date().toISOString()
            });
        }
    }

    updateAgentDisplay(agentId, status) {
        const agentContainer = document.getElementById('agent-status');
        if (!agentContainer) return;

        let agentElement = document.getElementById(`agent-${agentId}`);
        if (!agentElement) {
            agentElement = document.createElement('div');
            agentElement.id = `agent-${agentId}`;
            agentElement.className = 'bg-white/10 rounded-lg p-3 backdrop-blur-sm border border-white/20';
            agentContainer.appendChild(agentElement);
        }

        agentElement.innerHTML = `
            <div class="flex justify-between items-center">
                <div>
                    <div class="text-white font-medium text-sm">${agentId.replace('-', ' ').toUpperCase()}</div>
                    <div class="text-gray-300 text-xs">${status.status || 'unknown'}</div>
                </div>
                <div class="flex items-center space-x-2">
                    <div class="w-2 h-2 rounded-full ${status.is_active ? 'bg-green-400' : 'bg-gray-400'}"></div>
                    <span class="text-xs text-gray-400">${status.jobs_completed || 0} jobs</span>
                </div>
            </div>
        `;
    }

    updateSearchStats(resultCount) {
        const processedQueries = document.getElementById('processed-queries');
        if (processedQueries) {
            const current = parseInt(processedQueries.textContent) || 0;
            processedQueries.textContent = current + 1;
        }

        // Update result count display somewhere
        console.log(`[CHART] Search returned ${resultCount} results`);
    }

    async checkSystemStatus() {
        try {
            const response = await fetch('/api/v2/health');
            const data = await response.json();

            console.log('[MEDICAL] System status:', data);

            if (data.modes) {
                this.updateSystemStatus(data.modes);
            }

        } catch (error) {
            console.error('[ERROR] Failed to check system status:', error);
            this.fallbackMode = true;
            this.updateConnectionStatus(false);
        }
    }

    updateSystemStatus(modes) {
        const activeAgents = document.getElementById('active-agents');
        if (activeAgents) {
            activeAgents.textContent = modes.agents_active || 0;
        }

        if (!modes.futuristic_available) {
            this.fallbackMode = true;
            this.updateConnectionStatus(false);
        }
    }

    setupUI() {
        // Initialize any additional UI components
        console.log('[DESIGN] Setting up UI components');

        // Add responsive behavior
        this.setupResponsiveLayout();

        // Initialize empty agent status
        this.initializeAgentStatus();
    }

    setupResponsiveLayout() {
        // Add responsive behavior for mobile devices
        const handleResize = () => {
            // Adjust layout for different screen sizes
            const isMobile = window.innerWidth < 768;
            console.log(`[MOBILE] Screen size: ${window.innerWidth}px (${isMobile ? 'mobile' : 'desktop'})`);
        };

        window.addEventListener('resize', handleResize);
        handleResize(); // Initial call
    }

    initializeAgentStatus() {
        const agentContainer = document.getElementById('agent-status');
        if (!agentContainer) return;

        agentContainer.innerHTML = `
            <div class="text-gray-300 text-center py-4">
                <div class="text-2xl mb-2">[AGENT]</div>
                <div class="text-sm">Connecting to AI agents...</div>
            </div>
        `;
    }

    addToSearchHistory(searchData) {
        this.searchHistory.unshift({
            query: searchData.query || '',
            timestamp: new Date().toISOString(),
            jobId: searchData.job_id
        });

        // Keep only last 10 searches
        this.searchHistory = this.searchHistory.slice(0, 10);
    }

    async getSearchSuggestions(query) {
        if (query.length < 3) return;

        // Simple suggestion logic (could be enhanced with API call)
        const suggestions = [
            'COVID-19 vaccine efficacy',
            'cancer immunotherapy',
            'gene therapy trials',
            'biomarker discovery',
            'drug resistance mechanisms'
        ].filter(s => s.toLowerCase().includes(query.toLowerCase()));

        console.log('[IDEA] Search suggestions:', suggestions);
        // Could display these in a dropdown
    }

    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize the interface when the page loads
document.addEventListener('DOMContentLoaded', () => {
    console.log('[STAR] Starting Futuristic Interface');
    window.futuristicInterface = new FuturisticInterface();
});

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
    if (window.futuristicInterface) {
        if (document.hidden) {
            console.log('[VIEW] Page hidden - reducing activity');
        } else {
            console.log('[VIEW] Page visible - resuming activity');
            window.futuristicInterface.checkSystemStatus();
        }
    }
});
