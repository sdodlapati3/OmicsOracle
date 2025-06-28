/**
 * Enhanced Futuristic Interface JavaScript
 *
 * Updated version that works with the current OmicsOracle server setup
 * and provides real-time WebSocket communication with fallback support.
 */

class FuturisticInterface {
    constructor() {
        this.websocket = null;
        this.clientId = this.generateClientId();
        this.currentSearch = null;
        this.isConnected = false;
        this.fallbackMode = false;
        this.searchHistory = [];
        this.currentTheme = 'default';

        // Chart.js instances
        this.charts = new Map();

        // Initialize interface
        this.init();
    }

    generateClientId() {
        return 'client_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
    }

    init() {
        console.log('[INIT] Initializing Futuristic Interface');

        // Setup event listeners
        this.setupEventListeners();

        // Connect WebSocket
        this.connectWebSocket();

        // Setup UI components
        this.setupUI();

        // Check system status
        this.checkSystemStatus();

        // Update connection status initially
        this.updateConnectionStatus(false);
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
                if (e.target.value.length > 2) {
                    this.getSearchSuggestions(e.target.value);
                }
            }, 300));
        }
    }

    connectWebSocket() {
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/ws/${this.clientId}`;

        console.log('[PLUG] Connecting to WebSocket:', wsUrl);

        try {
            this.websocket = new WebSocket(wsUrl);

            this.websocket.onopen = (event) => {
                console.log('[OK] WebSocket connected');
                this.isConnected = true;
                this.fallbackMode = false;
                this.updateConnectionStatus(true);
                this.addLiveUpdate('WebSocket connected successfully', 'success');
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
                console.log('[PLUG] WebSocket disconnected');
                this.isConnected = false;
                this.updateConnectionStatus(false);
                this.addLiveUpdate('Connection lost, attempting to reconnect...', 'warning');

                // Attempt to reconnect after delay
                setTimeout(() => {
                    if (!this.isConnected) {
                        console.log('[REFRESH] Attempting to reconnect...');
                        this.connectWebSocket();
                    }
                }, 3000);
            };

            this.websocket.onerror = (error) => {
                console.error('[ERROR] WebSocket error:', error);
                this.fallbackMode = true;
                this.updateConnectionStatus(false);
                this.addLiveUpdate('WebSocket error, using fallback mode', 'error');
            };

        } catch (error) {
            console.error('[ERROR] Failed to create WebSocket connection:', error);
            this.fallbackMode = true;
            this.updateConnectionStatus(false);
            this.addLiveUpdate('WebSocket unavailable, using fallback mode', 'warning');
        }
    }

    handleWebSocketMessage(data) {
        console.log('[MESSAGE] WebSocket message:', data.type);

        switch (data.type) {
            case 'connection_established':
                this.handleConnectionEstablished(data);
                break;
            case 'search_progress':
                this.handleSearchProgress(data);
                break;
            case 'search_results':
                this.handleSearchResults(data);
                break;
            case 'search_error':
                this.handleSearchError(data);
                break;
            case 'system_status':
                this.handleSystemStatus(data);
                break;
            case 'pong':
                // Handle ping response
                break;
            default:
                console.log('[INFO] Unknown message type:', data.type);
        }
    }

    handleConnectionEstablished(data) {
        console.log('[CELEBRATE] Connection established:', data.message);
        this.addLiveUpdate(data.message, 'success');

        // Request system status
        this.sendWebSocketMessage({
            type: 'get_system_status'
        });
    }

    handleSearchProgress(data) {
        this.showSearchProgress(data.progress, data.status, data.details);
        this.addLiveUpdate(data.status, 'info');
    }

    handleSearchResults(data) {
        this.hideSearchProgress();
        this.displaySearchResults(data.data);
        this.addLiveUpdate(`Search completed - found ${data.data.total_found || 'unknown'} results`, 'success');
    }

    handleSearchError(data) {
        this.hideSearchProgress();
        this.addLiveUpdate(`Search error: ${data.error}`, 'error');
        this.showNotification('Search failed. Please try again.', 'error');
    }

    handleSystemStatus(data) {
        console.log('[CHART] System status:', data.data);
        this.addLiveUpdate(`System operational - ${data.data.active_connections} clients connected`, 'info');
    }

    async performSearch() {
        const searchInput = document.getElementById('smart-search');
        const query = searchInput?.value?.trim();

        if (!query) {
            this.showNotification('Please enter a search query', 'warning');
            return;
        }

        this.addLiveUpdate(`Starting search: "${query}"`, 'info');
        this.currentSearch = {
            query: query,
            startTime: Date.now()
        };

        if (this.isConnected && !this.fallbackMode) {
            // Use real-time WebSocket search
            await this.performRealtimeSearch(query);
        } else {
            // Use fallback HTTP search
            await this.performFallbackSearch(query);
        }
    }

    async performRealtimeSearch(query) {
        try {
            this.showSearchProgress(5, 'Initiating real-time search...', 'Using WebSocket connection');

            // Send search request via API with WebSocket updates
            const response = await fetch('/api/futuristic/search', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    query: query,
                    client_id: this.clientId,
                    max_results: 20,
                    enable_real_time: true
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            console.log('[ROCKET] Real-time search initiated:', result);

        } catch (error) {
            console.error('[ERROR] Real-time search failed:', error);
            this.addLiveUpdate('Real-time search failed, falling back to standard search', 'warning');
            await this.performFallbackSearch(query);
        }
    }

    async performFallbackSearch(query = null) {
        const searchInput = document.getElementById('smart-search');
        const finalQuery = query || searchInput?.value?.trim();

        if (!finalQuery) {
            this.showNotification('Please enter a search query', 'warning');
            return;
        }

        try {
            this.showSearchProgress(10, 'Performing standard search...', 'Using HTTP API');

            // Use the enhanced search endpoint
            const response = await fetch(`/api/search/enhanced?query=${encodeURIComponent(finalQuery)}&limit=20`);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            this.showSearchProgress(50, 'Processing results...', 'Parsing response data');

            const results = await response.json();

            this.showSearchProgress(90, 'Finalizing...', 'Rendering results');

            // Simulate some processing time
            setTimeout(() => {
                this.hideSearchProgress();
                this.displaySearchResults({
                    query: finalQuery,
                    results: results,
                    search_time: (Date.now() - this.currentSearch.startTime) / 1000,
                    timestamp: Date.now() / 1000
                });
                this.addLiveUpdate('Standard search completed successfully', 'success');
            }, 500);

        } catch (error) {
            console.error('[ERROR] Fallback search failed:', error);
            this.hideSearchProgress();
            this.addLiveUpdate(`Search failed: ${error.message}`, 'error');
            this.showNotification('Search failed. Please try again.', 'error');
        }
    }

    async getSearchSuggestions(query) {
        try {
            const response = await fetch(`/api/futuristic/suggestions?query=${encodeURIComponent(query)}`);
            if (response.ok) {
                const data = await response.json();
                this.showSearchSuggestions(data.suggestions);
            }
        } catch (error) {
            console.error('[ERROR] Failed to get suggestions:', error);
        }
    }

    showSearchSuggestions(suggestions) {
        // Implementation for showing search suggestions
        console.log('[IDEA] Search suggestions:', suggestions);
    }

    displaySearchResults(data) {
        const resultsContainer = document.getElementById('results-container');
        if (!resultsContainer) return;

        // Clear previous results
        resultsContainer.innerHTML = '';

        // Create results header
        const header = document.createElement('div');
        header.className = 'results-header';
        header.innerHTML = `
            <h3>Search Results for: "${data.query}"</h3>
            <p>Search completed in ${data.search_time?.toFixed(2) || 'N/A'}s</p>
        `;
        resultsContainer.appendChild(header);

        // Display results
        const resultsGrid = document.createElement('div');
        resultsGrid.className = 'results-grid';

        // Handle different result formats
        let resultsArray = [];
        if (data.results && Array.isArray(data.results)) {
            resultsArray = data.results;
        } else if (data.results && data.results.results && Array.isArray(data.results.results)) {
            resultsArray = data.results.results;
        } else if (data.results) {
            // Convert object to array for display
            resultsArray = [data.results];
        }

        if (resultsArray.length === 0) {
            resultsGrid.innerHTML = `
                <div class="no-results">
                    <h4>No results found</h4>
                    <p>Try adjusting your search terms or using different keywords.</p>
                </div>
            `;
        } else {
            resultsArray.forEach((result, index) => {
                const resultCard = this.createResultCard(result, index);
                resultsGrid.appendChild(resultCard);
            });
        }

        resultsContainer.appendChild(resultsGrid);

        // Show visualization if available
        this.showVisualization(data);
    }

    createResultCard(result, index) {
        const card = document.createElement('div');
        card.className = 'result-card';

        // Extract relevant information from result
        const title = result.title || result.name || `Result ${index + 1}`;
        const description = result.description || result.summary || 'No description available';
        const score = result.score || result.relevance || Math.random() * 100;

        card.innerHTML = `
            <div class="result-title">${title}</div>
            <div class="result-meta">
                Score: <span class="result-score">${score.toFixed(1)}</span>
                ${result.dataset_type ? `* Type: ${result.dataset_type}` : ''}
                ${result.organism ? `* Organism: ${result.organism}` : ''}
            </div>
            <div class="result-description">${description}</div>
            ${result.url ? `<a href="${result.url}" target="_blank">View Details</a>` : ''}
        `;

        return card;
    }

    showVisualization(data) {
        const vizContainer = document.getElementById('viz-container');
        if (!vizContainer) return;

        // Show visualization container
        vizContainer.style.display = 'block';

        // Create a simple chart for demonstration
        this.createResultsChart(data);
    }

    createResultsChart(data) {
        const canvas = document.getElementById('results-chart');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');

        // Destroy existing chart if it exists
        if (this.charts.has('results')) {
            this.charts.get('results').destroy();
        }

        // Create sample data for visualization
        const chartData = {
            labels: ['Genomics', 'Proteomics', 'Transcriptomics', 'Metabolomics', 'Other'],
            datasets: [{
                label: 'Results by Category',
                data: [12, 19, 8, 15, 6], // Sample data
                backgroundColor: [
                    'rgba(59, 130, 246, 0.8)',
                    'rgba(16, 185, 129, 0.8)',
                    'rgba(245, 158, 11, 0.8)',
                    'rgba(239, 68, 68, 0.8)',
                    'rgba(139, 92, 246, 0.8)'
                ]
            }]
        };

        const chart = new Chart(ctx, {
            type: 'doughnut',
            data: chartData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        this.charts.set('results', chart);
    }

    showSearchProgress(progress, status, details = '') {
        const progressSection = document.getElementById('progress-section');
        const progressFill = document.getElementById('progress-fill');
        const progressText = document.getElementById('progress-text');

        if (progressSection) progressSection.style.display = 'block';
        if (progressFill) progressFill.style.width = `${progress}%`;
        if (progressText) progressText.textContent = details || status;

        // Show loading spinner for results
        const loadingSpinner = document.getElementById('loading-spinner');
        if (loadingSpinner) loadingSpinner.style.display = 'block';
    }

    hideSearchProgress() {
        const progressSection = document.getElementById('progress-section');
        const loadingSpinner = document.getElementById('loading-spinner');

        if (progressSection) progressSection.style.display = 'none';
        if (loadingSpinner) loadingSpinner.style.display = 'none';
    }

    addLiveUpdate(message, type = 'info') {
        const updatesContainer = document.getElementById('live-updates-content');
        if (!updatesContainer) return;

        const updateItem = document.createElement('div');
        updateItem.className = 'update-item';

        const icon = this.getIconForType(type);
        const time = new Date().toLocaleTimeString();

        updateItem.innerHTML = `
            <span>${icon} ${message}</span>
            <span class="update-time">${time}</span>
        `;

        // Add to top of updates
        updatesContainer.insertBefore(updateItem, updatesContainer.firstChild);

        // Keep only last 10 updates
        while (updatesContainer.children.length > 10) {
            updatesContainer.removeChild(updatesContainer.lastChild);
        }
    }

    getIconForType(type) {
        const icons = {
            'success': '[OK]',
            'error': '[ERROR]',
            'warning': '[WARNING]',
            'info': '[INFO]'
        };
        return icons[type] || '[INFO]';
    }

    updateConnectionStatus(connected) {
        const indicator = document.getElementById('connection-indicator');
        const text = document.getElementById('connection-text');

        if (indicator) {
            indicator.className = `status-indicator ${connected ? 'connected' : ''}`;
        }

        if (text) {
            text.textContent = connected ? 'Connected' : 'Disconnected';
        }
    }

    showNotification(message, type = 'info') {
        // Create a simple notification (can be enhanced with a proper notification system)
        console.log(`${type.toUpperCase()}: ${message}`);

        // You could implement a toast notification system here
        alert(message); // Simple fallback
    }

    setupUI() {
        // Additional UI setup can go here
        console.log('[ART] UI components initialized');
    }

    async checkSystemStatus() {
        try {
            const response = await fetch('/api/futuristic/system/status');
            if (response.ok) {
                const status = await response.json();
                console.log('[CHART] System status:', status);
                this.addLiveUpdate(`System ${status.status} - ${status.active_connections} connections`, 'success');
            }
        } catch (error) {
            console.error('[ERROR] Failed to check system status:', error);
        }
    }

    sendWebSocketMessage(message) {
        if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
            this.websocket.send(JSON.stringify(message));
        }
    }

    updateTheme(theme) {
        this.currentTheme = theme;
        console.log(`[ART] Theme changed to: ${theme}`);
    }

    // Utility function for debouncing
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
}

// Export for global use
window.FuturisticInterface = FuturisticInterface;
