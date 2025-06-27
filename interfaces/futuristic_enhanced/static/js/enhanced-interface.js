/**
 * Enhanced Futuristic Interface JavaScript
 * 
 * Advanced client-side functionality for the next-generation OmicsOracle interface
 * Features:
 * - Clean Architecture backend integration
 * - Enhanced real-time WebSocket communication
 * - Advanced visualization capabilities
 * - Intelligent search with v2 API features
 * - Comprehensive error handling and fallback mechanisms
 */

class EnhancedFuturisticInterface {
    constructor() {
        this.websocket = null;
        this.clientId = this.generateClientId();
        this.currentJob = null;
        this.isConnected = false;
        this.backendUrl = this.detectBackendUrl();
        this.searchHistory = [];
        this.retryCount = 0;
        this.maxRetries = 3;

        // Chart.js instances for visualizations
        this.charts = new Map();
        
        // API configuration
        this.apiConfig = {
            baseUrl: window.location.origin,
            timeout: 30000,
            retryDelay: 1000
        };

        // Initialize enhanced interface
        this.init();
    }

    generateClientId() {
        return 'enhanced_client_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
    }

    detectBackendUrl() {
        // Auto-detect backend URL based on environment
        const hostname = window.location.hostname;
        const protocol = window.location.protocol;
        
        if (hostname === 'localhost' || hostname === '127.0.0.1') {
            return `${protocol}//${hostname}:8000`;
        }
        return `${protocol}//${hostname}`;
    }

    async init() {
        console.log('[🚀 ENHANCED] Initializing Enhanced Futuristic Interface');
        console.log(`[🔗 CONNECTION] Backend URL: ${this.backendUrl}`);

        try {
            // Setup UI components first
            this.setupUI();
            
            // Setup event listeners
            this.setupEventListeners();
            
            // Connect WebSocket
            await this.connectWebSocket();
            
            // Check system status
            await this.checkSystemStatus();
            
            // Initialize enhanced features
            this.initEnhancedFeatures();
            
            console.log('[✅ SUCCESS] Enhanced interface initialization complete');
        } catch (error) {
            console.error('[❌ ERROR] Failed to initialize interface:', error);
            this.showError('Failed to initialize interface', error.message);
        }
    }

    setupUI() {
        // Enhanced status indicators
        this.updateStatus('backend-status', 'checking', 'Backend: Checking...');
        this.updateStatus('websocket-status', 'connecting', 'WebSocket: Connecting...');
        
        // Setup enhanced search form
        this.setupSearchForm();
        
        // Setup system monitoring
        this.setupSystemMonitoring();
    }

    setupSearchForm() {
        const searchInput = document.getElementById('search-input');
        const searchBtn = document.getElementById('search-btn');
        const searchType = document.getElementById('search-type');
        const includeMetadata = document.getElementById('include-metadata');

        if (searchInput) {
            // Enhanced search input with autocomplete and validation
            searchInput.addEventListener('input', this.debounce((e) => {
                this.validateSearchInput(e.target.value);
            }, 300));

            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.performEnhancedSearch();
                }
            });
        }

        if (searchBtn) {
            searchBtn.addEventListener('click', () => this.performEnhancedSearch());
        }
    }

    setupEventListeners() {
        // Window events
        window.addEventListener('beforeunload', () => {
            this.cleanup();
        });

        // Visibility change for connection management
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.handleVisibilityHidden();
            } else {
                this.handleVisibilityVisible();
            }
        });

        // Network status monitoring
        window.addEventListener('online', () => this.handleNetworkOnline());
        window.addEventListener('offline', () => this.handleNetworkOffline());
    }

    async connectWebSocket() {
        try {
            const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${wsProtocol}//${window.location.host}/ws/${this.clientId}`;
            
            console.log(`[📡 WEBSOCKET] Connecting to: ${wsUrl}`);
            
            this.websocket = new WebSocket(wsUrl);
            
            this.websocket.onopen = (event) => {
                console.log('[✅ WEBSOCKET] Connected successfully');
                this.isConnected = true;
                this.retryCount = 0;
                this.updateStatus('websocket-status', 'connected', 'WebSocket: Connected');
                this.startHeartbeat();
            };

            this.websocket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleWebSocketMessage(data);
                } catch (error) {
                    console.error('[❌ WEBSOCKET] Failed to parse message:', error);
                }
            };

            this.websocket.onclose = (event) => {
                console.log('[🔌 WEBSOCKET] Connection closed:', event.code, event.reason);
                this.isConnected = false;
                this.updateStatus('websocket-status', 'disconnected', 'WebSocket: Disconnected');
                this.handleWebSocketClose(event);
            };

            this.websocket.onerror = (error) => {
                console.error('[❌ WEBSOCKET] Connection error:', error);
                this.updateStatus('websocket-status', 'error', 'WebSocket: Error');
            };

        } catch (error) {
            console.error('[❌ WEBSOCKET] Failed to connect:', error);
            this.updateStatus('websocket-status', 'error', 'WebSocket: Failed');
        }
    }

    handleWebSocketMessage(data) {
        console.log('[📨 MESSAGE]', data);

        switch (data.type) {
            case 'connection_established':
                this.handleConnectionEstablished(data);
                break;
            case 'search_completed':
                this.handleSearchCompleted(data);
                break;
            case 'pong':
                this.handlePong(data);
                break;
            case 'system_update':
                this.handleSystemUpdate(data);
                break;
            case 'error':
                this.handleWebSocketError(data);
                break;
            default:
                console.log('[📋 INFO] Unknown message type:', data.type);
        }
    }

    async performEnhancedSearch() {
        const searchInput = document.getElementById('search-input');
        const searchType = document.getElementById('search-type');
        const includeMetadata = document.getElementById('include-metadata');
        const searchBtn = document.getElementById('search-btn');

        if (!searchInput?.value.trim()) {
            this.showError('Search Error', 'Please enter a search query');
            return;
        }

        const query = searchInput.value.trim();
        console.log(`[🔍 SEARCH] Enhanced search: "${query}"`);

        // Update UI for search in progress
        if (searchBtn) {
            searchBtn.textContent = 'Searching...';
            searchBtn.disabled = true;
        }

        try {
            const searchRequest = {
                query: query,
                search_type: searchType?.value || 'enhanced',
                include_metadata: includeMetadata?.checked || true,
                max_results: 20,
                filters: this.buildSearchFilters()
            };

            const response = await this.makeApiRequest('/api/v2/search/enhanced', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(searchRequest)
            });

            if (response.ok) {
                const result = await response.json();
                this.displayEnhancedResults(result);
                this.addToSearchHistory(query, result);
            } else {
                throw new Error(`Search failed: ${response.status} ${response.statusText}`);
            }

        } catch (error) {
            console.error('[❌ SEARCH] Enhanced search failed:', error);
            this.showError('Search Failed', error.message);
            await this.attemptFallbackSearch(query);
        } finally {
            // Reset search button
            if (searchBtn) {
                searchBtn.textContent = 'Search Datasets';
                searchBtn.disabled = false;
            }
        }
    }

    async makeApiRequest(endpoint, options = {}) {
        const url = `${this.apiConfig.baseUrl}${endpoint}`;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.apiConfig.timeout);

        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });
            
            clearTimeout(timeout);
            return response;
        } catch (error) {
            clearTimeout(timeout);
            
            if (error.name === 'AbortError') {
                throw new Error('Request timeout');
            }
            throw error;
        }
    }

    displayEnhancedResults(result) {
        const resultsSection = document.getElementById('results-section');
        const resultsMetadata = document.getElementById('results-metadata');
        const resultsContainer = document.getElementById('results-container');

        if (!resultsSection || !resultsContainer) {
            console.error('[❌ UI] Results containers not found');
            return;
        }

        // Show results section
        resultsSection.style.display = 'block';

        // Display metadata
        if (resultsMetadata && result.metadata) {
            resultsMetadata.innerHTML = `
                <div class="metadata-summary">
                    <div class="metadata-item">
                        <span class="metadata-label">Search Time:</span>
                        <span class="metadata-value">${result.search_time.toFixed(3)}s</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Results Found:</span>
                        <span class="metadata-value">${result.total_found}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">API Version:</span>
                        <span class="metadata-value">${result.api_version}</span>
                    </div>
                </div>
            `;
        }

        // Display results
        if (result.results && result.results.length > 0) {
            resultsContainer.innerHTML = result.results.map((dataset, index) => 
                this.renderEnhancedDatasetCard(dataset, index)
            ).join('');
        } else {
            resultsContainer.innerHTML = `
                <div class="no-results">
                    <h3>No datasets found</h3>
                    <p>Try adjusting your search query or filters</p>
                </div>
            `;
        }

        // Add interaction handlers
        this.setupResultsInteraction();
    }

    renderEnhancedDatasetCard(dataset, index) {
        return `
            <div class="result-card enhanced" data-index="${index}">
                <div class="result-header">
                    <h3 class="result-title">${this.escapeHtml(dataset.title || 'Untitled Dataset')}</h3>
                    <div class="result-actions">
                        <button class="action-btn" onclick="enhancedInterface.viewDataset('${dataset.id}')">
                            📊 View
                        </button>
                        <button class="action-btn" onclick="enhancedInterface.analyzeDataset('${dataset.id}')">
                            🔬 Analyze
                        </button>
                    </div>
                </div>
                <div class="result-content">
                    <p class="result-description">${this.escapeHtml(dataset.description || 'No description available')}</p>
                    <div class="result-metadata">
                        <div class="metadata-grid">
                            ${dataset.organism ? `<div class="metadata-tag">🧬 ${dataset.organism}</div>` : ''}
                            ${dataset.study_type ? `<div class="metadata-tag">🔬 ${dataset.study_type}</div>` : ''}
                            ${dataset.sample_count ? `<div class="metadata-tag">📈 ${dataset.sample_count} samples</div>` : ''}
                            ${dataset.platform ? `<div class="metadata-tag">🖥️ ${dataset.platform}</div>` : ''}
                        </div>
                    </div>
                </div>
                <div class="result-footer">
                    <span class="result-id">ID: ${dataset.id}</span>
                    <span class="result-score">Score: ${(dataset.score || 0).toFixed(2)}</span>
                </div>
            </div>
        `;
    }

    async checkSystemStatus() {
        try {
            console.log('[⚙️ SYSTEM] Checking system status...');
            
            const response = await this.makeApiRequest('/api/v2/health');
            
            if (response.ok) {
                const health = await response.json();
                this.updateSystemStatus(health);
                this.updateStatus('backend-status', 'connected', 'Backend: Connected');
            } else {
                throw new Error(`Health check failed: ${response.status}`);
            }
        } catch (error) {
            console.error('[❌ SYSTEM] Health check failed:', error);
            this.updateStatus('backend-status', 'error', 'Backend: Error');
        }

        // Also check cache stats
        await this.updateCacheStats();
    }

    async updateCacheStats() {
        try {
            const response = await this.makeApiRequest('/api/v2/system/cache/stats');
            
            if (response.ok) {
                const stats = await response.json();
                this.displayCacheStats(stats);
            }
        } catch (error) {
            console.error('[❌ CACHE] Failed to get cache stats:', error);
        }
    }

    displayCacheStats(stats) {
        const cacheStatsElement = document.getElementById('cache-stats');
        if (cacheStatsElement && stats) {
            cacheStatsElement.innerHTML = `
                <div class="cache-stats-grid">
                    <div class="stat-item">
                        <span class="stat-label">Hit Rate:</span>
                        <span class="stat-value">${(stats.hit_rate || 0).toFixed(1)}%</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Total Hits:</span>
                        <span class="stat-value">${stats.total_hits || 0}</span>
                    </div>
                </div>
            `;
        }
    }

    initEnhancedFeatures() {
        console.log('[🎯 ENHANCED] Initializing enhanced features...');
        
        // Initialize real-time monitoring
        this.setupRealtimeMonitoring();
        
        // Initialize advanced visualizations
        this.setupAdvancedVisualizations();
        
        // Initialize keyboard shortcuts
        this.setupKeyboardShortcuts();
        
        // Initialize theme management
        this.setupThemeManagement();
    }

    setupRealtimeMonitoring() {
        // Subscribe to real-time updates
        if (this.websocket && this.isConnected) {
            this.websocket.send(JSON.stringify({
                type: 'subscribe',
                event: 'system_updates'
            }));
        }

        // Update real-time status indicator
        const realtimeStatus = document.getElementById('realtime-status');
        if (realtimeStatus) {
            realtimeStatus.innerHTML = this.isConnected ? 
                '<span class="status-indicator connected">🟢 Active</span>' :
                '<span class="status-indicator disconnected">🔴 Inactive</span>';
        }
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + K for quick search
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                const searchInput = document.getElementById('search-input');
                if (searchInput) {
                    searchInput.focus();
                    searchInput.select();
                }
            }
            
            // Escape to clear search
            if (e.key === 'Escape') {
                const searchInput = document.getElementById('search-input');
                if (searchInput && document.activeElement === searchInput) {
                    searchInput.value = '';
                    searchInput.blur();
                }
            }
        });
    }

    // Utility methods
    updateStatus(elementId, status, text) {
        const element = document.getElementById(elementId);
        if (element) {
            element.className = `status-item ${status}`;
            element.innerHTML = `<span class="status-dot"></span><span>${text}</span>`;
        }
    }

    showError(title, message) {
        console.error(`[❌ ERROR] ${title}: ${message}`);
        
        // You could implement a toast notification system here
        // For now, we'll use a simple alert
        alert(`${title}: ${message}`);
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
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

    cleanup() {
        if (this.websocket) {
            this.websocket.close();
        }
        
        // Clear any intervals or timeouts
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
        }
    }
}

// Global instance
window.enhancedInterface = new EnhancedFuturisticInterface();

// Backward compatibility
window.FuturisticInterface = EnhancedFuturisticInterface;
