/**
 * Enhanced Futuristic Interface - v2 API Integration
 * 
 * Modern TypeScript/JavaScript interface that integrates with the Clean Architecture backend
 */

class EnhancedFuturisticInterface {
    constructor() {
        this.websocket = null;
        this.clientId = this.generateClientId();
        this.currentJob = null;
        this.isConnected = false;
        this.fallbackMode = false;
        this.searchHistory = [];
        this.apiBaseUrl = 'http://localhost:8000/api';
        this.wsBaseUrl = 'ws://localhost:8000';
        
        // Chart.js instances
        this.charts = new Map();
        
        // Initialize interface
        this.init();
    }

    generateClientId() {
        return 'client_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
    }

    async init() {
        console.log('[🚀 LAUNCH] Initializing Enhanced Futuristic Interface');
        
        // Setup event listeners
        this.setupEventListeners();
        
        // Check backend connectivity
        await this.checkBackendConnectivity();
        
        // Connect WebSocket
        this.connectWebSocket();
        
        // Setup UI components
        this.setupUI();
        
        // Load initial data
        await this.loadInitialData();
        
        console.log('[✅ READY] Enhanced interface initialized successfully');
    }

    async checkBackendConnectivity() {
        try {
            // Test v2 API health endpoint
            const response = await fetch(`${this.apiBaseUrl}/v2/health`);
            if (response.ok) {
                const data = await response.json();
                console.log('[🔗 API] Connected to Clean Architecture backend:', data);
                this.updateConnectionStatus('connected', 'v2');
                return true;
            }
        } catch (error) {
            console.warn('[⚠️ API] v2 API not available, trying v1...', error);
        }

        try {
            // Fallback to v1 API
            const response = await fetch(`${this.apiBaseUrl}/v1/health`);
            if (response.ok) {
                const data = await response.json();
                console.log('[🔗 API] Connected to v1 API:', data);
                this.updateConnectionStatus('connected', 'v1');
                return true;
            }
        } catch (error) {
            console.error('[❌ API] Backend not available:', error);
            this.updateConnectionStatus('disconnected', 'none');
            return false;
        }
    }

    connectWebSocket() {
        try {
            // Try Clean Architecture WebSocket first
            this.websocket = new WebSocket(`${this.wsBaseUrl}/ws/${this.clientId}`);
            
            this.websocket.onopen = () => {
                console.log('[🔗 WebSocket] Connected to Clean Architecture backend');
                this.isConnected = true;
                this.updateWebSocketStatus('connected');
            };
            
            this.websocket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleWebSocketMessage(data);
                } catch (error) {
                    console.error('[❌ WebSocket] Failed to parse message:', error);
                }
            };
            
            this.websocket.onclose = () => {
                console.log('[🔌 WebSocket] Connection closed');
                this.isConnected = false;
                this.updateWebSocketStatus('disconnected');
                
                // Attempt reconnection
                setTimeout(() => {
                    if (!this.isConnected) {
                        console.log('[🔄 WebSocket] Attempting to reconnect...');
                        this.connectWebSocket();
                    }
                }, 5000);
            };
            
            this.websocket.onerror = (error) => {
                console.error('[❌ WebSocket] Connection error:', error);
                this.isConnected = false;
                this.updateWebSocketStatus('error');
            };
            
        } catch (error) {
            console.error('[❌ WebSocket] Failed to initialize connection:', error);
        }
    }

    handleWebSocketMessage(data) {
        console.log('[📨 WebSocket] Message received:', data);
        
        switch (data.type) {
            case 'search_progress':
                this.updateSearchProgress(data.payload);
                break;
            case 'search_result':
                this.displaySearchResult(data.payload);
                break;
            case 'analysis_complete':
                this.displayAnalysisResult(data.payload);
                break;
            case 'visualization_update':
                this.updateVisualization(data.payload);
                break;
            case 'system_status':
                this.updateSystemStatus(data.payload);
                break;
            default:
                console.log('[📝 WebSocket] Unknown message type:', data.type);
        }
    }

    setupEventListeners() {
        // Search functionality
        const searchBtn = document.getElementById('enhanced-search-btn');
        const searchInput = document.getElementById('enhanced-search-input');
        
        if (searchBtn && searchInput) {
            searchBtn.addEventListener('click', () => this.performEnhancedSearch());
            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.performEnhancedSearch();
                }
            });
        }

        // Theme switching
        const themeSelector = document.getElementById('theme-selector');
        if (themeSelector) {
            themeSelector.addEventListener('change', (e) => {
                this.switchTheme(e.target.value);
            });
        }

        // Advanced features
        const advancedToggle = document.getElementById('advanced-features-toggle');
        if (advancedToggle) {
            advancedToggle.addEventListener('change', (e) => {
                this.toggleAdvancedFeatures(e.target.checked);
            });
        }
    }

    async performEnhancedSearch() {
        const searchInput = document.getElementById('enhanced-search-input');
        if (!searchInput || !searchInput.value.trim()) {
            this.showNotification('Please enter a search query', 'warning');
            return;
        }

        const query = searchInput.value.trim();
        const startTime = Date.now();
        
        this.showSearchProgress(true);
        this.updateSearchProgress({ stage: 'initializing', progress: 0 });

        try {
            // Use v2 enhanced search API
            const searchRequest = {
                query: query,
                filters: this.getSearchFilters(),
                include_metadata: true,
                enable_ai_summary: true
            };

            console.log('[🔍 Search] Starting enhanced search:', searchRequest);

            const response = await fetch(`${this.apiBaseUrl}/v2/search/enhanced`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(searchRequest)
            });

            if (!response.ok) {
                throw new Error(`Search failed: ${response.status} ${response.statusText}`);
            }

            const result = await response.json();
            const searchTime = Date.now() - startTime;

            console.log('[✅ Search] Enhanced search completed:', result);

            // Display results
            this.displayEnhancedSearchResults(result, searchTime);
            
            // Add to search history
            this.addToSearchHistory(query, result, searchTime);
            
            this.showNotification(`Search completed in ${searchTime}ms`, 'success');

        } catch (error) {
            console.error('[❌ Search] Enhanced search failed:', error);
            
            // Fallback to v1 API
            try {
                await this.performFallbackSearch(query);
            } catch (fallbackError) {
                console.error('[❌ Search] Fallback search also failed:', fallbackError);
                this.showNotification('Search failed. Please try again.', 'error');
            }
        } finally {
            this.showSearchProgress(false);
        }
    }

    async performFallbackSearch(query) {
        console.log('[🔄 Search] Attempting fallback search...');
        
        const response = await fetch(`${this.apiBaseUrl}/v1/search`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                query: query,
                max_results: 10
            })
        });

        if (!response.ok) {
            throw new Error(`Fallback search failed: ${response.status}`);
        }

        const result = await response.json();
        this.displaySearchResults(result);
        this.showNotification('Search completed (fallback mode)', 'warning');
    }

    displayEnhancedSearchResults(result, searchTime) {
        const resultsContainer = document.getElementById('search-results');
        if (!resultsContainer) return;

        const { datasets, metadata, ai_summary } = result;

        resultsContainer.innerHTML = `
            <div class="search-summary">
                <h3>🔍 Search Results</h3>
                <div class="search-stats">
                    <span class="stat-item">
                        <strong>${datasets.length}</strong> datasets found
                    </span>
                    <span class="stat-item">
                        Search time: <strong>${searchTime}ms</strong>
                    </span>
                    <span class="stat-item">
                        API: <strong>v2 Enhanced</strong>
                    </span>
                </div>
            </div>

            ${ai_summary ? `
                <div class="ai-summary">
                    <h4>🤖 AI Summary</h4>
                    <p>${ai_summary}</p>
                </div>
            ` : ''}

            ${metadata ? `
                <div class="search-metadata">
                    <h4>📊 Search Metadata</h4>
                    <div class="metadata-grid">
                        ${Object.entries(metadata).map(([key, value]) => `
                            <div class="metadata-item">
                                <span class="metadata-key">${key}:</span>
                                <span class="metadata-value">${value}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            ` : ''}

            <div class="results-list">
                ${datasets.map((dataset, index) => this.renderDatasetCard(dataset, index)).join('')}
            </div>
        `;

        // Create visualizations if data is available
        if (datasets.length > 0) {
            this.createSearchVisualization(datasets);
        }
    }

    renderDatasetCard(dataset, index) {
        return `
            <div class="result-card enhanced-card" data-index="${index}">
                <div class="card-header">
                    <h4 class="dataset-title">${dataset.title || dataset.id}</h4>
                    <span class="dataset-id">${dataset.id}</span>
                </div>
                <div class="card-content">
                    <p class="dataset-summary">${dataset.summary || 'No summary available'}</p>
                    
                    ${dataset.organism ? `
                        <div class="dataset-metadata">
                            <span class="metadata-tag">🧬 ${dataset.organism}</span>
                        </div>
                    ` : ''}
                    
                    ${dataset.sample_count ? `
                        <div class="dataset-stats">
                            <span class="stat-badge">📊 ${dataset.sample_count} samples</span>
                        </div>
                    ` : ''}
                </div>
                <div class="card-actions">
                    <button class="action-btn primary" onclick="enhancedInterface.viewDatasetDetails('${dataset.id}')">
                        View Details
                    </button>
                    <button class="action-btn secondary" onclick="enhancedInterface.analyzeDataset('${dataset.id}')">
                        Analyze
                    </button>
                    <button class="action-btn tertiary" onclick="enhancedInterface.visualizeDataset('${dataset.id}')">
                        Visualize
                    </button>
                </div>
            </div>
        `;
    }

    // Additional methods for completeness
    updateConnectionStatus(status, apiVersion) {
        console.log(`[📡 Status] Connection: ${status}, API: ${apiVersion}`);
    }

    updateWebSocketStatus(status) {
        console.log(`[🔌 WebSocket] Status: ${status}`);
    }

    showNotification(message, type) {
        console.log(`[📢 ${type.toUpperCase()}] ${message}`);
    }

    showSearchProgress(show) {
        console.log(`[⏳ Progress] ${show ? 'Showing' : 'Hiding'} search progress`);
    }

    updateSearchProgress(progress) {
        console.log(`[⏳ Progress] ${progress.stage}: ${progress.progress}%`);
    }

    getSearchFilters() {
        return {}; // Default empty filters
    }

    addToSearchHistory(query, result, searchTime) {
        this.searchHistory.push({ query, result, searchTime, timestamp: Date.now() });
    }

    createSearchVisualization(datasets) {
        console.log(`[📊 Viz] Creating visualization for ${datasets.length} datasets`);
    }

    async loadInitialData() {
        console.log('[📥 Init] Loading initial data...');
    }

    setupUI() {
        console.log('[🎨 UI] Setting up user interface...');
    }

    switchTheme(themeName) {
        console.log(`[🎨 Theme] Switching to theme: ${themeName}`);
    }
}

// Global instance
let enhancedInterface;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    enhancedInterface = new EnhancedFuturisticInterface();
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = EnhancedFuturisticInterface;
}
