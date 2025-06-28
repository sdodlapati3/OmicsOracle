// OmicsOracle Futuristic Interface - Consolidated JavaScript
// Combines all interface functionality into a single file

/**
 * Main OmicsOracle Interface Class
 * Handles all frontend functionality including:
 * - Search operations
 * - UI interactions
 * - WebSocket communication
 * - Results display
 * - Statistics tracking
 */
class OmicsOracleInterface {
    constructor() {
        // Core state
        this.isSearching = false;
        this.searchCount = 0;
        this.totalResponseTime = 0;
        this.websocket = null;

        // DOM element references
        this.elements = {};

        // Initialize interface
        this.init();
    }

    init() {
        console.log('[INIT] Initializing OmicsOracle Interface');

        // Cache DOM elements
        this.cacheElements();

        // Setup event listeners
        this.setupEventListeners();

        // Initialize UI state
        this.initializeUI();

        // Update initial statistics
        this.updateStats();

        // Add initial log entry
        this.addLogEntry('System initialized');

        console.log('[OK] OmicsOracle Interface initialized successfully');
    }

    cacheElements() {
        this.elements = {
            searchInput: document.getElementById('search-input'),
            searchBtn: document.getElementById('search-btn'),
            searchStatus: document.getElementById('search-status'),
            resultsGrid: document.getElementById('results-grid'),
            noResults: document.getElementById('no-results'),
            maxResults: document.getElementById('max-results'),

            // Sidebar and modal elements
            agentSidebar: document.getElementById('agent-sidebar'),
            toggleAgentBtn: document.getElementById('toggle-agent-btn'),
            toggleAgentSidebarBtn: document.getElementById('toggle-agent-sidebar-btn'),
            aboutLink: document.getElementById('about-link'),
            aboutModal: document.getElementById('about-modal'),
            modalClose: document.querySelector('.modal-close'),
            themeToggleBtn: document.getElementById('theme-toggle-btn'),
            clearMonitorBtn: document.getElementById('clear-monitor-btn'),
            logMonitor: document.getElementById('log-monitor'),
            loadingOverlay: document.getElementById('loading-overlay'),

            // Statistics elements
            queryCount: document.getElementById('query-count'),
            avgResponseTime: document.getElementById('avg-response-time')
        };
    }

    setupEventListeners() {
        // Search functionality
        if (this.elements.searchBtn) {
            this.elements.searchBtn.addEventListener('click', () => this.performSearch());
        }

        if (this.elements.searchInput) {
            this.elements.searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.performSearch();
                }
            });
        }

        // Sidebar toggle
        if (this.elements.toggleAgentBtn) {
            this.elements.toggleAgentBtn.addEventListener('click', () => this.toggleAgentSidebar());
        }

        if (this.elements.toggleAgentSidebarBtn) {
            this.elements.toggleAgentSidebarBtn.addEventListener('click', () => this.toggleAgentSidebar());
        }

        // About modal
        if (this.elements.aboutLink) {
            this.elements.aboutLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.showAboutModal();
            });
        }

        if (this.elements.modalClose) {
            this.elements.modalClose.addEventListener('click', () => this.hideAboutModal());
        }

        // Theme toggle
        if (this.elements.themeToggleBtn) {
            this.elements.themeToggleBtn.addEventListener('click', () => this.toggleTheme());
        }

        // Monitor controls
        if (this.elements.clearMonitorBtn) {
            this.elements.clearMonitorBtn.addEventListener('click', () => this.clearMonitor());
        }

        // Click outside modal to close
        window.addEventListener('click', (e) => {
            if (this.elements.aboutModal && e.target === this.elements.aboutModal) {
                this.hideAboutModal();
            }
        });
    }

    initializeUI() {
        // Set initial modal and sidebar state
        if (this.elements.aboutModal) {
            this.elements.aboutModal.style.display = 'none';
        }

        if (this.elements.agentSidebar) {
            this.elements.agentSidebar.classList.add('hidden');
        }

        if (this.elements.loadingOverlay) {
            this.elements.loadingOverlay.style.display = 'none';
        }
    }

    async performSearch() {
        const query = this.elements.searchInput ? this.elements.searchInput.value.trim() : '';

        if (!query) {
            this.addLogEntry('Please enter a search query', 'warning');
            return;
        }

        if (this.isSearching) {
            this.addLogEntry('Search already in progress...', 'warning');
            return;
        }

        // Show loading state
        this.setSearchingState(true);
        this.clearPreviousResults();

        const startTime = Date.now();
        this.addLogEntry(`Searching for: "${query}"`, 'info');

        try {
            const response = await fetch('/api/search', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    query: query,
                    max_results: this.getMaxResults()
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const data = await response.json();
            const responseTime = (Date.now() - startTime) / 1000;

            // Update statistics
            this.searchCount++;
            this.totalResponseTime += responseTime;
            this.updateStats();

            this.addLogEntry(`Found ${data.total_found || 0} results in ${responseTime.toFixed(2)}s`, 'success');
            this.displayResults(data);

        } catch (error) {
            console.error('Search error:', error);
            this.displayError(error.message);
            this.addLogEntry(`Search failed: ${error.message}`, 'error');
        } finally {
            this.setSearchingState(false);
        }
    }

    setSearchingState(searching) {
        this.isSearching = searching;

        if (this.elements.searchBtn) {
            this.elements.searchBtn.disabled = searching;
            this.elements.searchBtn.textContent = searching ? 'Searching...' : 'Search';
        }

        if (this.elements.loadingOverlay) {
            this.elements.loadingOverlay.style.display = searching ? 'flex' : 'none';
        }
    }

    displayResults(data) {
        if (!this.elements.resultsGrid || !this.elements.noResults || !this.elements.searchStatus) {
            console.error('Required DOM elements not found');
            return;
        }

        if (!data.results || data.results.length === 0) {
            this.showNoResults(data.query);
            return;
        }

        // Hide no results message
        this.elements.noResults.style.display = 'none';

        // Update search status
        this.updateSearchStatus(data);

        // Build and display results
        this.buildResultsHTML(data.results);
    }

    showNoResults(query) {
        this.elements.resultsGrid.innerHTML = '';
        this.elements.noResults.style.display = 'block';
        this.elements.searchStatus.innerHTML = `
            <div class="search-status-message">
                <p>No datasets found for query: "${query || ''}"</p>
                <p class="search-status-sub">Try a different search term or check your spelling.</p>
            </div>
        `;
    }

    updateSearchStatus(data) {
        this.elements.searchStatus.innerHTML = `
            <div class="search-status-summary">
                <div>
                    <h3>Results for: "${data.query || ''}"</h3>
                </div>
                <div class="search-status-details">
                    <p>${data.results.length} of ${data.total_found || data.results.length} datasets shown</p>
                    <p class="search-time">Search time: ${data.search_time ? data.search_time.toFixed(2) : '0.00'}s</p>
                </div>
            </div>
        `;
    }

    buildResultsHTML(results) {
        let resultsHTML = '';

        results.forEach((result, index) => {
            // Process GEO summary for truncation
            const geoSummaryText = result.geo_summary || result.summary || '';
            const truncatedSummary = this.truncateText(geoSummaryText, 300);
            const needsShowMore = geoSummaryText.length > 300;

            resultsHTML += `
                <div class="result-card">
                    <div class="result-header">
                        <h3><a href="https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi?acc=${result.geo_id}" target="_blank">${result.geo_id}</a></h3>
                        ${result.relevance_score !== undefined && result.relevance_score !== null ? `<span class="relevance-score">Relevance: ${Math.round(result.relevance_score * 100)}%</span>` : '<span class="relevance-score">Relevance: --</span>'}
                    </div>
                    <h4>${result.title || 'Untitled'}</h4>
                    <div class="result-meta">
                        ${result.organism ? `<div><span>Organism:</span> ${result.organism}</div>` : ''}
                        ${result.sample_count || result.samples_count ? `<div><span>Samples:</span> ${result.sample_count || result.samples_count}</div>` : ''}
                        ${result.publication_date ? `<div><span>Date:</span> ${result.publication_date}</div>` : ''}
                    </div>
                    ${geoSummaryText ? `
                    <div class="result-summary">
                        <h5>Summary:</h5>
                        <div id="summary-${result.geo_id}" data-full-text="${this.escapeHtml(geoSummaryText)}">
                            ${truncatedSummary}
                        </div>
                        ${needsShowMore ? `
                            <button class="show-more-btn" onclick="window.omicsInterface.toggleSummary('summary-${result.geo_id}')">
                                Show More
                            </button>
                        ` : ''}
                    </div>
                    ` : ''}
                    ${result.ai_summary ? `
                    <div class="ai-summary">
                        <h5>🤖 AI Summary:</h5>
                        <div class="ai-summary-content">
                            ${this.escapeHtml(result.ai_summary)}
                        </div>
                    </div>
                    ` : ''}
                </div>
            `;
        });

        this.elements.resultsGrid.innerHTML = resultsHTML;
    }

    displayError(message) {
        if (!this.elements.resultsGrid || !this.elements.noResults || !this.elements.searchStatus) {
            console.error('Required DOM elements not found for error display');
            return;
        }

        this.elements.noResults.style.display = 'none';
        this.elements.resultsGrid.innerHTML = '';

        this.elements.searchStatus.innerHTML = `
            <div class="search-error">
                <h3>Search Error</h3>
                <p>${message}</p>
                <button onclick="location.reload()" class="reload-btn">
                    🔄 Reload Interface
                </button>
            </div>
        `;
    }

    clearPreviousResults() {
        if (this.elements.resultsGrid) {
            this.elements.resultsGrid.innerHTML = '';
        }

        if (this.elements.searchStatus) {
            this.elements.searchStatus.innerHTML = `
                <div class="search-status-message">
                    <p>Searching database...</p>
                </div>
            `;
        }

        if (this.elements.noResults) {
            this.elements.noResults.style.display = 'none';
        }
    }

    getMaxResults() {
        if (!this.elements.maxResults) return 10;

        const value = this.elements.maxResults.value;
        if (value === '1000') {
            this.addLogEntry('Loading all results may take longer...', 'warning');
        }

        return parseInt(value || '10');
    }

    // UI Helper Methods
    toggleAgentSidebar() {
        if (this.elements.agentSidebar) {
            this.elements.agentSidebar.classList.toggle('hidden');
        }
    }

    showAboutModal() {
        if (this.elements.aboutModal) {
            this.elements.aboutModal.style.display = 'flex';
        }
    }

    hideAboutModal() {
        if (this.elements.aboutModal) {
            this.elements.aboutModal.style.display = 'none';
        }
    }

    toggleTheme() {
        document.body.classList.toggle('dark-theme');

        if (this.elements.themeToggleBtn) {
            this.elements.themeToggleBtn.textContent = document.body.classList.contains('dark-theme') ? '☀️' : '🌙';
        }
    }

    clearMonitor() {
        if (this.elements.logMonitor) {
            this.elements.logMonitor.innerHTML = '<div class="log-entry">System initialized</div>';
        }
    }

    addLogEntry(message, type = 'info') {
        if (!this.elements.logMonitor) return;

        const entry = document.createElement('div');
        entry.className = `log-entry log-${type}`;
        entry.textContent = message;

        this.elements.logMonitor.insertBefore(entry, this.elements.logMonitor.firstChild);

        // Keep log size manageable
        if (this.elements.logMonitor.children.length > 50) {
            this.elements.logMonitor.removeChild(this.elements.logMonitor.lastChild);
        }
    }

    updateStats() {
        if (this.elements.queryCount) {
            this.elements.queryCount.textContent = this.searchCount.toString();
        }

        if (this.elements.avgResponseTime) {
            const avg = this.searchCount > 0 ? (this.totalResponseTime / this.searchCount).toFixed(2) : '0.00';
            this.elements.avgResponseTime.textContent = `${avg}s`;
        }
    }

    // Utility Methods
    truncateText(text, maxLength) {
        if (!text || text.length <= maxLength) return this.escapeHtml(text);

        // Find the last space before maxLength to avoid cutting words
        let truncateAt = maxLength;
        const lastSpace = text.lastIndexOf(' ', maxLength);
        if (lastSpace > maxLength * 0.7) { // Only use last space if it's not too far back
            truncateAt = lastSpace;
        }

        return this.escapeHtml(text.substring(0, truncateAt)) + '...';
    }

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    toggleSummary(summaryId) {
        const element = document.getElementById(summaryId);
        const button = element.parentElement.querySelector('.show-more-btn');

        if (!element || !button) return;

        const fullText = element.getAttribute('data-full-text');
        const isExpanded = element.classList.contains('expanded');

        if (isExpanded) {
            // Collapse
            element.innerHTML = this.truncateText(fullText, 300);
            element.classList.remove('expanded');
            button.textContent = 'Show More';
        } else {
            // Expand
            element.innerHTML = this.escapeHtml(fullText);
            element.classList.add('expanded');
            button.textContent = 'Show Less';
        }
    }

    // WebSocket functionality (simplified)
    initWebSocket() {
        try {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            this.websocket = new WebSocket(`${protocol}//${window.location.host}/ws`);

            this.websocket.onopen = () => {
                console.log('[WebSocket] Connected');
                this.addLogEntry('WebSocket connected', 'success');
            };

            this.websocket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.addLogEntry(`WebSocket: ${data.message || 'Update received'}`, 'info');
                } catch (error) {
                    console.error('WebSocket message error:', error);
                }
            };

            this.websocket.onclose = () => {
                console.log('[WebSocket] Disconnected');
                this.addLogEntry('WebSocket disconnected', 'warning');
            };

            this.websocket.onerror = (error) => {
                console.error('[WebSocket] Error:', error);
                this.addLogEntry('WebSocket error', 'error');
            };

        } catch (error) {
            console.error('Failed to initialize WebSocket:', error);
            this.addLogEntry('WebSocket initialization failed', 'error');
        }
    }
}

// Utility function for icon replacement
function replaceIconCodes(text) {
    const iconMap = {
        '[SEARCH]': '🔍',
        '[ANALYSIS]': '📊',
        '[AGENT]': '🤖',
        '[SUCCESS]': '✅',
        '[ERROR]': '❌',
        '[WARNING]': '⚠️',
        '[INFO]': 'ℹ️',
        '[LOADING]': '⏳',
        '[DNA]': '🧬',
        '[SAMPLE]': '🧪',
        '[DATA]': '📈'
    };

    let result = text;
    for (const [code, icon] of Object.entries(iconMap)) {
        result = result.replace(new RegExp(code.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), icon);
    }
    return result;
}

// Function to apply icon replacement to all elements on page
function applyIconReplacements() {
    // Get all text-containing elements that might have bracketed codes
    const elementsToCheck = document.querySelectorAll('h1, h2, h3, h4, h5, h6, p, span, button, div, .log-entry');

    elementsToCheck.forEach(element => {
        if (element.children.length === 0 && element.textContent.includes('[') && element.textContent.includes(']')) {
            element.textContent = replaceIconCodes(element.textContent);
        }
    });

    // Handle specific status element that may contain HTML
    const statusElement = document.getElementById('ws-status');
    if (statusElement && statusElement.innerHTML.includes('[')) {
        statusElement.innerHTML = replaceIconCodes(statusElement.innerHTML);
    }
}

// Initialize application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Create main interface instance
    window.omicsInterface = new OmicsOracleInterface();

    // Initialize WebSocket connection
    window.omicsInterface.initWebSocket();

    // Apply icon replacements after initial load
    setTimeout(() => {
        applyIconReplacements();
    }, 100);

    console.log('[READY] OmicsOracle Interface ready');
});

// Health check on load
fetch('/api/health')
    .then(response => response.json())
    .then(data => {
        console.log('[HEALTH] Health check:', data);
        if (data.status !== 'healthy') {
            console.warn('⚠️ System may not be fully operational');
        }
    })
    .catch(error => console.warn('[HEALTH] Health check failed:', error));

// Global function for backward compatibility
window.performSearch = () => {
    if (window.omicsInterface) {
        window.omicsInterface.performSearch();
    }
};
