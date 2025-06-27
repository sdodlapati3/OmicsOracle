// OmicsOracle Futuristic Interface - Clean JavaScript Implementation
// Integrates with the modular OmicsOracle pipeline backend

class OmicsOracleApp {
    constructor() {
        this.searchQueries = 0;
        this.totalResponseTime = 0;
        this.isSearching = false;
        this.websocket = null;
        this.searchHistory = this.loadSearchHistory();

        this.init();
    }

    init() {
        console.log('[INIT] Initializing OmicsOracle Futuristic Interface...');

        // Bind event listeners
        this.bindEventListeners();

        // Initialize search history autocomplete
        this.initSearchHistory();

        // Initialize WebSocket for live monitoring
        this.initWebSocket();

        // Update initial stats
        this.updateStats();

        console.log('[OK] Interface initialized successfully');
    }

    bindEventListeners() {
        const searchBtn = document.getElementById('search-btn');
        const searchInput = document.getElementById('search-input');
        const clearMonitorBtn = document.getElementById('clear-monitor-btn');
        const toggleAgentBtn = document.getElementById('toggle-agent-btn');
        const toggleAgentSidebarBtn = document.getElementById('toggle-agent-sidebar-btn');
        const aboutLink = document.getElementById('about-link');
        const modalClose = document.querySelector('.modal-close');
        const themeToggleBtn = document.getElementById('theme-toggle-btn');

        if (searchBtn) {
            searchBtn.addEventListener('click', () => this.performSearch());
        }

        if (searchInput) {
            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.performSearch();
                }
            });

            // Add search history functionality
            searchInput.addEventListener('focus', () => this.showSearchSuggestions());
            searchInput.addEventListener('input', () => this.filterSearchSuggestions());
            searchInput.addEventListener('blur', () => this.hideSearchSuggestions(200)); // Delay to allow click
        }

        if (clearMonitorBtn) {
            clearMonitorBtn.addEventListener('click', () => this.clearLiveMonitor());
        }

        // Add agent sidebar toggle functionality
        if (toggleAgentBtn) {
            toggleAgentBtn.addEventListener('click', () => this.toggleAgentSidebar());
        }

        if (toggleAgentSidebarBtn) {
            toggleAgentSidebarBtn.addEventListener('click', () => this.toggleAgentSidebar());
        }

        // Add about modal functionality
        if (aboutLink) {
            aboutLink.addEventListener('click', (e) => {
                e.preventDefault();
                this.showAboutModal();
            });
        }

        if (modalClose) {
            modalClose.addEventListener('click', () => this.hideAboutModal());
        }

        // Add theme toggle functionality
        if (themeToggleBtn) {
            themeToggleBtn.addEventListener('click', () => this.toggleTheme());
        }
    }

    updateStats() {
        const searchQueriesElement = document.getElementById('search-queries');
        const avgResponseTimeElement = document.getElementById('avg-response-time');
        const pipelineStatusElement = document.getElementById('pipeline-status');

        if (searchQueriesElement) {
            searchQueriesElement.textContent = this.searchQueries;
        }

        if (avgResponseTimeElement) {
            const avgTime = this.searchQueries > 0 ?
                (this.totalResponseTime / this.searchQueries).toFixed(2) : '--';
            avgResponseTimeElement.textContent = `${avgTime}s`;
        }

        if (pipelineStatusElement) {
            pipelineStatusElement.textContent = 'Active';
        }
    }

    addLiveUpdate(message, type = 'info') {
        const liveUpdatesContainer = document.getElementById('live-updates');
        if (!liveUpdatesContainer) return;

        const updateElement = document.createElement('div');
        updateElement.className = `live-update live-update-${type}`;

        const timestamp = new Date().toLocaleTimeString();
        updateElement.innerHTML = `
            <div class="flex justify-between items-center text-sm">
                <span class="text-gray-300">${message}</span>
                <span class="text-gray-500">${timestamp}</span>
            </div>
        `;

        // Add to the top
        liveUpdatesContainer.insertBefore(updateElement, liveUpdatesContainer.firstChild);

        // Keep only the last 10 updates
        while (liveUpdatesContainer.children.length > 10) {
            liveUpdatesContainer.removeChild(liveUpdatesContainer.lastChild);
        }
    }

    async performSearch() {
        console.log('[SEARCH] performSearch called');
        const searchInput = document.getElementById('search-input');
        const searchBtn = document.getElementById('search-btn');
        const query = searchInput?.value?.trim();

        console.log('[SEARCH] Search query:', query);
        console.log('[SEARCH] searchInput element:', searchInput);
        console.log('[SEARCH] searchBtn element:', searchBtn);

        if (!query) {
            this.addLiveUpdate('[WARNING] Please enter a search query', 'warning');
            return;
        }

        if (this.isSearching) {
            this.addLiveUpdate('[BUSY] Search already in progress...', 'warning');
            return;
        }

        console.log('[SEARCH] Starting search process...');

        // Show loading overlay
        const loadingOverlay = document.getElementById('loading-overlay');
        if (loadingOverlay) {
            loadingOverlay.style.display = 'flex';
        }

        // Clear previous results immediately - FIRST PRIORITY
        this.clearPreviousResults();

        // Hide search suggestions
        this.hideSearchSuggestions();

        // Add to search history
        this.addToSearchHistory(query);

        this.isSearching = true;

        // Update button to show searching state immediately with better formatting
        if (searchBtn) {
            searchBtn.disabled = true;
            searchBtn.classList.add('searching');
            searchBtn.innerHTML = '🔄 Searching<span class="dots-loading"></span>';
            searchBtn.style.cursor = 'not-allowed';
        }

        const startTime = Date.now();

        // Start a progress timer with better time formatting
        const progressTimer = setInterval(() => {
            const elapsed = Math.floor((Date.now() - startTime) / 1000);
            const searchBtn = document.getElementById('search-btn');
            if (searchBtn && this.isSearching) {
                const minutes = Math.floor(elapsed / 60);
                const seconds = elapsed % 60;
                const timeStr = minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
                searchBtn.innerHTML = `🔄 Searching (${timeStr})<span class="dots-loading"></span>`;
            }
        }, 1000);

        try {
            // Show and reset the progress monitor
            this.showProgressMonitor();
            this.updateProgressBars(0, "initializing");

            this.addLiveUpdate(`🔍 Searching for: "${query}"`, 'info');
            this.addToLiveProgressFeed(`<div class="text-blue-400">🔍 Starting search for: "${query}"</div>`);

            console.log('[API] Making fetch request to /api/search...');
            this.addToLiveProgressFeed(`<div class="text-yellow-400">🌐 Connecting to backend API...</div>`);

            // Add timeout to prevent hanging (minimum 20s based on investigation findings)
            // Extended to 5 minutes for complex searches with real-time progress updates
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 300000); // 300 second timeout (5 minutes)

            const response = await fetch('/api/search', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                },
                body: JSON.stringify({
                    query: query,
                    max_results: this.getMaxResults(),
                    search_type: 'comprehensive',
                    disable_cache: true,  // Force fresh data
                    timestamp: Date.now()  // Prevent browser caching
                }),
                signal: controller.signal
            });

            clearTimeout(timeoutId);
            clearInterval(progressTimer); // Clear the progress timer when request completes
            console.log('[API] Response received:', response.status, response.statusText);
            this.addToLiveProgressFeed(`<div class="text-green-400">[OK] Response received from server (${response.status})</div>`);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            this.addToLiveProgressFeed(`<div class="text-blue-400">📊 Processing search results...</div>`);
            const data = await response.json();
            console.log('[DATA] Data received:', data);

            const responseTime = (Date.now() - startTime) / 1000;

            this.searchQueries++;
            this.totalResponseTime += responseTime;

            this.updateStats();

            this.addLiveUpdate(`[OK] Found ${data.total_found} results in ${responseTime.toFixed(2)}s`, 'success');

            // Update progress to 100% if it's not already there
            this.updateProgressBars(100, "complete");
            this.displayResults(data);

            // Add query to search history
            this.addToSearchHistory(query);

        } catch (error) {
            console.error('🚨 Search failed:', error);

            let errorMessage = error.message;
            if (error.name === 'AbortError') {
                errorMessage = 'Search timed out after 5 minutes. Please try a more specific query.';
                this.addLiveUpdate('⏰ Search timed out - try a more specific query for faster results', 'error');
            } else {
                this.addLiveUpdate(`❌ Search failed: ${error.message}`, 'error');
            }

            this.displayError(error.message);

            // Update progress to show error state
            this.updateProgressBars(100, "error");
        } finally {
            // Clear progress timer
            if (progressTimer) {
                clearInterval(progressTimer);
            }

            this.isSearching = false;

            // Reset button to normal state
            if (searchBtn) {
                searchBtn.disabled = false;
                searchBtn.classList.remove('searching');
                searchBtn.innerHTML = '🚀 Search NCBI GEO Database';
                searchBtn.style.cursor = 'pointer';
            }

            // Hide loading overlay
            const loadingOverlay = document.getElementById('loading-overlay');
            if (loadingOverlay) {
                loadingOverlay.style.display = 'none';
            }
        }
    }

    clearPreviousResults() {
        // Clear results grid
        const resultsGrid = document.getElementById('results-grid');
        if (resultsGrid) {
            resultsGrid.innerHTML = '';
        }

        // Show loading status
        const searchStatus = document.getElementById('search-status');
        if (searchStatus) {
            searchStatus.innerHTML = `
                <div class="search-status-message">
                    <p>Searching database...</p>
                </div>
            `;
        }

        // Hide no results message
        const noResults = document.getElementById('no-results');
        if (noResults) {
            noResults.style.display = 'none';
        }

        // Show live monitor container (if using monitoring features)
        const monitorContainer = document.getElementById('log-monitor');
        if (monitorContainer) {
            this.addLiveUpdate('Starting new search...', 'info');
        }
    }
                    </div>
                    <div id="live-progress-feed" class="space-y-2 max-h-64 overflow-y-auto bg-black bg-opacity-50 rounded p-4 font-mono text-sm">
                        <div class="text-blue-400">[${new Date().toLocaleTimeString()}] 🚀 Initializing search...</div>
                    </div>
                    <div class="mt-3 text-center">
                        <p class="text-gray-400 text-sm">Real-time updates from the biomedical search pipeline</p>
                    </div>
                </div>
            `;
        }

        // Force a DOM repaint to ensure immediate visual update
        if (resultsContainer) {
            resultsContainer.offsetHeight; // Trigger reflow
        }
    }

    showProgressMonitor() {
        // Show live monitor container
        const monitorContainer = document.getElementById('live-monitor-container');
        if (monitorContainer) {
            monitorContainer.style.display = 'block';
        }

        // Clear any existing progress feed content
        const liveMonitor = document.getElementById('live-monitor');
        if (liveMonitor) {
            liveMonitor.innerHTML = '<div class="text-green-400">🚀 Query monitor ready...</div>';
        }
    }

    displayResults(data) {
        const resultsGrid = document.getElementById('results-grid');
        const noResults = document.getElementById('no-results');
        const searchStatus = document.getElementById('search-status');

        if (!resultsGrid || !noResults || !searchStatus) {
            console.error('Required DOM elements not found:', { resultsGrid, noResults, searchStatus });
            return;
        }

        // Hide loading overlay
        const loadingOverlay = document.getElementById('loading-overlay');
        if (loadingOverlay) {
            loadingOverlay.style.display = 'none';
        }

        if (!data.results || data.results.length === 0) {
            // Show no results message
            resultsGrid.innerHTML = '';
            noResults.style.display = 'block';
            searchStatus.innerHTML = `
                <div class="search-status-message">
                    <p>No datasets found for query: "${data.query}"</p>
                    <p class="search-status-sub">Try a different search term or check your spelling.</p>
                </div>
            `;
            return;
        }

        // Hide no results message
        noResults.style.display = 'none';

        // Update search status
        searchStatus.innerHTML = `
            <div class="search-status-summary">
                <div>
                    <h3>Results for: "${data.query}"</h3>
                </div>
                <div class="search-status-details">
                    <p>${data.results.length} of ${data.total_found} datasets shown</p>
                    <p class="search-time">Search time: ${data.search_time ? data.search_time.toFixed(2) : '0.00'}s</p>
                    ${data.total_found > data.results.length ?
                        `<p class="search-partial-results">Showing ${data.results.length} of ${data.total_found} available results.
                         Use the "Max Results" selector to show more.</p>` : ''}
                </div>
            </div>
            ${data.ai_insights ? `<div class="search-ai-insights">${data.ai_insights}</div>` : ''}
        `;

        // Update results grid
        let resultsHTML = '';
        data.results.forEach((dataset, index) => {
            resultsHTML += this.renderDataset(dataset, index);
        });

        resultsGrid.innerHTML = resultsHTML;
    }

    renderDataset(dataset, index) {
        // Handle null relevance score properly
        const relevanceScore = dataset.relevance_score || 0;
        const relevanceClass = relevanceScore > 0.8 ? 'high-relevance' :
                             relevanceScore > 0.5 ? 'medium-relevance' : 'low-relevance';

        // Build metadata grid dynamically, only showing available info
        let metadataGrid = '';

        if (dataset.organism && dataset.organism.trim()) {
            metadataGrid += `
                <div>
                    <span class="text-gray-400">Organism:</span>
                    <span class="text-white ml-2">${dataset.organism}</span>
                </div>`;
        }

        if (dataset.sample_count && dataset.sample_count > 0) {
            metadataGrid += `
                <div>
                    <span class="text-gray-400">Samples:</span>
                    <span class="text-white ml-2">${dataset.sample_count}</span>
                </div>`;
        }

        if (dataset.publication_date) {
            metadataGrid += `
                <div>
                    <span class="text-gray-400">Date:</span>
                    <span class="text-white ml-2">${dataset.publication_date}</span>
                </div>`;
        }

        // Create unique IDs for expandable content
        const summaryId = `summary-${dataset.geo_id}`;
        const aiId = `ai-${dataset.geo_id}`;

        return `
            <div class="dataset-card glass-effect rounded-lg p-4 ${relevanceClass}">
                <div class="flex justify-between items-start mb-3">
                    <h5 class="text-lg font-semibold text-white">
                        <a href="https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi?acc=${dataset.geo_id}"
                           target="_blank"
                           class="hover:text-blue-400 transition-colors">
                            ${dataset.geo_id}
                        </a>
                    </h5>
                    ${dataset.relevance_score ? `<span class="text-sm text-gray-400">
                        Score: ${(dataset.relevance_score * 100).toFixed(0)}%
                    </span>` : ''}
                </div>

                <h6 class="text-md font-medium text-gray-100 mb-2">
                    ${dataset.title || ''}
                </h6>

                ${metadataGrid ? `<div class="grid grid-cols-2 gap-4 mb-3 text-sm">${metadataGrid}</div>` : ''}

                ${dataset.summary ? `
                <div class="mb-3">
                    <h7 class="text-sm font-medium text-yellow-300 block mb-1">📊 GEO Summary:</h7>
                    <div class="expandable-content">
                        <div id="${summaryId}" class="text-gray-200 text-sm scientific-text full-text"
                             data-full-text="${this.escapeHtml(dataset.summary)}">
                            ${this.escapeHtml(dataset.summary)}
                        </div>
                    </div>
                </div>
                ` : ''}

                ${dataset.ai_insights ? `
                <div class="${dataset.summary ? 'border-t border-gray-600 pt-3' : ''}">
                    <h7 class="text-sm font-medium text-blue-300 block mb-1">🤖 AI Analysis:</h7>
                    <div class="expandable-content">
                        <div id="${aiId}" class="text-blue-100 text-sm scientific-text full-text" style="max-height: none !important; overflow: visible !important;"
                           data-full-text="${this.escapeHtml(dataset.ai_insights)}">
                            ${this.escapeHtml(dataset.ai_insights)}
                        </div>
                    </div>
                </div>
                ` : ''}
            </div>
        `;
    }

    displayError(message) {
        const resultsGrid = document.getElementById('results-grid');
        const noResults = document.getElementById('no-results');
        const searchStatus = document.getElementById('search-status');

        if (!resultsGrid || !noResults || !searchStatus) {
            console.error('Required DOM elements not found for error display');
            return;
        }

        // Hide no results message
        noResults.style.display = 'none';

        // Update search status with error
        searchStatus.innerHTML = `
            <div class="search-error">
                <h3>Search Error</h3>
                <p>${message}</p>
                <button onclick="location.reload()" class="reload-btn">
                    🔄 Reload Interface
                </button>
            </div>
        `;

        // Clear results grid
        resultsGrid.innerHTML = '';

        // Hide loading overlay
        const loadingOverlay = document.getElementById('loading-overlay');
        if (loadingOverlay) {
            loadingOverlay.style.display = 'none';
        }
    }

    truncateText(text, maxLength) {
        if (!text) return '';
        if (text.length <= maxLength) return text;

        // For AI analysis and important content, use a larger maxLength
        if (maxLength < 1000 && text.includes("analysis") || text.includes("insights")) {
            maxLength = 1500; // Allow longer text for analysis content
        }

        // Try to find a natural break point (end of sentence or paragraph)
        const breakPoints = ['. ', '! ', '? ', '\n\n', '\n'];
        let bestBreakPoint = maxLength;

        // Look for the closest break point before maxLength
        for (const breakChar of breakPoints) {
            const index = text.lastIndexOf(breakChar, maxLength);
            if (index > 0 && index < bestBreakPoint) {
                bestBreakPoint = index + (breakChar.length); // Include the break character(s)
            }
        }

        // If no good break point found, try to break at a word boundary
        if (bestBreakPoint === maxLength) {
            const lastSpace = text.lastIndexOf(' ', maxLength);
            if (lastSpace > maxLength * 0.8) { // Only use if reasonably close to target
                bestBreakPoint = lastSpace;
            }
        }

        return text.substr(0, bestBreakPoint) + '...';
    }

    initWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/monitor`;

        try {
            this.websocket = new WebSocket(wsUrl);

            this.websocket.onopen = () => {
                console.log('[WS] WebSocket connected for live monitoring');
            };

            this.websocket.onmessage = (event) => {
                console.log('[API] WebSocket message received:', event.data);

                try {
                    // Try to parse as JSON first (for structured progress updates)
                    const data = JSON.parse(event.data);

                    // Handle progress updates
                    if (data.type === 'progress') {
                        this.handleProgressUpdate(data);
                        return;
                    }

                    // Handle other JSON messages
                    if (data.message) {
                        this.addLiveUpdate(data.message, data.type || 'info');
                    }
                } catch (e) {
                    // If not valid JSON, treat as HTML message from backend

                    // Add to live monitor (main progress area)
                    this.addLiveMonitorMessage(event.data);

                    // Also add to live updates panel - extract text for summary
                    const tempDiv = document.createElement('div');
                    tempDiv.innerHTML = event.data;
                    const textContent = tempDiv.textContent || tempDiv.innerText || '';
                    if (textContent.trim()) {
                        // Clean up the message for the live updates panel
                        const cleanMessage = textContent.replace(/^\[.*?\]\s*/, '').trim(); // Remove timestamp
                        this.addLiveUpdate(cleanMessage, 'info');
                    }
                }
            };

            this.websocket.onclose = () => {
                console.log('[ERROR] WebSocket disconnected');
                // Attempt to reconnect after 3 seconds
                setTimeout(() => this.initWebSocket(), 3000);
            };

            this.websocket.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
        } catch (error) {
            console.error('Failed to initialize WebSocket:', error);
        }
    }

    handleProgressUpdate(data) {
        console.log('[PROGRESS]', data);

        // Update progress bar
        const progressBar = document.getElementById('progress-bar');
        const progressPercentage = document.getElementById('progress-percentage');
        const currentStage = document.getElementById('current-stage');

        if (progressBar && progressPercentage) {
            progressBar.style.width = `${data.percentage}%`;
            progressPercentage.textContent = `${Math.round(data.percentage)}%`;

            // Change color based on stage
            if (data.stage.includes('error') || data.stage.includes('failed')) {
                progressBar.className = 'bg-red-600 h-4 rounded-full transition-all duration-300';
            } else if (data.stage.includes('complete')) {
                progressBar.className = 'bg-green-600 h-4 rounded-full transition-all duration-300';
            } else {
                progressBar.className = 'bg-blue-600 h-4 rounded-full transition-all duration-300';
            }
        }

        if (currentStage) {
            currentStage.textContent = data.stage.replace(/_/g, ' ');
        }

        // Add message to live monitor
        const message = `<div class="text-${this.getColorForStage(data.stage)}">[${Math.round(data.percentage)}%] ${data.message}</div>`;
        this.addToLiveProgressFeed(message);

        // Show live monitor container if it's hidden
        const monitorContainer = document.getElementById('live-monitor-container');
        if (monitorContainer && monitorContainer.style.display === 'none') {
            monitorContainer.style.display = 'block';
        }

        // Add to live updates with shorter message
        this.addLiveUpdate(`${data.message} (${Math.round(data.percentage)}%)`, this.getUpdateTypeForStage(data.stage));
    }

    getColorForStage(stage) {
        if (stage.includes('error') || stage.includes('failed')) {
            return 'red-400';
        } else if (stage.includes('complete') || stage.includes('success')) {
            return 'green-400';
        } else if (stage.includes('warning') || stage.includes('skip')) {
            return 'yellow-400';
        } else {
            return 'blue-400';
        }
    }

    getUpdateTypeForStage(stage) {
        if (stage.includes('error') || stage.includes('failed')) {
            return 'error';
        } else if (stage.includes('complete') || stage.includes('success')) {
            return 'success';
        } else if (stage.includes('warning') || stage.includes('skip')) {
            return 'warning';
        } else {
            return 'info';
        }
    }

    addLiveMonitorMessage(htmlMessage) {
        const monitorContainer = document.getElementById('live-monitor-container');
        const monitor = document.getElementById('live-monitor');

        if (monitor) {
            // Show the monitor container when we have messages
            if (monitorContainer) {
                monitorContainer.style.display = 'block';
            }

            // Add the message
            monitor.insertAdjacentHTML('beforeend', htmlMessage);

            // Auto-scroll to bottom
            monitor.scrollTop = monitor.scrollHeight;

            // Limit to last 100 messages for performance
            const messages = monitor.children;
            if (messages.length > 100) {
                monitor.removeChild(messages[0]);
            }
        }
    }

    clearLiveMonitor() {
        const monitor = document.getElementById('live-monitor');
        if (monitor) {
            monitor.innerHTML = '<div class="text-green-400">🚀 Query monitor ready...</div>';
        }
    }

    getMaxResults() {
        const maxResultsSelect = document.getElementById('max-results');
        if (!maxResultsSelect) return 10; // Default if element not found

        const value = maxResultsSelect.value;
        if (value === '1000') {
            // Show warning for "All Results" option
            this.addLiveUpdate('[NOTICE] Loading all results may take longer...', 'warning');
        }

        return parseInt(value || '10');
    }

    loadSearchHistory() {
        // Temporarily disable search history to avoid cached data confusion
        return [];
        /*
        try {
            const history = localStorage.getItem('omicsOracle_searchHistory');
            return history ? JSON.parse(history) : [];
        } catch (e) {
            console.warn('Failed to load search history:', e);
            return [];
        }
        */
    }

    saveSearchHistory() {
        // Temporarily disable saving search history
        return;
        /*
        try {
            // Keep only the last 20 searches
            const historyToSave = this.searchHistory.slice(-20);
            localStorage.setItem('omicsOracle_searchHistory', JSON.stringify(historyToSave));
        } catch (e) {
            console.warn('Failed to save search history:', e);
        }
        */
    }

    addToSearchHistory(query) {
        // Add a query to search history
        if (!query || !this.searchHistory) return;

        // Don't add duplicates
        if (this.searchHistory.includes(query)) {
            // Move to the end of the array
            this.searchHistory = this.searchHistory.filter(item => item !== query);
        }

        // Add to history
        this.searchHistory.push(query);

        // Save to localStorage
        this.saveSearchHistory();
    }

    initSearchHistory() {
        // Initialize search history functionality
        console.log('[INIT] Initializing search history...');

        // If we have search history, setup autocomplete
        if (this.searchHistory && this.searchHistory.length > 0) {
            console.log(`[INIT] Loaded ${this.searchHistory.length} search history items`);
        }
    }

    initWebSocket() {
        // Initialize WebSocket for live monitoring if supported by the server
        console.log('[INIT] Initializing WebSocket connection...');
        try {
            // For now, this is a stub - actual WebSocket implementation would go here
            console.log('[INIT] WebSocket connection not needed or available');
        } catch (error) {
            console.error('[ERROR] Failed to connect WebSocket:', error);
        }
    }

    showSearchSuggestions() {
        // Show search suggestions based on history
        const suggestionsContainer = document.getElementById('search-suggestions');
        if (!suggestionsContainer || !this.searchHistory || this.searchHistory.length === 0) return;

        // Show the suggestions container
        suggestionsContainer.style.display = 'block';
    }

    filterSearchSuggestions() {
        // Filter search suggestions based on input
        const searchInput = document.getElementById('search-input');
        const suggestionsContainer = document.getElementById('search-suggestions');
        if (!searchInput || !suggestionsContainer) return;

        const query = searchInput.value.trim().toLowerCase();
        if (!query) {
            suggestionsContainer.style.display = 'none';
            return;
        }
    }

    hideSearchSuggestions(delay = 0) {
        // Hide search suggestions
        setTimeout(() => {
            const suggestionsContainer = document.getElementById('search-suggestions');
            if (suggestionsContainer) {
                suggestionsContainer.style.display = 'none';
            }
        }, delay);
    }

    addToSearchHistory(query) {
        // Add a query to search history
        if (!query || !this.searchHistory) return;

        // Don't add duplicates
        if (this.searchHistory.includes(query)) {
            // Move to the end of the array
            this.searchHistory = this.searchHistory.filter(item => item !== query);
        }

        // Add to history
        this.searchHistory.push(query);

        // Save to localStorage
        this.saveSearchHistory();
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.omicsOracleApp = new OmicsOracleApp();

    // Set initial state for the agent sidebar
    const sidebar = document.getElementById('agent-sidebar');
    if (sidebar) {
        sidebar.classList.add('hidden'); // Start with sidebar hidden
    }

    // Set initial state for modal
    const modal = document.getElementById('about-modal');
    if (modal) {
        modal.style.display = 'none'; // Start with modal hidden
    }

    // Set up global event listener for modal close when clicking outside
    window.addEventListener('click', (e) => {
        const modal = document.getElementById('about-modal');
        if (modal && e.target === modal) {
            modal.style.display = 'none';
        }
    });

    console.log('[INIT] DOM fully loaded and parsed');
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
    .catch(error => {
        console.error('❌ Health check failed:', error);
    });
