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
        console.log('🚀 Initializing OmicsOracle Futuristic Interface...');
        
        // Bind event listeners
        this.bindEventListeners();
        
        // Initialize search history autocomplete
        this.initSearchHistory();
        
        // Initialize WebSocket for live monitoring
        this.initWebSocket();
        
        // Update initial stats
        this.updateStats();
        
        console.log('✅ Interface initialized successfully');
    }

    bindEventListeners() {
        const searchBtn = document.getElementById('search-btn');
        const searchInput = document.getElementById('search-input');
        const clearMonitorBtn = document.getElementById('clear-monitor-btn');

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
        console.log('🔍 performSearch called');
        const searchInput = document.getElementById('search-input');
        const searchBtn = document.getElementById('search-btn');
        const query = searchInput?.value?.trim();

        console.log('🔍 Search query:', query);
        console.log('🔍 searchInput element:', searchInput);
        console.log('🔍 searchBtn element:', searchBtn);

        if (!query) {
            this.addLiveUpdate('⚠️ Please enter a search query', 'warning');
            return;
        }

        if (this.isSearching) {
            this.addLiveUpdate('⏳ Search already in progress...', 'warning');
            return;
        }

        console.log('🔍 Starting search process...');

        // Clear previous results immediately - FIRST PRIORITY
        this.clearPreviousResults();
        
        // Hide search suggestions
        this.hideSearchSuggestions();
        
        // Add to search history
        this.addToSearchHistory(query);

        this.isSearching = true;
        
        // Update button to show searching state immediately
        if (searchBtn) {
            searchBtn.disabled = true;
            searchBtn.classList.add('searching');
            searchBtn.innerHTML = '🔍 Searching<span class="dots-loading"></span>';
            searchBtn.style.cursor = 'not-allowed';
        }
        
        const startTime = Date.now();
        
        try {
            this.addLiveUpdate(`🔍 Searching for: "${query}"`, 'info');
            this.addToLiveProgressFeed(`<div class="text-blue-400">🔍 Starting search for: "${query}"</div>`);
            
            console.log('🌐 Making fetch request to /api/search...');
            this.addToLiveProgressFeed(`<div class="text-yellow-400">📡 Connecting to backend API...</div>`);
            
            // Add timeout to prevent hanging (extended for complex queries)
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 300000); // 5 minute timeout
            
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
                    max_results: 10,
                    search_type: 'comprehensive',
                    disable_cache: true,  // Force fresh data
                    timestamp: Date.now()  // Prevent browser caching
                }),
                signal: controller.signal
            });

            clearTimeout(timeoutId);
            console.log('📡 Response received:', response.status, response.statusText);
            this.addToLiveProgressFeed(`<div class="text-green-400">✅ Response received from server (${response.status})</div>`);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            this.addToLiveProgressFeed(`<div class="text-blue-400">📊 Processing search results...</div>`);
            const data = await response.json();
            console.log('📊 Data received:', data);
            console.log('🔍 First result check:', data.results?.[0]);
            console.log('🔍 Query vs Results:', {
                query: data.query,
                resultCount: data.results?.length,
                firstGeoId: data.results?.[0]?.geo_id,
                firstTitle: data.results?.[0]?.title
            });
            
            // DEBUG: Log each result for data mapping verification
            if (data.results) {
                data.results.forEach((result, index) => {
                    console.log(`🔍 Result ${index + 1}:`, {
                        geo_id: result.geo_id,
                        title: result.title?.substring(0, 60) + '...',
                        summary: result.summary?.substring(0, 60) + '...',
                        ai_insights: result.ai_insights?.substring(0, 60) + '...',
                        organism: result.organism,
                        sample_count: result.sample_count
                    });
                });
            }
            
            const responseTime = (Date.now() - startTime) / 1000;

            this.searchQueries++;
            this.totalResponseTime += responseTime;
            
            this.updateStats();
            
            this.addLiveUpdate(`✅ Found ${data.total_found} results in ${responseTime.toFixed(2)}s`, 'success');
            this.displayResults(data);

            // Add query to search history
            this.addToSearchHistory(query);

        } catch (error) {
            console.error('🚨 Search failed:', error);
            
            let errorMessage = error.message;
            if (error.name === 'AbortError') {
                errorMessage = 'Search timed out after 5 minutes. Please try a simpler query.';
                this.addLiveUpdate('⏰ Search timed out - please try again with a shorter query', 'error');
            } else {
                this.addLiveUpdate(`❌ Search failed: ${error.message}`, 'error');
            }
            
            this.displayError(error.message);
        } finally {
            this.isSearching = false;
            
            // Reset button to normal state
            if (searchBtn) {
                searchBtn.disabled = false;
                searchBtn.classList.remove('searching');
                searchBtn.innerHTML = '🚀 Search NCBI GEO Database';
                searchBtn.style.cursor = 'pointer';
            }
        }
    }

    clearPreviousResults() {
        // Show live progress area instead of static "Searching..."
        const resultsContainer = document.getElementById('search-results');
        if (resultsContainer) {
            resultsContainer.innerHTML = `
                <div class="bg-blue-900/30 border border-blue-500 rounded-lg p-6">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="text-xl font-bold text-white">🔍 Live Search Progress</h3>
                        <div class="animate-pulse">
                            <div class="w-3 h-3 bg-blue-500 rounded-full"></div>
                        </div>
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

    displayResults(data) {
        const resultsContainer = document.getElementById('search-results');
        if (!resultsContainer) return;

        if (!data.results || data.results.length === 0) {
            resultsContainer.innerHTML = `
                <div class="text-center py-8 text-gray-300">
                    <p>No datasets found for query: "${data.query}"</p>
                    <p class="text-sm text-gray-400 mt-2">Try a different search term or check your spelling.</p>
                </div>
            `;
            return;
        }

        let resultsHTML = `
            <div class="mb-6 bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                <div class="flex items-center justify-between">
                    <div>
                        <h3 class="text-xl font-bold text-white mb-1">Search Results</h3>
                        <p class="text-gray-300">Query: <span class="text-blue-300 font-medium">"${data.query}"</span></p>
                    </div>
                    <div class="text-right">
                        <p class="text-lg font-semibold text-green-400">${data.total_found} datasets found</p>
                        <p class="text-sm text-gray-400">Search time: ${data.search_time.toFixed(2)}s</p>
                    </div>
                </div>
                ${data.ai_insights ? `<p class="text-gray-300 text-sm mt-3 border-t border-gray-600 pt-3">${data.ai_insights}</p>` : ''}
            </div>
            <div class="space-y-4">
        `;

        data.results.forEach((dataset, index) => {
            resultsHTML += this.renderDataset(dataset, index);
        });

        resultsHTML += '</div>';
        resultsContainer.innerHTML = resultsHTML;
    }

    renderDataset(dataset, index) {
        const relevanceClass = dataset.relevance_score > 0.8 ? 'high-relevance' : 
                             dataset.relevance_score > 0.5 ? 'medium-relevance' : 'low-relevance';

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
                    <span class="text-sm text-gray-400">
                        Score: ${(dataset.relevance_score * 100).toFixed(0)}%
                    </span>
                </div>
                
                <h6 class="text-md font-medium text-gray-100 mb-2">
                    ${dataset.title || ''}
                </h6>
                
                ${metadataGrid ? `<div class="grid grid-cols-2 gap-4 mb-3 text-sm">${metadataGrid}</div>` : ''}
                
                ${dataset.summary ? `
                <div class="mb-3">
                    <h7 class="text-sm font-medium text-gray-300 block mb-1">Summary:</h7>
                    <div class="expandable-content">
                        <div id="${summaryId}" class="text-gray-200 text-sm" 
                             data-full-text="${this.escapeHtml(dataset.summary)}"
                             data-is-expanded="false">
                            ${dataset.summary.length > 200 ? this.truncateText(dataset.summary, 200) : dataset.summary}
                        </div>
                        ${dataset.summary.length > 200 ? 
                            `<button onclick="window.omicsApp.toggleText('${summaryId}')" 
                                     class="text-blue-400 hover:text-blue-300 text-xs mt-1 block">
                                Show more...
                             </button>` : ''}
                    </div>
                </div>
                ` : ''}
                
                ${dataset.ai_insights ? `
                <div class="border-t border-gray-600 pt-3">
                    <h7 class="text-sm font-medium text-blue-300 block mb-1">🤖 AI Analysis:</h7>
                    <div class="expandable-content">
                        <div id="${aiId}" class="text-blue-100 text-sm"
                           data-full-text="${this.escapeHtml(dataset.ai_insights)}"
                           data-is-expanded="false">
                            ${dataset.ai_insights.length > 200 ? this.truncateText(dataset.ai_insights, 200) : dataset.ai_insights}
                        </div>
                        ${dataset.ai_insights.length > 200 ? 
                            `<button onclick="window.omicsApp.toggleText('${aiId}')" 
                                     class="text-blue-400 hover:text-blue-300 text-xs mt-1 block">
                                Show more...
                             </button>` : ''}
                    </div>
                </div>
                ` : ''}
            </div>
        `;
    }

    displayError(message) {
        const resultsContainer = document.getElementById('search-results');
        if (!resultsContainer) return;

        resultsContainer.innerHTML = `
            <div class="text-center py-8">
                <div class="text-red-400 text-xl mb-4">❌ Search Error</div>
                <p class="text-gray-300 mb-4">${message}</p>
                <button onclick="location.reload()" 
                        class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition-colors">
                    🔄 Reload Interface
                </button>
            </div>
        `;
    }

    truncateText(text, maxLength) {
        if (text.length <= maxLength) return text;
        return text.substr(0, maxLength) + '...';
    }

    initWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/monitor`;
        
        try {
            this.websocket = new WebSocket(wsUrl);
            
            this.websocket.onopen = () => {
                console.log('🔗 WebSocket connected for live monitoring');
            };
            
            this.websocket.onmessage = (event) => {
                console.log('📡 WebSocket message received:', event.data);
                
                // Add to live progress feed in results area
                this.addToLiveProgressFeed(event.data);
                
                // Also add to live updates panel
                try {
                    const messageData = JSON.parse(event.data);
                    if (messageData.message) {
                        this.addLiveUpdate(messageData.message, messageData.type || 'info');
                    }
                } catch (e) {
                    // If not JSON, treat as HTML and extract text for live updates
                    const tempDiv = document.createElement('div');
                    tempDiv.innerHTML = event.data;
                    const textContent = tempDiv.textContent || tempDiv.innerText || '';
                    if (textContent.trim()) {
                        this.addLiveUpdate(textContent.trim(), 'info');
                    }
                }
            };
            
            this.websocket.onclose = () => {
                console.log('❌ WebSocket disconnected');
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
        // Remove duplicate if exists
        this.searchHistory = this.searchHistory.filter(item => item.query !== query);
        // Add to end with timestamp
        this.searchHistory.push({
            query: query,
            timestamp: new Date().toISOString(),
            count: (this.searchHistory.find(item => item.query === query)?.count || 0) + 1
        });
        this.saveSearchHistory();
    }
    
    initSearchHistory() {
        // Create suggestions dropdown
        const searchContainer = document.querySelector('.search-container') || document.querySelector('.relative');
        if (!searchContainer) return;
        
        const suggestionsDiv = document.createElement('div');
        suggestionsDiv.id = 'search-suggestions';
        suggestionsDiv.className = 'absolute top-full left-0 w-full bg-gray-800 border border-gray-600 rounded-b-lg z-50 hidden max-h-60 overflow-y-auto';
        suggestionsDiv.innerHTML = '';
        
        searchContainer.appendChild(suggestionsDiv);
    }
    
    showSearchSuggestions() {
        const suggestionsDiv = document.getElementById('search-suggestions');
        const searchInput = document.getElementById('search-input');
        
        if (!suggestionsDiv || !searchInput || this.searchHistory.length === 0) return;
        
        // Sort by most recent and most frequent
        const sortedHistory = [...this.searchHistory]
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            .slice(0, 10); // Show max 10 suggestions
            
        if (sortedHistory.length === 0) {
            suggestionsDiv.classList.add('hidden');
            return;
        }
        
        suggestionsDiv.innerHTML = sortedHistory.map(item => `
            <div class="search-suggestion px-3 py-2 hover:bg-gray-700 cursor-pointer border-b border-gray-600 last:border-b-0" 
                 data-query="${item.query}">
                <div class="text-gray-200 text-sm">${item.query}</div>
                <div class="text-gray-400 text-xs">
                    ${new Date(item.timestamp).toLocaleDateString()} • Used ${item.count} time${item.count > 1 ? 's' : ''}
                </div>
            </div>
        `).join('');
        
        // Add click handlers
        suggestionsDiv.querySelectorAll('.search-suggestion').forEach(suggestion => {
            suggestion.addEventListener('click', () => {
                const query = suggestion.getAttribute('data-query');
                searchInput.value = query;
                this.hideSearchSuggestions();
                this.performSearch();
            });
        });
        
        suggestionsDiv.classList.remove('hidden');
    }
    
    filterSearchSuggestions() {
        const searchInput = document.getElementById('search-input');
        const suggestionsDiv = document.getElementById('search-suggestions');
        
        if (!searchInput || !suggestionsDiv) return;
        
        const query = searchInput.value.toLowerCase().trim();
        
        if (query === '') {
            this.showSearchSuggestions(); // Show all if empty
            return;
        }
        
        const filteredHistory = this.searchHistory
            .filter(item => item.query.toLowerCase().includes(query))
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            .slice(0, 8);
            
        if (filteredHistory.length === 0) {
            suggestionsDiv.classList.add('hidden');
            return;
        }
        
        suggestionsDiv.innerHTML = filteredHistory.map(item => `
            <div class="search-suggestion px-3 py-2 hover:bg-gray-700 cursor-pointer border-b border-gray-600 last:border-b-0" 
                 data-query="${item.query}">
                <div class="text-gray-200 text-sm">${item.query}</div>
                <div class="text-gray-400 text-xs">
                    ${new Date(item.timestamp).toLocaleDateString()} • Used ${item.count} time${item.count > 1 ? 's' : ''}
                </div>
            </div>
        `).join('');
        
        // Add click handlers
        suggestionsDiv.querySelectorAll('.search-suggestion').forEach(suggestion => {
            suggestion.addEventListener('click', () => {
                const query = suggestion.getAttribute('data-query');
                searchInput.value = query;
                this.hideSearchSuggestions();
                this.performSearch();
            });
        });
        
        suggestionsDiv.classList.remove('hidden');
    }
    
    hideSearchSuggestions(delay = 0) {
        setTimeout(() => {
            const suggestionsDiv = document.getElementById('search-suggestions');
            if (suggestionsDiv) {
                suggestionsDiv.classList.add('hidden');
            }
        }, delay);
    }

    addToLiveProgressFeed(htmlMessage) {
        const progressFeed = document.getElementById('live-progress-feed');
        if (!progressFeed) return;

        // Extract text content from HTML message
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = htmlMessage;
        const textContent = tempDiv.textContent || tempDiv.innerText || '';
        
        if (textContent.trim()) {
            const timestamp = new Date().toLocaleTimeString();
            const progressLine = document.createElement('div');
            progressLine.className = 'text-green-400 animate-fade-in';
            progressLine.innerHTML = `[${timestamp}] ${textContent.trim()}`;
            
            progressFeed.appendChild(progressLine);
            
            // Auto-scroll to bottom
            progressFeed.scrollTop = progressFeed.scrollHeight;
            
            // Limit to last 50 messages for performance
            while (progressFeed.children.length > 50) {
                progressFeed.removeChild(progressFeed.firstChild);
            }
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    toggleText(elementId) {
        const element = document.getElementById(elementId);
        if (!element) return;

        const fullText = element.getAttribute('data-full-text');
        const isExpanded = element.getAttribute('data-is-expanded') === 'true';

        if (isExpanded) {
            // Collapse
            element.textContent = this.truncateText(fullText, 200);
            element.setAttribute('data-is-expanded', 'false');
            const button = element.parentElement.querySelector('button');
            if (button) button.textContent = 'Show more...';
        } else {
            // Expand
            element.textContent = fullText;
            element.setAttribute('data-is-expanded', 'true');
            const button = element.parentElement.querySelector('button');
            if (button) button.textContent = 'Show less';
        }
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.omicsApp = new OmicsOracleApp();
});

// Health check on load
fetch('/api/health')
    .then(response => response.json())
    .then(data => {
        console.log('🏥 Health check:', data);
        if (data.status !== 'healthy') {
            console.warn('⚠️ System may not be fully operational');
        }
    })
    .catch(error => {
        console.error('❌ Health check failed:', error);
    });
