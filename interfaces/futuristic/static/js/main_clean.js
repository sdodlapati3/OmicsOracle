// OmicsOracle Futuristic Interface - Clean JavaScript Implementation
// Integrates with the modular OmicsOracle pipeline backend

class OmicsOracleApp {
    constructor() {
        this.searchQueries = 0;
        this.totalResponseTime = 0;
        this.isSearching = false;
        
        this.init();
    }

    init() {
        console.log('🚀 Initializing OmicsOracle Futuristic Interface...');
        
        // Bind event listeners
        this.bindEventListeners();
        
        // Update initial status
        this.updateStatus('ready');
        this.updateStats();
        
        console.log('✅ Interface initialized successfully');
    }

    bindEventListeners() {
        const searchBtn = document.getElementById('search-btn');
        const searchInput = document.getElementById('search-input');

        if (searchBtn) {
            searchBtn.addEventListener('click', () => this.performSearch());
        }

        if (searchInput) {
            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.performSearch();
                }
            });
        }
    }

    updateStatus(status) {
        const statusElement = document.getElementById('status');
        if (statusElement) {
            switch (status) {
                case 'ready':
                    statusElement.innerHTML = '✅ Ready';
                    statusElement.className = 'status-ready';
                    break;
                case 'searching':
                    statusElement.innerHTML = '🔍 Searching...';
                    statusElement.className = 'status-searching';
                    break;
                case 'processing':
                    statusElement.innerHTML = '⚡ Processing...';
                    statusElement.className = 'status-processing';
                    break;
                case 'error':
                    statusElement.innerHTML = '❌ Error';
                    statusElement.className = 'status-error';
                    break;
            }
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
        const searchInput = document.getElementById('search-input');
        const query = searchInput?.value?.trim();

        if (!query) {
            this.addLiveUpdate('⚠️ Please enter a search query', 'warning');
            return;
        }

        if (this.isSearching) {
            this.addLiveUpdate('⏳ Search already in progress...', 'warning');
            return;
        }

        this.isSearching = true;
        this.updateStatus('searching');
        
        const startTime = Date.now();
        
        try {
            this.addLiveUpdate(`🔍 Searching for: "${query}"`, 'info');
            
            const response = await fetch('/api/search', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    query: query,
                    max_results: 10,
                    search_type: 'comprehensive'
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const data = await response.json();
            const responseTime = (Date.now() - startTime) / 1000;

            this.searchQueries++;
            this.totalResponseTime += responseTime;
            
            this.updateStatus('ready');
            this.updateStats();
            
            this.addLiveUpdate(`✅ Found ${data.total_found} results in ${responseTime.toFixed(2)}s`, 'success');
            this.displayResults(data);

        } catch (error) {
            console.error('Search failed:', error);
            
            this.updateStatus('error');
            this.addLiveUpdate(`❌ Search failed: ${error.message}`, 'error');
            
            this.displayError(error.message);
        } finally {
            this.isSearching = false;
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
            <div class="mb-4">
                <h4 class="text-lg font-semibold text-white mb-2">
                    Found ${data.total_found} datasets (search time: ${data.search_time.toFixed(2)}s)
                </h4>
                <p class="text-gray-300 text-sm mb-4">${data.ai_insights || ''}</p>
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

        return `
            <div class="dataset-card glass-effect-solid rounded-lg p-4 ${relevanceClass} border-l-4 border-blue-500">
                <div class="flex justify-between items-start mb-3">
                    <h5 class="text-lg font-bold text-white">
                        <a href="https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi?acc=${dataset.geo_id}" 
                           target="_blank" 
                           class="hover:text-blue-300 transition-colors underline decoration-2 underline-offset-4">
                            🔗 ${dataset.geo_id}
                        </a>
                    </h5>
                    <span class="text-xs bg-blue-600 text-white px-2 py-1 rounded-full">
                        Score: ${Math.min(100, (dataset.relevance_score * 100)).toFixed(0)}%
                    </span>
                </div>
                
                <h6 class="text-md font-semibold text-gray-100 mb-3 leading-tight">
                    ${dataset.title}
                </h6>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-2 mb-3 text-xs bg-gray-800 bg-opacity-50 p-3 rounded-lg">
                    <div class="flex items-center">
                        <span class="text-blue-300 font-medium">🧬 Organism:</span>
                        <span class="text-white ml-2 font-semibold">${dataset.organism && dataset.organism !== 'Not specified' ? dataset.organism : 'Human (likely)'}</span>
                    </div>
                    <div class="flex items-center">
                        <span class="text-green-300 font-medium">📊 Samples:</span>
                        <span class="text-white ml-2 font-semibold">${dataset.sample_count || 'Unknown'}</span>
                    </div>
                    <div class="flex items-center">
                        <span class="text-purple-300 font-medium">📅 Date:</span>
                        <span class="text-white ml-2 font-semibold">${dataset.publication_date || 'Recent'}</span>
                    </div>
                    <div class="flex items-center">
                        <span class="text-yellow-300 font-medium">📄 Type:</span>
                        <span class="text-white ml-2 font-semibold">${dataset.study_type || 'Expression profiling'}</span>
                    </div>
                </div>
                
                <div class="mb-3 bg-gray-900 bg-opacity-30 p-3 rounded-lg">
                    <h7 class="text-xs font-bold text-gray-200 block mb-2 uppercase tracking-wide">📋 Summary:</h7>
                    <p class="text-gray-100 text-xs leading-relaxed">
                        ${dataset.summary || 'No summary available'}
                    </p>
                </div>
                
                <div class="border-t border-gray-600 pt-3 bg-blue-900 bg-opacity-20 p-3 rounded-lg">
                    <h7 class="text-xs font-bold text-blue-200 block mb-2 uppercase tracking-wide">🤖 AI Analysis:</h7>
                    <p class="text-blue-100 text-xs leading-relaxed">
                        ${dataset.ai_summary || 'AI analysis not available'}
                    </p>
                </div>
                
                <div class="mt-3 flex justify-end">
                    <a href="https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi?acc=${dataset.geo_id}" 
                       target="_blank" 
                       class="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded-lg transition-colors text-xs font-medium">
                        🔗 View on NCBI GEO →
                    </a>
                </div>
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
