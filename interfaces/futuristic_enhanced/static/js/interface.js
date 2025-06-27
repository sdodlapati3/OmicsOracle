// OmicsOracle Interface - Fixed JavaScript Implementation
document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const searchInput = document.getElementById('search-input');
    const searchBtn = document.getElementById('search-btn');
    const searchStatus = document.getElementById('search-status');
    const resultsGrid = document.getElementById('results-grid');
    const noResults = document.getElementById('no-results');
    const maxResults = document.getElementById('max-results');

    // Sidebar and modal elements
    const agentSidebar = document.getElementById('agent-sidebar');
    const toggleAgentBtn = document.getElementById('toggle-agent-btn');
    const toggleAgentSidebarBtn = document.getElementById('toggle-agent-sidebar-btn');
    const aboutLink = document.getElementById('about-link');
    const aboutModal = document.getElementById('about-modal');
    const modalClose = document.querySelector('.modal-close');
    const themeToggleBtn = document.getElementById('theme-toggle-btn');
    const clearMonitorBtn = document.getElementById('clear-monitor-btn');
    const logMonitor = document.getElementById('log-monitor');

    // Initialize statistics
    let searchCount = 0;
    let totalResponseTime = 0;
    let isSearching = false;

    // Event Listeners
    if (searchBtn) {
        searchBtn.addEventListener('click', performSearch);
    }

    if (searchInput) {
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                performSearch();
            }
        });
    }

    if (toggleAgentBtn) {
        toggleAgentBtn.addEventListener('click', toggleAgentSidebar);
    }

    if (toggleAgentSidebarBtn) {
        toggleAgentSidebarBtn.addEventListener('click', toggleAgentSidebar);
    }

    if (aboutLink) {
        aboutLink.addEventListener('click', function(e) {
            e.preventDefault();
            showAboutModal();
        });
    }

    if (modalClose) {
        modalClose.addEventListener('click', hideAboutModal);
    }

    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', toggleTheme);
    }

    if (clearMonitorBtn) {
        clearMonitorBtn.addEventListener('click', clearMonitor);
    }

    // Initialize the modal and sidebar state
    if (aboutModal) {
        aboutModal.style.display = 'none';
    }

    if (agentSidebar) {
        agentSidebar.classList.add('hidden');
    }

    // Click outside modal to close
    window.addEventListener('click', function(e) {
        if (aboutModal && e.target === aboutModal) {
            hideAboutModal();
        }
    });

    // Update initial stats
    updateStats();

    // Add initial log entry
    addLogEntry('System initialized');

    // Functions
    function performSearch() {
        const query = searchInput ? searchInput.value.trim() : '';

        if (!query) {
            addLogEntry('Please enter a search query', 'warning');
            return;
        }

        if (isSearching) {
            addLogEntry('Search already in progress...', 'warning');
            return;
        }

        // Show loading overlay
        const loadingOverlay = document.getElementById('loading-overlay');
        if (loadingOverlay) {
            loadingOverlay.style.display = 'flex';
        }

        // Clear previous results
        clearPreviousResults();

        // Update UI to show searching state
        isSearching = true;

        if (searchBtn) {
            searchBtn.disabled = true;
            searchBtn.textContent = 'Searching...';
        }

        addLogEntry(`Searching for: "${query}"`, 'info');

        const startTime = Date.now();

        // Make API request
        fetch('/api/search', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                query: query,
                max_results: getMaxResults()
            })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            return response.json();
        })
        .then(data => {
            const responseTime = (Date.now() - startTime) / 1000;

            searchCount++;
            totalResponseTime += responseTime;

            updateStats();

            addLogEntry(`Found ${data.total_found || 0} results in ${responseTime.toFixed(2)}s`, 'success');

            displayResults(data);
        })
        .catch(error => {
            console.error('Search error:', error);
            displayError(error.message);
            addLogEntry(`Search failed: ${error.message}`, 'error');
        })
        .finally(() => {
            isSearching = false;

            if (searchBtn) {
                searchBtn.disabled = false;
                searchBtn.textContent = 'Search';
            }

            // Hide loading overlay
            const loadingOverlay = document.getElementById('loading-overlay');
            if (loadingOverlay) {
                loadingOverlay.style.display = 'none';
            }
        });
    }

    function displayResults(data) {
        if (!resultsGrid || !noResults || !searchStatus) {
            console.error('Required DOM elements not found');
            return;
        }

        if (!data.results || data.results.length === 0) {
            // Show no results message
            resultsGrid.innerHTML = '';
            noResults.style.display = 'block';
            searchStatus.innerHTML = `
                <div class="search-status-message">
                    <p>No datasets found for query: "${data.query || ''}"</p>
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
                    <h3>Results for: "${data.query || ''}"</h3>
                </div>
                <div class="search-status-details">
                    <p>${data.results.length} of ${data.total_found || data.results.length} datasets shown</p>
                    <p class="search-time">Search time: ${data.search_time ? data.search_time.toFixed(2) : '0.00'}s</p>
                </div>
            </div>
        `;

        // Build results HTML
        let resultsHTML = '';

        data.results.forEach((result, index) => {
            resultsHTML += `
                <div class="result-card">
                    <div class="result-header">
                        <h3><a href="https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi?acc=${result.geo_id}" target="_blank">${result.geo_id}</a></h3>
                        ${result.relevance_score ? `<span class="relevance-score">${Math.round(result.relevance_score * 100)}%</span>` : ''}
                    </div>
                    <h4>${result.title || 'Untitled'}</h4>
                    <div class="result-meta">
                        ${result.organism ? `<div><span>Organism:</span> ${result.organism}</div>` : ''}
                        ${result.sample_count ? `<div><span>Samples:</span> ${result.sample_count}</div>` : ''}
                        ${result.publication_date ? `<div><span>Date:</span> ${result.publication_date}</div>` : ''}
                    </div>
                    ${result.summary ? `
                    <div class="result-summary">
                        <h5>Summary:</h5>
                        <p>${result.summary}</p>
                    </div>
                    ` : ''}
                </div>
            `;
        });

        resultsGrid.innerHTML = resultsHTML;
    }

    function displayError(message) {
        if (!resultsGrid || !noResults || !searchStatus) {
            console.error('Required DOM elements not found for error display');
            return;
        }

        // Hide no results message
        noResults.style.display = 'none';

        // Clear results grid
        resultsGrid.innerHTML = '';

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
    }

    function clearPreviousResults() {
        if (resultsGrid) {
            resultsGrid.innerHTML = '';
        }

        if (searchStatus) {
            searchStatus.innerHTML = `
                <div class="search-status-message">
                    <p>Searching database...</p>
                </div>
            `;
        }

        if (noResults) {
            noResults.style.display = 'none';
        }
    }

    function getMaxResults() {
        if (!maxResults) return 10;

        const value = maxResults.value;
        if (value === '1000') {
            addLogEntry('Loading all results may take longer...', 'warning');
        }

        return parseInt(value || '10');
    }

    function toggleAgentSidebar() {
        if (agentSidebar) {
            agentSidebar.classList.toggle('hidden');
        }
    }

    function showAboutModal() {
        if (aboutModal) {
            aboutModal.style.display = 'flex';
        }
    }

    function hideAboutModal() {
        if (aboutModal) {
            aboutModal.style.display = 'none';
        }
    }

    function toggleTheme() {
        document.body.classList.toggle('dark-theme');

        if (themeToggleBtn) {
            themeToggleBtn.textContent = document.body.classList.contains('dark-theme') ? '☀️' : '🌙';
        }
    }

    function clearMonitor() {
        if (logMonitor) {
            logMonitor.innerHTML = '<div class="log-entry">System initialized</div>';
        }
    }

    function addLogEntry(message, type = 'info') {
        if (!logMonitor) return;

        const entry = document.createElement('div');
        entry.className = `log-entry log-${type}`;
        entry.textContent = message;

        logMonitor.insertBefore(entry, logMonitor.firstChild);

        // Keep log size manageable
        if (logMonitor.children.length > 50) {
            logMonitor.removeChild(logMonitor.lastChild);
        }
    }

    function updateStats() {
        const queryCount = document.getElementById('query-count');
        const avgResponseTime = document.getElementById('avg-response-time');

        if (queryCount) {
            queryCount.textContent = searchCount.toString();
        }

        if (avgResponseTime) {
            const avg = searchCount > 0 ? (totalResponseTime / searchCount).toFixed(2) : '0.00';
            avgResponseTime.textContent = `${avg}s`;
        }
    }
});
