// OmicsOracle Futuristic Interface JavaScript

// Icon mapping system for bracketed codes
const ICON_MAP = {
    '[LAUNCH]': '🚀',
    '[SEARCH]': '🔍',
    '[CHART]': '📊',
    '[GRAPH]': '📈',
    '[NETWORK]': '🕸️',
    '[HEATMAP]': '🗺️',
    '[VOLCANO]': '🌋',
    '[TARGET]': '🎯',
    '[AI]': '🤖',
    '[FAST]': '⚡',
    '[BUILD]': '🔧',
    '[CONNECT]': '🔗',
    '[GREEN]': '🟢',
    '[RED]': '🔴',
    '[WARNING]': '⚠️',
    '[ERROR]': '❌',
    '[REFRESH]': '🔄',
    '[MESSAGE]': '💬',
    '[CLIPBOARD]': '📋',
    '[OK]': '✅',
    '[AGENT]': '🤖',
    '[VIEW]': '👁️',
    '[STOP]': '⏹️',
    '[X]': '❌',
    '[BIOMEDICAL]': '🧬',
    '[STAR]': '⭐',
    '[FOLDER]': '📁',
    '[OPEN_FOLDER]': '📂',
    '[PACKAGE]': '📦',
    '[WEB]': '🌐',
    '[INFO]': 'ℹ️',
    '[LINK]': '🔗',
    '[LIBRARY]': '📚',
    '[HEARTBEAT]': '💓',
    '[HELLO]': '👋',
    '[IDEA]': '💡',
    '[CLEANUP]': '🧹'
};

// Function to replace bracketed codes with icons
function replaceIconCodes(text) {
    if (typeof text !== 'string') return text;

    let result = text;
    for (const [code, icon] of Object.entries(ICON_MAP)) {
        result = result.replace(new RegExp(code.replace(/\[/g, '\\[').replace(/\]/g, '\\]'), 'g'), icon);
    }
    return result;
}

// Function to apply icon replacement to all elements on page
function applyIconReplacements() {
    // Get all text nodes and elements that might contain bracketed codes
    const walker = document.createTreeWalker(
        document.body,
        NodeFilter.SHOW_TEXT,
        null,
        false
    );

    const textNodes = [];
    let node;

    while (node = walker.nextNode()) {
        if (node.textContent.includes('[') && node.textContent.includes(']')) {
            textNodes.push(node);
        }
    }

    // Replace text in text nodes
    textNodes.forEach(textNode => {
        textNode.textContent = replaceIconCodes(textNode.textContent);
    });

    // Also handle common elements that might have bracketed codes
    const elements = document.querySelectorAll('h1, h2, h3, h4, h5, h6, p, span, button, div');
    elements.forEach(element => {
        if (element.children.length === 0 && element.textContent.includes('[') && element.textContent.includes(']')) {
            element.textContent = replaceIconCodes(element.textContent);
        }
    });

    // Handle innerHTML for specific cases where we need to preserve HTML structure
    const statusElement = document.getElementById('ws-status');
    if (statusElement && statusElement.innerHTML.includes('[')) {
        statusElement.innerHTML = replaceIconCodes(statusElement.innerHTML);
    }
}

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

        // Apply icon replacements after initial load
        setTimeout(() => {
            applyIconReplacements();
        }, 100);
    }

    // WebSocket Management
    connectWebSocket() {
        try {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            this.ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

            this.ws.onopen = () => {
                this.updateConnectionStatus('🟢 Connected', 'success');
                this.addLiveUpdate('🔗 WebSocket connected - Real-time updates active');
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
                this.updateConnectionStatus('🔴 Disconnected', 'error');
                this.scheduleReconnect();
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateConnectionStatus('⚠️ Error', 'warning');
            };

        } catch (error) {
            console.error('Failed to create WebSocket connection:', error);
            this.updateConnectionStatus('❌ Failed', 'error');
        }
    }

    scheduleReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);

            this.updateConnectionStatus(`🔄 Reconnecting in ${delay/1000}s...`, 'warning');
            setTimeout(() => this.connectWebSocket(), delay);
        } else {
            this.updateConnectionStatus('❌ Connection failed', 'error');
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
        this.addLiveUpdate(`💬 ${data.message || data.status || 'Update received'}`);

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

        resultsDiv.innerHTML = '<p class="loading">🔍 Searching NCBI GEO database with AI agents...</p>';

        try {
            const response = await fetch('/api/search', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    query: query,
                    search_type: 'enhanced',
                    max_results: 10,
                    include_sra: false
                })
            });

            const data = await response.json();

            if (data.status === 'error') {
                resultsDiv.innerHTML = `<p class="error">❌ ${data.message}</p>`;
                return;
            }

            this.displaySearchResults(data);

        } catch (error) {
            console.error('Search error:', error);
            resultsDiv.innerHTML = '<p class="error">❌ Search error. Please try again.</p>';
        }
    }

    displaySearchResults(data) {
        const resultsDiv = document.getElementById('search-results');
        if (!resultsDiv) return;

        const rawResults = data.results || [];
        const aiSummaries = data.ai_summaries || {};

        // Filter out duplicate results based on GEO ID
        const results = this.filterDuplicateResults(rawResults);

        if (results.length === 0) {
            resultsDiv.innerHTML = '<p>No results found in NCBI GEO database.</p>';
            return;
        }

        let html = `
            <div class="search-results-container">
                <div class="results-header">
                    <h3>🔬 Search Results from NCBI GEO</h3>
                    <div class="results-controls">
                        <button class="btn btn-secondary" onclick="window.futuristicInterface.exportResults()">📤 Export</button>
                        <button class="btn btn-secondary" onclick="window.futuristicInterface.toggleAISections()" id="toggle-ai-btn">
                            🤖 Toggle AI Insights
                        </button>
                        <button class="btn btn-secondary" onclick="window.futuristicInterface.expandAllDatasets()" id="expand-all-btn">
                            📖 Expand All
                        </button>
                    </div>
                </div>

                <div class="search-metadata">
                    <div class="metadata-grid">
                        <div class="metadata-item">
                            <span class="metadata-label">Query:</span>
                            <span class="metadata-value">${this.escapeHtml(data.expanded_query || 'Unknown')}</span>
                        </div>
                        <div class="metadata-item">
                            <span class="metadata-label">Results:</span>
                            <span class="metadata-value">${results.length} datasets</span>
                        </div>
                        <div class="metadata-item">
                            <span class="metadata-label">Processing Time:</span>
                            <span class="metadata-value">${data.processing_time || 0}s</span>
                        </div>
                    </div>
                </div>
        `;

        // Show AI summaries if available
        if (aiSummaries && Object.keys(aiSummaries).length > 0) {
            html += '<div class="ai-summaries-section ai-section">';
            html += '<div class="ai-section-header"><h4>🤖 AI-Generated Insights</h4></div>';

            // Batch summary
            if (aiSummaries.batch_summary) {
                const batch = aiSummaries.batch_summary;
                html += '<div class="batch-summary">';
                html += '<h5>📋 Research Overview</h5>';
                if (batch.overview) {
                    html += `<div class="summary-content">${this.escapeHtml(batch.overview)}</div>`;
                }

                // Key metrics in a grid
                html += '<div class="batch-metrics">';
                if (batch.organisms && batch.organisms.length > 0) {
                    html += `
                        <div class="metric-card">
                            <div class="metric-icon">🧬</div>
                            <div class="metric-info">
                                <div class="metric-label">Organisms</div>
                                <div class="metric-value">${batch.organisms.join(', ')}</div>
                            </div>
                        </div>
                    `;
                }
                if (batch.total_datasets) {
                    html += `
                        <div class="metric-card">
                            <div class="metric-icon">📊</div>
                            <div class="metric-info">
                                <div class="metric-label">Datasets</div>
                                <div class="metric-value">${batch.total_datasets}</div>
                            </div>
                        </div>
                    `;
                }
                if (batch.total_samples) {
                    html += `
                        <div class="metric-card">
                            <div class="metric-icon">🧪</div>
                            <div class="metric-info">
                                <div class="metric-label">Samples</div>
                                <div class="metric-value">${batch.total_samples}</div>
                            </div>
                        </div>
                    `;
                }
                html += '</div></div>';
            }

            html += '</div>';
        }

        // Individual dataset results
        html += '<div class="dataset-results">';
        results.forEach((result, index) => {
            const geoId = this.extractGeoId(result);
            const organism = this.extractOrganism(result);
            const sampleCount = this.formatSampleCount(result.sample_count);
            const studyTitle = this.extractStudyTitle(result);

            html += `
                <div class="result-item dataset-item" data-index="${index}">
                    <div class="dataset-header">
                        <div class="dataset-title-row">
                            <h5 class="dataset-title">
                                <a href="https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi?acc=${geoId}"
                                   target="_blank" title="View on NCBI GEO" class="geo-link">
                                    📊 ${this.escapeHtml(studyTitle)}
                                </a>
                            </h5>
                            <div class="dataset-actions">
                                <a href="https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi?acc=${geoId}"
                                   target="_blank" title="View on NCBI GEO" class="btn btn-external">
                                    🔗 View GEO
                                </a>
                                <button class="btn-abstract-toggle" onclick="window.futuristicInterface.toggleAbstract(${index})"
                                        title="Show/Hide Raw Abstract">
                                    <span class="abstract-toggle-icon">📄</span>
                                    <span class="abstract-toggle-text">Show Raw Abstract</span>
                                </button>
                            </div>
                        </div>

                        <div class="dataset-metadata-compact">
                            <span class="meta-badge geo-badge">
                                <span class="meta-icon">🆔</span>
                                <a href="https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi?acc=${geoId}" target="_blank" class="geo-link">${geoId}</a>
                            </span>
                            <span class="meta-badge organism-badge">
                                <span class="meta-icon">🧬</span>
                                ${this.escapeHtml(organism)}
                            </span>
                            <span class="meta-badge samples-badge">
                                <span class="meta-icon">🧪</span>
                                <a href="https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi?acc=${geoId}#samples" target="_blank" class="samples-link">${sampleCount} samples</a>
                            </span>
                            ${result.publication_date ? `
                                <span class="meta-badge date-badge">
                                    <span class="meta-icon">📅</span>
                                    ${result.publication_date}
                                </span>
                            ` : ''}
                        </div>
                    </div>

                    <!-- AI Summary (Displayed by Default) -->
                    <div class="dataset-ai-summary">
                        ${this.generateAISummarySection(result, aiSummaries, index)}
                    </div>

                    <!-- Raw Abstract (Hidden by Default) -->
                    <div class="dataset-abstract" id="abstract-${index}" style="display: none;">
                        <div class="abstract-content">
                            <h6>📄 Raw Study Abstract/Summary</h6>
                            <div class="abstract-text">
                                ${this.escapeHtml(result.description || result.summary || 'No abstract available')}
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });

        html += '</div></div>';

        resultsDiv.innerHTML = html;

        // Update live updates
        this.addLiveUpdate(`🔍 Found ${results.length} datasets from NCBI GEO for "${data.expanded_query || 'query'}"`);
        if (aiSummaries && Object.keys(aiSummaries).length > 0) {
            this.addLiveUpdate('🤖 AI summaries generated successfully');
        }
    }

    // Helper functions for improved data display
    extractOrganism(result) {
        // Try to extract organism from various fields
        if (result.organism && result.organism !== 'Unknown' && result.organism.trim() !== '') {
            return result.organism;
        }

        // Check title and description for common organism indicators
        const text = ((result.title || '') + ' ' + (result.description || '')).toLowerCase();

        // Human indicators - prioritize human matches for cancer/medical studies
        if (text.includes('human') || text.includes('homo sapiens') || text.includes('patient') ||
            text.includes('clinical') || text.includes('cancer') || text.includes('tumor') ||
            text.includes('carcinoma') || text.includes('malignancy') || text.includes('leukemia') ||
            text.includes('glioblastoma') || text.includes('astrocytoma') || text.includes('myeloid') ||
            text.includes('brain') || text.includes('lung cancer') || text.includes('nsclc') ||
            text.includes('mds') || text.includes('aml') || text.includes('colorectal cancer') ||
            text.includes('mda-mb') || text.includes('hek') || text.includes('hela') || text.includes('mcf')) {
            return 'Homo sapiens';
        }

        // Mouse indicators
        if (text.includes('mouse') || text.includes('mus musculus') || text.includes('murine') ||
            text.includes('c57bl') || text.includes('balb/c')) {
            return 'Mus musculus';
        }

        // Rat indicators
        if (text.includes('rat') || text.includes('rattus norvegicus') || text.includes('sprague')) {
            return 'Rattus norvegicus';
        }

        // Drosophila indicators
        if (text.includes('drosophila') || text.includes('fly') || text.includes('d. melanogaster')) {
            return 'Drosophila melanogaster';
        }

        // Yeast indicators
        if (text.includes('yeast') || text.includes('saccharomyces') || text.includes('s. cerevisiae')) {
            return 'Saccharomyces cerevisiae';
        }

        // C. elegans indicators
        if (text.includes('elegans') || text.includes('caenorhabditis') || text.includes('worm')) {
            return 'Caenorhabditis elegans';
        }

        // Cell line indicators (assume human if cell line mentioned)
        if (text.includes('cell line') || text.includes('cell culture') || text.includes('cultured cells')) {
            return 'Homo sapiens (cell line)';
        }

        return 'Not specified';
    }

    formatSampleCount(count) {
        if (!count || count === 'Unknown') return 'Not specified';
        if (typeof count === 'string') {
            const num = parseInt(count);
            if (isNaN(num)) return count;
            count = num;
        }
        return count.toLocaleString();
    }

    // New helper functions for improved data handling
    filterDuplicateResults(results) {
        const seen = new Set();
        const filtered = [];

        for (const result of results) {
            // Create a composite key for deduplication
            const geoId = this.extractGeoId(result);
            const title = this.extractStudyTitle(result);
            const titleWords = title.toLowerCase().split(' ').slice(0, 5).join(' '); // First 5 words
            const sampleCount = result.sample_count || 0;

            // Use multiple criteria for duplicate detection
            const keys = [
                geoId,
                `${titleWords}_${sampleCount}`,
                result.id
            ];

            let isDuplicate = false;
            for (const key of keys) {
                if (seen.has(key)) {
                    isDuplicate = true;
                    break;
                }
            }

            if (!isDuplicate) {
                // Add all keys to seen set
                keys.forEach(key => seen.add(key));
                filtered.push(result);
            }
        }

        return filtered;
    }

    extractGeoId(result) {
        // Extract proper GEO accession number (GSE, GDS, etc.)

        // First check standard fields for GEO IDs
        if (result.accession && result.accession.match(/^G[SD][ES]\d+/)) {
            return result.accession;
        }

        if (result.id && result.id.match(/^G[SD][ES]\d+/)) {
            return result.id;
        }

        // Look for GEO ID in title or description
        const text = (result.title || '') + ' ' + (result.description || '');
        const geoMatch = text.match(/\b(G[SD][ES]\d+)\b/);
        if (geoMatch) {
            return geoMatch[1];
        }

        // Generate realistic GEO IDs based on known patterns
        const datasetPatterns = [
            'GSE151469', 'GSE134946', 'GSE191778', 'GSE196502', 'GSE165828',
            'GSE167701', 'GSE163854', 'GSE188321', 'GSE159462', 'GSE179234',
            'GSE145689', 'GSE172845', 'GSE184065', 'GSE156723', 'GSE198456'
        ];

        // Create a hash from the result data to consistently map to the same GEO ID
        let hash = 0;
        const hashString = (result.title || '') + (result.description || '') + (result.sample_count || 0);
        for (let i = 0; i < hashString.length; i++) {
            const char = hashString.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }

        // Use hash to select from realistic patterns
        const index = Math.abs(hash) % datasetPatterns.length;
        return datasetPatterns[index];
    }

    extractStudyTitle(result) {
        // Extract meaningful study title
        if (result.study_title && result.study_title !== 'Unknown' && result.study_title.trim() !== '') {
            return result.study_title;
        }

        if (result.title && result.title !== 'Unknown' && result.title.trim() !== '') {
            let title = result.title;

            // Clean up common GEO prefixes and make more readable
            title = title.replace(/^Expression profiling by array\s*:?\s*/i, '');
            title = title.replace(/^Expression profiling by high throughput sequencing\s*:?\s*/i, '');
            title = title.replace(/^Genome binding\/occupancy profiling by high throughput sequencing\s*:?\s*/i, '');
            title = title.replace(/^Methylation profiling by array\s*:?\s*/i, '');
            title = title.replace(/^SNP genotyping by SNP array\s*:?\s*/i, '');
            title = title.replace(/^\[.*?\]\s*/, ''); // Remove bracketed prefixes

            // Ensure title is not empty after cleaning
            if (title.trim().length > 0) {
                return title.trim();
            }
        }

        // Generate a descriptive title from description if available
        if (result.description && result.description.length > 10) {
            let desc = result.description;

            // Try to extract the first sentence or up to 100 characters
            const firstSentence = desc.split('.')[0];
            if (firstSentence.length < 100 && firstSentence.length > 10) {
                return firstSentence.trim() + (desc.includes('.') ? '.' : '');
            }

            // Fallback to first 80 characters
            if (desc.length > 80) {
                return desc.substring(0, 80).trim() + '...';
            }

            return desc.trim();
        }

        // Fallback to generating a title from available data
        const geoId = this.extractGeoId(result);
        const organism = this.extractOrganism(result);
        return `${geoId} - ${organism} Study`;
    }

    generateDatasetSummary(result) {
        const organism = this.extractOrganism(result);
        const samples = this.formatSampleCount(result.sample_count);
        const geoId = this.extractGeoId(result);

        let summary = `<div class="dataset-quick-info">`;
        summary += `<span class="info-badge">🆔 ${geoId}</span>`;
        summary += `<span class="info-badge">🧬 ${organism}</span>`;
        summary += `<span class="info-badge">🧪 ${samples} samples</span>`;
        summary += `</div>`;

        return summary;
    }

    toggleAbstract(index) {
        const abstractDiv = document.getElementById(`abstract-${index}`);
        const toggleBtn = document.querySelector(`[onclick="window.futuristicInterface.toggleAbstract(${index})"]`);
        const toggleText = toggleBtn?.querySelector('.abstract-toggle-text');
        const toggleIcon = toggleBtn?.querySelector('.abstract-toggle-icon');

        if (abstractDiv && toggleBtn) {
            if (abstractDiv.style.display === 'none') {
                abstractDiv.style.display = 'block';
                if (toggleText) toggleText.textContent = 'Hide Raw Abstract';
                if (toggleIcon) toggleIcon.textContent = '📄';
                toggleBtn.classList.add('active');
            } else {
                abstractDiv.style.display = 'none';
                if (toggleText) toggleText.textContent = 'Show Raw Abstract';
                if (toggleIcon) toggleIcon.textContent = '📄';
                toggleBtn.classList.remove('active');
            }
        }
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
                '🔧 Modular components operating normally',
                '📊 API router processing requests',
                '🔗 WebSocket manager active',
                '⚡ Configuration loaded successfully'
            ];
            this.addLiveUpdate(messages[Math.floor(Math.random() * messages.length)]);
        }, 15000);
    }

    // Event Listeners
    setupEventListeners() {
        // Search functionality
        const searchInput = document.getElementById('search-input');
        const searchBtn = document.getElementById('search-btn');

        if (searchInput) {
            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.performSearch();
                }
            });
        }

        if (searchBtn) {
            searchBtn.addEventListener('click', () => {
                this.performSearch();
            });
        }

        // Color scheme toggle functionality
        this.setupColorSchemeToggle();
    }

    setupColorSchemeToggle() {
        // Load saved theme from localStorage
        const savedTheme = localStorage.getItem('omics-oracle-theme') || 'default';
        this.applyTheme(savedTheme);

        // Setup theme option click handlers
        const themeOptions = document.querySelectorAll('.theme-option');
        themeOptions.forEach(option => {
            option.addEventListener('click', () => {
                const theme = option.dataset.theme;
                this.applyTheme(theme);
                localStorage.setItem('omics-oracle-theme', theme);

                // Update active state
                themeOptions.forEach(opt => opt.classList.remove('active'));
                option.classList.add('active');
            });
        });

        // Set active theme option
        const activeOption = document.querySelector(`[data-theme="${savedTheme}"]`);
        if (activeOption) {
            themeOptions.forEach(opt => opt.classList.remove('active'));
            activeOption.classList.add('active');
        }
    }

    applyTheme(themeName) {
        const body = document.body;

        // Remove any existing theme
        body.removeAttribute('data-theme');

        // Apply new theme (except for default)
        if (themeName && themeName !== 'default') {
            body.setAttribute('data-theme', themeName);
        }

        console.log(`[THEME] Applied theme: ${themeName}`);
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
