/**
 * OmicsOracle Modern Interface JavaScript
 * Enhanced search functionality with autocomplete, pagination, and data visualization
 */

// Global variables
let suggestionIndex = -1;
let suggestions = [];

// Utility function to safely escape HTML
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize enhanced search features when page loads
document.addEventListener('DOMContentLoaded', function() {
    loadQuickFilters();
    setupSearchInput();
    setupSearchHelpers();
    setupSearchForm();
});

// Load quick filter tags
async function loadQuickFilters() {
    try {
        const response = await fetch('/api/quick-filters');
        const data = await response.json();
        const filtersContainer = document.getElementById('quickFilters');

        if (data.filters && data.filters.length > 0) {
            data.filters.forEach(filter => {
                const tag = document.createElement('span');
                tag.className = 'filter-tag';
                tag.textContent = filter;
                tag.onclick = () => {
                    document.getElementById('query').value = filter;
                    document.getElementById('query').focus();
                };
                filtersContainer.appendChild(tag);
            });
        }
    } catch (error) {
        console.log('Quick filters not available');
    }
}

// Setup search input with autocomplete
function setupSearchInput() {
    const queryInput = document.getElementById('query');
    const suggestionsDiv = document.getElementById('searchSuggestions');

    queryInput.addEventListener('input', async function(e) {
        const query = e.target.value;
        if (query.length < 2) {
            hideSuggestions();
            return;
        }

        try {
            const response = await fetch(`/api/search-suggestions?q=${encodeURIComponent(query)}`);
            const data = await response.json();
            suggestions = data.suggestions || [];
            showSuggestions(suggestions);
        } catch (error) {
            console.log('Suggestions not available');
        }
    });

    queryInput.addEventListener('keydown', function(e) {
        if (e.key === 'ArrowDown') {
            e.preventDefault();
            suggestionIndex = Math.min(suggestionIndex + 1, suggestions.length - 1);
            highlightSuggestion();
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            suggestionIndex = Math.max(suggestionIndex - 1, -1);
            highlightSuggestion();
        } else if (e.key === 'Enter' && suggestionIndex >= 0) {
            e.preventDefault();
            selectSuggestion(suggestions[suggestionIndex]);
        } else if (e.key === 'Escape') {
            hideSuggestions();
        }
    });

    queryInput.addEventListener('blur', function() {
        // Delay hiding to allow clicks on suggestions
        setTimeout(hideSuggestions, 200);
    });
}

function showSuggestions(suggestions) {
    const suggestionsDiv = document.getElementById('searchSuggestions');
    if (suggestions.length === 0) {
        hideSuggestions();
        return;
    }

    suggestionsDiv.innerHTML = '';
    suggestions.forEach((suggestion, index) => {
        const item = document.createElement('div');
        item.className = 'suggestion-item';
        item.textContent = suggestion;
        item.onclick = () => selectSuggestion(suggestion);
        suggestionsDiv.appendChild(item);
    });

    suggestionsDiv.style.display = 'block';
    suggestionIndex = -1;
}

function hideSuggestions() {
    document.getElementById('searchSuggestions').style.display = 'none';
    suggestionIndex = -1;
}

function highlightSuggestion() {
    const items = document.querySelectorAll('.suggestion-item');
    items.forEach((item, index) => {
        item.classList.toggle('active', index === suggestionIndex);
    });
}

function selectSuggestion(suggestion) {
    document.getElementById('query').value = suggestion;
    hideSuggestions();
    document.getElementById('query').focus();
}

// Setup search helper links
function setupSearchHelpers() {
    document.getElementById('showExamples').addEventListener('click', showExampleSearches);
    document.getElementById('showHistory').addEventListener('click', showSearchHistory);
}

async function showExampleSearches() {
    try {
        const response = await fetch('/api/example-searches');
        const data = await response.json();
        showDropdown(data.examples, 'Example Searches');
    } catch (error) {
        console.log('Examples not available');
    }
}

async function showSearchHistory() {
    try {
        const response = await fetch('/api/search-history');
        const data = await response.json();
        if (data.history.length > 0) {
            showDropdown(data.history, 'Recent Searches');
        } else {
            alert('No recent searches found');
        }
    } catch (error) {
        console.log('Search history not available');
    }
}

async function refreshSearchHistory() {
    // Add current search query to history
    const currentQuery = document.getElementById('query').value;
    if (currentQuery && currentQuery.trim()) {
        try {
            const response = await fetch('/api/search-history', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ query: currentQuery.trim() })
            });
            
            if (response.ok) {
                console.log('Search query added to history:', currentQuery);
            }
        } catch (error) {
            console.log('Could not add search to history:', error);
        }
    }
}

function showDropdown(items, title) {
    // Remove existing dropdown
    const existing = document.querySelector('.search-dropdown');
    if (existing) existing.remove();

    const dropdown = document.createElement('div');
    dropdown.className = 'search-dropdown';
    dropdown.style.display = 'block';

    items.forEach(item => {
        const div = document.createElement('div');
        div.className = 'dropdown-item';
        div.textContent = item;
        div.onclick = () => {
            document.getElementById('query').value = item;
            dropdown.remove();
            document.getElementById('query').focus();
        };
        dropdown.appendChild(div);
    });

    // Position dropdown near the helpers
    const helpers = document.querySelector('.search-helpers');
    helpers.style.position = 'relative';
    helpers.appendChild(dropdown);

    // Auto-hide after 5 seconds
    setTimeout(() => {
        if (dropdown.parentNode) dropdown.remove();
    }, 5000);

    // Hide on click outside
    document.addEventListener('click', function hideDropdown(e) {
        if (!dropdown.contains(e.target) && !helpers.contains(e.target)) {
            dropdown.remove();
            document.removeEventListener('click', hideDropdown);
        }
    });
}

// Setup search form handler
function setupSearchForm() {
    document.getElementById('searchForm').addEventListener('submit', async function(e) {
        e.preventDefault();

        const searchBtn = document.getElementById('searchBtn');
        const results = document.getElementById('results');

        // Show loading state
        searchBtn.disabled = true;
        searchBtn.textContent = '🔄 Searching...';
        results.innerHTML = '<div class="loading">🔍 Searching datasets... Please wait.</div>';
        results.classList.add('show');

        try {
            const formData = new FormData(this);

            // Convert FormData to JSON for API
            const jsonData = {};
            for (let [key, value] of formData.entries()) {
                jsonData[key] = value;
            }

            const response = await fetch('/api/v1/search', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(jsonData)
            });

            const data = await response.json();

            if (response.ok) {
                displayResults(data);
                // Refresh search history after successful search
                await refreshSearchHistory();
            } else {
                displayError(data.error || 'Search failed');
            }

        } catch (error) {
            displayError('Network error: ' + error.message);
        } finally {
            searchBtn.disabled = false;
            searchBtn.textContent = '🔍 Search Datasets';
        }
    });
}

function displayResults(data) {
    const results = document.getElementById('results');

    if (data.results && data.results.length > 0) {
        // Debug logging
        console.log('Displaying results:', data.results.length, 'items');
        console.log('First result sample:', data.results[0]);

        // Extract pagination info
        const pagination = data.pagination || {};
        const totalCount = pagination.total_count || data.total_count || data.results.length;
        const displayedCount = data.results.length;
        const currentPage = pagination.page || 1;
        const totalPages = pagination.total_pages || 1;

        // Improved count display with pagination info
        let countMessage;
        if (totalPages > 1) {
            const startIndex = ((currentPage - 1) * pagination.page_size) + 1;
            const endIndex = Math.min(startIndex + displayedCount - 1, totalCount);
            countMessage = `✅ Showing ${startIndex}-${endIndex} of ${totalCount} datasets (Page ${currentPage} of ${totalPages})`;
        } else if (totalCount === displayedCount) {
            countMessage = `✅ Found ${totalCount} dataset${totalCount !== 1 ? 's' : ''}`;
        } else {
            countMessage = `✅ Showing ${displayedCount} of ${totalCount} datasets`;
        }

        let html = `<div class="success">${countMessage}</div>`;

        data.results.forEach((result, index) => {
            const globalIndex = ((currentPage - 1) * (pagination.page_size || 10)) + index + 1;

            // Debug log each result
            console.log(`Processing result ${index}:`, {
                id: result.id,
                title: result.title,
                hasMetadata: !!result.metadata,
                metadata: result.metadata
            });

            // Extract metadata from nested structure
            const metadata = result.metadata || {};
            const organism = metadata.organism || 'Unknown';
            const sampleCount = metadata.sample_count || 'Unknown';
            const summary = result.abstract || 'No summary available';
            const title = result.title || 'Untitled Dataset';

            // Create enhanced metadata badges
            let metaBadges = '';
            if (result.ai_enhanced || (metadata.ai_summary && metadata.ai_summary.brief)) {
                metaBadges += `<span class="meta-badge ai-enhanced">🤖 AI Enhanced</span>`;
            }
            if (organism && organism !== 'Unknown') {
                metaBadges += `<span class="meta-badge organism">${organism}</span>`;
            }
            if (sampleCount && sampleCount !== 'Unknown') {
                metaBadges += `<span class="meta-badge samples">${sampleCount} samples</span>`;
            }

            // Create action buttons
            const actionButtons = createActionButtons(result);

            html += `
                <div class="result-item" onclick="toggleResultExpansion(this)" data-geo-id="${result.id}" data-result-id="${result.id}">
                    <div class="result-number">${globalIndex}</div>
                    <div class="result-header">
                        <div class="result-title">
                            <span class="expand-icon">▶</span>
                            ${escapeHtml(title)}
                        </div>
                    </div>
                    <div class="result-meta">
                        ${metaBadges}
                        <span class="meta-badge">ID: ${result.id}</span>
                    </div>
                    <div class="result-summary collapsed">${escapeHtml(summary)}</div>

                    <div class="result-details">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <div class="detail-label">Dataset ID</div>
                                <div class="detail-value">${result.id}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Organism</div>
                                <div class="detail-value">${organism}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Sample Count</div>
                                <div class="detail-value">${sampleCount}</div>
                            </div>
                        </div>

                        <div class="result-actions">
                            ${actionButtons}
                        </div>
                    </div>
                </div>
            `;
        });

        // Add pagination controls if more than one page
        if (totalPages > 1) {
            html += createPaginationControls(pagination);
        }

        results.innerHTML = html;
    } else {
        results.innerHTML = '<div class="error">No datasets found for your query. Try different keywords.</div>';
    }
}

function createActionButtons(result) {
    let buttons = '';

    // View Samples button
    if (result.id && result.id !== 'unknown') {
        buttons += `<button class="btn-action primary" onclick="showSamples('${result.id}', event)">📋 View Samples</button>`;
    }

    // External links
    if (result.id && result.id.startsWith('GSE')) {
        buttons += `<a href="https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi?acc=${result.id}" target="_blank" class="btn-action">🔗 View on GEO</a>`;
    }

    // Save to favorites (placeholder)
    buttons += `<button class="btn-action" onclick="saveToFavorites('${result.id}', event)">⭐ Save</button>`;

    // Export (placeholder)
    buttons += `<button class="btn-action" onclick="exportResult('${result.id}', event)">📥 Export</button>`;

    return buttons;
}

function toggleResultExpansion(element) {
    // Prevent expansion when clicking action buttons
    if (event.target.closest('.result-actions') || event.target.closest('.btn-action')) {
        return;
    }

    element.classList.toggle('expanded');
    const summary = element.querySelector('.result-summary');
    summary.classList.toggle('collapsed');
}

function showSamples(geoId, event) {
    if (event) event.stopPropagation();

    // Show informative modal about sample viewer
    const modal = document.createElement('div');
    modal.className = 'sample-viewer-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>📋 Sample Viewer - Coming Soon</h3>
                <button onclick="closeSampleModal()" class="modal-close">✕</button>
            </div>
            <div class="modal-body">
                <p><strong>Dataset:</strong> ${geoId}</p>
                <p>The sample viewer will be implemented in the next phase and will include:</p>
                <ul>
                    <li>🔬 Individual sample details and metadata</li>
                    <li>📊 Sample group distributions and conditions</li>
                    <li>🏷️ Treatment vs control classifications</li>
                    <li>📈 Sample quality metrics and statistics</li>
                    <li>🔗 Direct links to raw data files</li>
                </ul>
                <p><em>This feature requires integration with the data reading module to access detailed GEO sample information.</em></p>
            </div>
            <div class="modal-footer">
                <button onclick="closeSampleModal()" class="btn-action">Got it</button>
            </div>
        </div>
        <div class="modal-backdrop" onclick="closeSampleModal()"></div>
    `;

    document.body.appendChild(modal);
}

function closeSampleModal() {
    const modal = document.querySelector('.sample-viewer-modal');
    if (modal) {
        modal.remove();
    }
}

function saveToFavorites(geoId, event) {
    if (event) event.stopPropagation();

    // Placeholder for favorites functionality
    alert(`Saved ${geoId} to favorites! (Feature coming soon)`);
}

function exportResult(geoId, event) {
    if (event) event.stopPropagation();

    // Show export options
    const exportMenu = document.createElement('div');
    exportMenu.className = 'export-menu';
    exportMenu.innerHTML = `
        <div class="export-header">Export ${geoId}</div>
        <button onclick="exportSingleDataset('${geoId}', 'csv', event)">📄 CSV Format</button>
        <button onclick="exportSingleDataset('${geoId}', 'json', event)">📋 JSON Format</button>
        <button onclick="exportAllResults('csv', event)">📊 All Results (CSV)</button>
        <button onclick="exportAllResults('json', event)">📋 All Results (JSON)</button>
        <button onclick="closeExportMenu(event)">❌ Cancel</button>
    `;

    // Position menu near the button
    const button = event.target;
    const rect = button.getBoundingClientRect();
    exportMenu.style.position = 'fixed';
    exportMenu.style.top = rect.bottom + 'px';
    exportMenu.style.left = rect.left + 'px';
    exportMenu.style.zIndex = '1000';

    document.body.appendChild(exportMenu);

    // Close menu when clicking outside
    setTimeout(() => {
        document.addEventListener('click', function closeOnClickOutside(e) {
            if (!exportMenu.contains(e.target)) {
                closeExportMenu();
                document.removeEventListener('click', closeOnClickOutside);
            }
        });
    }, 100);
}

function exportSingleDataset(geoId, format, event) {
    if (event) event.stopPropagation();

    // Find the dataset in current results
    const resultElement = document.querySelector(`[data-geo-id="${geoId}"]`);
    if (!resultElement) {
        alert('Dataset not found in current results');
        closeExportMenu();
        return;
    }

    // Extract data from the result element
    const title = resultElement.querySelector('.result-title').textContent.replace('▶', '').trim();
    const summary = resultElement.querySelector('.result-summary').textContent;
    const organism = resultElement.querySelector('.detail-value:nth-of-type(2)')?.textContent || 'Unknown';
    const sampleCount = resultElement.querySelector('.detail-value:nth-of-type(3)')?.textContent || 'Unknown';

    const datasetData = {
        id: geoId,
        title: title,
        abstract: summary,
        organism: organism,
        sample_count: sampleCount,
        export_date: new Date().toISOString(),
        export_source: 'OmicsOracle'
    };

    if (format === 'csv') {
        exportToCSV([datasetData], `${geoId}_dataset`);
    } else if (format === 'json') {
        exportToJSON(datasetData, `${geoId}_dataset`);
    }

    closeExportMenu();
}

function exportAllResults(format, event) {
    if (event) event.stopPropagation();

    // Extract all current results
    const resultElements = document.querySelectorAll('.result-item');
    const allData = [];

    resultElements.forEach(element => {
        const geoId = element.dataset.geoId;
        const title = element.querySelector('.result-title').textContent.replace('▶', '').trim();
        const summary = element.querySelector('.result-summary').textContent;
        const organism = element.querySelector('.detail-value:nth-of-type(2)')?.textContent || 'Unknown';
        const sampleCount = element.querySelector('.detail-value:nth-of-type(3)')?.textContent || 'Unknown';

        allData.push({
            id: geoId,
            title: title,
            abstract: summary,
            organism: organism,
            sample_count: sampleCount,
            result_number: element.querySelector('.result-number').textContent
        });
    });

    if (allData.length === 0) {
        alert('No results to export');
        closeExportMenu();
        return;
    }

    const exportData = {
        search_results: allData,
        total_results: allData.length,
        export_date: new Date().toISOString(),
        export_source: 'OmicsOracle',
        search_query: document.getElementById('query').value
    };

    if (format === 'csv') {
        exportToCSV(allData, 'omics_oracle_search_results');
    } else if (format === 'json') {
        exportToJSON(exportData, 'omics_oracle_search_results');
    }

    closeExportMenu();
}

function exportToCSV(data, filename) {
    if (!Array.isArray(data)) {
        data = [data];
    }

    if (data.length === 0) return;

    // Get headers from first object
    const headers = Object.keys(data[0]);

    // Create CSV content
    let csvContent = headers.join(',') + '\n';

    data.forEach(row => {
        const values = headers.map(header => {
            let value = row[header] || '';
            // Escape commas and quotes
            if (typeof value === 'string') {
                value = value.replace(/"/g, '""');
                if (value.includes(',') || value.includes('"') || value.includes('\n')) {
                    value = `"${value}"`;
                }
            }
            return value;
        });
        csvContent += values.join(',') + '\n';
    });

    // Download file
    downloadFile(csvContent, `${filename}.csv`, 'text/csv');
}

function exportToJSON(data, filename) {
    const jsonContent = JSON.stringify(data, null, 2);
    downloadFile(jsonContent, `${filename}.json`, 'application/json');
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.style.display = 'none';

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
}

function closeExportMenu(event) {
    if (event) event.stopPropagation();
    const menu = document.querySelector('.export-menu');
    if (menu) {
        menu.remove();
    }
}

function createPaginationControls(pagination) {
    const currentPage = pagination.page || 1;
    const totalPages = pagination.total_pages || 1;
    const hasPrevious = currentPage > 1;
    const hasNext = currentPage < totalPages;

    let paginationHtml = '<div class="pagination">';

    // Previous button
    paginationHtml += `<button onclick="goToPage(${currentPage - 1})" ${!hasPrevious ? 'disabled' : ''}>← Previous</button>`;

    // Page numbers (show current page and nearby pages)
    const startPage = Math.max(1, currentPage - 2);
    const endPage = Math.min(totalPages, currentPage + 2);

    if (startPage > 1) {
        paginationHtml += `<button onclick="goToPage(1)">1</button>`;
        if (startPage > 2) {
            paginationHtml += '<span class="pagination-info">...</span>';
        }
    }

    for (let i = startPage; i <= endPage; i++) {
        const activeClass = i === currentPage ? 'active' : '';
        paginationHtml += `<button class="${activeClass}" onclick="goToPage(${i})">${i}</button>`;
    }

    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            paginationHtml += '<span class="pagination-info">...</span>';
        }
        paginationHtml += `<button onclick="goToPage(${totalPages})">${totalPages}</button>`;
    }

    // Next button
    paginationHtml += `<button onclick="goToPage(${currentPage + 1})" ${!hasNext ? 'disabled' : ''}>Next →</button>`;

    // Page info
    paginationHtml += `<span class="pagination-info">Page ${currentPage} of ${totalPages}</span>`;

    paginationHtml += '</div>';

    return paginationHtml;
}

function goToPage(page) {
    document.getElementById('page').value = page;
    document.getElementById('searchForm').dispatchEvent(new Event('submit'));
}

function displayError(message) {
    const results = document.getElementById('results');
    results.innerHTML = `<div class="error">❌ Error: ${message}</div>`;
}
