// OmicsOracle UI Interactions
document.addEventListener('DOMContentLoaded', function() {
    // Sidebar toggle
    const toggleAgentBtn = document.getElementById('toggle-agent-btn');
    const toggleAgentSidebarBtn = document.getElementById('toggle-agent-sidebar-btn');
    const agentSidebar = document.getElementById('agent-sidebar');

    function toggleSidebar() {
        if (agentSidebar) {
            agentSidebar.classList.toggle('hidden');
        }
    }

    if (toggleAgentBtn) {
        toggleAgentBtn.addEventListener('click', toggleSidebar);
    }

    if (toggleAgentSidebarBtn) {
        toggleAgentSidebarBtn.addEventListener('click', toggleSidebar);
    }

    // About modal
    const aboutLink = document.getElementById('about-link');
    const aboutModal = document.getElementById('about-modal');
    const modalClose = document.querySelector('.modal-close');

    if (aboutLink) {
        aboutLink.addEventListener('click', function(e) {
            e.preventDefault();
            if (aboutModal) {
                aboutModal.style.display = 'flex';
            }
        });
    }

    if (modalClose) {
        modalClose.addEventListener('click', function() {
            if (aboutModal) {
                aboutModal.style.display = 'none';
            }
        });
    }

    // Close modal when clicking outside
    window.addEventListener('click', function(e) {
        if (e.target === aboutModal) {
            aboutModal.style.display = 'none';
        }
    });

    // Theme toggle
    const themeToggleBtn = document.getElementById('theme-toggle-btn');

    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', function() {
            document.body.classList.toggle('dark-mode');
            const isDarkMode = document.body.classList.contains('dark-mode');
            themeToggleBtn.textContent = isDarkMode ? '☀️' : '🌙';
        });
    }

    // Filter buttons
    const filterButtons = document.querySelectorAll('.filter-btn');

    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Remove active class from all buttons
            filterButtons.forEach(btn => btn.classList.remove('active'));
            // Add active class to clicked button
            this.classList.add('active');

            // Here you would filter results based on the selected filter
            const filterType = this.getAttribute('data-filter');
            console.log('Filter selected:', filterType);

            // Implementation of filtering logic would go here
        });
    });

    // Search functionality
    const searchBtn = document.getElementById('search-btn');
    const searchInput = document.getElementById('search-input');
    const resultsGrid = document.getElementById('results-grid');
    const noResults = document.getElementById('no-results');
    const loadingOverlay = document.getElementById('loading-overlay');
    const searchStatus = document.getElementById('search-status');

    function performSearch() {
        const query = searchInput?.value?.trim();
        if (!query) {
            alert('Please enter a search query');
            return;
        }

        // Show loading overlay
        if (loadingOverlay) {
            loadingOverlay.style.display = 'flex';
        }

        // Hide no results message
        if (noResults) {
            noResults.style.display = 'none';
        }

        // Clear previous results
        if (resultsGrid) {
            resultsGrid.innerHTML = '';
        }

        // Simulate search (in a real application, this would be an API call)
        setTimeout(() => {
            if (loadingOverlay) {
                loadingOverlay.style.display = 'none';
            }

            // For demonstration, show a success message
            if (searchStatus) {
                searchStatus.innerHTML = `
                    <div class="search-status-content">
                        <h3>Results for: "${query}"</h3>
                        <p>20 of 20 datasets shown</p>
                        <p>Search time: 3.14s</p>
                    </div>
                `;
                searchStatus.style.display = 'block';
            }

            // In a real application, you would populate resultsGrid with actual search results
            if (resultsGrid) {
                // Dummy result for demonstration
                resultsGrid.innerHTML = `
                    <div class="result-card">
                        <h3>GSE123456</h3>
                        <p class="relevance-score">90% relevant</p>
                        <h4>Sample Dataset Title</h4>
                        <div class="result-metadata">
                            <span>Samples: 42</span>
                            <span>Date: 2025-05-01</span>
                        </div>
                        <div class="result-summary">
                            <h5>Summary:</h5>
                            <p>This is a sample dataset summary that would contain information about the experiment.</p>
                        </div>
                    </div>
                `;
            }
        }, 1500);
    }

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

    // Initialize UI state
    if (agentSidebar) {
        agentSidebar.classList.add('hidden'); // Start with sidebar hidden
    }

    if (aboutModal) {
        aboutModal.style.display = 'none'; // Start with modal hidden
    }

    if (loadingOverlay) {
        loadingOverlay.style.display = 'none'; // Start with loading overlay hidden
    }

    console.log('[OK] UI interactions initialized');
});
