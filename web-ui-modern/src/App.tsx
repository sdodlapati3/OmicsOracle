import { useState } from 'react';
import Layout from './components/Layout';
import SearchBar from './components/SearchBar';
import ResultsList from './components/ResultsList';
import QueryRefinementContainer from './components/search/QueryRefinementContainer';
import { searchGenes, getQuerySuggestions, submitQueryFeedback, performEnhancedSearch } from './services/api';
import type { SearchResult, AppState, QueryFeedback } from './types';

function App() {
  const [appState, setAppState] = useState<AppState>({
    searchResults: [],
    isLoading: false,
    error: null,
    searchQuery: '',
    totalCount: 0,
    currentPage: 1,
    showRefinement: false,
    refinementData: undefined,
  });

  const handleSearch = async (query: string) => {
    setAppState(prev => ({
      ...prev,
      isLoading: true,
      error: null,
      searchQuery: query,
      showRefinement: false,
      refinementData: undefined,
    }));

    try {
      const response = await searchGenes({
        query,
        per_page: 20,
        page: 1,
      });

      // Check if we got no results - trigger refinement
      if (response.results.length === 0) {
        try {
          const refinementData = await getQuerySuggestions(query, response.results.length);
          setAppState(prev => ({
            ...prev,
            searchResults: response.results,
            totalCount: response.total_count,
            isLoading: false,
            showRefinement: true,
            refinementData: refinementData,
          }));
        } catch (refinementError) {
          // If refinement fails, just show no results
          setAppState(prev => ({
            ...prev,
            searchResults: response.results,
            totalCount: response.total_count,
            isLoading: false,
            showRefinement: false,
          }));
        }
      } else {
        setAppState(prev => ({
          ...prev,
          searchResults: response.results,
          totalCount: response.total_count,
          isLoading: false,
          showRefinement: false,
        }));
      }
    } catch (error) {
      setAppState(prev => ({
        ...prev,
        error: error instanceof Error ? error.message : 'An unexpected error occurred',
        isLoading: false,
        searchResults: [],
        showRefinement: false,
      }));
    }
  };

  const handleResultClick = (result: SearchResult) => {
    console.log('Result clicked:', result);
  };

  const handleQueryRefined = async (newQuery: string) => {
    // Perform enhanced search with the refined query
    try {
      setAppState(prev => ({
        ...prev,
        isLoading: true,
        showRefinement: false,
      }));

      // First try enhanced search
      let response;
      try {
        response = await performEnhancedSearch(newQuery, {
          use_synonyms: true,
          expand_abbreviations: true,
          relaxed_matching: true,
        });
      } catch (enhancedError) {
        // If enhanced search fails, fall back to regular search
        console.warn('Enhanced search failed, falling back to regular search:', enhancedError);
        response = await searchGenes({
          query: newQuery,
          per_page: 20,
          page: 1,
        });
      }

      setAppState(prev => ({
        ...prev,
        searchResults: response.results,
        totalCount: response.total_count,
        searchQuery: newQuery,
        isLoading: false,
        showRefinement: false,
      }));
    } catch (error) {
      setAppState(prev => ({
        ...prev,
        error: error instanceof Error ? error.message : 'Enhanced search failed',
        isLoading: false,
        showRefinement: false,
      }));
    }
  };

  const handleFeedbackSubmitted = async (feedback: QueryFeedback) => {
    try {
      await submitQueryFeedback(feedback);
      console.log('Feedback submitted successfully');
    } catch (error) {
      console.error('Failed to submit feedback:', error);
    }
  };

  const handleRefinementDismiss = () => {
    setAppState(prev => ({
      ...prev,
      showRefinement: false,
    }));
  };

  return (
    <Layout>
      <div className="min-h-screen bg-gray-50">
        <div className="max-w-4xl mx-auto py-8 px-4">
          <div className="text-center mb-8">
            <h1 className="text-4xl font-bold text-gray-900 mb-4">
              🧬 OmicsOracle
            </h1>
            <p className="text-lg text-gray-600 max-w-2xl mx-auto">
              Search and analyze genomic datasets with natural language queries.
            </p>
          </div>

          <div className="bg-white rounded-lg shadow-md p-6 mb-8">
            <SearchBar
              onSearch={handleSearch}
              loading={appState.isLoading}
              placeholder="e.g., breast cancer gene expression, COVID-19 RNA-seq..."
            />

            {appState.searchQuery && (
              <div className="mt-4 text-sm text-gray-600">
                {appState.isLoading ? (
                  <div className="flex items-center">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary-600 mr-2"></div>
                    Searching for "{appState.searchQuery}"...
                  </div>
                ) : appState.error ? (
                  <div className="text-red-600">
                    ❌ Error: {appState.error}
                  </div>
                ) : appState.searchResults.length > 0 ? (
                  <div className="text-green-600">
                    ✅ Found {appState.totalCount} datasets for "{appState.searchQuery}"
                  </div>
                ) : appState.searchQuery ? (
                  <div className="text-orange-600">
                    No results found for "{appState.searchQuery}"
                    {appState.showRefinement && (
                      <span className="ml-2 text-blue-600">
                        - See suggestions below
                      </span>
                    )}
                  </div>
                ) : null}
              </div>
            )}

            {/* Query Refinement Container */}
            {appState.showRefinement && appState.refinementData && (
              <div className="mt-4">
                <QueryRefinementContainer
                  originalQuery={appState.searchQuery}
                  searchResults={appState.searchResults}
                  onQueryRefined={handleQueryRefined}
                  onFeedbackSubmitted={handleFeedbackSubmitted}
                  onDismiss={handleRefinementDismiss}
                  refinementData={appState.refinementData}
                />
              </div>
            )}
          </div>

          {(appState.searchResults.length > 0 || appState.isLoading || appState.error) && (
            <div className="bg-white rounded-lg shadow-md">
              <div className="p-6 border-b border-gray-200">
                <h2 className="text-xl font-semibold text-gray-900">
                  Search Results
                </h2>
              </div>
              <div className="p-6">
                <ResultsList
                  results={appState.searchResults}
                  loading={appState.isLoading}
                  error={appState.error}
                  onResultClick={handleResultClick}
                />
              </div>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}

export default App;
