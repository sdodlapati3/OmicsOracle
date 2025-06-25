import React, { useState, useEffect } from 'react';
import {
  ExclamationTriangleIcon,
  MagnifyingGlassIcon,
  SparklesIcon,
  XMarkIcon
} from '@heroicons/react/24/outline';
import QuerySuggestions from './QuerySuggestions';
import AlternativeQueries from './AlternativeQueries';

interface SearchResult {
  id: string;
  title: string;
  summary: string;
  // Add other fields as needed
}

interface QueryFeedback {
  original_query: string;
  suggested_query: string;
  user_action: string;
  was_helpful: boolean;
  result_improvement?: number;
}

interface QuerySuggestion {
  suggested_query: string;
  type: string;
  confidence: number;
  explanation: string;
  expected_results?: number;
}

interface SimilarQuery {
  query: string;
  result_count: number;
  success_score: number;
  similarity_score: number;
  common_entities: string[];
}

interface QueryRefinementContainerProps {
  originalQuery: string;
  searchResults: SearchResult[];
  onQueryRefined: (newQuery: string) => void;
  onFeedbackSubmitted: (feedback: QueryFeedback) => void;
  onDismiss?: () => void;
  className?: string;
  refinementData?: {
    suggestions: QuerySuggestion[];
    similar_queries: SimilarQuery[];
    analysis: {
      query_complexity: number;
      entity_count: number;
      recognized_entities: string[];
      potential_issues: string[];
    };
  };
}

const RefinementTrigger: React.FC<{
  resultCount: number;
  onShow: () => void;
  onDismiss: () => void;
}> = ({ resultCount, onShow, onDismiss }) => {
  if (resultCount === 0) {
    return (
      <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
        <div className="flex items-start justify-between">
          <div className="flex items-start space-x-3">
            <ExclamationTriangleIcon className="h-6 w-6 text-yellow-600 mt-0.5 flex-shrink-0" />
            <div>
              <h3 className="text-sm font-medium text-yellow-900 mb-1">
                No results found
              </h3>
              <p className="text-sm text-yellow-800 mb-3">
                Your search didn't return any results. We can help you refine your query to find relevant datasets.
              </p>
              <button
                onClick={onShow}
                className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-yellow-600 hover:bg-yellow-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-500"
              >
                <SparklesIcon className="h-4 w-4 mr-2" />
                Get Query Suggestions
              </button>
            </div>
          </div>
          <button
            onClick={onDismiss}
            className="text-yellow-400 hover:text-yellow-600"
          >
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>
      </div>
    );
  }

  if (resultCount < 10) {
    return (
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
        <div className="flex items-start justify-between">
          <div className="flex items-start space-x-3">
            <MagnifyingGlassIcon className="h-6 w-6 text-blue-600 mt-0.5 flex-shrink-0" />
            <div>
              <h3 className="text-sm font-medium text-blue-900 mb-1">
                Limited results found
              </h3>
              <p className="text-sm text-blue-800 mb-3">
                We found {resultCount} result{resultCount !== 1 ? 's' : ''}, but you might find more relevant datasets with a refined search.
              </p>
              <button
                onClick={onShow}
                className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <SparklesIcon className="h-4 w-4 mr-2" />
                Improve Search
              </button>
            </div>
          </div>
          <button
            onClick={onDismiss}
            className="text-blue-400 hover:text-blue-600"
          >
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>
      </div>
    );
  }

  return null;
};

export const QueryRefinementContainer: React.FC<QueryRefinementContainerProps> = ({
  originalQuery,
  searchResults,
  onQueryRefined,
  onFeedbackSubmitted,
  onDismiss,
  className = '',
  refinementData,
}) => {
  const [showRefinement, setShowRefinement] = useState(false);
  const [activeTab, setActiveTab] = useState<'suggestions' | 'alternatives'>('suggestions');

  const resultCount = searchResults.length;
  const shouldShowTrigger = resultCount < 10;

  useEffect(() => {
    // Auto-show refinement for zero results if we have data
    if (resultCount === 0 && refinementData) {
      setShowRefinement(true);
    }
  }, [originalQuery, resultCount, refinementData]);

  const handleShowRefinement = () => {
    setShowRefinement(true);
  };

  const handleDismissRefinement = () => {
    setShowRefinement(false);
    onDismiss?.();
  };

  const handleSuggestionClick = (suggestion: QuerySuggestion) => {
    onQueryRefined(suggestion.suggested_query);

    // Submit feedback
    onFeedbackSubmitted({
      original_query: originalQuery,
      suggested_query: suggestion.suggested_query,
      user_action: 'suggestion_accepted',
      was_helpful: true,
    });
  };

  const handleSimilarQueryClick = (query: SimilarQuery) => {
    onQueryRefined(query.query);

    // Submit feedback
    onFeedbackSubmitted({
      original_query: originalQuery,
      suggested_query: query.query,
      user_action: 'similar_query_selected',
      was_helpful: true,
    });
  };

  // Get data from props
  const suggestions: QuerySuggestion[] = refinementData?.suggestions || [];
  const similarQueries: SimilarQuery[] = refinementData?.similar_queries || [];

  if (!shouldShowTrigger && !showRefinement) {
    return null;
  }

  return (
    <div className={`query-refinement-container ${className}`}>
      {/* Trigger component when refinement is not shown */}
      {!showRefinement && shouldShowTrigger && (
        <RefinementTrigger
          resultCount={resultCount}
          onShow={handleShowRefinement}
          onDismiss={handleDismissRefinement}
        />
      )}

      {/* Main refinement interface */}
      {showRefinement && (
        <div className="bg-white border border-gray-200 rounded-lg shadow-sm overflow-hidden">
          {/* Header */}
          <div className="bg-gradient-to-r from-blue-50 to-indigo-50 px-6 py-4 border-b border-gray-200">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <SparklesIcon className="h-6 w-6 text-blue-600" />
                <div>
                  <h3 className="text-lg font-medium text-gray-900">
                    Query Refinement
                  </h3>
                  <p className="text-sm text-gray-600">
                    We've analyzed your query "{originalQuery}" and generated suggestions to help you find more relevant results.
                  </p>
                </div>
              </div>
              <button
                onClick={handleDismissRefinement}
                className="text-gray-400 hover:text-gray-600 transition-colors"
              >
                <XMarkIcon className="h-6 w-6" />
              </button>
            </div>
          </div>

          {/* Content */}
          <div className="p-6">
            {/* Tab Navigation */}
            <div className="flex space-x-1 mb-6 bg-gray-100 rounded-lg p-1">
              <button
                onClick={() => setActiveTab('suggestions')}
                className={`flex-1 px-4 py-2 text-sm font-medium text-center rounded-lg transition-colors ${
                  activeTab === 'suggestions'
                    ? 'bg-white text-blue-700 shadow-sm'
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                Query Suggestions ({suggestions.length})
              </button>
              <button
                onClick={() => setActiveTab('alternatives')}
                className={`flex-1 px-4 py-2 text-sm font-medium text-center rounded-lg transition-colors ${
                  activeTab === 'alternatives'
                    ? 'bg-white text-blue-700 shadow-sm'
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                Similar Queries ({similarQueries.length})
              </button>
            </div>

            {/* Tab Content */}
            {activeTab === 'suggestions' && (
              <QuerySuggestions
                suggestions={suggestions}
                onSuggestionApplied={handleSuggestionClick}
                onFeedbackSubmitted={(suggestion, helpful) => {
                  onFeedbackSubmitted({
                    original_query: originalQuery,
                    suggested_query: suggestion.suggested_query,
                    user_action: helpful ? 'thumbs_up' : 'thumbs_down',
                    was_helpful: helpful,
                  });
                }}
                isLoading={false}
              />
            )}

            {activeTab === 'alternatives' && (
              <AlternativeQueries
                similarQueries={similarQueries}
                onQuerySelected={(queryText) => {
                  const queryObj = similarQueries.find(q => q.query === queryText);
                  if (queryObj) {
                    handleSimilarQueryClick(queryObj);
                  }
                }}
                isLoading={false}
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default QueryRefinementContainer;
