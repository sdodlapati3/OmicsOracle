import React from 'react';
import { ChevronRightIcon } from '@heroicons/react/24/outline';
import type { ResultsListProps, SearchResult } from '../types';
import LoadingSpinner from './LoadingSpinner';

const ResultCard: React.FC<{ result: SearchResult; onClick?: () => void }> = ({
  result,
  onClick
}) => {
  return (
    <div
      className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow cursor-pointer"
      onClick={onClick}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center space-x-3">
            <h3 className="text-lg font-semibold text-gray-900">
              {result.title}
            </h3>
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
              {result.id}
            </span>
          </div>

          {result.summary && (
            <p className="mt-2 text-sm text-gray-600 line-clamp-3">
              {result.summary}
            </p>
          )}

          <div className="mt-3 flex flex-wrap gap-2">
            {result.organism && (
              <span className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-green-100 text-green-700">
                🧬 {result.organism}
              </span>
            )}
            {result.platform && (
              <span className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-purple-100 text-purple-700">
                🔬 {result.platform}
              </span>
            )}
            {result.sample_count && (
              <span className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-orange-100 text-orange-700">
                🧪 {result.sample_count} samples
              </span>
            )}
          </div>

          <div className="mt-3 text-xs text-gray-500 space-y-1">
            {result.submission_date && (
              <div>📅 Submitted: {new Date(result.submission_date).toLocaleDateString()}</div>
            )}
            {result.pubmed_id && (
              <div>📄 PubMed: {result.pubmed_id}</div>
            )}
          </div>
        </div>

        <ChevronRightIcon className="h-5 w-5 text-gray-400 flex-shrink-0 ml-4" />
      </div>
    </div>
  );
};

const ResultsList: React.FC<ResultsListProps> = ({
  results,
  loading = false,
  error = null,
  onResultClick
}) => {
  if (loading) {
    return (
      <div className="flex justify-center items-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-6">
        <div className="flex items-center">
          <svg className="h-5 w-5 text-red-400 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div>
            <h3 className="text-red-800 font-medium">Search Error</h3>
            <p className="text-red-700 text-sm mt-1">{error}</p>
          </div>
        </div>
      </div>
    );
  }

  if (results.length === 0) {
    return (
      <div className="text-center py-12">
        <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.172 16.172a4 4 0 015.656 0M9 12h6m-6 8h6m-6 8h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
        </svg>
        <h3 className="mt-4 text-lg font-medium text-gray-900">No results found</h3>
        <p className="mt-2 text-sm text-gray-500">
          Try adjusting your search terms or check for typos.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-900">
          Search Results ({results.length})
        </h2>
      </div>

      <div className="grid gap-4">
        {results.map((result) => (
          <ResultCard
            key={result.id}
            result={result}
            onClick={() => onResultClick?.(result)}
          />
        ))}
      </div>
    </div>
  );
};

export default ResultsList;
