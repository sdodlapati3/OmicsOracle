import React, { useState } from 'react';
import {
  ClockIcon,
  ArrowTrendingUpIcon,
  CheckCircleIcon,
  DocumentTextIcon
} from '@heroicons/react/24/outline';

interface SimilarQuery {
  query: string;
  result_count: number;
  success_score: number;
  similarity_score: number;
  common_entities: string[];
}

interface AlternativeQueriesProps {
  similarQueries: SimilarQuery[];
  onQuerySelected: (query: string) => void;
  isLoading?: boolean;
  className?: string;
}

const SuccessIndicator: React.FC<{ score: number }> = ({ score }) => {
  const getScoreColor = (score: number) => {
    if (score >= 0.8) return 'text-green-600 bg-green-100';
    if (score >= 0.6) return 'text-yellow-600 bg-yellow-100';
    return 'text-red-600 bg-red-100';
  };

  const getScoreLabel = (score: number) => {
    if (score >= 0.8) return 'Excellent';
    if (score >= 0.6) return 'Good';
    return 'Fair';
  };

  return (
    <div className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getScoreColor(score)}`}>
      <CheckCircleIcon className="h-3 w-3 mr-1" />
      {getScoreLabel(score)}
    </div>
  );
};

const SimilarQueryCard: React.FC<{
  query: SimilarQuery;
  onSelect: () => void;
}> = ({ query, onSelect }) => {
  const [isHovered, setIsHovered] = useState(false);

  return (
    <div
      className={`
        border rounded-lg p-4 cursor-pointer transition-all duration-200
        ${isHovered ? 'border-blue-500 bg-blue-50 shadow-md' : 'border-gray-200 hover:border-gray-300'}
      `}
      onClick={onSelect}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <div className="space-y-3">
        {/* Query Text */}
        <div className="bg-white p-3 rounded border">
          <p className="font-mono text-sm text-gray-800 break-words">
            "{query.query}"
          </p>
        </div>

        {/* Metrics Row */}
        <div className="flex items-center justify-between text-sm">
          <div className="flex items-center space-x-4">
            <div className="flex items-center text-gray-600">
              <DocumentTextIcon className="h-4 w-4 mr-1" />
              <span>{query.result_count} results</span>
            </div>

            <div className="flex items-center text-gray-600">
              <ArrowTrendingUpIcon className="h-4 w-4 mr-1" />
              <span>{(query.similarity_score * 100).toFixed(0)}% similar</span>
            </div>
          </div>

          <SuccessIndicator score={query.success_score} />
        </div>

        {/* Common Entities */}
        {query.common_entities && query.common_entities.length > 0 && (
          <div className="flex flex-wrap gap-1">
            <span className="text-xs text-gray-500 mr-2">Common terms:</span>
            {query.common_entities.map((entity, index) => (
              <span
                key={index}
                className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-gray-100 text-gray-700"
              >
                {entity}
              </span>
            ))}
          </div>
        )}

        {/* Click Hint */}
        <div className={`text-xs text-center transition-opacity duration-200 ${isHovered ? 'opacity-100' : 'opacity-0'}`}>
          <span className="text-blue-600 font-medium">Click to try this query</span>
        </div>
      </div>
    </div>
  );
};

export const AlternativeQueries: React.FC<AlternativeQueriesProps> = ({
  similarQueries,
  onQuerySelected,
  isLoading = false,
  className = '',
}) => {
  if (isLoading) {
    return (
      <div className={`space-y-4 ${className}`}>
        <div className="flex items-center space-x-2">
          <ClockIcon className="h-5 w-5 text-blue-600 animate-spin" />
          <h3 className="text-lg font-semibold text-gray-900">
            Finding similar queries...
          </h3>
        </div>
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="border rounded-lg p-4 animate-pulse">
              <div className="space-y-3">
                <div className="h-4 bg-gray-200 rounded w-3/4"></div>
                <div className="flex space-x-4">
                  <div className="h-3 bg-gray-200 rounded w-20"></div>
                  <div className="h-3 bg-gray-200 rounded w-16"></div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (!similarQueries || similarQueries.length === 0) {
    return (
      <div className={`text-center py-8 ${className}`}>
        <ClockIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">
          No similar queries found
        </h3>
        <p className="text-gray-500">
          We couldn't find similar queries that returned good results.
        </p>
      </div>
    );
  }

  return (
    <div className={`space-y-4 ${className}`}>
      <div className="flex items-center space-x-2">
        <ArrowTrendingUpIcon className="h-5 w-5 text-green-600" />
        <h3 className="text-lg font-semibold text-gray-900">
          Similar Successful Queries
        </h3>
        <span className="bg-green-100 text-green-800 text-xs font-medium px-2 py-1 rounded-full">
          {similarQueries.length}
        </span>
      </div>

      <p className="text-sm text-gray-600 mb-4">
        These similar queries returned good results. Click on any query to try it:
      </p>

      <div className="space-y-3">
        {similarQueries.map((query, index) => (
          <SimilarQueryCard
            key={`${query.query}-${index}`}
            query={query}
            onSelect={() => onQuerySelected(query.query)}
          />
        ))}
      </div>

      <div className="bg-green-50 border border-green-200 rounded-lg p-4 mt-6">
        <div className="flex items-start space-x-3">
          <CheckCircleIcon className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
          <div className="text-sm">
            <p className="font-medium text-green-900 mb-1">
              Success Patterns
            </p>
            <p className="text-green-800">
              These queries worked well because they use common biomedical terms and
              include specific context like organism or assay type.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AlternativeQueries;
