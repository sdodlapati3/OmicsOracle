import React, { useState } from 'react';
import type { FormEvent } from 'react';
import { MagnifyingGlassIcon } from '@heroicons/react/24/outline';
import type { SearchBarProps } from '../types';
import LoadingSpinner from './LoadingSpinner';

const SearchBar: React.FC<SearchBarProps> = ({
  onSearch,
  loading = false,
  placeholder = "Search genes, proteins, or annotations..."
}) => {
  const [query, setQuery] = useState('');

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (query.trim() && !loading) {
      onSearch(query.trim());
    }
  };

  const handleClear = () => {
    setQuery('');
  };

  return (
    <div className="w-full max-w-4xl mx-auto">
      <form onSubmit={handleSubmit} className="relative">
        <div className="flex items-center">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
              <MagnifyingGlassIcon className="h-5 w-5 text-gray-400" />
            </div>
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={placeholder}
              disabled={loading}
              className="w-full pl-12 pr-12 py-4 text-lg border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 disabled:bg-gray-50 disabled:text-gray-500 transition-colors"
              autoComplete="off"
              autoFocus
            />
            {query && (
              <button
                type="button"
                onClick={handleClear}
                className="absolute inset-y-0 right-0 pr-4 flex items-center text-gray-400 hover:text-gray-600"
                disabled={loading}
              >
                <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            )}
          </div>
          <button
            type="submit"
            disabled={!query.trim() || loading}
            className="ml-4 px-8 py-4 bg-primary-600 text-white font-medium rounded-lg hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? (
              <div className="flex items-center">
                <LoadingSpinner size="sm" className="mr-2" />
                Searching...
              </div>
            ) : (
              'Search'
            )}
          </button>
        </div>
      </form>

      {/* Search suggestions/tips */}
      <div className="mt-3 text-sm text-gray-600">
        <p>
          Try searching for: <span className="font-medium">BRCA1</span>, <span className="font-medium">insulin</span>, or <span className="font-medium">tumor suppressor</span>
        </p>
      </div>
    </div>
  );
};

export default SearchBar;
