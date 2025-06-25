#!/bin/bash

# OmicsOracle MVP Setup Script
# Run this script to create the minimal viable web interface

echo "🚀 Setting up OmicsOracle MVP Web Interface..."
echo ""

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "❌ Error: Please run this script from the OmicsOracle root directory"
    exit 1
fi

# Create web directory
echo "📁 Creating web interface directory..."
mkdir -p web-interface
cd web-interface

# Initialize Vite React project
echo "⚡ Initializing Vite React TypeScript project..."
npm create vite@latest . -- --template react-ts

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Install additional required packages
echo "📦 Installing additional packages..."
npm install react-router-dom@^6.11.0
npm install axios@^1.4.0
npm install @headlessui/react@^1.7.0
npm install @heroicons/react@^2.0.0
npm install tailwindcss@^3.3.0 postcss@^8.4.0 autoprefixer@^3.0.0

# Install dev dependencies
npm install -D @types/node@^20.3.0
npm install -D prettier@^2.8.0

# Initialize Tailwind CSS
echo "🎨 Setting up Tailwind CSS..."
npx tailwindcss init -p

# Create tailwind.config.js
cat > tailwind.config.js << EOF
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
EOF

# Update src/index.css
cat > src/index.css << EOF
@tailwind base;
@tailwind components;
@tailwind utilities;

/* Custom styles */
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
    'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',
    sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

code {
  font-family: source-code-pro, Menlo, Monaco, Consolas, 'Courier New',
    monospace;
}
EOF

# Create directory structure
echo "📁 Creating project structure..."
mkdir -p src/components
mkdir -p src/services
mkdir -p src/types

# Create types file
cat > src/types/index.ts << 'EOF'
export interface SearchResult {
  id?: string;
  title: string;
  description?: string;
  category?: string;
  organism?: string;
  datePublished?: string;
  [key: string]: any;
}
EOF

# Create API service
cat > src/services/api.ts << 'EOF'
const API_BASE_URL = process.env.NODE_ENV === 'development' 
  ? 'http://localhost:8000' 
  : '';

export const searchAPI = {
  async search(query: string): Promise<{ results: any[] }> {
    const response = await fetch(`${API_BASE_URL}/api/search`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ query }),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return response.json();
  }
};
EOF

# Create LoadingSpinner component
cat > src/components/LoadingSpinner.tsx << 'EOF'
import React from 'react';

export default function LoadingSpinner() {
  return (
    <div className="flex items-center space-x-2">
      <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
      <span className="text-gray-600">Loading results...</span>
    </div>
  );
}
EOF

# Create Layout component
cat > src/components/Layout.tsx << 'EOF'
import React from 'react';

interface LayoutProps {
  children: React.ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Simple Header */}
      <header className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <h1 className="text-xl font-semibold text-gray-900">
            OmicsOracle
          </h1>
        </div>
      </header>

      {/* Main Content */}
      <main className="pb-16">
        {children}
      </main>

      {/* Simple Footer */}
      <footer className="bg-white border-t border-gray-200">
        <div className="max-w-7xl mx-auto px-4 py-6">
          <p className="text-center text-gray-500 text-sm">
            © 2025 OmicsOracle - Advanced Omics Data Analysis
          </p>
        </div>
      </footer>
    </div>
  );
}
EOF

# Create SearchBar component
cat > src/components/SearchBar.tsx << 'EOF'
import React, { useState } from 'react';
import { MagnifyingGlassIcon } from '@heroicons/react/24/outline';

interface SearchBarProps {
  onSearch: (query: string) => void;
  loading: boolean;
}

export default function SearchBar({ onSearch, loading }: SearchBarProps) {
  const [query, setQuery] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSearch(query);
  };

  return (
    <form onSubmit={handleSubmit} className="max-w-2xl mx-auto">
      <div className="relative">
        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <MagnifyingGlassIcon className="h-5 w-5 text-gray-400" />
        </div>
        
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search genes, proteins, pathways..."
          className="block w-full pl-10 pr-20 py-4 text-lg border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          disabled={loading}
        />
        
        <div className="absolute inset-y-0 right-0 flex items-center pr-3">
          <button
            type="submit"
            disabled={loading || !query.trim()}
            className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Searching...' : 'Search'}
          </button>
        </div>
      </div>
    </form>
  );
}
EOF

# Create ResultsList component
cat > src/components/ResultsList.tsx << 'EOF'
import React from 'react';
import { SearchResult } from '../types';
import LoadingSpinner from './LoadingSpinner';

interface ResultsListProps {
  results: SearchResult[];
  loading: boolean;
}

export default function ResultsList({ results, loading }: ResultsListProps) {
  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner />
      </div>
    );
  }

  if (results.length === 0) {
    return null;
  }

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold text-gray-900 mb-4">
        Search Results ({results.length})
      </h2>
      
      <div className="space-y-4">
        {results.map((result, index) => (
          <div
            key={result.id || index}
            className="bg-white border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow"
          >
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              {result.title}
            </h3>
            
            {result.description && (
              <p className="text-gray-600 mb-3">
                {result.description}
              </p>
            )}
            
            <div className="flex items-center space-x-4 text-sm text-gray-500">
              {result.category && (
                <span className="bg-gray-100 px-2 py-1 rounded">
                  {result.category}
                </span>
              )}
              {result.organism && (
                <span>Organism: {result.organism}</span>
              )}
              {result.datePublished && (
                <span>Published: {new Date(result.datePublished).toLocaleDateString()}</span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
EOF

# Update App.tsx
cat > src/App.tsx << 'EOF'
import React, { useState } from 'react';
import SearchBar from './components/SearchBar';
import ResultsList from './components/ResultsList';
import Layout from './components/Layout';
import { SearchResult } from './types';
import { searchAPI } from './services/api';

function App() {
  const [results, setResults] = useState<SearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = async (query: string) => {
    if (!query.trim()) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const data = await searchAPI.search(query);
      setResults(data.results || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Search failed');
      setResults([]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Layout>
      <div className="max-w-4xl mx-auto px-4 py-8">
        {/* Hero Section */}
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            OmicsOracle
          </h1>
          <p className="text-xl text-gray-600 mb-8">
            Search and explore omics data with advanced analytics
          </p>
          
          {/* Search Interface */}
          <SearchBar onSearch={handleSearch} loading={loading} />
        </div>

        {/* Error Display */}
        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
            <div className="text-red-800 font-medium">Search Error</div>
            <div className="text-red-600 text-sm">{error}</div>
          </div>
        )}

        {/* Results */}
        <ResultsList results={results} loading={loading} />
      </div>
    </Layout>
  );
}

export default App;
EOF

# Update package.json scripts
echo "📝 Updating package.json scripts..."
npm pkg set scripts.dev="vite --host 0.0.0.0 --port 3000"
npm pkg set scripts.preview="vite preview --host 0.0.0.0 --port 3000"

# Update vite.config.ts for API proxy
cat > vite.config.ts << 'EOF'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: '0.0.0.0',
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false,
      },
    },
  },
})
EOF

echo ""
echo "✅ MVP setup complete!"
echo ""
echo "🚀 Next steps:"
echo "1. cd web-interface"
echo "2. npm run dev"
echo "3. Open http://localhost:3000"
echo ""
echo "📁 Project structure created:"
echo "   web-interface/"
echo "   ├── src/"
echo "   │   ├── components/"
echo "   │   │   ├── SearchBar.tsx"
echo "   │   │   ├── ResultsList.tsx"
echo "   │   │   ├── Layout.tsx"
echo "   │   │   └── LoadingSpinner.tsx"
echo "   │   ├── services/"
echo "   │   │   └── api.ts"
echo "   │   ├── types/"
echo "   │   │   └── index.ts"
echo "   │   └── App.tsx"
echo "   └── package.json"
echo ""
echo "🔧 Make sure your OmicsOracle backend is running on port 8000"
echo "   Then test the search functionality!"
