// API Response Types
export interface SearchResult {
  id: string;
  title: string;
  summary: string;
  organism?: string;
  platform?: string;
  sample_count?: number;
  submission_date?: string;
  last_update_date?: string;
  pubmed_id?: string;
  sra_info?: any;
  [key: string]: any; // Allow for additional fields from API
}

export interface SearchResponse {
  results: SearchResult[];
  total_count: number;
  page: number;
  per_page: number;
  has_next: boolean;
  has_prev: boolean;
}

export interface SearchParams {
  query: string;
  page?: number;
  per_page?: number;
  organism?: string;
  gene_type?: string;
}

// Component Props Types
export interface SearchBarProps {
  onSearch: (query: string) => void;
  loading?: boolean;
  placeholder?: string;
}

export interface ResultsListProps {
  results: SearchResult[];
  loading?: boolean;
  error?: string | null;
  onResultClick?: (result: SearchResult) => void;
}

export interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

// Application State Types
export interface AppState {
  searchResults: SearchResult[];
  isLoading: boolean;
  error: string | null;
  searchQuery: string;
  totalCount: number;
  currentPage: number;
  showRefinement?: boolean;
  refinementData?: QueryRefinementData;
}

// Query Refinement Types
export interface QuerySuggestion {
  suggested_query: string;
  type: string;
  confidence: number;
  explanation: string;
  expected_results?: number;
}

export interface SimilarQuery {
  query: string;
  result_count: number;
  success_score: number;
  similarity_score: number;
  common_entities: string[];
}

export interface QueryRefinementData {
  suggestions: QuerySuggestion[];
  similar_queries: SimilarQuery[];
  original_query: string;
  analysis: {
    query_complexity: number;
    entity_count: number;
    recognized_entities: string[];
    potential_issues: string[];
  };
}

export interface QueryFeedback {
  original_query: string;
  suggested_query: string;
  user_action: string;
  was_helpful: boolean;
  result_improvement?: number;
}

export interface QueryRefinementContainerProps {
  originalQuery: string;
  searchResults: SearchResult[];
  onQueryRefined: (newQuery: string) => void;
  onFeedbackSubmitted: (feedback: QueryFeedback) => void;
  onDismiss?: () => void;
  className?: string;
}
