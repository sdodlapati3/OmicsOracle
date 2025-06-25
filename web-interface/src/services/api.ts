import axios from 'axios';
import type {
  SearchParams,
  SearchResponse,
  SearchResult,
  QueryRefinementData,
  QueryFeedback
} from '../types';

// API Configuration
const API_BASE_URL = 'http://localhost:8000';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// API Functions
export const searchGenes = async (params: SearchParams): Promise<SearchResponse> => {
  try {
    const searchData = {
      query: params.query,
      max_results: params.per_page || 20,
      organism: params.organism,
      assay_type: params.gene_type, // Map gene_type to assay_type
      output_format: 'json'
    };

    const response = await apiClient.post('/api/search', searchData);

    // Transform the API response to match our expected format
    const result = response.data;

    // Map backend response to frontend format
    const searchResults: SearchResult[] = result.metadata?.map((item: any) => ({
      id: item.id || '',
      title: item.title || '',
      summary: item.summary || '',
      organism: item.organism || '',
      platform: item.platform || '',
      sample_count: item.sample_count || 0,
      submission_date: item.submission_date || '',
      last_update_date: item.last_update_date || '',
      pubmed_id: item.pubmed_id || '',
      sra_info: item.sra_info || null,
    })) || [];

    return {
      results: searchResults,
      total_count: result.total_count || searchResults.length,
      page: params.page || 1,
      per_page: params.per_page || 20,
      has_next: false,
      has_prev: false
    };
  } catch (error) {
    if (axios.isAxiosError(error)) {
      if (error.response?.status === 404) {
        throw new Error('Search endpoint not found. Please ensure the API server is running.');
      }
      if (error.response && error.response.status >= 500) {
        throw new Error('Server error. Please try again later.');
      }
      if (error.code === 'ECONNREFUSED') {
        throw new Error('Could not connect to API server. Please ensure it is running on port 8000.');
      }
      throw new Error(error.response?.data?.message || 'Search request failed');
    }
    throw new Error('An unexpected error occurred');
  }
};

// Health check function
export const checkApiHealth = async (): Promise<boolean> => {
  try {
    const response = await apiClient.get('/health');
    return response.status === 200;
  } catch {
    return false;
  }
};

// Query Refinement API Functions
export const getQuerySuggestions = async (query: string, resultCount: number = 0): Promise<QueryRefinementData> => {
  try {
    const response = await apiClient.post('/api/refinement/suggestions', {
      original_query: query,
      result_count: resultCount
    });
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      throw new Error(error.response?.data?.message || 'Failed to get query suggestions');
    }
    throw new Error('An unexpected error occurred while getting suggestions');
  }
};

export const getSimilarQueries = async (query: string, limit: number = 5): Promise<{ similar_queries: any[] }> => {
  try {
    const response = await apiClient.get('/api/refinement/similar-queries', {
      params: { query, limit }
    });
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      throw new Error(error.response?.data?.message || 'Failed to get similar queries');
    }
    throw new Error('An unexpected error occurred while getting similar queries');
  }
};

export const submitQueryFeedback = async (feedback: QueryFeedback): Promise<void> => {
  try {
    await apiClient.post('/api/refinement/feedback', feedback);
  } catch (error) {
    if (axios.isAxiosError(error)) {
      throw new Error(error.response?.data?.message || 'Failed to submit feedback');
    }
    throw new Error('An unexpected error occurred while submitting feedback');
  }
};

export const performEnhancedSearch = async (
  query: string,
  options: {
    use_synonyms?: boolean;
    expand_abbreviations?: boolean;
    relaxed_matching?: boolean;
  } = {}
): Promise<SearchResponse> => {
  try {
    const searchData = {
      query,
      use_synonyms: options.use_synonyms ?? true,
      expand_abbreviations: options.expand_abbreviations ?? true,
      relaxed_matching: options.relaxed_matching ?? false,
      output_format: 'json'
    };

    const response = await apiClient.post('/api/refinement/search/enhanced', searchData);

    const result = response.data;
    return {
      results: result.metadata || [],
      total_count: result.metadata?.length || 0,
      page: 1,
      per_page: 20,
      has_next: false,
      has_prev: false
    };
  } catch (error) {
    if (axios.isAxiosError(error)) {
      throw new Error(error.response?.data?.message || 'Enhanced search failed');
    }
    throw new Error('An unexpected error occurred during enhanced search');
  }
};

// Export API client for direct use if needed
export { apiClient };
