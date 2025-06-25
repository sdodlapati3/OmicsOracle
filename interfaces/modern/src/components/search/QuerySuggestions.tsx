import React, { useState } from 'react';
import { Card, CardContent, CardHeader } from '../ui/Card';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import {
  LightBulbIcon,
  ArrowPathIcon,
  HandThumbUpIcon,
  HandThumbDownIcon,
  SparklesIcon
} from '@heroicons/react/24/outline';
import { cn } from '../../utils/cn';

interface QuerySuggestion {
  suggested_query: string;
  type: string;
  confidence: number;
  explanation: string;
  expected_results?: number;
}

interface QuerySuggestionsProps {
  suggestions: QuerySuggestion[];
  onSuggestionApplied: (suggestion: QuerySuggestion) => void;
  onSuggestionEdited: (originalSuggestion: QuerySuggestion, editedQuery: string) => void;
  onFeedbackSubmitted: (suggestion: QuerySuggestion, helpful: boolean) => void;
  isLoading?: boolean;
  className?: string;
}

const suggestionTypeLabels: Record<string, { label: string; color: string; icon: React.ComponentType<any> }> = {
  entity_simplification: { label: 'Simplify', color: 'bg-blue-100 text-blue-800', icon: SparklesIcon },
  synonym_substitution: { label: 'Synonym', color: 'bg-green-100 text-green-800', icon: ArrowPathIcon },
  query_broadening: { label: 'Broaden', color: 'bg-purple-100 text-purple-800', icon: LightBulbIcon },
  term_addition: { label: 'Add Terms', color: 'bg-orange-100 text-orange-800', icon: LightBulbIcon },
  structural_modification: { label: 'Restructure', color: 'bg-indigo-100 text-indigo-800', icon: ArrowPathIcon },
  spelling_correction: { label: 'Spelling', color: 'bg-red-100 text-red-800', icon: SparklesIcon },
};

const ConfidenceIndicator: React.FC<{ confidence: number }> = ({ confidence }) => {
  const getConfidenceColor = (conf: number) => {
    if (conf >= 0.8) return 'bg-green-500';
    if (conf >= 0.6) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  return (
    <div className="flex items-center space-x-2">
      <div className="w-16 bg-gray-200 rounded-full h-2">
        <div
          className={cn("h-2 rounded-full transition-all duration-300", getConfidenceColor(confidence))}
          style={{ width: `${confidence * 100}%` }}
        />
      </div>
      <span className="text-xs text-gray-600 font-medium">
        {(confidence * 100).toFixed(0)}%
      </span>
    </div>
  );
};

const SuggestionCard: React.FC<{
  suggestion: QuerySuggestion;
  onApply: () => void;
  onEdit: (editedQuery: string) => void;
  onFeedback: (helpful: boolean) => void;
}> = ({ suggestion, onApply, onEdit, onFeedback }) => {
  const [feedbackGiven, setFeedbackGiven] = useState(false);
  const [showFeedback, setShowFeedback] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [editedQuery, setEditedQuery] = useState(suggestion.suggested_query);

  const typeInfo = suggestionTypeLabels[suggestion.type] || {
    label: 'Unknown',
    color: 'bg-gray-100 text-gray-800',
    icon: LightBulbIcon
  };

  const IconComponent = typeInfo.icon;

  const handleEdit = () => {
    if (isEditing) {
      onEdit(editedQuery);
      setIsEditing(false);
    } else {
      setIsEditing(true);
    }
  };

  const handleCancelEdit = () => {
    setEditedQuery(suggestion.suggested_query);
    setIsEditing(false);
  };

  const handleFeedback = (helpful: boolean) => {
    onFeedback(helpful);
    setFeedbackGiven(true);
    setShowFeedback(false);
  };

  return (
    <Card className="transition-all duration-200 hover:shadow-md border-l-4 border-l-blue-500">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="flex items-center space-x-2">
            <IconComponent className="h-5 w-5 text-blue-600" />
            <Badge className={cn("text-xs", typeInfo.color)}>
              {typeInfo.label}
            </Badge>
          </div>
          <ConfidenceIndicator confidence={suggestion.confidence} />
        </div>
      </CardHeader>

      <CardContent className="pt-0">
        <div className="space-y-3">
          {/* Suggested Query */}
          <div className="bg-gray-50 p-3 rounded-lg border">
            {isEditing ? (
              <div className="space-y-2">
                <input
                  type="text"
                  value={editedQuery}
                  onChange={(e) => setEditedQuery(e.target.value)}
                  className="w-full font-mono text-sm text-gray-800 bg-white border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  autoFocus
                />
                <div className="flex space-x-2">
                  <Button
                    onClick={handleEdit}
                    size="sm"
                    className="bg-green-600 hover:bg-green-700 text-white text-xs"
                  >
                    Apply
                  </Button>
                  <Button
                    onClick={handleCancelEdit}
                    variant="outline"
                    size="sm"
                    className="text-xs"
                  >
                    Cancel
                  </Button>
                </div>
              </div>
            ) : (
              <div className="flex items-center justify-between">
                <p className="font-mono text-sm text-gray-800 break-words flex-1">
                  "{suggestion.suggested_query}"
                </p>
                <Button
                  onClick={() => setIsEditing(true)}
                  variant="ghost"
                  size="sm"
                  className="ml-2 text-gray-500 hover:text-gray-700 text-xs"
                >
                  Edit
                </Button>
              </div>
            )}
          </div>

          {/* Explanation */}
          <p className="text-sm text-gray-600 leading-relaxed">
            {suggestion.explanation}
          </p>

          {/* Expected Results */}
          {suggestion.expected_results && (
            <p className="text-xs text-gray-500">
              Expected results: ~{suggestion.expected_results}
            </p>
          )}

          {/* Action Buttons */}
          <div className="flex items-center justify-between pt-2">
            <Button
              onClick={onApply}
              className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 text-sm"
            >
              Try This Query
            </Button>

            <div className="flex items-center space-x-2">
              {!feedbackGiven && !showFeedback && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowFeedback(true)}
                  className="text-gray-500 hover:text-gray-700 text-xs"
                >
                  Rate
                </Button>
              )}

              {showFeedback && (
                <div className="flex items-center space-x-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleFeedback(true)}
                    className="text-green-600 hover:text-green-700 hover:bg-green-50 p-1"
                    title="Helpful"
                  >
                    <HandThumbUpIcon className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleFeedback(false)}
                    className="text-red-600 hover:text-red-700 hover:bg-red-50 p-1"
                    title="Not helpful"
                  >
                    <HandThumbDownIcon className="h-4 w-4" />
                  </Button>
                </div>
              )}

              {feedbackGiven && (
                <span className="text-xs text-gray-500">Thanks!</span>
              )}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export const QuerySuggestions: React.FC<QuerySuggestionsProps> = ({
  suggestions,
  onSuggestionApplied,
  onSuggestionEdited,
  onFeedbackSubmitted,
  isLoading = false,
  className,
}) => {
  if (isLoading) {
    return (
      <div className={cn("space-y-4", className)}>
        <div className="flex items-center space-x-2">
          <ArrowPathIcon className="h-5 w-5 text-blue-600 animate-spin" />
          <h3 className="text-lg font-semibold text-gray-900">
            Generating suggestions...
          </h3>
        </div>
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <Card key={i} className="animate-pulse">
              <CardContent className="p-6">
                <div className="space-y-3">
                  <div className="h-4 bg-gray-200 rounded w-3/4"></div>
                  <div className="h-3 bg-gray-200 rounded w-1/2"></div>
                  <div className="h-8 bg-gray-200 rounded w-32"></div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  if (!suggestions || suggestions.length === 0) {
    return (
      <div className={cn("text-center py-8", className)}>
        <LightBulbIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">
          No suggestions available
        </h3>
        <p className="text-gray-500">
          Try a different query or add more specific terms.
        </p>
      </div>
    );
  }

  return (
    <div className={cn("space-y-4", className)}>
      <div className="flex items-center space-x-2">
        <LightBulbIcon className="h-5 w-5 text-blue-600" />
        <h3 className="text-lg font-semibold text-gray-900">
          Query Suggestions
        </h3>
        <Badge variant="secondary" className="ml-2">
          {suggestions.length}
        </Badge>
      </div>

      <p className="text-sm text-gray-600 mb-4">
        We've analyzed your query and found some ways to improve your search results:
      </p>

      <div className="space-y-4">
        {suggestions.map((suggestion, index) => (
          <SuggestionCard
            key={`${suggestion.suggested_query}-${index}`}
            suggestion={suggestion}
            onApply={() => onSuggestionApplied(suggestion)}
            onEdit={(editedQuery) => onSuggestionEdited(suggestion, editedQuery)}
            onFeedback={(helpful) => onFeedbackSubmitted(suggestion, helpful)}
          />
        ))}
      </div>

      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mt-6">
        <div className="flex items-start space-x-3">
          <SparklesIcon className="h-5 w-5 text-blue-600 mt-0.5 flex-shrink-0" />
          <div className="text-sm">
            <p className="font-medium text-blue-900 mb-1">
              Pro Tip
            </p>
            <p className="text-blue-800">
              Higher confidence suggestions (green bars) are more likely to improve your results.
              Try the suggestions in order for best results.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default QuerySuggestions;
