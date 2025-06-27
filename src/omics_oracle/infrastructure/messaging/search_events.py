"""
Search-related domain events.

This module defines events that are published during search operations.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class SearchStartedEvent:
    """Event published when a search operation starts."""

    query: str
    search_type: str
    max_results: int
    timestamp: datetime
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class SearchCompletedEvent:
    """Event published when a search operation completes successfully."""

    query: str
    results_count: int
    search_duration: float
    timestamp: datetime
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class SearchFailedEvent:
    """Event published when a search operation fails."""

    query: str
    error_message: str
    error_type: str
    search_duration: float
    timestamp: datetime
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class DatasetRetrievedEvent:
    """Event published when a specific dataset is retrieved."""

    geo_id: str
    dataset_title: str
    timestamp: datetime
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class SimilarDatasetsFoundEvent:
    """Event published when similar datasets are found."""

    original_geo_id: str
    similar_datasets_count: int
    similarity_score_threshold: float
    timestamp: datetime
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
