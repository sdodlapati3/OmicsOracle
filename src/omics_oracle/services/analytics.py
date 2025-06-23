"""
Analytics service for OmicsOracle usage tracking and performance monitoring.

This service provides:
- Query analytics collection
- System performance monitoring
- Usage statistics aggregation
- Dashboard data preparation
"""

import json
import logging
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import psutil

from ..models.analytics import (
    AnalyticsResponse,
    DatasetAnalytics,
    QueryAnalytics,
    QueryStatus,
    SystemMetrics,
    UsageStatistics,
)

logger = logging.getLogger(__name__)


class AnalyticsService:
    """Service for collecting and analyzing OmicsOracle usage data."""

    def __init__(self, storage_path: str = "analytics_data") -> None:
        """Initialize analytics service."""
        self.storage_path = storage_path
        self.active_queries: Dict[str, QueryAnalytics] = {}
        self.query_history: List[QueryAnalytics] = []
        self.dataset_stats: Dict[str, DatasetAnalytics] = {}
        self.system_metrics_history: List[SystemMetrics] = []

        # Ensure storage directory exists
        os.makedirs(storage_path, exist_ok=True)

        # Load existing data
        self._load_analytics_data()

        logger.info(
            f"Analytics service initialized with storage at {storage_path}"
        )

    def _load_analytics_data(self) -> None:
        """Load existing analytics data from storage."""
        try:
            # Load query history
            query_file = os.path.join(self.storage_path, "query_history.json")
            if os.path.exists(query_file):
                with open(query_file, "r") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self.query_history = [
                            QueryAnalytics(**item) for item in data
                        ]
                logger.info(f"Loaded {len(self.query_history)} query records")

            # Load dataset statistics
            dataset_file = os.path.join(self.storage_path, "dataset_stats.json")
            if os.path.exists(dataset_file):
                with open(dataset_file, "r") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self.dataset_stats = {
                            k: DatasetAnalytics(**v) for k, v in data.items()
                        }
                logger.info(
                    f"Loaded stats for {len(self.dataset_stats)} datasets"
                )

        except Exception as e:
            logger.error(f"Error loading analytics data: {e}")

    def _save_analytics_data(self) -> None:
        """Save analytics data to storage."""
        try:
            # Save query history (last 10000 records)
            query_file = os.path.join(self.storage_path, "query_history.json")
            with open(query_file, "w") as f:
                data = [q.dict() for q in self.query_history[-10000:]]
                json.dump(data, f, default=str, indent=2)

            # Save dataset statistics
            dataset_file = os.path.join(self.storage_path, "dataset_stats.json")
            with open(dataset_file, "w") as f:
                data = {k: v.dict() for k, v in self.dataset_stats.items()}
                json.dump(data, f, default=str, indent=2)

            logger.debug("Analytics data saved successfully")

        except Exception as e:
            logger.error(f"Error saving analytics data: {e}")

    def start_query(self, query_analytics: QueryAnalytics) -> str:
        """Record the start of a query."""
        self.active_queries[query_analytics.query_id] = query_analytics
        logger.debug(f"Started tracking query: {query_analytics.query_id}")
        return query_analytics.query_id

    def complete_query(
        self,
        query_id: str,
        status: QueryStatus,
        processing_time: float,
        results_count: int = 0,
        entities_extracted: Optional[List[Dict[str, Any]]] = None,
        error_type: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """Record the completion of a query."""
        if query_id in self.active_queries:
            query = self.active_queries[query_id]
            query.status = status
            query.processing_time = processing_time
            query.results_count = results_count
            query.entities_extracted = entities_extracted or []
            query.error_type = error_type
            query.error_message = error_message

            # Move to history
            self.query_history.append(query)
            del self.active_queries[query_id]

            # Save periodically
            if len(self.query_history) % 10 == 0:
                self._save_analytics_data()

            logger.debug(f"Completed query tracking: {query_id}")
        else:
            logger.warning(f"Query {query_id} not found in active queries")

    def record_dataset_access(
        self,
        dataset_id: str,
        query_text: Optional[str] = None,
        entities: Optional[List[str]] = None,
    ) -> None:
        """Record access to a specific dataset."""
        if dataset_id not in self.dataset_stats:
            self.dataset_stats[dataset_id] = DatasetAnalytics(
                dataset_id=dataset_id
            )

        stats = self.dataset_stats[dataset_id]
        stats.access_count += 1
        stats.last_accessed = datetime.now()

        if query_text:
            stats.search_queries.append(query_text)
            # Keep only last 100 queries
            stats.search_queries = stats.search_queries[-100:]

        if entities:
            stats.entity_matches.extend(entities)
            # Keep only last 100 entities
            stats.entity_matches = stats.entity_matches[-100:]

    def get_system_metrics(self) -> SystemMetrics:
        """Get current system performance metrics."""
        try:
            # Get system resource usage
            memory_usage = psutil.virtual_memory().percent
            cpu_usage = psutil.cpu_percent(interval=1)

            # Calculate query statistics
            recent_queries = [
                q
                for q in self.query_history
                if q.timestamp > datetime.now() - timedelta(hours=1)
            ]

            total_queries = len(self.query_history)
            active_queries = len(self.active_queries)

            # Calculate average response time
            if recent_queries:
                avg_response_time = sum(
                    q.processing_time for q in recent_queries
                ) / len(recent_queries)
                error_rate = (
                    len(
                        [
                            q
                            for q in recent_queries
                            if q.status == QueryStatus.FAILED
                        ]
                    )
                    / len(recent_queries)
                    * 100
                )
                timeout_rate = (
                    len(
                        [
                            q
                            for q in recent_queries
                            if q.status == QueryStatus.TIMEOUT
                        ]
                    )
                    / len(recent_queries)
                    * 100
                )
            else:
                avg_response_time = 0.0
                error_rate = 0.0
                timeout_rate = 0.0

            metrics = SystemMetrics(
                total_queries=total_queries,
                active_queries=active_queries,
                average_response_time=avg_response_time,
                pipeline_status=True,  # TODO: Get actual pipeline status
                websocket_connections=0,  # TODO: Get from WebSocket manager
                memory_usage=memory_usage,
                cpu_usage=cpu_usage,
                error_rate=error_rate,
                timeout_rate=timeout_rate,
            )

            # Store in history
            self.system_metrics_history.append(metrics)
            # Keep only last 1000 metrics
            self.system_metrics_history = self.system_metrics_history[-1000:]

            return metrics

        except Exception as e:
            logger.error(f"Error getting system metrics: {e}")
            return SystemMetrics(
                memory_usage=0.0,
                cpu_usage=0.0,
            )

    def get_usage_statistics(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> UsageStatistics:
        """Get usage statistics for a date range."""
        if not start_date:
            start_date = datetime.now() - timedelta(days=7)
        if not end_date:
            end_date = datetime.now()

        # Filter queries by date range
        filtered_queries = [
            q
            for q in self.query_history
            if start_date <= q.timestamp <= end_date
        ]

        if not filtered_queries:
            return UsageStatistics(period_start=start_date, period_end=end_date)

        # Calculate basic statistics
        total_queries = len(filtered_queries)
        successful_queries = len(
            [q for q in filtered_queries if q.status == QueryStatus.COMPLETED]
        )
        failed_queries = len(
            [q for q in filtered_queries if q.status == QueryStatus.FAILED]
        )

        # Performance statistics
        response_times = [
            q.processing_time for q in filtered_queries if q.processing_time > 0
        ]
        avg_response_time = (
            sum(response_times) / len(response_times) if response_times else 0.0
        )
        min_response_time = min(response_times) if response_times else 0.0
        max_response_time = max(response_times) if response_times else 0.0

        # Popular terms analysis
        query_terms = []
        for q in filtered_queries:
            query_terms.extend(q.query_text.lower().split())

        term_counter = Counter(query_terms)
        top_search_terms = [
            {"term": term, "count": count}
            for term, count in term_counter.most_common(20)
            if len(term) > 2  # Skip short words
        ]

        # Entity analysis
        entity_counter: Dict[str, int] = defaultdict(int)
        for q in filtered_queries:
            for entity in q.entities_extracted:
                if "text" in entity and "label" in entity:
                    entity_counter[f"{entity['text']} ({entity['label']})"] += 1

        top_entities = [
            {"entity": entity, "count": count}
            for entity, count in sorted(
                entity_counter.items(), key=lambda x: x[1], reverse=True
            )[:20]
        ]

        # Dataset analysis
        dataset_counter: Counter = Counter()
        for stats in self.dataset_stats.values():
            if start_date <= stats.last_accessed <= end_date:
                dataset_counter[stats.dataset_id] = stats.access_count

        top_datasets = [
            {"dataset_id": dataset_id, "access_count": count}
            for dataset_id, count in dataset_counter.most_common(20)
        ]

        # User engagement (simplified)
        unique_sessions = len(
            set(
                q.user_session_id for q in filtered_queries if q.user_session_id
            )
        )
        avg_session_queries = total_queries / max(unique_sessions, 1)

        return UsageStatistics(
            period_start=start_date,
            period_end=end_date,
            total_queries=total_queries,
            successful_queries=successful_queries,
            failed_queries=failed_queries,
            avg_response_time=avg_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            top_search_terms=top_search_terms,
            top_entities=top_entities,
            top_datasets=top_datasets,
            unique_sessions=unique_sessions,
            avg_session_queries=avg_session_queries,
            repeat_users=0,  # TODO: Implement repeat user tracking
        )

    def get_analytics_data(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        aggregation: str = "day",
    ) -> AnalyticsResponse:
        """Get comprehensive analytics data."""
        if not start_date:
            start_date = datetime.now() - timedelta(days=7)
        if not end_date:
            end_date = datetime.now()

        # Get current system metrics
        system_metrics = self.get_system_metrics()

        # Get usage statistics
        usage_stats = self.get_usage_statistics(start_date, end_date)

        # Generate time series data
        query_trends = self._generate_query_trends(
            start_date, end_date, aggregation
        )
        performance_trends = self._generate_performance_trends(
            start_date, end_date, aggregation
        )
        entity_trends = self._generate_entity_trends(
            start_date, end_date, aggregation
        )

        return AnalyticsResponse(
            period={"start": start_date, "end": end_date},
            system_metrics=system_metrics,
            usage_statistics=usage_stats,
            query_trends=query_trends,
            performance_trends=performance_trends,
            entity_trends=entity_trends,
            popular_searches=usage_stats.top_search_terms,
            trending_datasets=usage_stats.top_datasets,
            common_entities=usage_stats.top_entities,
        )

    def _generate_query_trends(
        self, start_date: datetime, end_date: datetime, aggregation: str
    ) -> List[Dict[str, Any]]:
        """Generate query volume trends over time."""
        trends = []
        current = start_date

        # Determine time delta based on aggregation
        if aggregation == "hour":
            delta = timedelta(hours=1)
        elif aggregation == "day":
            delta = timedelta(days=1)
        elif aggregation == "week":
            delta = timedelta(weeks=1)
        else:  # month
            delta = timedelta(days=30)

        while current < end_date:
            next_period = current + delta

            # Count queries in this period
            period_queries = [
                q
                for q in self.query_history
                if current <= q.timestamp < next_period
            ]

            trends.append(
                {
                    "timestamp": current.isoformat(),
                    "total_queries": len(period_queries),
                    "successful_queries": len(
                        [
                            q
                            for q in period_queries
                            if q.status == QueryStatus.COMPLETED
                        ]
                    ),
                    "failed_queries": len(
                        [
                            q
                            for q in period_queries
                            if q.status == QueryStatus.FAILED
                        ]
                    ),
                }
            )

            current = next_period

        return trends

    def _generate_performance_trends(
        self, start_date: datetime, end_date: datetime, aggregation: str
    ) -> List[Dict[str, Any]]:
        """Generate performance trends over time."""
        # Use system metrics history for performance trends
        trends = []
        for metrics in self.system_metrics_history:
            if start_date <= metrics.timestamp <= end_date:
                trends.append(
                    {
                        "timestamp": metrics.timestamp.isoformat(),
                        "average_response_time": metrics.average_response_time,
                        "active_queries": metrics.active_queries,
                        "error_rate": metrics.error_rate,
                        "memory_usage": metrics.memory_usage,
                        "cpu_usage": metrics.cpu_usage,
                    }
                )

        return trends

    def _generate_entity_trends(
        self, start_date: datetime, end_date: datetime, aggregation: str
    ) -> List[Dict[str, Any]]:
        """Generate entity extraction trends over time."""
        trends = []

        # Group queries by time period and analyze entities
        filtered_queries = [
            q
            for q in self.query_history
            if start_date <= q.timestamp <= end_date
        ]

        entity_counts: Dict[str, int] = defaultdict(int)
        for query in filtered_queries:
            for entity in query.entities_extracted:
                if "label" in entity:
                    entity_counts[entity["label"]] += 1

        trends.append(
            {
                "timestamp": datetime.now().isoformat(),
                "entity_distribution": dict(entity_counts),
            }
        )

        return trends

    def cleanup(self) -> None:
        """Clean up analytics service and save data."""
        self._save_analytics_data()
        logger.info("Analytics service cleanup completed")


# Global analytics service instance
analytics_service = AnalyticsService()
