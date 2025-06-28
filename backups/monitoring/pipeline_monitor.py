"""
Pipeline monitoring module for OmicsOracle.

This module provides comprehensive monitoring capabilities for the OmicsOracle pipeline,
tracking each step of the process, from initialization to query processing to result formatting.
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PipelineEvent:
    """Event representing a pipeline stage or action."""

    def __init__(self, stage: str, message: str, percentage: float, detail: Optional[Dict[str, Any]] = None):
        """Initialize a pipeline event."""
        self.stage = stage
        self.message = message
        self.percentage = percentage
        self.detail = detail or {}
        self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "stage": self.stage,
            "message": self.message,
            "percentage": self.percentage,
            "detail": self.detail,
            "timestamp": self.timestamp,
            "timestamp_readable": datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S.%f"),
        }


class PipelineMonitor:
    """Monitor the OmicsOracle pipeline."""

    def __init__(self, log_to_file: bool = True, log_dir: str = "logs"):
        """Initialize the pipeline monitor."""
        self.events: List[PipelineEvent] = []
        self.event_types: Set[str] = set()
        self.start_time = time.time()
        self.query_count = 0
        self.error_count = 0
        self.current_query: Optional[str] = None
        self.current_query_id: Optional[str] = None
        self.current_percentage: float = 0.0

        # Callbacks
        self.callbacks: List[Callable] = []

        # Logging to file
        self.log_to_file = log_to_file
        self.log_dir = Path(log_dir)

        if self.log_to_file:
            self.log_dir.mkdir(exist_ok=True)
            self.event_log_file = self.log_dir / "pipeline_events.jsonl"
            self.summary_log_file = self.log_dir / "pipeline_summary.json"

    def add_callback(self, callback: Callable) -> None:
        """Add a callback function to be called for each event."""
        self.callbacks.append(callback)

    async def process_event(self, query_id: str, event: PipelineEvent) -> None:
        """Process a pipeline event."""
        # Store current query ID
        self.current_query_id = query_id

        # Store event
        self.events.append(event)
        self.event_types.add(event.stage)

        # Update current percentage
        self.current_percentage = event.percentage

        # Count errors
        if "error" in event.stage.lower() or "failed" in event.stage.lower():
            self.error_count += 1

        # Log to file if enabled
        if self.log_to_file:
            with open(self.event_log_file, "a") as f:
                event_data = event.to_dict()
                event_data["query_id"] = query_id
                f.write(json.dumps(event_data) + "\n")

        # Call callbacks
        for callback in self.callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(query_id, event)
                else:
                    callback(query_id, event)
            except Exception as e:
                logger.error(f"Error in callback: {e}")

    def start_query(self, query: str) -> str:
        """Start tracking a new query."""
        self.query_count += 1
        self.current_query = query
        query_id = f"{int(time.time())}-{self.query_count}"
        logger.info(f"Starting query tracking: {query_id} - '{query}'")
        return query_id

    def end_query(self, query_id: str, success: bool = True) -> None:
        """End tracking a query."""
        logger.info(f"Ending query tracking: {query_id}")

        # Update summary log
        if self.log_to_file:
            summary = self.get_summary()
            with open(self.summary_log_file, "w") as f:
                json.dump(summary, f, indent=2)

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of all pipeline activity."""
        now = time.time()
        return {
            "query_count": self.query_count,
            "error_count": self.error_count,
            "event_count": len(self.events),
            "event_types": list(self.event_types),
            "uptime": now - self.start_time,
            "uptime_readable": str(datetime.fromtimestamp(now) - datetime.fromtimestamp(self.start_time)),
            "current_query": self.current_query,
            "current_query_id": self.current_query_id,
            "current_percentage": self.current_percentage,
            "timestamp": now,
            "timestamp_readable": datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S"),
        }

    def get_query_events(self, query_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get events for a specific query."""
        if query_id is None:
            query_id = self.current_query_id

        if query_id is None:
            return []

        # Filter events for this query ID
        query_events = [event.to_dict() for event in self.events if event.detail.get("query_id") == query_id]

        return query_events


# Global monitor instance
global_monitor = PipelineMonitor()


def get_monitor() -> PipelineMonitor:
    """Get the global monitor instance."""
    return global_monitor


# Convenience functions for monitoring specific components


async def monitor_pipeline_init(pipeline) -> None:
    """Monitor pipeline initialization."""
    monitor = get_monitor()
    query_id = monitor.start_query("Pipeline Initialization")

    # Initial event
    await monitor.process_event(
        query_id,
        PipelineEvent(
            stage="pipeline_init",
            message="Starting pipeline initialization",
            percentage=0.0,
            detail={"component": "pipeline"},
        ),
    )

    # GEO client
    if hasattr(pipeline, "geo_client"):
        await monitor.process_event(
            query_id,
            PipelineEvent(
                stage="pipeline_init",
                message="GEO client initialized",
                percentage=25.0,
                detail={"component": "geo_client", "status": "ok"},
            ),
        )
    else:
        await monitor.process_event(
            query_id,
            PipelineEvent(
                stage="pipeline_init_error",
                message="GEO client initialization failed",
                percentage=25.0,
                detail={"component": "geo_client", "status": "error"},
            ),
        )

    # Summarizer
    if hasattr(pipeline, "summarizer"):
        await monitor.process_event(
            query_id,
            PipelineEvent(
                stage="pipeline_init",
                message="Summarizer initialized",
                percentage=50.0,
                detail={"component": "summarizer", "status": "ok"},
            ),
        )
    else:
        await monitor.process_event(
            query_id,
            PipelineEvent(
                stage="pipeline_init_error",
                message="Summarizer initialization failed",
                percentage=50.0,
                detail={"component": "summarizer", "status": "error"},
            ),
        )

    # NCBI email
    if (
        hasattr(pipeline, "config")
        and hasattr(pipeline.config, "ncbi")
        and hasattr(pipeline.config.ncbi, "email")
    ):
        email = pipeline.config.ncbi.email
        await monitor.process_event(
            query_id,
            PipelineEvent(
                stage="pipeline_init",
                message=f"NCBI email configured: {email}",
                percentage=75.0,
                detail={"component": "ncbi_email", "status": "ok", "email": email},
            ),
        )
    else:
        await monitor.process_event(
            query_id,
            PipelineEvent(
                stage="pipeline_init_warning",
                message="NCBI email not configured",
                percentage=75.0,
                detail={"component": "ncbi_email", "status": "warning"},
            ),
        )

    # Final event
    await monitor.process_event(
        query_id,
        PipelineEvent(
            stage="pipeline_init_complete",
            message="Pipeline initialization complete",
            percentage=100.0,
            detail={"component": "pipeline", "status": "ok"},
        ),
    )

    monitor.end_query(query_id)


async def monitor_query(query: str, max_results: int) -> str:
    """Monitor a query."""
    monitor = get_monitor()
    query_id = monitor.start_query(query)

    # Initial event
    await monitor.process_event(
        query_id,
        PipelineEvent(
            stage="query_start",
            message=f"Starting query: '{query}'",
            percentage=0.0,
            detail={"query": query, "max_results": max_results},
        ),
    )

    return query_id


async def monitor_query_complete(query_id: str, result: Any) -> None:
    """Monitor query completion."""
    monitor = get_monitor()

    # Get result details
    result_details = {}

    if result is not None:
        # Get geo_ids
        if hasattr(result, "geo_ids"):
            result_details["geo_id_count"] = len(result.geo_ids) if result.geo_ids else 0

        # Get metadata
        if hasattr(result, "metadata"):
            result_details["metadata_count"] = len(result.metadata) if result.metadata else 0

        # Get AI summaries
        if hasattr(result, "ai_summaries") and result.ai_summaries:
            result_details["has_ai_summaries"] = True
            if "individual_summaries" in result.ai_summaries:
                result_details["individual_summary_count"] = len(result.ai_summaries["individual_summaries"])
        else:
            result_details["has_ai_summaries"] = False

    # Final event
    await monitor.process_event(
        query_id,
        PipelineEvent(
            stage="query_complete", message=f"Query complete", percentage=100.0, detail=result_details
        ),
    )

    monitor.end_query(query_id)


async def monitor_error(query_id: str, error: Exception) -> None:
    """Monitor an error."""
    monitor = get_monitor()

    # Error event
    await monitor.process_event(
        query_id,
        PipelineEvent(
            stage="error",
            message=f"Error: {str(error)}",
            percentage=100.0,
            detail={"error_type": type(error).__name__, "error_message": str(error)},
        ),
    )

    monitor.end_query(query_id, success=False)
