"""
Distributed Tracing System

Provides distributed tracing capabilities:
- Request tracing across service boundaries
- Trace context propagation
- Performance and latency tracking
- Integration with observability systems
"""

import logging
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class TraceContext:
    """Context for distributed tracing."""

    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    span_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parent_span_id: Optional[str] = None
    baggage: Dict[str, str] = field(default_factory=dict)


@dataclass
class Span:
    """Individual span in a trace."""

    span_id: str
    trace_id: str
    operation_name: str
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    duration_ms: Optional[float] = None
    tags: Dict[str, Any] = field(default_factory=dict)
    logs: List[Dict[str, Any]] = field(default_factory=list)
    parent_span_id: Optional[str] = None

    def finish(self) -> None:
        """Finish the span."""
        self.end_time = time.time()
        self.duration_ms = (self.end_time - self.start_time) * 1000

    def log(self, message: str, **fields) -> None:
        """Add log entry to span."""
        log_entry = {"timestamp": time.time(), "message": message, **fields}
        self.logs.append(log_entry)

    def set_tag(self, key: str, value: Any) -> None:
        """Set tag on span."""
        self.tags[key] = value


class Tracer:
    """Distributed tracer for request tracking."""

    def __init__(self, service_name: str):
        self.service_name = service_name
        self._spans: Dict[str, Span] = {}
        self._current_context: Optional[TraceContext] = None

    def start_span(self, operation_name: str, parent_context: Optional[TraceContext] = None) -> Span:
        """Start a new span."""
        if parent_context:
            trace_id = parent_context.trace_id
            parent_span_id = parent_context.span_id
        else:
            trace_id = str(uuid.uuid4())
            parent_span_id = None

        span = Span(
            span_id=str(uuid.uuid4()),
            trace_id=trace_id,
            operation_name=operation_name,
            parent_span_id=parent_span_id,
        )

        span.set_tag("service.name", self.service_name)
        self._spans[span.span_id] = span

        return span

    @contextmanager
    def trace(self, operation_name: str, **tags):
        """Context manager for tracing operations."""
        span = self.start_span(operation_name)

        for key, value in tags.items():
            span.set_tag(key, value)

        try:
            yield span
        except Exception as e:
            span.set_tag("error", True)
            span.log(f"Exception: {str(e)}")
            raise
        finally:
            span.finish()

    def get_span(self, span_id: str) -> Optional[Span]:
        """Get span by ID."""
        return self._spans.get(span_id)

    def get_spans(self) -> List[Span]:
        """Get all spans."""
        return list(self._spans.values())


class TracingManager:
    """Manager for distributed tracing system."""

    def __init__(self):
        self._tracers: Dict[str, Tracer] = {}

    def get_tracer(self, service_name: str) -> Tracer:
        """Get or create tracer for service."""
        if service_name not in self._tracers:
            self._tracers[service_name] = Tracer(service_name)

        return self._tracers[service_name]

    def get_all_spans(self) -> List[Span]:
        """Get all spans from all tracers."""
        spans = []
        for tracer in self._tracers.values():
            spans.extend(tracer.get_spans())
        return spans


# Global tracing manager
tracing_manager = TracingManager()
