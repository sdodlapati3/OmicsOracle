"""
Query Tracer for OmicsOracle Pipeline

This module provides a comprehensive tracing system that records every step
of the query processing pipeline, from initial request to final result display.
"""

import asyncio
import contextlib
import functools
import inspect
import json
import logging
import os
import time
import traceback
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class QueryTracer:
    """
    Traces query execution through the entire OmicsOracle pipeline.
    Records inputs, outputs, transformations, and execution time at each stage.
    """

    def __init__(
        self,
        query_id: Optional[str] = None,
        original_query: Optional[str] = None,
        output_dir: str = "query_traces",
        save_interval: int = 10,
        detailed: bool = True,
    ):
        """
        Initialize a new query tracer.

        Args:
            query_id: Unique identifier for the query (generated if None)
            original_query: The original query string
            output_dir: Directory to save trace files
            save_interval: How often to save trace data (in seconds)
            detailed: Whether to capture detailed information at each step
        """
        self.query_id = query_id or f"query_{str(uuid.uuid4())[:8]}"
        self.original_query = original_query
        self.output_dir = Path(output_dir)
        self.detailed = detailed
        self.save_interval = save_interval

        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize trace data
        self.trace_data = {
            "query_id": self.query_id,
            "original_query": original_query,
            "start_time": time.time(),
            "start_timestamp": datetime.now().isoformat(),
            "steps": [],
            "geo_ids": [],
            "metadata": {},
            "transformations": [],
            "component_times": {},
            "errors": [],
            "warnings": [],
            "final_result": None,
            "end_time": None,
            "duration": None,
            "end_timestamp": None,
            "status": "started",
        }

        # Last save time
        self.last_save_time = time.time()

        logger.info(
            f"[TRACE] Started query tracing for '{original_query}' with ID: {self.query_id}"
        )

        # Track active tracers
        QueryTracer._active_tracers[self.query_id] = self

    # Static dictionary to track active tracers by query_id
    _active_tracers = {}

    @classmethod
    def get_tracer(cls, query_id: str) -> Optional["QueryTracer"]:
        """Get an active tracer by query_id."""
        return cls._active_tracers.get(query_id)

    def record_step(
        self,
        stage: str,
        component: str,
        inputs: Optional[Any] = None,
        outputs: Optional[Any] = None,
        duration: Optional[float] = None,
        status: str = "success",
        error: Optional[Exception] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record a step in the query processing pipeline.

        Args:
            stage: The stage in the pipeline (e.g., "parsing", "search", "ranking")
            component: The component performing the operation
            inputs: Input data to the component
            outputs: Output data from the component
            duration: How long the step took (in seconds)
            status: Status of the step ("success", "warning", "error")
            error: Exception if an error occurred
            metadata: Additional information about the step
        """
        step_id = len(self.trace_data["steps"]) + 1

        # Create a serializable representation of inputs and outputs
        inputs_safe = (
            self._make_serializable(inputs) if inputs is not None else None
        )
        outputs_safe = (
            self._make_serializable(outputs) if outputs is not None else None
        )

        # Record step data
        step = {
            "step_id": step_id,
            "timestamp": datetime.now().isoformat(),
            "time": time.time(),
            "stage": stage,
            "component": component,
            "status": status,
            "duration": duration,
        }

        # Add detailed information if requested
        if self.detailed:
            step["inputs"] = inputs_safe
            step["outputs"] = outputs_safe
            step["metadata"] = metadata or {}

        # Record error information if applicable
        if error:
            error_info = {
                "type": type(error).__name__,
                "message": str(error),
                "traceback": traceback.format_exc(),
            }
            step["error"] = error_info
            self.trace_data["errors"].append(error_info)

        # Add the step to our trace
        self.trace_data["steps"].append(step)

        # Update component timing information
        if duration is not None:
            if component not in self.trace_data["component_times"]:
                self.trace_data["component_times"][component] = {
                    "total_time": 0,
                    "calls": 0,
                    "max_time": 0,
                    "min_time": float("inf"),
                }

            self.trace_data["component_times"][component][
                "total_time"
            ] += duration
            self.trace_data["component_times"][component]["calls"] += 1
            self.trace_data["component_times"][component]["max_time"] = max(
                self.trace_data["component_times"][component]["max_time"],
                duration,
            )
            self.trace_data["component_times"][component]["min_time"] = min(
                self.trace_data["component_times"][component]["min_time"],
                duration,
            )

        # If the output contains GEO IDs, update our tracker
        if outputs and isinstance(outputs, dict) and "geo_ids" in outputs:
            self.trace_data["geo_ids"] = outputs["geo_ids"]

        # If the output contains metadata, update our tracker
        if outputs and isinstance(outputs, dict) and "metadata" in outputs:
            self.trace_data["metadata"] = outputs["metadata"]

        # Log the step
        log_level = (
            logging.INFO
            if status == "success"
            else logging.WARNING
            if status == "warning"
            else logging.ERROR
        )
        logger.log(
            log_level,
            f"[TRACE:{self.query_id}] {stage}:{component} - {status}"
            + (f" ({duration:.3f}s)" if duration else ""),
        )

        # Periodically save trace data
        if time.time() - self.last_save_time > self.save_interval:
            self.save_trace()
            self.last_save_time = time.time()

    def record_transformation(
        self,
        stage: str,
        input_value: Any,
        output_value: Any,
        transform_type: str,
        description: Optional[str] = None,
    ) -> None:
        """
        Record a transformation of the query or data.

        Args:
            stage: The stage where transformation occurred
            input_value: Value before transformation
            output_value: Value after transformation
            transform_type: Type of transformation (e.g., "expansion", "filtering")
            description: Description of the transformation
        """
        transformation = {
            "timestamp": datetime.now().isoformat(),
            "time": time.time(),
            "stage": stage,
            "transform_type": transform_type,
            "description": description,
            "input": self._make_serializable(input_value),
            "output": self._make_serializable(output_value),
        }

        self.trace_data["transformations"].append(transformation)

        # Log the transformation
        logger.info(
            f"[TRACE:{self.query_id}] {stage} transformed {transform_type}: "
            + f"{input_value} → {output_value}"
            + (f" ({description})" if description else "")
        )

    def record_warning(
        self, stage: str, message: str, details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Record a warning that occurred during processing."""
        warning = {
            "timestamp": datetime.now().isoformat(),
            "time": time.time(),
            "stage": stage,
            "message": message,
            "details": details or {},
        }

        self.trace_data["warnings"].append(warning)
        logger.warning(f"[TRACE:{self.query_id}] {stage} warning: {message}")

    def finalize(
        self, final_result: Optional[Any] = None, status: str = "completed"
    ) -> None:
        """
        Finalize the trace with the query result.

        Args:
            final_result: The final result of the query
            status: Final status of the query ("completed", "failed", "timeout", etc.)
        """
        # Record end time and duration
        end_time = time.time()
        self.trace_data["end_time"] = end_time
        self.trace_data["duration"] = end_time - self.trace_data["start_time"]
        self.trace_data["end_timestamp"] = datetime.now().isoformat()
        self.trace_data["status"] = status

        # Record final result
        if final_result is not None:
            self.trace_data["final_result"] = self._make_serializable(
                final_result
            )

        # Save the final trace
        self.save_trace()

        # Generate report
        self.generate_report()

        # Log completion
        logger.info(
            f"[TRACE:{self.query_id}] Query tracing complete. "
            + f"Duration: {self.trace_data['duration']:.3f}s, Status: {status}"
        )

        # Remove from active tracers
        if self.query_id in QueryTracer._active_tracers:
            del QueryTracer._active_tracers[self.query_id]

    def save_trace(self) -> None:
        """Save the current trace data to disk."""
        trace_file = self.output_dir / f"{self.query_id}_trace.json"
        with open(trace_file, "w") as f:
            json.dump(self.trace_data, f, indent=2, default=str)

    def generate_report(self) -> str:
        """Generate a human-readable report of the query trace."""
        report_file = self.output_dir / f"{self.query_id}_report.md"

        with open(report_file, "w") as f:
            f.write(f"# Query Trace Report: {self.query_id}\n\n")

            # Query information
            f.write("## Query Information\n\n")
            f.write(f"- **Original Query**: `{self.original_query}`\n")
            f.write(f"- **Start Time**: {self.trace_data['start_timestamp']}\n")
            f.write(f"- **End Time**: {self.trace_data['end_timestamp']}\n")
            f.write(
                f"- **Duration**: {self.trace_data['duration']:.3f} seconds\n"
            )
            f.write(f"- **Status**: {self.trace_data['status']}\n")

            # GEO IDs found
            f.write("\n## Results Summary\n\n")
            geo_ids = self.trace_data.get("geo_ids", [])
            f.write(f"- **GEO IDs Found**: {len(geo_ids)}\n")
            if geo_ids:
                f.write("  - " + ", ".join(geo_ids[:10]))
                if len(geo_ids) > 10:
                    f.write(f" and {len(geo_ids) - 10} more")
                f.write("\n")

            # Query transformations
            if self.trace_data["transformations"]:
                f.write("\n## Query Transformations\n\n")
                for i, transform in enumerate(
                    self.trace_data["transformations"], 1
                ):
                    f.write(
                        f"### {i}. {transform['stage']} - {transform['transform_type']}\n\n"
                    )
                    f.write(f"- **Input**: `{transform['input']}`\n")
                    f.write(f"- **Output**: `{transform['output']}`\n")
                    if transform.get("description"):
                        f.write(
                            f"- **Description**: {transform['description']}\n"
                        )
                    f.write("\n")

            # Component performance
            f.write("\n## Component Performance\n\n")
            f.write(
                "| Component | Calls | Total Time (s) | Avg Time (s) | Max Time (s) |\n"
            )
            f.write(
                "|-----------|-------|---------------|--------------|-------------|\n"
            )
            for component, times in self.trace_data["component_times"].items():
                avg_time = (
                    times["total_time"] / times["calls"]
                    if times["calls"] > 0
                    else 0
                )
                f.write(
                    f"| {component} | {times['calls']} | {times['total_time']:.3f} | {avg_time:.3f} | {times['max_time']:.3f} |\n"
                )

            # Execution steps
            f.write("\n## Execution Steps\n\n")
            for step in self.trace_data["steps"]:
                status_icon = (
                    "✅"
                    if step["status"] == "success"
                    else "⚠️"
                    if step["status"] == "warning"
                    else "❌"
                )
                f.write(
                    f"### {status_icon} Step {step['step_id']}: {step['stage']} - {step['component']}\n\n"
                )
                f.write(f"- **Time**: {step['timestamp']}\n")
                if step.get("duration") is not None:
                    f.write(f"- **Duration**: {step['duration']:.3f} seconds\n")
                f.write(f"- **Status**: {step['status']}\n")

                if self.detailed:
                    f.write("\n#### Inputs\n\n")
                    f.write("```\n")
                    f.write(
                        json.dumps(step.get("inputs"), indent=2, default=str)
                        if step.get("inputs")
                        else "None"
                    )
                    f.write("\n```\n\n")

                    f.write("#### Outputs\n\n")
                    f.write("```\n")
                    f.write(
                        json.dumps(step.get("outputs"), indent=2, default=str)
                        if step.get("outputs")
                        else "None"
                    )
                    f.write("\n```\n\n")

                if step.get("error"):
                    f.write("#### Error\n\n")
                    f.write(f"**Type**: {step['error']['type']}\n\n")
                    f.write(f"**Message**: {step['error']['message']}\n\n")
                    f.write("**Traceback**:\n\n")
                    f.write("```\n")
                    f.write(step["error"]["traceback"])
                    f.write("\n```\n\n")

                f.write("\n")

            # Errors and warnings
            if self.trace_data["errors"]:
                f.write("\n## Errors\n\n")
                for i, error in enumerate(self.trace_data["errors"], 1):
                    f.write(f"### Error {i}\n\n")
                    f.write(f"- **Type**: {error['type']}\n")
                    f.write(f"- **Message**: {error['message']}\n")
                    f.write("\n**Traceback**:\n\n")
                    f.write("```\n")
                    f.write(error["traceback"])
                    f.write("\n```\n\n")

            if self.trace_data["warnings"]:
                f.write("\n## Warnings\n\n")
                for i, warning in enumerate(self.trace_data["warnings"], 1):
                    f.write(f"### Warning {i}\n\n")
                    f.write(f"- **Stage**: {warning['stage']}\n")
                    f.write(f"- **Message**: {warning['message']}\n")
                    if warning.get("details"):
                        f.write("- **Details**:\n\n")
                        f.write("```\n")
                        f.write(
                            json.dumps(
                                warning["details"], indent=2, default=str
                            )
                        )
                        f.write("\n```\n\n")

            # Final result summary if detailed
            if self.detailed and self.trace_data.get("final_result"):
                f.write("\n## Final Result\n\n")
                f.write("```\n")
                f.write(
                    json.dumps(
                        self.trace_data["final_result"], indent=2, default=str
                    )
                )
                f.write("\n```\n")

        return str(report_file)

    @contextlib.contextmanager
    def trace_context(self, stage: str, component: str):
        """Context manager to trace a block of code."""
        start_time = time.time()
        error = None
        try:
            yield
        except Exception as e:
            error = e
            raise
        finally:
            duration = time.time() - start_time
            status = "error" if error else "success"
            self.record_step(
                stage, component, duration=duration, status=status, error=error
            )

    def trace_function(self, stage: Optional[str] = None):
        """
        Decorator to trace a function call.

        Args:
            stage: The pipeline stage (defaults to function name if not provided)
        """

        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                component = func.__qualname__
                nonlocal stage
                if stage is None:
                    stage = func.__name__

                # Capture function inputs
                try:
                    # Get argument names
                    sig = inspect.signature(func)
                    bound_args = sig.bind(*args, **kwargs)
                    bound_args.apply_defaults()
                    inputs = dict(bound_args.arguments)
                except Exception:
                    # Fall back to simpler method if signature binding fails
                    inputs = {"args": args, "kwargs": kwargs}

                start_time = time.time()
                error = None
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as e:
                    error = e
                    raise
                finally:
                    duration = time.time() - start_time
                    status = "error" if error else "success"
                    outputs = None if error else result
                    self.record_step(
                        stage,
                        component,
                        inputs,
                        outputs,
                        duration,
                        status,
                        error,
                    )

            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                component = func.__qualname__
                nonlocal stage
                if stage is None:
                    stage = func.__name__

                # Capture function inputs
                try:
                    # Get argument names
                    sig = inspect.signature(func)
                    bound_args = sig.bind(*args, **kwargs)
                    bound_args.apply_defaults()
                    inputs = dict(bound_args.arguments)
                except Exception:
                    # Fall back to simpler method if signature binding fails
                    inputs = {"args": args, "kwargs": kwargs}

                start_time = time.time()
                error = None
                try:
                    result = await func(*args, **kwargs)
                    return result
                except Exception as e:
                    error = e
                    raise
                finally:
                    duration = time.time() - start_time
                    status = "error" if error else "success"
                    outputs = None if error else result
                    self.record_step(
                        stage,
                        component,
                        inputs,
                        outputs,
                        duration,
                        status,
                        error,
                    )

            # Choose the right wrapper based on whether the function is async or not
            if asyncio.iscoroutinefunction(func):
                return async_wrapper
            return wrapper

        # Allow decorator to be used with or without arguments
        if callable(stage):
            func, stage = stage, None
            return decorator(func)
        return decorator

    def _make_serializable(self, obj: Any) -> Any:
        """Convert object to a JSON-serializable form."""
        if obj is None:
            return None

        try:
            # Check if it's directly serializable to JSON
            json.dumps(obj)
            return obj
        except (TypeError, OverflowError, ValueError):
            # If not, try to convert based on type
            if isinstance(obj, (list, tuple, set)):
                return [self._make_serializable(item) for item in obj]
            elif isinstance(obj, dict):
                return {
                    str(k): self._make_serializable(v) for k, v in obj.items()
                }
            elif hasattr(obj, "__dict__"):
                # For custom objects
                return {
                    "__type": type(obj).__name__,
                    "attributes": self._make_serializable(obj.__dict__),
                }
            elif inspect.isfunction(obj) or inspect.ismethod(obj):
                # For functions/methods
                return f"<function {obj.__qualname__}>"
            elif hasattr(obj, "__str__"):
                # Fallback to string representation
                return str(obj)
            else:
                # Last resort
                return repr(obj)
