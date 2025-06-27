"""
OmicsOracle Trace Analyzer and Report Generator

This script analyzes query trace files and generates a comprehensive
end-to-end flow document that shows how queries move through the system.
"""

import argparse
import glob
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_trace_file(file_path: str) -> Dict[str, Any]:
    """Load a trace file and return its contents."""
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load trace file {file_path}: {e}")
        return {}


def load_all_traces(
    trace_dir: str, query: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Load all trace files in the directory, optionally filtering by query.

    Args:
        trace_dir: Directory containing trace files
        query: Optional query string to filter traces

    Returns:
        List of trace data dictionaries
    """
    trace_files = glob.glob(os.path.join(trace_dir, "*_trace.json"))
    traces = []

    for file_path in trace_files:
        trace_data = load_trace_file(file_path)

        # Skip empty or invalid traces
        if not trace_data or "original_query" not in trace_data:
            continue

        # Filter by query if specified
        if (
            query
            and query.lower()
            not in trace_data.get("original_query", "").lower()
        ):
            continue

        traces.append(trace_data)

    # Sort by start time
    traces.sort(key=lambda t: t.get("start_time", 0))

    logger.info(
        f"Loaded {len(traces)} trace files"
        + (f" for query containing '{query}'" if query else "")
    )

    return traces


def extract_query_flow(traces: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Extract the query flow from trace data.

    Args:
        traces: List of trace data dictionaries

    Returns:
        Dictionary containing query flow information
    """
    if not traces:
        return {"flows": []}

    flows = []

    for trace in traces:
        query = trace.get("original_query", "Unknown query")
        query_id = trace.get("query_id", "Unknown ID")
        start_time = trace.get("start_timestamp", "Unknown time")
        duration = trace.get("duration", 0)
        status = trace.get("status", "unknown")

        # Extract steps
        steps = trace.get("steps", [])

        # Extract transformations
        transformations = trace.get("transformations", [])

        # Extract component performance
        component_times = trace.get("component_times", {})

        # Extract errors and warnings
        errors = trace.get("errors", [])
        warnings = trace.get("warnings", [])

        # Create flow entry
        flow = {
            "query": query,
            "query_id": query_id,
            "start_time": start_time,
            "duration": duration,
            "status": status,
            "steps": steps,
            "transformations": transformations,
            "component_times": component_times,
            "errors": errors,
            "warnings": warnings,
            "geo_ids": trace.get("geo_ids", []),
            "result": trace.get("final_result", None),
        }

        flows.append(flow)

    return {"flows": flows}


def generate_flow_document(flow_data: Dict[str, Any], output_file: str) -> None:
    """
    Generate a comprehensive flow document from the flow data.

    Args:
        flow_data: Dictionary containing query flow information
        output_file: Output file path for the document
    """
    flows = flow_data.get("flows", [])

    with open(output_file, "w") as f:
        # Document header
        f.write("# OmicsOracle Query Flow Analysis\n\n")
        f.write(
            f"*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n"
        )
        f.write(
            f"This document analyzes {len(flows)} query flows through the OmicsOracle system.\n\n"
        )

        # Table of contents
        f.write("## Table of Contents\n\n")
        f.write("1. [Summary](#summary)\n")
        f.write("2. [Query Flows](#query-flows)\n")
        for i, flow in enumerate(flows, 1):
            query = flow.get("query", "Unknown query")
            query_short = query[:50] + "..." if len(query) > 50 else query
            f.write(f"   {i}. [{query_short}](#flow-{i})\n")
        f.write("3. [Common Patterns](#common-patterns)\n")
        f.write("4. [Performance Analysis](#performance-analysis)\n")
        f.write("5. [Error Analysis](#error-analysis)\n\n")

        # Summary section
        f.write("## Summary\n\n")

        successful_flows = sum(
            1 for flow in flows if flow.get("status") == "completed"
        )
        failed_flows = sum(
            1 for flow in flows if flow.get("status") == "failed"
        )

        avg_duration = (
            sum(flow.get("duration", 0) for flow in flows) / len(flows)
            if flows
            else 0
        )
        avg_results = (
            sum(len(flow.get("geo_ids", [])) for flow in flows) / len(flows)
            if flows
            else 0
        )

        f.write(f"- **Total Flows**: {len(flows)}\n")
        f.write(f"- **Successful Flows**: {successful_flows}\n")
        f.write(f"- **Failed Flows**: {failed_flows}\n")
        f.write(f"- **Average Duration**: {avg_duration:.2f} seconds\n")
        f.write(f"- **Average Results**: {avg_results:.1f} GEO IDs\n\n")

        # Query transformations summary
        all_transformations = []
        for flow in flows:
            all_transformations.extend(flow.get("transformations", []))

        if all_transformations:
            transformation_types = {}
            for transform in all_transformations:
                t_type = transform.get("transform_type", "unknown")
                if t_type not in transformation_types:
                    transformation_types[t_type] = 0
                transformation_types[t_type] += 1

            f.write("### Query Transformation Types\n\n")
            for t_type, count in transformation_types.items():
                f.write(f"- **{t_type}**: {count}\n")
            f.write("\n")

        # Component performance summary
        all_components = set()
        for flow in flows:
            all_components.update(flow.get("component_times", {}).keys())

        if all_components:
            f.write("### Component Performance Summary\n\n")
            f.write("| Component | Avg. Time (s) | Avg. Calls | Flows |\n")
            f.write("|-----------|--------------|------------|-------|\n")

            for component in sorted(all_components):
                # Calculate averages across flows that include this component
                flows_with_component = [
                    flow
                    for flow in flows
                    if component in flow.get("component_times", {})
                ]

                avg_time = sum(
                    flow["component_times"][component]["total_time"]
                    for flow in flows_with_component
                ) / len(flows_with_component)

                avg_calls = sum(
                    flow["component_times"][component]["calls"]
                    for flow in flows_with_component
                ) / len(flows_with_component)

                f.write(
                    f"| {component} | {avg_time:.3f} | {avg_calls:.1f} | {len(flows_with_component)} |\n"
                )

            f.write("\n")

        # Query flows section
        f.write("## Query Flows\n\n")

        for i, flow in enumerate(flows, 1):
            query = flow.get("query", "Unknown query")
            query_id = flow.get("query_id", "Unknown ID")
            status = flow.get("status", "unknown")
            duration = flow.get("duration", 0)
            start_time = flow.get("start_time", "Unknown time")
            geo_ids = flow.get("geo_ids", [])

            status_emoji = (
                "✅"
                if status == "completed"
                else "❌"
                if status == "failed"
                else "⚠️"
            )

            f.write(
                f"### <a name='flow-{i}'></a>{status_emoji} Flow {i}: {query}\n\n"
            )
            f.write(f"- **Query ID**: {query_id}\n")
            f.write(f"- **Start Time**: {start_time}\n")
            f.write(f"- **Duration**: {duration:.2f} seconds\n")
            f.write(f"- **Status**: {status}\n")
            f.write(f"- **Results**: {len(geo_ids)} GEO IDs\n")

            if geo_ids:
                f.write("  - " + ", ".join(geo_ids[:10]))
                if len(geo_ids) > 10:
                    f.write(f" and {len(geo_ids) - 10} more")
                f.write("\n")

            # Transformations
            transformations = flow.get("transformations", [])
            if transformations:
                f.write("\n#### Query Transformations\n\n")
                for j, transform in enumerate(transformations, 1):
                    stage = transform.get("stage", "unknown")
                    t_type = transform.get("transform_type", "unknown")
                    input_val = transform.get("input", "")
                    output_val = transform.get("output", "")
                    description = transform.get("description", "")

                    f.write(f"**{j}. {stage} - {t_type}**\n\n")
                    f.write(f"- Input: `{input_val}`\n")
                    f.write(f"- Output: `{output_val}`\n")
                    if description:
                        f.write(f"- Description: {description}\n")
                    f.write("\n")

            # Key execution steps
            steps = flow.get("steps", [])
            if steps:
                f.write("\n#### Key Execution Steps\n\n")

                # Filter to just include key steps for brevity
                key_stages = {
                    "initialization",
                    "query_parsing",
                    "search",
                    "formatting",
                    "frontend",
                }
                key_steps = [
                    step
                    for step in steps
                    if step.get("stage") in key_stages
                    or step.get("status") == "error"
                ]

                for step in key_steps:
                    step_id = step.get("step_id", "?")
                    stage = step.get("stage", "unknown")
                    component = step.get("component", "unknown")
                    status = step.get("status", "unknown")
                    timestamp = step.get("timestamp", "unknown")
                    duration = step.get("duration")

                    status_icon = (
                        "✅"
                        if status == "success"
                        else "⚠️"
                        if status == "warning"
                        else "❌"
                    )

                    f.write(
                        f"**{status_icon} Step {step_id}: {stage} - {component}**\n\n"
                    )
                    f.write(f"- Time: {timestamp}\n")
                    if duration is not None:
                        f.write(f"- Duration: {duration:.3f} seconds\n")
                    f.write(f"- Status: {status}\n")

                    # Show error details if present
                    if "error" in step:
                        error = step["error"]
                        f.write(
                            f"\n**Error**: {error.get('type')}: {error.get('message')}\n\n"
                        )

                        # Include a snippet of the traceback
                        traceback = error.get("traceback", "").split("\n")
                        if len(traceback) > 5:
                            traceback = traceback[:5] + ["..."]
                        f.write("```\n" + "\n".join(traceback) + "\n```\n\n")

                    f.write("\n")

            # Errors and warnings
            errors = flow.get("errors", [])
            warnings = flow.get("warnings", [])

            if errors:
                f.write("\n#### Errors\n\n")
                for j, error in enumerate(errors, 1):
                    error_type = error.get("type", "Unknown error")
                    message = error.get("message", "No message")

                    f.write(f"**{j}. {error_type}**\n\n")
                    f.write(f"- Message: {message}\n")
                    f.write("\n")

            if warnings:
                f.write("\n#### Warnings\n\n")
                for j, warning in enumerate(warnings, 1):
                    stage = warning.get("stage", "unknown")
                    message = warning.get("message", "No message")

                    f.write(f"**{j}. {stage}**\n\n")
                    f.write(f"- Message: {message}\n")
                    f.write("\n")

            f.write("\n")

        # Common patterns section
        f.write("## Common Patterns\n\n")

        # Identify common components and stages
        all_stages = set()
        all_components = set()

        for flow in flows:
            for step in flow.get("steps", []):
                all_stages.add(step.get("stage", "unknown"))
                all_components.add(step.get("component", "unknown"))

        f.write("### Common Processing Stages\n\n")
        for stage in sorted(all_stages):
            steps_in_stage = sum(
                1
                for flow in flows
                for step in flow.get("steps", [])
                if step.get("stage") == stage
            )

            flows_with_stage = sum(
                1
                for flow in flows
                if any(
                    step.get("stage") == stage for step in flow.get("steps", [])
                )
            )

            f.write(
                f"- **{stage}**: Found in {flows_with_stage}/{len(flows)} flows, {steps_in_stage} total steps\n"
            )

        f.write("\n### Common Components\n\n")
        for component in sorted(all_components):
            steps_with_component = sum(
                1
                for flow in flows
                for step in flow.get("steps", [])
                if step.get("component") == component
            )

            flows_with_component = sum(
                1
                for flow in flows
                if any(
                    step.get("component") == component
                    for step in flow.get("steps", [])
                )
            )

            f.write(
                f"- **{component}**: Found in {flows_with_component}/{len(flows)} flows, {steps_with_component} total steps\n"
            )

        f.write("\n")

        # Performance analysis
        f.write("## Performance Analysis\n\n")

        # Calculate stage durations
        stage_durations = {}

        for flow in flows:
            for step in flow.get("steps", []):
                stage = step.get("stage", "unknown")
                duration = step.get("duration")

                if duration is not None:
                    if stage not in stage_durations:
                        stage_durations[stage] = []
                    stage_durations[stage].append(duration)

        if stage_durations:
            f.write("### Stage Performance\n\n")
            f.write(
                "| Stage | Avg. Duration (s) | Min (s) | Max (s) | Count |\n"
            )
            f.write(
                "|-------|-------------------|---------|---------|-------|\n"
            )

            for stage, durations in sorted(stage_durations.items()):
                avg_duration = sum(durations) / len(durations)
                min_duration = min(durations)
                max_duration = max(durations)

                f.write(
                    f"| {stage} | {avg_duration:.3f} | {min_duration:.3f} | {max_duration:.3f} | {len(durations)} |\n"
                )

            f.write("\n")

        # Error analysis
        f.write("## Error Analysis\n\n")

        # Count error types
        error_types = {}

        for flow in flows:
            for error in flow.get("errors", []):
                error_type = error.get("type", "Unknown error")

                if error_type not in error_types:
                    error_types[error_type] = 0
                error_types[error_type] += 1

        if error_types:
            f.write("### Error Types\n\n")
            for error_type, count in sorted(
                error_types.items(), key=lambda x: x[1], reverse=True
            ):
                f.write(f"- **{error_type}**: {count} occurrences\n")
        else:
            f.write("No errors found in the analyzed flows.\n")

        f.write("\n")

    logger.info(f"Generated flow document: {output_file}")


def analyze_traces(
    trace_dir: str, output_file: str, query: Optional[str] = None
) -> None:
    """
    Analyze trace files and generate a comprehensive flow document.

    Args:
        trace_dir: Directory containing trace files
        output_file: Output file path for the document
        query: Optional query string to filter traces
    """
    # Load traces
    traces = load_all_traces(trace_dir, query)

    if not traces:
        logger.warning("No trace files found")
        return

    # Extract query flow
    flow_data = extract_query_flow(traces)

    # Generate flow document
    generate_flow_document(flow_data, output_file)


def main():
    """Run the trace analyzer from the command line."""
    parser = argparse.ArgumentParser(
        description="Analyze OmicsOracle query traces"
    )
    parser.add_argument(
        "--trace-dir",
        default="query_traces",
        help="Directory containing trace files",
    )
    parser.add_argument(
        "--output", default="query_flow_analysis.md", help="Output file path"
    )
    parser.add_argument("--query", help="Filter traces by query string")

    args = parser.parse_args()

    analyze_traces(args.trace_dir, args.output, args.query)


if __name__ == "__main__":
    main()
