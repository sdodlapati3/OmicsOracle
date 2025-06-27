#!/usr/bin/env python3
"""
OmicsOracle Search Performance Monitor

This script monitors and analyzes the performance of the search system,
providing insights into query processing time, resource usage, and
potential bottlenecks.
"""

import argparse
import asyncio
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from tabulate import tabulate

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Default test queries representing different complexity levels
DEFAULT_TEST_QUERIES = [
    "human liver cancer RNA-seq",
    "single cell sequencing in lung tissue",
    "diabetes metabolic pathway analysis",
    "methylation patterns in brain tumors",
    "COVID-19 immune response in PBMC",
    "mouse embryonic stem cell differentiation",
    "chromatin accessibility in regulatory regions",
    "gene expression changes during heart development",
    "proteomics analysis of kidney disease",
    "microRNA targeting in hepatocellular carcinoma",
]


class SearchPerformanceMonitor:
    """Monitors and analyzes search system performance."""

    def __init__(self, base_url: str = "http://localhost:8000"):
        """
        Initialize the performance monitor.

        Args:
            base_url: Base URL of the OmicsOracle API
        """
        self.base_url = base_url
        self.search_endpoint = f"{base_url}/api/v1/search"
        self.results_dir = Path("performance_reports")
        self.results_dir.mkdir(exist_ok=True)

        # Performance metrics storage
        self.query_metrics = {}

    async def measure_query_performance(
        self, query: str, iterations: int = 3
    ) -> Dict[str, Any]:
        """
        Measure performance metrics for a specific query.

        Args:
            query: The search query to test
            iterations: Number of times to run the query for averaging

        Returns:
            Dictionary of performance metrics
        """
        metrics = {
            "query": query,
            "response_times": [],
            "component_times": [],
            "result_counts": [],
            "memory_usage": [],
            "cpu_usage": [],
        }

        async with aiohttp.ClientSession() as session:
            for i in range(iterations):
                start_time = time.time()

                try:
                    # Add performance tracking parameter
                    params = {
                        "query": query,
                        "track_performance": "true",
                        "limit": 10,
                    }

                    async with session.get(
                        self.search_endpoint, params=params
                    ) as response:
                        response_time = time.time() - start_time
                        metrics["response_times"].append(response_time)

                        if response.status == 200:
                            data = await response.json()

                            # Extract performance data if available
                            perf_data = data.get("performance", {})
                            component_times = perf_data.get(
                                "component_times", {}
                            )
                            metrics["component_times"].append(component_times)

                            # Extract result count
                            metrics["result_counts"].append(
                                len(data.get("results", []))
                            )

                            # Extract resource usage if available
                            metrics["memory_usage"].append(
                                perf_data.get("memory_usage", 0)
                            )
                            metrics["cpu_usage"].append(
                                perf_data.get("cpu_usage", 0)
                            )
                        else:
                            logger.warning(
                                f"Query failed with status {response.status}: {await response.text()}"
                            )

                except Exception as e:
                    logger.error(
                        f"Error measuring performance for query '{query}': {str(e)}"
                    )

                # Add a small delay between iterations
                await asyncio.sleep(0.5)

        # Calculate aggregated metrics
        if metrics["response_times"]:
            metrics["avg_response_time"] = sum(metrics["response_times"]) / len(
                metrics["response_times"]
            )
            metrics["min_response_time"] = min(metrics["response_times"])
            metrics["max_response_time"] = max(metrics["response_times"])

        if metrics["result_counts"]:
            metrics["avg_result_count"] = sum(metrics["result_counts"]) / len(
                metrics["result_counts"]
            )

        return metrics

    async def run_performance_test(
        self, queries: List[str], iterations: int = 3
    ) -> Dict[str, Any]:
        """
        Run a complete performance test on multiple queries.

        Args:
            queries: List of queries to test
            iterations: Number of iterations per query

        Returns:
            Dictionary with all performance metrics
        """
        logger.info(
            f"Running performance test on {len(queries)} queries with {iterations} iterations each"
        )

        all_metrics = {
            "timestamp": datetime.now().isoformat(),
            "queries": {},
            "summary": {},
        }

        for query in queries:
            logger.info(f"Testing query: {query}")
            metrics = await self.measure_query_performance(query, iterations)
            all_metrics["queries"][query] = metrics

        # Calculate summary statistics
        response_times = [
            m["avg_response_time"]
            for m in all_metrics["queries"].values()
            if "avg_response_time" in m
        ]

        if response_times:
            all_metrics["summary"]["overall_avg_response_time"] = sum(
                response_times
            ) / len(response_times)
            all_metrics["summary"]["overall_min_response_time"] = min(
                response_times
            )
            all_metrics["summary"]["overall_max_response_time"] = max(
                response_times
            )
            all_metrics["summary"]["response_time_std_dev"] = np.std(
                response_times
            )

        return all_metrics

    def generate_report(self, metrics: Dict[str, Any]) -> str:
        """
        Generate a human-readable performance report.

        Args:
            metrics: The performance metrics dictionary

        Returns:
            Report as formatted string
        """
        report = []
        report.append("# OmicsOracle Search Performance Report")
        report.append(f"Generated: {metrics['timestamp']}")
        report.append("")

        # Summary section
        report.append("## Summary")
        summary = metrics.get("summary", {})

        summary_table = []
        if "overall_avg_response_time" in summary:
            summary_table.append(
                [
                    "Average Response Time",
                    f"{summary['overall_avg_response_time']:.4f} sec",
                ]
            )
        if "overall_min_response_time" in summary:
            summary_table.append(
                [
                    "Minimum Response Time",
                    f"{summary['overall_min_response_time']:.4f} sec",
                ]
            )
        if "overall_max_response_time" in summary:
            summary_table.append(
                [
                    "Maximum Response Time",
                    f"{summary['overall_max_response_time']:.4f} sec",
                ]
            )
        if "response_time_std_dev" in summary:
            summary_table.append(
                [
                    "Response Time Std Dev",
                    f"{summary['response_time_std_dev']:.4f} sec",
                ]
            )

        report.append(tabulate(summary_table, tablefmt="pipe"))
        report.append("")

        # Per-query results
        report.append("## Query Performance Details")

        query_details = []
        headers = [
            "Query",
            "Avg Time (sec)",
            "Min Time (sec)",
            "Max Time (sec)",
            "Avg Results",
        ]

        for query, data in metrics["queries"].items():
            if "avg_response_time" in data:
                row = [
                    query,
                    f"{data.get('avg_response_time', 0):.4f}",
                    f"{data.get('min_response_time', 0):.4f}",
                    f"{data.get('max_response_time', 0):.4f}",
                    f"{data.get('avg_result_count', 0):.1f}",
                ]
                query_details.append(row)

        report.append(tabulate(query_details, headers=headers, tablefmt="pipe"))
        report.append("")

        # Component timing analysis if available
        report.append("## Component Performance Analysis")

        for query, data in metrics["queries"].items():
            if data.get("component_times") and len(data["component_times"]) > 0:
                report.append(f"### Query: {query}")

                # Average component times across iterations
                avg_component_times = {}
                for comp_time_dict in data["component_times"]:
                    for component, time_val in comp_time_dict.items():
                        if component not in avg_component_times:
                            avg_component_times[component] = []
                        avg_component_times[component].append(time_val)

                comp_table = []
                for component, times in avg_component_times.items():
                    avg_time = sum(times) / len(times)
                    comp_table.append([component, f"{avg_time:.4f} sec"])

                report.append(
                    tabulate(
                        comp_table,
                        headers=["Component", "Avg Time (sec)"],
                        tablefmt="pipe",
                    )
                )
                report.append("")

        return "\n".join(report)

    def generate_visualizations(
        self, metrics: Dict[str, Any], output_dir: Optional[Path] = None
    ) -> List[Path]:
        """
        Generate performance visualization plots.

        Args:
            metrics: The performance metrics
            output_dir: Directory to save visualizations (defaults to performance_reports)

        Returns:
            List of paths to generated visualization files
        """
        if output_dir is None:
            output_dir = self.results_dir

        output_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        generated_files = []

        # Prepare data for plotting
        queries = list(metrics["queries"].keys())
        avg_times = [
            metrics["queries"][q].get("avg_response_time", 0) for q in queries
        ]

        # 1. Query response time bar chart
        plt.figure(figsize=(12, 6))
        plt.bar(range(len(queries)), avg_times)
        plt.xticks(
            range(len(queries)),
            [q[:20] + "..." if len(q) > 20 else q for q in queries],
            rotation=45,
        )
        plt.xlabel("Query")
        plt.ylabel("Average Response Time (seconds)")
        plt.title("Query Response Time Comparison")
        plt.tight_layout()

        chart_path = output_dir / f"response_times_{timestamp}.png"
        plt.savefig(chart_path)
        plt.close()
        generated_files.append(chart_path)

        # 2. Component time breakdown for each query
        for query, data in metrics["queries"].items():
            if data.get("component_times") and len(data["component_times"]) > 0:
                # Average component times across iterations
                avg_component_times = {}
                for comp_time_dict in data["component_times"]:
                    for component, time_val in comp_time_dict.items():
                        if component not in avg_component_times:
                            avg_component_times[component] = []
                        avg_component_times[component].append(time_val)

                components = list(avg_component_times.keys())
                avg_times = [
                    sum(avg_component_times[c]) / len(avg_component_times[c])
                    for c in components
                ]

                plt.figure(figsize=(12, 6))
                plt.bar(range(len(components)), avg_times)
                plt.xticks(range(len(components)), components, rotation=45)
                plt.xlabel("Component")
                plt.ylabel("Average Time (seconds)")
                plt.title(f"Component Time Breakdown - {query[:30]}...")
                plt.tight_layout()

                query_name = query.replace(" ", "_")[:20]
                component_path = (
                    output_dir / f"components_{query_name}_{timestamp}.png"
                )
                plt.savefig(component_path)
                plt.close()
                generated_files.append(component_path)

        return generated_files

    async def run_and_save_report(
        self,
        queries: List[str],
        iterations: int = 3,
        save_json: bool = True,
        save_markdown: bool = True,
        generate_plots: bool = True,
    ) -> Dict[str, Path]:
        """
        Run performance tests and save results to files.

        Args:
            queries: List of search queries to test
            iterations: Number of iterations per query
            save_json: Whether to save raw metrics as JSON
            save_markdown: Whether to save formatted report as Markdown
            generate_plots: Whether to generate visualization plots

        Returns:
            Dictionary with paths to generated files
        """
        metrics = await self.run_performance_test(queries, iterations)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_files = {}

        # Save raw metrics as JSON
        if save_json:
            json_path = (
                self.results_dir / f"search_performance_{timestamp}.json"
            )
            with open(json_path, "w") as f:
                json.dump(metrics, f, indent=2)
            output_files["json"] = json_path
            logger.info(f"Saved raw metrics to {json_path}")

        # Save formatted report as Markdown
        if save_markdown:
            report = self.generate_report(metrics)
            md_path = (
                self.results_dir / f"search_performance_report_{timestamp}.md"
            )
            with open(md_path, "w") as f:
                f.write(report)
            output_files["markdown"] = md_path
            logger.info(f"Saved formatted report to {md_path}")

        # Generate visualization plots
        if generate_plots:
            plot_files = self.generate_visualizations(metrics)
            output_files["plots"] = plot_files
            logger.info(f"Generated {len(plot_files)} visualization plots")

        return output_files


async def main():
    """Main function to run the search performance monitor."""
    parser = argparse.ArgumentParser(
        description="OmicsOracle Search Performance Monitor"
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8000",
        help="Base URL of the OmicsOracle API",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="Number of iterations per query",
    )
    parser.add_argument(
        "--queries-file", help="JSON file with custom test queries"
    )
    parser.add_argument(
        "--no-json", action="store_true", help="Don't save raw metrics as JSON"
    )
    parser.add_argument(
        "--no-markdown",
        action="store_true",
        help="Don't save formatted report as Markdown",
    )
    parser.add_argument(
        "--no-plots",
        action="store_true",
        help="Don't generate visualization plots",
    )

    args = parser.parse_args()

    # Load custom queries if provided, otherwise use defaults
    if args.queries_file:
        try:
            with open(args.queries_file, "r") as f:
                test_queries = json.load(f)
                if not isinstance(test_queries, list):
                    logger.error(
                        "Queries file must contain a JSON array of query strings"
                    )
                    return
        except Exception as e:
            logger.error(f"Error loading queries file: {str(e)}")
            return
    else:
        test_queries = DEFAULT_TEST_QUERIES

    monitor = SearchPerformanceMonitor(base_url=args.url)
    output_files = await monitor.run_and_save_report(
        queries=test_queries,
        iterations=args.iterations,
        save_json=not args.no_json,
        save_markdown=not args.no_markdown,
        generate_plots=not args.no_plots,
    )

    print("\n🔍 Search Performance Test Completed")
    print("=================================")

    if "markdown" in output_files:
        print(f"📊 Report: {output_files['markdown']}")

    if "json" in output_files:
        print(f"📋 Raw Data: {output_files['json']}")

    if "plots" in output_files and output_files["plots"]:
        print(f"📈 Generated {len(output_files['plots'])} visualization plots")


if __name__ == "__main__":
    asyncio.run(main())
