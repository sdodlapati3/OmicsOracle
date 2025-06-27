#!/usr/bin/env python3
"""
OmicsOracle Search Error Analyzer

This script analyzes and categorizes errors in the search system,
providing insights into common failure modes and suggesting improvements.
"""

import argparse
import asyncio
import json
import logging
import re
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import matplotlib.pyplot as plt
import pandas as pd
from tabulate import tabulate

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Error patterns to look for in logs
ERROR_PATTERNS = {
    "connection_timeout": [
        r"ConnectionTimeout",
        r"timeout.*connect",
        r"connection.*timed out",
    ],
    "api_rate_limit": [
        r"rate limit exceeded",
        r"too many requests",
        r"429 Too Many Requests",
    ],
    "parsing_error": [
        r"SyntaxError",
        r"ParseError",
        r"Invalid syntax",
        r"Failed to parse",
    ],
    "authentication_error": [
        r"AuthenticationError",
        r"Invalid token",
        r"API key.*invalid",
        r"401 Unauthorized",
    ],
    "data_not_found": [
        r"No data found",
        r"GEO.*not found",
        r"404 Not Found",
        r"Dataset.*does not exist",
    ],
    "server_error": [
        r"500 Internal Server Error",
        r"502 Bad Gateway",
        r"503 Service Unavailable",
        r"504 Gateway Timeout",
    ],
    "query_too_complex": [
        r"Query.*too complex",
        r"exceeded.*complexity limit",
        r"query.*too large",
    ],
    "memory_error": [r"MemoryError", r"Out of memory", r"insufficient memory"],
    "invalid_parameter": [
        r"Invalid parameter",
        r"missing required parameter",
        r"parameter.*must be",
    ],
    "geo_api_error": [
        r"GEO API error",
        r"error.*accessing GEO",
        r"GEO.*not responding",
    ],
    "ncbi_api_error": [
        r"NCBI API error",
        r"error.*accessing NCBI",
        r"E-utilities.*error",
    ],
}


class SearchErrorAnalyzer:
    """Analyzes search system errors from logs and error reports."""

    def __init__(self):
        """Initialize the error analyzer."""
        self.results_dir = Path("error_analysis")
        self.results_dir.mkdir(exist_ok=True)

        # Error storage
        self.errors_by_category = {}
        self.errors_by_date = {}
        self.error_patterns = ERROR_PATTERNS

    def parse_log_file(self, log_path: Path) -> List[Dict[str, Any]]:
        """
        Parse a log file to extract error entries.

        Args:
            log_path: Path to the log file

        Returns:
            List of parsed error entries
        """
        logger.info(f"Parsing log file: {log_path}")

        # Common log patterns
        # 2023-06-27 14:03:06,789 - name - ERROR - Message
        log_pattern = re.compile(
            r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d{3})?)\s+-\s+"
            r"(\w+(?:\.\w+)*)\s+-\s+(\w+)\s+-\s+(.*)"
        )

        error_entries = []

        try:
            with open(log_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    # Skip non-error lines
                    if " ERROR " not in line and " CRITICAL " not in line:
                        continue

                    match = log_pattern.match(line)
                    if match:
                        (
                            timestamp_str,
                            logger_name,
                            level,
                            message,
                        ) = match.groups()

                        # Parse timestamp
                        try:
                            if "," in timestamp_str:
                                timestamp = datetime.strptime(
                                    timestamp_str, "%Y-%m-%d %H:%M:%S,%f"
                                )
                            else:
                                timestamp = datetime.strptime(
                                    timestamp_str, "%Y-%m-%d %H:%M:%S"
                                )
                        except ValueError:
                            timestamp = None

                        error_entries.append(
                            {
                                "timestamp": timestamp,
                                "date": timestamp.date() if timestamp else None,
                                "logger": logger_name,
                                "level": level,
                                "message": message,
                                "file": log_path.name,
                                "line": line_num,
                            }
                        )
                    else:
                        # For multiline errors, append to the last error message
                        if error_entries:
                            error_entries[-1]["message"] += "\n" + line.strip()

        except Exception as e:
            logger.error(f"Error parsing log file {log_path}: {str(e)}")

        logger.info(
            f"Extracted {len(error_entries)} error entries from {log_path}"
        )
        return error_entries

    def categorize_error(self, error_message: str) -> str:
        """
        Categorize an error message based on patterns.

        Args:
            error_message: The error message to categorize

        Returns:
            Category name or "uncategorized"
        """
        error_message = error_message.lower()

        for category, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern.lower(), error_message):
                    return category

        return "uncategorized"

    def analyze_errors(
        self, error_entries: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze error entries to extract insights.

        Args:
            error_entries: List of error entries

        Returns:
            Dictionary with error analysis results
        """
        logger.info(f"Analyzing {len(error_entries)} error entries")

        analysis = {
            "timestamp": datetime.now().isoformat(),
            "total_errors": len(error_entries),
            "errors_by_category": {},
            "errors_by_date": {},
            "errors_by_logger": {},
            "recent_errors": [],
            "example_errors": {},
            "recommendations": [],
        }

        # Categorize errors
        for entry in error_entries:
            category = self.categorize_error(entry["message"])

            # Count by category
            if category not in analysis["errors_by_category"]:
                analysis["errors_by_category"][category] = 0
            analysis["errors_by_category"][category] += 1

            # Group by date
            date_str = entry["date"].isoformat() if entry["date"] else "unknown"
            if date_str not in analysis["errors_by_date"]:
                analysis["errors_by_date"][date_str] = 0
            analysis["errors_by_date"][date_str] += 1

            # Group by logger
            logger_name = entry["logger"]
            if logger_name not in analysis["errors_by_logger"]:
                analysis["errors_by_logger"][logger_name] = 0
            analysis["errors_by_logger"][logger_name] += 1

            # Keep recent errors (last 50)
            if len(analysis["recent_errors"]) < 50:
                analysis["recent_errors"].append(
                    {
                        "timestamp": entry["timestamp"].isoformat()
                        if entry["timestamp"]
                        else None,
                        "category": category,
                        "message": entry["message"],
                        "file": entry["file"],
                        "line": entry["line"],
                    }
                )

            # Keep example errors for each category
            if (
                category not in analysis["example_errors"]
                and len(analysis["example_errors"]) < 20
            ):
                analysis["example_errors"][category] = entry["message"]

        # Generate recommendations based on findings
        self._generate_recommendations(analysis)

        return analysis

    def _generate_recommendations(self, analysis: Dict[str, Any]) -> None:
        """
        Generate recommendations based on error analysis.

        Args:
            analysis: The error analysis dictionary to update with recommendations
        """
        recommendations = []

        # Check for common error categories
        categories = analysis["errors_by_category"]

        if categories.get("connection_timeout", 0) > 0:
            recommendations.append(
                {
                    "category": "connection_timeout",
                    "issue": "Connection timeouts detected",
                    "suggestion": "Consider increasing timeout values or implementing retry mechanisms with exponential backoff.",
                    "priority": "high"
                    if categories.get("connection_timeout", 0) > 10
                    else "medium",
                }
            )

        if categories.get("api_rate_limit", 0) > 0:
            recommendations.append(
                {
                    "category": "api_rate_limit",
                    "issue": "API rate limit errors detected",
                    "suggestion": "Implement rate limiting on the client side or consider requesting increased limits from the API provider.",
                    "priority": "high",
                }
            )

        if categories.get("parsing_error", 0) > 0:
            recommendations.append(
                {
                    "category": "parsing_error",
                    "issue": "Data parsing errors detected",
                    "suggestion": "Improve input validation and add better error handling for malformed data.",
                    "priority": "medium",
                }
            )

        if categories.get("data_not_found", 0) > 0:
            recommendations.append(
                {
                    "category": "data_not_found",
                    "issue": "Frequent 'data not found' errors",
                    "suggestion": "Improve user feedback for non-existent data and consider implementing a fallback search strategy.",
                    "priority": "medium",
                }
            )

        if categories.get("server_error", 0) > 0:
            recommendations.append(
                {
                    "category": "server_error",
                    "issue": "Server-side errors detected",
                    "suggestion": "Investigate and fix server-side issues, and implement circuit breakers to handle temporary outages.",
                    "priority": "high"
                    if categories.get("server_error", 0) > 5
                    else "medium",
                }
            )

        if categories.get("memory_error", 0) > 0:
            recommendations.append(
                {
                    "category": "memory_error",
                    "issue": "Memory-related errors detected",
                    "suggestion": "Optimize memory usage, implement pagination for large results, and consider memory limits for queries.",
                    "priority": "high",
                }
            )

        if (
            categories.get("geo_api_error", 0) > 0
            or categories.get("ncbi_api_error", 0) > 0
        ):
            recommendations.append(
                {
                    "category": "external_api_error",
                    "issue": "Errors with external APIs (GEO, NCBI)",
                    "suggestion": "Implement more robust error handling for external APIs and consider local caching of frequently accessed data.",
                    "priority": "high",
                }
            )

        # Add generic recommendations if needed
        if len(recommendations) == 0:
            recommendations.append(
                {
                    "category": "general",
                    "issue": "Miscellaneous errors detected",
                    "suggestion": "Review error logs in detail and implement structured error handling throughout the application.",
                    "priority": "medium",
                }
            )

        # Check if uncategorized errors are a significant portion
        total = analysis["total_errors"]
        uncategorized = categories.get("uncategorized", 0)
        if (
            uncategorized > 0 and (uncategorized / total) > 0.3
        ):  # More than 30% uncategorized
            recommendations.append(
                {
                    "category": "uncategorized",
                    "issue": f"High number of uncategorized errors ({uncategorized} out of {total})",
                    "suggestion": "Review uncategorized errors and update error patterns to better categorize them.",
                    "priority": "medium",
                }
            )

        # Sort recommendations by priority
        priority_order = {"high": 0, "medium": 1, "low": 2}
        recommendations.sort(
            key=lambda x: priority_order.get(x["priority"], 99)
        )

        analysis["recommendations"] = recommendations

    def generate_report(self, analysis: Dict[str, Any]) -> str:
        """
        Generate a human-readable error analysis report.

        Args:
            analysis: The error analysis dictionary

        Returns:
            Report as formatted string
        """
        report = []
        report.append("# OmicsOracle Search Error Analysis Report")
        report.append(f"Generated: {analysis['timestamp']}")
        report.append(f"Total Errors Analyzed: {analysis['total_errors']}")
        report.append("")

        # Error categories
        report.append("## Error Categories")
        categories = [
            (cat, count)
            for cat, count in analysis["errors_by_category"].items()
        ]
        categories.sort(key=lambda x: x[1], reverse=True)

        cat_table = []
        for category, count in categories:
            percentage = (count / analysis["total_errors"]) * 100
            cat_table.append([category, count, f"{percentage:.1f}%"])

        report.append(
            tabulate(
                cat_table,
                headers=["Category", "Count", "Percentage"],
                tablefmt="pipe",
            )
        )
        report.append("")

        # Time distribution
        if analysis["errors_by_date"]:
            report.append("## Error Distribution by Date")
            dates = [
                (date, count)
                for date, count in analysis["errors_by_date"].items()
            ]
            dates.sort(key=lambda x: x[0])  # Sort by date

            date_table = []
            for date, count in dates:
                date_table.append([date, count])

            report.append(
                tabulate(date_table, headers=["Date", "Count"], tablefmt="pipe")
            )
            report.append("")

        # Logger distribution
        report.append("## Error Distribution by Logger")
        loggers = [
            (logger, count)
            for logger, count in analysis["errors_by_logger"].items()
        ]
        loggers.sort(key=lambda x: x[1], reverse=True)

        logger_table = []
        for logger, count in loggers:
            percentage = (count / analysis["total_errors"]) * 100
            logger_table.append([logger, count, f"{percentage:.1f}%"])

        report.append(
            tabulate(
                logger_table,
                headers=["Logger", "Count", "Percentage"],
                tablefmt="pipe",
            )
        )
        report.append("")

        # Example errors
        report.append("## Example Errors by Category")

        for category, message in analysis["example_errors"].items():
            report.append(f"### {category}")
            report.append("```")
            # Limit message length to avoid extremely long reports
            if len(message) > 500:
                report.append(message[:500] + "... (truncated)")
            else:
                report.append(message)
            report.append("```")
            report.append("")

        # Recommendations
        report.append("## Recommendations")

        for rec in analysis["recommendations"]:
            priority_marker = (
                "🔴"
                if rec["priority"] == "high"
                else "🟠"
                if rec["priority"] == "medium"
                else "🟡"
            )
            report.append(f"### {priority_marker} {rec['issue']}")
            report.append(f"**Priority:** {rec['priority'].upper()}")
            report.append(f"**Suggestion:** {rec['suggestion']}")
            report.append("")

        return "\n".join(report)

    def generate_visualizations(
        self, analysis: Dict[str, Any], output_dir: Optional[Path] = None
    ) -> List[Path]:
        """
        Generate error analysis visualization plots.

        Args:
            analysis: The error analysis
            output_dir: Directory to save visualizations (defaults to error_analysis)

        Returns:
            List of paths to generated visualization files
        """
        if output_dir is None:
            output_dir = self.results_dir

        output_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        generated_files = []

        # 1. Error categories pie chart
        if analysis["errors_by_category"]:
            plt.figure(figsize=(10, 8))
            categories = analysis["errors_by_category"]
            labels = list(categories.keys())
            sizes = list(categories.values())

            # If we have too many categories, group the smallest ones
            if len(labels) > 8:
                labels_sizes = list(zip(labels, sizes))
                labels_sizes.sort(key=lambda x: x[1], reverse=True)

                main_labels = [l for l, s in labels_sizes[:7]]
                main_sizes = [s for l, s in labels_sizes[:7]]

                other_size = sum(s for l, s in labels_sizes[7:])
                if other_size > 0:
                    main_labels.append("Other")
                    main_sizes.append(other_size)

                labels, sizes = main_labels, main_sizes

            plt.pie(
                sizes,
                labels=labels,
                autopct="%1.1f%%",
                shadow=True,
                startangle=140,
            )
            plt.axis("equal")
            plt.title("Error Distribution by Category")

            chart_path = output_dir / f"error_categories_{timestamp}.png"
            plt.savefig(chart_path)
            plt.close()
            generated_files.append(chart_path)

        # 2. Error timeline
        if analysis["errors_by_date"] and len(analysis["errors_by_date"]) > 1:
            plt.figure(figsize=(12, 6))
            dates = sorted(analysis["errors_by_date"].keys())
            counts = [analysis["errors_by_date"][d] for d in dates]

            plt.bar(range(len(dates)), counts)
            plt.xticks(range(len(dates)), dates, rotation=45)
            plt.xlabel("Date")
            plt.ylabel("Error Count")
            plt.title("Error Frequency Over Time")
            plt.tight_layout()

            timeline_path = output_dir / f"error_timeline_{timestamp}.png"
            plt.savefig(timeline_path)
            plt.close()
            generated_files.append(timeline_path)

        # 3. Logger distribution
        if analysis["errors_by_logger"]:
            plt.figure(figsize=(12, 6))
            loggers = [
                (logger, count)
                for logger, count in analysis["errors_by_logger"].items()
            ]
            loggers.sort(key=lambda x: x[1], reverse=True)

            # Limit to top 15 loggers if there are many
            if len(loggers) > 15:
                loggers = loggers[:15]

            logger_names = [l for l, c in loggers]
            logger_counts = [c for l, c in loggers]

            plt.barh(range(len(logger_names)), logger_counts)
            plt.yticks(range(len(logger_names)), logger_names)
            plt.xlabel("Error Count")
            plt.title("Error Distribution by Logger")
            plt.tight_layout()

            logger_path = output_dir / f"error_by_logger_{timestamp}.png"
            plt.savefig(logger_path)
            plt.close()
            generated_files.append(logger_path)

        return generated_files

    def analyze_and_save_report(
        self,
        log_files: List[Path],
        save_json: bool = True,
        save_markdown: bool = True,
        generate_plots: bool = True,
    ) -> Dict[str, Path]:
        """
        Analyze error logs and save results to files.

        Args:
            log_files: List of log files to analyze
            save_json: Whether to save raw analysis as JSON
            save_markdown: Whether to save formatted report as Markdown
            generate_plots: Whether to generate visualization plots

        Returns:
            Dictionary with paths to generated files
        """
        # Parse all log files
        all_errors = []
        for log_file in log_files:
            errors = self.parse_log_file(log_file)
            all_errors.extend(errors)

        # Analyze the errors
        analysis = self.analyze_errors(all_errors)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_files = {}

        # Save raw analysis as JSON
        if save_json:
            json_path = self.results_dir / f"error_analysis_{timestamp}.json"
            with open(json_path, "w") as f:
                json.dump(analysis, f, indent=2)
            output_files["json"] = json_path
            logger.info(f"Saved raw analysis to {json_path}")

        # Save formatted report as Markdown
        if save_markdown:
            report = self.generate_report(analysis)
            md_path = self.results_dir / f"error_analysis_report_{timestamp}.md"
            with open(md_path, "w") as f:
                f.write(report)
            output_files["markdown"] = md_path
            logger.info(f"Saved formatted report to {md_path}")

        # Generate visualization plots
        if generate_plots:
            plot_files = self.generate_visualizations(analysis)
            output_files["plots"] = plot_files
            logger.info(f"Generated {len(plot_files)} visualization plots")

        return output_files


def main():
    """Main function to run the search error analyzer."""
    parser = argparse.ArgumentParser(
        description="OmicsOracle Search Error Analyzer"
    )
    parser.add_argument(
        "--logs", nargs="+", required=True, help="Paths to log files to analyze"
    )
    parser.add_argument(
        "--no-json", action="store_true", help="Don't save raw analysis as JSON"
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

    # Convert log paths to Path objects
    log_paths = [Path(log_path) for log_path in args.logs]

    # Check that all log files exist
    missing_files = [str(path) for path in log_paths if not path.exists()]
    if missing_files:
        logger.error(
            f"The following log files were not found: {', '.join(missing_files)}"
        )
        return

    analyzer = SearchErrorAnalyzer()
    output_files = analyzer.analyze_and_save_report(
        log_files=log_paths,
        save_json=not args.no_json,
        save_markdown=not args.no_markdown,
        generate_plots=not args.no_plots,
    )

    print("\n🔍 Search Error Analysis Completed")
    print("=================================")

    if "markdown" in output_files:
        print(f"📊 Report: {output_files['markdown']}")

    if "json" in output_files:
        print(f"📋 Raw Data: {output_files['json']}")

    if "plots" in output_files and output_files["plots"]:
        print(f"📈 Generated {len(output_files['plots'])} visualization plots")


if __name__ == "__main__":
    main()
