#!/usr/bin/env python3
"""
Comprehensive Test Runner for OmicsOracle

This script runs all tests in the proper hierarchy and generates detailed reports.
It validates the complete event flow from server startup to result display.
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest


class TestResult:
    """Represents the result of a test execution."""

    def __init__(self, name: str, path: str, category: str):
        self.name = name
        self.path = path
        self.category = category
        self.status: Optional[str] = None
        self.duration: Optional[float] = None
        self.output: Optional[str] = None
        self.error: Optional[str] = None
        self.timestamp: Optional[datetime] = None


class OmicsOracleTestRunner:
    """Comprehensive test runner for OmicsOracle system."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.test_results: List[TestResult] = []
        self.summary: Dict[str, Any] = {}

        # Test categories and their files
        self.test_categories = {
            "unit": {
                "description": "Unit tests for individual components",
                "pattern": "tests/unit/test_*.py",
                "priority": 1,
            },
            "integration": {
                "description": "Integration tests for component interactions",
                "pattern": "tests/integration/test_*.py",
                "priority": 2,
            },
            "interface": {
                "description": "Interface and API tests",
                "pattern": "tests/interface/test_*.py",
                "priority": 3,
            },
            "e2e": {
                "description": "End-to-end pipeline tests",
                "pattern": "tests/e2e/test_*.py",
                "priority": 4,
            },
            "performance": {
                "description": "Performance and load tests",
                "pattern": "tests/performance/test_*.py",
                "priority": 5,
            },
            "validation": {
                "description": "Validation and diagnostic tests",
                "pattern": "tests/validation/test_*.py",
                "priority": 6,
            },
            "root_tests": {
                "description": "Root-level test files",
                "pattern": "test_*.py",
                "priority": 7,
            },
        }

    def discover_tests(self) -> List[TestResult]:
        """Discover all test files in the project."""
        discovered_tests = []

        for category, config in self.test_categories.items():
            pattern = config["pattern"]
            test_files = list(self.project_root.glob(pattern))

            for test_file in test_files:
                if test_file.is_file():
                    test_result = TestResult(
                        name=test_file.stem,
                        path=str(test_file.relative_to(self.project_root)),
                        category=category,
                    )
                    discovered_tests.append(test_result)

        # Sort by priority and name
        discovered_tests.sort(key=lambda x: (self.test_categories[x.category]["priority"], x.name))

        return discovered_tests

    def run_individual_test(self, test_result: TestResult) -> None:
        """Run an individual test file."""
        print(f"Running {test_result.category}: {test_result.name}...")

        start_time = time.time()
        test_result.timestamp = datetime.now()

        try:
            # Run pytest on the specific file
            cmd = [
                sys.executable,
                "-m",
                "pytest",
                test_result.path,
                "-v",
                "--tb=short",
                f"--junitxml=test_reports/{test_result.name}_results.xml",
            ]

            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout per test
            )

            test_result.duration = time.time() - start_time
            test_result.output = result.stdout
            test_result.error = result.stderr

            if result.returncode == 0:
                test_result.status = "PASSED"
            else:
                test_result.status = "FAILED"

        except subprocess.TimeoutExpired:
            test_result.duration = time.time() - start_time
            test_result.status = "TIMEOUT"
            test_result.error = "Test execution timed out"

        except FileNotFoundError:
            test_result.status = "NOT_FOUND"
            test_result.error = f"Test file not found: {test_result.path}"

        except Exception as e:
            test_result.duration = time.time() - start_time
            test_result.status = "ERROR"
            test_result.error = str(e)

    def run_all_tests(self, categories: Optional[List[str]] = None) -> None:
        """Run all discovered tests."""
        # Create test reports directory
        reports_dir = self.project_root / "test_reports"
        reports_dir.mkdir(exist_ok=True)

        # Discover tests
        all_tests = self.discover_tests()

        # Filter by categories if specified
        if categories:
            all_tests = [t for t in all_tests if t.category in categories]

        print(f"Discovered {len(all_tests)} test files")
        print("=" * 80)

        # Run each test
        for test_result in all_tests:
            self.run_individual_test(test_result)
            self.test_results.append(test_result)

            # Print immediate result
            status_color = {
                "PASSED": "\033[92m",  # Green
                "FAILED": "\033[91m",  # Red
                "TIMEOUT": "\033[93m",  # Yellow
                "NOT_FOUND": "\033[94m",  # Blue
                "ERROR": "\033[95m",  # Magenta
            }
            reset_color = "\033[0m"

            color = status_color.get(test_result.status, "")
            duration_str = f"{test_result.duration:.2f}s" if test_result.duration else "N/A"

            print(
                f"{color}{test_result.status:10}{reset_color} "
                f"{test_result.category:12} {test_result.name:30} ({duration_str})"
            )

    def generate_summary(self) -> Dict[str, Any]:
        """Generate test execution summary."""
        total_tests = len(self.test_results)
        passed = len([t for t in self.test_results if t.status == "PASSED"])
        failed = len([t for t in self.test_results if t.status == "FAILED"])
        errors = len([t for t in self.test_results if t.status in ["ERROR", "TIMEOUT", "NOT_FOUND"]])

        # Calculate totals by category
        category_summary = {}
        for category in self.test_categories.keys():
            category_tests = [t for t in self.test_results if t.category == category]
            category_summary[category] = {
                "total": len(category_tests),
                "passed": len([t for t in category_tests if t.status == "PASSED"]),
                "failed": len([t for t in category_tests if t.status == "FAILED"]),
                "errors": len([t for t in category_tests if t.status in ["ERROR", "TIMEOUT", "NOT_FOUND"]]),
            }

        # Calculate total duration
        total_duration = sum(t.duration for t in self.test_results if t.duration)

        self.summary = {
            "timestamp": datetime.now().isoformat(),
            "total_tests": total_tests,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "success_rate": (passed / total_tests * 100) if total_tests > 0 else 0,
            "total_duration": total_duration,
            "categories": category_summary,
            "detailed_results": [
                {
                    "name": t.name,
                    "path": t.path,
                    "category": t.category,
                    "status": t.status,
                    "duration": t.duration,
                    "timestamp": t.timestamp.isoformat() if t.timestamp else None,
                    "error": t.error,
                }
                for t in self.test_results
            ],
        }

        return self.summary

    def save_report(self, filename: str = "test_execution_report.json") -> None:
        """Save detailed test report to file."""
        report_path = self.project_root / "test_reports" / filename

        with open(report_path, "w") as f:
            json.dump(self.summary, f, indent=2, default=str)

        print(f"\nDetailed report saved to: {report_path}")

    def print_summary(self) -> None:
        """Print test execution summary."""
        print("\n" + "=" * 80)
        print("TEST EXECUTION SUMMARY")
        print("=" * 80)

        print(f"Total Tests: {self.summary['total_tests']}")
        print(f"Passed:      {self.summary['passed']} ({self.summary['success_rate']:.1f}%)")
        print(f"Failed:      {self.summary['failed']}")
        print(f"Errors:      {self.summary['errors']}")
        print(f"Duration:    {self.summary['total_duration']:.2f}s")

        print("\nBy Category:")
        print("-" * 40)
        for category, stats in self.summary["categories"].items():
            if stats["total"] > 0:
                success_rate = stats["passed"] / stats["total"] * 100
                print(
                    f"{category:12}: {stats['passed']:2}/{stats['total']:2} "
                    f"({success_rate:5.1f}%) | Failed: {stats['failed']} | Errors: {stats['errors']}"
                )

        if self.summary["failed"] > 0 or self.summary["errors"] > 0:
            print("\nFailed/Error Tests:")
            print("-" * 40)
            for result in self.summary["detailed_results"]:
                if result["status"] not in ["PASSED"]:
                    print(f"{result['status']:10} {result['category']:12} {result['name']}")
                    if result["error"]:
                        print(f"           Error: {result['error'][:100]}...")

    def validate_event_flow_coverage(self) -> Dict[str, Any]:
        """Validate that all events in the flow chart have corresponding tests."""
        # Define events from the flow chart
        server_init_events = [
            "Server Startup",
            "Logging Setup",
            "Path Setup",
            "Environment Variables",
            "Entrez Email Patch",
            "Config Loading",
            "NCBI Email Config",
            "Bio.Entrez Setup",
            "Pipeline Initialization",
            "Component Initialization",
            "GEO Client Init",
            "NLP Interpreter Init",
            "BiomedicalNER Init",
            "Synonym Mapper Init",
            "Summarizer Init",
            "Search Service Init",
            "Cache Disabling",
            "Progress Callback Setup",
            "API Routes Setup",
            "Static Files Setup",
            "CORS Setup",
            "WebSocket Manager Setup",
        ]

        search_process_events = [
            "Search Request",
            "Request Validation",
            "Pipeline Availability Check",
            "WebSocket Notification",
            "Query Processing",
            "Entity Extraction",
            "Query Expansion",
            "Intent Detection",
            "GEO Database Search",
            "NCBI Connection",
            "ESearch Request",
            "ESummary Request",
            "Result Processing",
            "Metadata Extraction",
            "Result Filtering",
            "AI Summarization",
            "OpenAI API Request",
            "Summary Generation",
            "Result Formatting",
            "Result Sorting",
            "Response Preparation",
            "Quality Check",
            "Response Creation",
        ]

        frontend_events = [
            "WebSocket Connection",
            "WebSocket Connection Acceptance",
            "WebSocket Message Handler",
            "Progress Updates",
            "Progress Event Parsing",
            "Progress Bar Update",
            "Live Monitor Update",
            "Results Preparation",
            "Results JSON Parsing",
            "Search History Update",
            "Results Rendering",
            "Dataset Card Creation",
            "GEO Summary Display",
            "AI Summary Display",
            "Error Handling",
            "API Error Processing",
            "WebSocket Error Processing",
            "UI Error Display",
        ]

        all_events = server_init_events + search_process_events + frontend_events

        # Map events to test files (simplified mapping)
        event_coverage = {}
        covered_events = 0

        for event in all_events:
            # Simple heuristic: check if any test name relates to the event
            related_tests = []
            for test_result in self.test_results:
                if any(keyword in test_result.name.lower() for keyword in event.lower().split()):
                    related_tests.append(test_result.name)

            event_coverage[event] = {
                "covered": len(related_tests) > 0,
                "related_tests": related_tests,
            }

            if related_tests:
                covered_events += 1

        coverage_percentage = (covered_events / len(all_events)) * 100

        return {
            "total_events": len(all_events),
            "covered_events": covered_events,
            "coverage_percentage": coverage_percentage,
            "event_coverage": event_coverage,
        }


def main():
    """Main entry point for test runner."""
    import argparse

    parser = argparse.ArgumentParser(description="OmicsOracle Comprehensive Test Runner")
    parser.add_argument(
        "--categories",
        nargs="+",
        help="Test categories to run (unit, integration, interface, e2e, performance, validation)",
    )
    parser.add_argument(
        "--report",
        default="test_execution_report.json",
        help="Output report filename",
    )
    parser.add_argument(
        "--validate-coverage",
        action="store_true",
        help="Validate event flow coverage",
    )

    args = parser.parse_args()

    # Find project root
    current_dir = Path.cwd()
    project_root = current_dir

    # Look for project markers
    while project_root.parent != project_root:
        if any(
            (project_root / marker).exists() for marker in ["pyproject.toml", "requirements.txt", "setup.py"]
        ):
            break
        project_root = project_root.parent

    print(f"Running tests from project root: {project_root}")

    # Create and run test runner
    runner = OmicsOracleTestRunner(project_root)

    try:
        runner.run_all_tests(categories=args.categories)
        runner.generate_summary()
        runner.print_summary()
        runner.save_report(args.report)

        if args.validate_coverage:
            print("\n" + "=" * 80)
            print("EVENT FLOW COVERAGE VALIDATION")
            print("=" * 80)

            coverage = runner.validate_event_flow_coverage()
            print(
                f"Event Coverage: {coverage['covered_events']}/{coverage['total_events']} "
                f"({coverage['coverage_percentage']:.1f}%)"
            )

            # Save coverage report
            coverage_path = project_root / "test_reports" / "event_coverage_report.json"
            with open(coverage_path, "w") as f:
                json.dump(coverage, f, indent=2)
            print(f"Coverage report saved to: {coverage_path}")

        # Return appropriate exit code
        if runner.summary["failed"] > 0 or runner.summary["errors"] > 0:
            sys.exit(1)
        else:
            print(f"\n✅ All tests passed! ({runner.summary['passed']} tests)")
            sys.exit(0)

    except KeyboardInterrupt:
        print("\n⚠️  Test execution interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Test runner failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
