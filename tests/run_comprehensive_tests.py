#!/usr/bin/env python3
"""
Comprehensive Web Interface Testing Suite for OmicsOracle

This module integrates all testing frameworks (load, security, browser, mobile)
and provides a unified testing interface with comprehensive reporting.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

# Add tests directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from performance.test_load_testing import LoadTestSuite
except ImportError:
    LoadTestSuite = None

try:
    from security.test_security_headers_fixed import SecurityHeadersTestSuite
    from security.test_security_testing_fixed import SecurityTestSuite
except ImportError:
    SecurityTestSuite = None
    SecurityHeadersTestSuite = None

try:
    from browser.test_browser_automation import BrowserAutomationTestSuite
except ImportError:
    BrowserAutomationTestSuite = None

try:
    from mobile.test_mobile_responsive import MobileTestSuite
except ImportError:
    MobileTestSuite = None


class ComprehensiveTestRunner:
    """Comprehensive test runner for all web interface testing."""

    def __init__(self, base_url: str = "http://localhost:8000"):
        """Initialize comprehensive test runner."""
        self.base_url = base_url
        self.results = {}
        self.start_time = time.time()

    def run_load_tests(self, duration: int = 30, users: int = 10) -> Dict[str, Any]:
        """Run load testing if available."""
        print("=" * 60)
        print("RUNNING LOAD TESTS")
        print("=" * 60)

        if LoadTestSuite is None:
            return {"error": "Load testing suite not available", "skipped": True}

        try:
            load_suite = LoadTestSuite(self.base_url)
            results = load_suite.run_comprehensive_load_test(
                duration=duration, users=users
            )

            print(f"✅ Load tests completed successfully")
            print(f"   - Total requests: {results.get('total_requests', 'N/A')}")
            print(f"   - Average response time: {results.get('avg_response_time', 'N/A'):.2f}s")
            print(f"   - Error rate: {results.get('error_rate', 'N/A'):.2f}%")

            return results

        except Exception as e:
            error_result = {"error": str(e), "failed": True}
            print(f"❌ Load tests failed: {str(e)}")
            return error_result

    def run_security_tests(self) -> Dict[str, Any]:
        """Run security testing if available."""
        print("=" * 60)
        print("RUNNING SECURITY TESTS")
        print("=" * 60)

        security_results = {}

        # Run main security tests
        if SecurityTestSuite is not None:
            try:
                security_suite = SecurityTestSuite(self.base_url)

                print("🔍 Testing injection vulnerabilities...")
                injection_results = security_suite.test_injection_attacks()

                print("🔍 Testing AI prompt injection...")
                ai_injection_results = security_suite.test_ai_prompt_injection()

                print("🔍 Testing authentication bypass...")
                auth_results = security_suite.test_authentication_bypass()

                print("🔍 Testing file upload vulnerabilities...")
                upload_results = security_suite.test_file_upload_vulnerabilities()

                print("🔍 Testing information disclosure...")
                info_results = security_suite.test_information_disclosure()

                # Generate comprehensive report
                security_report = security_suite.generate_security_report(
                    injection_results, ai_injection_results, auth_results,
                    upload_results, info_results
                )

                security_results["main_security"] = security_report

                print(f"✅ Main security tests completed")
                print(f"   - Risk level: {security_report.get('risk_level', 'Unknown')}")
                print(f"   - Vulnerabilities found: {len(security_report.get('recommendations', []))}")

            except Exception as e:
                security_results["main_security"] = {"error": str(e), "failed": True}
                print(f"❌ Main security tests failed: {str(e)}")
        else:
            security_results["main_security"] = {"error": "Security test suite not available", "skipped": True}

        # Run security headers tests
        if SecurityHeadersTestSuite is not None:
            try:
                headers_suite = SecurityHeadersTestSuite(self.base_url)

                print("🔍 Testing security headers...")
                headers_results = headers_suite.test_security_headers()

                print("🔍 Testing HTTPS configuration...")
                https_results = headers_suite.test_https_configuration()

                print("🔍 Testing rate limiting...")
                rate_limit_results = headers_suite.test_rate_limiting()

                print("🔍 Testing CORS configuration...")
                cors_results = headers_suite.test_cors_configuration()

                # Generate headers report
                headers_report = headers_suite.generate_headers_report(
                    headers_results, https_results, rate_limit_results, cors_results
                )

                security_results["security_headers"] = headers_report

                print(f"✅ Security headers tests completed")
                print(f"   - Overall security score: {headers_report.get('overall_security_score', 0):.1f}/100")
                print(f"   - Risk level: {headers_report.get('risk_level', 'Unknown')}")

            except Exception as e:
                security_results["security_headers"] = {"error": str(e), "failed": True}
                print(f"❌ Security headers tests failed: {str(e)}")
        else:
            security_results["security_headers"] = {"error": "Security headers test suite not available", "skipped": True}

        return security_results

    def run_browser_tests(self, browser: str = "chrome", headless: bool = True) -> Dict[str, Any]:
        """Run browser automation tests if available."""
        print("=" * 60)
        print("RUNNING BROWSER AUTOMATION TESTS")
        print("=" * 60)

        if BrowserAutomationTestSuite is None:
            return {"error": "Browser automation test suite not available", "skipped": True}

        try:
            browser_suite = BrowserAutomationTestSuite(
                self.base_url, browser=browser, headless=headless
            )

            # Setup WebDriver
            print(f"🌐 Setting up {browser} WebDriver...")
            browser_suite.setup_driver()

            try:
                print("🌐 Testing page loading...")
                page_loading_results = browser_suite.test_page_loading()

                print("🌐 Testing search functionality...")
                search_results = browser_suite.test_search_functionality()

                print("🌐 Testing AI summarization...")
                ai_results = browser_suite.test_ai_summarization()

                print("🌐 Testing responsive design...")
                responsive_results = browser_suite.test_responsive_design()

                print("🌐 Testing accessibility...")
                accessibility_results = browser_suite.test_accessibility()

                # Generate browser report
                browser_report = browser_suite.generate_browser_report(
                    page_loading_results, search_results, ai_results,
                    responsive_results, accessibility_results
                )

                print(f"✅ Browser tests completed")
                print(f"   - Overall score: {browser_report.get('overall_score', 0):.1f}/100")
                print(f"   - Test status: {browser_report.get('test_status', 'Unknown')}")

                return browser_report

            finally:
                # Always cleanup WebDriver
                browser_suite.teardown_driver()

        except Exception as e:
            error_result = {"error": str(e), "failed": True}
            print(f"❌ Browser tests failed: {str(e)}")
            return error_result

    def run_mobile_tests(self) -> Dict[str, Any]:
        """Run mobile testing if available."""
        print("=" * 60)
        print("RUNNING MOBILE TESTS")
        print("=" * 60)

        if MobileTestSuite is None:
            return {"error": "Mobile test suite not available", "skipped": True}

        try:
            mobile_suite = MobileTestSuite(self.base_url)

            print("📱 Testing mobile responsiveness...")
            responsiveness_results = mobile_suite.test_mobile_responsiveness()

            print("📱 Testing mobile performance...")
            performance_results = mobile_suite.test_mobile_performance()

            print("📱 Testing touch interactions...")
            touch_results = mobile_suite.test_touch_interactions()

            print("📱 Testing mobile accessibility...")
            accessibility_results = mobile_suite.test_mobile_accessibility()

            # Generate mobile report
            mobile_report = mobile_suite.generate_mobile_report(
                responsiveness_results, performance_results,
                touch_results, accessibility_results
            )

            print(f"✅ Mobile tests completed")
            print(f"   - Overall mobile score: {mobile_report.get('overall_mobile_score', 0):.1f}/100")
            print(f"   - Mobile ready: {mobile_report.get('mobile_ready', False)}")

            return mobile_report

        except Exception as e:
            error_result = {"error": str(e), "failed": True}
            print(f"❌ Mobile tests failed: {str(e)}")
            return error_result

    def run_all_tests(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run all available tests."""
        config = config or {}

        print("🚀 Starting Comprehensive Web Interface Testing")
        print(f"📍 Target URL: {self.base_url}")
        print(f"🕐 Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("")

        # Run all test suites
        if config.get("run_load_tests", True):
            self.results["load_testing"] = self.run_load_tests(
                duration=config.get("load_duration", 30),
                users=config.get("load_users", 10)
            )

        if config.get("run_security_tests", True):
            self.results["security_testing"] = self.run_security_tests()

        if config.get("run_browser_tests", True):
            self.results["browser_testing"] = self.run_browser_tests(
                browser=config.get("browser", "chrome"),
                headless=config.get("headless", True)
            )

        if config.get("run_mobile_tests", True):
            self.results["mobile_testing"] = self.run_mobile_tests()

        # Generate comprehensive report
        comprehensive_report = self.generate_comprehensive_report()

        # Save results
        self.save_results(comprehensive_report)

        # Print summary
        self.print_summary(comprehensive_report)

        return comprehensive_report

    def generate_comprehensive_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        end_time = time.time()
        total_duration = end_time - self.start_time

        # Calculate overall scores
        scores = {}

        # Load testing score
        load_result = self.results.get("load_testing", {})
        if not load_result.get("error") and not load_result.get("skipped"):
            error_rate = load_result.get("error_rate", 100)
            avg_response_time = load_result.get("avg_response_time", 10)
            scores["load"] = max(0, min(100, (100 - error_rate) * (5 / max(avg_response_time, 0.1))))

        # Security testing score
        security_result = self.results.get("security_testing", {})
        security_scores = []

        main_sec = security_result.get("main_security", {})
        if not main_sec.get("error") and not main_sec.get("skipped"):
            risk_level = main_sec.get("risk_level", "CRITICAL")
            risk_scores = {"MINIMAL": 100, "LOW": 80, "MEDIUM": 60, "HIGH": 40, "CRITICAL": 20}
            security_scores.append(risk_scores.get(risk_level, 20))

        headers_sec = security_result.get("security_headers", {})
        if not headers_sec.get("error") and not headers_sec.get("skipped"):
            security_scores.append(headers_sec.get("overall_security_score", 0))

        if security_scores:
            scores["security"] = sum(security_scores) / len(security_scores)

        # Browser testing score
        browser_result = self.results.get("browser_testing", {})
        if not browser_result.get("error") and not browser_result.get("skipped"):
            scores["browser"] = browser_result.get("overall_score", 0)

        # Mobile testing score
        mobile_result = self.results.get("mobile_testing", {})
        if not mobile_result.get("error") and not mobile_result.get("skipped"):
            scores["mobile"] = mobile_result.get("overall_mobile_score", 0)

        # Calculate overall score
        overall_score = sum(scores.values()) / len(scores) if scores else 0

        # Determine test status
        if overall_score >= 80:
            test_status = "EXCELLENT"
        elif overall_score >= 70:
            test_status = "GOOD"
        elif overall_score >= 60:
            test_status = "FAIR"
        elif overall_score >= 50:
            test_status = "POOR"
        else:
            test_status = "CRITICAL"

        # Collect all recommendations
        all_recommendations = []

        for test_category, result in self.results.items():
            if isinstance(result, dict):
                if "recommendations" in result:
                    all_recommendations.extend(result["recommendations"])

                # Handle nested results
                for sub_key, sub_result in result.items():
                    if isinstance(sub_result, dict) and "recommendations" in sub_result:
                        all_recommendations.extend(sub_result["recommendations"])

        return {
            "test_metadata": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "base_url": self.base_url,
                "total_duration": total_duration,
                "tests_run": list(self.results.keys())
            },
            "overall_assessment": {
                "overall_score": overall_score,
                "test_status": test_status,
                "category_scores": scores
            },
            "detailed_results": self.results,
            "recommendations": {
                "high_priority": all_recommendations[:5],  # Top 5 recommendations
                "all_recommendations": all_recommendations
            },
            "summary": {
                "tests_passed": sum(1 for r in self.results.values()
                                  if not r.get("error") and not r.get("failed")),
                "tests_failed": sum(1 for r in self.results.values()
                                 if r.get("error") or r.get("failed")),
                "tests_skipped": sum(1 for r in self.results.values()
                                   if r.get("skipped")),
                "total_tests": len(self.results)
            }
        }\n    \n    def save_results(self, report: Dict[str, Any]) -> None:\n        """Save test results to files."""\n        # Create results directory\n        results_dir = Path("test_results")\n        results_dir.mkdir(exist_ok=True)\n        \n        timestamp = time.strftime("%Y%m%d_%H%M%S")\n        \n        # Save comprehensive report\n        comprehensive_file = results_dir / f"comprehensive_test_report_{timestamp}.json"\n        with open(comprehensive_file, "w", encoding="utf-8") as f:\n            json.dump(report, f, indent=2)\n        \n        print(f"📄 Comprehensive report saved to: {comprehensive_file}")\n        \n        # Save individual test results\n        for test_name, test_result in self.results.items():\n            if not test_result.get("error") and not test_result.get("skipped"):\n                individual_file = results_dir / f"{test_name}_{timestamp}.json"\n                with open(individual_file, "w", encoding="utf-8") as f:\n                    json.dump(test_result, f, indent=2)\n                print(f"📄 {test_name} results saved to: {individual_file}")\n    \n    def print_summary(self, report: Dict[str, Any]) -> None:\n        """Print test summary."""\n        print("")\n        print("=" * 80)\n        print("🏁 COMPREHENSIVE TESTING SUMMARY")\n        print("=" * 80)\n        \n        assessment = report["overall_assessment"]\n        summary = report["summary"]\n        \n        print(f"📊 Overall Score: {assessment['overall_score']:.1f}/100 ({assessment['test_status']})")\n        print(f"📈 Tests Passed: {summary['tests_passed']}/{summary['total_tests']}")\n        print(f"❌ Tests Failed: {summary['tests_failed']}")\n        print(f"⏭️  Tests Skipped: {summary['tests_skipped']}")\n        print(f"⏱️  Total Duration: {report['test_metadata']['total_duration']:.1f} seconds")\n        \n        print("")\n        print("📋 Category Scores:")\n        for category, score in assessment["category_scores"].items():\n            print(f"   • {category.title()}: {score:.1f}/100")\n        \n        print("")\n        print("🔧 Top Recommendations:")\n        for i, rec in enumerate(report["recommendations"]["high_priority"], 1):\n            print(f"   {i}. {rec}")\n        \n        print("")\n        print("=" * 80)\n\n\ndef main():\n    """Main function for running comprehensive tests."""\n    parser = argparse.ArgumentParser(description="Comprehensive Web Interface Testing")\n    parser.add_argument("--url", default="http://localhost:8000", help="Base URL to test")\n    parser.add_argument("--skip-load", action="store_true", help="Skip load testing")\n    parser.add_argument("--skip-security", action="store_true", help="Skip security testing")\n    parser.add_argument("--skip-browser", action="store_true", help="Skip browser testing")\n    parser.add_argument("--skip-mobile", action="store_true", help="Skip mobile testing")\n    parser.add_argument("--browser", default="chrome", choices=["chrome", "firefox"], help="Browser for testing")\n    parser.add_argument("--no-headless", action="store_true", help="Run browser tests with GUI")\n    parser.add_argument("--load-duration", type=int, default=30, help="Load test duration in seconds")\n    parser.add_argument("--load-users", type=int, default=10, help="Number of concurrent users for load testing")\n    \n    args = parser.parse_args()\n    \n    # Create test configuration\n    config = {\n        "run_load_tests": not args.skip_load,\n        "run_security_tests": not args.skip_security,\n        "run_browser_tests": not args.skip_browser,\n        "run_mobile_tests": not args.skip_mobile,\n        "browser": args.browser,\n        "headless": not args.no_headless,\n        "load_duration": args.load_duration,\n        "load_users": args.load_users\n    }\n    \n    # Run comprehensive tests\n    runner = ComprehensiveTestRunner(args.url)\n    runner.run_all_tests(config)\n\n\nif __name__ == "__main__":\n    main()
