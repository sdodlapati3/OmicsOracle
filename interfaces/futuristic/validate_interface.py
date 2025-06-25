"""
Comprehensive testing and validation for the futuristic interface
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Any, Dict, List

import aiohttp


class FuturisticInterfaceValidator:
    """Comprehensive validation of the futuristic interface"""

    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url
        self.session = None
        self.test_results = []

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def run_comprehensive_tests(self) -> Dict[str, Any]:
        """Run all validation tests"""
        print("[TEST] Starting Comprehensive Futuristic Interface Validation")
        print("=" * 60)

        start_time = time.time()

        # Test categories
        test_suites = [
            ("Basic Connectivity", self.test_basic_connectivity),
            ("Static Files", self.test_static_files),
            ("API Endpoints", self.test_api_endpoints),
            ("Health Monitoring", self.test_health_monitoring),
            ("Performance Tracking", self.test_performance_tracking),
            ("Search Functionality", self.test_search_functionality),
            ("Agent System", self.test_agent_system),
            ("Visualization System", self.test_visualization_system),
            ("WebSocket Connection", self.test_websocket_connection),
            ("Error Handling", self.test_error_handling),
        ]

        total_tests = 0
        passed_tests = 0
        failed_tests = 0

        for suite_name, test_func in test_suites:
            print(f"\n[SEARCH] Testing: {suite_name}")
            print("-" * 40)

            try:
                results = await test_func()

                for test_name, passed, details in results:
                    total_tests += 1
                    status = "[OK] PASS" if passed else "[ERROR] FAIL"
                    print(f"  {status}: {test_name}")

                    if not passed:
                        print(f"    +- {details}")
                        failed_tests += 1
                    else:
                        passed_tests += 1

                    self.test_results.append(
                        {
                            "suite": suite_name,
                            "test": test_name,
                            "passed": passed,
                            "details": details,
                            "timestamp": datetime.now().isoformat(),
                        }
                    )

            except Exception as e:
                print(f"  [ERROR] FAIL: {suite_name} suite crashed: {e}")
                failed_tests += 1

        execution_time = time.time() - start_time

        print("\n" + "=" * 60)
        print("[CHART] VALIDATION SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ({passed_tests/total_tests*100:.1f}%)")
        print(f"Failed: {failed_tests} ({failed_tests/total_tests*100:.1f}%)")
        print(f"Execution Time: {execution_time:.2f} seconds")
        print(
            f"Status: {'[SUCCESS] ALL TESTS PASSED' if failed_tests == 0 else '[WARNING]  SOME TESTS FAILED'}"
        )

        return {
            "summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "success_rate": passed_tests / total_tests * 100,
                "execution_time_seconds": execution_time,
                "overall_status": "PASS" if failed_tests == 0 else "FAIL",
            },
            "detailed_results": self.test_results,
            "timestamp": datetime.now().isoformat(),
        }

    async def test_basic_connectivity(self) -> List[tuple]:
        """Test basic server connectivity"""
        tests = []

        # Test main page
        try:
            async with self.session.get(f"{self.base_url}/") as response:
                passed = response.status == 200
                details = (
                    f"Status: {response.status}"
                    if not passed
                    else "Main page loads successfully"
                )
                tests.append(("Main page loads", passed, details))
        except Exception as e:
            tests.append(("Main page loads", False, str(e)))

        # Test API docs
        try:
            async with self.session.get(f"{self.base_url}/docs") as response:
                passed = response.status == 200
                details = (
                    f"Status: {response.status}"
                    if not passed
                    else "API docs accessible"
                )
                tests.append(("API documentation", passed, details))
        except Exception as e:
            tests.append(("API documentation", False, str(e)))

        return tests

    async def test_static_files(self) -> List[tuple]:
        """Test static file serving"""
        tests = []

        # Test CSS file
        try:
            async with self.session.get(
                f"{self.base_url}/static/css/main.css"
            ) as response:
                passed = (
                    response.status == 200
                    and "text/css" in response.headers.get("content-type", "")
                )
                details = f"Status: {response.status}, Type: {response.headers.get('content-type')}"
                tests.append(("CSS file serving", passed, details))
        except Exception as e:
            tests.append(("CSS file serving", False, str(e)))

        # Test JS file
        try:
            async with self.session.get(
                f"{self.base_url}/static/js/main.js"
            ) as response:
                passed = (
                    response.status == 200
                    and "javascript" in response.headers.get("content-type", "")
                )
                details = f"Status: {response.status}, Type: {response.headers.get('content-type')}"
                tests.append(("JavaScript file serving", passed, details))
        except Exception as e:
            tests.append(("JavaScript file serving", False, str(e)))

        return tests

    async def test_api_endpoints(self) -> List[tuple]:
        """Test API endpoints"""
        tests = []

        endpoints = [
            ("/api/agents", "Agents endpoint"),
            ("/api/search", "Search endpoint (POST)", "POST"),
            ("/api/visualize", "Visualization endpoint (POST)", "POST"),
            ("/api/performance", "Performance endpoint"),
            ("/api/performance/endpoints", "Performance endpoints stats"),
            ("/api/performance/agents", "Performance agents stats"),
        ]

        for endpoint_info in endpoints:
            endpoint = endpoint_info[0]
            description = endpoint_info[1]
            method = endpoint_info[2] if len(endpoint_info) > 2 else "GET"

            try:
                if method == "POST":
                    # Send sample data for POST endpoints
                    sample_data = {}
                    if "search" in endpoint:
                        sample_data = {
                            "query": "test",
                            "search_type": "general",
                        }
                    elif "visualize" in endpoint:
                        sample_data = {"type": "scatter_plot", "data": []}

                    async with self.session.post(
                        f"{self.base_url}{endpoint}", json=sample_data
                    ) as response:
                        passed = response.status in [200, 201]
                        details = f"Status: {response.status}"
                        tests.append((description, passed, details))
                else:
                    async with self.session.get(
                        f"{self.base_url}{endpoint}"
                    ) as response:
                        passed = response.status == 200
                        details = f"Status: {response.status}"
                        tests.append((description, passed, details))

            except Exception as e:
                tests.append((description, False, str(e)))

        return tests

    async def test_health_monitoring(self) -> List[tuple]:
        """Test health monitoring endpoints"""
        tests = []

        # Test health endpoint
        try:
            async with self.session.get(
                f"{self.base_url}/api/health"
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    passed = "status" in data
                    details = f"Health status: {data.get('status', 'unknown')}"
                else:
                    passed = False
                    details = f"HTTP {response.status}"
                tests.append(("Health monitoring", passed, details))
        except Exception as e:
            tests.append(("Health monitoring", False, str(e)))

        # Test quick health check
        try:
            async with self.session.get(
                f"{self.base_url}/api/health/quick/status"
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    passed = "status" in data and "uptime" in data
                    details = f"Quick health check successful"
                else:
                    passed = False
                    details = f"HTTP {response.status}"
                tests.append(("Quick health check", passed, details))
        except Exception as e:
            tests.append(("Quick health check", False, str(e)))

        return tests

    async def test_performance_tracking(self) -> List[tuple]:
        """Test performance tracking"""
        tests = []

        # Test performance metrics
        try:
            async with self.session.get(
                f"{self.base_url}/api/performance"
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    passed = "metrics" in data and "uptime_seconds" in data.get(
                        "metrics", {}
                    )
                    details = f"Performance tracking active, uptime: {data.get('metrics', {}).get('uptime_seconds', 0):.1f}s"
                else:
                    passed = False
                    details = f"HTTP {response.status}"
                tests.append(("Performance metrics", passed, details))
        except Exception as e:
            tests.append(("Performance metrics", False, str(e)))

        return tests

    async def test_search_functionality(self) -> List[tuple]:
        """Test search functionality"""
        tests = []

        # Test search endpoint
        try:
            search_data = {
                "query": "cancer research",
                "search_type": "enhanced",
            }
            async with self.session.post(
                f"{self.base_url}/api/search", json=search_data
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    passed = "results" in data
                    details = f"Search returned {len(data.get('results', []))} results"
                else:
                    passed = False
                    details = f"HTTP {response.status}"
                tests.append(("Search functionality", passed, details))
        except Exception as e:
            tests.append(("Search functionality", False, str(e)))

        return tests

    async def test_agent_system(self) -> List[tuple]:
        """Test agent system"""
        tests = []

        # Test agents endpoint
        try:
            async with self.session.get(
                f"{self.base_url}/api/agents"
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    passed = "agents" in data
                    agent_count = len(data.get("agents", []))
                    details = f"Found {agent_count} agents"
                else:
                    passed = False
                    details = f"HTTP {response.status}"
                tests.append(("Agent system status", passed, details))
        except Exception as e:
            tests.append(("Agent system status", False, str(e)))

        return tests

    async def test_visualization_system(self) -> List[tuple]:
        """Test visualization system"""
        tests = []

        # Test visualization creation
        try:
            viz_data = {
                "type": "scatter_plot",
                "title": "Test Scatter Plot",
                "data": {
                    "points": [
                        {"x": 1, "y": 2, "label": "Point 1"},
                        {"x": 3, "y": 4, "label": "Point 2"},
                    ]
                },
            }
            async with self.session.post(
                f"{self.base_url}/api/visualize", json=viz_data
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    passed = data.get("status") == "success"
                    details = f"Visualization created: {data.get('visualization', {}).get('id', 'unknown')}"
                else:
                    passed = False
                    details = f"HTTP {response.status}"
                tests.append(("Visualization creation", passed, details))
        except Exception as e:
            tests.append(("Visualization creation", False, str(e)))

        return tests

    async def test_websocket_connection(self) -> List[tuple]:
        """Test WebSocket connection"""
        tests = []

        # Note: This is a simplified test - full WebSocket testing would require more complex setup
        try:
            # For now, just test that the endpoint doesn't return an error
            # In a full implementation, we'd use aiohttp's WebSocket client
            async with self.session.get(f"{self.base_url}/ws") as response:
                # WebSocket endpoint should return 426 (Upgrade Required) for HTTP requests
                passed = response.status == 426
                details = "WebSocket endpoint available (returns 426 for HTTP)"
                tests.append(("WebSocket endpoint", passed, details))
        except Exception as e:
            tests.append(("WebSocket endpoint", False, str(e)))

        return tests

    async def test_error_handling(self) -> List[tuple]:
        """Test error handling"""
        tests = []

        # Test 404 handling
        try:
            async with self.session.get(
                f"{self.base_url}/nonexistent"
            ) as response:
                passed = response.status == 404
                details = f"Returns proper 404 status"
                tests.append(("404 error handling", passed, details))
        except Exception as e:
            tests.append(("404 error handling", False, str(e)))

        # Test invalid search data
        try:
            async with self.session.post(
                f"{self.base_url}/api/search", json={}
            ) as response:
                passed = response.status in [
                    400,
                    422,
                    500,
                ]  # Should return error for invalid data
                details = (
                    f"Returns error status {response.status} for invalid data"
                )
                tests.append(("Invalid data handling", passed, details))
        except Exception as e:
            tests.append(("Invalid data handling", False, str(e)))

        return tests


async def main():
    """Run the comprehensive validation"""
    async with FuturisticInterfaceValidator() as validator:
        results = await validator.run_comprehensive_tests()

        # Save results to file
        with open("futuristic_interface_validation_results.json", "w") as f:
            json.dump(results, f, indent=2)

        print(
            f"\n[DOCUMENT] Detailed results saved to: futuristic_interface_validation_results.json"
        )

        return results["summary"]["overall_status"] == "PASS"


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
