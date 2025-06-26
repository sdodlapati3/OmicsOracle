#!/usr/bin/env python3
"""
Search Function Diagnostic Tool

This script performs targeted diagnostics on the search function to help
isolate performance issues and data integrity problems.

Usage:
    python diagnose_search_function.py --direct-test GSE278726
    python diagnose_search_function.py --timing-test "heart"
    python diagnose_search_function.py --connection-test
"""

import argparse
import asyncio
import json
import logging
import sys
import time
from datetime import datetime
from typing import Any, Dict, List

import aiohttp

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("search_diagnostics.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("search_diagnostics")


class SearchDiagnostics:
    def __init__(
        self, api_url="http://localhost:8001", disable_ssl_verify=False
    ):
        self.api_url = api_url
        self.disable_ssl_verify = disable_ssl_verify
        self.session = None

    async def init_session(self):
        """Initialize aiohttp session"""
        if self.session is None:
            connector = aiohttp.TCPConnector(
                ssl=False if self.disable_ssl_verify else None
            )
            self.session = aiohttp.ClientSession(connector=connector)

    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None

    async def direct_test(self, gse_id: str) -> Dict[str, Any]:
        """
        Compare direct API call vs. search results for a specific GSE ID
        """
        await self.init_session()
        results = {
            "gse_id": gse_id,
            "direct_api": None,
            "search": None,
            "comparison": {},
        }

        # Direct API call
        direct_start = time.time()
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            direct_url = f"{self.api_url}/api/geo/{gse_id}"
            async with self.session.get(
                direct_url, timeout=timeout
            ) as response:
                if response.status == 200:
                    results["direct_api"] = {
                        "status": "success",
                        "time": time.time() - direct_start,
                        "data": await response.json(),
                    }
                else:
                    results["direct_api"] = {
                        "status": "error",
                        "time": time.time() - direct_start,
                        "status_code": response.status,
                    }
        except asyncio.TimeoutError:
            results["direct_api"] = {
                "status": "timeout",
                "time": time.time() - direct_start,
            }
        except Exception as e:
            results["direct_api"] = {
                "status": "exception",
                "time": time.time() - direct_start,
                "error": str(e),
            }

        # Search API call
        search_start = time.time()
        try:
            timeout = aiohttp.ClientTimeout(total=20)
            search_payload = {"query": gse_id, "max_results": 10}
            async with self.session.post(
                f"{self.api_url}/api/search",
                json=search_payload,
                timeout=timeout,
            ) as response:
                if response.status == 200:
                    search_data = await response.json()
                    results["search"] = {
                        "status": "success",
                        "time": time.time() - search_start,
                        "result_count": len(search_data.get("results", [])),
                        "data": search_data,
                    }

                    # Find the target GSE ID in results
                    for result in search_data.get("results", []):
                        if result.get("geo_id") == gse_id:
                            results["search"]["target_found"] = True
                            results["search"]["target_result"] = result
                            break
                    else:
                        results["search"]["target_found"] = False
                else:
                    results["search"] = {
                        "status": "error",
                        "time": time.time() - search_start,
                        "status_code": response.status,
                    }
        except asyncio.TimeoutError:
            results["search"] = {
                "status": "timeout",
                "time": time.time() - search_start,
            }
        except Exception as e:
            results["search"] = {
                "status": "exception",
                "time": time.time() - search_start,
                "error": str(e),
            }

        # Compare results
        if (
            results["direct_api"]
            and results["direct_api"]["status"] == "success"
            and results["search"]
            and results["search"]["status"] == "success"
            and results["search"].get("target_found", False)
        ):
            direct_data = results["direct_api"]["data"]
            search_data = results["search"]["target_result"]

            results["comparison"] = {
                "title_match": direct_data.get("title")
                == search_data.get("title"),
                "direct_title": direct_data.get("title"),
                "search_title": search_data.get("title"),
                "time_difference": results["search"]["time"]
                - results["direct_api"]["time"],
            }

        print("\n" + "=" * 80)
        print(f"DIRECT API vs SEARCH COMPARISON FOR {gse_id}")
        print("=" * 80)

        if (
            results["direct_api"]
            and results["direct_api"]["status"] == "success"
        ):
            print(
                f"\nDirect API: SUCCESS in {results['direct_api']['time']:.2f}s"
            )
            if (
                "data" in results["direct_api"]
                and "title" in results["direct_api"]["data"]
            ):
                print(f"Title: {results['direct_api']['data']['title']}")
        else:
            print(
                f"\nDirect API: {results['direct_api']['status'].upper()} in {results['direct_api']['time']:.2f}s"
            )
            if "error" in results["direct_api"]:
                print(f"Error: {results['direct_api']['error']}")

        if results["search"] and results["search"]["status"] == "success":
            print(f"\nSearch API: SUCCESS in {results['search']['time']:.2f}s")
            print(f"Result count: {results['search']['result_count']}")

            if results["search"].get("target_found", False):
                print(f"Target GSE ID found in results")
                print(
                    f"Title: {results['search']['target_result'].get('title')}"
                )

                if (
                    "comparison" in results
                    and "title_match" in results["comparison"]
                ):
                    if results["comparison"]["title_match"]:
                        print(f"\nTitles MATCH between direct API and search")
                    else:
                        print(
                            f"\nTitles DO NOT MATCH between direct API and search"
                        )
                        print(
                            f"Direct API title: {results['comparison']['direct_title']}"
                        )
                        print(
                            f"Search title: {results['comparison']['search_title']}"
                        )
            else:
                print(f"Target GSE ID NOT FOUND in search results")
        else:
            print(
                f"\nSearch API: {results['search']['status'].upper()} in {results['search']['time']:.2f}s"
            )
            if "error" in results["search"]:
                print(f"Error: {results['search']['error']}")

        if (
            "comparison" in results
            and "time_difference" in results["comparison"]
        ):
            print(
                f"\nSearch is {results['comparison']['time_difference']:.2f}s slower than direct API"
            )

        print("\n" + "=" * 80)

        return results

    async def timing_test(
        self, query: str, iterations: int = 3
    ) -> Dict[str, Any]:
        """
        Test search API performance with different timeout values
        """
        await self.init_session()
        results = {"query": query, "iterations": iterations, "tests": []}

        timeouts = [5, 10, 20, 30, 45, 60]

        print("\n" + "=" * 80)
        print(f"SEARCH TIMING TEST FOR QUERY: '{query}'")
        print("=" * 80)

        for timeout_seconds in timeouts:
            for i in range(iterations):
                start_time = time.time()
                test_result = {
                    "timeout_setting": timeout_seconds,
                    "iteration": i + 1,
                    "start_time": datetime.now().strftime("%H:%M:%S"),
                }

                try:
                    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
                    search_payload = {"query": query, "max_results": 10}

                    print(
                        f"\nTesting with {timeout_seconds}s timeout (iteration {i+1}/{iterations})..."
                    )

                    async with self.session.post(
                        f"{self.api_url}/api/search",
                        json=search_payload,
                        timeout=timeout,
                    ) as response:
                        elapsed = time.time() - start_time
                        test_result["elapsed_time"] = elapsed

                        if response.status == 200:
                            data = await response.json()
                            test_result["status"] = "success"
                            test_result["result_count"] = len(
                                data.get("results", [])
                            )
                            print(
                                f"  SUCCESS in {elapsed:.2f}s - {test_result['result_count']} results"
                            )
                        else:
                            test_result["status"] = "error"
                            test_result["status_code"] = response.status
                            print(
                                f"  ERROR {response.status} in {elapsed:.2f}s"
                            )

                except asyncio.TimeoutError:
                    elapsed = time.time() - start_time
                    test_result["elapsed_time"] = elapsed
                    test_result["status"] = "timeout"
                    print(f"  TIMEOUT after {elapsed:.2f}s")

                except Exception as e:
                    elapsed = time.time() - start_time
                    test_result["elapsed_time"] = elapsed
                    test_result["status"] = "exception"
                    test_result["error"] = str(e)
                    print(f"  EXCEPTION after {elapsed:.2f}s: {str(e)}")

                results["tests"].append(test_result)

                # Short pause between tests
                await asyncio.sleep(2)

        # Summarize results
        success_count = sum(
            1 for t in results["tests"] if t["status"] == "success"
        )
        timeout_count = sum(
            1 for t in results["tests"] if t["status"] == "timeout"
        )
        error_count = sum(1 for t in results["tests"] if t["status"] == "error")

        avg_time_success = 0
        if success_count > 0:
            avg_time_success = (
                sum(
                    t["elapsed_time"]
                    for t in results["tests"]
                    if t["status"] == "success"
                )
                / success_count
            )

        print("\n" + "=" * 80)
        print(f"TIMING TEST SUMMARY FOR QUERY: '{query}'")
        print("=" * 80)
        print(f"\nTotal tests: {len(results['tests'])}")
        print(
            f"Successful: {success_count} ({success_count/len(results['tests'])*100:.1f}%)"
        )
        print(
            f"Timeouts: {timeout_count} ({timeout_count/len(results['tests'])*100:.1f}%)"
        )
        print(
            f"Errors: {error_count} ({error_count/len(results['tests'])*100:.1f}%)"
        )

        if success_count > 0:
            print(
                f"\nAverage time for successful searches: {avg_time_success:.2f}s"
            )

            # Find minimum timeout that works
            for timeout in timeouts:
                timeout_success = sum(
                    1
                    for t in results["tests"]
                    if t["status"] == "success"
                    and t["timeout_setting"] == timeout
                )
                timeout_total = sum(
                    1
                    for t in results["tests"]
                    if t["timeout_setting"] == timeout
                )

                if timeout_success > 0:
                    print(
                        f"Timeout {timeout}s: {timeout_success}/{timeout_total} successful ({timeout_success/timeout_total*100:.1f}%)"
                    )

                    if timeout_success == timeout_total:
                        print(
                            f"\nRECOMMENDATION: Minimum reliable timeout appears to be {timeout}s"
                        )
                        break
        else:
            print(f"\nNo successful searches - all timed out or failed")
            print(
                f"RECOMMENDATION: Investigate search service issues - may be unavailable or severely overloaded"
            )

        print("\n" + "=" * 80)

        return results

    async def connection_test(self) -> Dict[str, Any]:
        """
        Test basic connectivity to different API endpoints
        """
        await self.init_session()
        results = {"endpoints": {}}

        endpoints = [
            {"name": "Health Check", "path": "/health", "method": "get"},
            {"name": "API Root", "path": "/api", "method": "get"},
            {
                "name": "Search Endpoint",
                "path": "/api/search",
                "method": "post",
                "payload": {"query": "test", "max_results": 1},
            },
            {
                "name": "Direct GEO",
                "path": "/api/geo/GSE278726",
                "method": "get",
            },
        ]

        print("\n" + "=" * 80)
        print(f"API CONNECTION TEST")
        print("=" * 80)

        for endpoint in endpoints:
            start_time = time.time()
            name = endpoint["name"]
            path = endpoint["path"]
            method = endpoint["method"]
            url = f"{self.api_url}{path}"

            print(f"\nTesting {name} ({url})...")

            try:
                timeout = aiohttp.ClientTimeout(total=10)

                if method == "get":
                    async with self.session.get(
                        url, timeout=timeout
                    ) as response:
                        elapsed = time.time() - start_time
                        status = response.status

                        try:
                            data = await response.json()
                            content_type = "json"
                        except:
                            data = await response.text()
                            content_type = "text"

                        results["endpoints"][name] = {
                            "url": url,
                            "method": method,
                            "status": status,
                            "time": elapsed,
                            "content_type": content_type,
                            "success": 200 <= status < 300,
                        }

                        print(f"  Status: {status}, Time: {elapsed:.2f}s")

                elif method == "post":
                    payload = endpoint.get("payload", {})
                    async with self.session.post(
                        url, json=payload, timeout=timeout
                    ) as response:
                        elapsed = time.time() - start_time
                        status = response.status

                        try:
                            data = await response.json()
                            content_type = "json"
                        except:
                            data = await response.text()
                            content_type = "text"

                        results["endpoints"][name] = {
                            "url": url,
                            "method": method,
                            "status": status,
                            "time": elapsed,
                            "content_type": content_type,
                            "success": 200 <= status < 300,
                        }

                        print(f"  Status: {status}, Time: {elapsed:.2f}s")

            except asyncio.TimeoutError:
                elapsed = time.time() - start_time
                results["endpoints"][name] = {
                    "url": url,
                    "method": method,
                    "status": "timeout",
                    "time": elapsed,
                    "success": False,
                }
                print(f"  TIMEOUT after {elapsed:.2f}s")

            except Exception as e:
                elapsed = time.time() - start_time
                results["endpoints"][name] = {
                    "url": url,
                    "method": method,
                    "status": "exception",
                    "time": elapsed,
                    "error": str(e),
                    "success": False,
                }
                print(f"  EXCEPTION after {elapsed:.2f}s: {str(e)}")

        # Summarize results
        success_count = sum(
            1
            for _, data in results["endpoints"].items()
            if data.get("success", False)
        )

        print("\n" + "=" * 80)
        print(f"CONNECTION TEST SUMMARY")
        print("=" * 80)
        print(f"\nTotal endpoints tested: {len(results['endpoints'])}")
        print(
            f"Successful connections: {success_count}/{len(results['endpoints'])}"
        )

        # Check for patterns
        if success_count == 0:
            print(
                f"\nDIAGNOSIS: No endpoints are responding - API may be completely down"
            )
        elif all(
            data.get("success", False)
            for name, data in results["endpoints"].items()
            if name != "Search Endpoint"
        ):
            print(
                f"\nDIAGNOSIS: All endpoints except search are working - search service may be isolated issue"
            )
        elif all(
            data.get("success", False)
            for name, data in results["endpoints"].items()
            if "search" not in name.lower()
        ):
            print(
                f"\nDIAGNOSIS: Only search-related endpoints are failing - search service is likely down"
            )

        print("\n" + "=" * 80)

        return results


async def main():
    parser = argparse.ArgumentParser(
        description="Diagnose search function performance and data integrity issues"
    )

    # Create a mutually exclusive group for test types
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--direct-test",
        help="Compare direct API and search results for a GSE ID",
    )
    group.add_argument(
        "--timing-test", help="Test search performance with different timeouts"
    )
    group.add_argument(
        "--connection-test",
        action="store_true",
        help="Test basic API connectivity",
    )

    parser.add_argument(
        "--api-url", default="http://localhost:8001", help="API URL"
    )
    parser.add_argument(
        "--disable-ssl-verify",
        action="store_true",
        help="Disable SSL verification",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="Number of test iterations for timing tests",
    )

    args = parser.parse_args()

    diagnostics = SearchDiagnostics(
        api_url=args.api_url, disable_ssl_verify=args.disable_ssl_verify
    )

    try:
        if args.direct_test:
            await diagnostics.direct_test(args.direct_test)
        elif args.timing_test:
            await diagnostics.timing_test(args.timing_test, args.iterations)
        elif args.connection_test:
            await diagnostics.connection_test()
    finally:
        await diagnostics.close_session()


if __name__ == "__main__":
    asyncio.run(main())
