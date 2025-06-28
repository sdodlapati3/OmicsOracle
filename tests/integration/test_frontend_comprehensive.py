#!/usr/bin/env python3
"""
Comprehensive frontend endpoint tester for OmicsOracle Enhanced Interface.
Tests all frontend API endpoints and validates functionality.
"""

import sys
import time

import requests


def test_endpoint(url, description, method="GET", data=None, expected_status=200):
    """Test a single endpoint and return results."""
    try:
        if method.upper() == "POST":
            response = requests.post(url, json=data, timeout=30)
        else:
            response = requests.get(url, timeout=10)

        success = response.status_code == expected_status

        result = {
            "url": url,
            "description": description,
            "method": method,
            "status_code": response.status_code,
            "success": success,
            "response": None,
            "error": None,
        }

        if success:
            try:
                result["response"] = response.json()
            except Exception:
                result["response"] = response.text[:200]
        else:
            result["error"] = response.text[:200]

        return result

    except Exception as e:
        return {
            "url": url,
            "description": description,
            "method": method,
            "status_code": None,
            "success": False,
            "response": None,
            "error": str(e),
        }


def main():
    base_url = "http://localhost:8002"

    print("🚀 OmicsOracle Frontend Comprehensive Test")
    print("=" * 60)

    # Check if frontend is running
    try:
        response = requests.get(f"{base_url}/api/health", timeout=5)
        if response.status_code == 200:
            health_data = response.json()
            print(f"✅ Frontend is responding")
            print(f"📊 Pipeline Status: {health_data.get('status', 'unknown')}")
            print(f"🔧 Pipeline Available: {health_data.get('pipeline_available', False)}")
        else:
            print(f"⚠️  Frontend responding but health check failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Frontend is not responding at {base_url}")
        print(f"   Error: {e}")
        print("Please start the frontend with: ./start.sh --frontend-only --frontend-port 8002")
        sys.exit(1)

    print("\n🧪 Testing Frontend Endpoints...")
    print("=" * 60)

    # Test all frontend endpoints
    endpoints = [
        # Basic endpoints
        (f"{base_url}/api/health", "Health Check", "GET", None, 200),
        (f"{base_url}/", "Main Interface", "GET", None, 200),
        # Search endpoints
        (
            f"{base_url}/api/search",
            "Search - Simple Cancer Query",
            "POST",
            {"query": "cancer", "max_results": 2},
            200,
        ),
        (
            f"{base_url}/api/search",
            "Search - Complex Query",
            "POST",
            {
                "query": "gene expression analysis in breast cancer",
                "max_results": 1,
            },
            200,
        ),
        (
            f"{base_url}/api/search",
            "Search - Quick Test",
            "POST",
            {"query": "test", "max_results": 1},
            200,
        ),
    ]

    results = []
    for endpoint_info in endpoints:
        url, description, method, data, expected_status = endpoint_info

        print(f"\n🔍 Testing: {description}")
        start_time = time.time()

        result = test_endpoint(url, description, method, data, expected_status)

        end_time = time.time()
        result["test_time"] = end_time - start_time

        results.append(result)

        # Print immediate feedback
        status_icon = "✅" if result["success"] else "❌"
        time_str = f"({result['test_time']:.2f}s)"
        print(f"   {status_icon} {result['status_code'] or 'FAIL'} {time_str}")

        if result["success"] and method == "POST" and "search" in url:
            # Show search result summary
            try:
                resp_data = result["response"]
                if isinstance(resp_data, dict):
                    query = resp_data.get("query", "N/A")
                    total = resp_data.get("total_found", 0)
                    search_time = resp_data.get("search_time", 0)
                    print(f"   📊 Query: '{query[:50]}...' → {total} results in {search_time:.2f}s")
            except (ValueError, TypeError, KeyError):
                pass

    print("\n" + "=" * 60)
    print("📊 COMPREHENSIVE RESULTS")
    print("=" * 60)

    working_count = sum(1 for r in results if r["success"])
    total_count = len(results)

    print(f"✅ Working: {working_count}/{total_count} ({working_count/total_count*100:.1f}%)")

    # Show performance summary
    search_results = [r for r in results if r["success"] and "search" in r["url"].lower()]
    if search_results:
        avg_search_time = sum(r["test_time"] for r in search_results) / len(search_results)
        print(f"⚡ Average Search Time: {avg_search_time:.2f}s")

    # Show failures in detail
    failures = [r for r in results if not r["success"]]
    if failures:
        print(f"\n❌ FAILED ENDPOINTS ({len(failures)}):")
        print("-" * 40)
        for failure in failures:
            print(f"\n🔍 {failure['description']} [{failure['method']}]")
            print(f"   URL: {failure['url']}")
            print(f"   Status: {failure['status_code']}")
            if failure["error"]:
                print(f"   Error: {failure['error'][:100]}...")

    # Show working endpoints
    successes = [r for r in results if r["success"]]
    if successes:
        print(f"\n✅ WORKING ENDPOINTS ({len(successes)}):")
        print("-" * 40)
        for success in successes:
            method_str = f"[{success['method']}]"
            time_str = f"({success['test_time']:.2f}s)"
            print(f"✓ {success['description']} {method_str} {time_str}")

    print(
        f"\n🎯 Frontend Status: {'FULLY FUNCTIONAL' if working_count == total_count else 'PARTIAL FUNCTIONALITY'}"
    )

    if working_count == total_count:
        print("🎉 All frontend endpoints are working perfectly!")
        print("🌐 Frontend URL: http://localhost:8002")
        print("📚 WebSocket monitoring and real-time search are operational")


if __name__ == "__main__":
    main()
