#!/usr/bin/env python3
"""
Comprehensive API endpoint tester for OmicsOracle.
Tests all advertised endpoints and provides detailed feedback.
"""

import json
import sys
import time

import requests


def test_endpoint(url, description, expected_status=200):
    """Test a single endpoint and return results."""
    try:
        response = requests.get(url, timeout=10)
        success = response.status_code == expected_status

        result = {
            "url": url,
            "description": description,
            "status_code": response.status_code,
            "success": success,
            "response": None,
            "error": None,
        }

        if success:
            try:
                result["response"] = response.json()
            except:
                result["response"] = response.text[:200]
        else:
            result["error"] = response.text[:200]

        return result

    except Exception as e:
        return {
            "url": url,
            "description": description,
            "status_code": None,
            "success": False,
            "response": None,
            "error": str(e),
        }


def main():
    base_url = "http://localhost:8000"

    print("🧪 OmicsOracle API Endpoint Comprehensive Test")
    print("=" * 60)

    # Check if server is running
    try:
        response = requests.get(base_url, timeout=5)
        print("✅ Server is responding")
    except:
        print("❌ Server is not responding at http://localhost:8000")
        print("Please start the server with: ./start_server.sh")
        sys.exit(1)

    # Test all endpoints
    endpoints = [
        (f"{base_url}/health", "Health Check"),
        (f"{base_url}/api", "API Discovery"),
        (f"{base_url}/api/v1/", "V1 API Info"),
        (f"{base_url}/api/v2/", "V2 API Info"),
        (f"{base_url}/docs", "API Documentation", 200),
        # V1 Endpoints
        (f"{base_url}/api/v1/search?query=cancer", "V1 Search"),
        (f"{base_url}/api/v1/health", "V1 Health"),
        (f"{base_url}/api/v1/status", "V1 Status"),
        # V2 Endpoints
        (
            f"{base_url}/api/v2/search/advanced?query=cancer",
            "V2 Advanced Search",
        ),
        (f"{base_url}/api/v2/health/detailed", "V2 Detailed Health"),
        (f"{base_url}/api/v2/cache/stats", "V2 Cache Stats"),
        (f"{base_url}/api/v2/services/registry", "V2 Services Registry"),
    ]

    results = []
    for endpoint_info in endpoints:
        url = endpoint_info[0]
        description = endpoint_info[1]
        expected_status = endpoint_info[2] if len(endpoint_info) > 2 else 200

        result = test_endpoint(url, description, expected_status)
        results.append(result)

        # Print immediate feedback
        status_icon = "✅" if result["success"] else "❌"
        print(
            f"{status_icon} {description:25} | {result['status_code'] or 'FAIL':>4} | {url}"
        )

    print("\n" + "=" * 60)
    print("📊 DETAILED RESULTS")
    print("=" * 60)

    working_count = sum(1 for r in results if r["success"])
    total_count = len(results)

    print(
        f"✅ Working: {working_count}/{total_count} ({working_count/total_count*100:.1f}%)"
    )

    # Show failures in detail
    failures = [r for r in results if not r["success"]]
    if failures:
        print(f"\n❌ FAILED ENDPOINTS ({len(failures)}):")
        print("-" * 40)
        for failure in failures:
            print(f"\n🔍 {failure['description']}")
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
            print(f"✓ {success['description']} - {success['url']}")


if __name__ == "__main__":
    main()
