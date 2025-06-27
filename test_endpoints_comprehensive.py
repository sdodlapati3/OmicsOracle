#!/usr/bin/env python3
"""
Comprehensive API endpoint tester for OmicsOracle.
Tests all advertised endpoints and provides detailed feedback.
"""

import argparse
import json
import sys

import requests


def test_endpoint(
    url,
    description,
    expected_status=200,
    method="GET",
    payload=None,
    headers=None,
):
    """Test a single endpoint and return results."""
    try:
        if method.upper() == "GET":
            response = requests.get(url, timeout=10, headers=headers)
        elif method.upper() == "POST":
            response = requests.post(
                url, json=payload, timeout=10, headers=headers
            )
        else:
            return {
                "url": url,
                "description": description,
                "status_code": None,
                "success": False,
                "response": None,
                "error": f"Unsupported method: {method}",
            }

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
            except Exception:
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


def validate_enhanced_query_results(result):
    """Validate that enhanced query results contain expected structure and data."""
    validation = {"valid": False, "issues": []}

    if not result["success"]:
        validation["issues"].append("Request failed")
        return validation

    response = result["response"]

    # Check for required fields
    required_fields = ["datasets", "query", "total_found"]
    for field in required_fields:
        if field not in response:
            validation["issues"].append(f"Missing required field: {field}")

    # Check for expanded components if available
    if "components" in response:
        if not isinstance(response["components"], dict):
            validation["issues"].append("Components should be a dictionary")
        else:
            for component in ["disease", "tissue", "organism", "data_type"]:
                if component not in response["components"]:
                    validation["issues"].append(
                        f"Missing component: {component}"
                    )

    # Validate datasets
    if "datasets" in response and isinstance(response["datasets"], list):
        if not response["datasets"] and response.get("total_found", 0) > 0:
            validation["issues"].append(
                "Total found > 0 but no datasets returned"
            )

    # Set valid flag if no issues found
    if not validation["issues"]:
        validation["valid"] = True

    return validation


def test_enhanced_query_endpoints(base_url):
    """Test enhanced query endpoints with various biomedical queries."""
    test_queries = [
        "gene expression data for liver cancer",
        "human breast cancer transcriptome",
        "diabetes pancreatic tissue RNA-seq",
    ]

    results = []

    # Test each query
    for query in test_queries:
        # Test standard search
        url = f"{base_url}/api/v2/search/enhanced?query={query}"
        result = test_endpoint(
            url, f"Enhanced Search: '{query}'", expected_status=200
        )
        results.append(result)

        # Test with trace enabled
        url = f"{base_url}/api/v2/search/enhanced?query={query}&trace=true"
        result = test_endpoint(
            url, f"Enhanced Search with Trace: '{query}'", expected_status=200
        )
        results.append(result)

        # Test component extraction
        url = f"{base_url}/api/v2/query/components?query={query}"
        result = test_endpoint(
            url, f"Query Component Extraction: '{query}'", expected_status=200
        )
        results.append(result)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Test OmicsOracle API endpoints"
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="Base URL for the API",
    )
    parser.add_argument(
        "--enhanced-only",
        action="store_true",
        help="Only test enhanced query endpoints",
    )
    args = parser.parse_args()

    base_url = args.base_url

    print("🧪 OmicsOracle API Endpoint Comprehensive Test")
    print("=" * 60)

    # Check if server is responding
    try:
        requests.get(base_url, timeout=5)
        print(f"Server is responding at {base_url}")
    except Exception:
        print(f"Server is not responding at {base_url}")
        print("Please start the server with: ./start_server.sh")
        sys.exit(1)

    results = []

    # Test enhanced query endpoints if requested or with all tests
    if args.enhanced_only:
        print("\n🔍 Testing Enhanced Query Endpoints...")
        results.extend(test_enhanced_query_endpoints(base_url))
    else:
        # Test all endpoints
        standard_endpoints = [
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

        for endpoint_info in standard_endpoints:
            url = endpoint_info[0]
            description = endpoint_info[1]
            expected_status = (
                endpoint_info[2] if len(endpoint_info) > 2 else 200
            )

            result = test_endpoint(url, description, expected_status)
            results.append(result)

        # Add enhanced query endpoints
        print("\n🔍 Testing Enhanced Query Endpoints...")
        results.extend(test_enhanced_query_endpoints(base_url))

    # Print immediate feedback for all results
    for result in results:
        status_icon = "✅" if result["success"] else "❌"
        print(
            f"{status_icon} {result['description']:40} | {result['status_code'] or 'FAIL':>4} | {result['url']}"
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

            # For enhanced query endpoints, validate results
            if "Enhanced Search" in success["description"]:
                validation = validate_enhanced_query_results(success)
                if validation["valid"]:
                    print(f"  ✓ Enhanced query validation passed")
                else:
                    print(f"  ⚠️ Enhanced query validation failed:")
                    for issue in validation["issues"]:
                        print(f"    - {issue}")

    # Save detailed results to file
    results_file = "endpoint_test_results.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nDetailed results saved to: {results_file}")

    # Return success status
    return working_count == total_count


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
