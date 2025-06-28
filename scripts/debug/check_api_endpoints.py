#!/usr/bin/env python3
"""
Quick test script to check available API endpoints.
"""

import json

import requests

base_url = "http://localhost:8000"


def test_endpoint(endpoint, description):
    """Test a specific endpoint."""
    try:
        response = requests.get(f"{base_url}{endpoint}", timeout=5)
        print(f"✅ {description}: {endpoint} -> {response.status_code}")
        if response.status_code == 200:
            return response.json()
        return None
    except requests.exceptions.RequestException as e:
        print(f"❌ {description}: {endpoint} -> Error: {e}")
        return None


def main():
    print("🔍 Testing OmicsOracle API endpoints...")
    print("=" * 50)

    # Test basic endpoints
    endpoints_to_test = [
        ("/health", "Health Check"),
        ("/api", "API Discovery"),
        ("/api/v1/search?query=cancer", "V1 Search"),
        ("/api/v2/search/advanced?query=cancer", "V2 Advanced Search"),
        ("/docs", "API Documentation"),
    ]

    results = {}
    for endpoint, description in endpoints_to_test:
        result = test_endpoint(endpoint, description)
        if result:
            results[endpoint] = result

    print("\n📋 Successful responses:")
    print("=" * 50)
    for endpoint, data in results.items():
        print(f"\n🎯 {endpoint}:")
        print(
            json.dumps(data, indent=2)[:500] + "..." if len(str(data)) > 500 else json.dumps(data, indent=2)
        )


if __name__ == "__main__":
    main()
