#!/usr/bin/env python3
"""
Quick API endpoint test to verify our fixes worked.
"""

import json

import requests


def test_endpoints():
    base_url = "http://localhost:8000"

    endpoints_to_test = [
        ("/health", "Health Check"),
        ("/api", "API Discovery"),
        ("/api/v1/", "V1 API Info"),
        ("/api/v2/", "V2 API Info"),
        ("/docs", "API Documentation"),
    ]

    print("Testing OmicsOracle API Endpoints")
    print("=" * 50)

    for endpoint, description in endpoints_to_test:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            status = "✓" if response.status_code == 200 else "✗"
            print(
                f"{status} {description:20} {endpoint:15} -> {response.status_code}"
            )

            if response.status_code == 200 and endpoint in [
                "/api",
                "/api/v1/",
                "/api/v2/",
            ]:
                data = response.json()
                print(f"   {json.dumps(data, indent=6)[:200]}...")

        except requests.exceptions.RequestException as e:
            print(f"✗ {description:20} {endpoint:15} -> ERROR: {e}")

    print("\n" + "=" * 50)
    print("Server is running at http://localhost:8000")
    print("Full API docs available at http://localhost:8000/docs")


if __name__ == "__main__":
    test_endpoints()
