#!/usr/bin/env python3
"""
Simple server connectivity test for OmicsOracle
"""

import json
import sys

import requests


def test_endpoint(url, description):
    """Test a single endpoint and report results."""
    print(f"\n🔍 Testing {description}: {url}")
    try:
        response = requests.get(url, timeout=10)
        print(f"   Status: {response.status_code}")

        if response.status_code == 200:
            print("   ✅ SUCCESS")
            try:
                data = response.json()
                print(f"   Response keys: {list(data.keys())[:5]}...")
                return True
            except:
                print(f"   Response length: {len(response.text)} chars")
                return True
        else:
            print(f"   ❌ ERROR: {response.text[:100]}...")
            return False

    except requests.exceptions.ConnectionError:
        print("   ❌ CONNECTION REFUSED - Server not running?")
        return False
    except requests.exceptions.Timeout:
        print("   ⏱️  TIMEOUT")
        return False
    except Exception as e:
        print(f"   ⚠️  ERROR: {e}")
        return False


def main():
    print("🚀 OmicsOracle Server Connectivity Test")
    print("=" * 50)

    base_url = "http://localhost:8000"

    # Test endpoints
    endpoints = [
        ("", "Root Route"),
        ("/health", "Health Check"),
        ("/health/status", "Health Status"),
        ("/api", "API Discovery"),
        ("/docs", "API Documentation"),
    ]

    success_count = 0
    total_count = len(endpoints)

    for endpoint, description in endpoints:
        url = f"{base_url}{endpoint}"
        if test_endpoint(url, description):
            success_count += 1

    print("\n" + "=" * 50)
    print(f"📊 Results: {success_count}/{total_count} endpoints working")

    if success_count == total_count:
        print("🎉 ALL TESTS PASSED - Server is working perfectly!")
        return 0
    elif success_count > 0:
        print("⚠️  PARTIAL SUCCESS - Some endpoints working")
        return 1
    else:
        print("❌ ALL TESTS FAILED - Server may not be running")
        return 2


if __name__ == "__main__":
    sys.exit(main())
