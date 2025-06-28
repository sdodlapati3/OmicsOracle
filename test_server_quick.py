#!/usr/bin/env python3
"""
Quick server test to verify OmicsOracle is responding correctly.
"""

import json
import sys

import requests


def test_server(base_url="http://localhost:8000"):
    """Test if the OmicsOracle server is responding correctly."""
    print("🔍 Testing OmicsOracle Server...")
    print("=" * 50)

    tests = [
        {"name": "Root Endpoint", "url": f"{base_url}/", "method": "GET", "expected_status": 200},
        {"name": "Health Check", "url": f"{base_url}/health", "method": "GET", "expected_status": 200},
        {"name": "API Documentation", "url": f"{base_url}/docs", "method": "GET", "expected_status": 200},
        {"name": "API Discovery", "url": f"{base_url}/api", "method": "GET", "expected_status": 200},
    ]

    all_passed = True

    for test in tests:
        try:
            print(f"\n🧪 Testing {test['name']}...")
            print(f"   URL: {test['url']}")

            response = requests.get(test["url"], timeout=10)

            if response.status_code == test["expected_status"]:
                print(f"   ✅ Status: {response.status_code} (Expected: {test['expected_status']})")

                # Try to parse JSON response
                try:
                    data = response.json()
                    if test["name"] == "Root Endpoint":
                        print(f"   📝 Message: {data.get('message', 'N/A')}")
                        print(f"   🎯 Version: {data.get('version', 'N/A')}")
                    elif test["name"] == "Health Check":
                        print(f"   💚 Status: {data.get('status', 'N/A')}")
                    elif test["name"] == "API Discovery":
                        print(f"   🔄 API Name: {data.get('api_name', 'N/A')}")
                        print(f"   📊 Versions: {list(data.get('available_versions', {}).keys())}")
                except:
                    print(f"   📄 Response: {response.text[:100]}...")

            else:
                print(f"   ❌ Status: {response.status_code} (Expected: {test['expected_status']})")
                print(f"   📄 Response: {response.text[:200]}...")
                all_passed = False

        except requests.exceptions.ConnectionError:
            print(f"   💀 Connection Error: Server not reachable at {test['url']}")
            all_passed = False
        except requests.exceptions.Timeout:
            print(f"   ⏱️  Timeout: Server took too long to respond")
            all_passed = False
        except Exception as e:
            print(f"   💥 Error: {e}")
            all_passed = False

    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 ALL TESTS PASSED - Server is working correctly!")
        print("\n🚀 Server Access Points:")
        print(f"   • Web Interface: {base_url}/")
        print(f"   • API Documentation: {base_url}/docs")
        print(f"   • Health Check: {base_url}/health")
        print(f"   • API Discovery: {base_url}/api")
        return True
    else:
        print("💥 SOME TESTS FAILED - Check server configuration")
        return False


if __name__ == "__main__":
    success = test_server()
    sys.exit(0 if success else 1)
