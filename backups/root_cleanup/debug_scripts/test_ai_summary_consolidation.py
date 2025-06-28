#!/usr/bin/env python3
"""
Test script to validate AI Summary Consolidation.
Ensures no fallback, mock, or template summaries are returned.
"""

import json
import sys
from typing import Any, Dict, List

import requests


def test_search_endpoint():
    """Test that search endpoint returns null for ai_summary when no real AI content available."""
    print("🔍 Testing search endpoint for consolidation...")

    try:
        response = requests.post(
            "http://localhost:8000/api/v1/search/datasets",
            headers={"Content-Type": "application/json"},
            json={"query": "cancer", "limit": 5},
            timeout=10,
        )

        if response.status_code != 200:
            print(f"❌ Search endpoint failed: {response.status_code}")
            return False

        data = response.json()
        datasets = data.get("datasets", [])

        if not datasets:
            print("⚠️  No datasets returned from search")
            return True

        print(f"✅ Found {len(datasets)} datasets")

        # Check that all ai_summary fields are either null or contain real content
        fallback_found = False
        for dataset in datasets:
            ai_summary = dataset.get("ai_summary")

            if ai_summary is None:
                print(f"✅ Dataset {dataset.get('geo_id', 'unknown')}: ai_summary is null (correct)")
                continue

            # Check for fallback/mock content patterns
            if isinstance(ai_summary, str):
                fallback_patterns = [
                    "fallback",
                    "mock",
                    "template",
                    "placeholder",
                    "This is a generic",
                    "No AI summary available",
                    "AI-powered summary not available",
                    "Currently generating",
                ]

                summary_lower = ai_summary.lower()
                for pattern in fallback_patterns:
                    if pattern.lower() in summary_lower:
                        print(f"❌ Found fallback content in {dataset.get('geo_id', 'unknown')}: {pattern}")
                        fallback_found = True
                        break

                if not fallback_found:
                    print(
                        f"✅ Dataset {dataset.get('geo_id', 'unknown')}: ai_summary appears to be real content"
                    )

            elif isinstance(ai_summary, dict):
                # Check dictionary summaries
                for key, value in ai_summary.items():
                    if value and isinstance(value, str):
                        fallback_patterns = ["fallback", "mock", "template", "placeholder"]
                        value_lower = value.lower()
                        for pattern in fallback_patterns:
                            if pattern.lower() in value_lower:
                                print(
                                    f"❌ Found fallback content in {dataset.get('geo_id', 'unknown')}.{key}: {pattern}"
                                )
                                fallback_found = True
                                break

        return not fallback_found

    except Exception as e:
        print(f"❌ Error testing search endpoint: {e}")
        return False


def test_frontend_accessibility():
    """Test that frontend is accessible."""
    print("🌐 Testing frontend accessibility...")

    try:
        response = requests.get("http://localhost:8001/", timeout=10)
        if response.status_code == 200:
            print("✅ Frontend is accessible")
            return True
        else:
            print(f"❌ Frontend returned status: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error accessing frontend: {e}")
        return False


def test_backend_health():
    """Test backend health endpoints."""
    print("🏥 Testing backend health...")

    try:
        response = requests.get("http://localhost:8000/health/", timeout=10)
        if response.status_code == 200:
            print("✅ Backend health check passed")
            return True
        else:
            print(f"❌ Backend health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error checking backend health: {e}")
        return False


def main():
    """Run all consolidation tests."""
    print("🚀 AI Summary Consolidation Validation Test")
    print("=" * 50)

    tests = [
        ("Backend Health", test_backend_health),
        ("Frontend Accessibility", test_frontend_accessibility),
        ("Search Endpoint Consolidation", test_search_endpoint),
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        print(f"\n📋 Running: {test_name}")
        if test_func():
            passed += 1
        else:
            print(f"❌ {test_name} failed")

    print(f"\n{'='*50}")
    print(f"🎯 Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! AI Summary consolidation is working correctly.")
        print("✅ No fallback, mock, or template summaries detected.")
        print("✅ Backend and frontend are running properly.")
        return True
    else:
        print("❌ Some tests failed. Check the output above for details.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
