#!/usr/bin/env python3
"""
Simple test to examine actual API responses and scoring.
"""

import json

import requests


def test_api_scoring():
    """Test the API to see actual scoring results."""

    # API endpoint
    url = "http://localhost:8000/api/search"

    # Test query
    payload = {"query": "cancer gene expression", "max_results": 5}

    print(f"Testing API with query: '{payload['query']}'")
    print("=" * 60)

    try:
        response = requests.post(url, json=payload, timeout=30)

        if response.status_code == 200:
            data = response.json()

            print(f"Found {len(data.get('results', []))} results:")
            print()

            for i, result in enumerate(data.get("results", [])):
                print(f"Result {i+1}:")
                print(f"  ID: {result.get('id', 'N/A')}")
                print(f"  Title: {result.get('title', 'N/A')[:100]}...")
                print(f"  Relevance Score: {result.get('relevance_score', 'N/A')}")
                print(f"  Source: {result.get('source', 'N/A')}")
                print()

        else:
            print(f"API Error: {response.status_code}")
            print(f"Response: {response.text}")

    except requests.exceptions.ConnectionError:
        print("Cannot connect to API. Make sure the server is running on http://localhost:8000")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    test_api_scoring()
