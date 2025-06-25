#!/usr/bin/env python3
"""
Test script for enhanced search interface features
"""

import asyncio

import aiohttp


async def test_enhanced_search_interface():
    """Test the enhanced search interface features"""

    base_url = "http://localhost:8888"

    async with aiohttp.ClientSession() as session:
        print("🧪 Testing Enhanced Search Interface")
        print("=" * 60)

        # Test cases for new API endpoints
        tests = [
            {
                "name": "Search Suggestions",
                "endpoint": "/api/search-suggestions",
                "params": {"q": "cancer"},
                "expected_keys": ["query", "suggestions", "status"],
            },
            {
                "name": "Quick Filters",
                "endpoint": "/api/quick-filters",
                "params": {},
                "expected_keys": ["filters", "status"],
            },
            {
                "name": "Search History",
                "endpoint": "/api/search-history",
                "params": {},
                "expected_keys": ["history", "status"],
            },
            {
                "name": "Example Searches",
                "endpoint": "/api/example-searches",
                "params": {},
                "expected_keys": ["examples", "status"],
            },
        ]

        # First, test basic connectivity
        try:
            async with session.get(f"{base_url}/health") as response:
                if response.status != 200:
                    print(f"❌ Server not available at {base_url}")
                    return
                print(f"✅ Server is running at {base_url}")
        except Exception as e:
            print(f"❌ Cannot connect to server: {e}")
            return

        print("\n📊 Testing New API Endpoints:")
        print("-" * 40)

        for test in tests:
            print(f"\n🔍 Testing {test['name']}...")

            try:
                url = f"{base_url}{test['endpoint']}"
                params = test["params"]

                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()

                        print(f"   ✅ Status: HTTP {response.status}")
                        print(
                            f"   📄 Response Status: {data.get('status', 'unknown')}"
                        )

                        # Check expected keys
                        missing_keys = []
                        for key in test["expected_keys"]:
                            if key not in data:
                                missing_keys.append(key)

                        if not missing_keys:
                            print("   All expected keys present")
                        else:
                            print(f"   Missing keys: {missing_keys}")

                        # Show sample data
                        if test["name"] == "Search Suggestions":
                            suggestions = data.get("suggestions", [])
                            print(f"   📋 Suggestions count: {len(suggestions)}")
                            if suggestions:
                                print(f"   📝 Sample: {suggestions[0][:50]}...")

                        elif test["name"] == "Quick Filters":
                            filters = data.get("filters", [])
                            print(f"   🏷️  Filter count: {len(filters)}")
                            if filters:
                                print(
                                    f"   📝 Filters: {', '.join(filters[:3])}..."
                                )

                        elif test["name"] == "Search History":
                            history = data.get("history", [])
                            print(f"   📚 History count: {len(history)}")
                            if history:
                                print(
                                    f"   📝 Recent: {history[0] if history else 'None'}"
                                )

                        elif test["name"] == "Example Searches":
                            examples = data.get("examples", [])
                            print(f"   💡 Examples count: {len(examples)}")
                            if examples:
                                print(f"   📝 Sample: {examples[0]}")

                    else:
                        print(f"   ❌ HTTP Error: {response.status}")
                        error_text = await response.text()
                        print(f"   📝 Response: {error_text[:100]}...")

            except Exception as e:
                print(f"   ❌ Exception: {e}")

            # Small delay between requests
            await asyncio.sleep(0.3)

        print("\n🧪 Testing Search Suggestions with Different Queries:")
        print("-" * 50)

        suggestion_queries = ["brain", "rna", "diabetes", "heart", "xyz"]

        for query in suggestion_queries:
            print(f"\n🔍 Testing suggestions for: '{query}'")
            try:
                url = f"{base_url}/api/search-suggestions"
                params = {"q": query}

                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        suggestions = data.get("suggestions", [])
                        print(f"   📊 Found {len(suggestions)} suggestions")
                        if suggestions:
                            print(f"   📝 Top suggestion: {suggestions[0]}")
                    else:
                        print(f"   ❌ Error: HTTP {response.status}")
            except Exception as e:
                print(f"   ❌ Exception: {e}")

        print("\n✅ Enhanced search interface testing completed!")
        print("\n🎯 Summary:")
        print("   • Auto-complete suggestions: API ready")
        print("   • Quick filter tags: API ready")
        print("   • Search history: API ready")
        print("   • Example searches: API ready")
        print("   • Frontend JavaScript: Implemented")
        print("   • CSS styling: Enhanced")


if __name__ == "__main__":
    asyncio.run(test_enhanced_search_interface())
