#!/usr/bin/env python3
"""
Test script for pagination functionality
"""

import asyncio

import aiohttp


async def test_pagination():
    """Test the pagination system with different page sizes and pages"""

    base_url = "http://localhost:8888"

    async with aiohttp.ClientSession() as session:
        print("🧪 Testing Pagination System")
        print("=" * 50)

        # Test data for pagination
        test_cases = [
            {"query": "BRCA1", "page": 1, "page_size": 5},
            {"query": "BRCA1", "page": 2, "page_size": 5},
            {"query": "cancer", "page": 1, "page_size": 3},
            {"query": "cancer", "page": 2, "page_size": 3},
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

        for i, test_case in enumerate(test_cases, 1):
            print(
                f"\n🔍 Test {i}: Query='{test_case['query']}', Page={test_case['page']}, Size={test_case['page_size']}"
            )

            # Prepare form data
            form_data = aiohttp.FormData()
            form_data.add_field("query", test_case["query"])
            form_data.add_field(
                "max_results", "20"
            )  # Request more total results
            form_data.add_field("page", str(test_case["page"]))
            form_data.add_field("page_size", str(test_case["page_size"]))

            try:
                async with session.post(
                    f"{base_url}/search", data=form_data
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        # Extract pagination info
                        pagination = data.get("pagination", {})
                        results = data.get("results", [])

                        print(f"   ✅ Status: {data.get('status', 'unknown')}")
                        print(f"   📊 Results: {len(results)} displayed")
                        print(
                            f"   📄 Page: {pagination.get('current_page', 'N/A')} of {pagination.get('total_pages', 'N/A')}"
                        )
                        print(
                            f"   🔢 Total: {pagination.get('total_results', 'N/A')} datasets"
                        )
                        print(
                            f"   📍 Range: {pagination.get('start_index', 'N/A')}-{pagination.get('end_index', 'N/A')}"
                        )
                        print(
                            f"   ⬅️  Has Previous: {pagination.get('has_previous', False)}"
                        )
                        print(
                            f"   ➡️  Has Next: {pagination.get('has_next', False)}"
                        )

                        # Display first result title for verification
                        if results:
                            print(
                                f"   📋 First Result: {results[0].get('title', 'N/A')[:60]}..."
                            )

                    else:
                        print(f"   ❌ Error: HTTP {response.status}")
                        error_text = await response.text()
                        print(f"   📝 Response: {error_text[:200]}...")

            except Exception as e:
                print(f"   ❌ Exception: {e}")

            # Small delay between requests to be gentle on the server
            await asyncio.sleep(0.5)

        print("\n✅ Pagination testing completed!")


if __name__ == "__main__":
    asyncio.run(test_pagination())
