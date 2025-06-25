#!/usr/bin/env python3
"""
Test script to debug the duplicate AI summary issue
"""

import asyncio
import aiohttp


async def test_search_issue() -> None:
    """Test the search to identify duplicate summary issue"""
    
    base_url = "http://localhost:8888"
    
    async with aiohttp.ClientSession() as session:
        print("🔍 Testing Search for Duplicate Summary Issue")
        print("=" * 60)
        
        # Test the specific search that shows duplicate summaries
        form_data = aiohttp.FormData()
        form_data.add_field("query", "immune system COVID-19")
        form_data.add_field("max_results", "10")
        form_data.add_field("page", "1")
        form_data.add_field("page_size", "5")  # Get first 5 results
        
        try:
            async with session.post(f"{base_url}/search", data=form_data) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    print(f"✅ Status: {data.get('status')}")
                    print(f"📊 Total Results: {data.get('total_count')}")
                    print(f"📄 Results Returned: {len(data.get('results', []))}")
                    print()
                    
                    # Analyze each result for duplicate summaries
                    results = data.get('results', [])
                    summaries = []
                    
                    for i, result in enumerate(results, 1):
                        print(f"Result {i}:")
                        print(f"  ID: {result.get('id')}")
                        print(f"  Title: {result.get('title', '')[:80]}...")
                        print(f"  AI Enhanced: {result.get('ai_enhanced')}")
                        
                        summary = result.get('summary', '')
                        # Check for first 100 characters to identify duplicates
                        summary_start = summary[:100]
                        summaries.append(summary_start)
                        
                        print(f"  Summary Start: {summary_start}...")
                        print()
                    
                    # Check for duplicates
                    print("🔍 Duplicate Analysis:")
                    unique_summaries = set(summaries)
                    if len(unique_summaries) < len(summaries):
                        print("Found duplicate summaries!")
                        print(f"   Total summaries: {len(summaries)}")
                        print(f"   Unique summaries: {len(unique_summaries)}")
                        
                        # Find which summaries are duplicated
                        from collections import Counter
                        summary_counts = Counter(summaries)
                        for summary, count in summary_counts.items():
                            if count > 1:
                                print(f"   Duplicate: '{summary[:50]}...' appears {count} times")
                    else:
                        print("✅ All summaries are unique")
                        
                else:
                    print(f"❌ Error: HTTP {response.status}")
                    
        except Exception as e:
            print(f"❌ Exception: {e}")


if __name__ == "__main__":
    asyncio.run(test_search_issue())
