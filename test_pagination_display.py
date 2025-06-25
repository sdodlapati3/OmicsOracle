#!/usr/bin/env python3
"""
Test script to verify pagination behavior
"""

import asyncio
import aiohttp


async def test_pagination_display() -> None:
    """Test pagination to see if controls are displayed properly"""
    
    base_url = "http://localhost:8888"
    
    async with aiohttp.ClientSession() as session:
        print("🔍 Testing Pagination Display")
        print("=" * 50)
        
        # Test search with small page size to force pagination
        form_data = aiohttp.FormData()
        form_data.add_field("query", "immune system COVID-19")
        form_data.add_field("max_results", "20")  # Request more total results
        form_data.add_field("page", "1")
        form_data.add_field("page_size", "3")  # Small page size to force pagination
        
        try:
            async with session.post(f"{base_url}/search", data=form_data) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    print(f"✅ Status: {data.get('status')}")
                    
                    # Check pagination metadata
                    pagination = data.get('pagination', {})
                    print(f"📊 Pagination Info:")
                    print(f"  Current Page: {pagination.get('current_page')}")
                    print(f"  Page Size: {pagination.get('page_size')}")
                    print(f"  Total Results: {pagination.get('total_results')}")
                    print(f"  Total Pages: {pagination.get('total_pages')}")
                    print(f"  Has Next: {pagination.get('has_next')}")
                    print(f"  Has Previous: {pagination.get('has_previous')}")
                    print()
                    
                    # Show results summary
                    results = data.get('results', [])
                    print(f"📄 Results Summary:")
                    for i, result in enumerate(results, 1):
                        print(f"  {i}. {result.get('id')} - AI Enhanced: {result.get('ai_enhanced')}")
                        print(f"     Organism: {result.get('organism', 'Unknown')}")
                        
                    # Test page 2
                    print("\n🔍 Testing Page 2:")
                    form_data.add_field("page", "2")
                    
                    async with session.post(f"{base_url}/search", data=form_data) as response2:
                        if response2.status == 200:
                            data2 = await response2.json()
                            pagination2 = data2.get('pagination', {})
                            results2 = data2.get('results', [])
                            
                            print(f"  Page 2 - Current Page: {pagination2.get('current_page')}")
                            print(f"  Page 2 - Results Count: {len(results2)}")
                            print(f"  Page 2 - Has Previous: {pagination2.get('has_previous')}")
                            print(f"  Page 2 - Has Next: {pagination2.get('has_next')}")
                            
                else:
                    print(f"❌ Error: HTTP {response.status}")
                    
        except Exception as e:
            print(f"❌ Exception: {e}")


if __name__ == "__main__":
    asyncio.run(test_pagination_display())
