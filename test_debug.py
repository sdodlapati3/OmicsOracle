#!/usr/bin/env python3
"""
Test the debug endpoint to see result structure
"""

import asyncio
import aiohttp
import json


async def test_debug_endpoint() -> None:
    """Test the debug endpoint to understand result structure"""
    
    base_url = "http://localhost:8888"
    
    async with aiohttp.ClientSession() as session:
        print("🔍 Testing Debug Endpoint")
        print("=" * 50)
        
        # Test the debug endpoint
        form_data = aiohttp.FormData()
        form_data.add_field("query", "immune system COVID-19")
        form_data.add_field("max_results", "2")
        
        try:
            async with session.post(f"{base_url}/debug-search", data=form_data) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    print("📊 Debug Information:")
                    print(json.dumps(data, indent=2))
                        
                else:
                    print(f"❌ Error: HTTP {response.status}")
                    error_text = await response.text()
                    print(f"Error: {error_text}")
                    
        except Exception as e:
            print(f"❌ Exception: {e}")


if __name__ == "__main__":
    asyncio.run(test_debug_endpoint())
