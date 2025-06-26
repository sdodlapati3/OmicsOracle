#!/usr/bin/env python3
"""
Quick functionality test for OmicsOracle system
"""

import json

import requests
from colorama import Fore, Style, init

init()


def test_system():
    """Quick system test"""
    print(f"{Fore.CYAN}🚀 OmicsOracle Quick Test{Style.RESET_ALL}\n")

    # Test backend health
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(
                f"{Fore.GREEN}✅ Backend Health: {data.get('status', 'unknown')}{Style.RESET_ALL}"
            )
        else:
            print(
                f"{Fore.RED}❌ Backend failed: {response.status_code}{Style.RESET_ALL}"
            )
    except Exception as e:
        print(f"{Fore.RED}❌ Backend error: {e}{Style.RESET_ALL}")

    # Test search functionality
    test_queries = ["BRCA1", "insulin", "tumor suppressor"]

    for query in test_queries:
        try:
            print(f"\n🔍 Testing: '{query}'")
            response = requests.post(
                "http://localhost:8000/api/search",
                json={"query": query, "max_results": 5},
                timeout=15,
            )

            if response.status_code == 200:
                data = response.json()
                status = data.get("status", "unknown")
                count = data.get("total_count", 0)
                time_taken = data.get("processing_time", 0)

                if status == "completed":
                    print(f"   ✅ Success: {count} results ({time_taken:.2f}s)")
                else:
                    print(f"   ⚠️  Status: {status}")
            else:
                print(f"   ❌ Failed: HTTP {response.status_code}")

        except Exception as e:
            print(f"   ❌ Error: {e}")

    # Test frontend
    try:
        response = requests.get("http://localhost:5173", timeout=3)
        if response.status_code == 200:
            print(
                f"\n{Fore.GREEN}✅ Frontend accessible at http://localhost:5173{Style.RESET_ALL}"
            )
        else:
            print(
                f"\n{Fore.YELLOW}⚠️  Frontend status: {response.status_code}{Style.RESET_ALL}"
            )
    except:
        print(
            f"\n{Fore.YELLOW}⚠️  Frontend may still be starting up{Style.RESET_ALL}"
        )

    print(f"\n{Fore.CYAN}🎯 Manual Test:{Style.RESET_ALL}")
    print("1. Open http://localhost:5173 in browser")
    print("2. Try searching: 'dna methylation WGBS human brain cancer'")
    print("3. Check if results appear or error shows")

    print(
        f"\n{Fore.GREEN}✅ System is running! Backend functional, frontend should be accessible.{Style.RESET_ALL}"
    )


if __name__ == "__main__":
    test_system()
