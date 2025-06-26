#!/usr/bin/env python
"""
OmicsOracle Progress Events Test Client

This script tests the progress events implementation by:
1. Connecting to the WebSocket endpoint
2. Sending a search query
3. Listening for real-time progress updates
4. Auto-exiting when the search is complete

The script will automatically exit when:
- It receives a progress event with stage "complete"
- The WebSocket connection is closed
- The maximum wait time is reached (3 minutes by default)
"""

import asyncio
import json
import time
from datetime import datetime
from urllib.parse import urljoin

import requests
import websockets

# Configuration
BASE_URL = "http://localhost:8001"
WS_URL = "ws://localhost:8001/ws/monitor"
SEARCH_ENDPOINT = "/api/search"
MAX_WAIT_TIME = 180  # 3 minutes max wait time before auto-exit


async def connect_websocket(exit_event):
    """
    Connect to the WebSocket endpoint and listen for messages.

    Args:
        exit_event: An asyncio Event that will be set when a "complete" progress event is received
    """
    try:
        async with websockets.connect(WS_URL) as websocket:
            print(f"Connected to WebSocket at {WS_URL}")

            # Listen for messages
            while True:
                try:
                    message = await websocket.recv()

                    # Try to parse as JSON if possible
                    try:
                        data = json.loads(message)
                        if (
                            isinstance(data, dict)
                            and data.get("type") == "progress"
                        ):
                            # Format progress event nicely
                            timestamp = datetime.fromtimestamp(
                                data.get("timestamp", time.time())
                            ).strftime("%H:%M:%S")
                            percentage = f"{data.get('percentage', 0):.1f}%"
                            stage = data.get("stage", "unknown")
                            msg = data.get("message", "")

                            print(
                                f"[{timestamp}] [{percentage.rjust(6)}] {stage}: {msg}"
                            )

                            # Auto-exit when complete stage is received
                            if stage == "complete":
                                print(
                                    "\n✅ Search completed successfully! Exiting..."
                                )
                                exit_event.set()
                                return
                        else:
                            # Regular message
                            print(f"Received: {message[:100]}...")
                    except json.JSONDecodeError:
                        # Handle non-JSON messages (like HTML)
                        if len(message) > 100:
                            print(
                                f"Received non-JSON message: {message[:100]}..."
                            )
                        else:
                            print(f"Received: {message}")

                except websockets.exceptions.ConnectionClosed:
                    print("WebSocket connection closed")
                    exit_event.set()
                    break

    except Exception as e:
        print(f"WebSocket error: {e}")
        exit_event.set()


async def send_search_query(
    query="dna methylation immune cells", max_results=10
):
    """Send a search query to the API."""
    url = urljoin(BASE_URL, SEARCH_ENDPOINT)

    data = {
        "query": query,
        "max_results": max_results,
        "search_type": "comprehensive",
    }

    print(f"Sending search query: '{query}'")
    try:
        response = requests.post(url, json=data)

        if response.status_code == 200:
            result = response.json()
            print(
                f"Search successful - found {result.get('total_found', 0)} results"
            )
            return result
        else:
            print(
                f"Search failed with status {response.status_code}: {response.text}"
            )
            return None

    except Exception as e:
        print(f"Error sending search query: {e}")
        return None


async def main():
    """Run the main test."""
    print("Starting OmicsOracle Progress Events Test Client")

    # Create an event that will be set when we should exit
    exit_event = asyncio.Event()

    # Start WebSocket listener in the background
    websocket_task = asyncio.create_task(connect_websocket(exit_event))

    # Wait a moment for WebSocket to connect
    await asyncio.sleep(1)

    # Send a search query
    result = await send_search_query()

    if not result:
        print("Search query failed, exiting...")
        return

    # Listen for progress events with timeout
    try:
        print(
            "\nListening for progress events (will auto-exit on completion)..."
        )
        # Wait for the exit event or timeout
        try:
            await asyncio.wait_for(exit_event.wait(), timeout=MAX_WAIT_TIME)
        except asyncio.TimeoutError:
            print(
                f"\n⚠️ Maximum wait time ({MAX_WAIT_TIME} seconds) exceeded. Exiting..."
            )
    except KeyboardInterrupt:
        print("\nTest client stopped by user")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Clean up the websocket task if it's still running
        if not websocket_task.done():
            websocket_task.cancel()
            try:
                await websocket_task
            except asyncio.CancelledError:
                pass


if __name__ == "__main__":
    asyncio.run(main())
