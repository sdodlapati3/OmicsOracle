#!/usr/bin/env python
"""
WebSocket Progress Monitor for OmicsOracle.

This script adds middleware to the FastAPI app to log all WebSocket messages,
particularly focusing on progress events.
"""

import json
import logging
import sys
import time
from typing import Any, Dict, List, Union

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("websocket_messages.log"),
    ],
)
logger = logging.getLogger("websocket_monitor")

# Store all progress messages
progress_messages: List[Dict[str, Any]] = []


def log_websocket_message(message: Union[Dict[str, Any], str]):
    """Log a WebSocket message and store progress events."""
    try:
        # Handle string messages (HTML formatted)
        if isinstance(message, str):
            # Try to parse as JSON if it starts with {
            if message.strip().startswith("{"):
                try:
                    json_message = json.loads(message)
                    return log_websocket_message(json_message)  # Recursively process as JSON
                except json.JSONDecodeError:
                    pass
            logger.debug(f"Text WebSocket message: {message[:200]}...")
            return

        # Handle dictionary messages (JSON formatted)
        message_str = json.dumps(message, indent=2)

        # Check if it's a progress event
        if message.get("type") == "progress":
            logger.info(
                f"Progress Event: {message.get('stage')} - {message.get('message')} ({message.get('percentage')}%)"
            )
            # Add timestamp to the message
            message["timestamp"] = time.time()
            progress_messages.append(message)
        # Check if it's a search result
        elif message.get("type") == "search_result":
            result_count = len(message.get("datasets", []))
            logger.info(f"Search Result: Found {result_count} datasets for query '{message.get('query')}'")
        # Check if it's an error
        elif message.get("type") == "error":
            logger.error(f"Error Event: {message.get('message')}")
        else:
            # For other message types, just log a summary
            msg_type = message.get("type", "unknown")
            logger.debug(f"WebSocket message type: {msg_type} - {message_str[:100]}...")

        # Write all progress messages to a file periodically
        if len(progress_messages) % 5 == 0:
            with open("progress_events_websocket.json", "w") as f:
                json.dump(progress_messages, f, indent=2)

    except Exception as e:
        logger.error(f"Error logging WebSocket message: {str(e)}")
        # Add exception details for better debugging
        import traceback

        logger.error(f"Exception details: {traceback.format_exc()}")


def setup_websocket_monitoring(app):
    """
    Set up WebSocket monitoring for a FastAPI app.

    This function adds middleware to intercept and log WebSocket messages.
    """
    # Original broadcast methods
    original_broadcast = None
    original_broadcast_progress = None

    # Find the connection manager
    if hasattr(app, "state") and hasattr(app.state, "connection_manager"):
        connection_manager = app.state.connection_manager

        # Save the original broadcast method
        if hasattr(connection_manager, "broadcast"):
            original_broadcast = connection_manager.broadcast

            # Override the broadcast method to log messages
            async def broadcast_with_logging(message):
                try:
                    log_websocket_message(message)
                except Exception as e:
                    logger.error(f"Error in broadcast_with_logging: {e}")
                return await original_broadcast(message)

            # Replace the broadcast method
            connection_manager.broadcast = broadcast_with_logging

        # Save the original broadcast_progress method
        if hasattr(connection_manager, "broadcast_progress"):
            original_broadcast_progress = connection_manager.broadcast_progress

            # Override the broadcast_progress method to log messages
            async def broadcast_progress_with_logging(query_id, stage, message, percentage, detail=None):
                try:
                    progress_data = {
                        "type": "progress",
                        "query_id": query_id,
                        "stage": stage,
                        "message": message,
                        "percentage": percentage,
                        "detail": detail or {},
                    }
                    log_websocket_message(progress_data)
                except Exception as e:
                    logger.error(f"Error in broadcast_progress_with_logging: {e}")

                return await original_broadcast_progress(query_id, stage, message, percentage, detail)

            # Replace the broadcast_progress method
            connection_manager.broadcast_progress = broadcast_progress_with_logging

        logger.info("WebSocket monitoring successfully set up")
        return True

    logger.warning("Could not set up WebSocket monitoring - connection manager not found")
    return False


# Add this to interfaces/futuristic/main.py after initializing the app
# Example usage:
# Set up WebSocket monitoring
# try:
#     from websocket_monitor import setup_websocket_monitoring
#     setup_websocket_monitoring(app)
#     logger.info("WebSocket monitoring enabled")
# except ImportError:
#     logger.warning("WebSocket monitoring module not found")

if __name__ == "__main__":
    logger.info("This module is intended to be imported, not run directly.")
