#!/usr/bin/env python
"""
WebSocket Progress Monitor for OmicsOracle

This script adds middleware to the FastAPI app to log all WebSocket messages,
particularly focusing on progress events.
"""

import logging
import os
import sys
import json
from typing import Dict, Any, List

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("websocket_messages.log")
    ]
)
logger = logging.getLogger("websocket_monitor")

# Store all progress messages
progress_messages: List[Dict[str, Any]] = []

def log_websocket_message(message: Dict[str, Any]):
    """Log a WebSocket message and store progress events."""
    try:
        # Format the message for logging
        message_str = json.dumps(message, indent=2)
        
        # Check if it's a progress event
        if message.get("type") == "progress":
            logger.info(f"Progress Event: {message.get('stage')} - {message.get('message')} ({message.get('percentage')}%)")
            progress_messages.append(message)
        else:
            logger.debug(f"WebSocket message: {message_str[:200]}...")
        
        # Write all progress messages to a file periodically
        if len(progress_messages) % 5 == 0:
            with open("progress_events_websocket.json", "w") as f:
                json.dump(progress_messages, f, indent=2)
    
    except Exception as e:
        logger.error(f"Error logging WebSocket message: {str(e)}")


def setup_websocket_monitoring(app):
    """
    Set up WebSocket monitoring for a FastAPI app.
    
    This function adds middleware to intercept and log WebSocket messages.
    """
    # Original broadcast method
    original_broadcast = None
    
    # Find the connection manager
    if hasattr(app, "state") and hasattr(app.state, "connection_manager"):
        connection_manager = app.state.connection_manager
        
        # Save the original broadcast method
        if hasattr(connection_manager, "broadcast"):
            original_broadcast = connection_manager.broadcast
            
            # Override the broadcast method to log messages
            async def broadcast_with_logging(message):
                log_websocket_message(message)
                return await original_broadcast(message)
            
            # Replace the broadcast method
            connection_manager.broadcast = broadcast_with_logging
            
            logger.info("WebSocket monitoring successfully set up")
            return True
    
    logger.warning("Could not set up WebSocket monitoring - connection manager not found")
    return False


# Add this to interfaces/futuristic/main.py after initializing the app
"""
# Set up WebSocket monitoring
try:
    from websocket_monitor import setup_websocket_monitoring
    setup_websocket_monitoring(app)
    logger.info("WebSocket monitoring enabled")
except ImportError:
    logger.warning("WebSocket monitoring module not found")
"""

if __name__ == "__main__":
    logger.info("This module is intended to be imported, not run directly.")
