"""
Enhanced Search Agent for Futuristic Interface

Handles intelligent search operations with fallback to legacy system
and improved error handling, caching, and real-time updates
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from pydantic import BaseModel

from .base import AgentCapability, AgentMessage, AgentType, BaseAgent

logger = logging.getLogger(__name__)


class SearchResult(BaseModel):
    """Search result model"""

    id: str
    title: str
    description: str
    relevance_score: float
    source: str
    url: Optional[str] = None
    metadata: Dict = {}
    timestamp: str
    search_type: str = "basic"


class SearchCache:
    """Simple in-memory cache for search results"""

    def __init__(self, ttl_minutes: int = 30):
        self.cache = {}
        self.ttl = timedelta(minutes=ttl_minutes)

    def get(self, query_hash: str) -> Optional[Dict]:
        """Get cached result if still valid"""
        if query_hash in self.cache:
            result, timestamp = self.cache[query_hash]
            if datetime.utcnow() - timestamp < self.ttl:
                return result
            else:
                del self.cache[query_hash]
        return None

    def set(self, query_hash: str, result: Dict):
        """Cache search result"""
        self.cache[query_hash] = (result, datetime.utcnow())


class EnhancedSearchAgent(BaseAgent):
    """Enhanced intelligent search agent with caching and real-time updates"""

    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentType.SEARCH)
        self.capabilities = [
            AgentCapability.TEXT_SEARCH,
            AgentCapability.SEMANTIC_SEARCH,
            AgentCapability.INTELLIGENT_SEARCH,
            AgentCapability.ENTITY_EXTRACTION,
        ]
        self.legacy_pipeline = None
        self.search_cache = SearchCache()
        self.search_history = []
        self.update_callbacks = []

    async def initialize(self) -> bool:
        """Initialize the enhanced search agent"""
        try:
            logger.info(
                f"[SEARCH] Initializing enhanced search agent {self.agent_id}"
            )

            # Try to import legacy pipeline as fallback
            try:
                import sys
                from pathlib import Path

                sys.path.insert(
                    0, str(Path(__file__).parent.parent.parent.parent)
                )

                from src.omics_oracle.core.config import Config
                from src.omics_oracle.pipeline import OmicsOracle

                config = Config()
                self.legacy_pipeline = OmicsOracle(config)
                logger.info("[OK] Legacy pipeline initialized as fallback")

            except Exception as e:
                logger.warning(
                    f"[WARNING] Could not initialize legacy pipeline: {e}"
                )
                logger.info("[REFRESH] Running in enhanced-only mode")

            logger.info(
                f"[OK] Enhanced search agent {self.agent_id} initialized"
            )
            return True

        except Exception as e:
            logger.error(
                f"[ERROR] Failed to initialize enhanced search agent {self.agent_id}: {e}"
            )
            return False

    async def cleanup(self) -> None:
        """Clean up search agent resources"""
        logger.info(
            f"[CLEANUP] Cleaning up enhanced search agent {self.agent_id}"
        )
        if self.legacy_pipeline:
            try:
                # Cleanup legacy pipeline if available
                if hasattr(self.legacy_pipeline, "close"):
                    await self.legacy_pipeline.close()
            except Exception as e:
                logger.warning(f"Error cleaning up legacy pipeline: {e}")

    def add_update_callback(self, callback):
        """Add callback for real-time updates"""
        self.update_callbacks.append(callback)

    async def _send_update(self, message: str):
        """Send real-time update to all callbacks"""
        for callback in self.update_callbacks:
            try:
                await callback(f"Search Agent: {message}")
            except Exception as e:
                logger.error(f"Error sending update: {e}")

    async def process_message(
        self, message: AgentMessage
    ) -> Optional[AgentMessage]:
        """Process search-related messages with enhanced error handling"""
        try:
            if message.type == "search_request":
                return await self._handle_search_request(message)
            elif message.type == "health_check":
                return await self._handle_health_check(message)
            elif message.type == "clear_cache":
                return await self._handle_clear_cache(message)
            else:
                logger.warning(f"Unknown message type: {message.type}")
                return None

        except Exception as e:
            logger.error(f"Enhanced search agent error processing message: {e}")
            return AgentMessage(
                type="error",
                sender=self.agent_id,
                recipient=message.sender,
                payload={"error": str(e), "original_message": message.type},
                timestamp=datetime.utcnow(),
            )

    async def _handle_search_request(
        self, message: AgentMessage
    ) -> AgentMessage:
        """Handle search request with intelligent caching and fallback"""
        query = message.payload.get("query", "")
        search_type = message.payload.get("search_type", "basic")
        filters = message.payload.get("filters", {})

        if not query.strip():
            return AgentMessage(
                type="search_response",
                sender=self.agent_id,
                recipient=message.sender,
                payload={"results": [], "error": "Empty query"},
                timestamp=datetime.utcnow(),
            )

        self.current_job = message.payload.get(
            "job_id", f"search_{len(self.search_history)}"
        )
        start_time = datetime.utcnow()

        await self._send_update(
            f"Starting {search_type} search for: {query[:50]}..."
        )

        try:
            # Check cache first
            query_hash = hash(
                f"{query}_{search_type}_{json.dumps(filters, sort_keys=True)}"
            )
            cached_result = self.search_cache.get(str(query_hash))

            if cached_result:
                logger.info(
                    f"[CLIPBOARD] Returning cached result for query: {query[:50]}..."
                )
                await self._send_update("Retrieved from cache")
                return AgentMessage(
                    type="search_response",
                    sender=self.agent_id,
                    recipient=message.sender,
                    payload=cached_result,
                    timestamp=datetime.utcnow(),
                )

            # Perform search based on type
            if search_type == "intelligent":
                results = await self._intelligent_search(query, filters)
            elif search_type == "semantic":
                results = await self._semantic_search(query, filters)
            else:
                results = await self._basic_search(query, filters)

            # Calculate processing time and prepare response
            processing_time = (datetime.utcnow() - start_time).total_seconds()

            response_payload = {
                "results": [result.dict() for result in results],
                "query": query,
                "search_type": search_type,
                "processing_time": processing_time,
                "results_count": len(results),
                "timestamp": datetime.utcnow().isoformat(),
            }

            # Cache the result
            self.search_cache.set(str(query_hash), response_payload)

            # Store in history
            self.search_history.append(
                {
                    "query": query,
                    "search_type": search_type,
                    "results_count": len(results),
                    "processing_time": processing_time,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

            await self._send_update(
                f"Found {len(results)} results in {processing_time:.2f}s"
            )

            self.current_job = None

            return AgentMessage(
                type="search_response",
                sender=self.agent_id,
                recipient=message.sender,
                payload=response_payload,
                timestamp=datetime.utcnow(),
            )

        except Exception as e:
            logger.error(f"Search error: {e}")
            await self._send_update(f"Search failed: {str(e)}")

            return AgentMessage(
                type="search_error",
                sender=self.agent_id,
                recipient=message.sender,
                payload={
                    "error": str(e),
                    "query": query,
                    "search_type": search_type,
                },
                timestamp=datetime.utcnow(),
            )
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            self.processing_times.append(processing_time)
            self.jobs_completed += 1
            self.last_activity = datetime.utcnow()

            return AgentMessage(
                type="search_response",
                sender_id=self.agent_id,
                target_id=message.sender_id,
                payload={
                    "job_id": self.current_job,
                    "results": [r.dict() for r in results],
                    "total_count": len(results),
                    "processing_time": processing_time,
                    "search_type": search_type,
                },
            )

        except Exception as e:
            logger.error(f"[ERROR] Search request failed: {e}")
            return await self._fallback_search(message)

    async def _intelligent_search(
        self, query: str, filters: Dict
    ) -> List[SearchResult]:
        """Advanced AI-powered search (future implementation)"""
        # For now, enhance basic search with intelligence
        return await self._enhanced_legacy_search(query, filters, "intelligent")

    async def _semantic_search(
        self, query: str, filters: Dict
    ) -> List[SearchResult]:
        """Semantic search with vector embeddings (future implementation)"""
        # For now, fall back to legacy with enhanced processing
        return await self._enhanced_legacy_search(query, filters, "semantic")

    async def _basic_search(
        self, query: str, filters: Dict
    ) -> List[SearchResult]:
        """Basic text search with legacy system"""
        return await self._enhanced_legacy_search(query, filters, "basic")

    async def _enhanced_legacy_search(
        self, query: str, filters: Dict, search_type: str
    ) -> List[SearchResult]:
        """Use legacy search with futuristic enhancements"""
        if not self.legacy_pipeline:
            raise Exception("Legacy pipeline not available")

        try:
            # Use legacy pipeline's process_query method
            result = await self.legacy_pipeline.process_query(query)

            # Convert to futuristic format with enhancements
            enhanced_results = []
            if result and result.metadata:
                for i, item in enumerate(result.metadata[:50]):  # Limit results
                    enhanced_result = SearchResult(
                        id=item.get("accession", f"result_{i}"),
                        title=item.get("title", "Unknown Title"),
                        abstract=item.get("summary", ""),
                        authors=item.get("authors", []),
                        publication_date=self._parse_date(
                            item.get("submission_date")
                        ),
                        source=item.get("source", "GEO"),
                        confidence_score=self._calculate_confidence(
                            item, search_type
                        ),
                        tags=self._generate_tags(item),
                        metadata=item,
                    )
                    enhanced_results.append(enhanced_result)

            return enhanced_results

        except Exception as e:
            logger.error(f"[ERROR] Legacy search failed: {e}")
            return []

    async def _fallback_search(self, message: AgentMessage) -> AgentMessage:
        """Fallback to basic legacy search"""
        query = message.payload.get("query", "")

        try:
            if self.legacy_pipeline:
                result = await self.legacy_pipeline.process_query(query)

                # Convert to basic format
                results = []
                if result and result.metadata:
                    for i, item in enumerate(result.metadata[:20]):
                        basic_result = SearchResult(
                            id=item.get("accession", f"legacy_{i}"),
                            title=item.get("title", "Unknown"),
                            abstract=item.get("summary", ""),
                            authors=item.get("authors", []),
                            source="Legacy System",
                            confidence_score=0.8,  # Default confidence for legacy
                            tags=["legacy"],
                            metadata=item,
                        )
                        results.append(basic_result)

                return AgentMessage(
                    type="search_response",
                    sender_id=self.agent_id,
                    target_id=message.sender_id,
                    payload={
                        "job_id": message.payload.get("job_id"),
                        "results": [r.dict() for r in results],
                        "total_count": len(results),
                        "search_mode": "legacy_fallback",
                    },
                )
            else:
                raise Exception("No search methods available")

        except Exception as e:
            logger.error(f"[ERROR] Fallback search failed: {e}")
            return AgentMessage(
                type="error",
                sender_id=self.agent_id,
                target_id=message.sender_id,
                payload={
                    "error": "Search failed",
                    "message": str(e),
                    "job_id": message.payload.get("job_id"),
                },
            )

    async def _handle_clear_cache(self, message: AgentMessage) -> AgentMessage:
        """Handle cache clearing request"""
        try:
            cache_size = len(self.search_cache.cache)
            self.search_cache.cache.clear()

            return AgentMessage(
                type="cache_cleared",
                sender=self.agent_id,
                recipient=message.sender,
                payload={
                    "cleared_entries": cache_size,
                    "message": "Search cache cleared successfully",
                },
                timestamp=datetime.utcnow(),
            )
        except Exception as e:
            return AgentMessage(
                type="error",
                sender=self.agent_id,
                recipient=message.sender,
                payload={"error": f"Failed to clear cache: {str(e)}"},
                timestamp=datetime.utcnow(),
            )

    async def _handle_health_check(self, message: AgentMessage) -> AgentMessage:
        """Handle health check request"""
        return AgentMessage(
            type="health_response",
            sender=self.agent_id,
            recipient=message.sender,
            payload={
                "status": "healthy",
                "cache_size": len(self.search_cache.cache),
                "search_history_count": len(self.search_history),
                "capabilities": self.capabilities,
                "legacy_available": self.legacy_pipeline is not None,
            },
            timestamp=datetime.utcnow(),
        )

    def _parse_date(self, date_str: Optional[str]) -> Optional[str]:
        """Parse and format date string"""
        if not date_str:
            return None
        try:
            # Simple date formatting - enhance as needed
            return str(date_str)
        except Exception:
            return None

    def _calculate_confidence(self, item: Dict, search_type: str) -> float:
        """Calculate confidence score based on search type and item data"""
        base_score = 0.7

        # Boost for different search types
        if search_type == "intelligent":
            base_score += 0.2
        elif search_type == "semantic":
            base_score += 0.1

        # Boost for data quality
        if item.get("title"):
            base_score += 0.05
        if item.get("summary"):
            base_score += 0.05

        return min(base_score, 1.0)

    def _generate_tags(self, item: Dict) -> List[str]:
        """Generate tags based on item metadata"""
        tags = []

        if item.get("organism"):
            tags.append(f"organism:{item['organism']}")

        if item.get("platform"):
            tags.append(f"platform:{item['platform']}")

        if item.get("study_type"):
            tags.append(f"type:{item['study_type']}")

        return tags
