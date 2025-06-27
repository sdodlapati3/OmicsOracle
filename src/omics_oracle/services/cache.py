"""
Caching service for OmicsOracle AI summaries.

This module provides intelligent caching for AI-generated summaries to:
- Reduce OpenAI API costs
- Improve response times
- Enable offline operation for cached results
"""

import hashlib
import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Represents a cached AI summary entry."""

    query_hash: str
    query_text: str
    summary_type: str
    summary_data: Dict[str, Any]
    created_at: datetime
    expires_at: datetime
    token_count: int

    def is_expired(self) -> bool:
        """Check if the cache entry has expired."""
        return datetime.utcnow() > self.expires_at


class SummaryCache:
    """
    SQLite-based cache for AI summaries with intelligent expiration.
    """

    def __init__(
        self, cache_dir: Optional[Path] = None, ttl_hours: int = 168
    ):  # 1 week default
        """
        Initialize the summary cache.

        Args:
            cache_dir: Directory for cache database (defaults to data/cache)
            ttl_hours: Time to live for cache entries in hours
        """
        self.ttl_hours = ttl_hours

        # Set up cache directory
        if cache_dir is None:
            cache_dir = (
                Path(__file__).parent.parent.parent.parent / "data" / "cache"
            )

        cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = cache_dir / "ai_summaries.db"

        # Initialize database
        self._init_database()

        logger.info(f"Summary cache initialized: {self.db_path}")

    def _init_database(self):
        """Initialize the SQLite database with required tables."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ai_summaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query_hash TEXT UNIQUE NOT NULL,
                    query_text TEXT NOT NULL,
                    summary_type TEXT NOT NULL,
                    summary_data TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    token_count INTEGER DEFAULT 0,
                    access_count INTEGER DEFAULT 0,
                    last_accessed TEXT
                )
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_query_hash
                ON ai_summaries(query_hash)
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_expires_at
                ON ai_summaries(expires_at)
            """
            )

            conn.commit()

    def _generate_cache_key(
        self, query: str, summary_type: str, max_results: int = 10
    ) -> str:
        """
        Generate a cache key for a query.

        Args:
            query: The search query
            summary_type: Type of summary (batch, individual, etc.)
            max_results: Maximum results requested

        Returns:
            SHA256 hash as cache key
        """
        cache_input = f"{query.lower().strip()}_{summary_type}_{max_results}"
        return hashlib.sha256(cache_input.encode("utf-8")).hexdigest()

    def get(
        self, query: str, summary_type: str, max_results: int = 10
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached AI summary if available and not expired.

        Args:
            query: The search query
            summary_type: Type of summary requested
            max_results: Maximum results requested

        Returns:
            Cached summary data or None if not found/expired
        """
        cache_key = self._generate_cache_key(query, summary_type, max_results)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT summary_data, expires_at, access_count
                FROM ai_summaries
                WHERE query_hash = ?
            """,
                (cache_key,),
            )

            result = cursor.fetchone()

            if not result:
                logger.debug(f"Cache miss for query: {query[:50]}...")
                return None

            summary_data, expires_at_str, access_count = result
            expires_at = datetime.fromisoformat(expires_at_str)

            # Check if expired
            if datetime.utcnow() > expires_at:
                logger.debug(f"Cache expired for query: {query[:50]}...")
                self._delete_expired_entry(cache_key)
                return None

            # Update access statistics
            conn.execute(
                """
                UPDATE ai_summaries
                SET access_count = ?, last_accessed = ?
                WHERE query_hash = ?
            """,
                (access_count + 1, datetime.utcnow().isoformat(), cache_key),
            )

            conn.commit()

            logger.info(
                f"Cache hit for query: {query[:50]}... (accessed {access_count + 1} times)"
            )
            return json.loads(summary_data)

    def set(
        self,
        query: str,
        summary_type: str,
        summary_data: Dict[str, Any],
        max_results: int = 10,
        token_count: int = 0,
    ):
        """
        Store AI summary in cache.

        Args:
            query: The search query
            summary_type: Type of summary
            summary_data: The summary data to cache
            max_results: Maximum results requested
            token_count: Number of tokens used for this summary
        """
        cache_key = self._generate_cache_key(query, summary_type, max_results)
        created_at = datetime.utcnow()
        expires_at = created_at + timedelta(hours=self.ttl_hours)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO ai_summaries
                (query_hash, query_text, summary_type, summary_data,
                 created_at, expires_at, token_count, access_count, last_accessed)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
            """,
                (
                    cache_key,
                    query,
                    summary_type,
                    json.dumps(summary_data),
                    created_at.isoformat(),
                    expires_at.isoformat(),
                    token_count,
                    created_at.isoformat(),
                ),
            )

            conn.commit()

        logger.info(
            f"Cached AI summary for query: {query[:50]}... (tokens: {token_count})"
        )

    def _delete_expired_entry(self, cache_key: str):
        """Delete an expired cache entry."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM ai_summaries WHERE query_hash = ?", (cache_key,)
            )
            conn.commit()

    def cleanup_expired(self) -> int:
        """
        Remove expired cache entries.

        Returns:
            Number of entries removed
        """
        current_time = datetime.utcnow().isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT COUNT(*) FROM ai_summaries WHERE expires_at < ?
            """,
                (current_time,),
            )

            expired_count = cursor.fetchone()[0]

            if expired_count > 0:
                conn.execute(
                    """
                    DELETE FROM ai_summaries WHERE expires_at < ?
                """,
                    (current_time,),
                )

                conn.commit()
                logger.info(f"Cleaned up {expired_count} expired cache entries")

            return expired_count

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        with sqlite3.connect(self.db_path) as conn:
            # Total entries
            cursor = conn.execute("SELECT COUNT(*) FROM ai_summaries")
            total_entries = cursor.fetchone()[0]

            # Expired entries
            current_time = datetime.utcnow().isoformat()
            cursor = conn.execute(
                """
                SELECT COUNT(*) FROM ai_summaries WHERE expires_at < ?
            """,
                (current_time,),
            )
            expired_entries = cursor.fetchone()[0]

            # Total tokens saved
            cursor = conn.execute(
                """
                SELECT SUM(token_count * access_count) FROM ai_summaries
            """
            )
            result = cursor.fetchone()[0]
            tokens_saved = result if result else 0

            # Most accessed queries
            cursor = conn.execute(
                """
                SELECT query_text, access_count, created_at
                FROM ai_summaries
                ORDER BY access_count DESC
                LIMIT 5
            """
            )
            popular_queries = [
                {
                    "query": row[0][:100] + "..."
                    if len(row[0]) > 100
                    else row[0],
                    "access_count": row[1],
                    "created_at": row[2],
                }
                for row in cursor.fetchall()
            ]

            return {
                "total_entries": total_entries,
                "active_entries": total_entries - expired_entries,
                "expired_entries": expired_entries,
                "tokens_saved": tokens_saved,
                "popular_queries": popular_queries,
                "cache_file": str(self.db_path),
            }

    def clear_all(self) -> int:
        """
        Clear all cache entries.

        Returns:
            Number of entries removed
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM ai_summaries")
            count = cursor.fetchone()[0]

            conn.execute("DELETE FROM ai_summaries")
            conn.commit()

            logger.info(f"Cleared all {count} cache entries")
            return count
