"""
Cost Management Service for OmicsOracle

This module tracks API usage, costs, and implements usage limits.
"""

import json
import logging
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class UsageRecord:
    """Record of API usage."""

    timestamp: str
    service: str  # 'openai', 'geo', etc.
    endpoint: str
    tokens_used: int
    cost_usd: float
    query: str
    response_size: int
    user_id: str = "anonymous"
    session_id: str = None


@dataclass
class UsageStats:
    """Usage statistics."""

    total_requests: int
    total_tokens: int
    total_cost_usd: float
    daily_requests: int
    daily_tokens: int
    daily_cost_usd: float
    current_month_cost_usd: float
    average_tokens_per_request: float


class CostManager:
    """Manages API costs and usage tracking."""

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize cost manager."""
        if db_path is None:
            db_path = Path("data/cache/usage_tracking.db")

        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._lock = Lock()

        # Cost rates (per 1K tokens)
        self.cost_rates = {
            "gpt-4": {"input": 0.03, "output": 0.06},
            "gpt-4-turbo": {"input": 0.01, "output": 0.03},
            "gpt-3.5-turbo": {"input": 0.001, "output": 0.002},
        }

        # Default limits
        self.daily_limits = {
            "tokens": 100000,  # 100K tokens per day
            "cost_usd": 50.0,  # $50 per day
            "requests": 1000,  # 1000 requests per day
        }

        self.monthly_limits = {
            "cost_usd": 1000.0,  # $1000 per month
            "tokens": 2000000,  # 2M tokens per month
        }

        self._init_database()
        logger.info(f"Cost manager initialized: {self.db_path}")

    def _init_database(self):
        """Initialize the usage tracking database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS usage_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    service TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    tokens_used INTEGER NOT NULL,
                    cost_usd REAL NOT NULL,
                    query TEXT,
                    response_size INTEGER,
                    user_id TEXT DEFAULT 'anonymous',
                    session_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_timestamp
                ON usage_records(timestamp)
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_service
                ON usage_records(service)
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_user_id
                ON usage_records(user_id)
            """
            )

    def record_usage(
        self,
        service: str,
        endpoint: str,
        tokens_used: int,
        model: str = "gpt-4",
        query: str = "",
        response_size: int = 0,
        user_id: str = "anonymous",
        session_id: str = None,
    ) -> float:
        """
        Record API usage and return the cost.

        Args:
            service: Service name (e.g., 'openai')
            endpoint: API endpoint
            tokens_used: Number of tokens consumed
            model: Model used (for cost calculation)
            query: Original query
            response_size: Size of response
            user_id: User identifier
            session_id: Session identifier

        Returns:
            Cost in USD
        """
        # Calculate cost
        cost_usd = self._calculate_cost(tokens_used, model)

        # Create usage record
        record = UsageRecord(
            timestamp=datetime.now().isoformat(),
            service=service,
            endpoint=endpoint,
            tokens_used=tokens_used,
            cost_usd=cost_usd,
            query=query[:500],  # Truncate long queries
            response_size=response_size,
            user_id=user_id,
            session_id=session_id,
        )

        # Store in database
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO usage_records
                    (timestamp, service, endpoint, tokens_used, cost_usd,
                     query, response_size, user_id, session_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        record.timestamp,
                        record.service,
                        record.endpoint,
                        record.tokens_used,
                        record.cost_usd,
                        record.query,
                        record.response_size,
                        record.user_id,
                        record.session_id,
                    ),
                )

        logger.info(
            f"Usage recorded: {service} - {tokens_used} tokens - ${cost_usd:.4f}"
        )
        return cost_usd

    def _calculate_cost(self, tokens_used: int, model: str) -> float:
        """Calculate cost based on tokens and model."""
        # Simplified cost calculation (assumes average of input/output rates)
        if model in self.cost_rates:
            rate = (
                self.cost_rates[model]["input"]
                + self.cost_rates[model]["output"]
            ) / 2
        else:
            # Default to GPT-4 rates
            rate = (
                self.cost_rates["gpt-4"]["input"]
                + self.cost_rates["gpt-4"]["output"]
            ) / 2

        return (tokens_used / 1000) * rate

    def get_usage_stats(
        self, user_id: str = None, days: int = 30
    ) -> UsageStats:
        """Get usage statistics."""
        now = datetime.now()
        start_date = now - timedelta(days=days)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        month_start = now.replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )

        with sqlite3.connect(self.db_path) as conn:
            # Total stats
            query = """
                SELECT COUNT(*), COALESCE(SUM(tokens_used), 0), COALESCE(SUM(cost_usd), 0)
                FROM usage_records
                WHERE timestamp >= ?
            """
            params = [start_date.isoformat()]

            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)

            cursor = conn.execute(query, params)
            total_requests, total_tokens, total_cost = cursor.fetchone()

            # Daily stats
            query = """
                SELECT COUNT(*), COALESCE(SUM(tokens_used), 0), COALESCE(SUM(cost_usd), 0)
                FROM usage_records
                WHERE timestamp >= ?
            """
            params = [today_start.isoformat()]

            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)

            cursor = conn.execute(query, params)
            daily_requests, daily_tokens, daily_cost = cursor.fetchone()

            # Monthly cost
            query = """
                SELECT COALESCE(SUM(cost_usd), 0)
                FROM usage_records
                WHERE timestamp >= ?
            """
            params = [month_start.isoformat()]

            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)

            cursor = conn.execute(query, params)
            monthly_cost = cursor.fetchone()[0]

        # Calculate averages
        avg_tokens = total_tokens / max(total_requests, 1)

        return UsageStats(
            total_requests=total_requests or 0,
            total_tokens=total_tokens or 0,
            total_cost_usd=total_cost or 0.0,
            daily_requests=daily_requests or 0,
            daily_tokens=daily_tokens or 0,
            daily_cost_usd=daily_cost or 0.0,
            current_month_cost_usd=monthly_cost or 0.0,
            average_tokens_per_request=avg_tokens,
        )

    def check_limits(self, user_id: str = "anonymous") -> Dict[str, Any]:
        """Check if user is within usage limits."""
        stats = self.get_usage_stats(user_id=user_id, days=1)

        # Check daily limits
        daily_violations = []
        if stats.daily_tokens > self.daily_limits["tokens"]:
            daily_violations.append(
                f"Daily token limit exceeded: {stats.daily_tokens}/{self.daily_limits['tokens']}"
            )

        if stats.daily_cost_usd > self.daily_limits["cost_usd"]:
            daily_violations.append(
                f"Daily cost limit exceeded: ${stats.daily_cost_usd:.2f}/${self.daily_limits['cost_usd']}"
            )

        if stats.daily_requests > self.daily_limits["requests"]:
            daily_violations.append(
                f"Daily request limit exceeded: {stats.daily_requests}/{self.daily_limits['requests']}"
            )

        # Check monthly limits
        monthly_violations = []
        if stats.current_month_cost_usd > self.monthly_limits["cost_usd"]:
            monthly_violations.append(
                f"Monthly cost limit exceeded: ${stats.current_month_cost_usd:.2f}/${self.monthly_limits['cost_usd']}"
            )

        return {
            "within_limits": len(daily_violations) == 0
            and len(monthly_violations) == 0,
            "daily_violations": daily_violations,
            "monthly_violations": monthly_violations,
            "daily_usage": {
                "tokens": f"{stats.daily_tokens}/{self.daily_limits['tokens']}",
                "cost": f"${stats.daily_cost_usd:.2f}/${self.daily_limits['cost_usd']}",
                "requests": f"{stats.daily_requests}/{self.daily_limits['requests']}",
            },
            "monthly_usage": {
                "cost": f"${stats.current_month_cost_usd:.2f}/${self.monthly_limits['cost_usd']}"
            },
        }

    def get_usage_history(
        self, user_id: str = None, days: int = 7, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get usage history."""
        start_date = datetime.now() - timedelta(days=days)

        query = """
            SELECT timestamp, service, endpoint, tokens_used, cost_usd,
                   query, response_size, user_id
            FROM usage_records
            WHERE timestamp >= ?
        """
        params = [start_date.isoformat()]

        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(query, params)

            records = []
            for row in cursor.fetchall():
                records.append(
                    {
                        "timestamp": row[0],
                        "service": row[1],
                        "endpoint": row[2],
                        "tokens_used": row[3],
                        "cost_usd": row[4],
                        "query": row[5],
                        "response_size": row[6],
                        "user_id": row[7],
                    }
                )

        return records

    def cleanup_old_records(self, days_to_keep: int = 90):
        """Clean up old usage records."""
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM usage_records WHERE timestamp < ?",
                [cutoff_date.isoformat()],
            )
            deleted_count = cursor.rowcount

        logger.info(f"Cleaned up {deleted_count} old usage records")
        return deleted_count

    def export_usage_data(
        self, output_path: Path, user_id: str = None, days: int = 30
    ):
        """Export usage data to JSON file."""
        history = self.get_usage_history(
            user_id=user_id, days=days, limit=10000
        )
        stats = self.get_usage_stats(user_id=user_id, days=days)

        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "period_days": days,
            "statistics": asdict(stats),
            "usage_history": history,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

        logger.info(f"Usage data exported to: {output_path}")
        return output_path


# Global cost manager instance
cost_manager = CostManager()
