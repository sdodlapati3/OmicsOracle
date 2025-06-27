"""
Alert Management System

Provides comprehensive alerting capabilities:
- Rule-based alerting
- Threshold monitoring
- Alert aggregation and notification
- Integration with external systems
"""

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


@dataclass
class Alert:
    """Individual alert."""

    id: str
    title: str
    description: str
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.OPEN
    timestamp: float = field(default_factory=time.time)
    source: str = "unknown"
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def acknowledge(self) -> None:
        """Acknowledge the alert."""
        self.status = AlertStatus.ACKNOWLEDGED

    def resolve(self) -> None:
        """Resolve the alert."""
        self.status = AlertStatus.RESOLVED


class AlertRule(ABC):
    """Abstract base class for alert rules."""

    @abstractmethod
    def check(self, metrics: Dict[str, Any]) -> Optional[Alert]:
        """Check if alert condition is met."""
        pass


class ThresholdAlertRule(AlertRule):
    """Alert rule based on metric thresholds."""

    def __init__(
        self,
        metric_name: str,
        threshold: float,
        comparison: str = "greater_than",
        severity: AlertSeverity = AlertSeverity.WARNING,
        title: Optional[str] = None,
    ):
        self.metric_name = metric_name
        self.threshold = threshold
        self.comparison = comparison
        self.severity = severity
        self.title = title or f"{metric_name} threshold exceeded"

    def check(self, metrics: Dict[str, Any]) -> Optional[Alert]:
        """Check threshold condition."""
        if self.metric_name not in metrics:
            return None

        value = metrics[self.metric_name]

        if self.comparison == "greater_than" and value > self.threshold:
            triggered = True
        elif self.comparison == "less_than" and value < self.threshold:
            triggered = True
        elif self.comparison == "equals" and value == self.threshold:
            triggered = True
        else:
            triggered = False

        if triggered:
            return Alert(
                id=f"{self.metric_name}_{int(time.time())}",
                title=self.title,
                description=f"{self.metric_name} is {value} (threshold: {self.threshold})",
                severity=self.severity,
                source="threshold_rule",
                metadata={
                    "metric_name": self.metric_name,
                    "current_value": value,
                    "threshold": self.threshold,
                    "comparison": self.comparison,
                },
            )

        return None


class AlertManager:
    """Manager for handling alerts and notifications."""

    def __init__(self):
        self._alerts: Dict[str, Alert] = {}
        self._rules: List[AlertRule] = []
        self._handlers: List[Callable[[Alert], None]] = []

    def add_rule(self, rule: AlertRule) -> None:
        """Add alert rule."""
        self._rules.append(rule)

    def add_handler(self, handler: Callable[[Alert], None]) -> None:
        """Add alert handler."""
        self._handlers.append(handler)

    def check_alerts(self, metrics: Dict[str, Any]) -> List[Alert]:
        """Check all rules and generate alerts."""
        new_alerts = []

        for rule in self._rules:
            alert = rule.check(metrics)
            if alert:
                self._alerts[alert.id] = alert
                new_alerts.append(alert)

                # Notify handlers
                for handler in self._handlers:
                    try:
                        handler(alert)
                    except Exception as e:
                        logger.error(f"Alert handler failed: {e}")

        return new_alerts

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get alert by ID."""
        return self._alerts.get(alert_id)

    def get_alerts(
        self,
        status: Optional[AlertStatus] = None,
        severity: Optional[AlertSeverity] = None,
    ) -> List[Alert]:
        """Get alerts with optional filtering."""
        alerts = list(self._alerts.values())

        if status:
            alerts = [a for a in alerts if a.status == status]

        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        return alerts

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert."""
        if alert_id in self._alerts:
            self._alerts[alert_id].acknowledge()
            return True
        return False

    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert."""
        if alert_id in self._alerts:
            self._alerts[alert_id].resolve()
            return True
        return False


# Global alert manager
alert_manager = AlertManager()
