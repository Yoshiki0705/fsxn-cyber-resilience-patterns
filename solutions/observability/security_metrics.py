"""Security metrics publisher for CloudWatch.

Publishes custom metrics from security events processed by the
event-driven response pipeline. Used by Lambda functions to track
security posture indicators.

Metric Namespace: FsxOntapCyberResilience
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import boto3

logger = logging.getLogger(__name__)

NAMESPACE = "FsxOntapCyberResilience"


@dataclass
class SecurityMetricsPublisher:
    """Publishes security-related custom metrics to CloudWatch.

    Attributes:
        namespace: CloudWatch metric namespace.
        environment: Deployment environment for dimensioning.
        project_name: Project name for dimensioning.
    """

    namespace: str = NAMESPACE
    environment: str = "dev"
    project_name: str = "fsxn-cyber-resilience"
    _client: Any = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        """Initialize CloudWatch client."""
        self._client = boto3.client("cloudwatch")

    @property
    def _dimensions(self) -> list[dict[str, str]]:
        """Standard dimensions applied to all metrics."""
        return [
            {"Name": "Environment", "Value": self.environment},
            {"Name": "Project", "Value": self.project_name},
        ]

    def put_metric(
        self,
        metric_name: str,
        value: float,
        unit: str = "Count",
        dimensions: list[dict[str, str]] | None = None,
    ) -> None:
        """Publish a single metric data point.

        Args:
            metric_name: Name of the metric.
            value: Numeric value.
            unit: CloudWatch unit (Count, Milliseconds, etc.).
            dimensions: Additional dimensions beyond the standard ones.
        """
        all_dimensions = self._dimensions.copy()
        if dimensions:
            all_dimensions.extend(dimensions)

        try:
            self._client.put_metric_data(
                Namespace=self.namespace,
                MetricData=[
                    {
                        "MetricName": metric_name,
                        "Value": value,
                        "Unit": unit,
                        "Timestamp": datetime.now(timezone.utc),
                        "Dimensions": all_dimensions,
                    }
                ],
            )
            logger.debug(f"Published metric {metric_name}={value} ({unit})")
        except Exception:
            logger.exception(f"Failed to publish metric {metric_name}")

    def record_events_received(self, count: int = 1) -> None:
        """Record security events received from SQS."""
        self.put_metric("SecurityEventsReceived", count)

    def record_malware_detected(
        self, scanner_name: str = "unknown", count: int = 1
    ) -> None:
        """Record malware detection event."""
        self.put_metric(
            "MalwareDetected",
            count,
            dimensions=[{"Name": "Scanner", "Value": scanner_name}],
        )

    def record_ransomware_alert(self, count: int = 1) -> None:
        """Record ARP ransomware alert."""
        self.put_metric("RansomwareAlerts", count)

    def record_quarantine_executed(self, count: int = 1) -> None:
        """Record quarantine workflow execution."""
        self.put_metric("QuarantineExecuted", count)

    def record_scan_latency(self, latency_ms: float) -> None:
        """Record file scan latency in milliseconds."""
        self.put_metric("ScanLatencyP99", latency_ms, unit="Milliseconds")

    def record_false_positive(self, count: int = 1) -> None:
        """Record false positive determination by admin."""
        self.put_metric("FalsePositives", count)

    def record_dlq_messages(self, count: int) -> None:
        """Record current DLQ message count."""
        self.put_metric("DlqMessages", count)
