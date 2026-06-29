"""Deep Instinct verdict handler Lambda function.

Processes verdict events from Deep Instinct agent and publishes
normalized security events to EventBridge for downstream processing.

Event flow:
  DI Agent → CloudWatch Logs (or webhook) → This Lambda → EventBridge
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

EVENT_BUS_NAME = os.environ.get("EVENT_BUS_NAME", "default")
FILE_SYSTEM_ID = os.environ.get("FILE_SYSTEM_ID", "")
SOURCE = "fsxn.cyber-resilience.deep-instinct"


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Process Deep Instinct verdict events.

    Normalizes DI verdicts into the standard security event format
    and publishes them to EventBridge.

    Args:
        event: DI verdict payload (from webhook or log subscription).
        context: Lambda context.

    Returns:
        Processing result with published event count.
    """
    events_client = boto3.client("events")
    published_count = 0
    errors: list[str] = []

    records = event.get("records", [event]) if "records" not in event else event["records"]

    for record in records:
        try:
            verdict = _parse_verdict(record)
            if verdict is None:
                continue

            detail_type = _map_detail_type(verdict["classification"])
            severity = _map_severity(verdict["confidence"], verdict["classification"])

            entry = {
                "Source": SOURCE,
                "DetailType": detail_type,
                "EventBusName": EVENT_BUS_NAME,
                "Detail": json.dumps(
                    {
                        "fileSystemId": FILE_SYSTEM_ID,
                        "filePath": verdict["file_path"],
                        "operation": verdict.get("operation", "write"),
                        "verdict": verdict["classification"].upper(),
                        "confidence": verdict["confidence"],
                        "scannerName": "deep-instinct",
                        "severity": severity,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "modelVersion": verdict.get("model_version", "unknown"),
                        "threatFamily": verdict.get("threat_family", ""),
                    }
                ),
            }

            response = events_client.put_events(Entries=[entry])
            if response["FailedEntryCount"] == 0:
                published_count += 1
            else:
                errors.append(f"Failed to publish event for {verdict['file_path']}")

        except Exception as e:
            logger.exception(f"Error processing record: {e}")
            errors.append(str(e))

    logger.info(f"Published {published_count} events, {len(errors)} errors")

    return {
        "statusCode": 200,
        "published": published_count,
        "errors": errors,
    }


def _parse_verdict(record: dict[str, Any]) -> dict[str, Any] | None:
    """Parse a Deep Instinct verdict record.

    Args:
        record: Raw verdict record from DI agent.

    Returns:
        Normalized verdict dict or None if not actionable.
    """
    # DI webhook format
    if "file_path" in record and "classification" in record:
        return record

    # CloudWatch Logs subscription format
    if "message" in record:
        try:
            return json.loads(record["message"])
        except (json.JSONDecodeError, TypeError):
            return None

    # Nested body format
    if "body" in record:
        try:
            return json.loads(record["body"]) if isinstance(record["body"], str) else record["body"]
        except (json.JSONDecodeError, TypeError):
            return None

    return None


def _map_detail_type(classification: str) -> str:
    """Map DI classification to EventBridge detail-type.

    Args:
        classification: DI classification string.

    Returns:
        Normalized detail type.
    """
    mapping = {
        "malicious": "MalwareDetected",
        "suspicious": "SuspiciousFileDetected",
        "benign": "FileScanClean",
    }
    return mapping.get(classification.lower(), "SecurityEvent")


def _map_severity(confidence: float, classification: str) -> str:
    """Map DI confidence and classification to severity level.

    Args:
        confidence: Model confidence score (0.0 - 1.0).
        classification: DI classification string.

    Returns:
        Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO).
    """
    if classification.lower() == "malicious":
        return "CRITICAL" if confidence >= 0.9 else "HIGH"
    elif classification.lower() == "suspicious":
        return "MEDIUM" if confidence >= 0.7 else "LOW"
    return "INFO"
