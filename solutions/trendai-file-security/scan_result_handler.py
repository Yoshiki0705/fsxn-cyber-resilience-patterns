"""TrendAI Vscan result handler Lambda function.

Processes scan verdict events from TrendAI Vision One File Security
and publishes normalized security events to EventBridge.

Integration patterns:
  1. Vscan/ICAP: FPolicy → ICAP → TrendAI → verdict → this Lambda (via SQS)
  2. S3 AP batch: S3 AP scan → SNS/SQS → this Lambda
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
SOURCE = "fsxn.cyber-resilience.trendai"


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Process TrendAI scan verdict events.

    Handles both Vscan/ICAP verdicts (via log/webhook) and
    S3 AP batch scan results (via SQS/SNS).

    Args:
        event: TrendAI verdict payload.
        context: Lambda context.

    Returns:
        Processing result with published event count.
    """
    events_client = boto3.client("events")
    published_count = 0
    errors: list[str] = []

    # Handle SQS-wrapped events
    records = event.get("Records", [event])

    for record in records:
        try:
            body = _extract_body(record)
            if body is None:
                continue

            verdict = _normalize_verdict(body)
            if verdict is None:
                continue

            detail_type = _map_detail_type(verdict["verdict"])
            severity = _classify_severity(verdict)

            entry = {
                "Source": SOURCE,
                "DetailType": detail_type,
                "EventBusName": EVENT_BUS_NAME,
                "Detail": json.dumps({
                    "fileSystemId": FILE_SYSTEM_ID,
                    "filePath": verdict["file_path"],
                    "operation": verdict.get("operation", "write"),
                    "verdict": verdict["verdict"].upper(),
                    "scannerName": "trendai",
                    "severity": severity,
                    "malwareName": verdict.get("malware_name", ""),
                    "scanType": verdict.get("scan_type", "realtime"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }),
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


def _extract_body(record: dict[str, Any]) -> dict[str, Any] | None:
    """Extract event body from various record wrappers.

    Handles raw dict, SQS message body, and SNS-wrapped messages.

    Args:
        record: Raw record from event source.

    Returns:
        Extracted body dict or None.
    """
    # SQS record
    if "body" in record:
        body_str = record["body"]
        try:
            body = json.loads(body_str) if isinstance(body_str, str) else body_str
        except (json.JSONDecodeError, TypeError):
            return None

        # SNS-wrapped inside SQS
        if "Message" in body:
            try:
                return json.loads(body["Message"])
            except (json.JSONDecodeError, TypeError):
                return None
        return body

    # Direct invocation
    if "file_path" in record or "filePath" in record:
        return record

    return None


def _normalize_verdict(body: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize various TrendAI verdict formats to a standard structure.

    Args:
        body: Raw verdict payload.

    Returns:
        Normalized verdict dict or None if unparseable.
    """
    # Standard format
    if "file_path" in body and "verdict" in body:
        return body

    # TrendAI File Security API format
    if "filePath" in body and "scanResult" in body:
        return {
            "file_path": body["filePath"],
            "verdict": body["scanResult"].lower(),
            "malware_name": body.get("malwareName", ""),
            "scan_type": body.get("scanType", "realtime"),
            "operation": body.get("operation", "write"),
        }

    # S3 AP scan result format
    if "objectKey" in body and "status" in body:
        return {
            "file_path": body["objectKey"],
            "verdict": "infected" if body["status"] == "MALICIOUS" else "clean",
            "malware_name": body.get("details", {}).get("malwareName", ""),
            "scan_type": "batch",
            "operation": "s3ap-scan",
        }

    return None


def _map_detail_type(verdict: str) -> str:
    """Map TrendAI verdict to EventBridge detail-type.

    Args:
        verdict: Normalized verdict string.

    Returns:
        EventBridge detail type.
    """
    mapping = {
        "infected": "MalwareDetected",
        "malicious": "MalwareDetected",
        "suspicious": "SuspiciousFileDetected",
        "clean": "FileScanClean",
    }
    return mapping.get(verdict.lower(), "SecurityEvent")


def _classify_severity(verdict: dict[str, Any]) -> str:
    """Classify severity based on verdict and malware type.

    Args:
        verdict: Normalized verdict dict.

    Returns:
        Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO).
    """
    verdict_str = verdict.get("verdict", "").lower()
    malware_name = verdict.get("malware_name", "").lower()

    if verdict_str in ("infected", "malicious"):
        # Ransomware indicators get CRITICAL
        if any(kw in malware_name for kw in ("ransom", "crypt", "locker", "wannacry")):
            return "CRITICAL"
        return "HIGH"
    elif verdict_str == "suspicious":
        return "MEDIUM"
    return "INFO"
