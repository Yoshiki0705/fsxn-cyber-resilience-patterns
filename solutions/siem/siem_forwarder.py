"""Third-party SIEM forwarder — Splunk HEC, QRadar LEEF, generic CEF.

Receives batched events from SQS, transforms to SIEM-specific formats,
and forwards via HTTPS. Includes PII redaction for external endpoints.

Environment Variables:
    SIEM_FORMAT: splunk | qradar | cef
    SIEM_ENDPOINT: HTTPS endpoint URL
    SIEM_SECRET_ARN: Secrets Manager ARN for SIEM auth credentials
    REDACT_PII: true | false (default: true)
    DLQ_BUCKET: S3 bucket for dead-letter storage
    ENVIRONMENT: Deployment environment
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3
import urllib3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SIEM_FORMAT = os.environ.get("SIEM_FORMAT", "splunk")
SIEM_ENDPOINT = os.environ.get("SIEM_ENDPOINT", "")
SIEM_SECRET_ARN = os.environ.get("SIEM_SECRET_ARN", "")
REDACT_PII = os.environ.get("REDACT_PII", "true").lower() == "true"
DLQ_BUCKET = os.environ.get("DLQ_BUCKET", "")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")

# PII fields to redact (configurable)
PII_FIELDS = ["clientIp", "userName", "client_ip", "user_name"]

http = urllib3.PoolManager()


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Process SQS batch of security events and forward to SIEM.

    Args:
        event: SQS batch event.
        context: Lambda context.

    Returns:
        Processing result.
    """
    records = event.get("Records", [])
    forwarded = 0
    failed = 0

    # Batch events for efficient delivery
    batch: list[dict[str, Any]] = []
    for record in records:
        try:
            body = json.loads(record["body"])
            if REDACT_PII:
                body = redact_pii(body, PII_FIELDS)
            batch.append(body)
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse record: {e}")
            failed += 1

    if batch:
        success = _forward_batch(batch)
        if success:
            forwarded = len(batch)
        else:
            failed += len(batch)
            _store_dead_letter(batch)

    return {"statusCode": 200, "forwarded": forwarded, "failed": failed}


def redact_pii(event: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    """Redact PII fields by replacing with SHA256 hash prefix.

    Args:
        event: Event dict to redact.
        fields: List of field names to redact.

    Returns:
        Redacted event dict (new copy).
    """
    redacted = {}
    for key, value in event.items():
        if key in fields and isinstance(value, str) and value:
            redacted[key] = f"REDACTED:{hashlib.sha256(value.encode()).hexdigest()[:8]}"
        elif isinstance(value, dict):
            redacted[key] = redact_pii(value, fields)
        else:
            redacted[key] = value
    return redacted


def format_splunk_hec(events: list[dict[str, Any]]) -> str:
    """Format events as Splunk HEC JSON payload.

    Args:
        events: List of security events.

    Returns:
        Newline-delimited Splunk HEC JSON.
    """
    lines = []
    for event in events:
        hec_event = {
            "event": event,
            "sourcetype": "fsxn:security",
            "source": "fsxn-cyber-resilience",
            "index": "main",
            "time": datetime.now(timezone.utc).timestamp(),
        }
        lines.append(json.dumps(hec_event))
    return "\n".join(lines)


def format_qradar_leef(events: list[dict[str, Any]]) -> str:
    """Format events as QRadar LEEF.

    Args:
        events: List of security events.

    Returns:
        Newline-delimited LEEF records.
    """
    lines = []
    for event in events:
        detail_type = event.get("detail-type", event.get("DetailType", "SecurityEvent"))
        severity = event.get("severity", "5")
        leef = (
            f"LEEF:2.0|NetApp|FSxONTAP|1.0|{detail_type}|"
            f"sev={severity}\t"
            f"filePath={event.get('filePath', '')}\t"
            f"verdict={event.get('verdict', '')}\t"
            f"scanner={event.get('scannerName', '')}"
        )
        lines.append(leef)
    return "\n".join(lines)


def format_cef(events: list[dict[str, Any]]) -> str:
    """Format events as generic CEF.

    Args:
        events: List of security events.

    Returns:
        Newline-delimited CEF records.
    """
    lines = []
    for event in events:
        detail_type = event.get("detail-type", event.get("DetailType", "SecurityEvent"))
        severity = event.get("severity", "5")
        cef = (
            f"CEF:0|FSxONTAP|CyberResilience|1.0|{detail_type}|"
            f"{detail_type}|{severity}|"
            f"filePath={event.get('filePath', '')} "
            f"verdict={event.get('verdict', '')} "
            f"scanner={event.get('scannerName', '')}"
        )
        lines.append(cef)
    return "\n".join(lines)


def _forward_batch(events: list[dict[str, Any]]) -> bool:
    """Forward batch of events to SIEM endpoint.

    Args:
        events: Transformed events.

    Returns:
        True if delivery succeeded.
    """
    if not SIEM_ENDPOINT:
        logger.warning("SIEM_ENDPOINT not configured, skipping delivery")
        return True

    # Format based on SIEM type
    formatters = {
        "splunk": format_splunk_hec,
        "qradar": format_qradar_leef,
        "cef": format_cef,
    }
    formatter = formatters.get(SIEM_FORMAT, format_splunk_hec)
    payload = formatter(events)

    # Get credentials
    headers = _get_auth_headers()
    headers["Content-Type"] = "application/json" if SIEM_FORMAT == "splunk" else "text/plain"

    # Send with retry
    for attempt in range(3):
        try:
            response = http.request(
                "POST",
                SIEM_ENDPOINT,
                body=payload.encode(),
                headers=headers,
                timeout=30.0,
            )
            if response.status < 300:
                logger.info(f"SIEM delivery success: {len(events)} events")
                return True
            logger.warning(f"SIEM delivery attempt {attempt + 1} failed: HTTP {response.status}")
        except Exception as e:
            logger.warning(f"SIEM delivery attempt {attempt + 1} error: {e}")

    logger.error("SIEM delivery failed after 3 attempts")
    return False


def _get_auth_headers() -> dict[str, str]:
    """Get SIEM authentication headers from Secrets Manager."""
    if not SIEM_SECRET_ARN:
        return {}

    try:
        sm = boto3.client("secretsmanager")
        response = sm.get_secret_value(SecretId=SIEM_SECRET_ARN)
        secret = json.loads(response["SecretString"])
        # Splunk HEC token format
        if SIEM_FORMAT == "splunk":
            return {"Authorization": f"Splunk {secret.get('token', '')}"}
        # Generic bearer
        return {"Authorization": f"Bearer {secret.get('token', '')}"}
    except Exception as e:
        logger.error(f"Failed to retrieve SIEM credentials: {e}")
        return {}


def _store_dead_letter(events: list[dict[str, Any]]) -> None:
    """Store failed events in S3 dead-letter bucket."""
    if not DLQ_BUCKET:
        return

    try:
        s3 = boto3.client("s3")
        now = datetime.now(timezone.utc)
        key = f"dead-letter/{now.strftime('%Y/%m/%d')}/{now.isoformat()}.json"
        s3.put_object(
            Bucket=DLQ_BUCKET,
            Key=key,
            Body=json.dumps(events).encode(),
            ContentType="application/json",
        )
        logger.info(f"Dead-letter stored: s3://{DLQ_BUCKET}/{key}")
    except Exception as e:
        logger.error(f"Failed to store dead-letter: {e}")
