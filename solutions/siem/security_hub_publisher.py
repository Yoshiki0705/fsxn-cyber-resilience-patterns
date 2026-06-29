"""AWS Security Hub findings publisher.

Transforms EventBridge security events into ASFF (AWS Security Finding Format)
and publishes to Security Hub via BatchImportFindings API.

Environment Variables:
    PRODUCT_ARN: Security Hub custom product integration ARN
    ENVIRONMENT: Deployment environment
    AWS_REGION: AWS region (auto-set by Lambda)
    AWS_ACCOUNT_ID: Account ID (resolved at runtime)
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

PRODUCT_ARN = os.environ.get("PRODUCT_ARN", "")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")

securityhub = boto3.client("securityhub")
sts = boto3.client("sts")

# Severity mapping: internal → ASFF
SEVERITY_MAP = {
    "CRITICAL": {"Label": "CRITICAL", "Normalized": 90},
    "HIGH": {"Label": "HIGH", "Normalized": 70},
    "MEDIUM": {"Label": "MEDIUM", "Normalized": 40},
    "LOW": {"Label": "LOW", "Normalized": 10},
    "INFO": {"Label": "INFORMATIONAL", "Normalized": 0},
}


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Process EventBridge event and publish to Security Hub.

    Args:
        event: EventBridge event (detail-type + detail).
        context: Lambda context.

    Returns:
        Publishing result with finding count.
    """
    detail = event.get("detail", {})
    detail_type = event.get("detail-type", "SecurityEvent")
    source = event.get("source", "")
    region = os.environ.get("AWS_REGION", "ap-northeast-1")
    account_id = event.get("account", _get_account_id())

    finding = _build_asff_finding(
        detail=detail,
        detail_type=detail_type,
        source=source,
        region=region,
        account_id=account_id,
    )

    try:
        response = securityhub.batch_import_findings(Findings=[finding])
        failed = response.get("FailedCount", 0)
        if failed > 0:
            logger.error(f"Failed to import finding: {response.get('FailedFindings', [])}")
        else:
            logger.info(f"Finding published: {finding['Id']}")
        return {"statusCode": 200, "published": 1 - failed, "failed": failed}
    except Exception as e:
        logger.exception(f"Security Hub publish error: {e}")
        return {"statusCode": 500, "published": 0, "error": str(e)}


def _build_asff_finding(
    detail: dict[str, Any],
    detail_type: str,
    source: str,
    region: str,
    account_id: str,
) -> dict[str, Any]:
    """Build an ASFF-compliant finding from an internal security event.

    Args:
        detail: Event detail payload.
        detail_type: EventBridge detail-type.
        source: EventBridge source.
        region: AWS region.
        account_id: AWS account ID.

    Returns:
        ASFF finding dict.
    """
    file_system_id = detail.get("fileSystemId", "unknown")
    file_path = detail.get("filePath", "")
    severity = detail.get("severity", "MEDIUM")
    scanner_name = detail.get("scannerName", "")
    timestamp = detail.get("timestamp", datetime.now(timezone.utc).isoformat())

    finding_id = _generate_finding_id(region, account_id, file_system_id, file_path, timestamp)

    return {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": PRODUCT_ARN,
        "GeneratorId": f"fsxn-cyber-resilience-{scanner_name or 'arp'}",
        "AwsAccountId": account_id,
        "Types": [_map_finding_type(detail_type)],
        "CreatedAt": timestamp,
        "UpdatedAt": datetime.now(timezone.utc).isoformat(),
        "Severity": SEVERITY_MAP.get(severity, SEVERITY_MAP["MEDIUM"]),
        "Title": f"{detail_type}: {file_path or file_system_id}",
        "Description": (
            f"Security event detected on FSx for ONTAP file system {file_system_id}. "
            f"Scanner: {scanner_name or 'ARP'}. Verdict: {detail.get('verdict', 'N/A')}."
        ),
        "Resources": [
            {
                "Type": "Other",
                "Id": f"arn:aws:fsx:{region}:{account_id}:file-system/{file_system_id}",
                "Region": region,
                "Details": {
                    "Other": {
                        "filePath": file_path,
                        "volumeId": detail.get("volumeId", ""),
                        "svmId": detail.get("svmId", ""),
                        "scannerName": scanner_name,
                    }
                },
            }
        ],
        "ProductFields": {
            "source": source,
            "environment": ENVIRONMENT,
            "verdict": detail.get("verdict", ""),
        },
    }


def _generate_finding_id(
    region: str,
    account_id: str,
    file_system_id: str,
    file_path: str,
    timestamp: str,
) -> str:
    """Generate a deterministic FindingId for deduplication.

    Same file + timestamp → same FindingId (allows Security Hub to update
    rather than create duplicate findings).
    """
    content = f"{file_system_id}:{file_path}:{timestamp}"
    content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
    return f"{region}/{account_id}/{file_system_id}/{content_hash}"


def _map_finding_type(detail_type: str) -> str:
    """Map EventBridge detail-type to ASFF finding type."""
    type_map = {
        "MalwareDetected": "Software and Configuration Checks/Vulnerabilities/Malware",
        "RansomwareDetected": "Software and Configuration Checks/Vulnerabilities/Malware",
        "SuspiciousFileDetected": "Unusual Behaviors/Application",
        "SuspiciousActivity": "Unusual Behaviors/Application",
        "FileScanClean": "Software and Configuration Checks",
    }
    return type_map.get(detail_type, "Software and Configuration Checks")


def _get_account_id() -> str:
    """Get current AWS account ID."""
    try:
        return sts.get_caller_identity()["Account"]
    except Exception:
        return "unknown"
