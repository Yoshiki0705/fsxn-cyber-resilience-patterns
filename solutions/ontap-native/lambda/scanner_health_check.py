"""Scanner Health Check Lambda — ICAP connectivity verification.

Tests TCP connectivity to scanner instances on port 1344 (ICAP).
Publishes ScannerHealthy custom metric to CloudWatch.
Triggered every 60 seconds by EventBridge Scheduler.

Environment Variables:
    SCANNER_IPS: Comma-separated list of scanner private IPs
    ENVIRONMENT: Deployment environment
    PROJECT_NAME: Project name for metric dimensions
"""
from __future__ import annotations

import logging
import os
import socket
from datetime import datetime, timezone
from typing import Any

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SCANNER_IPS = os.environ.get("SCANNER_IPS", "").split(",")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")
PROJECT_NAME = os.environ.get("PROJECT_NAME", "fsxn-cyber-resilience")
ICAP_PORT = 1344
CONNECT_TIMEOUT = 5  # seconds

cloudwatch = boto3.client("cloudwatch")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Check ICAP connectivity for all configured scanner IPs.

    Args:
        event: EventBridge Scheduler event.
        context: Lambda context.

    Returns:
        Health check results per scanner.
    """
    results: list[dict[str, Any]] = []

    for ip in SCANNER_IPS:
        ip = ip.strip()
        if not ip:
            continue

        healthy = _check_icap_connectivity(ip)
        _publish_metric(ip, healthy)
        results.append({"ip": ip, "healthy": healthy})
        logger.info(f"Scanner {ip}: {'healthy' if healthy else 'UNHEALTHY'}")

    healthy_count = sum(1 for r in results if r["healthy"])
    total = len(results)
    logger.info(f"Health check complete: {healthy_count}/{total} healthy")

    return {
        "statusCode": 200,
        "results": results,
        "healthy": healthy_count,
        "total": total,
    }


def _check_icap_connectivity(ip: str) -> bool:
    """Test TCP connectivity to ICAP port.

    Args:
        ip: Scanner private IP address.

    Returns:
        True if connection succeeds within timeout.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        result = sock.connect_ex((ip, ICAP_PORT))
        sock.close()
        return result == 0
    except (socket.timeout, socket.error, OSError) as e:
        logger.warning(f"Health check failed for {ip}:{ICAP_PORT}: {e}")
        return False


def _publish_metric(ip: str, healthy: bool) -> None:
    """Publish scanner health metric to CloudWatch.

    Args:
        ip: Scanner IP address (used as dimension).
        healthy: Whether the scanner is reachable.
    """
    try:
        cloudwatch.put_metric_data(
            Namespace="FsxOntapCyberResilience",
            MetricData=[
                {
                    "MetricName": "ScannerHealthy",
                    "Value": 1.0 if healthy else 0.0,
                    "Unit": "None",
                    "Timestamp": datetime.now(timezone.utc),
                    "Dimensions": [
                        {"Name": "Environment", "Value": ENVIRONMENT},
                        {"Name": "Project", "Value": PROJECT_NAME},
                        {"Name": "ScannerIP", "Value": ip},
                    ],
                }
            ],
        )
    except Exception:
        logger.exception(f"Failed to publish health metric for {ip}")
