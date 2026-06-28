"""CloudWatch Dashboard configuration generator for security monitoring.

Generates the JSON widget definitions for a security-focused
CloudWatch Dashboard deployed via CloudFormation.
"""
from __future__ import annotations

import json
from typing import Any

NAMESPACE = "FsxOntapCyberResilience"


def generate_dashboard_body(
    project_name: str = "fsxn-cyber-resilience",
    environment: str = "dev",
    region: str = "ap-northeast-1",
) -> str:
    """Generate CloudWatch Dashboard JSON body.

    Args:
        project_name: Project name for metric dimensions.
        environment: Deployment environment.
        region: AWS region.

    Returns:
        JSON string suitable for AWS::CloudWatch::Dashboard DashboardBody.
    """
    dimensions = ["Environment", environment, "Project", project_name]

    widgets: list[dict[str, Any]] = [
        # Row 1: Key security indicators
        {
            "type": "metric",
            "x": 0,
            "y": 0,
            "width": 6,
            "height": 6,
            "properties": {
                "title": "Security Events Received",
                "region": region,
                "metrics": [
                    [NAMESPACE, "SecurityEventsReceived", *dimensions],
                ],
                "stat": "Sum",
                "period": 300,
            },
        },
        {
            "type": "metric",
            "x": 6,
            "y": 0,
            "width": 6,
            "height": 6,
            "properties": {
                "title": "Malware Detected",
                "region": region,
                "metrics": [
                    [NAMESPACE, "MalwareDetected", *dimensions],
                ],
                "stat": "Sum",
                "period": 300,
                "annotations": {
                    "horizontal": [
                        {"value": 10, "label": "Burst threshold", "color": "#ff0000"},
                    ]
                },
            },
        },
        {
            "type": "metric",
            "x": 12,
            "y": 0,
            "width": 6,
            "height": 6,
            "properties": {
                "title": "Ransomware Alerts (ARP)",
                "region": region,
                "metrics": [
                    [NAMESPACE, "RansomwareAlerts", *dimensions],
                ],
                "stat": "Sum",
                "period": 300,
            },
        },
        {
            "type": "metric",
            "x": 18,
            "y": 0,
            "width": 6,
            "height": 6,
            "properties": {
                "title": "Quarantine Actions",
                "region": region,
                "metrics": [
                    [NAMESPACE, "QuarantineExecuted", *dimensions],
                ],
                "stat": "Sum",
                "period": 300,
            },
        },
        # Row 2: Performance and health
        {
            "type": "metric",
            "x": 0,
            "y": 6,
            "width": 8,
            "height": 6,
            "properties": {
                "title": "Scan Latency (p99)",
                "region": region,
                "metrics": [
                    [NAMESPACE, "ScanLatencyP99", *dimensions],
                ],
                "stat": "p99",
                "period": 60,
                "annotations": {
                    "horizontal": [
                        {"value": 100, "label": "SLA threshold", "color": "#ff7f0e"},
                    ]
                },
            },
        },
        {
            "type": "metric",
            "x": 8,
            "y": 6,
            "width": 8,
            "height": 6,
            "properties": {
                "title": "DLQ Messages",
                "region": region,
                "metrics": [
                    [NAMESPACE, "DlqMessages", *dimensions],
                ],
                "stat": "Maximum",
                "period": 60,
            },
        },
        {
            "type": "metric",
            "x": 16,
            "y": 6,
            "width": 8,
            "height": 6,
            "properties": {
                "title": "False Positives",
                "region": region,
                "metrics": [
                    [NAMESPACE, "FalsePositives", *dimensions],
                ],
                "stat": "Sum",
                "period": 86400,
            },
        },
    ]

    return json.dumps({"widgets": widgets})
