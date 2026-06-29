"""ARP Lifecycle Manager — manages ARP state transitions.

Triggered daily by EventBridge Scheduler. Tracks learning start date
per volume in DynamoDB and transitions ARP from dry_run to enabled
after the configured learning period.

Environment Variables:
    STATE_TABLE_NAME: DynamoDB table for ARP state tracking
    FSX_SECRET_ARN: Secrets Manager ARN for fsxadmin credentials
    MANAGEMENT_ENDPOINT: FSx for ONTAP management DNS
    SNS_TOPIC_ARN: SNS topic for transition notifications
    LEARNING_DAYS: Days before transition (default: 30)
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Any

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

STATE_TABLE_NAME = os.environ.get("STATE_TABLE_NAME", "")
FSX_SECRET_ARN = os.environ.get("FSX_SECRET_ARN", "")
MANAGEMENT_ENDPOINT = os.environ.get("MANAGEMENT_ENDPOINT", "")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
LEARNING_DAYS = int(os.environ.get("LEARNING_DAYS", "30"))


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Daily ARP lifecycle check.

    For each tracked volume:
    1. Check if learning period has elapsed
    2. If yes, notify via SNS and transition ARP to enabled
    3. Update state in DynamoDB

    Args:
        event: EventBridge Scheduler event.
        context: Lambda context.

    Returns:
        Processing summary.
    """
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(STATE_TABLE_NAME)
    sns = boto3.client("sns")

    today = datetime.now(timezone.utc).date()
    results: dict[str, Any] = {"checked": 0, "transitioned": 0, "errors": []}

    # Scan all volumes in dry_run state
    response = table.scan(
        FilterExpression="current_state = :state",
        ExpressionAttributeValues={":state": "dry_run"},
    )

    for item in response.get("Items", []):
        results["checked"] += 1
        volume_uuid = item["volume_uuid"]
        start_date = datetime.fromisoformat(item["arp_start_date"]).date()
        learning_days = int(item.get("learning_days", LEARNING_DAYS))

        elapsed = (today - start_date).days
        logger.info(f"Volume {volume_uuid}: {elapsed}/{learning_days} days elapsed")

        if elapsed >= learning_days:
            try:
                _transition_arp(volume_uuid, table, sns)
                results["transitioned"] += 1
            except Exception as e:
                logger.error(f"Failed to transition {volume_uuid}: {e}")
                results["errors"].append({"volume_uuid": volume_uuid, "error": str(e)})

    logger.info(f"ARP lifecycle check: {results}")
    return results


def _transition_arp(
    volume_uuid: str,
    table: Any,
    sns: Any,
) -> None:
    """Transition a volume's ARP from dry_run to enabled.

    Args:
        volume_uuid: Target volume UUID.
        table: DynamoDB table resource.
        sns: SNS client.
    """
    # Notify before transition
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"ARP Transition: Volume {volume_uuid[:8]}... ready for active mode",
        Message=json.dumps({
            "action": "arp_transition",
            "volume_uuid": volume_uuid,
            "from_state": "dry_run",
            "to_state": "enabled",
            "message": "Learning period complete. Transitioning to active protection.",
        }),
    )

    # Perform transition via ONTAP REST API
    from ontap_client import OntapClient

    client = OntapClient(
        management_endpoint=MANAGEMENT_ENDPOINT,
        secret_arn=FSX_SECRET_ARN,
    )
    client.enable_arp(volume_uuid, state="enabled")

    # Update DynamoDB state
    table.update_item(
        Key={"volume_uuid": volume_uuid},
        UpdateExpression="SET current_state = :state, transition_date = :date",
        ExpressionAttributeValues={
            ":state": "enabled",
            ":date": datetime.now(timezone.utc).isoformat(),
        },
    )

    logger.info(f"ARP transitioned to enabled for volume {volume_uuid}")


def register_volume(
    volume_uuid: str,
    learning_days: int = 30,
) -> dict[str, Any]:
    """Register a new volume for ARP lifecycle tracking.

    Called by the Security Config Custom Resource after enabling ARP.

    Args:
        volume_uuid: Volume UUID to track.
        learning_days: Days of learning before transition.

    Returns:
        DynamoDB put_item response.
    """
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(STATE_TABLE_NAME)

    item = {
        "volume_uuid": volume_uuid,
        "arp_start_date": datetime.now(timezone.utc).isoformat(),
        "current_state": "dry_run",
        "learning_days": learning_days,
        "last_check_date": datetime.now(timezone.utc).isoformat(),
        "transition_requested": False,
    }

    return table.put_item(Item=item)
