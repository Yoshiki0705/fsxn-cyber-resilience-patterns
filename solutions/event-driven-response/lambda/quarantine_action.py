"""Quarantine Action Lambda — ONTAP REST API operations for incident response.

Called by Step Functions quarantine workflow to execute containment actions
on FSx for ONTAP volumes via the ONTAP REST API.

Supported actions:
    - restrict_export_policy: Block NFS/SMB client access (quarantine)
    - restore_export_policy: Re-enable access after investigation
    - create_forensic_snapshot: Create named snapshot for evidence
    - create_forensic_clone: Create read-only FlexClone for analysis

Environment Variables:
    FSX_SECRET_ARN: Secrets Manager ARN for fsxadmin credentials
    FSX_MANAGEMENT_ENDPOINT: FSx for ONTAP management DNS (or passed in event)
    ENVIRONMENT: Deployment environment
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import Any


logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Add shared module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "shared"))
sys.path.insert(0, "/opt/python")  # Lambda Layer path


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Route to appropriate quarantine action.

    Args:
        event: Action request from Step Functions.
            Required keys: action
            Optional keys vary by action (volumeId, svmId, snapshotName, etc.)
        context: Lambda context.

    Returns:
        Action result dict.

    Raises:
        ValueError: On unknown action.
    """
    action = event.get("action", "")
    logger.info(f"Quarantine action: {action}")
    logger.info(f"Event: {json.dumps(event, default=str)}")

    client = _get_client(event)

    if action == "restrict_export_policy":
        return _restrict_export_policy(client, event)
    elif action == "restore_export_policy":
        return _restore_export_policy(client, event)
    elif action == "create_forensic_snapshot":
        return _create_forensic_snapshot(client, event)
    elif action == "create_forensic_clone":
        return _create_forensic_clone(client, event)
    else:
        raise ValueError(f"Unknown action: {action}")


def _restrict_export_policy(client: Any, event: dict[str, Any]) -> dict[str, Any]:
    """Restrict export policy to deny all client access (quarantine).

    Args:
        client: ONTAP API client.
        event: Must contain 'svmId' or 'svmUuid'.

    Returns:
        Quarantine result.
    """
    svm_uuid = event.get("svmUuid") or event.get("svmId", "")
    volume_id = event.get("volumeId", "")

    logger.info(f"Restricting export policy for SVM {svm_uuid}")

    # Get the default export policy for the SVM
    policy = client.get_export_policy(svm_uuid, "default")
    policy_id = policy.get("id")

    if not policy_id:
        logger.warning("Could not find default export policy — attempting by volume")
        # Fallback: use the volume's export policy
        return {
            "status": "warning",
            "message": "Export policy not found. Manual quarantine may be required.",
            "volumeId": volume_id,
            "svmUuid": svm_uuid,
        }

    client.restrict_export_policy(policy_id)

    return {
        "status": "quarantined",
        "volumeId": volume_id,
        "svmUuid": svm_uuid,
        "policyId": policy_id,
        "timestamp": _now_iso(),
    }


def _restore_export_policy(client: Any, event: dict[str, Any]) -> dict[str, Any]:
    """Restore export policy to allow client access (un-quarantine).

    Args:
        client: ONTAP API client.
        event: Must contain 'svmUuid' and optionally 'clientMatch'.

    Returns:
        Restore result.
    """
    svm_uuid = event.get("svmUuid") or event.get("svmId", "")
    client_match = event.get("clientMatch", "0.0.0.0/0")
    volume_id = event.get("volumeId", "")

    logger.info(f"Restoring export policy for SVM {svm_uuid}")

    policy = client.get_export_policy(svm_uuid, "default")
    policy_id = policy.get("id")

    if not policy_id:
        return {
            "status": "error",
            "message": "Export policy not found for restore.",
            "svmUuid": svm_uuid,
        }

    client.restore_export_policy(policy_id, client_match)

    return {
        "status": "restored",
        "volumeId": volume_id,
        "svmUuid": svm_uuid,
        "policyId": policy_id,
        "clientMatch": client_match,
        "timestamp": _now_iso(),
    }


def _create_forensic_snapshot(client: Any, event: dict[str, Any]) -> dict[str, Any]:
    """Create a named forensic snapshot on the affected volume.

    Args:
        client: ONTAP API client.
        event: Must contain 'volumeId' (ONTAP volume UUID).

    Returns:
        Snapshot creation result.
    """
    volume_uuid = event.get("volumeUuid") or event.get("volumeId", "")
    timestamp = event.get("timestamp", _now_iso())
    snapshot_name = f"forensic-{timestamp.replace(':', '-').replace('.', '-')[:19]}"

    logger.info(f"Creating forensic snapshot '{snapshot_name}' on volume {volume_uuid}")

    result = client.create_snapshot(volume_uuid, snapshot_name)

    return {
        "status": "snapshot_created",
        "volumeUuid": volume_uuid,
        "snapshotName": snapshot_name,
        "snapshotUuid": result.get("uuid", ""),
        "timestamp": _now_iso(),
    }


def _create_forensic_clone(client: Any, event: dict[str, Any]) -> dict[str, Any]:
    """Create a FlexClone for forensic investigation.

    Args:
        client: ONTAP API client.
        event: Must contain 'volumeId' (parent volume UUID) and 'svmUuid'.
               Optionally 'snapshotUuid' for point-in-time clone.

    Returns:
        Clone creation result.
    """
    volume_uuid = event.get("volumeUuid") or event.get("volumeId", "")
    svm_uuid = event.get("svmUuid") or event.get("svmId", "")
    snapshot_uuid = event.get("snapshotUuid", None)
    timestamp_suffix = str(int(time.time()))
    clone_name = f"forensic_clone_{timestamp_suffix}"

    logger.info(f"Creating forensic clone '{clone_name}' from volume {volume_uuid}")

    result = client.create_clone(
        svm_uuid=svm_uuid,
        parent_volume_uuid=volume_uuid,
        clone_name=clone_name,
        snapshot_uuid=snapshot_uuid,
    )

    return {
        "status": "clone_created",
        "cloneName": clone_name,
        "cloneUuid": result.get("uuid", ""),
        "parentVolumeUuid": volume_uuid,
        "svmUuid": svm_uuid,
        "timestamp": _now_iso(),
    }


def _get_client(event: dict[str, Any]) -> Any:
    """Create ONTAP client from environment and event properties."""
    from ontap_client import OntapClient

    management_endpoint = event.get("managementEndpoint") or os.environ.get(
        "FSX_MANAGEMENT_ENDPOINT", ""
    )
    secret_arn = os.environ.get("FSX_SECRET_ARN", "")

    if not management_endpoint:
        raise ValueError(
            "Management endpoint not provided. "
            "Set FSX_MANAGEMENT_ENDPOINT env var or pass 'managementEndpoint' in event."
        )
    if not secret_arn:
        raise ValueError("FSX_SECRET_ARN environment variable not set.")

    return OntapClient(
        management_endpoint=management_endpoint,
        secret_arn=secret_arn,
    )


def _now_iso() -> str:
    """Return current UTC time in ISO format."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
