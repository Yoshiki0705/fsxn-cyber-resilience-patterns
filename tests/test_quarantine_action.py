"""Unit tests for Quarantine Action Lambda.

Tests the ONTAP API-driven quarantine operations with mocked OntapClient.
"""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

os.environ["FSX_SECRET_ARN"] = "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:test-secret"
os.environ["FSX_MANAGEMENT_ENDPOINT"] = "management.fs-0123456789abcdef0.fsx.ap-northeast-1.amazonaws.com"
os.environ["ENVIRONMENT"] = "dev"


class TestQuarantineAction:
    """Test quarantine action routing and execution."""

    @patch("quarantine_action._get_client")
    def test_restrict_export_policy(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.get_export_policy.return_value = {"id": 42}
        mock_client.restrict_export_policy.return_value = {}
        mock_get_client.return_value = mock_client

        from quarantine_action import handler

        event = {
            "action": "restrict_export_policy",
            "svmUuid": "svm-uuid-123",
            "volumeId": "fsvol-0123456789abcdef0",
        }

        result = handler(event, None)

        assert result["status"] == "quarantined"
        assert result["policyId"] == 42
        mock_client.restrict_export_policy.assert_called_once_with(42)

    @patch("quarantine_action._get_client")
    def test_restore_export_policy(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.get_export_policy.return_value = {"id": 42}
        mock_client.restore_export_policy.return_value = {}
        mock_get_client.return_value = mock_client

        from quarantine_action import handler

        event = {
            "action": "restore_export_policy",
            "svmUuid": "svm-uuid-123",
            "volumeId": "fsvol-0123456789abcdef0",
            "clientMatch": "10.0.0.0/16",
        }

        result = handler(event, None)

        assert result["status"] == "restored"
        assert result["clientMatch"] == "10.0.0.0/16"
        mock_client.restore_export_policy.assert_called_once_with(42, "10.0.0.0/16")

    @patch("quarantine_action._get_client")
    def test_create_forensic_snapshot(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.create_snapshot.return_value = {"uuid": "snap-uuid-456"}
        mock_get_client.return_value = mock_client

        from quarantine_action import handler

        event = {
            "action": "create_forensic_snapshot",
            "volumeUuid": "vol-uuid-789",
            "timestamp": "2026-06-25T10:30:00Z",
        }

        result = handler(event, None)

        assert result["status"] == "snapshot_created"
        assert result["snapshotUuid"] == "snap-uuid-456"
        assert "forensic-" in result["snapshotName"]
        mock_client.create_snapshot.assert_called_once()

    @patch("quarantine_action._get_client")
    def test_create_forensic_clone(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.create_clone.return_value = {"uuid": "clone-uuid-101"}
        mock_get_client.return_value = mock_client

        from quarantine_action import handler

        event = {
            "action": "create_forensic_clone",
            "volumeUuid": "vol-uuid-789",
            "svmUuid": "svm-uuid-123",
            "snapshotUuid": "snap-uuid-456",
        }

        result = handler(event, None)

        assert result["status"] == "clone_created"
        assert result["cloneUuid"] == "clone-uuid-101"
        assert "forensic_clone_" in result["cloneName"]
        mock_client.create_clone.assert_called_once()

    @patch("quarantine_action._get_client")
    def test_unknown_action_raises(self, mock_get_client: MagicMock) -> None:
        mock_get_client.return_value = MagicMock()

        from quarantine_action import handler

        with pytest.raises(ValueError, match="Unknown action"):
            handler({"action": "invalid_action"}, None)

    @patch("quarantine_action._get_client")
    def test_restrict_policy_not_found(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.get_export_policy.return_value = {}
        mock_get_client.return_value = mock_client

        from quarantine_action import handler

        event = {
            "action": "restrict_export_policy",
            "svmUuid": "svm-uuid-123",
            "volumeId": "fsvol-0123456789abcdef0",
        }

        result = handler(event, None)

        assert result["status"] == "warning"
        assert "not found" in result["message"].lower()
