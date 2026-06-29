"""Unit tests for ARP Lifecycle Manager Lambda."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest


# Patch env vars before importing module
os.environ["STATE_TABLE_NAME"] = "test-arp-state"
os.environ["FSX_SECRET_ARN"] = "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:test"
os.environ["MANAGEMENT_ENDPOINT"] = "management.fs-test.fsx.ap-northeast-1.amazonaws.com"
os.environ["SNS_TOPIC_ARN"] = "arn:aws:sns:ap-northeast-1:123456789012:test-topic"
os.environ["LEARNING_DAYS"] = "30"

import arp_lifecycle


class TestArpLifecycleHandler:
    """Tests for the daily lifecycle check handler."""

    @patch("arp_lifecycle.boto3.resource")
    @patch("arp_lifecycle.boto3.client")
    def test_no_volumes_in_dry_run(self, mock_client, mock_resource):
        mock_table = MagicMock()
        mock_table.scan.return_value = {"Items": []}
        mock_resource.return_value.Table.return_value = mock_table

        result = arp_lifecycle.handler({}, None)

        assert result["checked"] == 0
        assert result["transitioned"] == 0

    @patch("arp_lifecycle.boto3.resource")
    @patch("arp_lifecycle.boto3.client")
    def test_volume_not_yet_ready(self, mock_client, mock_resource):
        """Volume within learning period should not transition."""
        mock_table = MagicMock()
        recent_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        mock_table.scan.return_value = {
            "Items": [
                {"volume_uuid": "vol-001", "arp_start_date": recent_date, "current_state": "dry_run", "learning_days": 30}
            ]
        }
        mock_resource.return_value.Table.return_value = mock_table

        result = arp_lifecycle.handler({}, None)

        assert result["checked"] == 1
        assert result["transitioned"] == 0

    @patch("arp_lifecycle._transition_arp")
    @patch("arp_lifecycle.boto3.resource")
    @patch("arp_lifecycle.boto3.client")
    def test_volume_ready_for_transition(self, mock_client, mock_resource, mock_transition):
        """Volume past learning period should transition."""
        mock_table = MagicMock()
        old_date = (datetime.now(timezone.utc) - timedelta(days=35)).isoformat()
        mock_table.scan.return_value = {
            "Items": [
                {"volume_uuid": "vol-001", "arp_start_date": old_date, "current_state": "dry_run", "learning_days": 30}
            ]
        }
        mock_resource.return_value.Table.return_value = mock_table

        result = arp_lifecycle.handler({}, None)

        assert result["checked"] == 1
        assert result["transitioned"] == 1
        mock_transition.assert_called_once()

    @patch("arp_lifecycle._transition_arp")
    @patch("arp_lifecycle.boto3.resource")
    @patch("arp_lifecycle.boto3.client")
    def test_transition_failure_recorded(self, mock_client, mock_resource, mock_transition):
        """Failed transitions should be recorded in errors."""
        mock_table = MagicMock()
        old_date = (datetime.now(timezone.utc) - timedelta(days=35)).isoformat()
        mock_table.scan.return_value = {
            "Items": [
                {"volume_uuid": "vol-fail", "arp_start_date": old_date, "current_state": "dry_run", "learning_days": 30}
            ]
        }
        mock_resource.return_value.Table.return_value = mock_table
        mock_transition.side_effect = Exception("ONTAP API error")

        result = arp_lifecycle.handler({}, None)

        assert result["checked"] == 1
        assert result["transitioned"] == 0
        assert len(result["errors"]) == 1
        assert "vol-fail" in result["errors"][0]["volume_uuid"]


class TestTransitionArp:
    """Tests for the ARP state transition function."""

    @patch("ontap_client.OntapClient")
    def test_transition_calls_ontap_and_updates_dynamo(self, mock_client_class):
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_table = MagicMock()
        mock_sns = MagicMock()

        with patch("arp_lifecycle.MANAGEMENT_ENDPOINT", "test.endpoint"):
            with patch("arp_lifecycle.FSX_SECRET_ARN", "test-secret"):
                arp_lifecycle._transition_arp("vol-001", mock_table, mock_sns)

        # SNS notification sent
        mock_sns.publish.assert_called_once()
        assert "vol-001" in mock_sns.publish.call_args[1]["Subject"]

        # ONTAP API called
        mock_client.enable_arp.assert_called_once_with("vol-001", state="enabled")

        # DynamoDB updated
        mock_table.update_item.assert_called_once()
        update_args = mock_table.update_item.call_args[1]
        assert update_args["ExpressionAttributeValues"][":state"] == "enabled"
