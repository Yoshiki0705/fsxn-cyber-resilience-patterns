"""Unit tests for Event Transformer Lambda.

Tests the SQS → EventBridge transformation logic using moto mocks.
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch


# Set environment variables before importing handler
os.environ["EVENT_BUS_NAME"] = "test-security-bus"
os.environ["ENVIRONMENT"] = "dev"

import event_transformer

# Ensure module-level EVENT_BUS_NAME is set correctly for this test file
event_transformer.EVENT_BUS_NAME = "test-security-bus"

from event_transformer import (  # noqa: E402
    _classify_detail_type,
    _classify_severity,
    _transform_event,
    handler,
)


class TestClassifyDetailType:
    """Test event classification logic."""

    def test_malicious_verdict(self) -> None:
        assert _classify_detail_type("file_write", "MALICIOUS") == "MalwareDetected"

    def test_infected_verdict(self) -> None:
        assert _classify_detail_type("file_write", "INFECTED") == "MalwareDetected"

    def test_suspicious_verdict(self) -> None:
        assert _classify_detail_type("file_write", "SUSPICIOUS") == "SuspiciousActivity"

    def test_ransomware_event_type(self) -> None:
        assert _classify_detail_type("ransomware_detected", "") == "RansomwareDetected"

    def test_arp_alert(self) -> None:
        assert _classify_detail_type("arp_alert", "") == "RansomwareDetected"

    def test_normal_file_event(self) -> None:
        assert _classify_detail_type("file_write", "") == "FileEvent"

    def test_clean_verdict(self) -> None:
        assert _classify_detail_type("file_write", "CLEAN") == "FileEvent"


class TestClassifySeverity:
    """Test severity classification."""

    def test_malicious_is_critical(self) -> None:
        assert _classify_severity("file_write", "MALICIOUS") == "CRITICAL"

    def test_infected_is_critical(self) -> None:
        assert _classify_severity("file_write", "INFECTED") == "CRITICAL"

    def test_suspicious_is_high(self) -> None:
        assert _classify_severity("file_write", "SUSPICIOUS") == "HIGH"

    def test_ransomware_detected_is_critical(self) -> None:
        assert _classify_severity("ransomware_detected", "") == "CRITICAL"

    def test_arp_alert_is_high(self) -> None:
        assert _classify_severity("arp_alert", "") == "HIGH"

    def test_default_is_low(self) -> None:
        assert _classify_severity("file_write", "") == "LOW"


class TestTransformEvent:
    """Test raw event → EventBridge entry transformation."""

    def test_fpolicy_event_transform(self) -> None:
        raw = {
            "source": "fpolicy",
            "event_type": "file_write",
            "file_system_id": "fs-0123456789abcdef0",
            "svm_id": "svm-0123456789abcdef0",
            "volume_id": "fsvol-0123456789abcdef0",
            "file_path": "/production/test.exe",
            "client_ip": "10.0.x.x",
            "user_name": "DOMAIN\\user1",
            "timestamp": "2026-06-25T10:30:00Z",
        }
        entry = _transform_event(raw)

        assert entry["Source"] == "fsxn.cyber-resilience.fpolicy"
        assert entry["DetailType"] == "FileEvent"
        assert entry["EventBusName"] == "test-security-bus"

        detail = json.loads(entry["Detail"])
        assert detail["fileSystemId"] == "fs-0123456789abcdef0"
        assert detail["volumeId"] == "fsvol-0123456789abcdef0"
        assert detail["severity"] == "LOW"

    def test_scanner_malicious_transform(self) -> None:
        raw = {
            "source": "scanner",
            "scanner_name": "trendai",
            "verdict": "MALICIOUS",
            "file_path": "/production/malware.exe",
            "volume_id": "fsvol-0123456789abcdef0",
            "svm_id": "svm-0123456789abcdef0",
            "file_system_id": "fs-0123456789abcdef0",
            "timestamp": "2026-06-25T10:30:00Z",
        }
        entry = _transform_event(raw)

        assert entry["Source"] == "fsxn.cyber-resilience.scanner"
        assert entry["DetailType"] == "MalwareDetected"

        detail = json.loads(entry["Detail"])
        assert detail["severity"] == "CRITICAL"
        assert detail["scannerName"] == "trendai"
        assert detail["verdict"] == "MALICIOUS"

    def test_arp_event_transform(self) -> None:
        raw = {
            "source": "arp",
            "event_type": "ransomware_detected",
            "file_system_id": "fs-0123456789abcdef0",
            "volume_id": "fsvol-0123456789abcdef0",
            "snapshot_name": "anti_ransomware_backup.2026-06-25_1030",
            "affected_files_count": 150,
            "timestamp": "2026-06-25T10:30:00Z",
        }
        entry = _transform_event(raw)

        assert entry["Source"] == "fsxn.cyber-resilience.arp"
        assert entry["DetailType"] == "RansomwareDetected"

        detail = json.loads(entry["Detail"])
        assert detail["severity"] == "CRITICAL"
        assert (
            detail["metadata"]["snapshot_name"]
            == "anti_ransomware_backup.2026-06-25_1030"
        )
        assert detail["metadata"]["affected_files_count"] == 150


class TestHandler:
    """Test the Lambda handler with mocked EventBridge."""

    @patch("event_transformer.events_client")
    def test_handler_processes_sqs_records(self, mock_events: MagicMock) -> None:
        mock_events.put_events.return_value = {
            "FailedEntryCount": 0,
            "Entries": [{"EventId": "123"}],
        }

        event = {
            "Records": [
                {
                    "messageId": "msg-001",
                    "body": json.dumps(
                        {
                            "source": "fpolicy",
                            "event_type": "file_write",
                            "file_system_id": "fs-0123456789abcdef0",
                            "svm_id": "svm-0123456789abcdef0",
                            "volume_id": "fsvol-0123456789abcdef0",
                            "timestamp": "2026-06-25T10:30:00Z",
                        }
                    ),
                }
            ]
        }

        result = handler(event, None)

        assert result["statusCode"] == 200
        assert result["published"] == 1
        assert result["failures"] == 0
        mock_events.put_events.assert_called_once()

    @patch("event_transformer.events_client")
    def test_handler_reports_parse_failures(self, mock_events: MagicMock) -> None:
        event = {
            "Records": [
                {
                    "messageId": "msg-bad",
                    "body": "not-valid-json{{{",
                }
            ]
        }

        result = handler(event, None)

        assert result["statusCode"] == 200
        assert result["published"] == 0
        assert "batchItemFailures" in result
        assert result["batchItemFailures"][0]["itemIdentifier"] == "msg-bad"
        mock_events.put_events.assert_not_called()

    @patch("event_transformer.events_client")
    def test_handler_multiple_records_batch(self, mock_events: MagicMock) -> None:
        mock_events.put_events.return_value = {
            "FailedEntryCount": 0,
            "Entries": [{"EventId": f"id-{i}"} for i in range(3)],
        }

        records = []
        for i in range(3):
            records.append(
                {
                    "messageId": f"msg-{i:03d}",
                    "body": json.dumps(
                        {
                            "source": "fpolicy",
                            "event_type": "file_write",
                            "file_system_id": "fs-0123456789abcdef0",
                            "svm_id": "svm-0123456789abcdef0",
                            "volume_id": "fsvol-0123456789abcdef0",
                            "timestamp": "2026-06-25T10:30:00Z",
                        }
                    ),
                }
            )

        result = handler({"Records": records}, None)

        assert result["published"] == 3
        assert result["failures"] == 0
