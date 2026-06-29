"""Unit tests for Deep Instinct verdict_handler Lambda."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from verdict_handler import _map_detail_type, _map_severity, _parse_verdict, handler


class TestMapDetailType:
    """Tests for detail-type mapping from DI classification."""

    def test_malicious(self):
        assert _map_detail_type("malicious") == "MalwareDetected"

    def test_suspicious(self):
        assert _map_detail_type("suspicious") == "SuspiciousFileDetected"

    def test_benign(self):
        assert _map_detail_type("benign") == "FileScanClean"

    def test_unknown_classification(self):
        assert _map_detail_type("unknown") == "SecurityEvent"

    def test_case_insensitive(self):
        assert _map_detail_type("MALICIOUS") == "MalwareDetected"


class TestMapSeverity:
    """Tests for severity mapping from confidence + classification."""

    def test_malicious_high_confidence(self):
        assert _map_severity(0.95, "malicious") == "CRITICAL"

    def test_malicious_low_confidence(self):
        assert _map_severity(0.85, "malicious") == "HIGH"

    def test_malicious_boundary(self):
        assert _map_severity(0.9, "malicious") == "CRITICAL"

    def test_suspicious_high_confidence(self):
        assert _map_severity(0.75, "suspicious") == "MEDIUM"

    def test_suspicious_low_confidence(self):
        assert _map_severity(0.5, "suspicious") == "LOW"

    def test_benign(self):
        assert _map_severity(0.99, "benign") == "INFO"

    @given(
        confidence=st.floats(min_value=0.0, max_value=1.0),
        classification=st.sampled_from(["malicious", "suspicious", "benign"]),
    )
    @settings(max_examples=50)
    def test_always_returns_valid_severity(self, confidence, classification):
        """Property: severity mapping is total — always returns a valid level."""
        result = _map_severity(confidence, classification)
        assert result in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


class TestParseVerdict:
    """Tests for verdict record parsing."""

    def test_direct_format(self):
        record = {"file_path": "/data/test.exe", "classification": "malicious", "confidence": 0.95}
        result = _parse_verdict(record)
        assert result["file_path"] == "/data/test.exe"

    def test_cloudwatch_logs_format(self):
        inner = json.dumps({"file_path": "/data/test.exe", "classification": "benign", "confidence": 0.99})
        record = {"message": inner}
        result = _parse_verdict(record)
        assert result["classification"] == "benign"

    def test_body_string_format(self):
        inner = json.dumps({"file_path": "/data/test.exe", "classification": "suspicious", "confidence": 0.6})
        record = {"body": inner}
        result = _parse_verdict(record)
        assert result["confidence"] == 0.6

    def test_body_dict_format(self):
        record = {"body": {"file_path": "/data/test.exe", "classification": "malicious", "confidence": 0.9}}
        result = _parse_verdict(record)
        assert result is not None

    def test_invalid_message_returns_none(self):
        record = {"message": "not-json"}
        assert _parse_verdict(record) is None

    def test_empty_record_returns_none(self):
        assert _parse_verdict({}) is None


class TestHandler:
    """Tests for the main Lambda handler function."""

    @patch("verdict_handler.boto3.client")
    def test_handler_malicious_event(self, mock_boto, mock_env_vars):
        mock_events = MagicMock()
        mock_events.put_events.return_value = {"FailedEntryCount": 0}
        mock_boto.return_value = mock_events

        event = {
            "records": [
                {"file_path": "/vol/data/malware.exe", "classification": "malicious", "confidence": 0.95}
            ]
        }
        result = handler(event, None)

        assert result["statusCode"] == 200
        assert result["published"] == 1
        assert result["errors"] == []

        call_args = mock_events.put_events.call_args[1]["Entries"][0]
        assert call_args["DetailType"] == "MalwareDetected"
        detail = json.loads(call_args["Detail"])
        assert detail["severity"] == "CRITICAL"
        assert detail["scannerName"] == "deep-instinct"

    @patch("verdict_handler.boto3.client")
    def test_handler_skips_unparseable(self, mock_boto, mock_env_vars):
        mock_events = MagicMock()
        mock_boto.return_value = mock_events

        event = {"records": [{"garbage": "data"}]}
        result = handler(event, None)

        assert result["published"] == 0
        mock_events.put_events.assert_not_called()

    @patch("verdict_handler.boto3.client")
    def test_handler_multiple_records(self, mock_boto, mock_env_vars):
        mock_events = MagicMock()
        mock_events.put_events.return_value = {"FailedEntryCount": 0}
        mock_boto.return_value = mock_events

        event = {
            "records": [
                {"file_path": "/a.exe", "classification": "malicious", "confidence": 0.9},
                {"file_path": "/b.doc", "classification": "benign", "confidence": 0.99},
            ]
        }
        result = handler(event, None)
        assert result["published"] == 2
