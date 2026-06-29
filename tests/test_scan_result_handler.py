"""Unit tests for TrendAI scan_result_handler Lambda."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from hypothesis import given, settings
from hypothesis import strategies as st

from scan_result_handler import (
    _classify_severity,
    _extract_body,
    _map_detail_type,
    _normalize_verdict,
    handler,
)


class TestExtractBody:
    """Tests for SQS/SNS record body extraction."""

    def test_sqs_record(self):
        record = {"body": json.dumps({"file_path": "/test.exe", "verdict": "infected"})}
        result = _extract_body(record)
        assert result["verdict"] == "infected"

    def test_sns_wrapped_in_sqs(self):
        inner = json.dumps({"file_path": "/test.exe", "verdict": "clean"})
        record = {"body": json.dumps({"Message": inner})}
        result = _extract_body(record)
        assert result["verdict"] == "clean"

    def test_direct_invocation(self):
        record = {"file_path": "/test.exe", "verdict": "infected"}
        result = _extract_body(record)
        assert result["file_path"] == "/test.exe"

    def test_invalid_body_returns_none(self):
        record = {"body": "not-json{{{"}
        assert _extract_body(record) is None

    def test_empty_record(self):
        assert _extract_body({}) is None


class TestNormalizeVerdict:
    """Tests for verdict normalization across formats."""

    def test_standard_format(self):
        body = {
            "file_path": "/data/file.exe",
            "verdict": "infected",
            "malware_name": "Trojan.Gen",
        }
        result = _normalize_verdict(body)
        assert result["file_path"] == "/data/file.exe"
        assert result["verdict"] == "infected"

    def test_trendai_api_format(self):
        body = {
            "filePath": "/data/file.exe",
            "scanResult": "INFECTED",
            "malwareName": "Ransom.WannaCry",
        }
        result = _normalize_verdict(body)
        assert result["file_path"] == "/data/file.exe"
        assert result["verdict"] == "infected"
        assert result["malware_name"] == "Ransom.WannaCry"

    def test_s3ap_batch_format(self):
        body = {
            "objectKey": "/vol/data/suspicious.dll",
            "status": "MALICIOUS",
            "details": {"malwareName": "Exploit.CVE"},
        }
        result = _normalize_verdict(body)
        assert result["file_path"] == "/vol/data/suspicious.dll"
        assert result["verdict"] == "infected"
        assert result["scan_type"] == "batch"

    def test_s3ap_clean_result(self):
        body = {"objectKey": "/vol/data/clean.pdf", "status": "CLEAN", "details": {}}
        result = _normalize_verdict(body)
        assert result["verdict"] == "clean"

    def test_unknown_format_returns_none(self):
        assert _normalize_verdict({"random": "data"}) is None

    @given(
        verdict=st.sampled_from(["infected", "malicious", "suspicious", "clean"]),
        file_path=st.text(min_size=1, max_size=100),
    )
    @settings(max_examples=50)
    def test_standard_format_always_normalizes(self, verdict, file_path):
        """Property: all valid standard payloads normalize successfully."""
        body = {"file_path": file_path, "verdict": verdict}
        result = _normalize_verdict(body)
        assert result is not None
        assert result["verdict"] == verdict


class TestMapDetailType:
    """Tests for verdict → detail-type mapping."""

    def test_infected(self):
        assert _map_detail_type("infected") == "MalwareDetected"

    def test_malicious(self):
        assert _map_detail_type("malicious") == "MalwareDetected"

    def test_suspicious(self):
        assert _map_detail_type("suspicious") == "SuspiciousFileDetected"

    def test_clean(self):
        assert _map_detail_type("clean") == "FileScanClean"

    def test_unknown(self):
        assert _map_detail_type("unknown") == "SecurityEvent"


class TestClassifySeverity:
    """Tests for severity classification."""

    def test_infected_ransomware(self):
        verdict = {"verdict": "infected", "malware_name": "Ransom.WannaCry"}
        assert _classify_severity(verdict) == "CRITICAL"

    def test_infected_generic(self):
        verdict = {"verdict": "infected", "malware_name": "Trojan.Generic"}
        assert _classify_severity(verdict) == "HIGH"

    def test_suspicious(self):
        verdict = {"verdict": "suspicious", "malware_name": ""}
        assert _classify_severity(verdict) == "MEDIUM"

    def test_clean(self):
        verdict = {"verdict": "clean", "malware_name": ""}
        assert _classify_severity(verdict) == "INFO"

    def test_ransomware_keywords(self):
        for keyword in ["ransom", "crypt", "locker", "wannacry"]:
            verdict = {
                "verdict": "malicious",
                "malware_name": f"Test.{keyword}.variant",
            }
            assert _classify_severity(verdict) == "CRITICAL"


class TestHandler:
    """Tests for the main Lambda handler."""

    @patch("scan_result_handler.boto3.client")
    def test_handler_sqs_event(self, mock_boto, mock_env_vars):
        mock_events = MagicMock()
        mock_events.put_events.return_value = {"FailedEntryCount": 0}
        mock_boto.return_value = mock_events

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "file_path": "/vol/data/virus.exe",
                            "verdict": "infected",
                            "malware_name": "Trojan",
                        }
                    )
                }
            ]
        }
        result = handler(event, None)
        assert result["published"] == 1

        call_args = mock_events.put_events.call_args[1]["Entries"][0]
        assert call_args["DetailType"] == "MalwareDetected"
        detail = json.loads(call_args["Detail"])
        assert detail["scannerName"] == "trendai"
        assert detail["severity"] == "HIGH"

    @patch("scan_result_handler.boto3.client")
    def test_handler_batch_scan_result(self, mock_boto, mock_env_vars):
        mock_events = MagicMock()
        mock_events.put_events.return_value = {"FailedEntryCount": 0}
        mock_boto.return_value = mock_events

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "objectKey": "/vol/data/mal.dll",
                            "status": "MALICIOUS",
                            "details": {"malwareName": "Ransom.Lock"},
                        }
                    )
                }
            ]
        }
        result = handler(event, None)
        assert result["published"] == 1

        detail = json.loads(mock_events.put_events.call_args[1]["Entries"][0]["Detail"])
        assert detail["severity"] == "CRITICAL"
        assert detail["scanType"] == "batch"
