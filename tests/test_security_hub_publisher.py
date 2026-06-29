"""Unit tests for Security Hub publisher."""

from __future__ import annotations

import os
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

os.environ["PRODUCT_ARN"] = "arn:aws:securityhub:ap-northeast-1:123456789012:product/123456789012/fsxn"
os.environ["ENVIRONMENT"] = "dev"

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "solutions", "siem"))

from security_hub_publisher import (
    _build_asff_finding,
    _generate_finding_id,
    _map_finding_type,
    handler,
)


class TestBuildAsffFinding:
    """Tests for ASFF finding construction."""

    def test_basic_finding_structure(self):
        finding = _build_asff_finding(
            detail={
                "fileSystemId": "fs-test",
                "filePath": "/data/malware.exe",
                "severity": "CRITICAL",
                "scannerName": "trendai",
                "verdict": "MALICIOUS",
            },
            detail_type="MalwareDetected",
            source="fsxn.cyber-resilience.scanner",
            region="ap-northeast-1",
            account_id="123456789012",
        )

        assert finding["SchemaVersion"] == "2018-10-08"
        assert "123456789012" in finding["Id"]
        assert finding["Severity"]["Label"] == "CRITICAL"
        assert finding["Resources"][0]["Type"] == "Other"
        assert "fs-test" in finding["Resources"][0]["Id"]

    def test_finding_includes_file_path(self):
        finding = _build_asff_finding(
            detail={"fileSystemId": "fs-test", "filePath": "/important/doc.exe", "severity": "HIGH"},
            detail_type="MalwareDetected",
            source="test",
            region="us-east-1",
            account_id="123456789012",
        )
        assert "/important/doc.exe" in finding["Title"]
        assert finding["Resources"][0]["Details"]["Other"]["filePath"] == "/important/doc.exe"

    def test_severity_mapping(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            finding = _build_asff_finding(
                detail={"fileSystemId": "fs-test", "severity": sev},
                detail_type="SecurityEvent",
                source="test",
                region="us-east-1",
                account_id="123456789012",
            )
            assert "Label" in finding["Severity"]


class TestFindingIdDeduplication:
    """Tests for deterministic FindingId generation."""

    def test_same_input_same_id(self):
        id1 = _generate_finding_id("us-east-1", "123456789012", "fs-test", "/file.exe", "2026-01-01T00:00:00Z")
        id2 = _generate_finding_id("us-east-1", "123456789012", "fs-test", "/file.exe", "2026-01-01T00:00:00Z")
        assert id1 == id2

    def test_different_file_different_id(self):
        id1 = _generate_finding_id("us-east-1", "123456789012", "fs-test", "/a.exe", "2026-01-01T00:00:00Z")
        id2 = _generate_finding_id("us-east-1", "123456789012", "fs-test", "/b.exe", "2026-01-01T00:00:00Z")
        assert id1 != id2

    @given(
        file_path=st.text(min_size=1, max_size=200),
        timestamp=st.text(min_size=10, max_size=30),
    )
    @settings(max_examples=50)
    def test_always_produces_valid_id(self, file_path, timestamp):
        """Property: FindingId is always non-empty and contains region/account."""
        result = _generate_finding_id("us-east-1", "123456789012", "fs-test", file_path, timestamp)
        assert result
        assert "us-east-1" in result
        assert "123456789012" in result


class TestFindingTypeMapping:
    """Tests for detail-type → ASFF type mapping."""

    def test_malware_type(self):
        assert "Malware" in _map_finding_type("MalwareDetected")

    def test_ransomware_type(self):
        assert "Malware" in _map_finding_type("RansomwareDetected")

    def test_suspicious_type(self):
        assert "Unusual" in _map_finding_type("SuspiciousActivity")

    def test_unknown_type(self):
        result = _map_finding_type("UnknownEvent")
        assert result  # Should return a default


class TestHandler:
    """Tests for the main handler."""

    @patch("security_hub_publisher.securityhub")
    @patch("security_hub_publisher._get_account_id", return_value="123456789012")
    def test_handler_success(self, mock_account, mock_sh):
        mock_sh.batch_import_findings.return_value = {"FailedCount": 0, "SuccessCount": 1}

        event = {
            "detail-type": "MalwareDetected",
            "source": "fsxn.cyber-resilience.scanner",
            "account": "123456789012",
            "detail": {
                "fileSystemId": "fs-test",
                "filePath": "/test.exe",
                "severity": "HIGH",
                "scannerName": "trendai",
                "verdict": "MALICIOUS",
            },
        }

        result = handler(event, None)
        assert result["published"] == 1
        mock_sh.batch_import_findings.assert_called_once()

    @patch("security_hub_publisher.securityhub")
    @patch("security_hub_publisher._get_account_id", return_value="123456789012")
    def test_handler_failure(self, mock_account, mock_sh):
        mock_sh.batch_import_findings.side_effect = Exception("Access denied")

        event = {"detail-type": "Test", "source": "test", "detail": {"fileSystemId": "fs-test"}}
        result = handler(event, None)
        assert result["published"] == 0
        assert "error" in result
