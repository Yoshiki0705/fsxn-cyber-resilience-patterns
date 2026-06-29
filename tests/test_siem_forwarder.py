"""Unit tests for SIEM forwarder with PII redaction."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

os.environ["SIEM_FORMAT"] = "splunk"
os.environ["SIEM_ENDPOINT"] = ""
os.environ["REDACT_PII"] = "true"
os.environ["DLQ_BUCKET"] = ""
os.environ["ENVIRONMENT"] = "dev"

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "solutions", "siem"))

from siem_forwarder import (
    format_cef,
    format_qradar_leef,
    format_splunk_hec,
    handler,
    redact_pii,
)


class TestPiiRedaction:
    """Tests for PII redaction logic."""

    def test_redacts_client_ip(self):
        event = {"clientIp": "192.168.1.100", "filePath": "/test.exe"}
        result = redact_pii(event, ["clientIp"])
        assert result["clientIp"].startswith("REDACTED:")
        assert result["filePath"] == "/test.exe"

    def test_redacts_username(self):
        event = {"userName": "DOMAIN\\admin", "verdict": "CLEAN"}
        result = redact_pii(event, ["userName"])
        assert result["userName"].startswith("REDACTED:")
        assert result["verdict"] == "CLEAN"

    def test_redacts_nested_fields(self):
        event = {"detail": {"clientIp": "10.0.1.5", "safe": "value"}}
        result = redact_pii(event, ["clientIp"])
        assert result["detail"]["clientIp"].startswith("REDACTED:")
        assert result["detail"]["safe"] == "value"

    def test_empty_value_not_redacted(self):
        event = {"clientIp": "", "filePath": "/test"}
        result = redact_pii(event, ["clientIp"])
        assert result["clientIp"] == ""

    def test_non_string_not_redacted(self):
        event = {"clientIp": 12345, "filePath": "/test"}
        result = redact_pii(event, ["clientIp"])
        assert result["clientIp"] == 12345

    @given(
        ip=st.from_regex(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", fullmatch=True),
        username=st.text(min_size=4, max_size=50, alphabet=st.characters(categories=("L", "N"))),
    )
    @settings(max_examples=50)
    def test_pii_never_appears_in_output(self, ip, username):
        """Property: redacted fields never contain original values (min 4 chars)."""
        event = {"clientIp": ip, "userName": username, "safe": "keep"}
        result = redact_pii(event, ["clientIp", "userName"])
        output_str = json.dumps(result)
        assert ip not in output_str
        assert username not in output_str
        assert "keep" in output_str


class TestFormatSplunk:
    """Tests for Splunk HEC format."""

    def test_produces_valid_json_lines(self):
        events = [{"filePath": "/test.exe", "severity": "HIGH"}]
        output = format_splunk_hec(events)
        parsed = json.loads(output)
        assert parsed["sourcetype"] == "fsxn:security"
        assert parsed["event"]["filePath"] == "/test.exe"

    def test_multiple_events(self):
        events = [{"a": 1}, {"b": 2}]
        output = format_splunk_hec(events)
        lines = output.strip().split("\n")
        assert len(lines) == 2


class TestFormatQradar:
    """Tests for QRadar LEEF format."""

    def test_leef_header(self):
        events = [{"detail-type": "MalwareDetected", "severity": "9"}]
        output = format_qradar_leef(events)
        assert output.startswith("LEEF:2.0|NetApp|FSxONTAP|")

    def test_includes_fields(self):
        events = [{"filePath": "/malware.exe", "verdict": "MALICIOUS", "scannerName": "trendai"}]
        output = format_qradar_leef(events)
        assert "filePath=/malware.exe" in output
        assert "verdict=MALICIOUS" in output


class TestFormatCef:
    """Tests for CEF format."""

    def test_cef_header(self):
        events = [{"detail-type": "RansomwareDetected", "severity": "10"}]
        output = format_cef(events)
        assert output.startswith("CEF:0|FSxONTAP|")


class TestHandler:
    """Tests for the main forwarder handler."""

    @patch("siem_forwarder._forward_batch", return_value=True)
    def test_handler_processes_sqs_batch(self, mock_forward):
        event = {
            "Records": [
                {"body": json.dumps({"filePath": "/a.exe", "clientIp": "10.0.1.1", "verdict": "MALICIOUS"})},
                {"body": json.dumps({"filePath": "/b.doc", "clientIp": "10.0.1.2", "verdict": "CLEAN"})},
            ]
        }
        result = handler(event, None)
        assert result["forwarded"] == 2
        assert result["failed"] == 0

        # Verify PII was redacted before forwarding
        forwarded_events = mock_forward.call_args[0][0]
        for evt in forwarded_events:
            assert "10.0.1" not in json.dumps(evt)

    @patch("siem_forwarder._forward_batch", return_value=False)
    @patch("siem_forwarder._store_dead_letter")
    def test_handler_dead_letters_on_failure(self, mock_dlq, mock_forward):
        event = {"Records": [{"body": json.dumps({"test": "data"})}]}
        result = handler(event, None)
        assert result["failed"] == 1
        mock_dlq.assert_called_once()
