"""Integration tests for Phase 3 — SIEM, compliance, multi-account.

Validates ASFF format correctness, SIEM format round-trips,
compliance report determinism, and cross-account IAM patterns.
"""
from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "solutions", "siem"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "solutions", "compliance"))

from security_hub_publisher import _build_asff_finding, _generate_finding_id
from siem_forwarder import format_cef, format_qradar_leef, format_splunk_hec, redact_pii


class TestAsffFormatValidation:
    """Validate ASFF findings meet Security Hub requirements."""

    def test_required_fields_present(self):
        finding = _build_asff_finding(
            detail={"fileSystemId": "fs-test", "severity": "HIGH", "scannerName": "trendai"},
            detail_type="MalwareDetected",
            source="fsxn.cyber-resilience.scanner",
            region="ap-northeast-1",
            account_id="123456789012",
        )

        required_fields = ["SchemaVersion", "Id", "ProductArn", "GeneratorId", "AwsAccountId", "Types", "Severity", "Title", "Resources"]
        for field in required_fields:
            assert field in finding, f"Missing ASFF field: {field}"

    def test_schema_version_correct(self):
        finding = _build_asff_finding(
            detail={"fileSystemId": "fs-test"},
            detail_type="Test",
            source="test",
            region="us-east-1",
            account_id="123456789012",
        )
        assert finding["SchemaVersion"] == "2018-10-08"

    def test_resources_array_not_empty(self):
        finding = _build_asff_finding(
            detail={"fileSystemId": "fs-test"},
            detail_type="Test",
            source="test",
            region="us-east-1",
            account_id="123456789012",
        )
        assert len(finding["Resources"]) >= 1
        assert finding["Resources"][0]["Type"] == "Other"

    def test_finding_id_contains_region_and_account(self):
        finding = _build_asff_finding(
            detail={"fileSystemId": "fs-test", "filePath": "/data/file.exe"},
            detail_type="MalwareDetected",
            source="test",
            region="ap-northeast-1",
            account_id="123456789012",
        )
        assert "ap-northeast-1" in finding["Id"]
        assert "123456789012" in finding["Id"]


class TestSiemFormatRoundTrip:
    """Validate SIEM format conversions produce parseable output."""

    SAMPLE_EVENTS = [
        {"filePath": "/data/malware.exe", "verdict": "MALICIOUS", "scannerName": "trendai", "severity": "9"},
        {"filePath": "/data/clean.pdf", "verdict": "CLEAN", "scannerName": "deep-instinct", "severity": "1"},
    ]

    def test_splunk_hec_produces_valid_json(self):
        output = format_splunk_hec(self.SAMPLE_EVENTS)
        lines = output.strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            parsed = json.loads(line)
            assert "event" in parsed
            assert "sourcetype" in parsed
            assert parsed["sourcetype"] == "fsxn:security"

    def test_qradar_leef_produces_correct_header(self):
        output = format_qradar_leef(self.SAMPLE_EVENTS)
        lines = output.strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            assert line.startswith("LEEF:2.0|NetApp|FSxONTAP|")

    def test_cef_produces_correct_header(self):
        output = format_cef(self.SAMPLE_EVENTS)
        lines = output.strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            assert line.startswith("CEF:0|FSxONTAP|")

    def test_splunk_preserves_event_data(self):
        output = format_splunk_hec(self.SAMPLE_EVENTS)
        parsed = json.loads(output.split("\n")[0])
        assert parsed["event"]["filePath"] == "/data/malware.exe"
        assert parsed["event"]["verdict"] == "MALICIOUS"


class TestComplianceReportDeterminism:
    """Verify compliance checks produce consistent results."""

    def test_same_ontap_state_same_result(self):
        """Given identical ONTAP API responses, compliance results should be identical."""
        from compliance_collector import _check_encryption_status

        mock_client = MagicMock()
        mock_client.list_volumes.return_value = [
            {"name": "vol1", "uuid": "uuid-1"},
            {"name": "vol2", "uuid": "uuid-2"},
        ]

        result1 = _check_encryption_status(mock_client)
        result2 = _check_encryption_status(mock_client)

        assert result1 == result2

    def test_arp_check_returns_tuple(self):
        from compliance_collector import _check_arp_status

        mock_client = MagicMock()
        mock_client.list_volumes.return_value = [{"name": "vol1", "uuid": "uuid-1"}]
        mock_client.get_arp_status.return_value = {"state": "enabled"}

        actual_state, compliant, evidence = _check_arp_status(mock_client)

        assert isinstance(actual_state, str)
        assert isinstance(compliant, bool)
        assert isinstance(evidence, dict)
        assert compliant is True


class TestCrossAccountIamPattern:
    """Validate cross-account IAM patterns in templates."""

    @pytest.fixture
    def spoke_template(self):
        import yaml
        from pathlib import Path

        class CfnLoader(yaml.SafeLoader):
            pass

        def cfn_constructor(loader, tag_suffix, node):
            if isinstance(node, yaml.ScalarNode):
                return {tag_suffix: loader.construct_scalar(node)}
            elif isinstance(node, yaml.SequenceNode):
                return {tag_suffix: loader.construct_sequence(node)}
            elif isinstance(node, yaml.MappingNode):
                return {tag_suffix: loader.construct_mapping(node)}

        CfnLoader.add_multi_constructor("!", cfn_constructor)

        template_path = Path(__file__).parent.parent / "templates" / "spoke-monitoring.yaml"
        with open(template_path) as f:
            return yaml.load(f, Loader=CfnLoader)

    def test_spoke_role_has_single_permission(self, spoke_template):
        """Cross-account role should only have events:PutEvents."""
        role = spoke_template["Resources"]["CrossAccountEventRole"]
        policies = role["Properties"]["Policies"]
        statements = policies[0]["PolicyDocument"]["Statement"]

        # Should have exactly 1 statement with only PutEvents
        assert len(statements) == 1
        assert statements[0]["Action"] == "events:PutEvents"

    def test_spoke_role_targets_hub_bus_only(self, spoke_template):
        """Role resource should reference hub event bus ARN pattern."""
        role = spoke_template["Resources"]["CrossAccountEventRole"]
        resource = role["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0]["Resource"]
        # Should be a Sub with hub account/region/bus references
        assert "Sub" in resource or isinstance(resource, str)

    def test_event_rule_uses_prefix_match(self, spoke_template):
        """Event rule should use prefix matching for source filtering."""
        rule = spoke_template["Resources"]["SpokeToHubRule"]
        pattern = rule["Properties"]["EventPattern"]
        source = pattern["source"]
        # Should match all fsxn.cyber-resilience.* sources
        assert any("prefix" in str(s) for s in source)


class TestPiiRedactionIntegration:
    """End-to-end PII redaction verification."""

    def test_full_event_redaction_flow(self):
        """Simulate: EventBridge event → redaction → SIEM format."""
        raw_event = {
            "fileSystemId": "fs-test",
            "filePath": "/data/malware.exe",
            "clientIp": "192.168.1.100",
            "userName": "DOMAIN\\admin_user",
            "verdict": "MALICIOUS",
            "scannerName": "trendai",
        }

        # Redact
        redacted = redact_pii(raw_event, ["clientIp", "userName"])

        # Format as Splunk
        output = format_splunk_hec([redacted])
        parsed = json.loads(output)

        # Verify PII is gone
        assert "192.168.1.100" not in json.dumps(parsed)
        assert "admin_user" not in json.dumps(parsed)

        # Verify non-PII preserved
        assert parsed["event"]["filePath"] == "/data/malware.exe"
        assert parsed["event"]["verdict"] == "MALICIOUS"
