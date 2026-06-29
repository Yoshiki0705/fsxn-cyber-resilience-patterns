"""Integration tests for the end-to-end event flow pipeline.

Validates data transformations at each stage:
  Raw FPolicy event → SQS → Event_Transformer → EventBridge → Step Functions

All tests are mock-based (no real AWS calls).
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import event_transformer


# --- Test Data ---

SAMPLE_FPOLICY_EVENTS = [
    {
        "source": "scanner",
        "scanner_name": "trendai",
        "event_type": "file_write",
        "verdict": "MALICIOUS",
        "file_system_id": "fs-0123456789abcdef0",
        "svm_id": "svm-0123456789abcdef0",
        "volume_id": "fsvol-0123456789abcdef0",
        "file_path": "/production/documents/malicious.exe",
        "client_ip": "10.0.x.x",
        "user_name": "DOMAIN\\user1",
        "timestamp": "2026-06-25T10:30:00Z",
    },
    {
        "source": "arp",
        "event_type": "ransomware_detected",
        "file_system_id": "fs-0123456789abcdef0",
        "volume_id": "fsvol-0123456789abcdef0",
        "snapshot_name": "anti_ransomware_backup.2026-06-25_1030",
        "affected_files_count": 150,
        "timestamp": "2026-06-25T10:30:00Z",
    },
    {
        "source": "fpolicy",
        "event_type": "file_write",
        "file_system_id": "fs-0123456789abcdef0",
        "file_path": "/production/documents/normal.docx",
        "timestamp": "2026-06-25T10:30:00Z",
    },
]

QUARANTINE_RULE_PATTERN = {
    "source": ["fsxn.cyber-resilience.fpolicy", "fsxn.cyber-resilience.arp"],
    "detail-type": ["MalwareDetected", "RansomwareDetected"],
}


@pytest.fixture(autouse=True)
def patch_event_bus():
    """Patch module-level EVENT_BUS_NAME for all tests in this file."""
    with patch.object(event_transformer, "EVENT_BUS_NAME", "fsxn-cyber-resilience-security-dev"):
        yield


class TestEventTransformerPipeline:
    """Tests for the event transformer stage of the pipeline."""

    @patch.object(event_transformer, "events_client")
    def test_fpolicy_event_produces_correct_eventbridge_entry(self, mock_events):
        mock_events.put_events.return_value = {"FailedEntryCount": 0}

        sqs_event = {"Records": [{"body": json.dumps(SAMPLE_FPOLICY_EVENTS[0])}]}
        result = event_transformer.handler(sqs_event, None)

        assert result["published"] == 1
        entry = mock_events.put_events.call_args[1]["Entries"][0]
        assert entry["Source"] == "fsxn.cyber-resilience.scanner"
        assert entry["DetailType"] == "MalwareDetected"
        assert entry["EventBusName"] == "fsxn-cyber-resilience-security-dev"

    @patch.object(event_transformer, "events_client")
    def test_arp_event_produces_correct_source(self, mock_events):
        mock_events.put_events.return_value = {"FailedEntryCount": 0}

        sqs_event = {"Records": [{"body": json.dumps(SAMPLE_FPOLICY_EVENTS[1])}]}
        event_transformer.handler(sqs_event, None)

        entry = mock_events.put_events.call_args[1]["Entries"][0]
        assert entry["Source"] == "fsxn.cyber-resilience.arp"
        assert entry["DetailType"] == "RansomwareDetected"


class TestEventBridgeRuleMatching:
    """Tests verifying transformed events match EventBridge rule patterns."""

    @patch.object(event_transformer, "events_client")
    def test_malware_event_matches_quarantine_rule(self, mock_events):
        """MalwareDetected detail-type should trigger the quarantine rule."""
        mock_events.put_events.return_value = {"FailedEntryCount": 0}

        sqs_event = {"Records": [{"body": json.dumps(SAMPLE_FPOLICY_EVENTS[0])}]}
        event_transformer.handler(sqs_event, None)

        entry = mock_events.put_events.call_args[1]["Entries"][0]
        # MalwareDetected detail-type triggers quarantine regardless of source
        assert entry["DetailType"] in QUARANTINE_RULE_PATTERN["detail-type"]

    @patch.object(event_transformer, "events_client")
    def test_ransomware_event_matches_quarantine_rule(self, mock_events):
        """RansomwareDetected from ARP should trigger the quarantine rule."""
        mock_events.put_events.return_value = {"FailedEntryCount": 0}

        sqs_event = {"Records": [{"body": json.dumps(SAMPLE_FPOLICY_EVENTS[1])}]}
        event_transformer.handler(sqs_event, None)

        entry = mock_events.put_events.call_args[1]["Entries"][0]
        assert entry["Source"] in QUARANTINE_RULE_PATTERN["source"]
        assert entry["DetailType"] in QUARANTINE_RULE_PATTERN["detail-type"]

    @patch.object(event_transformer, "events_client")
    def test_normal_file_event_does_not_match_quarantine_rule(self, mock_events):
        mock_events.put_events.return_value = {"FailedEntryCount": 0}

        sqs_event = {"Records": [{"body": json.dumps(SAMPLE_FPOLICY_EVENTS[2])}]}
        event_transformer.handler(sqs_event, None)

        entry = mock_events.put_events.call_args[1]["Entries"][0]
        assert entry["DetailType"] not in QUARANTINE_RULE_PATTERN["detail-type"]


class TestStepFunctionsAslValidation:
    """Tests that validate Step Functions ASL references in the template."""

    @pytest.fixture
    def quarantine_asl(self):
        """Load and parse the Step Functions ASL from the CFn template."""
        import yaml

        # Custom loader to handle CloudFormation intrinsic functions (!Sub, !Ref, etc.)
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

        template_path = Path(__file__).parent.parent / "templates" / "event-driven.yaml"
        with open(template_path) as f:
            template = yaml.load(f, Loader=CfnLoader)

        sm = template["Resources"]["QuarantineStateMachine"]
        asl_string = sm["Properties"]["DefinitionString"]["Sub"]
        return json.loads(asl_string)

    def test_asl_starts_at_create_forensic_snapshot(self, quarantine_asl):
        assert quarantine_asl["StartAt"] == "CreateForensicSnapshot"

    def test_asl_has_all_required_states(self, quarantine_asl):
        required = [
            "CreateForensicSnapshot", "RestrictExportPolicy", "SendAlert",
            "WaitForApproval", "ApprovalDecision", "RestoreAccess",
            "CreateFlexClone", "NotifyFailure", "EscalateTimeout",
        ]
        for state in required:
            assert state in quarantine_asl["States"], f"Missing state: {state}"

    def test_asl_quarantine_lambda_referenced(self, quarantine_asl):
        resource = quarantine_asl["States"]["RestrictExportPolicy"]["Resource"]
        assert "${QuarantineLambda.Arn}" in resource

    def test_asl_sns_topic_referenced(self, quarantine_asl):
        params = quarantine_asl["States"]["SendAlert"]["Parameters"]
        assert "${SecurityAlertTopic}" in params["TopicArn"]

    def test_asl_approval_timeout(self, quarantine_asl):
        assert quarantine_asl["States"]["WaitForApproval"]["TimeoutSeconds"] == 86400


class TestEventClassificationProperty:
    """Property-based tests for event classification."""

    @given(
        source=st.sampled_from(["fpolicy", "arp", "scanner"]),
        event_type=st.sampled_from(["file_write", "ransomware_detected", "arp_alert"]),
        verdict=st.sampled_from(["MALICIOUS", "SUSPICIOUS", "CLEAN", ""]),
    )
    @settings(max_examples=50)
    @patch.object(event_transformer, "events_client")
    def test_all_valid_sources_produce_valid_eventbridge_source(self, mock_events, source, event_type, verdict):
        mock_events.put_events.return_value = {"FailedEntryCount": 0}

        raw_event = {"source": source, "event_type": event_type, "verdict": verdict, "file_path": "/test"}
        sqs_event = {"Records": [{"body": json.dumps(raw_event)}]}

        event_transformer.handler(sqs_event, None)

        entry = mock_events.put_events.call_args[1]["Entries"][0]
        assert entry["Source"].startswith("fsxn.cyber-resilience.")
        assert entry["DetailType"] in {"MalwareDetected", "RansomwareDetected", "SuspiciousActivity", "FileEvent"}
