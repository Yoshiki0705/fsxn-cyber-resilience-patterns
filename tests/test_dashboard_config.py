"""Unit tests for dashboard_config.py CloudWatch Dashboard generator."""

from __future__ import annotations

import json

from dashboard_config import NAMESPACE, generate_dashboard_body


class TestGenerateDashboardBody:
    """Tests for the dashboard JSON body generator."""

    def test_returns_valid_json(self):
        body = generate_dashboard_body()
        parsed = json.loads(body)
        assert "widgets" in parsed

    def test_contains_all_expected_metrics(self):
        body = generate_dashboard_body()
        parsed = json.loads(body)

        expected_metrics = [
            "SecurityEventsReceived",
            "MalwareDetected",
            "RansomwareAlerts",
            "QuarantineExecuted",
            "ScanLatencyP99",
            "DlqMessages",
            "FalsePositives",
        ]

        body_str = json.dumps(parsed)
        for metric in expected_metrics:
            assert metric in body_str, f"Missing metric: {metric}"

    def test_widget_count(self):
        body = generate_dashboard_body()
        parsed = json.loads(body)
        assert len(parsed["widgets"]) == 7

    def test_uses_correct_namespace(self):
        body = generate_dashboard_body()
        assert NAMESPACE in body

    def test_uses_provided_parameters(self):
        body = generate_dashboard_body(
            project_name="test-project",
            environment="staging",
            region="us-west-2",
        )
        assert "test-project" in body
        assert "staging" in body
        assert "us-west-2" in body

    def test_default_region(self):
        body = generate_dashboard_body()
        assert "ap-northeast-1" in body

    def test_widgets_have_required_fields(self):
        body = generate_dashboard_body()
        parsed = json.loads(body)
        for widget in parsed["widgets"]:
            assert "type" in widget
            assert "properties" in widget
            assert "title" in widget["properties"]
            assert "metrics" in widget["properties"]
            assert "region" in widget["properties"]

    def test_malware_widget_has_annotation(self):
        body = generate_dashboard_body()
        parsed = json.loads(body)
        # Find MalwareDetected widget (index 1)
        malware_widget = parsed["widgets"][1]
        assert "annotations" in malware_widget["properties"]
        assert "horizontal" in malware_widget["properties"]["annotations"]
