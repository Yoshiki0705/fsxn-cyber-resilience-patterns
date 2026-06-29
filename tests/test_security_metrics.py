"""Unit tests for security_metrics.py CloudWatch metrics publisher."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from security_metrics import NAMESPACE, SecurityMetricsPublisher


@pytest.fixture
def publisher():
    """Create a SecurityMetricsPublisher with mocked CloudWatch client."""
    with patch("security_metrics.boto3.client") as mock_boto:
        mock_cw = MagicMock()
        mock_boto.return_value = mock_cw
        pub = SecurityMetricsPublisher(environment="dev", project_name="fsxn-cyber-resilience")
        pub._mock_cw = mock_cw  # Expose for assertions
        yield pub


class TestSecurityMetricsPublisher:
    """Tests for the metrics publisher."""

    def test_namespace(self, publisher):
        assert publisher.namespace == "FsxOntapCyberResilience"

    def test_dimensions(self, publisher):
        dims = publisher._dimensions
        assert {"Name": "Environment", "Value": "dev"} in dims
        assert {"Name": "Project", "Value": "fsxn-cyber-resilience"} in dims

    def test_put_metric(self, publisher):
        publisher.put_metric("TestMetric", 42.0, "Count")

        publisher._mock_cw.put_metric_data.assert_called_once()
        call_args = publisher._mock_cw.put_metric_data.call_args[1]
        assert call_args["Namespace"] == NAMESPACE
        metric_data = call_args["MetricData"][0]
        assert metric_data["MetricName"] == "TestMetric"
        assert metric_data["Value"] == 42.0
        assert metric_data["Unit"] == "Count"

    def test_put_metric_with_extra_dimensions(self, publisher):
        publisher.put_metric("TestMetric", 1.0, dimensions=[{"Name": "Scanner", "Value": "trendai"}])

        call_args = publisher._mock_cw.put_metric_data.call_args[1]
        dims = call_args["MetricData"][0]["Dimensions"]
        assert {"Name": "Scanner", "Value": "trendai"} in dims
        assert len(dims) == 3  # Environment + Project + Scanner

    def test_record_events_received(self, publisher):
        publisher.record_events_received(5)
        metric = publisher._mock_cw.put_metric_data.call_args[1]["MetricData"][0]
        assert metric["MetricName"] == "SecurityEventsReceived"
        assert metric["Value"] == 5

    def test_record_malware_detected(self, publisher):
        publisher.record_malware_detected(scanner_name="deep-instinct", count=2)
        metric = publisher._mock_cw.put_metric_data.call_args[1]["MetricData"][0]
        assert metric["MetricName"] == "MalwareDetected"
        assert metric["Value"] == 2
        dims = metric["Dimensions"]
        assert {"Name": "Scanner", "Value": "deep-instinct"} in dims

    def test_record_ransomware_alert(self, publisher):
        publisher.record_ransomware_alert()
        metric = publisher._mock_cw.put_metric_data.call_args[1]["MetricData"][0]
        assert metric["MetricName"] == "RansomwareAlerts"

    def test_record_quarantine_executed(self, publisher):
        publisher.record_quarantine_executed()
        metric = publisher._mock_cw.put_metric_data.call_args[1]["MetricData"][0]
        assert metric["MetricName"] == "QuarantineExecuted"

    def test_record_scan_latency(self, publisher):
        publisher.record_scan_latency(25.5)
        metric = publisher._mock_cw.put_metric_data.call_args[1]["MetricData"][0]
        assert metric["MetricName"] == "ScanLatencyP99"
        assert metric["Value"] == 25.5
        assert metric["Unit"] == "Milliseconds"

    def test_record_false_positive(self, publisher):
        publisher.record_false_positive(3)
        metric = publisher._mock_cw.put_metric_data.call_args[1]["MetricData"][0]
        assert metric["MetricName"] == "FalsePositives"
        assert metric["Value"] == 3

    def test_record_dlq_messages(self, publisher):
        publisher.record_dlq_messages(7)
        metric = publisher._mock_cw.put_metric_data.call_args[1]["MetricData"][0]
        assert metric["MetricName"] == "DlqMessages"

    def test_put_metric_exception_does_not_raise(self, publisher):
        publisher._mock_cw.put_metric_data.side_effect = Exception("CloudWatch error")
        # Should not raise — logs the error
        publisher.put_metric("FailMetric", 1.0)
