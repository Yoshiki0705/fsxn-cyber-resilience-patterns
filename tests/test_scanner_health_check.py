"""Unit tests for scanner health check Lambda."""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

os.environ["SCANNER_IPS"] = "10.0.3.10,10.0.4.10"
os.environ["ENVIRONMENT"] = "dev"
os.environ["PROJECT_NAME"] = "fsxn-cyber-resilience"

import scanner_health_check


class TestHealthCheck:
    """Tests for ICAP health check logic."""

    @patch("scanner_health_check.socket.socket")
    @patch("scanner_health_check.cloudwatch")
    def test_healthy_scanner(self, mock_cw, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_sock

        result = scanner_health_check.handler({}, None)

        assert result["healthy"] == 2
        assert result["total"] == 2
        assert all(r["healthy"] for r in result["results"])

    @patch("scanner_health_check.socket.socket")
    @patch("scanner_health_check.cloudwatch")
    def test_unhealthy_scanner(self, mock_cw, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # Connection refused
        mock_socket_class.return_value = mock_sock

        result = scanner_health_check.handler({}, None)

        assert result["healthy"] == 0
        assert result["total"] == 2

    @patch("scanner_health_check.socket.socket")
    @patch("scanner_health_check.cloudwatch")
    def test_mixed_health(self, mock_cw, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = [0, 111]
        mock_socket_class.return_value = mock_sock

        result = scanner_health_check.handler({}, None)

        assert result["healthy"] == 1
        assert result["total"] == 2

    @patch("scanner_health_check.socket.socket")
    @patch("scanner_health_check.cloudwatch")
    def test_publishes_metrics(self, mock_cw, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_sock

        scanner_health_check.handler({}, None)

        assert mock_cw.put_metric_data.call_count == 2
        call_args = mock_cw.put_metric_data.call_args_list[0][1]
        assert call_args["Namespace"] == "FsxOntapCyberResilience"
        metric = call_args["MetricData"][0]
        assert metric["MetricName"] == "ScannerHealthy"
        assert metric["Value"] == 1.0

    @patch("scanner_health_check.socket.socket")
    @patch("scanner_health_check.cloudwatch")
    def test_socket_timeout_is_unhealthy(self, mock_cw, mock_socket_class):
        import socket
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.timeout("timed out")
        mock_socket_class.return_value = mock_sock

        result = scanner_health_check._check_icap_connectivity("10.0.3.10")
        assert result is False
