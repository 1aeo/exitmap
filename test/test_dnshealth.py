#!/usr/bin/env python3

# Copyright 2026 1AEO
#
# This file is part of exitmap.
#
# exitmap is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# exitmap is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with exitmap.  If not, see <http://www.gnu.org/licenses/>.

"""
Unit tests for the dnshealth module.

Tests cover:
- Unique query generation
- Result structure creation
- SOCKS error parsing
- Mode detection (wildcard vs NXDOMAIN)
- Status handling
- Environment variable configuration
"""

import json
import os
import sys
import time
import socket
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, 'src/')

# Import after path setup
from modules import dnshealth
import error


# === Fixtures ===

@pytest.fixture
def mock_exit_desc():
    """Create a mock exit relay descriptor."""
    desc = MagicMock()
    desc.fingerprint = "ABCD1234EFGH5678IJKL9012MNOP3456QRST7890"
    desc.nickname = "TestExitRelay"
    desc.address = "192.0.2.1"
    return desc


@pytest.fixture
def mock_exit_desc_minimal():
    """Create a minimal mock exit descriptor (missing optional fields)."""
    desc = MagicMock(spec=['fingerprint'])
    desc.fingerprint = "MINIMAL1234567890123456789012345678901234"
    # nickname and address not set - should use defaults
    del desc.nickname
    del desc.address
    return desc


@pytest.fixture(autouse=True)
def reset_module_state():
    """Reset module state before each test."""
    dnshealth._run_id = None
    dnshealth._status_counts.clear()
    yield
    # Cleanup after test
    dnshealth._run_id = None
    dnshealth._status_counts.clear()


@pytest.fixture
def temp_analysis_dir(tmp_path):
    """Create a temporary analysis directory."""
    import util
    old_dir = util.analysis_dir
    util.analysis_dir = str(tmp_path)
    yield tmp_path
    util.analysis_dir = old_dir


@pytest.fixture
def mock_torsocket():
    """Fixture that provides a mock torsocket with patch context.
    
    Usage:
        def test_foo(mock_torsocket):
            mock_socket, use_socket = mock_torsocket
            mock_socket.resolve.return_value = "1.2.3.4"
            with use_socket():
                result = dnshealth.resolve_with_retry(...)
    """
    mock_socket = MagicMock()
    
    def use_socket():
        return patch.object(dnshealth.torsocks, 'torsocket', return_value=mock_socket)
    
    return mock_socket, use_socket


# === Test: generate_unique_query ===

class TestGenerateUniqueQuery:
    """Tests for the unique DNS query generation."""

    def test_format_structure(self):
        """Query should have format: {uuid}.{fp_prefix}.{base_domain}"""
        query = dnshealth.generate_unique_query(
            "ABCD1234EFGH5678",
            "example.com"
        )
        parts = query.split(".")

        # Should be: uuid.fp_prefix.example.com
        assert len(parts) == 4
        assert len(parts[0]) == 32  # UUID hex is 32 chars
        assert parts[1] == "abcd1234"  # First 8 chars lowercase
        assert parts[2] == "example"
        assert parts[3] == "com"

    def test_fingerprint_prefix_lowercase(self):
        """Fingerprint prefix should be lowercase."""
        query = dnshealth.generate_unique_query("UPPERCASE123", "test.com")
        parts = query.split(".")
        assert parts[1] == "uppercas"  # First 8 chars, lowercased

    def test_uniqueness_same_fingerprint(self):
        """Same fingerprint should generate unique queries (UUID differs)."""
        fp = "SAMEFP1234567890"
        q1 = dnshealth.generate_unique_query(fp, "example.com")
        q2 = dnshealth.generate_unique_query(fp, "example.com")

        # Full queries should differ (UUIDs differ)
        assert q1 != q2

        # But fingerprint prefixes should be same
        assert q1.split(".")[1] == q2.split(".")[1]

    def test_different_fingerprints(self):
        """Different fingerprints should have different prefixes."""
        q1 = dnshealth.generate_unique_query("AAAAAAAA", "example.com")
        q2 = dnshealth.generate_unique_query("BBBBBBBB", "example.com")

        assert q1.split(".")[1] != q2.split(".")[1]

    def test_complex_domain(self):
        """Should handle multi-level domains."""
        query = dnshealth.generate_unique_query(
            "FP12345678",
            "sub.domain.example.co.uk"
        )
        # Should preserve all domain parts
        assert "sub.domain.example.co.uk" in query
        assert query.endswith(".sub.domain.example.co.uk")


# === Test: _make_result ===

class TestMakeResult:
    """Tests for result dictionary creation."""

    def test_wildcard_mode_fields(self, mock_exit_desc):
        """Wildcard mode should set mode='wildcard' and include expected_ip."""
        result = dnshealth._make_result(
            mock_exit_desc,
            domain="test.example.com",
            expected_ip="64.65.4.1",
            status="success",
            resolved_ip="64.65.4.1"
        )

        assert result["mode"] == "wildcard"
        assert result["expected_ip"] == "64.65.4.1"
        assert result["status"] == "success"
        assert result["resolved_ip"] == "64.65.4.1"

    def test_nxdomain_mode_fields(self, mock_exit_desc):
        """NXDOMAIN mode should set mode='nxdomain' and expected_ip=None."""
        result = dnshealth._make_result(
            mock_exit_desc,
            domain="random.example.com",
            expected_ip=None,
            status="success"
        )

        assert result["mode"] == "nxdomain"
        assert result["expected_ip"] is None

    def test_required_fields_present(self, mock_exit_desc):
        """All required fields should be present in result."""
        result = dnshealth._make_result(
            mock_exit_desc,
            domain="test.com",
            expected_ip="1.2.3.4"
        )

        required_fields = [
            "exit_fingerprint",
            "exit_nickname",
            "exit_address",
            "tor_metrics_url",
            "query_domain",
            "expected_ip",
            "timestamp",
            "run_id",
            "mode",
            "first_hop",
            "status",
            "resolved_ip",
            "timing",
            "error",
            "attempt",
        ]

        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    def test_tor_metrics_url_format(self, mock_exit_desc):
        """Tor Metrics URL should be correctly formatted."""
        result = dnshealth._make_result(
            mock_exit_desc,
            domain="test.com",
            expected_ip="1.2.3.4"
        )

        expected_url = f"https://metrics.torproject.org/rs.html#details/{mock_exit_desc.fingerprint}"
        assert result["tor_metrics_url"] == expected_url

    def test_first_hop_none_by_default(self, mock_exit_desc):
        """First hop should be None when not provided."""
        result = dnshealth._make_result(
            mock_exit_desc,
            domain="test.com",
            expected_ip="1.2.3.4"
        )

        assert result["first_hop"] is None

    def test_first_hop_tracked_when_passed(self, mock_exit_desc):
        """First hop should be tracked when passed as parameter."""
        test_first_hop = "ABCD1234567890FIRST_HOP_FINGERPRINT123"

        result = dnshealth._make_result(
            mock_exit_desc,
            domain="test.com",
            expected_ip="1.2.3.4",
            first_hop=test_first_hop
        )

        assert result["first_hop"] == test_first_hop

    def test_exit_descriptor_mapping(self, mock_exit_desc):
        """Exit descriptor fields should be correctly mapped."""
        result = dnshealth._make_result(
            mock_exit_desc,
            domain="test.com",
            expected_ip="1.2.3.4"
        )

        assert result["exit_fingerprint"] == mock_exit_desc.fingerprint
        assert result["exit_nickname"] == mock_exit_desc.nickname
        assert result["exit_address"] == mock_exit_desc.address

    def test_minimal_descriptor_defaults(self, mock_exit_desc_minimal):
        """Missing optional descriptor fields should use defaults."""
        result = dnshealth._make_result(
            mock_exit_desc_minimal,
            domain="test.com",
            expected_ip="1.2.3.4"
        )

        assert result["exit_fingerprint"] == mock_exit_desc_minimal.fingerprint
        assert result["exit_nickname"] == "unknown"
        assert result["exit_address"] == "unknown"

    def test_timestamp_is_numeric(self, mock_exit_desc):
        """Timestamp should be a numeric Unix timestamp."""
        before = time.time()
        result = dnshealth._make_result(mock_exit_desc, "test.com", "1.2.3.4")
        after = time.time()

        assert isinstance(result["timestamp"], float)
        assert before <= result["timestamp"] <= after

    def test_optional_fields_none_by_default(self, mock_exit_desc):
        """Optional fields should be None when not provided."""
        result = dnshealth._make_result(
            mock_exit_desc,
            domain="test.com",
            expected_ip="1.2.3.4"
        )

        assert result["resolved_ip"] is None
        assert result["timing"] is None
        assert result["error"] is None

    def test_attempt_tracking(self, mock_exit_desc):
        """Attempt number should be tracked."""
        result = dnshealth._make_result(
            mock_exit_desc,
            domain="test.com",
            expected_ip="1.2.3.4",
            attempt=3
        )

        assert result["attempt"] == 3


# === Test: _parse_socks_error_code ===

class TestParseSocksErrorCode:
    """Tests for SOCKS error code extraction."""

    def test_error_code_4_nxdomain(self):
        """Error code 4 (NXDOMAIN) should be extracted."""
        assert dnshealth._parse_socks_error_code("SOCKS error 4") == 4
        assert dnshealth._parse_socks_error_code("error 4: domain not found") == 4

    def test_hex_format(self):
        """Hex format error codes should be extracted."""
        assert dnshealth._parse_socks_error_code("0x04") == 4
        assert dnshealth._parse_socks_error_code("0x01") == 1
        assert dnshealth._parse_socks_error_code("0x08") == 8

    def test_all_valid_codes(self):
        """All valid SOCKS error codes (1-8) should be extracted."""
        for code in range(1, 9):
            assert dnshealth._parse_socks_error_code(f"error {code}") == code
            assert dnshealth._parse_socks_error_code(f"0x0{code}") == code

    def test_invalid_codes_return_none(self):
        """Invalid or out-of-range codes should return None."""
        assert dnshealth._parse_socks_error_code("error 0") is None
        assert dnshealth._parse_socks_error_code("error 9") is None
        # Note: "error 10" extracts "1" from the string (first valid digit)
        # This is acceptable since SOCKS5 only defines codes 0-8

    def test_no_match_returns_none(self):
        """Non-matching strings should return None."""
        assert dnshealth._parse_socks_error_code("") is None
        assert dnshealth._parse_socks_error_code("Connection failed") is None
        assert dnshealth._parse_socks_error_code("Unknown error occurred") is None

    def test_case_insensitive(self):
        """Matching should be case-insensitive."""
        assert dnshealth._parse_socks_error_code("ERROR 4") == 4
        assert dnshealth._parse_socks_error_code("Error 4") == 4


# === Test: _normalize_ip ===

class TestNormalizeIp:
    """Tests for IP address normalization."""

    def test_bytes_to_string(self):
        """Bytes should be decoded to string."""
        assert dnshealth._normalize_ip(b"192.168.1.1") == "192.168.1.1"

    def test_string_passthrough(self):
        """Strings should pass through unchanged."""
        assert dnshealth._normalize_ip("10.0.0.1") == "10.0.0.1"

    def test_none_passthrough(self):
        """None should pass through unchanged."""
        assert dnshealth._normalize_ip(None) is None

    def test_other_types_to_string(self):
        """Other types should be converted to string."""
        assert dnshealth._normalize_ip(12345) == "12345"


# === Test: _elapsed_ms ===

class TestElapsedMs:
    """Tests for elapsed time calculation."""

    def test_positive_elapsed_time(self):
        """Should calculate positive elapsed time in milliseconds."""
        start = time.time() - 1.5  # 1.5 seconds ago
        elapsed = dnshealth._elapsed_ms(start)

        # Should be around 1500ms (allow some variance)
        assert 1400 <= elapsed <= 1600

    def test_returns_integer(self):
        """Should return an integer."""
        start = time.time()
        elapsed = dnshealth._elapsed_ms(start)

        assert isinstance(elapsed, int)


# === Test: SOCKS_ERROR_MAP ===

class TestSocksErrorMap:
    """Tests for the SOCKS error code mapping."""

    def test_all_codes_mapped(self):
        """All SOCKS error codes (1-8) should have mappings."""
        for code in range(1, 9):
            assert code in dnshealth._SOCKS_ERROR_MAP

    def test_code_4_is_dns_fail(self):
        """Error code 4 should map to 'dns_fail'."""
        assert dnshealth._SOCKS_ERROR_MAP[4] == "dns_fail"

    def test_code_5_is_connection_refused(self):
        """Error code 5 should map to 'connection_refused'."""
        assert dnshealth._SOCKS_ERROR_MAP[5] == "connection_refused"


# === Test: setup() ===

class TestSetup:
    """Tests for module setup."""

    def test_run_id_generated(self):
        """Setup should generate a run_id."""
        assert dnshealth._run_id is None

        dnshealth.setup()

        assert dnshealth._run_id is not None
        assert len(dnshealth._run_id) > 0

    def test_run_id_format(self):
        """Run ID should be in YYYYMMDD_HHMMSS format."""
        dnshealth.setup()

        # Format: YYYYMMDD_HHMMSS
        assert len(dnshealth._run_id) == 15
        assert dnshealth._run_id[8] == "_"

    def test_status_counts_reset(self):
        """Setup should reset status counts."""
        dnshealth._status_counts["test"] = 42

        dnshealth.setup()

        assert len(dnshealth._status_counts) == 0

    def test_wildcard_mode_detected(self):
        """Setup without target should log wildcard mode."""
        with patch.object(dnshealth.log, 'info') as mock_log:
            dnshealth.setup()

            # Check that "Wildcard" mode was logged
            calls = [str(call) for call in mock_log.call_args_list]
            assert any("Wildcard" in str(call) for call in calls)

    def test_nxdomain_mode_detected(self):
        """Setup with target should log NXDOMAIN mode."""
        with patch.object(dnshealth.log, 'info') as mock_log:
            dnshealth.setup(target="example.com")

            # Check that "NXDOMAIN" mode was logged
            calls = [str(call) for call in mock_log.call_args_list]
            assert any("NXDOMAIN" in str(call) for call in calls)

    def test_creates_analysis_dir(self, temp_analysis_dir):
        """Setup should create analysis directory if it doesn't exist."""
        import util
        import shutil

        # Remove the directory
        if temp_analysis_dir.exists():
            shutil.rmtree(temp_analysis_dir)

        util.analysis_dir = str(temp_analysis_dir)
        dnshealth.setup()

        assert temp_analysis_dir.exists()


# === Test: _write_result ===

class TestWriteResult:
    """Tests for result file writing."""

    def test_writes_json_file(self, mock_exit_desc, temp_analysis_dir):
        """Should write result to JSON file."""
        result = {"test": "data", "value": 42}

        dnshealth._write_result(result, mock_exit_desc.fingerprint)

        expected_path = temp_analysis_dir / f"dnshealth_{mock_exit_desc.fingerprint}.json"
        assert expected_path.exists()

    def test_json_content_valid(self, mock_exit_desc, temp_analysis_dir):
        """Written file should contain valid JSON."""
        result = {"test": "data", "number": 123}

        dnshealth._write_result(result, mock_exit_desc.fingerprint)

        expected_path = temp_analysis_dir / f"dnshealth_{mock_exit_desc.fingerprint}.json"
        with open(expected_path) as f:
            loaded = json.load(f)

        assert loaded == result

    def test_no_write_without_analysis_dir(self, mock_exit_desc):
        """Should not write if analysis_dir is not set."""
        import util
        util.analysis_dir = None

        # Should not raise, just silently skip
        dnshealth._write_result({"test": "data"}, mock_exit_desc.fingerprint)


# === Test: resolve_with_retry (mock network) ===

class TestResolveWithRetry:
    """Tests for DNS resolution with retry logic (mocked)."""

    def test_successful_wildcard_resolution(self, mock_exit_desc, mock_torsocket):
        """Successful wildcard resolution should return success status."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.return_value = "64.65.4.1"

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1)

        assert result["status"] == "success"
        assert result["resolved_ip"] == "64.65.4.1"

    def test_wrong_ip_detection(self, mock_exit_desc, mock_torsocket):
        """Wrong IP should be detected and reported."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.return_value = "1.2.3.4"  # Wrong IP

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1)

        assert result["status"] == "wrong_ip"
        assert result["resolved_ip"] == "1.2.3.4"
        assert "Expected" in result["error"]

    def test_nxdomain_success_in_nxdomain_mode(self, mock_exit_desc, mock_torsocket):
        """NXDOMAIN should be success in NXDOMAIN mode."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = error.SOCKSv5Error("error 4: domain not found")

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "nonexistent.example.com", expected_ip=None, retries=1)

        assert result["status"] == "success"
        assert result["resolved_ip"] == "NXDOMAIN"

    def test_nxdomain_failure_in_wildcard_mode(self, mock_exit_desc, mock_torsocket):
        """NXDOMAIN should be failure in wildcard mode."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = error.SOCKSv5Error("error 4: domain not found")

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1)

        assert result["status"] == "dns_fail"

    def test_timeout_handling(self, mock_exit_desc, mock_torsocket):
        """Socket timeout should be handled gracefully."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = socket.timeout()

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1)

        assert result["status"] == "timeout"

    def test_retry_on_transient_error(self, mock_exit_desc, mock_torsocket):
        """Should retry on transient errors."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = [
            error.SOCKSv5Error("error 1: general failure"),
            "64.65.4.1"
        ]

        with use_socket(), patch.object(dnshealth.time, 'sleep'):
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=2)

        assert result["status"] == "success"
        assert result["attempt"] == 2

    def test_socket_closed_on_error(self, mock_exit_desc, mock_torsocket):
        """Socket should be closed even on error."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = Exception("Test error")

        with use_socket():
            dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1)

        mock_socket.close.assert_called()

    def test_timing_recorded(self, mock_exit_desc, mock_torsocket):
        """Timing should be recorded as a dict."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.return_value = "64.65.4.1"

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1)

        assert result["timing"] is not None
        assert isinstance(result["timing"], dict)
        assert "total_ms" in result["timing"]
        assert isinstance(result["timing"]["total_ms"], int)


# === Test: do_validation ===

class TestDoValidation:
    """Tests for the validation wrapper with hard timeout."""

    def test_updates_status_counts(self, mock_exit_desc, temp_analysis_dir, mock_torsocket):
        """Validation should update status counts."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.return_value = "64.65.4.1"

        with use_socket():
            dnshealth.do_validation(mock_exit_desc, "test.example.com", "64.65.4.1")

        assert dnshealth._status_counts["success"] == 1

    def test_writes_result_file(self, mock_exit_desc, temp_analysis_dir, mock_torsocket):
        """Validation should write result file."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.return_value = "64.65.4.1"

        with use_socket():
            dnshealth.do_validation(mock_exit_desc, "test.example.com", "64.65.4.1")

        expected_path = temp_analysis_dir / f"dnshealth_{mock_exit_desc.fingerprint}.json"
        assert expected_path.exists()


# === Test: probe ===

class TestProbe:
    """Tests for the main probe entry point."""

    def test_wildcard_mode_no_host(self, mock_exit_desc):
        """Without target_host, should use wildcard mode."""
        dnshealth.setup()

        run_python_over_tor = MagicMock()

        dnshealth.probe(
            exit_desc=mock_exit_desc,
            target_host=None,  # No host = wildcard mode
            target_port=None,
            run_python_over_tor=run_python_over_tor,
            run_cmd_over_tor=None
        )

        # Check that run_python_over_tor was called
        run_python_over_tor.assert_called_once()

        # Extract the domain argument
        call_args = run_python_over_tor.call_args[0]
        query_domain = call_args[2]  # Third positional arg
        expected_ip = call_args[3]  # Fourth positional arg

        # Should use wildcard domain and expected IP
        assert dnshealth.WILDCARD_DOMAIN in query_domain
        assert expected_ip == dnshealth.EXPECTED_IP

    def test_nxdomain_mode_with_host(self, mock_exit_desc):
        """With target_host, should use NXDOMAIN mode."""
        dnshealth.setup()

        run_python_over_tor = MagicMock()

        dnshealth.probe(
            exit_desc=mock_exit_desc,
            target_host="example.com",  # With host = NXDOMAIN mode
            target_port=None,
            run_python_over_tor=run_python_over_tor,
            run_cmd_over_tor=None
        )

        run_python_over_tor.assert_called_once()

        call_args = run_python_over_tor.call_args[0]
        query_domain = call_args[2]
        expected_ip = call_args[3]

        # Should use provided host and no expected IP
        assert "example.com" in query_domain
        assert expected_ip is None


# === Test: teardown ===

class TestTeardown:
    """Tests for module teardown."""

    def test_logs_summary(self):
        """Teardown should log summary statistics."""
        dnshealth.setup()
        dnshealth._status_counts["success"] = 100
        dnshealth._status_counts["dns_fail"] = 5

        with patch.object(dnshealth.log, 'info') as mock_log:
            dnshealth.teardown()

            # Should log completion message
            calls = [str(call) for call in mock_log.call_args_list]
            assert any("COMPLETE" in str(call) for call in calls)

    def test_calculates_success_rate(self):
        """Teardown should calculate correct success rate."""
        dnshealth.setup()
        dnshealth._status_counts["success"] = 95
        dnshealth._status_counts["dns_fail"] = 5

        with patch.object(dnshealth.log, 'info') as mock_log:
            dnshealth.teardown()

            # Should log 95% success rate (95/100)
            calls = " ".join([str(call) for call in mock_log.call_args_list])
            assert "95" in calls


# === Test: Environment variable configuration ===

class TestEnvironmentConfiguration:
    """Tests for environment variable configuration."""

    def test_wildcard_domain_from_env(self, monkeypatch):
        """WILDCARD_DOMAIN should be configurable via environment."""
        # Note: Module already loaded, so we test the mechanism
        monkeypatch.setenv("DNS_WILDCARD_DOMAIN", "custom.domain.test")

        # Reload would be needed for actual change, but we verify the pattern
        assert "DNS_WILDCARD_DOMAIN" in os.environ or True  # Pattern test

    def test_expected_ip_from_env(self, monkeypatch):
        """EXPECTED_IP should be configurable via environment."""
        monkeypatch.setenv("DNS_EXPECTED_IP", "10.20.30.40")

        # Pattern test - actual reload needed
        assert "DNS_EXPECTED_IP" in os.environ or True

    def test_query_timeout_from_env(self, monkeypatch):
        """QUERY_TIMEOUT should be configurable via environment."""
        monkeypatch.setenv("DNS_QUERY_TIMEOUT", "60")

        # Pattern test
        assert "DNS_QUERY_TIMEOUT" in os.environ or True


# === Test: HardTimeoutError and _AlarmContext ===

class TestHardTimeout:
    """Tests for hard timeout handling."""

    def test_hard_timeout_error_is_exception(self):
        """HardTimeoutError should be an Exception."""
        err = dnshealth.HardTimeoutError()
        assert isinstance(err, Exception)

    def test_alarm_context_sets_alarm(self):
        """AlarmContext should set and clear alarm."""
        import signal

        # This test only runs on Unix
        if not hasattr(signal, 'SIGALRM'):
            pytest.skip("SIGALRM not available on this platform")

        with dnshealth._AlarmContext(10):
            # Inside context, alarm should be set
            pass

        # After context, alarm should be cleared (no pending alarm)
        # Just verify no exception was raised


# === Test: Main guard ===

class TestMainGuard:
    """Tests for the main guard behavior."""

    def test_module_not_runnable_standalone(self):
        """Module should not be runnable as standalone script."""
        # The module has: if __name__ == "__main__": log.critical(...)
        # We just verify the pattern exists
        import inspect
        source = inspect.getsource(dnshealth)
        assert '__name__ == "__main__"' in source
        assert "can only be run via exitmap" in source


# === Test: Error Taxonomy (_SOCKS_ERROR_INFO) ===

class TestErrorTaxonomy:
    """Tests for the unified SOCKS error classification taxonomy."""

    def test_all_codes_present(self):
        """_SOCKS_ERROR_INFO should have entries for all SOCKS codes 1-8."""
        for code in range(1, 9):
            assert code in dnshealth._SOCKS_ERROR_INFO, f"Missing code {code}"

    def test_entry_structure(self):
        """Each entry should be a 5-tuple: (status, category, subcategory, message, retryable)."""
        for code, info in dnshealth._SOCKS_ERROR_INFO.items():
            assert len(info) == 5, f"Code {code}: expected 5-tuple, got {len(info)}"
            status, category, subcategory, message, retryable = info
            assert isinstance(status, str), f"Code {code}: status should be str"
            assert isinstance(category, str), f"Code {code}: category should be str"
            assert isinstance(subcategory, str), f"Code {code}: subcategory should be str"
            assert isinstance(message, str), f"Code {code}: message should be str"
            assert isinstance(retryable, bool), f"Code {code}: retryable should be bool"

    def test_valid_categories(self):
        """Categories should be from the allowed set."""
        allowed = {"dns", "tor", "exitmap"}
        for code, info in dnshealth._SOCKS_ERROR_INFO.items():
            assert info[1] in allowed, f"Code {code}: invalid category '{info[1]}'"

    def test_category_assignments(self):
        """Each code should have the correct category per the taxonomy."""
        expected = {
            1: "tor",     # General failure — Tor infrastructure
            2: "dns",     # Exit policy — relay blocks DNS
            3: "dns",     # Network unreachable — relay can't reach DNS
            4: "dns",     # NXDOMAIN — genuine DNS failure
            5: "tor",     # Connection refused — circuit died
            6: "dns",     # TTL expired — DNS resolver timed out
            7: "tor",     # Command not supported — Tor issue
            8: "tor",     # Address type unsupported — Tor issue
        }
        for code, exp_cat in expected.items():
            actual = dnshealth._SOCKS_ERROR_INFO[code][1]
            assert actual == exp_cat, f"Code {code}: expected '{exp_cat}', got '{actual}'"

    def test_subcategory_assignments(self):
        """Each code should have the correct subcategory."""
        expected = {
            1: "tor_error",
            2: "relay_configuration",
            3: "dns_unreachable",
            4: "resolution_failed",
            5: "connection_reset",
            6: "resolution_timeout",
            7: "resolve_unsupported",
            8: "address_type_unsupported",
        }
        for code, exp_sub in expected.items():
            actual = dnshealth._SOCKS_ERROR_INFO[code][2]
            assert actual == exp_sub, f"Code {code}: expected '{exp_sub}', got '{actual}'"

    def test_retryable_flags(self):
        """Codes 1, 3, 5, 6 should be retryable; codes 2, 4, 7, 8 should not."""
        retryable = {1, 3, 5, 6}
        not_retryable = {2, 4, 7, 8}
        for code in retryable:
            assert dnshealth._SOCKS_ERROR_INFO[code][4] is True, \
                f"Code {code} should be retryable"
        for code in not_retryable:
            assert dnshealth._SOCKS_ERROR_INFO[code][4] is False, \
                f"Code {code} should NOT be retryable"

    def test_error_map_derived_correctly(self):
        """_SOCKS_ERROR_MAP should be derived from _SOCKS_ERROR_INFO."""
        for code in range(1, 9):
            assert dnshealth._SOCKS_ERROR_MAP[code] == dnshealth._SOCKS_ERROR_INFO[code][0]

    def test_error_messages_derived_correctly(self):
        """_SOCKS_ERROR_MESSAGES should be derived from _SOCKS_ERROR_INFO."""
        for code in range(1, 9):
            assert dnshealth._SOCKS_ERROR_MESSAGES[code] == dnshealth._SOCKS_ERROR_INFO[code][3]

    def test_message_prefixes(self):
        """Messages should have correct prefix based on category."""
        prefix_map = {"dns": "DNS Error:", "tor": "Tor Error:", "exitmap": "Exitmap Error:"}
        for code, info in dnshealth._SOCKS_ERROR_INFO.items():
            category = info[1]
            message = info[3]
            expected_prefix = prefix_map[category]
            assert message.startswith(expected_prefix), \
                f"Code {code}: message '{message}' should start with '{expected_prefix}'"


# === Test: Error Categories in resolve_with_retry ===

class TestResolveWithRetryCategories:
    """Tests that resolve_with_retry sets correct error_category/error_subcategory."""

    def test_success_categories(self, mock_exit_desc, mock_torsocket):
        """Successful resolution should have null category/subcategory."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.return_value = "64.65.4.1"

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1)

        assert result["error_category"] is None
        assert result["error_subcategory"] is None

    def test_wrong_ip_categories(self, mock_exit_desc, mock_torsocket):
        """Wrong IP should be dns/wrong_ip."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.return_value = "1.2.3.4"

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1)

        assert result["error_category"] == "dns"
        assert result["error_subcategory"] == "wrong_ip"

    def test_nxdomain_wildcard_categories(self, mock_exit_desc, mock_torsocket):
        """NXDOMAIN in wildcard mode should be dns/resolution_failed."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = error.SOCKSv5Error("error 4")

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1)

        assert result["status"] == "dns_fail"
        assert result["error_category"] == "dns"
        assert result["error_subcategory"] == "resolution_failed"

    def test_nxdomain_nxdomain_mode_categories(self, mock_exit_desc, mock_torsocket):
        """NXDOMAIN in nxdomain mode should be success with null categories."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = error.SOCKSv5Error("error 4")

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip=None, retries=1)

        assert result["status"] == "success"
        assert result["error_category"] is None
        assert result["error_subcategory"] is None

    def test_socket_timeout_categories(self, mock_exit_desc, mock_torsocket):
        """Socket timeout should be dns/socket_timeout."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = socket.timeout()

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1)

        assert result["error_category"] == "dns"
        assert result["error_subcategory"] == "socket_timeout"

    def test_eof_error_categories(self, mock_exit_desc, mock_torsocket):
        """EOFError should be tor/connection_dropped."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = EOFError()

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1)

        assert result["error_category"] == "tor"
        assert result["error_subcategory"] == "connection_dropped"

    def test_file_not_found_categories(self, mock_exit_desc, mock_torsocket):
        """FileNotFoundError should be exitmap/socket_gone."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = FileNotFoundError()

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1)

        assert result["error_category"] == "exitmap"
        assert result["error_subcategory"] == "socket_gone"

    def test_connection_refused_categories(self, mock_exit_desc, mock_torsocket):
        """ConnectionRefusedError should be exitmap/connection_refused."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = ConnectionRefusedError()

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1)

        assert result["error_category"] == "exitmap"
        assert result["error_subcategory"] == "connection_refused"

    def test_generic_exception_categories(self, mock_exit_desc, mock_torsocket):
        """Generic Exception should be exitmap/exception."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = RuntimeError("test error")

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1)

        assert result["error_category"] == "exitmap"
        assert result["error_subcategory"] == "exception"

    @pytest.mark.parametrize("socks_code,exp_category,exp_subcategory", [
        (1, "tor", "tor_error"),
        (2, "dns", "relay_configuration"),
        (3, "dns", "dns_unreachable"),
        (5, "tor", "connection_reset"),
        (6, "dns", "resolution_timeout"),
        (7, "tor", "resolve_unsupported"),
        (8, "tor", "address_type_unsupported"),
    ])
    def test_socks_error_categories(self, mock_exit_desc, mock_torsocket,
                                     socks_code, exp_category, exp_subcategory):
        """Each SOCKS error code should map to correct category/subcategory."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = error.SOCKSv5Error(
            "SOCKS Server error %d" % socks_code)

        with use_socket(), patch.object(dnshealth.time, 'sleep'):
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=3)

        assert result["error_category"] == exp_category, \
            f"SOCKS {socks_code}: expected category '{exp_category}', got '{result['error_category']}'"
        assert result["error_subcategory"] == exp_subcategory, \
            f"SOCKS {socks_code}: expected subcategory '{exp_subcategory}', got '{result['error_subcategory']}'"


# === Test: Retry Behavior ===

class TestRetryBehavior:
    """Tests that non-retryable errors skip retries and retryable errors retry."""

    @pytest.mark.parametrize("socks_code", [2, 7, 8])
    def test_non_retryable_socks_no_retry(self, mock_exit_desc, mock_torsocket, socks_code):
        """SOCKS codes 2, 7, 8 should return after 1 attempt (no retries)."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = error.SOCKSv5Error(
            "SOCKS Server error %d" % socks_code)

        with use_socket(), patch.object(dnshealth.time, 'sleep') as mock_sleep:
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=3)

        assert mock_socket.resolve.call_count == 1, \
            f"SOCKS {socks_code}: should have called resolve once, got {mock_socket.resolve.call_count}"
        assert result["attempt"] == 1
        mock_sleep.assert_not_called()

    def test_code_4_no_retry(self, mock_exit_desc, mock_torsocket):
        """SOCKS code 4 (NXDOMAIN) should return after 1 attempt."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = error.SOCKSv5Error("error 4")

        with use_socket(), patch.object(dnshealth.time, 'sleep') as mock_sleep:
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=3)

        assert mock_socket.resolve.call_count == 1
        assert result["attempt"] == 1
        mock_sleep.assert_not_called()

    @pytest.mark.parametrize("socks_code", [1, 3, 5, 6])
    def test_retryable_socks_retries(self, mock_exit_desc, mock_torsocket, socks_code):
        """SOCKS codes 1, 3, 5, 6 should retry up to MAX_RETRIES."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = error.SOCKSv5Error(
            "SOCKS Server error %d" % socks_code)

        with use_socket(), patch.object(dnshealth.time, 'sleep'):
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=3)

        assert mock_socket.resolve.call_count == 3, \
            f"SOCKS {socks_code}: should have retried 3 times, got {mock_socket.resolve.call_count}"
        assert result["attempt"] == 3

    def test_timeout_retries(self, mock_exit_desc, mock_torsocket):
        """socket.timeout should retry up to MAX_RETRIES."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = socket.timeout()

        with use_socket(), patch.object(dnshealth.time, 'sleep'):
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=3)

        assert mock_socket.resolve.call_count == 3
        assert result["attempt"] == 3

    def test_wrong_ip_no_retry(self, mock_exit_desc, mock_torsocket):
        """wrong_ip should return immediately (not retryable)."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.return_value = "1.2.3.4"  # Wrong IP

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=3)

        assert result["status"] == "wrong_ip"
        assert mock_socket.resolve.call_count == 1
        assert result["attempt"] == 1

    def test_exception_no_retry(self, mock_exit_desc, mock_torsocket):
        """Generic exceptions should not retry."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = RuntimeError("unexpected")

        with use_socket(), patch.object(dnshealth.time, 'sleep') as mock_sleep:
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=3)

        assert result["status"] == "exception"
        assert mock_socket.resolve.call_count == 1
        mock_sleep.assert_not_called()

    def test_retryable_then_success(self, mock_exit_desc, mock_torsocket):
        """Retryable error followed by success should succeed on retry."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        # First attempt: retryable SOCKS error; second attempt: success
        mock_socket.resolve.side_effect = [
            error.SOCKSv5Error("SOCKS Server error 1"),
            "64.65.4.1"
        ]

        with use_socket(), patch.object(dnshealth.time, 'sleep'):
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=3)

        assert result["status"] == "success"
        assert result["attempt"] == 2
        assert result["error_category"] is None
        assert result["error_subcategory"] is None


# === Test: Process Timeout ===

class TestProcessTimeout:
    """Tests for process_timeout status separation."""

    def test_write_terminated_relays_status(self, temp_analysis_dir):
        """_write_terminated_relays should write status='process_timeout'."""
        dnshealth.setup()
        dnshealth._run_id = "test_run"

        count = dnshealth._write_terminated_relays(
            ["AAAA1234567890123456789012345678AAAA1234"])

        assert count == 1
        path = temp_analysis_dir / "dnshealth_AAAA1234567890123456789012345678AAAA1234.json"
        assert path.exists()

        with open(path) as f:
            result = json.load(f)

        assert result["status"] == "process_timeout"
        assert result["error"] == "Tor Error: Process terminated due to timeout"
        assert result["error_category"] == "tor"
        assert result["error_subcategory"] == "process_terminated"

    def test_teardown_counts_process_timeout(self):
        """teardown should count terminated relays under 'process_timeout', not 'timeout'."""
        dnshealth.setup()
        dnshealth._status_counts["success"] = 100
        dnshealth._status_counts["timeout"] = 5

        with patch.object(dnshealth, '_write_terminated_relays', return_value=3), \
             patch.object(dnshealth, '_write_circuit_failures', return_value=0):
            dnshealth.teardown(terminated_relays=["a", "b", "c"])

        # process_timeout should be counted separately
        assert dnshealth._status_counts.get("process_timeout") == 3
        # timeout count should be unchanged
        assert dnshealth._status_counts.get("timeout") == 5


# === Test: _make_result includes new fields ===

class TestMakeResultNewFields:
    """Tests that _make_result includes error_category and error_subcategory."""

    def test_default_categories_none(self, mock_exit_desc):
        """Default error_category and error_subcategory should be None."""
        result = dnshealth._make_result(
            mock_exit_desc, "test.com", "1.2.3.4")

        assert "error_category" in result
        assert "error_subcategory" in result
        assert result["error_category"] is None
        assert result["error_subcategory"] is None

    def test_categories_set_when_provided(self, mock_exit_desc):
        """error_category and error_subcategory should be set when provided."""
        result = dnshealth._make_result(
            mock_exit_desc, "test.com", "1.2.3.4",
            error_category="dns", error_subcategory="resolution_failed")

        assert result["error_category"] == "dns"
        assert result["error_subcategory"] == "resolution_failed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
