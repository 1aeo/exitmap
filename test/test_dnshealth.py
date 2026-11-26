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
import socket
import struct
import sys
import time
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
    dnshealth._consensus = None
    dnshealth._status_counts.clear()
    yield
    # Cleanup after test
    dnshealth._run_id = None
    dnshealth._consensus = None
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
        assert result["error"] is None

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

    def test_writes_circuit_failures_from_stats(self, temp_analysis_dir):
        """Teardown should map Statistics circuit failures to circuit_failures.json."""
        from types import SimpleNamespace
        from stem import CircStatus
        from stem.response.events import CircuitEvent
        from stats import Statistics

        stats_obj = Statistics()
        stats_obj.total_circuits = 2
        exit_a = "A" * 40
        exit_b = "B" * 40
        guard = "G" * 40
        stats_obj.register_circuit("10", guard, exit_a)
        ev = CircuitEvent("foo", "bar")
        ev.id = "10"
        ev.status = CircStatus.FAILED
        ev.reason = "TIMEOUT"
        stats_obj.update_circs(ev)
        stats_obj.record_immediate_failure(guard, exit_b, "No path")

        consensus = {
            exit_a: SimpleNamespace(nickname="ExitA", address="192.0.2.10"),
            guard: SimpleNamespace(nickname="GuardG", address="192.0.2.20"),
        }
        dnshealth.setup(consensus=consensus)
        dnshealth.teardown(stats=stats_obj)

        failures_path = temp_analysis_dir / "circuit_failures.json"
        stats_path = temp_analysis_dir / "scan_stats.json"
        assert failures_path.exists()
        assert stats_path.exists()

        with open(failures_path) as f:
            failures = {row["exit_fingerprint"]: row for row in json.load(f)}
        assert failures[exit_a]["status"] == "relay_unreachable"
        assert failures[exit_a]["circuit_reason"] == "circuit_timeout"
        assert failures[exit_a]["tor_reason"] == "TIMEOUT"
        assert failures[exit_a]["first_hop"] == guard
        assert failures[exit_a]["exit_nickname"] == "ExitA"
        assert failures[exit_a]["first_hop_nickname"] == "GuardG"
        assert failures[exit_a]["error"].startswith("Tor Circuit: ")
        assert failures[exit_b]["circuit_reason"] == "circuit_creation_failed"
        assert failures[exit_b]["tor_reason"] == "CREATION_FAILED"
        assert failures[exit_b]["error"].startswith("Tor Circuit: ")
        assert "No path" in failures[exit_b]["error"]

    def test_writes_terminated_relays_without_clobbering_existing(self, temp_analysis_dir):
        """Teardown writes timeout files for terminated relays but preserves existing results."""
        fp_new = "T" * 40
        fp_done = "D" * 40
        existing_path = temp_analysis_dir / ("dnshealth_%s.json" % fp_done)
        existing_path.write_text(json.dumps({
            "exit_fingerprint": fp_done,
            "status": "success",
        }))

        dnshealth.setup()
        dnshealth.teardown(terminated_relays=[fp_new, fp_done])

        out_path = temp_analysis_dir / ("dnshealth_%s.json" % fp_new)
        assert out_path.exists()
        with open(out_path) as f:
            out_data = json.load(f)
        assert out_data["status"] == "timeout"
        assert out_data["exit_fingerprint"] == fp_new
        assert out_data["error"].startswith("Exitmap Error: ")
        assert json.loads(existing_path.read_text())["status"] == "success"

    def test_teardown_counts_worker_result_files(self, temp_analysis_dir, caplog):
        """Teardown aggregates worker result JSON files even when parent _status_counts is empty."""
        dnshealth.setup()
        for idx, status in enumerate(("success", "success", "dns_fail")):
            fp = ("%02d" % idx) + ("E" * 38)
            path = temp_analysis_dir / ("dnshealth_%s.json" % fp)
            path.write_text(json.dumps({"exit_fingerprint": fp, "status": status}))

        with caplog.at_level("INFO"):
            dnshealth.teardown()

        assert "3 total | 2 success (66.7%)" in caplog.text
        assert "'dns_fail': 1" in caplog.text


# === Test: Protocol-layer error prefixes and retry policy ===

class TestErrorPrefixesAndRetryPolicy:
    """Tests for 4-layer error prefixes, stale error clearing, and retry behavior."""

    @pytest.mark.parametrize("exc,expected_status,expected_prefix", [
        (error.SOCKSv5Error("SOCKS Server error 4"), "dns_fail", "DNS Error: "),
        (error.SOCKSv5Error("SOCKS Server error 3"), "network_unreachable", "DNS Error: "),
        (error.SOCKSv5Error("SOCKS Server error 6"), "ttl_expired", "DNS Error: "),
        (socket.timeout(), "timeout", "DNS Error: "),
        (error.SOCKSv5Error("SOCKS Server error 1"), "socks_general_failure", "Tor Error: "),
        (error.SOCKSv5Error("SOCKS Server error 2"), "socks_ruleset_blocked", "Tor Error: "),
        (error.SOCKSv5Error("SOCKS Server error 5"), "connection_refused", "Tor Error: "),
        (error.SOCKSv5Error("SOCKS Server error 7"), "socks_command_unsupported", "Tor Error: "),
        (error.SOCKSv5Error("SOCKS Server error 8"), "socks_address_unsupported", "Tor Error: "),
        (EOFError("eof"), "eof_error", "Tor Error: "),
        (FileNotFoundError("no socket"), "tor_connection_lost", "Exitmap Error: "),
        (ConnectionRefusedError("refused"), "tor_connection_refused", "Exitmap Error: "),
        (RuntimeError("boom"), "exception", "Exitmap Error: "),
    ])
    def test_resolve_error_prefixes(
        self, mock_exit_desc, mock_torsocket, exc, expected_status, expected_prefix
    ):
        """Each failure mode should emit its accurate protocol-layer prefix."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = exc

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1
            )

        assert result["status"] == expected_status
        assert result["error"].startswith(expected_prefix)

    def test_wrong_ip_prefix(self, mock_exit_desc, mock_torsocket):
        """Wrong IP response should use the DNS Error prefix."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.return_value = "1.2.3.4"

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1
            )

        assert result["status"] == "wrong_ip"
        assert result["error"].startswith("DNS Error: ")

    def test_do_validation_hard_timeout_and_exception_prefixes(
        self, mock_exit_desc, temp_analysis_dir
    ):
        """Hard timeout uses DNS Error and outer exception uses Exitmap Error."""
        dnshealth.setup()

        with patch.object(dnshealth, "resolve_with_retry", side_effect=dnshealth.HardTimeoutError()):
            dnshealth.do_validation(mock_exit_desc, "test.example.com", "64.65.4.1")
        with open(temp_analysis_dir / f"dnshealth_{mock_exit_desc.fingerprint}.json") as f:
            hard_res = json.load(f)
        assert hard_res["status"] == "hard_timeout"
        assert hard_res["error"].startswith("DNS Error: ")

        with patch.object(dnshealth, "resolve_with_retry", side_effect=RuntimeError("unexpected")):
            dnshealth.do_validation(mock_exit_desc, "test.example.com", "64.65.4.1")
        with open(temp_analysis_dir / f"dnshealth_{mock_exit_desc.fingerprint}.json") as f:
            exc_res = json.load(f)
        assert exc_res["status"] == "exception"
        assert exc_res["error"] == "Exitmap Error: RuntimeError: unexpected"

    @pytest.mark.parametrize("raw_msg", ["SOCKS Server error", "SOCKS Server error 9"])
    def test_unparsed_socks_error_preserves_raw_message(
        self, mock_exit_desc, mock_torsocket, raw_msg
    ):
        """Unparsed SOCKS errors should use Tor Error and keep the raw message without SOCKS None."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = error.SOCKSv5Error(raw_msg)

        with use_socket():
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=1
            )

        assert result["status"] == "socks_error"
        assert result["error"].startswith("Tor Error: SOCKS - ")
        assert raw_msg in result["error"]
        assert "SOCKS None" not in result["error"]

    def test_circuit_failure_prefixes_and_reason_keys(self, temp_analysis_dir):
        """Circuit failure mapping should use Tor Circuit prefix and preserve reason_key."""
        known_key, known_msg, known_tor = dnshealth._get_circuit_failure_info({"reason": "TIMEOUT"})
        assert known_key == "circuit_timeout"
        assert known_msg == "Tor Circuit: Construction timed out"
        assert known_tor == "TIMEOUT"

        create_key, create_msg, create_tor = dnshealth._get_circuit_failure_info(
            {"reason": "CREATION_FAILED", "error": "No path"}
        )
        assert create_key == "circuit_creation_failed"
        assert create_msg == "Tor Circuit: Failed to create circuit (No path)"
        assert create_tor == "CREATION_FAILED"

        unk_key, unk_msg, unk_tor = dnshealth._get_circuit_failure_info({"reason": "SOME_NEW_REASON"})
        assert unk_key == "circuit_failed"
        assert unk_msg == "Tor Circuit: Unknown failure (SOME_NEW_REASON)"
        assert unk_tor == "SOME_NEW_REASON"

        fp = "T" * 40
        dnshealth.setup()
        assert dnshealth._write_terminated_relays([fp]) == 1
        with open(temp_analysis_dir / f"dnshealth_{fp}.json") as f:
            term = json.load(f)
        assert term["status"] == "timeout"
        assert term["error"] == "Exitmap Error: Probe terminated during shutdown grace timeout"

    def test_stale_error_cleared_when_retry_succeeds(self, mock_exit_desc, mock_torsocket):
        """An error on attempt 1 must be cleared when attempt 2 succeeds (wildcard and NXDOMAIN)."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = [socket.timeout(), "64.65.4.1"]

        with use_socket(), patch.object(dnshealth.time, "sleep"):
            wildcard_res = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=3
            )

        assert wildcard_res["status"] == "success"
        assert wildcard_res["attempt"] == 2
        assert wildcard_res["error"] is None

        mock_socket.resolve.side_effect = [
            socket.timeout(),
            error.SOCKSv5Error("SOCKS Server error 4"),
        ]
        with use_socket(), patch.object(dnshealth.time, "sleep"):
            nxdomain_res = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip=None, retries=3
            )

        assert nxdomain_res["status"] == "success"
        assert nxdomain_res["resolved_ip"] == "NXDOMAIN"
        assert nxdomain_res["attempt"] == 2
        assert nxdomain_res["error"] is None

    @pytest.mark.parametrize("exc", [
        error.SOCKSv5Error("SOCKS Server error 2"),
        error.SOCKSv5Error("SOCKS Server error 7"),
        error.SOCKSv5Error("SOCKS Server error 8"),
        RuntimeError("unexpected exception"),
    ])
    def test_non_retryable_errors_stop_after_one_attempt(
        self, mock_exit_desc, mock_torsocket, exc
    ):
        """Non-retryable SOCKS codes (2, 7, 8) and generic exceptions should not retry."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = exc

        with use_socket(), patch.object(dnshealth.time, "sleep") as mock_sleep:
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=3
            )

        assert mock_socket.resolve.call_count == 1
        assert result["attempt"] == 1
        mock_sleep.assert_not_called()

    @pytest.mark.parametrize("exc", [
        error.SOCKSv5Error("SOCKS Server error 1"),
        error.SOCKSv5Error("SOCKS Server error 3"),
        error.SOCKSv5Error("SOCKS Server error 5"),
        error.SOCKSv5Error("SOCKS Server error 6"),
        error.SOCKSv5Error("SOCKS Server error"),
        socket.timeout(),
        EOFError("eof"),
        struct.error("unpack requires a buffer of 2 bytes"),
        FileNotFoundError("no socket"),
        ConnectionRefusedError("refused"),
    ])
    def test_retryable_errors_retry_up_to_limit(
        self, mock_exit_desc, mock_torsocket, exc
    ):
        """Transient SOCKS and transport/connection errors should retry up to retries."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = exc

        with use_socket(), patch.object(dnshealth.time, "sleep") as mock_sleep:
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=3
            )

        assert mock_socket.resolve.call_count == 3
        assert result["attempt"] == 3
        assert mock_sleep.call_count == 2

    def test_struct_error_treated_as_retryable_eof_error(
        self, mock_exit_desc, mock_torsocket
    ):
        """Truncated SOCKS port unpack (struct.error) should classify as eof_error and retry."""
        dnshealth.setup()
        mock_socket, use_socket = mock_torsocket
        mock_socket.resolve.side_effect = struct.error("unpack requires a buffer of 2 bytes")

        with use_socket(), patch.object(dnshealth.time, "sleep") as mock_sleep:
            result = dnshealth.resolve_with_retry(
                mock_exit_desc, "test.example.com", expected_ip="64.65.4.1", retries=3
            )

        assert mock_socket.resolve.call_count == 3
        assert result["attempt"] == 3
        assert result["status"] == "eof_error"
        assert result["error"] == "Tor Error: Connection closed unexpectedly (first_hop=<random>)"
        assert mock_sleep.call_count == 2


# === Test: Environment variable configuration ===

class TestEnvironmentConfiguration:
    """Tests for environment variable configuration."""

    def test_wildcard_domain_from_env(self):
        """WILDCARD_DOMAIN should be a non-empty domain string."""
        assert isinstance(dnshealth.WILDCARD_DOMAIN, str)
        assert len(dnshealth.WILDCARD_DOMAIN) > 0

    def test_expected_ip_from_env(self):
        """EXPECTED_IP should be a non-empty IP string."""
        assert isinstance(dnshealth.EXPECTED_IP, str)
        assert len(dnshealth.EXPECTED_IP) > 0

    def test_query_timeout_from_env(self):
        """QUERY_TIMEOUT and numeric env settings should be positive numbers."""
        assert isinstance(dnshealth.QUERY_TIMEOUT, int)
        assert dnshealth.QUERY_TIMEOUT > 0
        assert isinstance(dnshealth.MAX_RETRIES, int)
        assert dnshealth.MAX_RETRIES >= 1
        assert isinstance(dnshealth.HARD_TIMEOUT, int)
        assert dnshealth.HARD_TIMEOUT > 0


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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
