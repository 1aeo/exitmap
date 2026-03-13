#!/usr/bin/env python3

# Copyright 2026 1aeo <tor@1aeo.com>
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
Unit tests for the enhanced dnsresolution module.
"""

import json
import socket
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, 'src/')

from modules import dnsresolution
import error


# === Fixtures ===

@pytest.fixture
def exit_desc():
    """Mock exit relay descriptor."""
    desc = MagicMock()
    desc.fingerprint = "ABCD1234EFGH5678IJKL9012MNOP3456QRST7890"
    desc.nickname = "TestRelay"
    desc.address = "192.0.2.1"
    return desc


@pytest.fixture(autouse=True)
def reset_state():
    """Reset module state between tests."""
    dnsresolution._status_counts.clear()
    saved_wc = dnsresolution.WILDCARD_DOMAIN
    saved_ip = dnsresolution.EXPECTED_IP
    yield
    dnsresolution._status_counts.clear()
    dnsresolution.WILDCARD_DOMAIN = saved_wc
    dnsresolution.EXPECTED_IP = saved_ip


@pytest.fixture
def analysis_dir(tmp_path):
    """Provide a temporary analysis directory."""
    import util
    old = util.analysis_dir
    util.analysis_dir = str(tmp_path)
    yield tmp_path
    util.analysis_dir = old


@pytest.fixture
def mock_sock():
    """Mock torsocket with a patch context."""
    sock = MagicMock()

    def use():
        return patch.object(
            dnsresolution.torsocks, 'torsocket', return_value=sock)

    return sock, use


# === Test: generate_unique_query ===

class TestGenerateUniqueQuery:

    def test_format(self):
        q = dnsresolution.generate_unique_query("ABCD1234EFGH", "ex.com")
        parts = q.split(".")
        assert len(parts) == 4  # uuid . fp_prefix . ex . com
        assert len(parts[0]) == 32
        assert parts[1] == "abcd1234"

    def test_uniqueness(self):
        fp = "SAMEFP1234567890"
        q1 = dnsresolution.generate_unique_query(fp, "ex.com")
        q2 = dnsresolution.generate_unique_query(fp, "ex.com")
        assert q1 != q2
        assert q1.split(".")[1] == q2.split(".")[1]  # same fp prefix

    def test_different_fps(self):
        q1 = dnsresolution.generate_unique_query("AAAA1234", "ex.com")
        q2 = dnsresolution.generate_unique_query("BBBB5678", "ex.com")
        assert q1.split(".")[1] != q2.split(".")[1]


# === Test: _is_nxdomain ===

class TestIsNxdomain:

    def test_error_4(self):
        assert dnsresolution._is_nxdomain("error 4") is True
        assert dnsresolution._is_nxdomain("SOCKS error 4: host") is True

    def test_hex_format(self):
        assert dnsresolution._is_nxdomain("0x04") is True

    def test_no_match(self):
        assert dnsresolution._is_nxdomain("error 1") is False
        assert dnsresolution._is_nxdomain("timeout") is False
        assert dnsresolution._is_nxdomain("") is False


# === Test: _normalize_ip ===

class TestNormalizeIp:

    def test_bytes(self):
        assert dnsresolution._normalize_ip(b"1.2.3.4") == "1.2.3.4"

    def test_string(self):
        assert dnsresolution._normalize_ip("1.2.3.4") == "1.2.3.4"

    def test_none(self):
        assert dnsresolution._normalize_ip(None) is None


# === Test: validate — success paths ===

class TestValidateSuccess:

    def test_nxdomain_mode_success(self, exit_desc, mock_sock):
        """NXDOMAIN response = success in default mode."""
        sock, use = mock_sock
        sock.resolve.side_effect = error.SOCKSv5Error("error 4")
        with use():
            dnsresolution.validate(exit_desc, "test.ex.com")
        assert dnsresolution._status_counts["success"] == 1

    def test_wildcard_mode_success(self, exit_desc, mock_sock):
        """Correct IP = success in wildcard mode."""
        sock, use = mock_sock
        sock.resolve.return_value = "1.2.3.4"
        with use():
            dnsresolution.validate(exit_desc, "test.wc.com", "1.2.3.4")
        assert dnsresolution._status_counts["success"] == 1

    def test_default_mode_resolve_success(self, exit_desc, mock_sock):
        """Any resolved IP = success in default mode (no expected_ip)."""
        sock, use = mock_sock
        sock.resolve.return_value = "93.184.215.14"
        with use():
            dnsresolution.validate(exit_desc, "test.ex.com")
        assert dnsresolution._status_counts["success"] == 1


# === Test: validate — failure paths ===

class TestValidateFailure:

    def test_wrong_ip(self, exit_desc, mock_sock):
        """Wrong IP in wildcard mode."""
        sock, use = mock_sock
        sock.resolve.return_value = "9.9.9.9"
        with use():
            dnsresolution.validate(exit_desc, "test.wc.com", "1.2.3.4")
        assert dnsresolution._status_counts["wrong_ip"] == 1

    def test_nxdomain_in_wildcard(self, exit_desc, mock_sock):
        """NXDOMAIN in wildcard mode = dns_fail."""
        sock, use = mock_sock
        sock.resolve.side_effect = error.SOCKSv5Error("error 4")
        with use():
            dnsresolution.validate(exit_desc, "test.wc.com", "1.2.3.4")
        assert dnsresolution._status_counts["dns_fail"] == 1

    def test_timeout(self, exit_desc, mock_sock):
        """Socket timeout after retries."""
        sock, use = mock_sock
        sock.resolve.side_effect = socket.timeout()
        with use(), patch.object(dnsresolution.time, 'sleep'):
            dnsresolution.validate(exit_desc, "test.ex.com")
        assert dnsresolution._status_counts["timeout"] == 1

    def test_eof_error(self, exit_desc, mock_sock):
        """EOF error after retries."""
        sock, use = mock_sock
        sock.resolve.side_effect = EOFError()
        with use(), patch.object(dnsresolution.time, 'sleep'):
            dnsresolution.validate(exit_desc, "test.ex.com")
        assert dnsresolution._status_counts["eof_error"] == 1


# === Test: validate — retry behavior ===

class TestValidateRetry:

    def test_retry_then_success(self, exit_desc, mock_sock):
        """Transient error on first attempt, success on second."""
        sock, use = mock_sock
        sock.resolve.side_effect = [
            error.SOCKSv5Error("error 1"),
            "1.2.3.4",
        ]
        with use(), patch.object(dnsresolution.time, 'sleep'):
            dnsresolution.validate(exit_desc, "test.ex.com")
        assert dnsresolution._status_counts["success"] == 1

    def test_socket_closed_on_error(self, exit_desc, mock_sock):
        """Socket is closed even on error."""
        sock, use = mock_sock
        sock.resolve.side_effect = Exception("boom")
        with use(), patch.object(dnsresolution.time, 'sleep'):
            dnsresolution.validate(exit_desc, "test.ex.com")
        assert sock.close.call_count == dnsresolution.MAX_RETRIES


# === Test: JSON output ===

class TestJsonOutput:

    def test_writes_json(self, exit_desc, mock_sock, analysis_dir):
        """Result JSON is written when analysis_dir is set."""
        sock, use = mock_sock
        sock.resolve.return_value = "1.2.3.4"
        with use():
            dnsresolution.validate(exit_desc, "q.ex.com")
        path = analysis_dir / ("dns_%s.json" % exit_desc.fingerprint)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["status"] == "success"
        assert data["fingerprint"] == exit_desc.fingerprint

    def test_no_write_without_dir(self, exit_desc, mock_sock):
        """No crash when analysis_dir is None."""
        import util
        util.analysis_dir = None
        sock, use = mock_sock
        sock.resolve.return_value = "1.2.3.4"
        with use():
            dnsresolution.validate(exit_desc, "q.ex.com")
        # Just verify no exception was raised.


# === Test: setup / teardown ===

class TestSetupTeardown:

    def test_setup_logs_mode(self):
        with patch.object(dnsresolution.log, 'info') as mock_log:
            dnsresolution.setup()
            calls = " ".join(str(c) for c in mock_log.call_args_list)
            assert "NXDOMAIN" in calls

    def test_teardown_logs_summary(self):
        dnsresolution._status_counts["success"] = 10
        dnsresolution._status_counts["timeout"] = 2
        with patch.object(dnsresolution.log, 'info') as mock_log:
            dnsresolution.teardown()
            calls = " ".join(str(c) for c in mock_log.call_args_list)
            assert "12" in calls or "10" in calls  # total or success count

    def test_teardown_accepts_kwargs(self):
        """teardown must accept arbitrary kwargs for forward compat."""
        dnsresolution.teardown(stats=None, controller=None, foo="bar")


# === Test: probe routing ===

class TestProbe:

    def test_default_mode(self, exit_desc):
        """Default mode calls validate for each domain."""
        run = MagicMock()
        dnsresolution.probe(
            exit_desc=exit_desc, target_host=None, target_port=None,
            run_python_over_tor=run, run_cmd_over_tor=None)
        assert run.call_count == len(dnsresolution.domains)

    def test_explicit_host(self, exit_desc):
        """Explicit host mode calls validate once."""
        run = MagicMock()
        dnsresolution.probe(
            exit_desc=exit_desc, target_host="custom.com",
            target_port=None,
            run_python_over_tor=run, run_cmd_over_tor=None)
        run.assert_called_once()
        # Domain should contain "custom.com"
        call_args = run.call_args[0]
        assert "custom.com" in call_args[2]

    def test_wildcard_mode(self, exit_desc):
        """Wildcard mode passes expected_ip."""
        dnsresolution.WILDCARD_DOMAIN = "wc.test.com"
        dnsresolution.EXPECTED_IP = "9.8.7.6"
        run = MagicMock()
        dnsresolution.probe(
            exit_desc=exit_desc, target_host=None, target_port=None,
            run_python_over_tor=run, run_cmd_over_tor=None)
        run.assert_called_once()
        call_args = run.call_args[0]
        assert "wc.test.com" in call_args[2]
        assert call_args[3] == "9.8.7.6"

    def test_accepts_kwargs(self, exit_desc):
        """probe must accept arbitrary kwargs (e.g. first_hop)."""
        run = MagicMock()
        dnsresolution.probe(
            exit_desc=exit_desc, target_host=None, target_port=None,
            run_python_over_tor=run, run_cmd_over_tor=None,
            first_hop="DEADBEEF", extra="ignored")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
