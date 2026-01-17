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
Module to detect broken DNS resolution on Tor exit relays.

Generates unique DNS queries per relay and validates resolution.

Modes:
- Wildcard (default): Query unique subdomain, verify expected IP returned
- NXDOMAIN (fallback): Query random UUID, treat NXDOMAIN as success

Usage:
    exitmap dnshealth                          # Wildcard mode (default)
    exitmap dnshealth -H example.com           # NXDOMAIN mode (fallback)
"""
import json
import logging
import os
import re
import signal
import socket
import time
import uuid
from collections import Counter

import error
import torsocks
import util
from util import exiturl

log = logging.getLogger(__name__)

# === Configuration ===
# Wildcard domain/IP can be customized via environment variables.
# To use your own validation infrastructure:
#   export DNS_WILDCARD_DOMAIN="your.wildcard.domain.com"
#   export DNS_EXPECTED_IP="1.2.3.4"
# The domain should be a wildcard DNS record that resolves *.domain to EXPECTED_IP.
WILDCARD_DOMAIN = os.environ.get("DNS_WILDCARD_DOMAIN", "tor.exit.validator.1aeo.com")
EXPECTED_IP = os.environ.get("DNS_EXPECTED_IP", "64.65.4.1")

# Timing settings (optimal values from experiments)
QUERY_TIMEOUT = int(os.environ.get("DNS_QUERY_TIMEOUT", "45"))   # seconds per query
MAX_RETRIES = int(os.environ.get("DNS_MAX_RETRIES", "3"))        # attempts per relay
HARD_TIMEOUT = int(os.environ.get("DNS_HARD_TIMEOUT", "180"))    # max seconds per probe
RETRY_DELAY = float(os.environ.get("DNS_RETRY_DELAY", "1.0"))    # seconds between retries

# SOCKS error code to status mapping
_SOCKS_ERROR_MAP = {
    1: "socks_general_failure",
    2: "socks_ruleset_blocked",
    3: "network_unreachable",
    4: "dns_fail",
    5: "connection_refused",
    6: "ttl_expired",
    7: "socks_command_unsupported",
    8: "socks_address_unsupported",
}

# Regex to extract SOCKS error code (compiled once)
_SOCKS_ERROR_RE = re.compile(r"(?:error\s*|0x0)([1-8])", re.IGNORECASE)

# Module state
destinations = None
_run_id = None
_status_counts = Counter()


class HardTimeoutError(Exception):
    """Raised when probe exceeds hard timeout."""


def _timeout_handler(signum, frame):
    raise HardTimeoutError()


class _AlarmContext:
    """Context manager for SIGALRM-based hard timeout (Unix only)."""
    
    __slots__ = ('timeout', 'old_handler')
    
    def __init__(self, timeout):
        self.timeout = timeout
        self.old_handler = None
    
    def __enter__(self):
        try:
            self.old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(self.timeout)
        except (ValueError, AttributeError):
            pass  # Not on Unix or in wrong thread
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            signal.alarm(0)
            if self.old_handler is not None:
                signal.signal(signal.SIGALRM, self.old_handler)
        except (ValueError, AttributeError):
            pass
        return False  # Don't suppress exceptions


def _normalize_ip(value):
    """Normalize IP to string."""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value if value is None else str(value)


def _parse_socks_error_code(err_str):
    """Extract SOCKS error code (1-8) from error string, or None."""
    match = _SOCKS_ERROR_RE.search(err_str)
    if match:
        code = int(match.group(1))
        if 1 <= code <= 8:
            return code
    return None


def _make_result(exit_desc, domain, expected_ip, status="unknown",
                 resolved_ip=None, latency_ms=None, error_msg=None, attempt=0):
    """Create result dict - single source of truth for result structure."""
    return {
        "exit_fingerprint": exit_desc.fingerprint,
        "exit_nickname": getattr(exit_desc, "nickname", "unknown"),
        "exit_address": getattr(exit_desc, "address", "unknown"),
        "query_domain": domain,
        "expected_ip": expected_ip,
        "timestamp": time.time(),
        "run_id": _run_id,
        "mode": "wildcard" if expected_ip else "nxdomain",
        "status": status,
        "resolved_ip": resolved_ip,
        "latency_ms": latency_ms,
        "error": error_msg,
        "attempt": attempt,
    }


def _elapsed_ms(start_time):
    """Calculate elapsed time in milliseconds."""
    return int((time.time() - start_time) * 1000)


def _write_result(result, fingerprint):
    """Write result to JSON file."""
    if not util.analysis_dir:
        return
    try:
        path = os.path.join(util.analysis_dir, "dnshealth_%s.json" % fingerprint)
        with open(path, "w") as f:
            json.dump(result, f)  # No indent for speed
    except Exception as e:
        log.error("Failed to write result for %s: %s", fingerprint, e)


# === Core Functions ===
def setup(consensus=None, target=None, **kwargs):
    """Initialize scan metadata."""
    global _run_id, _status_counts
    _run_id = time.strftime("%Y%m%d_%H%M%S")
    _status_counts = Counter()

    log.info("DNS Health: %s mode (%s)",
             "NXDOMAIN" if target else "Wildcard",
             target or ("%s -> %s" % (WILDCARD_DOMAIN, EXPECTED_IP)))
    log.info("Run ID: %s", _run_id)
    log.info("Configuration: QUERY_TIMEOUT=%ds, MAX_RETRIES=%d, HARD_TIMEOUT=%ds, RETRY_DELAY=%.1fs",
             QUERY_TIMEOUT, MAX_RETRIES, HARD_TIMEOUT, RETRY_DELAY)

    if util.analysis_dir:
        os.makedirs(util.analysis_dir, exist_ok=True)
        log.info("Analysis dir: %s", util.analysis_dir)


def generate_unique_query(fingerprint, base_domain):
    """Generate unique DNS query: {uuid}.{fp_prefix}.{base_domain}"""
    return "%s.%s.%s" % (uuid.uuid4().hex, fingerprint[:8].lower(), base_domain)


def resolve_with_retry(exit_desc, domain, expected_ip=None, retries=MAX_RETRIES):
    """Resolve domain through exit relay with retry logic."""
    exit_url = exiturl(exit_desc.fingerprint)
    result = _make_result(exit_desc, domain, expected_ip)

    for attempt in range(1, retries + 1):
        result["attempt"] = attempt
        sock = None
        start = time.time()
        status = error_msg = None

        try:
            sock = torsocks.torsocket()
            sock.settimeout(QUERY_TIMEOUT)
            ip = _normalize_ip(sock.resolve(domain))
            result["resolved_ip"] = ip
            result["latency_ms"] = _elapsed_ms(start)

            if expected_ip:
                if ip == expected_ip:
                    result["status"] = "success"
                    log.info("%s resolved to %s (correct)", exit_url, ip)
                else:
                    result["status"] = "wrong_ip"
                    result["error"] = "Expected %s, got %s" % (expected_ip, ip)
                    log.warning("%s wrong IP: %s != %s", exit_url, ip, expected_ip)
            else:
                result["status"] = "success"
                log.info("%s resolved to %s", exit_url, ip)
            return result

        except error.SOCKSv5Error as err:
            result["latency_ms"] = _elapsed_ms(start)
            err_str = str(err)
            err_code = _parse_socks_error_code(err_str)

            # NXDOMAIN (error 4) - not a retry-able error
            if err_code == 4:
                if expected_ip:
                    result["status"] = "dns_fail"
                    result["error"] = "NXDOMAIN (domain should resolve)"
                    log.warning("%s NXDOMAIN for wildcard", exit_url)
                else:
                    result["status"] = "success"
                    result["resolved_ip"] = "NXDOMAIN"
                    log.info("%s NXDOMAIN (DNS working)", exit_url)
                return result

            # Other SOCKS errors - may retry
            status = _SOCKS_ERROR_MAP.get(err_code, "socks_error")
            error_msg = err_str

        except socket.timeout:
            status, error_msg = "timeout", "Timeout after %ds" % QUERY_TIMEOUT

        except EOFError as err:
            status, error_msg = "eof_error", str(err)

        except Exception as err:
            status, error_msg = "exception", str(err)

        finally:
            # Ensure socket is closed even on error
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

        # Common error handling for non-SOCKS errors (only if status was set)
        if status is not None:
            result["latency_ms"] = _elapsed_ms(start)
            result["status"] = status
            result["error"] = error_msg
            log.warning("Attempt %d/%d: %s [%s] %s", attempt, retries, exit_url, status, error_msg)

            if attempt < retries:
                time.sleep(RETRY_DELAY)

    return result


def do_validation(exit_desc, query_domain, expected_ip):
    """Perform DNS validation with hard timeout protection."""
    global _status_counts
    fp = exit_desc.fingerprint

    with _AlarmContext(HARD_TIMEOUT):
        try:
            result = resolve_with_retry(exit_desc, query_domain, expected_ip)
        except HardTimeoutError:
            log.error("HARD_TIMEOUT %s exceeded %ds", exiturl(fp), HARD_TIMEOUT)
            result = _make_result(exit_desc, query_domain, expected_ip,
                                  status="hard_timeout",
                                  latency_ms=HARD_TIMEOUT * 1000,
                                  error_msg="Hard timeout after %ds" % HARD_TIMEOUT,
                                  attempt=MAX_RETRIES)
        except Exception as e:
            log.error("EXCEPTION %s: %s", exiturl(fp), e)
            result = _make_result(exit_desc, query_domain, expected_ip,
                                  status="exception", error_msg=str(e))

    _status_counts[result["status"]] += 1
    _write_result(result, fp)


def probe(exit_desc, target_host, target_port, run_python_over_tor,
          run_cmd_over_tor, **kwargs):
    """Probe exit relay's DNS resolution capability."""
    base_domain = target_host or WILDCARD_DOMAIN
    expected_ip = None if target_host else EXPECTED_IP
    query_domain = generate_unique_query(exit_desc.fingerprint, base_domain)
    run_python_over_tor(do_validation, exit_desc, query_domain, expected_ip)


def teardown():
    """Called after all probes complete."""
    total = sum(_status_counts.values())
    success = _status_counts.get("success", 0)
    success_rate = (success / total * 100) if total > 0 else 0

    log.info("=" * 60)
    log.info("DNS HEALTH SCAN COMPLETE")
    log.info("=" * 60)
    log.info("Run ID: %s", _run_id)
    log.info("Total: %d | Success: %d (%.2f%%) | Failed: %d",
             total, success, success_rate, total - success)
    log.info("Status breakdown: %s", dict(_status_counts))
    if util.analysis_dir:
        log.info("Results: %s", util.analysis_dir)
    log.info("=" * 60)


if __name__ == "__main__":
    log.critical("Module can only be run via exitmap, not standalone.")
