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

# First hop tracking (set by deployment scripts via environment)
# If set, this fingerprint is used as the first hop for all circuits
FIRST_HOP = os.environ.get("EXITMAP_FIRST_HOP", None)

# Tor Metrics URL template
TOR_METRICS_URL = "https://metrics.torproject.org/rs.html#details/{}"

# SOCKS5 error code classification for Tor RESOLVE (0xF0) command.
#
# When exitmap sends a SOCKS5 RESOLVE command, the exit relay performs a DNS
# lookup. Tor maps its internal stream-end reasons to SOCKS5 reply codes via
# stream_end_reason_to_socks5_response() in reasons.c:
# https://gitlab.torproject.org/tpo/core/tor/-/blob/HEAD/src/core/or/reasons.c
#
# SOCKS5 code definitions from socks5_status.h:
# https://gitlab.torproject.org/tpo/core/tor/-/blob/HEAD/src/lib/net/socks5_status.h
#
# Each entry: (status, error_category, error_subcategory, message, retryable)
#
# Categories:
#   dns     — exit relay's DNS resolution failed, is blocked, or is unreachable
#   tor     — Tor circuit/infrastructure failure, DNS resolver likely never consulted
#   exitmap — scanner application issue, not the relay's fault
#
_SOCKS_ERROR_INFO = {
    # 0x01 SOCKS5_GENERAL_ERROR
    # reasons.c: MISC, DESTROY, RESOURCELIMIT, HIBERNATING, INTERNAL, TORPROTOCOL
    # Tor infrastructure failures — circuit torn down, relay overloaded, relay
    # hibernating, internal error, protocol violation. None indicate DNS issues.
    # Retryable: RESOURCELIMIT could be momentary, and dead-circuit retries are fast.
    1: ("socks_general_failure", "tor", "tor_error",
        "Tor Error: SOCKS 1 - General failure (circuit/relay issue)", True),

    # 0x02 SOCKS5_NOT_ALLOWED
    # reasons.c: EXITPOLICY, ENTRYPOLICY
    # Relay's Tor exit policy blocks DNS resolution. Relay operator configured their
    # relay to not allow DNS lookups. DNS resolver was never consulted.
    # Not retryable: policy won't change between attempts.
    2: ("socks_ruleset_blocked", "dns", "relay_configuration",
        "DNS Error: SOCKS 2 - Not allowed by relay exit policy", False),

    # 0x03 SOCKS5_NET_UNREACHABLE
    # reasons.c: NET_UNREACHABLE
    # Exit relay cannot reach its DNS resolver at the network level. Relay is on
    # the Tor network but its local path to DNS is broken.
    # Retryable: could be a transient network blip on the relay side.
    3: ("network_unreachable", "dns", "dns_unreachable",
        "DNS Error: SOCKS 3 - Relay cannot reach DNS resolver", True),

    # 0x04 SOCKS5_HOST_UNREACHABLE
    # reasons.c: RESOLVEFAILED, NOROUTE
    # DNS resolver on exit relay could not resolve the domain. For RESOLVE commands
    # NOROUTE is rare (no TCP connection involved). Genuine DNS failure — resolver
    # was consulted and returned no result.
    # Not retryable: same query to same resolver = same negative-cached result.
    4: ("dns_fail", "dns", "resolution_failed",
        "DNS Error: SOCKS 4 - Domain not found (NXDOMAIN)", False),

    # 0x05 SOCKS5_CONNECTION_REFUSED
    # reasons.c: CONNECTREFUSED, CONNRESET, DONE
    # Tor circuit died before DNS answer returned. For RESOLVE there is no TCP
    # connection to "refuse" — these are circuit-level failures. Exit relay's
    # DNS resolver was likely never consulted.
    # Retryable: fast retry on dead circuit is low cost.
    5: ("connection_refused", "tor", "connection_reset",
        "Tor Error: SOCKS 5 - Circuit closed before DNS reply", True),

    # 0x06 SOCKS5_TTL_EXPIRED
    # reasons.c: TIMEOUT
    # Exit relay accepted the RESOLVE request but DNS lookup timed out. Relay's
    # DNS resolver is slow, overloaded, or unreachable from relay.
    # Retryable: resolver may recover between retry attempts.
    6: ("ttl_expired", "dns", "resolution_timeout",
        "DNS Error: SOCKS 6 - DNS resolution timed out on relay", True),

    # 0x07 SOCKS5_COMMAND_NOT_SUPPORTED
    # No stream end reason maps here in reasons.c. Local Tor does not understand
    # RESOLVE (0xF0). Should never happen with any modern Tor (support since 0.2.x).
    # Not retryable: same broken Tor binary on every attempt.
    7: ("socks_command_unsupported", "tor", "resolve_unsupported",
        "Tor Error: SOCKS 7 - Tor does not support RESOLVE command", False),

    # 0x08 SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED
    # No stream end reason maps here in reasons.c. Local Tor does not support
    # domain-name address type (0x03). Should never happen.
    # Not retryable: same broken Tor binary on every attempt.
    8: ("socks_address_unsupported", "tor", "address_type_unsupported",
        "Tor Error: SOCKS 8 - Tor does not support domain address type", False),
}

# Convenience lookups (derived from _SOCKS_ERROR_INFO for backward compatibility)
_SOCKS_ERROR_MAP = {code: info[0] for code, info in _SOCKS_ERROR_INFO.items()}
_SOCKS_ERROR_MESSAGES = {code: info[3] for code, info in _SOCKS_ERROR_INFO.items()}

# Regex to extract SOCKS error code (compiled once)
_SOCKS_ERROR_RE = re.compile(r"(?:error\s*|0x0)([1-8])", re.IGNORECASE)


def _fmt_first_hop(first_hop):
    """Format first hop for error messages. Returns full 40-char fingerprint or '<random>'."""
    if first_hop:
        return first_hop  # Full 40-char fingerprint
    return "<random>"


def _fmt_with_hop(msg, first_hop):
    """Append first hop fingerprint to message. Always shows first hop (specific or random)."""
    return "%s (first_hop=%s)" % (msg, _fmt_first_hop(first_hop))


def _fmt_exception(err):
    """Format exception as 'Type: message' or just 'Type' if message is empty."""
    err_type = type(err).__name__
    err_str = str(err)
    return "%s: %s" % (err_type, err_str) if err_str else err_type

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
                 resolved_ip=None, timing=None, error_msg=None, attempt=0, first_hop=None,
                 error_category=None, error_subcategory=None):
    """Create result dict - single source of truth for result structure."""
    fp = exit_desc.fingerprint
    return {
        "exit_fingerprint": fp,
        "exit_nickname": getattr(exit_desc, "nickname", "unknown"),
        "exit_address": getattr(exit_desc, "address", "unknown"),
        "tor_metrics_url": TOR_METRICS_URL.format(fp),
        "query_domain": domain,
        "expected_ip": expected_ip,
        "timestamp": time.time(),
        "run_id": _run_id,
        "mode": "wildcard" if expected_ip else "nxdomain",
        "first_hop": first_hop,  # Full 40-char fingerprint of first hop relay
        "status": status,
        "resolved_ip": resolved_ip,
        "timing": timing,  # {total_ms, socket_ms, dns_ms}
        "error": error_msg,
        "error_category": error_category,      # dns, tor, exitmap, or None (success)
        "error_subcategory": error_subcategory,  # specific failure type within category
        "attempt": attempt,
    }


def _elapsed_ms(start_time):
    """Calculate elapsed time in milliseconds."""
    return int((time.time() - start_time) * 1000)


def _make_timing(total_start):
    """
    Create timing dict with total elapsed time.
    
    Note: We cannot easily split Tor circuit establishment from DNS resolution
    because both happen inside torsocks.resolve() - negotiate() is called internally.
    The total_ms includes: socket creation + Tor circuit + DNS resolution.
    
    Args:
        total_start: Time when measurement began
    
    Returns:
        dict with total_ms
    """
    now = time.time()
    total_ms = int((now - total_start) * 1000) if total_start else None
    return {"total_ms": total_ms}


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
    log.info("First hop: %s", FIRST_HOP or "<random>")
    log.info("Configuration: QUERY_TIMEOUT=%ds, MAX_RETRIES=%d, HARD_TIMEOUT=%ds, RETRY_DELAY=%.1fs",
             QUERY_TIMEOUT, MAX_RETRIES, HARD_TIMEOUT, RETRY_DELAY)

    if util.analysis_dir:
        os.makedirs(util.analysis_dir, exist_ok=True)
        log.info("Analysis dir: %s", util.analysis_dir)


def generate_unique_query(fingerprint, base_domain):
    """Generate unique DNS query: {uuid}.{fp_prefix}.{base_domain}"""
    return "%s.%s.%s" % (uuid.uuid4().hex, fingerprint[:8].lower(), base_domain)


def resolve_with_retry(exit_desc, domain, expected_ip=None, retries=MAX_RETRIES, first_hop=None):
    """Resolve domain through exit relay with retry logic."""
    exit_url = exiturl(exit_desc.fingerprint)
    result = _make_result(exit_desc, domain, expected_ip, first_hop=first_hop)
    retryable = True  # Default: allow retries unless overridden

    for attempt in range(1, retries + 1):
        result["attempt"] = attempt
        sock = None
        total_start = time.time()
        status = error_msg = None
        retryable = True

        try:
            sock = torsocks.torsocket()
            sock.settimeout(QUERY_TIMEOUT)
            ip = _normalize_ip(sock.resolve(domain))

            result["resolved_ip"] = ip
            result["timing"] = _make_timing(total_start)

            if expected_ip:
                if ip == expected_ip:
                    result["status"] = "success"
                    result["error_category"] = None
                    result["error_subcategory"] = None
                    log.info("%s resolved to %s (correct)", exit_url, ip)
                else:
                    result["status"] = "wrong_ip"
                    result["error"] = "DNS Error: Expected %s, got %s" % (expected_ip, ip)
                    result["error_category"] = "dns"
                    result["error_subcategory"] = "wrong_ip"
                    log.warning("%s wrong IP: %s != %s", exit_url, ip, expected_ip)
            else:
                result["status"] = "success"
                result["error_category"] = None
                result["error_subcategory"] = None
                log.info("%s resolved to %s", exit_url, ip)
            return result

        except error.SOCKSv5Error as err:
            # SOCKS error — look up category/subcategory from _SOCKS_ERROR_INFO
            result["timing"] = _make_timing(total_start)
            err_str = str(err)
            err_code = _parse_socks_error_code(err_str)

            # Special handling for code 4 (NXDOMAIN) — mode-dependent
            if err_code == 4:
                if expected_ip:
                    result["status"] = "dns_fail"
                    result["error"] = "DNS Error: SOCKS 4 - Domain not found (NXDOMAIN)"
                    result["error_category"] = "dns"
                    result["error_subcategory"] = "resolution_failed"
                    log.warning("%s NXDOMAIN for wildcard", exit_url)
                else:
                    result["status"] = "success"
                    result["resolved_ip"] = "NXDOMAIN"
                    result["error_category"] = None
                    result["error_subcategory"] = None
                    log.info("%s NXDOMAIN (DNS working)", exit_url)
                return result

            # All other SOCKS errors — use _SOCKS_ERROR_INFO for classification
            info = _SOCKS_ERROR_INFO.get(err_code)
            if info:
                status, category, subcategory, base_msg, retryable = info
                result["error_category"] = category
                result["error_subcategory"] = subcategory
            else:
                status = "socks_error"
                base_msg = "Exitmap Error: SOCKS %s - Unknown error code" % err_code
                result["error_category"] = "exitmap"
                result["error_subcategory"] = "unknown_socks_code"
                retryable = False
            error_msg = _fmt_with_hop(base_msg, first_hop)

        except socket.timeout:
            status = "timeout"
            error_msg = _fmt_with_hop("DNS Error: Timeout after %ds" % QUERY_TIMEOUT, first_hop)
            result["error_category"] = "dns"
            result["error_subcategory"] = "socket_timeout"

        except EOFError:
            status = "eof_error"
            error_msg = _fmt_with_hop("Tor Error: Connection closed unexpectedly", first_hop)
            result["error_category"] = "tor"
            result["error_subcategory"] = "connection_dropped"

        except FileNotFoundError:
            # Tor SOCKS socket gone - process likely crashed
            status = "tor_connection_lost"
            error_msg = _fmt_with_hop(
                "Exitmap Error: Lost connection to Tor (socket gone) while testing exit %s" % exit_desc.fingerprint[:8],
                first_hop)
            result["error_category"] = "exitmap"
            result["error_subcategory"] = "socket_gone"

        except ConnectionRefusedError:
            # Tor not accepting connections
            status = "tor_connection_refused"
            error_msg = _fmt_with_hop(
                "Exitmap Error: Tor refused connection (may be restarting) while testing exit %s" % exit_desc.fingerprint[:8],
                first_hop)
            result["error_category"] = "exitmap"
            result["error_subcategory"] = "connection_refused"

        except HardTimeoutError:
            # Let hard timeout propagate to do_validation handler
            raise

        except Exception as err:
            status = "exception"
            error_msg = "Exitmap Error: %s" % _fmt_exception(err)
            result["error_category"] = "exitmap"
            result["error_subcategory"] = "exception"
            retryable = False

        finally:
            # Ensure socket is closed even on error
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

        # Set result fields and decide whether to retry
        if status is not None:
            result["timing"] = _make_timing(total_start)
            result["status"] = status
            result["error"] = error_msg
            log.warning("Attempt %d/%d: %s [%s] %s", attempt, retries, exit_url, status, error_msg)

            if not retryable:
                return result

            if attempt < retries:
                time.sleep(RETRY_DELAY)

    return result


def do_validation(exit_desc, query_domain, expected_ip, first_hop=None):
    """Perform DNS validation with hard timeout protection."""
    fp = exit_desc.fingerprint

    with _AlarmContext(HARD_TIMEOUT):
        try:
            result = resolve_with_retry(exit_desc, query_domain, expected_ip, first_hop=first_hop)
        except HardTimeoutError:
            log.error("HARD_TIMEOUT %s exceeded %ds (first_hop=%s)", 
                      exiturl(fp), HARD_TIMEOUT, _fmt_first_hop(first_hop))
            # Hard timeout - we don't know where time was spent
            hard_timing = {"total_ms": HARD_TIMEOUT * 1000, "socket_ms": None, "dns_ms": None}
            result = _make_result(exit_desc, query_domain, expected_ip,
                                  status="hard_timeout",
                                  timing=hard_timing,
                                  error_msg=_fmt_with_hop("DNS Error: Hard timeout after %ds" % HARD_TIMEOUT, first_hop),
                                  attempt=MAX_RETRIES,
                                  first_hop=first_hop,
                                  error_category="dns",
                                  error_subcategory="hard_timeout")
        except Exception as e:
            error_msg = "Exitmap Error: %s" % _fmt_exception(e)
            log.error("EXCEPTION %s: %s (first_hop=%s)", 
                      exiturl(fp), error_msg, _fmt_first_hop(first_hop))
            result = _make_result(exit_desc, query_domain, expected_ip,
                                  status="exception", error_msg=error_msg, first_hop=first_hop,
                                  error_category="exitmap",
                                  error_subcategory="exception")

    _status_counts[result["status"]] += 1
    _write_result(result, fp)


def probe(exit_desc, target_host, target_port, run_python_over_tor,
          run_cmd_over_tor, first_hop=None, **kwargs):
    """Probe exit relay's DNS resolution capability."""
    base_domain = target_host or WILDCARD_DOMAIN
    expected_ip = None if target_host else EXPECTED_IP
    query_domain = generate_unique_query(exit_desc.fingerprint, base_domain)
    # Use passed first_hop or fall back to environment variable
    first_hop_fpr = first_hop or FIRST_HOP
    run_python_over_tor(do_validation, exit_desc, query_domain, expected_ip, first_hop_fpr)


# Default relay info when lookup fails
_UNKNOWN_RELAY = ("unknown", "unknown")


def _get_relay_info(controller, fingerprint):
    """Look up relay (nickname, address) from controller. Returns _UNKNOWN_RELAY on failure."""
    if not controller or not fingerprint:
        return _UNKNOWN_RELAY
    try:
        desc = controller.get_server_descriptor(relay=fingerprint)
        if desc:
            return (getattr(desc, "nickname", None) or "unknown",
                    getattr(desc, "address", None) or "unknown")
    except Exception:
        pass  # Relay offline or controller closing
    return _UNKNOWN_RELAY


def _write_circuit_failures(stats, controller=None):
    """Write circuit failure data to JSON files for aggregation."""
    if not util.analysis_dir or not stats:
        return 0
    
    # Get failed relays once (was called twice before)
    failed_relays = stats.get_failed_circuit_relays()
    
    # Partition into resolved vs unresolved in single pass
    resolved, unresolved = [], []
    for fp, info in failed_relays.items():
        (unresolved if fp.startswith("UNRESOLVED_") else resolved).append((fp, info))
    
    # Write scan_stats.json
    scan_stats = {
        "total_circuits": stats.total_circuits,
        "successful_circuits": stats.successful_circuits,
        "failed_circuits": stats.failed_circuits,
        "resolved_failures": len(resolved),
        "unresolved_failures": len(unresolved),
        "run_id": _run_id,
        "timestamp": time.time(),
    }
    try:
        with open(os.path.join(util.analysis_dir, "scan_stats.json"), "w") as f:
            json.dump(scan_stats, f)
        log.info("Scan stats: %d total, %d successful, %d failed",
                 stats.total_circuits, stats.successful_circuits, stats.failed_circuits)
    except Exception as e:
        log.error("Failed to write scan stats: %s", e)
    
    if not resolved:
        log.debug("No circuit failure fingerprints captured")
        return stats.failed_circuits
    
    # Build failure entries with relay lookups
    failures = []
    for fp, info in resolved:
        nickname, address = _get_relay_info(controller, fp)
        first_hop_fp = info.get("first_hop")
        fh_nick, fh_addr = _get_relay_info(controller, first_hop_fp)
        failures.append({
            "exit_fingerprint": fp, "exit_nickname": nickname, "exit_address": address,
            "tor_metrics_url": TOR_METRICS_URL.format(fp),
            "status": "relay_unreachable", "circuit_reason": info["reason_key"],
            "error": info["error"], "tor_reason": info["tor_reason"],
            "timestamp": info["timestamp"], "run_id": _run_id,
            "first_hop": first_hop_fp, "first_hop_nickname": fh_nick, "first_hop_address": fh_addr,
            "query_domain": None, "expected_ip": None, "resolved_ip": None,
            "timing": None, "mode": None, "attempt": None,
        })
    
    if unresolved:
        log.warning("Skipped %d unresolved circuit failures (no fingerprint)", len(unresolved))
    
    try:
        with open(os.path.join(util.analysis_dir, "circuit_failures.json"), "w") as f:
            json.dump(failures, f)
        log.info("Wrote %d circuit failures to circuit_failures.json", len(failures))
    except Exception as e:
        log.error("Failed to write circuit failures: %s", e)
    
    return stats.failed_circuits


def _write_terminated_relays(relays, controller=None):
    """Write terminated relays as process_timeout (forcibly killed mid-scan).

    The entire subprocess — which includes circuit setup, SOCKS negotiation,
    DNS query, and retries — stalled so badly the parent process killed it.
    This could be a hung Tor circuit, stuck socket, or deadlock. Not
    necessarily a DNS issue.
    """
    if not util.analysis_dir or not relays:
        return 0
    now = time.time()
    for fp in relays:
        nickname, address = _get_relay_info(controller, fp)
        _write_result({
            "exit_fingerprint": fp, "exit_nickname": nickname, "exit_address": address,
            "status": "process_timeout", "run_id": _run_id, "timestamp": now,
            "error": "Tor Error: Process terminated due to timeout",
            "error_category": "tor",
            "error_subcategory": "process_terminated",
            "tor_metrics_url": TOR_METRICS_URL.format(fp),
            "query_domain": None, "expected_ip": None, "resolved_ip": None,
            "timing": None, "mode": None, "first_hop": None, "attempt": None,
        }, fp)
    return len(relays)


def teardown(stats=None, controller=None, terminated_relays=None, **kwargs):
    """Called after all probes complete."""
    circuit_failures = _write_circuit_failures(stats, controller) if stats else 0
    terminated = _write_terminated_relays(terminated_relays, controller)
    if terminated:
        _status_counts["process_timeout"] = _status_counts.get("process_timeout", 0) + terminated
    
    total, success = sum(_status_counts.values()), _status_counts.get("success", 0)
    log.info("=" * 60)
    log.info("DNS HEALTH SCAN COMPLETE | %s | %d total | %d success (%.1f%%)",
             _run_id, total, success, (success / total * 100) if total else 0)
    log.info("Breakdown: %s", dict(_status_counts))
    if circuit_failures: log.info("Circuit failures: %d", circuit_failures)
    if terminated: log.info("Terminated during retry: %d", terminated)
    if util.analysis_dir: log.info("Results: %s", util.analysis_dir)
    log.info("=" * 60)


if __name__ == "__main__":
    log.critical("Module can only be run via exitmap, not standalone.")
