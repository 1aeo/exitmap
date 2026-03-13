#!/usr/bin/env python3

# Copyright 2021 The Tor Project Inc.
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
Module to detect broken DNS resolution.

Generates unique DNS queries per exit relay and validates resolution,
with retry logic and optional structured JSON output.

Modes:
- Default: unique query per relay per domain, NXDOMAIN = DNS works
- Wildcard: set DNS_WILDCARD_DOMAIN and DNS_EXPECTED_IP env vars
  to verify resolved IP matches expected

Usage:
    exitmap dnsresolution                       # default NXDOMAIN mode
    exitmap dnsresolution -H example.com        # NXDOMAIN against one domain
    exitmap --analysis-dir /tmp/out dnsresolution   # write JSON results
"""

import json
import logging
import os
import re
import socket
import time
import uuid
from collections import Counter

import error
import torsocks
import util
from util import exiturl

log = logging.getLogger(__name__)

destinations = None

# Domains to test in default mode (backward compatible).
domains = {
    "www.example.com": [],
    "www.torproject.org": [],
}

# Optional wildcard validation mode, activated via environment variables.
# Set DNS_WILDCARD_DOMAIN to a wildcard DNS record (*.domain -> EXPECTED_IP).
WILDCARD_DOMAIN = os.environ.get("DNS_WILDCARD_DOMAIN", "")
EXPECTED_IP = os.environ.get("DNS_EXPECTED_IP", "")

MAX_RETRIES = 2
RETRY_DELAY = 1.0
QUERY_TIMEOUT = 10

# Regex to detect SOCKS error code 4 (host unreachable / NXDOMAIN).
_NXDOMAIN_RE = re.compile(r"(?:error\s*|0x0)4", re.IGNORECASE)

_status_counts = Counter()


def generate_unique_query(fingerprint, base_domain):
    """Generate a unique DNS query to defeat resolver caching.

    Returns ``{uuid}.{fp_prefix}.{base_domain}`` so every relay gets a
    fresh query that cannot be served from cache.
    """
    return "%s.%s.%s" % (
        uuid.uuid4().hex, fingerprint[:8].lower(), base_domain)


def _is_nxdomain(err_str):
    """Return True if the SOCKS error string indicates NXDOMAIN (code 4)."""
    return bool(_NXDOMAIN_RE.search(err_str))


def _normalize_ip(value):
    """Normalize resolver return value to a string."""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value if value is None else str(value)


def _write_result(result, fingerprint):
    """Write per-relay JSON result to analysis_dir, if configured."""
    if not util.analysis_dir:
        return
    try:
        path = os.path.join(
            util.analysis_dir, "dns_%s.json" % fingerprint)
        with open(path, "w") as fd:
            json.dump(result, fd)
    except Exception as exc:
        log.error("Failed to write result for %s: %s", fingerprint, exc)


def validate(exit_desc, domain, expected_ip=None):
    """Resolve *domain* through the exit relay, with retries.

    When *expected_ip* is set (wildcard mode), the resolved IP is compared
    against it.  When *expected_ip* is ``None`` (NXDOMAIN mode), a SOCKS
    error 4 (NXDOMAIN) counts as success because it proves the resolver
    reached the authoritative server and got the correct "does not exist"
    answer.

    Results are written as JSON to ``--analysis-dir`` when configured.
    """
    exit_url = exiturl(exit_desc.fingerprint)
    result = {
        "fingerprint": exit_desc.fingerprint,
        "domain": domain,
        "expected_ip": expected_ip,
        "status": "unknown",
        "resolved_ip": None,
        "error": None,
        "attempt": 0,
        "total_ms": None,
        "timestamp": time.time(),
    }

    for attempt in range(1, MAX_RETRIES + 1):
        result["attempt"] = attempt
        sock = None
        t0 = time.time()

        try:
            sock = torsocks.torsocket()
            sock.settimeout(QUERY_TIMEOUT)
            ip = _normalize_ip(sock.resolve(domain))

            result["resolved_ip"] = ip
            result["total_ms"] = int((time.time() - t0) * 1000)

            if expected_ip:
                if ip == expected_ip:
                    result["status"] = "success"
                    log.info("%s resolved %s to %s (correct)",
                             exit_url, domain, ip)
                else:
                    result["status"] = "wrong_ip"
                    result["error"] = (
                        "Expected %s, got %s" % (expected_ip, ip))
                    log.warning("%s wrong IP for %s: %s != %s",
                                exit_url, domain, ip, expected_ip)
            else:
                result["status"] = "success"
                log.info("%s resolved %s to %s", exit_url, domain, ip)

            _status_counts[result["status"]] += 1
            _write_result(result, exit_desc.fingerprint)
            return

        except error.SOCKSv5Error as err:
            result["total_ms"] = int((time.time() - t0) * 1000)
            err_str = str(err)

            if _is_nxdomain(err_str):
                if expected_ip:
                    # Wildcard mode: NXDOMAIN means DNS is broken.
                    result["status"] = "dns_fail"
                    result["error"] = "NXDOMAIN"
                    log.warning("%s NXDOMAIN for %s (wildcard mode)",
                                exit_url, domain)
                else:
                    # Default mode: NXDOMAIN means DNS works.
                    result["status"] = "success"
                    result["resolved_ip"] = "NXDOMAIN"
                    log.info("%s NXDOMAIN for %s (DNS working)",
                             exit_url, domain)

                _status_counts[result["status"]] += 1
                _write_result(result, exit_desc.fingerprint)
                return

            # Other SOCKS errors — transient, retry.
            result["status"] = "socks_error"
            result["error"] = err_str
            log.warning("Attempt %d/%d: %s SOCKS error for %s: %s",
                        attempt, MAX_RETRIES, exit_url, domain, err_str)

        except socket.timeout:
            result["total_ms"] = int((time.time() - t0) * 1000)
            result["status"] = "timeout"
            result["error"] = "Timeout after %ds" % QUERY_TIMEOUT
            log.warning("Attempt %d/%d: %s timeout for %s",
                        attempt, MAX_RETRIES, exit_url, domain)

        except EOFError:
            result["total_ms"] = int((time.time() - t0) * 1000)
            result["status"] = "eof_error"
            result["error"] = "Connection closed unexpectedly"
            log.warning("Attempt %d/%d: %s EOF for %s",
                        attempt, MAX_RETRIES, exit_url, domain)

        except Exception as err:
            result["total_ms"] = int((time.time() - t0) * 1000)
            result["status"] = "exception"
            result["error"] = "%s: %s" % (type(err).__name__, err)
            log.warning("Attempt %d/%d: %s exception for %s: %s",
                        attempt, MAX_RETRIES, exit_url, domain, err)

        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY)

    # All retries exhausted.
    _status_counts[result["status"]] += 1
    _write_result(result, exit_desc.fingerprint)


def setup(consensus=None, target=None, **kwargs):
    """Log scan mode and create analysis directory if needed."""
    global _status_counts
    _status_counts = Counter()

    if WILDCARD_DOMAIN and not target:
        log.info("dnsresolution: wildcard mode (%s -> %s)",
                 WILDCARD_DOMAIN, EXPECTED_IP)
    elif target:
        log.info("dnsresolution: NXDOMAIN mode against %s", target)
    else:
        log.info("dnsresolution: NXDOMAIN mode against %s",
                 ", ".join(domains.keys()))

    if util.analysis_dir:
        os.makedirs(util.analysis_dir, exist_ok=True)
        log.info("Analysis dir: %s", util.analysis_dir)


def teardown(**kwargs):
    """Log summary statistics."""
    total = sum(_status_counts.values())
    success = _status_counts.get("success", 0)
    if total:
        log.info("dnsresolution complete: %d total, %d success (%.1f%%)",
                 total, success, success / total * 100)
        log.info("Breakdown: %s", dict(_status_counts))
    else:
        log.info("dnsresolution complete: no probes recorded")


def probe(exit_desc, target_host, target_port,
          run_python_over_tor, run_cmd_over_tor, **kwargs):
    """Probe exit relay DNS resolution with unique queries and retries."""
    if WILDCARD_DOMAIN and not target_host:
        # Wildcard validation mode.
        query = generate_unique_query(
            exit_desc.fingerprint, WILDCARD_DOMAIN)
        run_python_over_tor(validate, exit_desc, query, EXPECTED_IP)
    elif target_host:
        # Explicit host — NXDOMAIN mode with unique subdomain.
        query = generate_unique_query(
            exit_desc.fingerprint, target_host)
        run_python_over_tor(validate, exit_desc, query)
    else:
        # Default — test each domain with unique queries.
        for domain in domains:
            query = generate_unique_query(
                exit_desc.fingerprint, domain)
            run_python_over_tor(validate, exit_desc, query)


if __name__ == "__main__":
    log.critical("Module can only be run over Tor, and not stand-alone.")
