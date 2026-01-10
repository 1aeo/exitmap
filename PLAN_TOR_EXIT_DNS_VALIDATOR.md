# Tor Exit Relay DNS Validation System - Implementation Plan

## Executive Summary

This plan outlines the architecture for a system that periodically connects to all Tor exit relays, runs unique DNS queries to confirm working DNS resolution, and reports broken DNS to operators. The system builds upon the existing `exitmap` framework and incorporates deployment patterns from the `aroivalidator-deploy` project.

**This plan incorporates best ideas from three approaches:**
- **Claude (this plan)**: Comprehensive architecture and deployment patterns
- **GPT5.2 (cursor/tor-exit-relay-dns-check-a8cc)**: Error taxonomy, sharding, alerting strategy
- **Gemini 3 (cursor/tor-exit-relay-dns-check-6548)**: Working implementation, NXDOMAIN handling

---

## 1. Current State Analysis

### 1.1 Exitmap Codebase (This Repository)

**Existing DNS Modules:**
- `dnsresolution.py` - Basic DNS resolution test using Tor's SOCKS5 RESOLVE extension
- `dnspoison.py` - DNS poisoning detection comparing results to expected IPs
- `dnssec.py` - DNSSEC validation testing

**Core Components:**
- `exitmap.py` - Main entry point, bootstraps Tor, iterates over exits
- `eventhandler.py` - Handles circuit/stream events, runs modules via multiprocessing
- `torsocks.py` - SOCKS5 interface with DNS resolution support
- `relayselector.py` - Filters exits by various criteria

**Recent Experiments (cursor/exit-relay-dns-validation-0896 branch):**
- DNS resolution validation report for specific operators
- Found 5% failure rate on some operators (prsv.ch: 9 relays with DNS issues)
- Identified patterns: multiple relays on same IP failing together

### 1.2 Alternative Implementations Reviewed

**GPT5.2 Branch (cursor/tor-exit-relay-dns-check-a8cc):**
- Detailed strategic plan with error taxonomy
- Sharding concept (`--shard N/M`) for distributed scanning
- Alerting strategy: 2 consecutive failures before notification
- Pages Function proxy for dynamic caching

**Gemini 3 Branch (cursor/tor-exit-relay-dns-check-6548):**
- Working `dnsunique.py` module implementation
- Key insight: SOCKS error 4 (Host Unreachable) = NXDOMAIN = **DNS is working**
- UUID-based unique query generation
- Per-relay JSON output files with bash aggregation
- Integration with existing exitmap `analysis_dir`

### 1.3 AROIValidator Patterns (Reference)

**Scheduling & Deployment:**
```
aroivalidator-deploy/
├── scripts/
│   ├── run-batch-validation.sh   # Hourly cron job
│   ├── upload-do.sh              # Cloud storage upload
│   └── install.sh                # Setup with cron
├── config.env.example            # Configuration template
└── public/                       # JSON results directory
```

**Key Patterns:**
1. Atomic locking via `flock` to prevent concurrent runs
2. Parallel uploads to multiple cloud providers
3. JSON manifest (`files.json`) listing all results
4. `latest.json` symlink to most recent results
5. Hourly cron scheduling with cloud upload

---

## 2. Proposed Architecture

### 2.1 System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    DNS Validator System                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │   Scheduler  │───▶│  DNS Prober  │───▶│  Result Publisher │  │
│  │   (cron)     │    │  (exitmap)   │    │  (cloud storage)  │  │
│  └──────────────┘    └──────────────┘    └──────────────────┘  │
│         │                   │                     │              │
│         ▼                   ▼                     ▼              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  Lock File   │    │  Unique DNS  │    │   JSON Results   │  │
│  │  (atomic)    │    │  Query Gen   │    │   + Dashboard    │  │
│  └──────────────┘    └──────────────┘    └──────────────────┘  │
│         │                                         │              │
│         ▼                                         ▼              │
│  ┌──────────────┐                        ┌──────────────────┐  │
│  │   Sharding   │                        │     Alerting     │  │
│  │  (optional)  │                        │  (2+ failures)   │  │
│  └──────────────┘                        └──────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Key Design Decisions (Consolidated from All Approaches)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Unique query generation | UUID + fingerprint prefix | Simple, guaranteed unique (Gemini 3) |
| NXDOMAIN interpretation | **Success** (DNS works!) | SOCKS error 4 = resolver responded correctly (Gemini 3) |
| Error taxonomy | `success`, `dns_fail`, `timeout`, `circuit_fail` | Actionable categories (GPT5.2) |
| Output format | Per-relay JSON files → aggregated report | Works with exitmap's analysis_dir (Gemini 3) |
| Retry strategy | 1-2 retries for DNS failures only | Reduce flakiness without hiding real issues (GPT5.2) |
| Sharding | `--shard N/M` (optional) | Scale to multiple hosts (GPT5.2) |
| Alerting threshold | 2 consecutive run failures | Avoid alert fatigue (GPT5.2) |

### 2.3 Component Breakdown

#### Component 1: DNS Health Module (`src/modules/dnshealth.py`)

**Purpose:** Generate unique DNS queries per exit relay to detect broken DNS resolution.

**Key Features (consolidated):**
- **Unique queries**: `{uuid}.{fingerprint[:8]}.{base_domain}` (Gemini 3 pattern)
- **NXDOMAIN = Success**: SOCKS error 4 means DNS resolver is working (Gemini 3 insight)
- **Error classification**: Separate circuit failures from DNS failures (GPT5.2)
- **Per-relay output**: Individual JSON files to analysis_dir (Gemini 3)
- **Retry logic**: 1-2 retries for transient failures (GPT5.2)

```python
# Status taxonomy (from GPT5.2, refined):
# - "success"      : Resolved to IP or NXDOMAIN (DNS working)
# - "dns_fail"     : SOCKS error other than NXDOMAIN (DNS broken)
# - "timeout"      : Resolution timed out
# - "circuit_fail" : Circuit never built (not a DNS issue)
```

#### Component 2: Batch Runner (`scripts/run_dns_validation.sh`)

**Purpose:** Orchestrate full network scan with proper locking and output handling.

**Features (consolidated):**
- Atomic lock file via `flock` (all approaches)
- Embedded Python aggregation (Gemini 3)
- Sharding support `--shard N/M` (GPT5.2)
- Configurable via environment variables

#### Component 3: Result Aggregator

**Purpose:** Collect per-relay JSON files into unified report.

**Features:**
- Group failures by exit IP (common DNS server issues)
- Calculate per-operator failure rates
- Track consecutive failures for alerting (GPT5.2)
- Generate `latest.json` + `files.json` manifest

#### Component 4: Publisher (`scripts/publish-results.sh`)

**Purpose:** Upload results to cloud storage and update manifest.

**Features:**
- Parallel upload to DO Spaces + R2 (aroivalidator pattern)
- Pages Function proxy for dynamic caching (GPT5.2)
- Historical data retention

---

## 3. Implementation Phases

### Phase 1: Core DNS Validation Module (Week 1-2)

**New Files:**
```
src/modules/dnshealth.py          # Main validation module (consolidated name)
```

**`src/modules/dnshealth.py` Design (Best of All Approaches):**

```python
#!/usr/bin/env python3
# Copyright 2021 The Tor Project Inc.
#
# This file is part of exitmap.
#
# exitmap is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""
Module to detect broken DNS resolution on Tor exit relays.

Generates unique DNS queries per relay to avoid caching issues and
confirm live DNS resolution capability.

Key insight (from Gemini 3): SOCKS error 4 (Host Unreachable) when resolving
a random UUID subdomain means NXDOMAIN - the DNS resolver IS working correctly!

Status taxonomy (from GPT5.2):
- "success"      : Resolved to IP or NXDOMAIN (DNS working)
- "dns_fail"     : SOCKS error indicating DNS failure
- "timeout"      : Resolution timed out  
- "circuit_fail" : Would be set by eventhandler if circuit never built
"""
import logging
import socket
import time
import json
import os
import uuid
from typing import Dict, Any

import torsocks
import error
import util
from util import exiturl

log = logging.getLogger(__name__)

# Configurable base domain
# Option 1: Use example.com (random UUID will get NXDOMAIN = success)
# Option 2: Use your own wildcard domain for IP verification
DEFAULT_BASE_DOMAIN = "example.com"
QUERY_TIMEOUT = 10  # seconds
MAX_RETRIES = 1     # Retry once for transient failures (GPT5.2 suggestion)

destinations = None  # Module uses DNS resolution, not TCP connections

# Run metadata
_run_id = None


def setup(consensus=None, target=None, **kwargs):
    """Initialize scan metadata."""
    global _run_id
    _run_id = time.strftime("%Y%m%d_%H%M%S")
    log.info(f"DNS Health module initialized. Run ID: {_run_id}")


def generate_unique_query(fingerprint: str, base_domain: str) -> str:
    """
    Generate a unique DNS query for this relay.
    
    Format: {uuid}.{fingerprint_prefix}.{base_domain}
    
    Using UUID ensures:
    - No caching between runs or relays
    - Unique even if same relay tested multiple times
    """
    unique_id = str(uuid.uuid4())
    fp_prefix = fingerprint[:8].lower()
    return f"{unique_id}.{fp_prefix}.{base_domain}"


def resolve_with_retry(exit_desc, domain: str, max_retries: int = MAX_RETRIES) -> Dict[str, Any]:
    """
    Attempt to resolve domain through exit relay with retry logic.
    
    Key insight from Gemini 3: SOCKS error 4 = NXDOMAIN = DNS IS WORKING!
    This is because "Host Unreachable" for DNS resolution means the resolver
    correctly identified that the domain doesn't exist.
    """
    exit_fp = exit_desc.fingerprint
    exit_url = exiturl(exit_fp)
    
    result = {
        "exit_fingerprint": exit_fp,
        "exit_nickname": getattr(exit_desc, 'nickname', 'unknown'),
        "exit_address": getattr(exit_desc, 'address', 'unknown'),
        "query_domain": domain,
        "timestamp": time.time(),
        "run_id": _run_id,
        "status": "unknown",
        "resolved_ip": None,
        "latency_ms": None,
        "error": None,
        "attempts": 0,
    }
    
    last_error = None
    
    for attempt in range(max_retries + 1):
        result["attempts"] = attempt + 1
        sock = torsocks.torsocket()
        sock.settimeout(QUERY_TIMEOUT)
        
        start_time = time.time()
        
        try:
            ip = sock.resolve(domain)
            # Successfully resolved to an IP
            result["status"] = "success"
            result["resolved_ip"] = ip
            result["latency_ms"] = int((time.time() - start_time) * 1000)
            log.info(f"✓ {exit_url} resolved {domain} to {ip}")
            return result
            
        except error.SOCKSv5Error as err:
            err_str = str(err)
            
            # KEY INSIGHT (Gemini 3): SOCKS error 4 = Host Unreachable = NXDOMAIN
            # For a random UUID subdomain, NXDOMAIN means DNS IS WORKING!
            if "error 4" in err_str.lower() or "host unreachable" in err_str.lower():
                result["status"] = "success"
                result["resolved_ip"] = "NXDOMAIN"
                result["latency_ms"] = int((time.time() - start_time) * 1000)
                log.info(f"✓ {exit_url} returned NXDOMAIN for {domain} (DNS working)")
                return result
            
            # Other SOCKS errors indicate actual DNS failure
            last_error = f"SOCKS error: {err}"
            log.debug(f"Attempt {attempt+1}: {exit_url} DNS error: {err}")
            
        except socket.timeout:
            last_error = f"Timeout after {QUERY_TIMEOUT}s"
            log.debug(f"Attempt {attempt+1}: {exit_url} timed out")
            
        except EOFError as err:
            last_error = f"Connection closed: {err}"
            log.debug(f"Attempt {attempt+1}: {exit_url} EOF error")
            
        except Exception as err:
            last_error = f"Unexpected error: {err}"
            log.debug(f"Attempt {attempt+1}: {exit_url} exception: {err}")
        
        # Small delay before retry
        if attempt < max_retries:
            time.sleep(0.5)
    
    # All retries exhausted - determine failure type
    result["error"] = last_error
    
    if "timeout" in last_error.lower():
        result["status"] = "timeout"
    else:
        result["status"] = "dns_fail"
    
    log.warning(f"✗ {exit_url} DNS FAILED after {result['attempts']} attempts: {last_error}")
    return result


def probe(exit_desc, target_host, target_port, run_python_over_tor, 
          run_cmd_over_tor, **kwargs):
    """
    Probe the given exit relay's DNS resolution capability.
    """
    base_domain = target_host if target_host else DEFAULT_BASE_DOMAIN
    query_domain = generate_unique_query(exit_desc.fingerprint, base_domain)
    
    def do_validation(exit_desc, query_domain):
        result = resolve_with_retry(exit_desc, query_domain)
        
        # Write individual result to analysis_dir (Gemini 3 pattern)
        if util.analysis_dir:
            filename = os.path.join(
                util.analysis_dir, 
                f"dnshealth_{exit_desc.fingerprint}.json"
            )
            try:
                with open(filename, 'w') as f:
                    json.dump(result, f, indent=2)
            except Exception as e:
                log.error(f"Failed to write {filename}: {e}")
    
    run_python_over_tor(do_validation, exit_desc, query_domain)


def teardown():
    """
    Called after all probes complete.
    Individual results are in analysis_dir; aggregation done by batch script.
    """
    log.info(f"DNS Health scan complete. Run ID: {_run_id}")
    log.info(f"Results written to: {util.analysis_dir}")


if __name__ == "__main__":
    log.critical("Module can only be run via exitmap, not standalone.")
```

**Key improvements from alternative approaches:**

| Feature | Source | Implementation |
|---------|--------|----------------|
| NXDOMAIN = Success | Gemini 3 | SOCKS error 4 interpreted as working DNS |
| UUID uniqueness | Gemini 3 | `uuid.uuid4()` for guaranteed uniqueness |
| Per-relay JSON | Gemini 3 | Individual files to `analysis_dir` |
| Retry logic | GPT5.2 | `MAX_RETRIES = 1` for transient failures |
| Status taxonomy | GPT5.2 | `success`, `dns_fail`, `timeout` categories |
| Run ID tracking | GPT5.2 | Track which run each result belongs to |

### Phase 2: DNS Infrastructure Setup (Week 2-3)

**Required DNS Setup:**

You need a domain with a wildcard DNS record that resolves all subdomains. Two options:

**Option A: Authoritative DNS Server (Recommended for accuracy)**
```
; Zone file for dns-check.torrelayvalidator.net
$TTL 60
@       IN  SOA   ns1.torrelayvalidator.net. admin.torrelayvalidator.net. (
                  2024010901  ; Serial
                  3600        ; Refresh
                  600         ; Retry  
                  604800      ; Expire
                  60 )        ; Minimum TTL (1 minute)
        IN  NS    ns1.torrelayvalidator.net.
        IN  NS    ns2.torrelayvalidator.net.
        IN  A     YOUR_SERVER_IP

; Wildcard - all subdomains resolve to same IP
*       IN  A     YOUR_SERVER_IP
```

**Option B: Use External Service**
- Cloudflare, Route53, or similar with wildcard DNS
- Less control over TTLs but simpler setup

### Phase 3: Batch Runner & Scheduler (Week 3-4)

**`scripts/run_dns_validation.sh`:** (Consolidated from Gemini 3 + aroivalidator patterns)

```bash
#!/bin/bash
# Tor Exit Relay DNS Health Validation - Batch Runner
# Combines patterns from Gemini 3 implementation and aroivalidator-deploy
set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
ANALYSIS_DIR="${REPO_ROOT}/analysis_results/$(date +%Y-%m-%d_%H-%M-%S)"
OUTPUT_DIR="${REPO_ROOT}/public"
LOG_DIR="${REPO_ROOT}/logs"
LOCK_FILE="/tmp/exitmap_dns_health.lock"
LATEST_REPORT="${OUTPUT_DIR}/latest.json"

# Scan parameters (override via environment)
: "${BUILD_DELAY:=2}"           # Seconds between circuit builds
: "${DELAY_NOISE:=1}"           # Random delay variance
: "${VERBOSITY:=info}"          # Log level
: "${FIRST_HOP:=}"              # Optional: your controlled relay
: "${SHARD:=}"                  # Optional: "N/M" for distributed scanning (GPT5.2)
: "${ALL_EXITS:=true}"          # Test all exits including BadExit

# Logging helper
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Atomic lock to prevent concurrent runs (all approaches agree)
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    log "Another instance is running. Exiting."
    exit 0
fi
echo $$ >&9
trap 'rm -f "$LOCK_FILE"' EXIT

log "=== DNS Health Validation Starting ==="

# Setup directories
mkdir -p "$ANALYSIS_DIR" "$OUTPUT_DIR" "$LOG_DIR"

# Setup environment (Gemini 3 pattern)
cd "$REPO_ROOT"
if [[ -d "venv" ]]; then
    source venv/bin/activate
elif [[ -d ".venv" ]]; then
    source .venv/bin/activate
else
    log "Creating virtualenv..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -e .
fi

# Build exitmap command
EXITMAP_CMD="python3 -m exitmap"
EXITMAP_CMD="$EXITMAP_CMD --build-delay $BUILD_DELAY"
EXITMAP_CMD="$EXITMAP_CMD --delay-noise $DELAY_NOISE"
EXITMAP_CMD="$EXITMAP_CMD --verbosity $VERBOSITY"
EXITMAP_CMD="$EXITMAP_CMD --analysis-dir $ANALYSIS_DIR"

[[ -n "$FIRST_HOP" ]] && EXITMAP_CMD="$EXITMAP_CMD --first-hop $FIRST_HOP"
[[ "$ALL_EXITS" == "true" ]] && EXITMAP_CMD="$EXITMAP_CMD --all-exits"

# Sharding support (GPT5.2 idea) - would need exitmap modification
# [[ -n "$SHARD" ]] && EXITMAP_CMD="$EXITMAP_CMD --shard $SHARD"

EXITMAP_CMD="$EXITMAP_CMD dnshealth"

# Run the scan
log "Running: $EXITMAP_CMD"
if ! $EXITMAP_CMD > "$LOG_DIR/exitmap_$(date +%Y%m%d_%H%M%S).log" 2>&1; then
    log "Exitmap execution had errors. Check logs for details."
    # Continue - partial results may exist
fi

# Aggregate Results (Gemini 3 embedded Python pattern)
log "Aggregating results..."
REPORT_FILE="${OUTPUT_DIR}/dns_health_$(date +%Y%m%d_%H%M%S).json"

python3 << AGGREGATE
import json
import glob
import os
from datetime import datetime

analysis_dir = "$ANALYSIS_DIR"
report_file = "$REPORT_FILE"

# Find all per-relay result files
files = glob.glob(os.path.join(analysis_dir, '**', 'dnshealth_*.json'), recursive=True)

results = []
stats = {"success": 0, "dns_fail": 0, "timeout": 0, "circuit_fail": 0, "unknown": 0}

for f in files:
    try:
        with open(f, 'r') as fd:
            data = json.load(fd)
            results.append(data)
            status = data.get('status', 'unknown')
            stats[status] = stats.get(status, 0) + 1
    except Exception as e:
        print(f"Error reading {f}: {e}")

total = len(results)
success_rate = (stats["success"] / total * 100) if total > 0 else 0

report = {
    "metadata": {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "analysis_dir": analysis_dir,
        "total_relays": total,
        "success": stats["success"],
        "dns_fail": stats["dns_fail"],
        "timeout": stats["timeout"],
        "circuit_fail": stats["circuit_fail"],
        "success_rate_percent": round(success_rate, 2),
    },
    "results": results,
    "failures": [r for r in results if r.get("status") != "success"],
    "failures_by_ip": {},  # Group by exit IP for operator diagnosis
}

# Group failures by IP (helps identify common DNS server issues)
for r in report["failures"]:
    ip = r.get("exit_address", "unknown")
    if ip not in report["failures_by_ip"]:
        report["failures_by_ip"][ip] = []
    report["failures_by_ip"][ip].append(r["exit_fingerprint"])

with open(report_file, 'w') as f:
    json.dump(report, f, indent=2)

print(f"Aggregated {total} results: {stats['success']} success, {stats['dns_fail']} dns_fail, {stats['timeout']} timeout")
AGGREGATE

# Update latest.json and manifest
if [[ -f "$REPORT_FILE" ]]; then
    cp "$REPORT_FILE" "$LATEST_REPORT"
    log "Report: $REPORT_FILE"
    
    # Update files.json manifest
    find "$OUTPUT_DIR" -maxdepth 1 -name "dns_health_*.json" -printf '%f\n' \
        | sort -r | jq -Rs 'split("\n") | map(select(length > 0))' \
        > "$OUTPUT_DIR/files.json.tmp" \
        && mv "$OUTPUT_DIR/files.json.tmp" "$OUTPUT_DIR/files.json"
fi

log "=== DNS Health Validation Complete ==="

# Optional: Trigger publish script
# [[ -x "$SCRIPT_DIR/publish-results.sh" ]] && "$SCRIPT_DIR/publish-results.sh"
```

**Sharding Support (GPT5.2 idea - future enhancement):**

To add `--shard N/M` support, modify `relayselector.py`:

```python
def get_exits(..., shard=None):
    """
    shard: "N/M" string where N is this shard (0-indexed), M is total shards
    """
    # ... existing code ...
    
    if shard:
        n, m = map(int, shard.split('/'))
        exit_destinations = {
            fp: dests for i, (fp, dests) in enumerate(exit_destinations.items())
            if i % m == n
        }
    
    return exit_destinations
```

**Cron Setup (`/etc/cron.d/tor-dns-health`):**

```cron
# Run DNS health validation every 6 hours
# Offset by 15 minutes to spread load on Tor network
15 */6 * * * torvalidator /home/torvalidator/exitmap/scripts/run_dns_validation.sh >> /home/torvalidator/exitmap/logs/cron.log 2>&1

# Monthly: compress old data (aroivalidator pattern)
0 3 1 * * torvalidator /home/torvalidator/exitmap/scripts/compress-old-data.sh >> /home/torvalidator/exitmap/logs/cron.log 2>&1
```

### Phase 4: Result Aggregation & Reporting (Week 4-5)

**`src/dnsvalidator/aggregator.py`:** (Enhanced with GPT5.2 consecutive failure tracking)

```python
#!/usr/bin/env python3
"""
Aggregate DNS validation results into operator-level reports.

Includes consecutive failure tracking for alerting (GPT5.2 suggestion):
- Track failures across runs
- Only alert after 2+ consecutive failures to avoid noise
"""
import json
import logging
from collections import defaultdict
from typing import Dict, List, Any, Set
from pathlib import Path
from datetime import datetime

log = logging.getLogger(__name__)

# State file for tracking consecutive failures (GPT5.2 idea)
FAILURE_STATE_FILE = "failure_state.json"


def load_failure_state(state_dir: Path) -> Dict[str, int]:
    """Load consecutive failure counts per relay."""
    state_file = state_dir / FAILURE_STATE_FILE
    if state_file.exists():
        try:
            with open(state_file) as f:
                return json.load(f)
        except Exception as e:
            log.warning(f"Failed to load failure state: {e}")
    return {}


def save_failure_state(state_dir: Path, state: Dict[str, int]):
    """Save updated failure state."""
    state_file = state_dir / FAILURE_STATE_FILE
    try:
        with open(state_file, 'w') as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        log.error(f"Failed to save failure state: {e}")


def update_failure_tracking(
    results: List[Dict], 
    state_dir: Path,
    alert_threshold: int = 2
) -> Dict[str, Any]:
    """
    Update consecutive failure tracking and identify relays to alert on.
    
    GPT5.2 insight: Only alert after 2+ consecutive failures to reduce noise.
    
    Returns:
        {
            "new_alerts": [fingerprints that crossed threshold this run],
            "ongoing_failures": [fingerprints with consecutive failures],
            "recovered": [fingerprints that were failing but now passed],
        }
    """
    # Load previous state
    failure_counts = load_failure_state(state_dir)
    
    # Process current results
    current_failures: Set[str] = set()
    current_successes: Set[str] = set()
    
    for relay in results:
        fp = relay.get("exit_fingerprint") or relay.get("fingerprint")
        status = relay.get("status")
        
        if status == "success":
            current_successes.add(fp)
        else:
            current_failures.add(fp)
    
    # Update counts and identify alerts
    new_alerts = []
    ongoing_failures = []
    recovered = []
    
    # Handle failures
    for fp in current_failures:
        old_count = failure_counts.get(fp, 0)
        new_count = old_count + 1
        failure_counts[fp] = new_count
        
        if new_count >= alert_threshold:
            if old_count < alert_threshold:
                new_alerts.append(fp)  # Just crossed threshold
            else:
                ongoing_failures.append(fp)  # Already alerting
    
    # Handle recoveries
    for fp in current_successes:
        if fp in failure_counts:
            if failure_counts[fp] >= alert_threshold:
                recovered.append(fp)
            del failure_counts[fp]
    
    # Save updated state
    save_failure_state(state_dir, failure_counts)
    
    return {
        "new_alerts": new_alerts,
        "ongoing_failures": ongoing_failures,
        "recovered": recovered,
        "threshold": alert_threshold,
    }


def load_results(results_dir: Path, limit: int = 10) -> List[Dict]:
    """Load recent validation result files."""
    results = []
    files = sorted(results_dir.glob("dns_health_*.json"), reverse=True)[:limit]
    for f in files:
        try:
            with open(f) as fp:
                results.append(json.load(fp))
        except Exception as e:
            log.warning(f"Failed to load {f}: {e}")
    return results


def extract_operator(contact: str) -> str:
    """
    Extract operator identifier from relay contact info.
    
    Looks for patterns like:
    - email:admin@example.com
    - url:https://example.com
    """
    if not contact:
        return "unknown"
    
    import re
    contact_lower = contact.lower()
    
    # Try to extract domain from email
    if "@" in contact:
        match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', contact)
        if match:
            return match.group(1)
    
    # Try to extract domain from URL
    if "url:" in contact_lower:
        match = re.search(r'url:https?://([a-zA-Z0-9.-]+)', contact_lower)
        if match:
            return match.group(1)
    
    return contact[:50] if len(contact) > 50 else contact


def aggregate_by_ip(results: List[Dict]) -> Dict[str, Dict]:
    """
    Group failures by exit IP address.
    
    This helps identify:
    - Multiple relays on same server with broken DNS
    - Common DNS server issues
    """
    by_ip = defaultdict(lambda: {
        "total_relays": 0,
        "failed_relays": 0,
        "fingerprints": [],
        "failed_fingerprints": [],
        "failure_types": defaultdict(int),
    })
    
    for relay in results:
        ip = relay.get("exit_address", "unknown")
        status = relay.get("status", "unknown")
        fp = relay.get("exit_fingerprint") or relay.get("fingerprint")
        
        by_ip[ip]["total_relays"] += 1
        by_ip[ip]["fingerprints"].append(fp)
        
        if status != "success":
            by_ip[ip]["failed_relays"] += 1
            by_ip[ip]["failed_fingerprints"].append(fp)
            by_ip[ip]["failure_types"][status] += 1
    
    # Calculate rates and convert for JSON
    for ip_data in by_ip.values():
        ip_data["failure_rate"] = (
            ip_data["failed_relays"] / ip_data["total_relays"] * 100
            if ip_data["total_relays"] > 0 else 0
        )
        ip_data["failure_types"] = dict(ip_data["failure_types"])
    
    return dict(by_ip)


def generate_operator_report(
    latest_results: Dict,
    alert_info: Dict[str, Any],
    by_ip: Dict[str, Dict]
) -> str:
    """
    Generate markdown report for operators.
    """
    meta = latest_results.get("metadata", {})
    
    lines = [
        "# Tor Exit Relay DNS Health Report",
        "",
        f"**Generated:** {datetime.now().isoformat()}",
        "",
        "## Summary",
        "",
        f"- **Total Relays Tested:** {meta.get('total_relays', 'N/A')}",
        f"- **Success:** {meta.get('success', 'N/A')}",
        f"- **DNS Failures:** {meta.get('dns_fail', 'N/A')}",
        f"- **Timeouts:** {meta.get('timeout', 'N/A')}",
        f"- **Success Rate:** {meta.get('success_rate_percent', 'N/A')}%",
        "",
    ]
    
    # Alert section (GPT5.2 consecutive failure tracking)
    if alert_info.get("new_alerts"):
        lines.extend([
            "## 🚨 New Alerts (2+ consecutive failures)",
            "",
            "The following relays have failed DNS resolution in 2+ consecutive scans:",
            "",
        ])
        for fp in alert_info["new_alerts"][:20]:
            lines.append(f"- [{fp[:16]}...](https://metrics.torproject.org/rs.html#details/{fp})")
        lines.append("")
    
    if alert_info.get("recovered"):
        lines.extend([
            "## ✅ Recovered",
            "",
            "The following relays have recovered from previous failures:",
            "",
        ])
        for fp in alert_info["recovered"][:20]:
            lines.append(f"- [{fp[:16]}...](https://metrics.torproject.org/rs.html#details/{fp})")
        lines.append("")
    
    # Failures by IP
    lines.extend([
        "## Failures by IP Address",
        "",
        "| IP Address | Total | Failed | Rate | Failure Types |",
        "|------------|-------|--------|------|---------------|",
    ])
    
    sorted_ips = sorted(
        by_ip.items(),
        key=lambda x: x[1]["failed_relays"],
        reverse=True
    )
    
    for ip, data in sorted_ips:
        if data["failed_relays"] > 0:
            types = ", ".join(f"{k}:{v}" for k, v in data["failure_types"].items())
            lines.append(
                f"| {ip} | {data['total_relays']} | "
                f"{data['failed_relays']} | {data['failure_rate']:.1f}% | {types} |"
            )
    
    lines.extend([
        "",
        "---",
        "",
        "*Report generated by Tor Exit DNS Health Validator*",
    ])
    
    return "\n".join(lines)
```

### Phase 5: Cloud Publishing (Week 5-6)

**`scripts/publish-results.sh`:**

```bash
#!/bin/bash
# Publish DNS validation results to cloud storage
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.env" 2>/dev/null || true

OUTPUT_DIR="${OUTPUT_DIR:-$HOME/exitmap/results}"

: "${DO_ENABLED:=false}"
: "${R2_ENABLED:=false}"
: "${RCLONE_PATH:=$(command -v rclone 2>/dev/null || echo "")}"

if [[ -z "$RCLONE_PATH" ]] || [[ ! -x "$RCLONE_PATH" ]]; then
    echo "rclone not found - skipping cloud upload"
    exit 0
fi

echo "Publishing results from $OUTPUT_DIR"

PIDS=()

# DigitalOcean Spaces
if [[ "$DO_ENABLED" == "true" ]]; then
    (
        echo "Uploading to DO Spaces..."
        $RCLONE_PATH sync "$OUTPUT_DIR" "do:${DO_BUCKET}/dns-validation" \
            --transfers 32 \
            --checkers 64 \
            --include "*.json" \
            --s3-acl public-read
        echo "✓ DO Spaces upload complete"
    ) &
    PIDS+=($!)
fi

# Cloudflare R2
if [[ "$R2_ENABLED" == "true" ]]; then
    (
        echo "Uploading to R2..."
        $RCLONE_PATH sync "$OUTPUT_DIR" "r2:${R2_BUCKET}/dns-validation" \
            --transfers 64 \
            --checkers 128 \
            --include "*.json"
        echo "✓ R2 upload complete"
    ) &
    PIDS+=($!)
fi

# Wait for all uploads
FAILED=0
for pid in "${PIDS[@]:-}"; do
    wait "$pid" || ((FAILED++))
done

if [[ $FAILED -gt 0 ]]; then
    echo "⚠ $FAILED upload(s) failed"
    exit 1
fi

echo "✓ All uploads complete"
```

---

## 4. Configuration

**`config.env.example`:**

```bash
# Tor Exit Relay DNS Validator Configuration

# === Scan Settings ===
BUILD_DELAY=2                    # Seconds between circuit builds
DELAY_NOISE=1                    # Random variance added to delay
FIRST_HOP=                       # Your controlled relay (recommended)
VERBOSITY=info                   # debug, info, warning, error

# === DNS Infrastructure ===
DNS_CHECK_DOMAIN=dns-check.yourdomain.com

# === Output ===
OUTPUT_DIR=$HOME/exitmap/results
LOG_DIR=$HOME/exitmap/logs

# === Cloud Storage (Optional) ===
DO_ENABLED=false
DO_BUCKET=your-bucket
DO_SPACES_KEY=
DO_SPACES_SECRET=
DO_SPACES_REGION=nyc3

R2_ENABLED=false
R2_BUCKET=your-bucket
R2_ACCESS_KEY_ID=
R2_SECRET_ACCESS_KEY=

# === Scheduling ===
SCAN_INTERVAL_HOURS=6            # How often to run full scan
```

---

## 5. Deployment Steps

### 5.1 Initial Setup

```bash
# 1. Clone/update repository
cd ~/exitmap

# 2. Create Python environment
python3 -m venv venv
source venv/bin/activate
pip install -e .[dev]

# 3. Configure
cp config.env.example config.env
nano config.env  # Edit settings

# 4. Set up DNS infrastructure (see Phase 2)
# Create wildcard DNS record for your domain

# 5. Test the module
python -m exitmap --exit YOUR_TEST_RELAY dnsvalidator

# 6. Install cron job
sudo cp etc/cron.d/tor-dns-validator /etc/cron.d/
```

### 5.2 Operational Commands

```bash
# Manual scan
./bin/run-dns-validation.sh

# View latest results
cat results/latest.json | jq '.metadata'

# Generate operator report
python -m dnsvalidator.aggregator results/ > report.md

# Publish to cloud
./scripts/publish-results.sh

# View logs
tail -f logs/dns-validation.log
```

---

## 6. Success Metrics

1. **Coverage**: Scan all ~1,500+ exit relays within scan window
2. **Accuracy**: < 1% false positives (verified against control relays)
3. **Timeliness**: Results available within 2 hours of scan start
4. **Reliability**: 99% scan completion rate
5. **Actionability**: Reports clearly identify operators with issues

---

## 7. Future Enhancements

### 7.1 Immediate Follow-ups
- [ ] Integrate with Tor Metrics for relay contact info lookup
- [ ] Add email notifications for new failures
- [ ] Create operator-facing dashboard

### 7.2 Advanced Features
- [ ] DNS response time tracking (latency monitoring)
- [ ] DNSSEC validation status per relay
- [ ] Historical trend analysis
- [ ] Integration with Tor bad-relay reporting

### 7.3 Scale Considerations
- [ ] Distributed scanning (multiple vantage points)
- [ ] Incremental scanning (only re-test failures)
- [ ] Rate limiting per operator network

---

## 8. File Structure

After implementation, the repository will have:

```
exitmap/
├── bin/
│   └── exitmap                      # Existing entry point
├── src/
│   ├── modules/
│   │   ├── dnsresolution.py         # Existing (basic)
│   │   ├── dnspoison.py             # Existing
│   │   ├── dnssec.py                # Existing
│   │   └── dnshealth.py             # NEW: Main DNS health module
│   └── dnsvalidator/                # NEW: Support package
│       ├── __init__.py
│       └── aggregator.py            # Report generation + alerting
├── scripts/
│   ├── run_dns_validation.sh        # NEW: Batch runner
│   ├── publish-results.sh           # NEW: Cloud upload
│   ├── compress-old-data.sh         # NEW: Data retention
│   └── install.sh                   # NEW: Setup script
├── configs/
│   └── cron.d/
│       └── tor-dns-health           # NEW: Cron job template
├── config.env.example               # NEW: Configuration template
├── analysis_results/                # NEW: Per-run analysis (timestamped)
│   └── YYYY-MM-DD_HH-MM-SS/
│       └── dnshealth_*.json         # Per-relay results
├── public/                          # NEW: Published output
│   ├── dns_health_*.json            # Aggregated reports
│   ├── latest.json                  # Symlink to latest
│   ├── files.json                   # Manifest
│   └── failure_state.json           # Consecutive failure tracking
└── logs/                            # NEW: Log directory
    ├── exitmap_*.log                # Per-run logs
    └── cron.log                     # Cron output
```

---

## 9. Timeline Summary

| Week | Phase | Deliverables |
|------|-------|--------------|
| 1-2 | Core Module | `dnsvalidator.py`, basic scanning |
| 2-3 | DNS Setup | Wildcard DNS, query generation |
| 3-4 | Automation | Batch runner, cron scheduling |
| 4-5 | Reporting | Aggregation, operator reports |
| 5-6 | Publishing | Cloud upload, dashboard |

---

## 10. Consolidated Ideas from All Approaches

This plan incorporates the best ideas from three different approaches:

### Attribution Table

| Feature | Source | Why It's Good |
|---------|--------|---------------|
| **NXDOMAIN = Success** | Gemini 3 | Brilliant insight: SOCKS error 4 means DNS resolver correctly returned "no such domain" |
| **UUID uniqueness** | Gemini 3 | Simple, guaranteed unique, no timestamp collision issues |
| **Per-relay JSON files** | Gemini 3 | Works with exitmap's existing `analysis_dir`, easy to aggregate |
| **Embedded Python aggregation** | Gemini 3 | Avoids external dependencies, clean bash integration |
| **Error taxonomy** | GPT5.2 | `success`, `dns_fail`, `timeout`, `circuit_fail` - actionable categories |
| **Consecutive failure tracking** | GPT5.2 | Alert after 2+ failures to reduce noise, track recovery |
| **Sharding concept** | GPT5.2 | `--shard N/M` for distributed scanning across hosts |
| **Retry logic** | GPT5.2 | 1-2 retries for transient failures |
| **Pages Function proxy** | GPT5.2 | Dynamic cache headers for CDN (future enhancement) |
| **Atomic locking** | All + aroivalidator | `flock` prevents concurrent runs |
| **Cloud upload pattern** | aroivalidator-deploy | Parallel upload to DO Spaces + R2 |
| **Manifest files** | aroivalidator-deploy | `latest.json`, `files.json` for API |

### Branch References

```
# Alternative implementations reviewed:
origin/cursor/tor-exit-relay-dns-check-a8cc  # GPT5.2 - Strategic plan
origin/cursor/tor-exit-relay-dns-check-6548  # Gemini 3 - Working implementation
origin/cursor/exit-relay-dns-validation-0896 # Previous experiment
```

### Key Technical Decisions

1. **Why NXDOMAIN = Success?**
   - When we query `{uuid}.example.com`, we expect NXDOMAIN
   - SOCKS error 4 ("Host Unreachable") during DNS resolve = resolver responded correctly
   - If DNS was broken, we'd get timeout or different SOCKS error

2. **Why per-relay files instead of global results list?**
   - Exitmap runs modules in separate processes (multiprocessing)
   - Global state doesn't persist across processes
   - File-based output is process-safe and matches exitmap's design

3. **Why 2+ consecutive failures for alerts?**
   - Transient failures are common (network issues, Tor path problems)
   - Alerting on single failures creates noise
   - 2+ consecutive failures indicates persistent issue worth investigating

---

## 11. References

- [Exitmap Source](https://gitlab.torproject.org/tpo/network-health/exitmap)
- [AROI Validator](https://github.com/1aeo/aroivalidator)
- [AROI Validator Deploy](https://github.com/1aeo/aroivalidator-deploy)
- [Tor Onionoo API](https://metrics.torproject.org/onionoo.html)
- [GPT5.2 Plan Branch](https://github.com/1aeo/exitmap/tree/cursor/tor-exit-relay-dns-check-a8cc)
- [Gemini 3 Implementation Branch](https://github.com/1aeo/exitmap/tree/cursor/tor-exit-relay-dns-check-6548)
- [Previous DNS Validation Experiment](https://github.com/1aeo/exitmap/tree/cursor/exit-relay-dns-validation-0896)
