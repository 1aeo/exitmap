# Tor Exit Relay DNS Validation System - Implementation Plan

## Executive Summary

This plan outlines a system that periodically connects to all Tor exit relays, runs unique DNS queries to confirm working DNS resolution, and reports broken DNS to operators.

**Two Repositories:**
1. **exitmap** (this repo) - Core scanning module implementation
2. **exitmap-deploy** (new repo) - Deployment, scheduling, cloud publishing

**Wildcard Domain:** `*.tor.exit.validator.1aeo.com` → `64.65.4.1` ✓ Verified working

---

## DNS Test Modes: Wildcard vs NXDOMAIN

### Comparison

| Aspect | Wildcard Mode (Recommended) | NXDOMAIN Mode |
|--------|----------------------------|---------------|
| **Domain** | `*.tor.exit.validator.1aeo.com` | `*.example.com` |
| **Expected result** | Resolves to `64.65.4.1` | SOCKS error 4 (NXDOMAIN) |
| **Validates** | DNS works AND returns correct IP | DNS responds (any response) |
| **Infrastructure** | Requires your wildcard DNS | No setup needed |
| **False positives** | Low - verifies exact IP | Higher - any response = success |
| **Detects poisoning** | Yes - wrong IP detected | No - any IP accepted |
| **Detects broken resolvers** | Yes | Yes |
| **Complexity** | Slightly more code | Simpler |

### Why Wildcard Mode is Recommended

1. **Stronger validation**: Verifies the resolver returns the *correct* IP, not just *any* response
2. **Detects DNS poisoning**: If a relay's resolver returns wrong IP, we catch it
3. **You control it**: Your infrastructure, your rules, no dependency on `example.com`
4. **TTL control**: Can set low TTL (60s) to ensure fresh queries

### When NXDOMAIN Mode is Useful

1. **Quick testing**: No DNS setup required
2. **Fallback**: If wildcard domain is unreachable
3. **Simpler logic**: Any resolver response = working DNS

### Decision: **Wildcard Mode as Default**

Since `*.tor.exit.validator.1aeo.com` is working and resolves to `64.65.4.1`, use wildcard mode as default with NXDOMAIN as fallback.

---

## Unique Query Format (from GPT5.2)

### Why Uniqueness Matters

Each DNS query must be unique per relay per run to:
1. **Avoid cache artifacts**: Prevent resolver caching from masking failures
2. **Make failures unambiguous**: Know exactly which relay failed
3. **Enable log correlation**: Match authoritative DNS logs to specific tests

### Format Options

| Format | Example | Pros | Cons |
|--------|---------|------|------|
| **UUID + Fingerprint prefix** (recommended) | `a1b2c3d4-e5f6-7890-abcd-ef1234567890.abc12345.tor.exit.validator.1aeo.com` | Unique, traceable | Longer |
| **Hash-based** | `h7x9k2m4.dnscheck.example.com` | Shorter | Less traceable |
| **Timestamp + FP** | `20250114_143000.abc12345.dnscheck.example.com` | Time-traceable | Collision possible |

### Recommended Format

```
{uuid}.{fingerprint_prefix_8}.{base_domain}
```

Example: `f47ac10b-58cc-4372-a567-0e02b2c3d479.abc12345.tor.exit.validator.1aeo.com`

---

# Part 1: exitmap Repository (This Repo)

## Scope

Add a new module `dnshealth.py` to the existing exitmap codebase that:
- Generates unique DNS queries per relay
- Validates DNS resolution through Tor circuits
- Outputs structured JSON results
- Supports sharding for distributed scanning

## New Files

```
src/modules/dnshealth.py          # Main DNS health validation module
```

## Scaling & Performance Controls

### Sharding for Distributed Scanning

For large-scale scanning across multiple hosts, use deterministic sharding:

```bash
# Host 1: Scan first third of exits
exitmap dnshealth --shard 0/3 --analysis-dir ./results

# Host 2: Scan second third
exitmap dnshealth --shard 1/3 --analysis-dir ./results

# Host 3: Scan final third
exitmap dnshealth --shard 2/3 --analysis-dir ./results
```

**Implementation**: Hash fingerprint mod M, include only exits where `hash(fingerprint) % M == N`

### Rate Limiting Recommendations

| Setting | Default | Conservative | Aggressive |
|---------|---------|--------------|------------|
| `--build-delay` | 2s | 3s | 1s |
| `--delay-noise` | 1s | 2s | 0.5s |
| `QUERY_TIMEOUT` | 10s | 15s | 5s |
| `MAX_RETRIES` | 2 | 3 | 1 |

**Recommended for production**: Use conservative settings to avoid overloading the Tor network.

### Timeouts

- **Per-resolve timeout**: 10 seconds (configurable via `QUERY_TIMEOUT`)
- **Per-circuit module runtime**: Bounded by exitmap's circuit timeout
- **Full scan estimate**: ~2-4 hours for all exits with conservative delays

## Module Design: `src/modules/dnshealth.py`

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

Generates unique DNS queries per relay and validates resolution.

Modes:
- Wildcard (default): Query unique subdomain, verify expected IP returned
- NXDOMAIN (fallback): Query random UUID, treat NXDOMAIN as success

Usage:
    exitmap dnshealth                          # Wildcard mode (default)
    exitmap dnshealth -H example.com           # NXDOMAIN mode (fallback)
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

# Wildcard domain configuration
WILDCARD_DOMAIN = "tor.exit.validator.1aeo.com"
EXPECTED_IP = "64.65.4.1"

# Fallback for NXDOMAIN mode
NXDOMAIN_DOMAIN = "example.com"

# Scan settings
QUERY_TIMEOUT = 10  # seconds
MAX_RETRIES = 2     # Total attempts per relay

destinations = None  # Module uses DNS resolution, not TCP connections

# Run metadata
_run_id = None
_shard = "0/1"  # Default: no sharding
_first_hop = None  # Track first hop for debugging


def setup(consensus=None, target=None, **kwargs):
    """Initialize scan metadata."""
    global _run_id, _shard, _first_hop
    _run_id = time.strftime("%Y%m%d_%H%M%S")
    
    # Extract shard info if provided (future: from command line)
    _shard = kwargs.get('shard', '0/1')
    _first_hop = kwargs.get('first_hop', None)
    
    if target:
        log.info(f"DNS Health: NXDOMAIN mode (target={target})")
    else:
        log.info(f"DNS Health: Wildcard mode ({WILDCARD_DOMAIN} → {EXPECTED_IP})")
    
    log.info(f"Run ID: {_run_id}, Shard: {_shard}")


def generate_unique_query(fingerprint: str, base_domain: str) -> str:
    """
    Generate a unique DNS query for this relay.
    
    Format: {uuid}.{fingerprint_prefix}.{base_domain}
    """
    unique_id = str(uuid.uuid4())
    fp_prefix = fingerprint[:8].lower()
    return f"{unique_id}.{fp_prefix}.{base_domain}"


def resolve_with_retry(exit_desc, domain: str, expected_ip: str = None, 
                       retries: int = MAX_RETRIES) -> Dict[str, Any]:
    """
    Resolve domain through exit relay with retry logic.
    
    Modes:
    - If expected_ip is set: Wildcard mode, verify IP matches
    - If expected_ip is None: NXDOMAIN mode, SOCKS error 4 = success
    """
    exit_fp = exit_desc.fingerprint
    exit_url = exiturl(exit_fp)
    
    result = {
        "exit_fingerprint": exit_fp,
        "exit_nickname": getattr(exit_desc, 'nickname', 'unknown'),
        "exit_address": getattr(exit_desc, 'address', 'unknown'),
        "first_hop_fingerprint": _first_hop,  # Track entry guard for debugging
        "query_domain": domain,
        "expected_ip": expected_ip,
        "timestamp": time.time(),
        "run_id": _run_id,
        "shard": _shard,
        "mode": "wildcard" if expected_ip else "nxdomain",
        "status": "unknown",
        "resolved_ip": None,
        "latency_ms": None,
        "error": None,
        "error_code": None,  # Normalized error code for programmatic use
        "attempt": 0,
    }
    
    for attempt in range(1, retries + 1):
        result["attempt"] = attempt
        sock = torsocks.torsocket()
        sock.settimeout(QUERY_TIMEOUT)
        
        start_time = time.time()
        
        try:
            ip = sock.resolve(domain)
            result["resolved_ip"] = ip
            result["latency_ms"] = int((time.time() - start_time) * 1000)
            
            # Wildcard mode: verify IP matches expected
            if expected_ip:
                if ip == expected_ip:
                    result["status"] = "success"
                    log.info(f"✓ {exit_url} resolved to {ip} (correct)")
                else:
                    result["status"] = "wrong_ip"
                    result["error"] = f"Expected {expected_ip}, got {ip}"
                    log.warning(f"✗ {exit_url} returned wrong IP: {ip} != {expected_ip}")
            else:
                # NXDOMAIN mode: any resolution is success
                result["status"] = "success"
                log.info(f"✓ {exit_url} resolved to {ip}")
            
            return result
            
        except error.SOCKSv5Error as err:
            err_str = str(err)
            result["latency_ms"] = int((time.time() - start_time) * 1000)
            
            # SOCKS error 4 = Host Unreachable = NXDOMAIN
            if "error 4" in err_str:
                if expected_ip:
                    # Wildcard mode: NXDOMAIN is failure (should have resolved)
                    result["status"] = "dns_fail"
                    result["error"] = "NXDOMAIN (domain should resolve)"
                    result["error_code"] = "NXDOMAIN"
                    log.warning(f"✗ {exit_url} returned NXDOMAIN for wildcard domain")
                else:
                    # NXDOMAIN mode: NXDOMAIN is success (expected)
                    result["status"] = "success"
                    result["resolved_ip"] = "NXDOMAIN"
                    log.info(f"✓ {exit_url} returned NXDOMAIN (DNS working)")
                return result
            
            # Classify SOCKS errors (from GPT5.2 error taxonomy)
            if "error 1" in err_str:
                result["error_code"] = "SOCKS_GENERAL_FAILURE"
            elif "error 2" in err_str:
                result["error_code"] = "SOCKS_NOT_ALLOWED"
            elif "error 3" in err_str:
                result["error_code"] = "SOCKS_NETWORK_UNREACHABLE"
            elif "error 5" in err_str:
                result["error_code"] = "SOCKS_CONNECTION_REFUSED"
            elif "error 6" in err_str:
                result["error_code"] = "SOCKS_TTL_EXPIRED"
            elif "error 7" in err_str:
                result["error_code"] = "SOCKS_COMMAND_NOT_SUPPORTED"
            else:
                result["error_code"] = "SOCKS_UNKNOWN"
            
            # Other SOCKS errors
            result["status"] = "error"
            result["error"] = err_str
            log.warning(f"Attempt {attempt}/{retries}: {exit_url} SOCKS error: {err}")
            
        except socket.timeout:
            result["status"] = "timeout"
            result["error"] = f"Timeout after {QUERY_TIMEOUT}s"
            result["error_code"] = "TIMEOUT"
            log.warning(f"Attempt {attempt}/{retries}: {exit_url} timed out")
            
        except Exception as err:
            result["status"] = "exception"
            result["error"] = str(err)
            result["error_code"] = "EXCEPTION"
            log.error(f"Attempt {attempt}/{retries}: {exit_url} exception: {err}")
        
        # Wait before retry
        if attempt < retries:
            time.sleep(1)
    
    log.warning(f"✗ {exit_url} FAILED after {result['attempt']} attempts: {result['error']}")
    return result


def probe(exit_desc, target_host, target_port, run_python_over_tor, 
          run_cmd_over_tor, **kwargs):
    """
    Probe the given exit relay's DNS resolution capability.
    
    If target_host is provided (-H flag), use NXDOMAIN mode.
    Otherwise, use wildcard mode with WILDCARD_DOMAIN.
    """
    if target_host:
        # NXDOMAIN mode: user specified a domain
        base_domain = target_host
        expected_ip = None
    else:
        # Wildcard mode: use our controlled domain
        base_domain = WILDCARD_DOMAIN
        expected_ip = EXPECTED_IP
    
    query_domain = generate_unique_query(exit_desc.fingerprint, base_domain)
    
    def do_validation(exit_desc, query_domain, expected_ip):
        result = resolve_with_retry(exit_desc, query_domain, expected_ip)
        
        # Write individual result to analysis_dir
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
    
    run_python_over_tor(do_validation, exit_desc, query_domain, expected_ip)


def teardown():
    """Called after all probes complete."""
    log.info(f"DNS Health scan complete. Run ID: {_run_id}")
    if util.analysis_dir:
        log.info(f"Results written to: {util.analysis_dir}")


if __name__ == "__main__":
    log.critical("Module can only be run via exitmap, not standalone.")
```

## Usage Examples

```bash
# Wildcard mode (default) - recommended
exitmap dnshealth --analysis-dir ./results

# NXDOMAIN mode (fallback)
exitmap dnshealth -H example.com --analysis-dir ./results

# With first hop for faster scanning
exitmap dnshealth --first-hop YOUR_RELAY_FPR --analysis-dir ./results

# Scan specific exit
exitmap dnshealth -e EXIT_FINGERPRINT --analysis-dir ./results
```

## Output Format

Each relay produces a JSON file in `analysis_dir`:

```json
{
  "exit_fingerprint": "ABC123...",
  "exit_nickname": "MyRelay",
  "exit_address": "192.0.2.1",
  "first_hop_fingerprint": "DEF456...",
  "query_domain": "uuid.abc123.tor.exit.validator.1aeo.com",
  "expected_ip": "64.65.4.1",
  "timestamp": 1704825600.123,
  "run_id": "20250109_143000",
  "shard": "0/1",
  "mode": "wildcard",
  "status": "success",
  "resolved_ip": "64.65.4.1",
  "latency_ms": 1523,
  "error": null,
  "error_code": null,
  "attempt": 1
}
```

### Field Descriptions (from GPT5.2)

| Field | Description |
|-------|-------------|
| `exit_fingerprint` | 40-char hex fingerprint of exit relay |
| `exit_nickname` | Human-readable relay name |
| `exit_address` | IPv4/IPv6 address of exit |
| `first_hop_fingerprint` | Entry guard fingerprint (useful for debugging) |
| `query_domain` | Unique DNS name tested |
| `expected_ip` | Expected resolution (wildcard mode only) |
| `timestamp` | Unix timestamp of test |
| `run_id` | Batch identifier (YYYYMMDD_HHMMSS) |
| `shard` | Shard identifier (N/M format) |
| `mode` | `wildcard` or `nxdomain` |
| `status` | See Status Values table |
| `resolved_ip` | Actual IP returned (or "NXDOMAIN") |
| `latency_ms` | Resolution time in milliseconds |
| `error` | Human-readable error message |
| `error_code` | Normalized error code for programmatic use |
| `attempt` | Which retry attempt succeeded/failed |

## Status Values

| Status | Meaning | Actionable? | Category |
|--------|---------|-------------|----------|
| `success` | DNS working correctly | No | ✅ Pass |
| `wrong_ip` | Resolved to unexpected IP (possible poisoning) | Yes - investigate | ❌ DNS Issue |
| `dns_fail` | DNS resolution failed (NXDOMAIN for wildcard) | Yes - relay has broken DNS | ❌ DNS Issue |
| `timeout` | Resolution timed out | Maybe - could be transient | ⚠️ Transient |
| `circuit_fail` | Circuit build failed before DNS test | No - not a DNS issue | ⚠️ Network |
| `error` | SOCKS/connection error on built circuit | Maybe - could be circuit issue | ⚠️ Transient |
| `exception` | Unexpected error | Yes - investigate | ❌ Bug |

### Error Classification (from GPT5.2)

**Key insight**: Separate circuit build failures from DNS resolution failures.

- **Circuit failures** (path/network issues): Don't count against DNS health
- **DNS failures** (on a successfully built circuit): Count against relay's DNS

This prevents false positives where a relay has working DNS but circuit builds fail due to network conditions.

---

# Part 2: exitmap-deploy Repository (New Repo)

## Scope

Separate repository for deployment automation:
- Scheduled execution via cron
- Result aggregation
- Cloud storage uploads (DO Spaces, R2)
- Cloudflare Pages/Workers for web dashboard

## Repository Structure

```
exitmap-deploy/
├── README.md
├── config.env.example           # Configuration template
├── scripts/
│   ├── run_dns_validation.sh    # Main batch runner
│   ├── aggregate_results.py     # JSON aggregation
│   ├── upload_do.sh             # DigitalOcean Spaces upload
│   ├── upload_r2.sh             # Cloudflare R2 upload
│   └── install.sh               # Setup script
├── configs/
│   └── cron.d/
│       └── exitmap-dns          # Cron job template
├── functions/
│   └── [[path]].js              # Cloudflare Pages Function (proxy)
└── public/
    └── index.html               # Dashboard (optional)
```

## Configuration: `config.env.example`

```bash
# exitmap-deploy Configuration

# === Paths ===
EXITMAP_DIR=$HOME/exitmap
OUTPUT_DIR=$HOME/exitmap-deploy/public
LOG_DIR=$HOME/exitmap-deploy/logs

# === Scan Settings ===
BUILD_DELAY=2                    # Seconds between circuit builds
DELAY_NOISE=1                    # Random variance
FIRST_HOP=                       # Your controlled relay (recommended)
ALL_EXITS=true                   # Include BadExit relays

# === Cloud Storage ===
DO_ENABLED=false
DO_BUCKET=exitmap-dns-results
DO_SPACES_KEY=
DO_SPACES_SECRET=
DO_SPACES_REGION=nyc3

R2_ENABLED=false
R2_BUCKET=exitmap-dns-results
R2_ACCESS_KEY_ID=
R2_SECRET_ACCESS_KEY=

# === Cloudflare Pages ===
CF_ACCOUNT_ID=
CF_API_TOKEN=
PAGES_PROJECT=exitmap-dns
```

## Batch Runner: `scripts/run_dns_validation.sh`

```bash
#!/bin/bash
# exitmap-deploy: DNS Health Validation Batch Runner
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(dirname "$SCRIPT_DIR")"

# Load configuration
source "$DEPLOY_DIR/config.env" 2>/dev/null || {
    echo "Error: config.env not found. Copy config.env.example first."
    exit 1
}

TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
ANALYSIS_DIR="${OUTPUT_DIR}/analysis_${TIMESTAMP}"
REPORT_FILE="${OUTPUT_DIR}/dns_health_${TIMESTAMP}.json"
LATEST_REPORT="${OUTPUT_DIR}/latest.json"
LOCK_FILE="/tmp/exitmap_dns_health.lock"

# Logging helper
log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"; }

# Atomic lock
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    log "Another instance running. Exiting."
    exit 0
fi
echo $$ >&9
trap 'rm -f "$LOCK_FILE"' EXIT

log "=== DNS Health Validation Starting ==="

mkdir -p "$ANALYSIS_DIR" "$LOG_DIR"

# Setup exitmap environment
cd "$EXITMAP_DIR"
[[ -d "venv" ]] && source venv/bin/activate
[[ -d ".venv" ]] && source .venv/bin/activate

# Build command
CMD="python -m exitmap dnshealth"
CMD="$CMD --build-delay ${BUILD_DELAY:-2}"
CMD="$CMD --delay-noise ${DELAY_NOISE:-1}"
CMD="$CMD --analysis-dir $ANALYSIS_DIR"
[[ -n "${FIRST_HOP:-}" ]] && CMD="$CMD --first-hop $FIRST_HOP"
[[ "${ALL_EXITS:-true}" == "true" ]] && CMD="$CMD --all-exits"

# Run scan
log "Running: $CMD"
$CMD > "$LOG_DIR/exitmap_${TIMESTAMP}.log" 2>&1 || {
    log "Exitmap had errors - check logs"
}

# Aggregate results
log "Aggregating results..."
python3 "$SCRIPT_DIR/aggregate_results.py" \
    --input "$ANALYSIS_DIR" \
    --output "$REPORT_FILE" \
    --previous "$LATEST_REPORT"

# Update latest.json and manifest
if [[ -f "$REPORT_FILE" ]]; then
    cp "$REPORT_FILE" "$LATEST_REPORT"
    
    # Update files.json manifest
    find "$OUTPUT_DIR" -maxdepth 1 -name "dns_health_*.json" -printf '%f\n' \
        | sort -r | jq -Rs 'split("\n") | map(select(length > 0))' \
        > "$OUTPUT_DIR/files.json"
    
    log "Report: $REPORT_FILE"
fi

# Cloud uploads (parallel)
PIDS=()

if [[ "${DO_ENABLED:-false}" == "true" ]]; then
    log "Uploading to DO Spaces..."
    "$SCRIPT_DIR/upload_do.sh" "$REPORT_FILE" "$LATEST_REPORT" &
    PIDS+=($!)
fi

if [[ "${R2_ENABLED:-false}" == "true" ]]; then
    log "Uploading to R2..."
    "$SCRIPT_DIR/upload_r2.sh" "$REPORT_FILE" "$LATEST_REPORT" &
    PIDS+=($!)
fi

# Wait for uploads
for pid in "${PIDS[@]:-}"; do
    wait "$pid" || log "Upload failed (PID $pid)"
done

log "=== Complete ==="
```

## Result Aggregator: `scripts/aggregate_results.py`

```python
#!/usr/bin/env python3
"""Aggregate per-relay DNS health results into a single report."""
import argparse
import json
import glob
import os
from datetime import datetime
from collections import defaultdict

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True, help='Analysis directory')
    parser.add_argument('--output', required=True, help='Output report file')
    parser.add_argument('--previous', help='Previous report for tracking')
    args = parser.parse_args()
    
    # Load previous state for consecutive failure tracking
    previous_state = {}
    if args.previous and os.path.exists(args.previous):
        try:
            with open(args.previous) as f:
                prev_data = json.load(f)
                for res in prev_data.get('results', []):
                    fp = res.get('exit_fingerprint')
                    if fp:
                        previous_state[fp] = res
        except Exception as e:
            print(f"Warning: Could not load previous report: {e}")
    
    # Find all result files
    files = glob.glob(os.path.join(args.input, 'dnshealth_*.json'))
    
    results = []
    stats = defaultdict(int)
    
    for f in files:
        try:
            with open(f) as fd:
                data = json.load(fd)
                
                status = data.get('status', 'unknown')
                stats[status] += 1
                
                # Track consecutive failures
                fp = data.get('exit_fingerprint')
                if status == 'success':
                    data['consecutive_failures'] = 0
                else:
                    prev_failures = 0
                    if fp in previous_state:
                        prev = previous_state[fp]
                        if prev.get('status') != 'success':
                            prev_failures = prev.get('consecutive_failures', 0)
                    data['consecutive_failures'] = prev_failures + 1
                
                results.append(data)
        except Exception as e:
            print(f"Error reading {f}: {e}")
    
    total = len(results)
    success_rate = (stats['success'] / total * 100) if total > 0 else 0
    
    # Group failures by IP
    failures_by_ip = defaultdict(list)
    for r in results:
        if r.get('status') != 'success':
            ip = r.get('exit_address', 'unknown')
            failures_by_ip[ip].append(r['exit_fingerprint'])
    
    report = {
        'metadata': {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'total_relays': total,
            'success': stats['success'],
            'wrong_ip': stats['wrong_ip'],
            'dns_fail': stats['dns_fail'],
            'timeout': stats['timeout'],
            'error': stats['error'],
            'success_rate_percent': round(success_rate, 2),
        },
        'results': results,
        'failures': [r for r in results if r.get('status') != 'success'],
        'failures_by_ip': dict(failures_by_ip),
    }
    
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"Aggregated {total} results: {stats['success']} success, "
          f"{total - stats['success']} failures ({success_rate:.1f}% success rate)")

if __name__ == '__main__':
    main()
```

## Cron Schedule: `configs/cron.d/exitmap-dns`

```cron
# Run DNS health validation every 6 hours
15 */6 * * * exitmap /home/exitmap/exitmap-deploy/scripts/run_dns_validation.sh >> /home/exitmap/exitmap-deploy/logs/cron.log 2>&1
```

## Cloudflare Pages Function: `functions/[[path]].js`

```javascript
// Proxy JSON files from R2/DO Spaces with proper caching
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  
  // Determine cache TTL based on file type
  let cacheTTL;
  if (path === '/latest.json' || path === '/files.json') {
    cacheTTL = 60;  // 1 minute for frequently updated files
  } else if (path.match(/dns_health_.*\.json$/)) {
    cacheTTL = 31536000;  // 1 year for immutable historical files
  } else {
    return new Response('Not found', { status: 404 });
  }
  
  // Fetch from R2
  const object = await env.R2_BUCKET.get(path.slice(1));
  if (!object) {
    return new Response('Not found', { status: 404 });
  }
  
  return new Response(object.body, {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': `public, max-age=${cacheTTL}`,
      'Access-Control-Allow-Origin': '*',
    },
  });
}
```

---

## Network Sensitivity & Constraints (from GPT5.2)

### Important Considerations

1. **Tor Network Impact**: Scanning all exits is network-sensitive
   - Use conservative `--build-delay` values (2-3 seconds)
   - Consider sharding across multiple hosts for large scans
   - Avoid running during known high-traffic periods

2. **Controlled DNS Zone**: Prefer wildcard mode
   - Provides stronger validation (correct IP vs any response)
   - Enables log correlation on authoritative DNS
   - Full control over TTL and infrastructure

3. **Artifact Immutability**: Keep results cache-friendly
   - Timestamped files (e.g., `dns_health_20250114_143000.json`) are immutable
   - `latest.json` has short TTL (1 minute)
   - `files.json` manifest is short-lived

4. **Concurrency**: Prevent overlapping runs
   - Use `flock` lockfile pattern
   - Cron/systemd timer should respect lock

---

## Implementation Timeline

### Phase 0: Planning (Complete) ✅
- [x] Design DNS test modes
- [x] Define output format
- [x] Plan sharding strategy
- [x] Document error taxonomy

### Phase 1: exitmap Module (Week 1)
- [ ] Create `src/modules/dnshealth.py`
- [ ] Implement sharding support
- [ ] Test with single relay
- [ ] Test full scan
- [ ] Verify JSON output format

### Phase 2: exitmap-deploy Setup (Week 2)
- [ ] Create new repository
- [ ] Implement `run_dns_validation.sh`
- [ ] Implement `aggregate_results.py`
- [ ] Test local execution

### Phase 3: Cloud Integration (Week 3)
- [ ] Configure DO Spaces
- [ ] Configure R2
- [ ] Implement upload scripts
- [ ] Set up Cloudflare Pages

### Phase 4: Production (Week 4)
- [ ] Deploy to production server
- [ ] Configure cron
- [ ] Monitor first runs
- [ ] Verify data in cloud storage

### Phase 5: Scaling (Future)
- [ ] Multi-host sharded scanning
- [ ] Alerting system
- [ ] Dashboard with trends
- [ ] Operator notifications

---

## Quick Start

### exitmap (this repo)
```bash
# Install
pip install -e .

# Test the module with a single exit
exitmap dnshealth -e SOME_EXIT_FPR --analysis-dir ./test_results

# Full scan (single host)
exitmap dnshealth --analysis-dir ./results --build-delay 2

# Distributed scan across 3 hosts
# Host 1:
exitmap dnshealth --shard 0/3 --analysis-dir ./results --build-delay 2
# Host 2:
exitmap dnshealth --shard 1/3 --analysis-dir ./results --build-delay 2
# Host 3:
exitmap dnshealth --shard 2/3 --analysis-dir ./results --build-delay 2

# NXDOMAIN mode (fallback, no controlled domain needed)
exitmap dnshealth -H example.com --analysis-dir ./results
```

### exitmap-deploy (new repo)
```bash
# Clone and configure
git clone https://github.com/1aeo/exitmap-deploy
cd exitmap-deploy
cp config.env.example config.env
nano config.env

# Install dependencies
./scripts/install.sh

# Manual run
./scripts/run_dns_validation.sh

# View results
cat public/latest.json | jq '.metadata'
```

---

## Future Work: Alerting System

> **Note:** Alerting is planned for a future phase after the core system is stable.

### Planned Features

1. **Consecutive Failure Tracking**
   - Track failures across runs per relay
   - Alert threshold: 2+ consecutive failures
   - Track recoveries

2. **Alert Channels**
   - Email notifications
   - Webhook integration
   - Tor Metrics integration

3. **Operator Notifications**
   - Group failures by operator/contact info
   - Generate operator-specific reports
   - Opt-in notification system

### Implementation Sketch

```python
# Future: src/dnsvalidator/alerting.py

def check_alerts(current_results, previous_results, threshold=2):
    """
    Identify relays that need alerting.
    
    Returns:
        new_alerts: Relays that just crossed threshold
        ongoing: Relays with ongoing failures
        recovered: Relays that recovered
    """
    # ... implementation ...
    pass

def send_alerts(alerts, channel='email'):
    """Send alerts via configured channel."""
    pass
```

---

## References

- [Exitmap Source](https://gitlab.torproject.org/tpo/network-health/exitmap)
- [AROI Validator](https://github.com/1aeo/aroivalidator) - Reference for validation patterns
- [AROI Validator Deploy](https://github.com/1aeo/aroivalidator-deploy) - Reference for deployment patterns
- [GPT5.2 Plan](https://github.com/1aeo/exitmap/tree/cursor/tor-exit-relay-dns-check-a8cc)
- [Gemini 3 Implementation](https://github.com/1aeo/exitmap/tree/cursor/tor-exit-relay-dns-check-6548)

---

## Attribution

| Feature | Source |
|---------|--------|
| NXDOMAIN = Success insight | Gemini 3 |
| UUID uniqueness | Gemini 3 |
| Per-relay JSON files | Gemini 3 |
| Retry with delay | Gemini 3 |
| Consecutive failure tracking | Gemini 3 + GPT5.2 |
| Error taxonomy & error_code | GPT5.2 |
| Two DNS modes (wildcard/NXDOMAIN) | GPT5.2 |
| Sharding concept (`--shard N/M`) | GPT5.2 |
| First hop tracking | GPT5.2 |
| Rate limiting recommendations | GPT5.2 |
| Network sensitivity guidance | GPT5.2 |
| Circuit vs DNS failure separation | GPT5.2 |
| Unique query format options | GPT5.2 |
| Deployment patterns | aroivalidator-deploy |
