# Tor Exit Relay DNS Validation System - Implementation Plan

## Executive Summary

This plan outlines the architecture for a system that periodically connects to all Tor exit relays, runs unique DNS queries to confirm working DNS resolution, and reports broken DNS to operators. The system builds upon the existing `exitmap` framework and incorporates deployment patterns from the `aroivalidator-deploy` project.

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

### 1.2 AROIValidator Patterns (Reference)

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
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Breakdown

#### Component 1: Enhanced DNS Probe Module (`src/modules/dnsvalidator.py`)

**Purpose:** Generate unique DNS queries per exit relay to detect caching issues and confirm live DNS resolution.

**Key Features:**
- Unique subdomain per exit relay using fingerprint hash
- Query multiple DNS record types (A, AAAA, TXT)
- Configurable timeout and retry logic
- Structured result logging (JSON-friendly)

```python
# Unique query format:
# {relay_fingerprint_prefix}.{timestamp}.dns-check.your-domain.com
# Example: abc123def.1704825600.dns-check.torrelayvalidator.net
```

#### Component 2: Batch Runner (`bin/run-dns-validation.sh`)

**Purpose:** Orchestrate full network scan with proper locking and output handling.

**Features:**
- Atomic lock file (prevents concurrent runs)
- Configurable scan parameters (batch size, delay)
- Structured JSON output with metadata
- Error handling and logging

#### Component 3: Result Processor (`src/dnsvalidator/processor.py`)

**Purpose:** Aggregate scan results into operator-level reports.

**Features:**
- Group failures by operator (contact info / family)
- Group failures by IP address (common DNS server issues)
- Calculate per-operator failure rates
- Generate actionable reports for operators

#### Component 4: Publisher (`scripts/publish-results.sh`)

**Purpose:** Upload results to cloud storage and update manifest.

**Features:**
- Parallel upload to multiple destinations
- Atomic manifest updates
- CDN cache invalidation
- Historical data retention

---

## 3. Implementation Phases

### Phase 1: Core DNS Validation Module (Week 1-2)

**New Files:**
```
src/modules/dnsvalidator.py       # Main validation module
src/dnsvalidator/__init__.py      # Package init
src/dnsvalidator/query.py         # Unique DNS query generator
src/dnsvalidator/results.py       # Result data structures
```

**`src/modules/dnsvalidator.py` Design:**

```python
#!/usr/bin/env python3
"""
Module to detect broken DNS resolution on Tor exit relays.

Generates unique DNS queries per relay to avoid caching issues and
confirm live DNS resolution capability.
"""
import hashlib
import logging
import socket
import time
import json
from typing import Optional, Dict, Any

import torsocks
import error
from util import exiturl

log = logging.getLogger(__name__)

# Configure these for your DNS infrastructure
DNS_CHECK_DOMAIN = "dns-check.torrelayvalidator.net"
QUERY_TIMEOUT = 15  # seconds

destinations = None  # Module uses DNS resolution, not TCP connections

# Global result storage for this scan
_scan_results = []
_scan_start_time = None


def setup(consensus=None, **kwargs):
    """Initialize scan metadata."""
    global _scan_results, _scan_start_time
    _scan_results = []
    _scan_start_time = time.time()
    log.info(f"DNS Validator initialized. Domain: {DNS_CHECK_DOMAIN}")


def generate_unique_query(fingerprint: str) -> str:
    """
    Generate a unique DNS query for this relay.
    
    Format: {fp_prefix}.{timestamp}.{nonce}.{domain}
    This ensures:
    - Each relay gets a unique query (fp_prefix)
    - Each scan gets unique queries (timestamp)
    - Queries are short enough for DNS (< 253 chars total)
    """
    fp_prefix = fingerprint[:16].lower()
    timestamp = int(_scan_start_time)
    # Create a nonce from fingerprint + timestamp to add uniqueness
    nonce = hashlib.sha256(f"{fingerprint}{timestamp}".encode()).hexdigest()[:8]
    
    return f"{fp_prefix}.{timestamp}.{nonce}.{DNS_CHECK_DOMAIN}"


def validate_dns(exit_desc, query_domain: str) -> Dict[str, Any]:
    """
    Attempt to resolve the unique domain through this exit relay.
    
    Returns a result dict with status and timing information.
    """
    exit_url = exiturl(exit_desc.fingerprint)
    result = {
        "fingerprint": exit_desc.fingerprint,
        "nickname": exit_desc.nickname,
        "address": exit_desc.address,
        "query_domain": query_domain,
        "timestamp": time.time(),
        "success": False,
        "error": None,
        "resolved_ip": None,
        "latency_ms": None,
    }
    
    sock = torsocks.torsocket()
    sock.settimeout(QUERY_TIMEOUT)
    
    start_time = time.time()
    
    try:
        # Use Tor's SOCKS5 RESOLVE extension
        ip = sock.resolve(query_domain)
        result["success"] = True
        result["resolved_ip"] = ip
        result["latency_ms"] = int((time.time() - start_time) * 1000)
        log.debug(f"{exit_url} resolved {query_domain} to {ip} in {result['latency_ms']}ms")
        
    except error.SOCKSv5Error as err:
        result["error"] = f"SOCKS5 error: {err}"
        log.warning(f"{exit_url} DNS resolution failed: {err}")
        
    except socket.timeout:
        result["error"] = f"Timeout after {QUERY_TIMEOUT}s"
        log.warning(f"{exit_url} DNS resolution timed out")
        
    except EOFError as err:
        result["error"] = f"Connection closed: {err}"
        log.warning(f"{exit_url} connection error: {err}")
        
    except Exception as err:
        result["error"] = f"Unexpected error: {err}"
        log.error(f"{exit_url} unexpected error: {err}")
    
    return result


def probe(exit_desc, target_host, target_port, run_python_over_tor, 
          run_cmd_over_tor, **kwargs):
    """
    Probe the given exit relay's DNS resolution capability.
    """
    query_domain = generate_unique_query(exit_desc.fingerprint)
    
    def do_validation(exit_desc, query_domain):
        result = validate_dns(exit_desc, query_domain)
        _scan_results.append(result)
        
        if result["success"]:
            log.info(f"✓ {exit_desc.fingerprint[:8]} DNS OK ({result['latency_ms']}ms)")
        else:
            log.error(f"✗ {exit_desc.fingerprint[:8]} DNS FAILED: {result['error']}")
    
    run_python_over_tor(do_validation, exit_desc, query_domain)


def teardown():
    """
    Called after all probes complete. Save results to file.
    """
    global _scan_results
    
    if not _scan_results:
        log.warning("No results to save")
        return
    
    # Calculate summary statistics
    total = len(_scan_results)
    successful = sum(1 for r in _scan_results if r["success"])
    failed = total - successful
    failure_rate = (failed / total * 100) if total > 0 else 0
    
    # Build output structure
    output = {
        "metadata": {
            "scan_start": _scan_start_time,
            "scan_end": time.time(),
            "dns_check_domain": DNS_CHECK_DOMAIN,
            "total_relays": total,
            "successful": successful,
            "failed": failed,
            "failure_rate_percent": round(failure_rate, 2),
        },
        "results": _scan_results,
        "failures": [r for r in _scan_results if not r["success"]],
    }
    
    # Save to file
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"dns_validation_{timestamp}.json"
    
    try:
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        log.info(f"Results saved to {filename}")
        log.info(f"Summary: {successful}/{total} relays passed ({failure_rate:.1f}% failure rate)")
    except IOError as e:
        log.error(f"Failed to save results: {e}")


if __name__ == "__main__":
    log.critical("Module can only be run via exitmap, not standalone.")
```

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

**`bin/run-dns-validation.sh`:**

```bash
#!/bin/bash
# Tor Exit Relay DNS Validation - Scheduled Batch Runner
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_DIR="${PROJECT_DIR}/logs"
OUTPUT_DIR="${PROJECT_DIR}/results"
LOCK_FILE="${LOG_DIR}/dns-validation.lock"

# Configuration (override via environment)
: "${BUILD_DELAY:=2}"           # Seconds between circuit builds
: "${DELAY_NOISE:=1}"           # Random delay variance
: "${VERBOSITY:=info}"          # Log level
: "${FIRST_HOP:=}"              # Optional: your controlled relay

mkdir -p "$LOG_DIR" "$OUTPUT_DIR"

# Atomic lock to prevent concurrent runs
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "$(date): Another scan is already running" >> "$LOG_DIR/cron.log"
    exit 0
fi
echo $$ >&9
trap 'rm -f "$LOCK_FILE"' EXIT

echo "=== DNS Validation Scan $(date) ===" | tee -a "$LOG_DIR/cron.log"

cd "$PROJECT_DIR"

# Activate virtual environment if exists
[[ -d "venv" ]] && source venv/bin/activate
[[ -d ".venv" ]] && source .venv/bin/activate

# Build exitmap command
CMD="python -m exitmap"
CMD="$CMD --build-delay $BUILD_DELAY"
CMD="$CMD --delay-noise $DELAY_NOISE"
CMD="$CMD --verbosity $VERBOSITY"
CMD="$CMD --analysis-dir $OUTPUT_DIR"

[[ -n "$FIRST_HOP" ]] && CMD="$CMD --first-hop $FIRST_HOP"

CMD="$CMD dnsvalidator"

# Run the scan
echo "Running: $CMD" >> "$LOG_DIR/cron.log"
$CMD 2>&1 | tee -a "$LOG_DIR/dns-validation.log"

# Post-processing
echo "Scan completed at $(date)" >> "$LOG_DIR/cron.log"

# Generate latest.json symlink
LATEST=$(ls -t "$OUTPUT_DIR"/dns_validation_*.json 2>/dev/null | head -1)
if [[ -n "$LATEST" ]]; then
    ln -sf "$(basename "$LATEST")" "$OUTPUT_DIR/latest.json"
    echo "Latest results: $LATEST" >> "$LOG_DIR/cron.log"
fi

# Update manifest
find "$OUTPUT_DIR" -maxdepth 1 -name "dns_validation_*.json" -printf '%f\n' \
    | sort -r | jq -Rs 'split("\n") | map(select(length > 0))' \
    > "$OUTPUT_DIR/files.json.tmp" \
    && mv "$OUTPUT_DIR/files.json.tmp" "$OUTPUT_DIR/files.json"

echo "=== Scan Complete ===" | tee -a "$LOG_DIR/cron.log"
```

**Cron Setup (`/etc/cron.d/tor-dns-validator`):**

```cron
# Run DNS validation every 6 hours
# Offset from hour to spread load on Tor network
15 */6 * * * torvalidator /home/torvalidator/exitmap/bin/run-dns-validation.sh >> /home/torvalidator/exitmap/logs/cron.log 2>&1
```

### Phase 4: Result Aggregation & Reporting (Week 4-5)

**`src/dnsvalidator/aggregator.py`:**

```python
#!/usr/bin/env python3
"""
Aggregate DNS validation results into operator-level reports.
"""
import json
import logging
from collections import defaultdict
from typing import Dict, List, Any
from pathlib import Path

log = logging.getLogger(__name__)


def load_results(results_dir: Path) -> List[Dict]:
    """Load all validation result files."""
    results = []
    for f in sorted(results_dir.glob("dns_validation_*.json"), reverse=True):
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
    - ContactInfo field
    """
    if not contact:
        return "unknown"
    
    contact_lower = contact.lower()
    
    # Try to extract domain from email
    if "@" in contact:
        import re
        match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', contact)
        if match:
            return match.group(1)
    
    # Try to extract domain from URL
    if "url:" in contact_lower:
        import re
        match = re.search(r'url:https?://([a-zA-Z0-9.-]+)', contact_lower)
        if match:
            return match.group(1)
    
    # Fallback to truncated contact
    return contact[:50] if len(contact) > 50 else contact


def aggregate_by_operator(results: List[Dict]) -> Dict[str, Dict]:
    """
    Group failures by operator.
    """
    operators = defaultdict(lambda: {
        "total_relays": 0,
        "failed_relays": 0,
        "fingerprints": [],
        "failed_fingerprints": [],
        "ip_addresses": set(),
        "failed_ips": set(),
    })
    
    for scan in results:
        for relay in scan.get("results", []):
            # Note: We'd need to enhance the module to capture contact info
            # For now, group by IP address as proxy for operator
            ip = relay.get("address", "unknown")
            operator = ip  # Simplified - enhance later
            
            operators[operator]["total_relays"] += 1
            operators[operator]["fingerprints"].append(relay["fingerprint"])
            operators[operator]["ip_addresses"].add(ip)
            
            if not relay.get("success"):
                operators[operator]["failed_relays"] += 1
                operators[operator]["failed_fingerprints"].append(relay["fingerprint"])
                operators[operator]["failed_ips"].add(ip)
    
    # Convert sets to lists for JSON serialization
    for op in operators.values():
        op["ip_addresses"] = list(op["ip_addresses"])
        op["failed_ips"] = list(op["failed_ips"])
        op["failure_rate"] = (
            op["failed_relays"] / op["total_relays"] * 100
            if op["total_relays"] > 0 else 0
        )
    
    return dict(operators)


def generate_operator_report(operators: Dict[str, Dict]) -> str:
    """
    Generate markdown report for operators.
    """
    lines = [
        "# Tor Exit Relay DNS Resolution Report",
        "",
        f"Generated: {__import__('datetime').datetime.now().isoformat()}",
        "",
        "## Summary",
        "",
        "| Operator/IP | Total Relays | Failed | Failure Rate |",
        "|-------------|--------------|--------|--------------|",
    ]
    
    # Sort by failure count
    sorted_ops = sorted(
        operators.items(),
        key=lambda x: x[1]["failed_relays"],
        reverse=True
    )
    
    for op_id, data in sorted_ops:
        if data["failed_relays"] > 0:
            lines.append(
                f"| {op_id} | {data['total_relays']} | "
                f"{data['failed_relays']} | {data['failure_rate']:.1f}% |"
            )
    
    lines.extend([
        "",
        "## Failed Relays Detail",
        "",
    ])
    
    for op_id, data in sorted_ops:
        if data["failed_relays"] > 0:
            lines.extend([
                f"### {op_id}",
                "",
                "Failed fingerprints:",
                "",
            ])
            for fp in data["failed_fingerprints"][:20]:  # Limit for readability
                lines.append(
                    f"- [{fp[:16]}...](https://metrics.torproject.org/rs.html#details/{fp})"
                )
            if len(data["failed_fingerprints"]) > 20:
                lines.append(f"- ... and {len(data['failed_fingerprints']) - 20} more")
            lines.append("")
    
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
│   ├── exitmap                      # Existing
│   └── run-dns-validation.sh        # NEW: Batch runner
├── src/
│   ├── modules/
│   │   ├── dnsresolution.py         # Existing (basic)
│   │   ├── dnsvalidator.py          # NEW: Enhanced module
│   │   └── ...
│   └── dnsvalidator/                # NEW: Package
│       ├── __init__.py
│       ├── query.py                 # DNS query generation
│       ├── results.py               # Result structures
│       └── aggregator.py            # Report generation
├── scripts/
│   ├── publish-results.sh           # NEW: Cloud upload
│   └── install.sh                   # NEW: Setup script
├── etc/
│   └── cron.d/
│       └── tor-dns-validator        # NEW: Cron job
├── config.env.example               # NEW: Configuration
├── results/                         # NEW: Output directory
│   ├── dns_validation_*.json
│   ├── latest.json -> ...
│   └── files.json
└── logs/                            # NEW: Log directory
    ├── dns-validation.log
    └── cron.log
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

## 10. References

- [Exitmap Source](https://gitlab.torproject.org/tpo/network-health/exitmap)
- [AROI Validator](https://github.com/1aeo/aroivalidator)
- [AROI Validator Deploy](https://github.com/1aeo/aroivalidator-deploy)
- [Tor Onionoo API](https://metrics.torproject.org/onionoo.html)
- [DNS Validation Branch](cursor/exit-relay-dns-validation-0896)
