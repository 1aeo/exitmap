# Tor Exit Relay DNS Validation System - Implementation Plan

## Executive Summary

This plan outlines a system that periodically connects to all Tor exit relays, runs unique DNS queries to confirm working DNS resolution, and reports broken DNS to operators.

**Two Repositories:**
1. **exitmap** (this repo) - Core scanning module implementation
2. **exitmap-deploy** (new repo) - Deployment, scheduling, cloud publishing

**Wildcard Domain:** `*.tor.exit.validator.1aeo.com` → `64.65.4.1` ✓ Verified working

---

## Exitmap Architecture & Data Flow

### Current Codebase Structure

```
src/
├── exitmap.py          # Main entry point, bootstraps Tor, orchestrates scans
├── eventhandler.py     # Handles Tor circuit/stream events, spawns module processes
├── relayselector.py    # Selects exit relays from consensus
├── torsocks.py         # Routes Python network calls through Tor SOCKS
├── command.py          # Routes shell commands through Tor
├── util.py             # Utilities (analysis_dir, exiturl, etc.)
├── error.py            # Custom exceptions (SOCKSv5Error, etc.)
├── stats.py            # Scan statistics tracking
└── modules/            # Scanning modules (one per task)
    ├── dnsresolution.py    # Basic DNS resolution check
    ├── dnspoison.py        # DNS poisoning detection
    ├── dnssec.py           # DNSSEC validation
    └── ...                 # Other modules
```

### Data Flow: How a Scan Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. STARTUP                                                                  │
│    exitmap.py main()                                                        │
│    ├── Parse command line args                                              │
│    ├── Bootstrap Tor process (stem)                                         │
│    └── Connect to Tor controller                                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. MODULE LOADING                                                           │
│    run_module(module_name, ...)                                             │
│    ├── Import module from src/modules/{name}.py                             │
│    ├── Call module.setup(consensus=...) if exists                           │
│    └── Select exit relays via relayselector.get_exits()                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. CIRCUIT CREATION                                                         │
│    iter_exit_relays(exit_relays, ...)                                       │
│    ├── For each exit relay:                                                 │
│    │   ├── Pick first hop (--first-hop or random)                           │
│    │   ├── controller.new_circuit([first_hop, exit_relay])                  │
│    │   └── Sleep (--build-delay + noise)                                    │
│    └── EventHandler listens for CIRC events                                 │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. MODULE EXECUTION (per circuit)                                           │
│    EventHandler.new_circuit() [when CircStatus.BUILT]                       │
│    ├── Get exit relay descriptor                                            │
│    ├── Spawn new process:                                                   │
│    │   └── module.probe(                                                    │
│    │         exit_desc,              # Relay info (fingerprint, address)    │
│    │         run_python_over_tor,    # Wrapper to route Python through Tor  │
│    │         run_cmd_over_tor,       # Wrapper to route commands through Tor│
│    │         target_host,            # From -H flag                         │
│    │         target_port             # From -p flag                         │
│    │       )                                                                │
│    └── Module does its work over the Tor circuit                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. CLEANUP                                                                  │
│    ├── Module signals completion via IPC queue                              │
│    ├── Circuit is closed                                                    │
│    ├── When all circuits done: module.teardown() if exists                  │
│    └── Exit                                                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Where Our New Module Fits

```
src/modules/
├── dnsresolution.py    # Existing: Basic "can resolve" check (no uniqueness)
├── dnspoison.py        # Existing: Compare to whitelist (static domains)
├── dnssec.py           # Existing: DNSSEC validation
└── dnshealth.py        # NEW: Unique queries + structured JSON output ◄────
```

**Why `dnshealth.py` is needed:**
- `dnsresolution.py`: No unique queries, no structured output, can't track failures over time
- `dnspoison.py`: Static domain list, focused on poisoning not broken DNS
- `dnshealth.py`: Unique query per relay, JSON output, consecutive failure tracking

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

### Fallback: Multiple Stable Domains

If you cannot operate any DNS zone, a less reliable but workable fallback:

- Resolve multiple stable domains (e.g., `google.com`, `cloudflare.com`, `amazon.com`)
- Classify "broken DNS" only if **multiple** domains fail
- Treat results as "suspected broken DNS" (higher uncertainty)

**Caveat**: Caching and upstream variance make this harder to interpret reliably.

### Decision: **Wildcard Mode as Default**

Since `*.tor.exit.validator.1aeo.com` is working and resolves to `64.65.4.1`, use wildcard mode as default with NXDOMAIN as fallback.

---

## Unique Query Format

### Why Uniqueness Matters

Each DNS query must be unique per relay per run to:
1. **Avoid cache artifacts**: Prevent resolver caching from masking failures
2. **Make failures unambiguous**: Know exactly which relay failed
3. **Enable log correlation**: Match authoritative DNS logs to specific tests

### Format Options

| Format | Example | Debuggability | Collision Risk |
|--------|---------|---------------|----------------|
| ~~UUID + FP prefix~~ | `f47ac10b-...uuid.abc12345.domain` | ❌ Poor - UUID is meaningless | None |
| **RunID + Timestamp_ms + Full FP** | `20250114143052.1.20250114143127789.ABC...40chars.domain` | ✅ Excellent | None |

### Recommended Format

```
{run_id}.{attempt}.{timestamp_ms}.{full_fingerprint}.{base_domain}
```

| Field | Purpose | Example |
|-------|---------|---------|
| `run_id` | Batch identifier - correlate all queries from same scan | `20250114143052` |
| `attempt` | Retry attempt (1 = first try, 2 = first retry) | `1` |
| `timestamp_ms` | Exact query moment - correlate with authoritative DNS logs | `20250114143127789` |
| `full_fingerprint` | 40-char relay fingerprint - unambiguous identification | `ABCD1234...7890` |
| `base_domain` | Your wildcard domain | `tor.exit.validator.1aeo.com` |

### Example

```
20250114143052.1.20250114143127789.ABCD1234EFGH5678IJKL9012MNOP3456QRST7890.tor.exit.validator.1aeo.com
│              │ │                 │                                        │
│              │ │                 └─ Full fingerprint (which relay)        └─ Base domain
│              │ └─ Query timestamp_ms (exact moment of this query)
│              └─ Attempt number (1=first, 2=retry)
└─ Run ID (which batch)
```

### Why This Format

1. **run_id + attempt are grouped** - Both are "run context"
2. **timestamp_ms is query-specific** - Exact moment this DNS query was made
3. **Full fingerprint** - No ambiguity, no collisions between relays
4. **No UUID** - Every field has debugging value
5. **Retry uniqueness** - Each retry has different attempt + timestamp_ms, ensuring fresh DNS lookup

### DNS Label Length Check

```
run_id:           14 chars  (20250114143052)
attempt:           1 char   (1)
timestamp_ms:     17 chars  (20250114143127789)
fingerprint:      40 chars  (full hex)
separators:        4 chars  (dots)
                  ─────────
Total:           ~76 chars + base_domain ✓ (well under 253 limit)
```

---

# Part 1: exitmap Repository (This Repo)

## Existing DNS Modules: Modify vs New?

### What Exists Today

| Module | Purpose | Domains | Output | Unique Queries? |
|--------|---------|---------|--------|-----------------|
| `dnsresolution.py` | "Can relay resolve DNS?" | Static: `example.com`, `torproject.org` | Log only | ❌ No |
| `dnspoison.py` | "Is relay returning correct IPs?" | Static list, compared to system DNS whitelist | Log only | ❌ No |

### Options Comparison

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| **A: New `dnshealth.py`** | Create new module from scratch | Clean design, no breakage, clear purpose | More code to maintain |
| **B: Modify `dnsresolution.py`** | Add features to existing module | Reuse existing code | Changes behavior, name misleading, heavy modification |
| **C: Modify `dnspoison.py`** | Repurpose for health checks | Has IP validation | Wrong purpose, relies on system DNS whitelist |
| **D: Shared utils + new module** | Extract DNS code to `dnsutils.py`, new `dnshealth.py` | DRY, clean | More refactoring, changes internal APIs |

### Detailed Analysis

**Option A: New `dnshealth.py`** ✅ Recommended

```
dnsresolution.py  →  "Can resolve static domains?" (unchanged)
dnspoison.py      →  "Is relay poisoning DNS?"     (unchanged)  
dnshealth.py      →  "Is relay DNS working?"       (NEW - unique queries, JSON output)
```

- **Different purpose**: Health monitoring ≠ poisoning detection ≠ basic resolution
- **No breakage**: Existing users of `dnsresolution`/`dnspoison` unaffected
- **Clean design**: Built for structured output, unique queries, failure tracking

**Option B: Modify `dnsresolution.py`** ⚠️ Not recommended

Would require adding:
- Unique query generation
- Structured JSON output with JSONL + locking
- Retry logic with attempt tracking
- NXDOMAIN = success interpretation
- Wildcard mode vs NXDOMAIN mode
- `setup()` and `teardown()` functions

Problems:
- Name `dnsresolution` doesn't reflect new capabilities
- Breaks scripts that expect current behavior (log-only)
- Module becomes complex multi-purpose tool

**Option C: Modify `dnspoison.py`** ❌ Not recommended

- Designed for different purpose (detecting malicious DNS changes)
- Relies on system DNS whitelist - we want controlled wildcard domain
- Would fundamentally change what the module does

**Option D: Shared utilities** 🤔 Future consideration

Could extract common DNS resolution code to `src/dnsutils.py`:
```python
# src/dnsutils.py
def resolve_with_timeout(domain, timeout=10):
    sock = torsocks.torsocket()
    sock.settimeout(timeout)
    return sock.resolve(domain)
```

But this is premature optimization - the DNS code is only ~10 lines. Consider if we add more DNS modules later.

### Decision: **Option A - New `dnshealth.py`**

Reasons:
1. **Clear separation**: Each module has one purpose
2. **No breakage**: Existing modules continue working
3. **Clean slate**: Design for structured output from the start
4. **Naming**: `dnshealth` clearly indicates "health check" purpose

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

## Results Storage: Per-Process Files + Merge (Recommended)

### The Lock Contention Problem

Exitmap uses **multiprocessing** - each relay is tested in a separate subprocess. 

**Why NOT JSONL with file locking?**

```
Subprocess 1 ─┐
Subprocess 2 ─┼─► LOCK_EX ─► write ─► UNLOCK ─► exit
Subprocess 3 ─┤     ↑
    ...       │     │ BLOCKED (waiting for lock)
Subprocess N ─┘     │
```

Risk: If many circuits complete simultaneously, processes queue up waiting for the lock. While lock duration is short (~1ms), 100 processes arriving at once = 100ms queue, and processes hold memory while waiting.

### Comparison

| Option | How it works | Lock contention? | Recommendation |
|--------|--------------|------------------|----------------|
| **aroivalidator style** | Collect in memory, write once | N/A | ❌ Won't work (multiprocess) |
| **JSONL with locking** | Each process locks, appends, unlocks | ⚠️ Yes - queue risk | ❌ Risky |
| **Per-process files + merge** | Each process writes own file, merge in teardown | ✅ None | ✅ Recommended |
| **Manager list** | `multiprocessing.Manager().list()` | ⚠️ IPC overhead | ⚠️ Complex |

### Recommended: Per-Process Files + Merge

```
During scan (parallel, no locking):
  Subprocess 1 ──► results/abc123...json
  Subprocess 2 ──► results/def456...json
  Subprocess N ──► results/xyz789...json

After scan (teardown, sequential):
  results/*.json ──► dnshealth_20250114143052.json (single merged file)
                 ──► delete individual files
```

**Benefits**:
- **No lock contention**: Each process writes to unique file
- **No blocking**: Processes never wait on each other
- **Simple**: No locking code needed
- **Atomic**: Each write is independent
- **Clean output**: Single JSON file after merge

**The "many small files" concern is minimal**:
- Files are tiny (~500 bytes each)
- They're temporary (deleted after merge)
- Modern filesystems handle 1000s of small files fine
- All created in a dedicated subdirectory

### Implementation

```python
def write_result(result: dict, fingerprint: str):
    """
    Write result to per-process file. No locking needed.
    """
    if not util.analysis_dir:
        return
    
    # Each process writes to unique file (fingerprint is unique)
    filepath = os.path.join(util.analysis_dir, f"result_{fingerprint}.json")
    with open(filepath, 'w') as f:
        json.dump(result, f)
```

### Merge in teardown()

```python
def teardown():
    """
    Merge per-relay result files into single JSON report.
    Called after ALL subprocesses complete (no concurrency issues).
    """
    if not util.analysis_dir:
        return
    
    import glob
    
    results = []
    stats = defaultdict(int)
    
    # Read all result files
    pattern = os.path.join(util.analysis_dir, "result_*.json")
    for filepath in glob.glob(pattern):
        with open(filepath, 'r') as f:
            result = json.load(f)
            results.append(result)
            stats[result.get('status', 'unknown')] += 1
        # Delete after reading
        os.remove(filepath)
    
    # Write merged report
    total = len(results)
    report = {
        'metadata': {
            'run_id': _run_id,
            'shard': _shard,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'total_relays': total,
            'success': stats['success'],
            'dns_fail': stats['dns_fail'],
            'wrong_ip': stats['wrong_ip'],
            'timeout': stats['timeout'],
            'error': stats['error'],
            'success_rate_percent': round(stats['success'] / total * 100, 2) if total else 0,
        },
        'results': results,
    }
    
    output_path = os.path.join(util.analysis_dir, f"dnshealth_{_run_id}.json")
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    log.info(f"Report: {output_path}")
    log.info(f"Results: {total} relays, {stats['success']} success")
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
import glob
from typing import Dict, Any
from collections import defaultdict
from datetime import datetime

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


def generate_unique_query(fingerprint: str, base_domain: str, attempt: int = 1) -> str:
    """
    Generate a unique DNS query for this relay.
    
    Format: {run_id}.{attempt}.{timestamp_ms}.{full_fingerprint}.{base_domain}
    
    Every field has debugging value:
    - run_id: Which batch (correlate queries from same scan)
    - attempt: Which try (1=first, 2+=retry)
    - timestamp_ms: Exact query moment (correlate with authoritative DNS logs)
    - full_fingerprint: Which relay (unambiguous)
    """
    timestamp_ms = time.strftime("%Y%m%d%H%M%S") + f"{int(time.time() * 1000) % 1000:03d}"
    return f"{_run_id}.{attempt}.{timestamp_ms}.{fingerprint}.{base_domain}"


def resolve_with_retry(exit_desc, base_domain: str, expected_ip: str = None, 
                       retries: int = MAX_RETRIES) -> Dict[str, Any]:
    """
    Resolve domain through exit relay with retry logic.
    
    Each attempt generates a fresh unique query to avoid DNS caching.
    
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
        "query_domain": None,  # Set per attempt
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
        # Generate fresh unique query for each attempt (avoids DNS caching)
        domain = generate_unique_query(exit_fp, base_domain, attempt)
        result["query_domain"] = domain
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
            
            # Classify SOCKS errors
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
    
    def do_validation(exit_desc, base_domain, expected_ip):
        # Query is generated inside resolve_with_retry for each attempt
        result = resolve_with_retry(exit_desc, base_domain, expected_ip)
        
        # Write result to per-process file (no locking needed - unique per fingerprint)
        if util.analysis_dir:
            filepath = os.path.join(
                util.analysis_dir, 
                f"result_{exit_desc.fingerprint}.json"
            )
            try:
                with open(filepath, 'w') as f:
                    json.dump(result, f)
            except Exception as e:
                log.error(f"Failed to write {filepath}: {e}")
    
    run_python_over_tor(do_validation, exit_desc, base_domain, expected_ip)


def teardown():
    """
    Called after all probes complete.
    Merges per-relay result files into single JSON report.
    No concurrency issues - all subprocesses have exited.
    """
    log.info(f"DNS Health scan complete. Run ID: {_run_id}")
    
    if not util.analysis_dir:
        return
    
    # Read all per-relay result files
    results = []
    stats = defaultdict(int)
    
    pattern = os.path.join(util.analysis_dir, "result_*.json")
    result_files = glob.glob(pattern)
    
    if not result_files:
        log.warning(f"No result files found matching: {pattern}")
        return
    
    for filepath in result_files:
        try:
            with open(filepath, 'r') as f:
                result = json.load(f)
                results.append(result)
                stats[result.get('status', 'unknown')] += 1
            # Delete individual file after reading
            os.remove(filepath)
        except Exception as e:
            log.error(f"Failed to read {filepath}: {e}")
    
    total = len(results)
    success_rate = round(stats['success'] / total * 100, 2) if total else 0
    
    report = {
        'metadata': {
            'run_id': _run_id,
            'shard': _shard,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'total_relays': total,
            'success': stats['success'],
            'dns_fail': stats['dns_fail'],
            'wrong_ip': stats['wrong_ip'],
            'timeout': stats['timeout'],
            'error': stats['error'],
            'success_rate_percent': success_rate,
        },
        'results': results,
    }
    
    json_path = os.path.join(util.analysis_dir, f"dnshealth_{_run_id}.json")
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    log.info(f"Report: {json_path}")
    log.info(f"Results: {total} relays, {stats['success']} success ({success_rate}%)")


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
  "exit_fingerprint": "ABCD1234EFGH5678IJKL9012MNOP3456QRST7890",
  "exit_nickname": "MyRelay",
  "exit_address": "192.0.2.1",
  "first_hop_fingerprint": "DEF456...",
  "query_domain": "20250114143052.1.20250114143127789.ABCD1234EFGH5678IJKL9012MNOP3456QRST7890.tor.exit.validator.1aeo.com",
  "expected_ip": "64.65.4.1",
  "timestamp": 1736865052.123,
  "run_id": "20250114143052",
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

### Field Descriptions

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

### Error Classification

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
│   ├── postprocess_results.py   # Add consecutive failure tracking
│   ├── generate_report.py       # Generate human-readable report.md
│   ├── retention.sh             # Monthly cleanup script
│   ├── upload_do.sh             # DigitalOcean Spaces upload
│   ├── upload_r2.sh             # Cloudflare R2 upload
│   └── install.sh               # Setup script
├── configs/
│   └── cron.d/
│       ├── exitmap-dns          # Cron job template (6-hourly)
│       └── exitmap-retention    # Monthly retention/cleanup
├── functions/
│   └── [[path]].js              # Cloudflare Pages Function (proxy)
└── public/
    └── index.html               # Dashboard (optional)
```

## Output Artifacts

Exitmap's `dnshealth` module produces a **single JSON file** directly (no aggregation needed):

| File | Description | Cache TTL |
|------|-------------|-----------|
| `dnshealth_YYYYMMDD_HHMMSS.json` | Full results with metadata (from exitmap) | 1 year |
| `latest.json` | Copy of latest JSON (from batch runner) | 1 minute |
| `files.json` | Manifest of all run files | 1 minute |
| `report_YYYYMMDD_HHMMSS.md` | Human-readable report (optional) | 1 year |

**Note**: The `dnshealth.py` module's `teardown()` function converts the working JSONL file to a single JSON with metadata. The batch runner just needs to copy it to `latest.json` and update the manifest.

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

# Setup exitmap environment (auto-create venv if needed)
cd "$EXITMAP_DIR"
if [[ -d "venv" ]]; then
    source venv/bin/activate
elif [[ -d ".venv" ]]; then
    source .venv/bin/activate
else
    log "Creating virtualenv..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
fi

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

# Find the output JSON (exitmap's teardown() creates it)
REPORT_FILE=$(find "$ANALYSIS_DIR" -name "dnshealth_*.json" -type f | head -1)

if [[ -f "$REPORT_FILE" ]]; then
    # Add consecutive failure tracking
    log "Post-processing results..."
    python3 "$SCRIPT_DIR/postprocess_results.py" \
        --input "$REPORT_FILE" \
        --previous "$LATEST_REPORT"
    
    # Copy to public directory with timestamp
    FINAL_REPORT="${OUTPUT_DIR}/dnshealth_${TIMESTAMP}.json"
    cp "$REPORT_FILE" "$FINAL_REPORT"
    cp "$FINAL_REPORT" "$LATEST_REPORT"
    
    # Update files.json manifest
    find "$OUTPUT_DIR" -maxdepth 1 -name "dnshealth_*.json" -printf '%f\n' \
        | sort -r | jq -Rs 'split("\n") | map(select(length > 0))' \
        > "$OUTPUT_DIR/files.json"
    
    log "Report: $FINAL_REPORT"
else
    log "No results file found in $ANALYSIS_DIR"
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

## Post-Processor: `scripts/postprocess_results.py`

Since `dnshealth.py` now produces a single JSON file directly, this script only needs to:
1. Add consecutive failure tracking (comparing to previous run)
2. Add failure groupings

```python
#!/usr/bin/env python3
"""Post-process DNS health results: add consecutive failure tracking."""
import argparse
import json
import os
from collections import defaultdict

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True, help='Current run JSON file')
    parser.add_argument('--previous', help='Previous run JSON for failure tracking')
    parser.add_argument('--output', help='Output file (default: overwrite input)')
    args = parser.parse_args()
    
    output_path = args.output or args.input
    
    # Load current results
    with open(args.input) as f:
        data = json.load(f)
    
    results = data.get('results', [])
    
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
    
    # Add consecutive failure tracking
    for result in results:
        fp = result.get('exit_fingerprint')
        status = result.get('status')
        
        if status == 'success':
            result['consecutive_failures'] = 0
        else:
            prev_failures = 0
            if fp in previous_state:
                prev = previous_state[fp]
                if prev.get('status') != 'success':
                    prev_failures = prev.get('consecutive_failures', 0)
            result['consecutive_failures'] = prev_failures + 1
    
    # Add failure groupings
    failures_by_ip = defaultdict(list)
    for r in results:
        if r.get('status') != 'success':
            ip = r.get('exit_address', 'unknown')
            failures_by_ip[ip].append(r['exit_fingerprint'])
    
    data['failures'] = [r for r in results if r.get('status') != 'success']
    data['failures_by_ip'] = dict(failures_by_ip)
    
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    
    total = len(results)
    failures = len(data['failures'])
    print(f"Processed {total} results: {failures} failures tracked")

if __name__ == '__main__':
    main()
```

## Report Generator: `scripts/generate_report.py`

```python
#!/usr/bin/env python3
"""Generate human-readable Markdown report from JSON results."""
import argparse
import json
from datetime import datetime

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True, help='JSON report file')
    parser.add_argument('--output', required=True, help='Output Markdown file')
    args = parser.parse_args()
    
    with open(args.input) as f:
        data = json.load(f)
    
    meta = data.get('metadata', {})
    failures = data.get('failures', [])
    
    report = f"""# DNS Health Report

**Generated**: {meta.get('timestamp', 'Unknown')}

## Summary

| Metric | Value |
|--------|-------|
| Total Relays | {meta.get('total_relays', 0)} |
| Success | {meta.get('success', 0)} |
| DNS Failures | {meta.get('dns_fail', 0)} |
| Wrong IP | {meta.get('wrong_ip', 0)} |
| Timeouts | {meta.get('timeout', 0)} |
| Errors | {meta.get('error', 0)} |
| **Success Rate** | **{meta.get('success_rate_percent', 0):.1f}%** |

## Failing Relays ({len(failures)})

| Fingerprint | Nickname | Exit IP | Status | Consecutive Failures |
|-------------|----------|---------|--------|---------------------|
"""
    
    for f in sorted(failures, key=lambda x: x.get('consecutive_failures', 0), reverse=True):
        report += f"| `{f.get('exit_fingerprint', '')[:16]}...` | {f.get('exit_nickname', 'unknown')} | {f.get('exit_address', 'unknown')} | {f.get('status', 'unknown')} | {f.get('consecutive_failures', 0)} |\n"
    
    with open(args.output, 'w') as f:
        f.write(report)
    
    print(f"Report written to {args.output}")

if __name__ == '__main__':
    main()
```

## Cron Schedule: `configs/cron.d/exitmap-dns`

```cron
# Run DNS health validation every 6 hours
15 */6 * * * exitmap /home/exitmap/exitmap-deploy/scripts/run_dns_validation.sh >> /home/exitmap/exitmap-deploy/logs/cron.log 2>&1
```

## Monthly Retention: `configs/cron.d/exitmap-retention`

```cron
# Monthly: compress old results, delete very old data
0 3 1 * * exitmap /home/exitmap/exitmap-deploy/scripts/retention.sh >> /home/exitmap/exitmap-deploy/logs/retention.log 2>&1
```

### `scripts/retention.sh` (example)

```bash
#!/bin/bash
# Compress results older than 30 days, delete older than 1 year
OUTPUT_DIR="${OUTPUT_DIR:-$HOME/exitmap-deploy/public}"

# Compress JSON files older than 30 days
find "$OUTPUT_DIR" -name "dns_health_*.json" -mtime +30 -exec gzip {} \;

# Delete compressed files older than 365 days
find "$OUTPUT_DIR" -name "dns_health_*.json.gz" -mtime +365 -delete

# Keep only last 100 entries in files.json
# (handled by aggregate script)
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

## Network Sensitivity & Constraints

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

## Future Work: Dashboard UI

A minimal frontend page (`public/index.html`) can show:

1. **Overall failure rate** (current run)
2. **List of failing exits** with:
   - Fingerprint (linked to Tor Metrics)
   - Exit IP address
   - Last-seen timestamp
   - Failure type
   - Consecutive failure count
3. **Grouping options**:
   - By exit IP (detect shared infrastructure issues)
   - By ASN (detect ISP-level DNS problems)
   - By operator label (if available from contact info)
4. **Trend over time** (rolling window chart)
5. **Historical data** (select previous runs from `files.json`)

### Dashboard Data Sources

```javascript
// Fetch latest results
const latest = await fetch('/latest.json').then(r => r.json());

// Fetch list of historical runs
const files = await fetch('/files.json').then(r => r.json());

// Fetch specific historical run
const historical = await fetch(`/${files[5]}`).then(r => r.json());
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

### Alert Payload

Each alert should include:
- `fingerprint`: Relay fingerprint
- `exit_ip`: Exit relay IP address
- `failure_type`: Status code (dns_fail, wrong_ip, timeout)
- `first_seen`: When failures started
- `last_seen`: Most recent failure
- `consecutive_count`: Number of consecutive failures
- `tor_metrics_url`: Link to relay on Tor Metrics

### Implementation Sketch

```python
# Future: scripts/check_alerts.py

def check_alerts(current_results, previous_results, threshold=2):
    """
    Identify relays that need alerting.
    
    Returns:
        new_alerts: Relays that just crossed threshold
        ongoing: Relays with ongoing failures
        recovered: Relays that recovered
    """
    new_alerts = []
    ongoing = []
    recovered = []
    
    for result in current_results:
        fp = result['exit_fingerprint']
        consecutive = result.get('consecutive_failures', 0)
        prev = previous_results.get(fp, {})
        prev_consecutive = prev.get('consecutive_failures', 0)
        
        if consecutive >= threshold and prev_consecutive < threshold:
            new_alerts.append(result)  # Just crossed threshold
        elif consecutive >= threshold:
            ongoing.append(result)  # Still failing
        elif prev_consecutive >= threshold and consecutive == 0:
            recovered.append(result)  # Just recovered
    
    return new_alerts, ongoing, recovered

def send_alerts(alerts, channel='email'):
    """Send alerts via configured channel."""
    # Email, webhook, or Tor Metrics integration
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
| Per-query uniqueness concept | Gemini 3 (improved: UUID → run_id.attempt.timestamp_ms.fingerprint) |
| Per-relay JSON files | Gemini 3 |
| Retry with delay | Gemini 3 |
| Auto-create virtualenv | Gemini 3 |
| Consecutive failure tracking | Gemini 3 + GPT5.2 |
| Error taxonomy & error_code | GPT5.2 |
| Two DNS modes (wildcard/NXDOMAIN) | GPT5.2 |
| Sharding concept (`--shard N/M`) | GPT5.2 |
| First hop tracking | GPT5.2 |
| Rate limiting recommendations | GPT5.2 |
| Network sensitivity guidance | GPT5.2 |
| Circuit vs DNS failure separation | GPT5.2 |
| Unique query format options | GPT5.2 |
| Results storage options | GPT5.2 |
| Existing modules analysis | GPT5.2 |
| Multiple stable domains fallback | GPT5.2 |
| Summary file concept | GPT5.2 |
| Report.md generation | GPT5.2 |
| Monthly retention cron | GPT5.2 |
| Dashboard UI features | GPT5.2 |
| Alert payload details | GPT5.2 |
| Deployment patterns | aroivalidator-deploy |
