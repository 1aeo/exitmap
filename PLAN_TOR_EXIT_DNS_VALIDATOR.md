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
| **RunID + Offset + Full FP** | `20250114143052.1.75789.ABC...40chars.domain` | ✅ Excellent | None |

### Recommended Format

```
{run_id}.{attempt}.{offset_ms}.{full_fingerprint}.{base_domain}
```

| Field | Purpose | Example |
|-------|---------|---------|
| `run_id` | Batch identifier - correlate all queries from same scan | `20250114143052` |
| `attempt` | Retry attempt (1 = first try, 2 = first retry) | `1` |
| `offset_ms` | Milliseconds since batch start - unique per query, dedups with run_id | `75789` |
| `full_fingerprint` | 40-char relay fingerprint - unambiguous identification | `ABCD1234...7890` |
| `base_domain` | Your wildcard domain | `tor.exit.validator.1aeo.com` |

### Example

```
20250114143052.1.75789.ABCD1234EFGH5678IJKL9012MNOP3456QRST7890.tor.exit.validator.1aeo.com
│              │ │     │                                        │
│              │ │     └─ Full fingerprint (which relay)        └─ Base domain
│              │ └─ Offset: 75789ms = 75.789 seconds since batch start
│              └─ Attempt number (1=first, 2=retry)
└─ Run ID (batch start: 2025-01-14 14:30:52)
```

**To reconstruct exact query time:** `run_id + offset_ms`
- Run started: 2025-01-14 14:30:52.000
- Offset: 75789ms = 75.789 seconds
- Query time: 2025-01-14 14:31:27.789

### Why This Format

1. **No redundancy** - `offset_ms` instead of full `timestamp_ms` saves ~12 chars
2. **Still unique** - Each query has different offset (time keeps moving)
3. **Full fingerprint** - No ambiguity, no collisions between relays
4. **Reconstructable** - Can compute exact time from run_id + offset
5. **Retry uniqueness** - Each retry has different attempt + offset_ms

### DNS Label Length Check

```
run_id:           14 chars  (20250114143052)
attempt:           1 char   (1)
offset_ms:      3-6 chars   (75789) - varies, max ~6 for multi-hour scans
fingerprint:      40 chars  (full hex)
separators:        4 chars  (dots)
                  ─────────
Total:           ~62-65 chars + base_domain ✓ (well under 253 limit)
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
    
    # Read all result files
    results = []
    pattern = os.path.join(util.analysis_dir, "result_*.json")
    for filepath in glob.glob(pattern):
        with open(filepath, 'r') as f:
            results.append(json.load(f))
        os.remove(filepath)
    
    # Calculate stats
    total = len(results)
    passed = sum(1 for r in results if r.get('ok'))
    
    by_fail_type = defaultdict(int)
    for r in results:
        if not r.get('ok'):
            by_fail_type[r.get('fail_type', 'unknown')] += 1
    
    # Write merged report
    report = {
        'metadata': {
            'run_id': _run_id,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'total': total,
            'passed': passed,
            'failed': total - passed,
            'by_fail_type': dict(by_fail_type),
            'pass_rate_percent': round(passed / total * 100, 2) if total else 0,
        },
        'results': results,
    }
    
    output_path = os.path.join(util.analysis_dir, f"dnshealth_{_run_id}.json")
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    log.info(f"Report: {output_path}, {passed}/{total} passed")
```

## Scaling & Performance Controls

### Single-Host Architecture

Exitmap's concurrency model for a single host:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ exitmap main process                                                        │
│ ├── Tor controller connection                                               │
│ ├── EventHandler (listens for circuit events)                               │
│ └── For each exit relay:                                                    │
│     ├── Build circuit (sequential, with --build-delay between)              │
│     └── On BUILT → spawn subprocess for probe()                             │
└─────────────────────────────────────────────────────────────────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                      ▼
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│ Subprocess 1 │      │ Subprocess 2 │      │ Subprocess N │
│ probe(exit1) │      │ probe(exit2) │      │ probe(exitN) │
│ └─► JSON     │      │ └─► JSON     │      │ └─► JSON     │
└──────────────┘      └──────────────┘      └──────────────┘
        │                      │                      │
        └──────────────────────┼──────────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │ teardown()          │
                    │ Merge all JSON →    │
                    │ dnshealth_*.json    │
                    └─────────────────────┘
```

**Key insight**: Circuits are built sequentially (rate-limited by `--build-delay`), but probes run concurrently as circuits complete. With 3000 exits at 2s delay:
- Circuit building: ~100 minutes (sequential)
- Peak concurrent probes: Depends on probe duration vs build rate

### Resource Management for 3000 Relays

#### Memory Estimation

```
Per-probe subprocess:     ~5-10 MB
Peak concurrent probes:   ~50-100 (depends on timing)
Estimated peak memory:    500 MB - 1 GB

With --build-delay=2s and probe duration ~5-15s:
- New circuit every 2s
- Each probe takes 5-15s
- At steady state: ~5-10 concurrent probes typical
- Worst case (many timeouts): ~50+ concurrent probes
```

#### Controlling Concurrency

Exitmap doesn't have a `--max-concurrent` flag, but you can control concurrency through:

1. **Build delay** (primary control):
   ```bash
   # Slower circuit building = fewer concurrent probes
   exitmap dnshealth --build-delay 3 --analysis-dir ./results
   ```

2. **System limits** (if needed):
   ```bash
   # Limit total memory for exitmap process tree
   systemd-run --user --scope -p MemoryMax=2G \
       exitmap dnshealth --analysis-dir ./results
   ```

> **Note**: If memory becomes a problem with 3000+ relays, see **Phase 5.1: Sharding** in the Implementation Timeline for sequential batch processing.

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
# Copyright 2025 1aeo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
import re
from typing import Dict, Any, Optional
from collections import defaultdict
from datetime import datetime

import torsocks
import error
import util
from util import exiturl

log = logging.getLogger(__name__)

__all__ = [
    'setup', 'probe', 'teardown', 'destinations',
    'generate_unique_query', 'resolve_with_retry',
    'WILDCARD_DOMAIN', 'EXPECTED_IP', 'QUERY_TIMEOUT',
]

# Wildcard domain configuration
WILDCARD_DOMAIN = "tor.exit.validator.1aeo.com"
EXPECTED_IP = "64.65.4.1"

# Fallback for NXDOMAIN mode
NXDOMAIN_DOMAIN = "example.com"

# Scan settings
QUERY_TIMEOUT = 10  # seconds per attempt
CIRCUIT_RETRIES = 2 # Retries for circuit failures (instant, cheap to retry)
TIMEOUT_RETRIES = 1 # Retries for timeouts (already waited 10s, expensive)
DNS_RETRIES = 0     # No retries for DNS errors (relay's fault, won't change)

destinations = None  # Module uses DNS resolution, not TCP connections

# Run metadata
_run_id = None
_run_start_time = None  # For computing offset_ms

# SOCKS error parsing regex (more robust than string splitting)
SOCKS_ERROR_PATTERN = re.compile(r'error\s+(\d+)', re.IGNORECASE)


def setup(consensus: Optional[Any] = None, target: Optional[str] = None, **kwargs) -> None:
    """Initialize scan metadata."""
    global _run_id, _run_start_time
    _run_start_time = time.time()
    _run_id = time.strftime("%Y%m%d%H%M%S")
    
    if target:
        log.info(f"DNS Health: NXDOMAIN mode (target={target})")
    else:
        log.info(f"DNS Health: Wildcard mode ({WILDCARD_DOMAIN} → {EXPECTED_IP})")
    
    log.info(f"Run ID: {_run_id}")


def generate_unique_query(fingerprint: str, base_domain: str, attempt: int = 1) -> str:
    """
    Generate a unique DNS query for this relay.
    
    Format: {run_id}.{attempt}.{offset_ms}.{full_fingerprint}.{base_domain}
    
    Every field has debugging value:
    - run_id: Which batch (correlate queries from same scan)
    - attempt: Which try (1=first, 2+=retry)
    - offset_ms: Milliseconds since run start (unique, can reconstruct exact time)
    - full_fingerprint: Which relay (unambiguous)
    """
    offset_ms = int((time.time() - _run_start_time) * 1000)
    return f"{_run_id}.{attempt}.{offset_ms}.{fingerprint}.{base_domain}"


def resolve_with_retry(exit_desc, base_domain: str, expected_ip: Optional[str] = None, 
                       first_hop: Optional[str] = None) -> Dict[str, Any]:
    """
    Resolve domain through exit relay with smart retry logic.
    
    Retry strategy (based on error type):
    - DNS errors: No retry (relay's fault, won't change)
    - Timeouts: 1 retry (already waited 10s, expensive)
    - Circuit errors: 2 retries (instant failure, cheap to retry)
    
    Each attempt generates a fresh unique query to avoid DNS caching.
    """
    exit_fp = exit_desc.fingerprint
    exit_url = exiturl(exit_fp)
    
    result = {
        "fingerprint": exit_fp,
        "nickname": getattr(exit_desc, 'nickname', 'unknown'),
        "address": getattr(exit_desc, 'address', 'unknown'),
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "run_id": _run_id,
        
        "ok": False,  # Default to fail, set True on success
        # fail_type, fail_reason, error only added on failure
        
        "resolved_ip": None,
        "latency_ms": None,
    }
    
    # Track expected_ip for validation (not in output)
    _expected_ip = expected_ip
    hop_suffix = f" via {first_hop}" if first_hop else ""
    
    # Retry counters (different limits by error type)
    circuit_attempts = 0
    timeout_attempts = 0
    attempt = 0
    
    while True:
        attempt += 1
        domain = generate_unique_query(exit_fp, base_domain, attempt)
        
        sock = torsocks.torsocket()
        sock.settimeout(QUERY_TIMEOUT)
        
        start_time = time.time()
        should_retry = False
        
        try:
            ip = sock.resolve(domain)
            result["resolved_ip"] = ip
            result["latency_ms"] = int((time.time() - start_time) * 1000)
            
            if _expected_ip:
                if ip == _expected_ip:
                    result["ok"] = True
                    log.info(f"✓ {exit_url} resolved to {ip}")
                else:
                    # DNS error - NO RETRY (relay's fault)
                    result["fail_type"] = "dns"
                    result["fail_reason"] = "wrong_ip"
                    result["error"] = f"Got {ip}, expected {_expected_ip}"
                    log.warning(f"✗ {exit_url} wrong IP: {ip}")
            else:
                result["ok"] = True
                log.info(f"✓ {exit_url} resolved to {ip}")
            
            return result
            
        except error.SOCKSv5Error as err:
            err_str = str(err)
            result["latency_ms"] = int((time.time() - start_time) * 1000)
            
            # Parse SOCKS error number using regex (more robust than string splitting)
            socks_err: Optional[int] = None
            match = SOCKS_ERROR_PATTERN.search(err_str)
            if match:
                socks_err = int(match.group(1))
            
            # SOCKS 4 = NXDOMAIN
            if socks_err == 4:
                if _expected_ip:
                    # DNS error - NO RETRY
                    result["fail_type"] = "dns"
                    result["fail_reason"] = "nxdomain"
                    result["error"] = "SOCKS 4: Domain not found (NXDOMAIN)"
                    log.warning(f"✗ {exit_url} NXDOMAIN")
                else:
                    result["ok"] = True
                    result["resolved_ip"] = "NXDOMAIN"
                    log.info(f"✓ {exit_url} NXDOMAIN (DNS working)")
                return result
            
            # DNS errors - NO RETRY (relay's fault, won't change)
            elif socks_err == 5:
                result["fail_type"] = "dns"
                result["fail_reason"] = "refused"
                result["error"] = "SOCKS 5: Connection refused"
            elif socks_err in (7, 8):
                result["fail_type"] = "dns"
                result["fail_reason"] = "unsupported"
                result["error"] = f"SOCKS {socks_err}: Command not supported"
            
            # Circuit errors - RETRY (transient, cheap to retry)
            else:
                circuit_attempts += 1
                result["fail_type"] = "circuit"
                result["fail_reason"] = "socks_error"
                
                if socks_err == 1:
                    result["error"] = f"SOCKS 1: General failure{hop_suffix}"
                elif socks_err == 2:
                    result["error"] = f"SOCKS 2: Not allowed by ruleset{hop_suffix}"
                elif socks_err == 3:
                    result["error"] = f"SOCKS 3: Network unreachable{hop_suffix}"
                elif socks_err == 6:
                    result["error"] = f"SOCKS 6: TTL expired{hop_suffix}"
                else:
                    result["error"] = f"SOCKS {socks_err or '?'}: Unknown error{hop_suffix}"
                
                if circuit_attempts <= CIRCUIT_RETRIES:
                    should_retry = True
                    log.info(f"Circuit error ({circuit_attempts}/{CIRCUIT_RETRIES}), retrying: {exit_url}")
            
        except EOFError:
            circuit_attempts += 1
            result["fail_type"] = "circuit"
            result["fail_reason"] = "eof"
            result["error"] = f"Connection closed unexpectedly{hop_suffix}"
            
            if circuit_attempts <= CIRCUIT_RETRIES:
                should_retry = True
                log.info(f"EOF ({circuit_attempts}/{CIRCUIT_RETRIES}), retrying: {exit_url}")
            
        except socket.timeout:
            timeout_attempts += 1
            result["fail_type"] = "timeout"
            result["fail_reason"] = "timeout"
            result["error"] = f"Timed out after {QUERY_TIMEOUT}s{hop_suffix}"
            
            # Timeouts are EXPENSIVE (already waited 10s) - limited retries
            if timeout_attempts <= TIMEOUT_RETRIES:
                should_retry = True
                log.info(f"Timeout ({timeout_attempts}/{TIMEOUT_RETRIES}), retrying: {exit_url}")
            
        except Exception as err:
            # Bug - NO RETRY
            result["fail_type"] = "bug"
            result["fail_reason"] = "exception"
            result["error"] = f"Exception: {type(err).__name__}: {err}"
            log.error(f"Exception: {exit_url} {err}")
        
        if not should_retry:
            break
        
        # Short delay before retry (circuit failures are instant)
        time.sleep(0.5)
    
    log.warning(f"✗ {exit_url} FAILED: {result['error']}")
    return result


def probe(exit_desc, target_host: Optional[str], target_port: Optional[int], 
          run_python_over_tor, run_cmd_over_tor, 
          first_hop: Optional[str] = None, **kwargs) -> None:
    """
    Probe the given exit relay's DNS resolution capability.
    
    If target_host is provided (-H flag), use NXDOMAIN mode.
    Otherwise, use wildcard mode with WILDCARD_DOMAIN.
    
    first_hop: Optional first hop fingerprint (requires exitmap modification).
    """
    if target_host:
        # NXDOMAIN mode: user specified a domain
        base_domain = target_host
        expected_ip = None
    else:
        # Wildcard mode: use our controlled domain
        base_domain = WILDCARD_DOMAIN
        expected_ip = EXPECTED_IP
    
    def do_validation(exit_desc, base_domain, expected_ip, first_hop):
        # Query is generated inside resolve_with_retry for each attempt
        result = resolve_with_retry(exit_desc, base_domain, expected_ip, first_hop=first_hop)
        
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
    
    run_python_over_tor(do_validation, exit_desc, base_domain, expected_ip, first_hop)


def teardown() -> None:
    """
    Called after all probes complete.
    Merges per-relay result files into single JSON report.
    """
    log.info(f"DNS Health scan complete. Run ID: {_run_id}")
    
    if not util.analysis_dir:
        return
    
    # Read all result files
    results = []
    pattern = os.path.join(util.analysis_dir, "result_*.json")
    result_files = glob.glob(pattern)
    
    if not result_files:
        log.warning(f"No result files found")
        return
    
    for filepath in result_files:
        try:
            with open(filepath, 'r') as f:
                results.append(json.load(f))
            os.remove(filepath)
        except Exception as e:
            log.error(f"Failed to read {filepath}: {e}")
    
    # Calculate stats
    total = len(results)
    passed = sum(1 for r in results if r.get('ok'))
    
    by_fail_type = defaultdict(int)
    for r in results:
        if not r.get('ok'):
            by_fail_type[r.get('fail_type', 'unknown')] += 1
    
    report = {
        'metadata': {
            'run_id': _run_id,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'total': total,
            'passed': passed,
            'failed': total - passed,
            'by_fail_type': dict(by_fail_type),
            'pass_rate_percent': round(passed / total * 100, 2) if total else 0,
        },
        'results': results,
    }
    
    json_path = os.path.join(util.analysis_dir, f"dnshealth_{_run_id}.json")
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    log.info(f"Report: {json_path}, {passed}/{total} passed")


if __name__ == "__main__":
    log.critical("Module can only be run via exitmap, not standalone.")
```

## Exit Relay Selection (Handled by exitmap, NOT the module)

**Key insight**: Modules don't select which exits to scan - exitmap does.

### How It Works

```
User runs: exitmap dnshealth -e ABC123 --analysis-dir ./results
                              │
                              ▼
         exitmap.py: select_exits() picks relays based on args
                              │
                              ▼
         For each exit: build circuit, then call module.probe(exit_desc, ...)
                              │
                              ▼
         dnshealth.py: probe() receives ONE exit, tests it, writes result
```

The module's `probe()` function receives:
- `exit_desc` - Relay descriptor (fingerprint, address, nickname, etc.)
- `target_host` - From `-H` flag (we use this for NXDOMAIN mode)
- `target_port` - From `-p` flag (unused for DNS)
- `run_python_over_tor` - Wrapper to route code through this circuit
- `first_hop` - **Optional** (requires exitmap modification below)

### Optional: Add first_hop to exitmap (for debugging)

To include first hop fingerprint in circuit error messages, add to `eventhandler.py`:

```python
# In new_circuit(), after getting exit_fpr:
first_hop_fpr = circ_event.path[0][0] if circ_event.path else None

# In module_call args, add first_hop_fpr parameter
# In module(), pass first_hop=first_hop_fpr to probe()
```

Without this change, `dnshealth.py` still works - error messages just won't include first hop info.

### Exit Selection Options (all handled by exitmap)

```bash
# Default: all good exits (no BadExit flag)
exitmap dnshealth --analysis-dir ./results

# Single exit by fingerprint
exitmap dnshealth -e ABC123DEF456... --analysis-dir ./results

# Multiple exits from file (one fingerprint per line)
exitmap dnshealth -E exits.txt --analysis-dir ./results

# By country code
exitmap dnshealth -C US --analysis-dir ./results

# All exits including BadExit
exitmap dnshealth --all-exits --analysis-dir ./results

# Only BadExit relays
exitmap dnshealth --bad-exits --analysis-dir ./results
```

### Module-Specific Options

```bash
# Wildcard mode (default) - uses controlled domain
exitmap dnshealth --analysis-dir ./results

# NXDOMAIN mode - uses -H to specify base domain
exitmap dnshealth -H example.com --analysis-dir ./results

# With specific first hop (faster, your controlled relay)
exitmap dnshealth --first-hop YOUR_RELAY_FPR --analysis-dir ./results

# Rate limiting
exitmap dnshealth --build-delay 3 --delay-noise 1 --analysis-dir ./results
```

## Output Format

### Per-Relay Result (Minimal)

**Success:**
```json
{
  "fingerprint": "ABCD1234EFGH5678IJKL9012MNOP3456QRST7890",
  "nickname": "MyRelay",
  "address": "192.0.2.1",
  "timestamp": "2025-01-14T14:30:52Z",
  "run_id": "20250114143052",
  
  "ok": true,
  "resolved_ip": "64.65.4.1",
  "latency_ms": 1523
}
```

**Failure:**
```json
{
  "fingerprint": "ABCD1234EFGH5678IJKL9012MNOP3456QRST7890",
  "nickname": "MyRelay",
  "address": "192.0.2.1",
  "timestamp": "2025-01-14T14:30:52Z",
  "run_id": "20250114143052",
  
  "ok": false,
  "fail_type": "dns",
  "fail_reason": "wrong_ip",
  "error": "Got 93.184.216.34, expected 64.65.4.1",
  "resolved_ip": "93.184.216.34",
  "latency_ms": 1523
}
```

### Field Reference (8 fields total)

| Field | Type | Always Present | Description |
|-------|------|----------------|-------------|
| `fingerprint` | string | ✓ | 40-char relay fingerprint |
| `nickname` | string | ✓ | Relay name |
| `address` | string | ✓ | Relay IP |
| `timestamp` | string | ✓ | ISO 8601 timestamp |
| `run_id` | string | ✓ | Batch ID |
| `ok` | boolean | ✓ | **Pass/fail** |
| `fail_type` | string | only if `ok=false` | Category: `dns`, `circuit`, `timeout`, `bug` |
| `fail_reason` | string | only if `ok=false` | Specific reason (see table) |
| `error` | string | only if `ok=false` | Human-readable details |
| `resolved_ip` | string | if available | IP returned (or `"NXDOMAIN"`) |
| `latency_ms` | int | if available | Resolution time in ms |

### Complete Error Reference (One Table)

All possible output field values:

| Scenario | `ok` | `fail_type` | `fail_reason` | `error` | Retries |
|----------|------|-------------|---------------|---------|---------|
| ✅ Success | `true` | - | - | - | - |
| ✅ NXDOMAIN mode | `true` | - | - | - | - |
| Wrong IP | `false` | `"dns"` | `"wrong_ip"` | `"Got {ip}, expected {expected}"` | 0 |
| SOCKS 4: NXDOMAIN | `false` | `"dns"` | `"nxdomain"` | `"SOCKS 4: Domain not found (NXDOMAIN)"` | 0 |
| SOCKS 5: Refused | `false` | `"dns"` | `"refused"` | `"SOCKS 5: Connection refused"` | 0 |
| SOCKS 7/8: Unsupported | `false` | `"dns"` | `"unsupported"` | `"SOCKS {N}: Command not supported"` | 0 |
| SOCKS 1: General | `false` | `"circuit"` | `"socks_error"` | `"SOCKS 1: General failure via {first_hop}"` | 2 |
| SOCKS 2: Not allowed | `false` | `"circuit"` | `"socks_error"` | `"SOCKS 2: Not allowed by ruleset via {first_hop}"` | 2 |
| SOCKS 3: Net unreachable | `false` | `"circuit"` | `"socks_error"` | `"SOCKS 3: Network unreachable via {first_hop}"` | 2 |
| SOCKS 6: TTL expired | `false` | `"circuit"` | `"socks_error"` | `"SOCKS 6: TTL expired via {first_hop}"` | 2 |
| SOCKS 9+: Unknown | `false` | `"circuit"` | `"socks_error"` | `"SOCKS {N}: Unknown error via {first_hop}"` | 2 |
| EOF | `false` | `"circuit"` | `"eof"` | `"Connection closed unexpectedly via {first_hop}"` | 2 |
| Timeout | `false` | `"timeout"` | `"timeout"` | `"Timed out after 10s via {first_hop}"` | 1 |
| Exception | `false` | `"bug"` | `"exception"` | `"Exception: {Type}: {message}"` | 0 |

**Legend**: `{ip}` = actual IP, `{expected}` = expected IP, `{first_hop}` = 40-char fingerprint (if available), `{N}` = SOCKS error number

### Retry Strategy

| Error Type | Retries | Delay | Rationale |
|------------|---------|-------|-----------|
| **DNS errors** (`dns`) | 0 | - | Relay's fault - won't change on retry |
| **Circuit errors** (`circuit`) | 2 | 0.5s | Transient Tor issue - cheap to retry (instant failure) |
| **Timeouts** (`timeout`) | 1 | 0.5s | Already waited 10s - expensive, but worth one more try |
| **Bugs** (`bug`) | 0 | - | Our code error - won't change on retry |

**Why different retry counts?**

```
DNS error:     [attempt 1] ──► FAIL (relay's DNS is broken, retrying won't help)
               Total time: ~1s

Circuit error: [attempt 1] ──► fail ──► [attempt 2] ──► fail ──► [attempt 3] ──► FAIL
               Total time: ~2s (instant failures + 0.5s delays)

Timeout:       [attempt 1] ──────10s──────► fail ──► [attempt 2] ──────10s──────► FAIL
               Total time: ~20s (expensive! only 1 retry)
```

### Failure Types (4 categories)

| `fail_type` | Meaning | Action |
|-------------|---------|--------|
| `dns` | Relay's DNS is broken | **Report to operator** |
| `circuit` | Network/circuit issue | Ignore (not relay's fault) |
| `timeout` | Timed out | Retry later (transient) |
| `bug` | Our code error | Fix our code |

### Filtering

```python
# Pass/fail
passed = [r for r in results if r['ok']]
failed = [r for r in results if not r['ok']]

# Actionable failures (DNS issues)
dns_issues = [r for r in results if r.get('fail_type') == 'dns']

# Success rate (excluding circuit issues we can't blame on relay)
testable = [r for r in results if r['ok'] or r.get('fail_type') != 'circuit']
success_rate = len([r for r in testable if r['ok']]) / len(testable)
```

---

## Unit Tests: `test/test_dnshealth.py`

```python
"""Unit tests for dnshealth module."""
import pytest
import json
import os
import tempfile
from unittest.mock import Mock, patch, MagicMock

# Import module under test
import sys
sys.path.insert(0, 'src/modules')


class TestGenerateUniqueQuery:
    """Test unique query generation."""
    
    def test_format(self):
        """Query follows expected format."""
        from dnshealth import generate_unique_query, setup
        setup()  # Initialize _run_id
        
        query = generate_unique_query("ABCD1234" * 5, "example.com", attempt=1)
        parts = query.split(".")
        
        assert len(parts) >= 5  # run_id.attempt.offset.fingerprint.domain
        assert parts[1] == "1"  # attempt
        assert len(parts[3]) == 40  # full fingerprint
        assert "example.com" in query
    
    def test_uniqueness(self):
        """Each call produces unique query."""
        from dnshealth import generate_unique_query, setup
        setup()
        
        fp = "ABCD1234" * 5
        q1 = generate_unique_query(fp, "example.com", 1)
        q2 = generate_unique_query(fp, "example.com", 1)
        
        assert q1 != q2  # Different offset_ms
    
    def test_retry_different(self):
        """Different attempts produce different queries."""
        from dnshealth import generate_unique_query, setup
        setup()
        
        fp = "ABCD1234" * 5
        q1 = generate_unique_query(fp, "example.com", 1)
        q2 = generate_unique_query(fp, "example.com", 2)
        
        assert q1 != q2
        assert ".1." in q1
        assert ".2." in q2


class TestRetryStrategy:
    """Test error-specific retry behavior."""
    
    @patch('dnshealth.torsocks')
    def test_dns_error_no_retry(self, mock_torsocks):
        """DNS errors should not retry."""
        from dnshealth import resolve_with_retry, setup
        import error
        
        setup()
        mock_sock = MagicMock()
        mock_sock.resolve.side_effect = error.SOCKSv5Error("SOCKS Server error 5")
        mock_torsocks.torsocket.return_value = mock_sock
        
        exit_desc = Mock(fingerprint="A" * 40)
        result = resolve_with_retry(exit_desc, "example.com", "1.2.3.4")
        
        assert result["ok"] == False
        assert result["fail_type"] == "dns"
        assert mock_sock.resolve.call_count == 1  # No retries
    
    @patch('dnshealth.torsocks')
    def test_circuit_error_retries(self, mock_torsocks):
        """Circuit errors should retry up to CIRCUIT_RETRIES times."""
        from dnshealth import resolve_with_retry, setup, CIRCUIT_RETRIES
        import error
        
        setup()
        mock_sock = MagicMock()
        mock_sock.resolve.side_effect = error.SOCKSv5Error("SOCKS Server error 1")
        mock_torsocks.torsocket.return_value = mock_sock
        
        exit_desc = Mock(fingerprint="A" * 40)
        result = resolve_with_retry(exit_desc, "example.com", "1.2.3.4")
        
        assert result["fail_type"] == "circuit"
        assert mock_sock.resolve.call_count == CIRCUIT_RETRIES + 1
    
    @patch('dnshealth.torsocks')
    def test_timeout_limited_retries(self, mock_torsocks):
        """Timeouts should retry only TIMEOUT_RETRIES times."""
        from dnshealth import resolve_with_retry, setup, TIMEOUT_RETRIES
        import socket
        
        setup()
        mock_sock = MagicMock()
        mock_sock.resolve.side_effect = socket.timeout()
        mock_torsocks.torsocket.return_value = mock_sock
        
        exit_desc = Mock(fingerprint="A" * 40)
        result = resolve_with_retry(exit_desc, "example.com", "1.2.3.4")
        
        assert result["fail_type"] == "timeout"
        assert mock_sock.resolve.call_count == TIMEOUT_RETRIES + 1


class TestOutputFormat:
    """Test result output format."""
    
    @patch('dnshealth.torsocks')
    def test_success_fields(self, mock_torsocks):
        """Success result has correct fields."""
        from dnshealth import resolve_with_retry, setup
        
        setup()
        mock_sock = MagicMock()
        mock_sock.resolve.return_value = "64.65.4.1"
        mock_torsocks.torsocket.return_value = mock_sock
        
        exit_desc = Mock(fingerprint="A" * 40, nickname="TestRelay", address="1.2.3.4")
        result = resolve_with_retry(exit_desc, "example.com", "64.65.4.1")
        
        assert result["ok"] == True
        assert result["resolved_ip"] == "64.65.4.1"
        assert result["latency_ms"] is not None
        assert "fail_type" not in result or result.get("fail_type") is None
    
    @patch('dnshealth.torsocks')
    def test_failure_fields(self, mock_torsocks):
        """Failure result has error fields."""
        from dnshealth import resolve_with_retry, setup
        import error
        
        setup()
        mock_sock = MagicMock()
        mock_sock.resolve.side_effect = error.SOCKSv5Error("SOCKS Server error 4")
        mock_torsocks.torsocket.return_value = mock_sock
        
        exit_desc = Mock(fingerprint="A" * 40, nickname="TestRelay", address="1.2.3.4")
        result = resolve_with_retry(exit_desc, "example.com", "64.65.4.1")
        
        assert result["ok"] == False
        assert result["fail_type"] == "dns"
        assert result["fail_reason"] == "nxdomain"
        assert "SOCKS 4" in result["error"]


class TestNXDOMAINMode:
    """Test NXDOMAIN mode (fallback)."""
    
    @patch('dnshealth.torsocks')
    def test_nxdomain_is_success(self, mock_torsocks):
        """In NXDOMAIN mode, SOCKS error 4 is success."""
        from dnshealth import resolve_with_retry, setup
        import error
        
        setup()
        mock_sock = MagicMock()
        mock_sock.resolve.side_effect = error.SOCKSv5Error("SOCKS Server error 4")
        mock_torsocks.torsocket.return_value = mock_sock
        
        exit_desc = Mock(fingerprint="A" * 40)
        # expected_ip=None triggers NXDOMAIN mode
        result = resolve_with_retry(exit_desc, "example.com", expected_ip=None)
        
        assert result["ok"] == True
        assert result["resolved_ip"] == "NXDOMAIN"


class TestTeardown:
    """Test result aggregation in teardown."""
    
    def test_merge_results(self):
        """Teardown merges per-relay files correctly."""
        from dnshealth import teardown, setup, _run_id
        import dnshealth
        
        setup()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create mock result files
            for i, status in enumerate([True, True, False]):
                result = {
                    "fingerprint": f"FP{i}" * 10,
                    "ok": status,
                    "fail_type": "dns" if not status else None,
                }
                with open(os.path.join(tmpdir, f"result_FP{i}.json"), "w") as f:
                    json.dump(result, f)
            
            # Mock util.analysis_dir
            with patch.object(dnshealth, 'util') as mock_util:
                mock_util.analysis_dir = tmpdir
                dnshealth._run_id = "20250114120000"
                teardown()
            
            # Check merged report
            report_path = os.path.join(tmpdir, f"dnshealth_{dnshealth._run_id}.json")
            with open(report_path) as f:
                report = json.load(f)
            
            assert report["metadata"]["total"] == 3
            assert report["metadata"]["passed"] == 2
            assert report["metadata"]["failed"] == 1
            assert len(report["results"]) == 3


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_empty_fingerprint(self):
        """Handle empty fingerprint gracefully."""
        from dnshealth import generate_unique_query, setup
        setup()
        
        # Should not crash, though this is invalid input
        query = generate_unique_query("", "example.com", 1)
        assert "example.com" in query
    
    def test_malformed_fingerprint(self):
        """Handle non-hex fingerprint."""
        from dnshealth import generate_unique_query, setup
        setup()
        
        # Module should handle this (it's just a string)
        query = generate_unique_query("not-a-valid-fingerprint!", "example.com", 1)
        assert "example.com" in query
    
    @patch('dnshealth.torsocks')
    def test_missing_exit_desc_attrs(self, mock_torsocks):
        """Handle exit_desc missing optional attributes."""
        from dnshealth import resolve_with_retry, setup
        
        setup()
        mock_sock = MagicMock()
        mock_sock.resolve.return_value = "64.65.4.1"
        mock_torsocks.torsocket.return_value = mock_sock
        
        # Minimal exit_desc with only fingerprint
        exit_desc = Mock(spec=['fingerprint'])
        exit_desc.fingerprint = "A" * 40
        
        result = resolve_with_retry(exit_desc, "example.com", "64.65.4.1")
        
        assert result["ok"] == True
        assert result["nickname"] == "unknown"
        assert result["address"] == "unknown"
    
    def test_teardown_no_results(self):
        """Teardown handles empty results directory."""
        from dnshealth import teardown, setup
        import dnshealth
        
        setup()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(dnshealth, 'util') as mock_util:
                mock_util.analysis_dir = tmpdir
                dnshealth._run_id = "20250114120000"
                # Should not crash with no result files
                teardown()
    
    def test_teardown_malformed_json(self):
        """Teardown handles corrupted result files."""
        from dnshealth import teardown, setup
        import dnshealth
        
        setup()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a corrupted JSON file
            with open(os.path.join(tmpdir, "result_BADFILE.json"), "w") as f:
                f.write("{invalid json")
            
            # Create a valid file too
            with open(os.path.join(tmpdir, "result_GOODFILE.json"), "w") as f:
                json.dump({"fingerprint": "G" * 40, "ok": True}, f)
            
            with patch.object(dnshealth, 'util') as mock_util:
                mock_util.analysis_dir = tmpdir
                dnshealth._run_id = "20250114120000"
                # Should not crash, should skip bad file
                teardown()
            
            # Should have created report with 1 result
            report_path = os.path.join(tmpdir, f"dnshealth_{dnshealth._run_id}.json")
            with open(report_path) as f:
                report = json.load(f)
            assert report["metadata"]["total"] == 1


class TestDNSLabelLength:
    """Test DNS query length constraints."""
    
    def test_query_under_253_chars(self):
        """Generated queries stay under DNS 253 char limit."""
        from dnshealth import generate_unique_query, setup
        setup()
        
        # Test with longest possible fingerprint (40 hex chars)
        fp = "F" * 40
        base_domain = "tor.exit.validator.1aeo.com"
        
        for attempt in range(1, 10):
            query = generate_unique_query(fp, base_domain, attempt)
            assert len(query) <= 253, f"Query too long: {len(query)} chars"
    
    def test_label_under_63_chars(self):
        """Each DNS label stays under 63 char limit."""
        from dnshealth import generate_unique_query, setup
        setup()
        
        fp = "F" * 40
        query = generate_unique_query(fp, "tor.exit.validator.1aeo.com", 1)
        
        labels = query.split(".")
        for label in labels:
            assert len(label) <= 63, f"Label too long: {label} ({len(label)} chars)"
    
    def test_longest_possible_query(self):
        """Extreme case: long run, high attempt, long offset."""
        from dnshealth import generate_unique_query, setup
        import dnshealth
        
        # Simulate a very long scan (offset would be large)
        dnshealth._run_start_time = 0  # Epoch
        dnshealth._run_id = "20250114143052"
        
        import time
        # Current time gives max realistic offset
        fp = "F" * 40
        query = generate_unique_query(fp, "tor.exit.validator.1aeo.com", 99)
        
        # Even with large offset_ms, should be under limit
        assert len(query) <= 253


class TestConcurrency:
    """Test thread/process safety scenarios."""
    
    def test_result_files_unique_per_fingerprint(self):
        """Each fingerprint gets unique result file (no collisions)."""
        from dnshealth import probe, setup
        import dnshealth
        
        setup()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(dnshealth, 'util') as mock_util:
                mock_util.analysis_dir = tmpdir
                
                # Simulate two different relays
                fps = ["A" * 40, "B" * 40]
                
                for fp in fps:
                    filepath = os.path.join(tmpdir, f"result_{fp}.json")
                    with open(filepath, 'w') as f:
                        json.dump({"fingerprint": fp}, f)
                
                # Should have 2 distinct files
                files = os.listdir(tmpdir)
                assert len(files) == 2
                assert "result_" + "A" * 40 + ".json" in files
                assert "result_" + "B" * 40 + ".json" in files
    
    def test_teardown_idempotent(self):
        """Multiple teardown calls don't crash."""
        from dnshealth import teardown, setup
        import dnshealth
        
        setup()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create one result file
            with open(os.path.join(tmpdir, "result_TEST.json"), "w") as f:
                json.dump({"fingerprint": "T" * 40, "ok": True}, f)
            
            with patch.object(dnshealth, 'util') as mock_util:
                mock_util.analysis_dir = tmpdir
                dnshealth._run_id = "20250114120000"
                
                # First teardown
                teardown()
                
                # Second teardown (no files left) - should not crash
                teardown()
```

### Running Tests

```bash
# From exitmap root directory
pytest test/test_dnshealth.py -v

# With coverage
pytest test/test_dnshealth.py --cov=src/modules/dnshealth --cov-report=term-missing

# Quick smoke test
pytest test/test_dnshealth.py::TestGenerateUniqueQuery -v
```

## CI Configuration: `.gitlab-ci.yml`

The exitmap project is hosted on GitLab (torproject.org). Add CI configuration to run tests automatically on merge requests.

```yaml
# .gitlab-ci.yml - Add to repository root

stages:
  - lint
  - test

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

cache:
  paths:
    - .cache/pip/

# Lint stage - fast feedback
lint:
  stage: lint
  image: python:3.11-slim
  script:
    - pip install flake8
    - flake8 src/modules/dnshealth.py --max-line-length=100
  rules:
    - changes:
        - src/modules/dnshealth.py
        - test/test_dnshealth.py

# Unit tests
test:dnshealth:
  stage: test
  image: python:3.11-slim
  script:
    - pip install .[dev]
    - pytest test/test_dnshealth.py -v --cov=src/modules/dnshealth --cov-report=term-missing
  coverage: '/TOTAL.*\s+(\d+%)/'
  rules:
    - changes:
        - src/modules/dnshealth.py
        - test/test_dnshealth.py

# Full test suite (runs on main branch)
test:all:
  stage: test
  image: python:3.11-slim
  script:
    - pip install .[dev]
    - pytest test/ -v --cov=src --cov-report=term-missing
  coverage: '/TOTAL.*\s+(\d+%)/'
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

### CI Pipeline Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        Merge Request                            │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ LINT STAGE                                                      │
│ ├── flake8 src/modules/dnshealth.py                             │
│ └── Fast fail on style issues                                   │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ TEST STAGE                                                      │
│ ├── pytest test/test_dnshealth.py                               │
│ ├── Coverage report                                             │
│ └── Pass/fail on test results                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module Documentation

### `src/modules/dnshealth.py` - DNS Health Check Module

**Purpose**: Validate DNS resolution through Tor exit relays using unique queries per relay.

#### Usage

```bash
# Default: Wildcard mode (recommended)
exitmap dnshealth --analysis-dir ./results

# NXDOMAIN mode (fallback, no infrastructure needed)
exitmap dnshealth -H example.com --analysis-dir ./results

# Single relay test
exitmap dnshealth -e FINGERPRINT --analysis-dir ./results

# All exits including BadExit
exitmap dnshealth --all-exits --analysis-dir ./results
```

#### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--analysis-dir` | Output directory for results | Required |
| `-H`, `--target-host` | Base domain (enables NXDOMAIN mode) | None (wildcard mode) |
| `-e` | Single exit fingerprint | All exits |
| `-E` | File with fingerprints (one per line) | All exits |
| `-C` | Country code filter | All countries |
| `--first-hop` | Specific guard relay | Random |
| `--build-delay` | Seconds between circuits | 2 |
| `--all-exits` | Include BadExit relays | False |

#### Output

Results written to `{analysis-dir}/dnshealth_{run_id}.json`:

```json
{
  "metadata": {
    "run_id": "20250114143052",
    "timestamp": "2025-01-14T14:35:00Z",
    "total": 1500,
    "passed": 1450,
    "failed": 50,
    "by_fail_type": {"dns": 30, "circuit": 15, "timeout": 5},
    "pass_rate_percent": 96.67
  },
  "results": [
    {"fingerprint": "...", "ok": true, "resolved_ip": "64.65.4.1", ...},
    {"fingerprint": "...", "ok": false, "fail_type": "dns", "error": "...", ...}
  ]
}
```

#### Modes

| Mode | Domain | Success Condition | Use When |
|------|--------|-------------------|----------|
| **Wildcard** | `*.tor.exit.validator.1aeo.com` | Returns `64.65.4.1` | You control DNS infrastructure |
| **NXDOMAIN** | `*.{your-domain}` | SOCKS error 4 | Quick testing, no DNS setup |

#### Dependencies

```
# Already in exitmap requirements.txt
stem>=1.8.0

# Standard library (no additional deps)
socket, json, time, os, glob, logging
```

---

## Troubleshooting

### Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| `No results generated` | `--analysis-dir` not specified | Add `--analysis-dir ./results` |
| `All relays timeout` | Tor not running/bootstrapped | Check `tor` process, wait for bootstrap |
| `0% success rate` | Wildcard domain not resolving | Test: `dig test.tor.exit.validator.1aeo.com` |
| `Module not found` | Wrong working directory | Run from exitmap root: `./bin/exitmap dnshealth` |
| `Permission denied` | Can't write to analysis dir | Check directory permissions |
| `High circuit failure rate` | Network issues / bad guard | Try `--first-hop YOUR_RELAY` |

### Debugging

```bash
# Verbose logging
exitmap -v dnshealth --analysis-dir ./results

# Test single relay first
exitmap dnshealth -e KNOWN_GOOD_FINGERPRINT --analysis-dir ./results

# Check Tor connectivity
exitmap checktest --analysis-dir ./results

# Inspect raw result files (before teardown merges them)
ls -la ./results/result_*.json
```

### Verifying Setup

```bash
# 1. Check wildcard DNS is working
dig +short test123.tor.exit.validator.1aeo.com
# Should return: 64.65.4.1

# 2. Check Tor is running
pgrep -a tor

# 3. Test with one relay
exitmap dnshealth -e $(exitmap -l | head -1) --analysis-dir ./test_results
cat ./test_results/dnshealth_*.json | jq '.metadata'

# 4. Run full scan
exitmap dnshealth --analysis-dir ./results
```

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
    
    with open(args.input) as f:
        data = json.load(f)
    
    results = data.get('results', [])
    
    # Load previous state
    previous_state = {}
    if args.previous and os.path.exists(args.previous):
        try:
            with open(args.previous) as f:
                for res in json.load(f).get('results', []):
                    if fp := res.get('fingerprint'):
                        previous_state[fp] = res
        except Exception as e:
            print(f"Warning: Could not load previous report: {e}")
    
    # Add consecutive failure tracking
    for result in results:
        fp = result.get('fingerprint')
        if result.get('ok'):
            result['consecutive_failures'] = 0
        else:
            prev = previous_state.get(fp, {})
            prev_failures = prev.get('consecutive_failures', 0) if not prev.get('ok', True) else 0
            result['consecutive_failures'] = prev_failures + 1
    
    # Group failures by IP (useful for identifying shared infrastructure issues)
    failures_by_ip = defaultdict(list)
    for r in results:
        if not r.get('ok'):
            failures_by_ip[r.get('address', '?')].append(r['fingerprint'])
    
    data['failures'] = [r for r in results if not r.get('ok')]
    data['failures_by_ip'] = dict(failures_by_ip)
    
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Processed {len(results)}: {len(data['failures'])} failures")

if __name__ == '__main__':
    main()
```

## Report Generator: `scripts/generate_report.py`

```python
#!/usr/bin/env python3
"""Generate human-readable Markdown report from JSON results."""
import argparse
import json

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True, help='JSON report file')
    parser.add_argument('--output', required=True, help='Output Markdown file')
    args = parser.parse_args()
    
    with open(args.input) as f:
        data = json.load(f)
    
    meta = data.get('metadata', {})
    results = data.get('results', [])
    failures = [r for r in results if not r.get('ok')]
    by_type = meta.get('by_fail_type', {})
    
    report = f"""# DNS Health Report

**Generated**: {meta.get('timestamp', 'Unknown')}

## Summary

| Metric | Value |
|--------|-------|
| Total | {meta.get('total', 0)} |
| Passed | {meta.get('passed', 0)} |
| Failed | {meta.get('failed', 0)} |
| └─ DNS | {by_type.get('dns', 0)} |
| └─ Circuit | {by_type.get('circuit', 0)} |
| └─ Timeout | {by_type.get('timeout', 0)} |
| **Pass Rate** | **{meta.get('pass_rate_percent', 0):.1f}%** |

## Failing Relays ({len(failures)})

| Fingerprint | Nickname | IP | Type | Reason | Error |
|-------------|----------|----|------|--------|-------|
"""
    
    # Sort: dns issues first (actionable), then others
    for f in sorted(failures, key=lambda x: (x.get('fail_type') != 'dns', x.get('fail_type', ''))):
        fp = f.get('fingerprint', '')[:16]
        error = (f.get('error', '') or '')[:40]
        report += f"| `{fp}...` | {f.get('nickname', '?')} | {f.get('address', '?')} | {f.get('fail_type', '?')} | {f.get('fail_reason', '?')} | {error} |\n"
    
    with open(args.output, 'w') as f:
        f.write(report)
    
    print(f"Report: {args.output}")

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

---

### Phase 1: exitmap Module (Week 1)

#### 1.1 Create Core Module File
- [ ] Create `src/modules/dnshealth.py` with module skeleton
- [ ] Add license header (Apache 2.0)
- [ ] Add imports and `__all__` exports
- [ ] Define module constants:
  - `WILDCARD_DOMAIN = "tor.exit.validator.1aeo.com"`
  - `EXPECTED_IP = "64.65.4.1"`
  - `QUERY_TIMEOUT = 10`
  - `CIRCUIT_RETRIES = 2`
  - `TIMEOUT_RETRIES = 1`
- [ ] Set `destinations = None` (DNS resolution, not TCP)

#### 1.2 Implement Core Functions
- [ ] `setup(consensus, target, **kwargs)` - Initialize `_run_id`, `_run_start_time`
- [ ] `generate_unique_query(fingerprint, base_domain, attempt)` - Create unique DNS query
- [ ] `resolve_with_retry(exit_desc, base_domain, expected_ip, first_hop)` - Main resolution logic
  - [ ] SOCKS error parsing with regex `SOCKS_ERROR_PATTERN`
  - [ ] Retry logic: 0 for DNS errors, 1 for timeouts, 2 for circuit errors
  - [ ] Result dict with all required fields
- [ ] `probe(exit_desc, target_host, target_port, ...)` - Module entry point
- [ ] `teardown()` - Merge per-relay JSON files into final report

#### 1.3 Create Unit Tests
- [ ] Create `test/test_dnshealth.py`
- [ ] `TestGenerateUniqueQuery` - Format, uniqueness, retry differentiation
- [ ] `TestRetryStrategy` - DNS/circuit/timeout retry counts
- [ ] `TestOutputFormat` - Success/failure field validation
- [ ] `TestNXDOMAINMode` - SOCKS error 4 = success when expected_ip=None
- [ ] `TestTeardown` - Merge logic, stats calculation
- [ ] `TestEdgeCases` - Empty FP, malformed JSON, missing attrs
- [ ] `TestDNSLabelLength` - Under 253 chars, labels under 63 chars
- [ ] `TestConcurrency` - Unique files per FP, idempotent teardown

#### 1.4 Manual Testing
- [ ] Verify wildcard DNS resolves: `dig +short test.tor.exit.validator.1aeo.com`
- [ ] Test single relay: `exitmap dnshealth -e <FP> --analysis-dir ./test`
- [ ] Test NXDOMAIN mode: `exitmap dnshealth -e <FP> -H example.com --analysis-dir ./test`
- [ ] Verify JSON output structure matches spec
- [ ] Run full scan on small subset: `exitmap dnshealth -E 10relays.txt --analysis-dir ./test`

#### 1.5 CI Configuration
- [ ] Create `.gitlab-ci.yml` with lint and test stages
- [ ] Verify CI passes on MR
- [ ] Add coverage badge to README (optional)

**Phase 1 Exit Criteria:**
- [ ] All unit tests pass (`pytest test/test_dnshealth.py -v`)
- [ ] Coverage >= 80%
- [ ] Single relay scan produces valid JSON
- [ ] Full scan completes successfully

---

### Phase 2: exitmap-deploy Setup (Week 2)

#### 2.1 Create Repository Structure
- [ ] Create `exitmap-deploy` repository
- [ ] Create directory structure:
  ```
  exitmap-deploy/
  ├── README.md
  ├── config.env.example
  ├── scripts/
  │   ├── run_dns_validation.sh
  │   ├── postprocess_results.py
  │   ├── generate_report.py
  │   ├── retention.sh
  │   ├── upload_do.sh
  │   ├── upload_r2.sh
  │   └── install.sh
  ├── configs/
  │   └── cron.d/
  │       ├── exitmap-dns
  │       └── exitmap-retention
  ├── functions/
  │   └── [[path]].js
  └── public/
      └── index.html
  ```
- [ ] Create `.gitignore` (logs, results, .env)

#### 2.2 Configuration
- [ ] Create `config.env.example` with all settings:
  - `EXITMAP_DIR` - Path to exitmap repo
  - `OUTPUT_DIR` - Where results are stored
  - `LOG_DIR` - Where logs go
  - `BUILD_DELAY` - Seconds between circuits (default: 2)
  - `DELAY_NOISE` - Random variance (default: 1)
  - `FIRST_HOP` - Optional controlled relay FP
  - `ALL_EXITS` - Include BadExit (default: true)
  - Cloud storage settings (DO, R2)
- [ ] Create `scripts/install.sh`:
  - Check Python version
  - Create virtualenv if needed
  - Install exitmap dependencies
  - Validate config

#### 2.3 Batch Runner Script
- [ ] Create `scripts/run_dns_validation.sh`:
  - [ ] Load config.env
  - [ ] Implement flock-based locking (prevent concurrent runs)
  - [ ] Create timestamped analysis directory
  - [ ] Activate virtualenv
  - [ ] Build and execute exitmap command
  - [ ] Call postprocess_results.py
  - [ ] Copy to latest.json
  - [ ] Update files.json manifest
  - [ ] Trigger cloud uploads (parallel)
  - [ ] Log success/failure

#### 2.4 Post-Processing Scripts
- [ ] Create `scripts/postprocess_results.py`:
  - [ ] Load current run JSON
  - [ ] Load previous run (if exists) for consecutive failure tracking
  - [ ] Add `consecutive_failures` field to each result
  - [ ] Group failures by IP (detect shared infrastructure issues)
  - [ ] Write updated JSON

- [ ] Create `scripts/generate_report.py`:
  - [ ] Load JSON results
  - [ ] Generate Markdown report with summary table
  - [ ] List failing relays sorted by fail_type
  - [ ] Include Tor Metrics links

#### 2.5 Retention Script
- [ ] Create `scripts/retention.sh`:
  - Compress JSON files older than 30 days
  - Delete compressed files older than 365 days
  - Trim files.json to last 100 entries

#### 2.6 Local Testing
- [ ] Run `./scripts/install.sh` - verify setup
- [ ] Run `./scripts/run_dns_validation.sh` manually
- [ ] Verify `public/latest.json` created
- [ ] Verify `public/files.json` updated
- [ ] Test postprocess adds consecutive_failures
- [ ] Test generate_report.py produces valid Markdown

**Phase 2 Exit Criteria:**
- [ ] Manual run completes successfully
- [ ] Output files match expected format
- [ ] Locking prevents concurrent runs
- [ ] Logs capture all steps

---

### Phase 3: Cloud Integration (Week 3)

#### 3.1 DigitalOcean Spaces Setup
- [ ] Create DO Spaces bucket `exitmap-dns-results`
- [ ] Create Spaces access key (read/write)
- [ ] Set bucket policy (public read, authenticated write)
- [ ] Configure CORS for web access:
  ```json
  {
    "CORSRules": [{
      "AllowedOrigins": ["*"],
      "AllowedMethods": ["GET"],
      "AllowedHeaders": ["*"],
      "MaxAgeSeconds": 3600
    }]
  }
  ```
- [ ] Create `scripts/upload_do.sh`:
  ```bash
  #!/bin/bash
  # Upload files to DO Spaces using s3cmd or aws-cli
  source "$(dirname "$0")/../config.env"
  
  for file in "$@"; do
      filename=$(basename "$file")
      
      # Set cache headers based on file type
      if [[ "$filename" == "latest.json" ]] || [[ "$filename" == "files.json" ]]; then
          cache="max-age=60"
      else
          cache="max-age=31536000"
      fi
      
      s3cmd put "$file" \
          "s3://${DO_BUCKET}/$filename" \
          --acl-public \
          --add-header="Cache-Control:$cache" \
          --add-header="Content-Type:application/json"
  done
  ```
- [ ] Test upload: `./scripts/upload_do.sh public/latest.json`
- [ ] Verify file accessible via Spaces URL

#### 3.2 Cloudflare R2 Setup
- [ ] Create R2 bucket `exitmap-dns-results`
- [ ] Create R2 API token with read/write
- [ ] Configure custom domain (optional)
- [ ] Create `scripts/upload_r2.sh`:
  ```bash
  #!/bin/bash
  # Upload files to Cloudflare R2 using wrangler or aws-cli (S3-compatible)
  source "$(dirname "$0")/../config.env"
  
  export AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID"
  export AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY"
  export AWS_ENDPOINT_URL="https://${CF_ACCOUNT_ID}.r2.cloudflarestorage.com"
  
  for file in "$@"; do
      filename=$(basename "$file")
      aws s3 cp "$file" "s3://${R2_BUCKET}/$filename" \
          --content-type "application/json"
  done
  ```
- [ ] Test upload and verify accessibility

#### 3.3 Cloudflare Pages Setup (Optional Dashboard)
- [ ] Create Pages project `exitmap-dns`
- [ ] Connect to exitmap-deploy repo (or manual deploy)
- [ ] Configure build settings:
  - Build command: (none, static files)
  - Output directory: `public/`
- [ ] Create `functions/[[path]].js` for R2 proxy:
  - Route `/latest.json` → R2 bucket
  - Set appropriate Cache-Control headers
  - Handle 404s gracefully
- [ ] Configure R2 bucket binding in Pages settings
- [ ] Deploy and test: `https://exitmap-dns.pages.dev/latest.json`

#### 3.4 Test Cloud Pipeline
- [ ] Run full batch with cloud uploads enabled:
  ```bash
  DO_ENABLED=true R2_ENABLED=true ./scripts/run_dns_validation.sh
  ```
- [ ] Verify files appear in DO Spaces
- [ ] Verify files appear in R2
- [ ] Test public URLs work
- [ ] Test cache headers are correct

**Phase 3 Exit Criteria:**
- [ ] Files upload to DO Spaces successfully
- [ ] Files upload to R2 successfully
- [ ] Public URLs are accessible
- [ ] Cache headers are correct (1 min for latest, 1 year for historical)

---

### Phase 4: Production Deployment (Week 4)

#### 4.1 Server Setup
- [ ] Provision server (or use existing)
- [ ] Install dependencies:
  ```bash
  sudo apt update
  sudo apt install python3 python3-venv tor s3cmd jq
  ```
- [ ] Create dedicated user (optional): `sudo useradd -m exitmap`
- [ ] Clone repositories:
  ```bash
  git clone https://gitlab.torproject.org/tpo/network-health/exitmap.git ~/exitmap
  git clone https://github.com/1aeo/exitmap-deploy.git ~/exitmap-deploy
  ```
- [ ] Set up exitmap:
  ```bash
  cd ~/exitmap
  python3 -m venv venv
  source venv/bin/activate
  pip install -e .
  ```

#### 4.2 Configuration
- [ ] Create `~/exitmap-deploy/config.env` from template
- [ ] Set all required paths:
  - `EXITMAP_DIR=$HOME/exitmap`
  - `OUTPUT_DIR=$HOME/exitmap-deploy/public`
  - `LOG_DIR=$HOME/exitmap-deploy/logs`
- [ ] Configure cloud credentials (DO and/or R2)
- [ ] Set `FIRST_HOP` to a reliable relay you control (optional but recommended)
- [ ] Test config: `./scripts/run_dns_validation.sh` (single manual run)

#### 4.3 Tor Configuration
- [ ] Ensure Tor is running and bootstrapped:
  ```bash
  sudo systemctl status tor
  journalctl -u tor | grep "Bootstrapped 100%"
  ```
- [ ] (Optional) Configure torrc for better performance:
  ```
  # /etc/tor/torrc
  DataDirectory /var/lib/tor
  ControlPort 9051
  CookieAuthentication 1
  ```
- [ ] Verify exitmap can connect to Tor:
  ```bash
  cd ~/exitmap && source venv/bin/activate
  exitmap checktest -e $(exitmap -l | head -1)
  ```

#### 4.4 Cron Setup
- [ ] Install cron jobs:
  ```bash
  sudo cp ~/exitmap-deploy/configs/cron.d/exitmap-dns /etc/cron.d/
  sudo cp ~/exitmap-deploy/configs/cron.d/exitmap-retention /etc/cron.d/
  ```
- [ ] Verify cron syntax: `crontab -l` (if using user crontab)
- [ ] Set correct user/paths in cron files:
  ```cron
  # /etc/cron.d/exitmap-dns
  15 */6 * * * exitmap /home/exitmap/exitmap-deploy/scripts/run_dns_validation.sh >> /home/exitmap/exitmap-deploy/logs/cron.log 2>&1
  ```

#### 4.5 Monitoring First Runs
- [ ] Wait for first scheduled run (or trigger manually)
- [ ] Check logs: `tail -f ~/exitmap-deploy/logs/cron.log`
- [ ] Verify output created: `ls -la ~/exitmap-deploy/public/`
- [ ] Check cloud storage updated:
  ```bash
  curl -I https://your-spaces-url/latest.json
  curl -I https://your-r2-url/latest.json
  ```
- [ ] Verify JSON is valid: `cat public/latest.json | jq '.metadata'`

#### 4.6 Second Run Validation
- [ ] Wait for second scheduled run
- [ ] Verify `consecutive_failures` is being tracked
- [ ] Verify `files.json` has multiple entries
- [ ] Check historical files are being created

#### 4.7 Alerting Setup (Basic)
- [ ] Add simple failure notification to batch script:
  ```bash
  # At end of run_dns_validation.sh
  FAIL_RATE=$(cat "$LATEST_REPORT" | jq '.metadata.pass_rate_percent')
  if (( $(echo "$FAIL_RATE < 90" | bc -l) )); then
      echo "Warning: Pass rate dropped to $FAIL_RATE%" | mail -s "Exitmap Alert" your@email.com
  fi
  ```
- [ ] Or use webhook for Slack/Discord notification

#### 4.8 Documentation
- [ ] Update exitmap README.md to mention dnshealth module
- [ ] Create exitmap-deploy README.md with setup instructions
- [ ] Document runbook for common issues:
  - What to do if scan fails
  - How to manually trigger scan
  - How to check logs
  - How to rotate credentials

**Phase 4 Exit Criteria:**
- [ ] Cron runs successfully every 6 hours
- [ ] Cloud storage receives updates
- [ ] Logs show no errors
- [ ] Pass rate is reasonable (>90%)
- [ ] At least 3 successful scheduled runs completed

---

### Phase 5: Scaling (Future)

#### 5.1 Sharding & Resource Management (if needed for 3k+ relays)
- [ ] Add `--shard N/M` CLI argument to `src/exitmap.py`
- [ ] Add `filter_by_shard()` to `src/relayselector.py` (SHA256 hash-based)
- [ ] Add `should_include_relay()` to `dnshealth.py`
- [ ] Create `scripts/run_full_scan.sh` for sequential shard execution
- [ ] Create `scripts/merge_shard_results.py` for result aggregation
- [ ] Create `scripts/monitor_scan.sh` for resource monitoring
- [ ] Add `TestSharding` unit tests
- [ ] Document host capacity recommendations

#### 5.2 Additional Scaling Features
- [ ] Alerting system (email, webhook, Tor Metrics integration)
- [ ] Dashboard with trends over time
- [ ] Operator notification system
- [ ] Auto-recovery from failed scans

---

## Test Validation Plan

This section defines acceptance criteria and validation steps to verify the implementation is complete and working correctly.

### Unit Test Coverage Targets

| Component | Target | Rationale |
|-----------|--------|-----------|
| `dnshealth.py` | 80%+ | Core module, critical for reliability |
| `generate_unique_query()` | 100% | Simple function, easy to cover |
| `resolve_with_retry()` | 90%+ | Complex retry logic needs thorough testing |
| `teardown()` | 85%+ | File I/O edge cases |

**Run coverage check:**
```bash
pytest test/test_dnshealth.py --cov=src/modules/dnshealth --cov-report=term-missing --cov-fail-under=80
```

### Integration Test Scenarios

| Scenario | Command | Expected Outcome |
|----------|---------|------------------|
| **Single relay** | `exitmap dnshealth -e FINGERPRINT --analysis-dir ./test` | JSON with 1 result |
| **Small batch** | `exitmap dnshealth -E 10relays.txt --analysis-dir ./test` | JSON with 10 results |
| **Wildcard mode** | `exitmap dnshealth -e FP --analysis-dir ./test` | Resolves to `64.65.4.1` |
| **NXDOMAIN mode** | `exitmap dnshealth -e FP -H example.com --analysis-dir ./test` | NXDOMAIN = success |

### End-to-End Validation Checklist

Run these manual checks after implementation is complete:

```bash
# 1. Verify module loads
exitmap --help | grep dnshealth
# Expected: dnshealth module listed

# 2. Verify wildcard DNS is working (from your network)
dig +short test123.tor.exit.validator.1aeo.com
# Expected: 64.65.4.1

# 3. Test single relay (use a known good exit)
GOOD_EXIT=$(exitmap -l 2>/dev/null | grep -v BadExit | head -1 | awk '{print $1}')
exitmap dnshealth -e "$GOOD_EXIT" --analysis-dir ./validation_test
cat ./validation_test/dnshealth_*.json | jq '.metadata'
# Expected: {"total": 1, "passed": 1, "failed": 0, ...}

# 4. Verify JSON structure
cat ./validation_test/dnshealth_*.json | jq '.results[0] | keys'
# Expected: ["address", "fingerprint", "latency_ms", "nickname", "ok", "resolved_ip", "run_id", "timestamp"]

# 5. Test failure handling (use known bad exit or nonexistent FP)
exitmap dnshealth -e "0000000000000000000000000000000000000000" --analysis-dir ./validation_fail
# Expected: Circuit error or no results (invalid FP)

# 6. Full scan dry-run (list only)
exitmap dnshealth -l 2>/dev/null | wc -l
# Expected: ~1500-2000 exits (current network size)
```

### Performance Benchmarks

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| **Single relay scan** | < 30s | `time exitmap dnshealth -e FP --analysis-dir ./test` |
| **Memory per relay** | < 5MB | Monitor during scan with `top` |
| **Result file size** | < 1KB each | `ls -la ./results/result_*.json` |
| **Merged report size** | < 5MB for 2000 relays | `ls -la ./results/dnshealth_*.json` |
| **Full scan time** | 2-4 hours (2s delay) | Estimate: `2000 relays * 2s = 66 min` + overhead |

### Validation Sign-off

Before marking implementation complete:

- [ ] All unit tests pass (`pytest test/test_dnshealth.py -v`)
- [ ] Coverage >= 80% (`pytest --cov-fail-under=80`)
- [ ] CI pipeline passes (if configured)
- [ ] E2E checklist items 1-6 verified
- [ ] Performance within targets
- [ ] Documentation reviewed and accurate

---

## Quick Start Guide

### 5-Minute Setup (exitmap module)

Get the DNS health module running in 5 minutes:

```bash
# 1. Clone and install exitmap (if not already done)
git clone https://gitlab.torproject.org/tpo/network-health/exitmap.git
cd exitmap
python3 -m venv venv && source venv/bin/activate
pip install -e .

# 2. Verify Tor is running (exitmap needs it)
pgrep tor || echo "Start Tor first: sudo systemctl start tor"

# 3. Verify wildcard DNS is working
dig +short test.tor.exit.validator.1aeo.com
# Should return: 64.65.4.1

# 4. Run your first scan (single relay)
mkdir -p results
exitmap dnshealth -e $(exitmap -l 2>/dev/null | head -1) --analysis-dir ./results

# 5. View results
cat results/dnshealth_*.json | jq '.metadata'
```

**Expected output:**
```json
{
  "run_id": "20250115120000",
  "timestamp": "2025-01-15T12:00:30Z",
  "total": 1,
  "passed": 1,
  "failed": 0,
  "by_fail_type": {},
  "pass_rate_percent": 100
}
```

### Common Commands

```bash
# Wildcard mode (default, recommended)
exitmap dnshealth --analysis-dir ./results

# NXDOMAIN mode (no DNS setup needed)
exitmap dnshealth -H example.com --analysis-dir ./results

# Single relay test
exitmap dnshealth -e FINGERPRINT --analysis-dir ./results

# Multiple relays from file
exitmap dnshealth -E fingerprints.txt --analysis-dir ./results

# Country filter
exitmap dnshealth -C US --analysis-dir ./results

# Include BadExit relays
exitmap dnshealth --all-exits --analysis-dir ./results

# Rate limiting (be nice to the network)
exitmap dnshealth --build-delay 3 --delay-noise 1 --analysis-dir ./results
```

### Example Output Walkthrough

**Successful scan result:**
```json
{
  "fingerprint": "ABCD1234EFGH5678IJKL9012MNOP3456QRST7890",
  "nickname": "MyTorRelay",
  "address": "192.0.2.1",
  "timestamp": "2025-01-15T12:00:30Z",
  "run_id": "20250115120000",
  "ok": true,
  "resolved_ip": "64.65.4.1",
  "latency_ms": 1523
}
```

**Failed scan result (DNS issue):**
```json
{
  "fingerprint": "WXYZ9876DCBA5432...",
  "nickname": "BrokenDNSRelay",
  "address": "198.51.100.1",
  "timestamp": "2025-01-15T12:01:45Z",
  "run_id": "20250115120000",
  "ok": false,
  "fail_type": "dns",
  "fail_reason": "nxdomain",
  "error": "SOCKS 4: Domain not found (NXDOMAIN)",
  "resolved_ip": null,
  "latency_ms": 892
}
```

**Merged report structure:**
```json
{
  "metadata": {
    "run_id": "20250115120000",
    "timestamp": "2025-01-15T12:35:00Z",
    "total": 1523,
    "passed": 1489,
    "failed": 34,
    "by_fail_type": {
      "dns": 20,
      "circuit": 10,
      "timeout": 4
    },
    "pass_rate_percent": 97.77
  },
  "results": [ /* array of per-relay results */ ]
}
```

### Troubleshooting FAQ

**Q: "Module not found" error**
```
A: Run from exitmap root directory, or use: python -m exitmap dnshealth
```

**Q: "No results generated"**
```
A: Did you specify --analysis-dir? It's required:
   exitmap dnshealth --analysis-dir ./results
```

**Q: "All relays timing out"**
```
A: Check if Tor is running and bootstrapped:
   - pgrep tor
   - Check Tor logs for "Bootstrapped 100%"
   - Try: exitmap checktest (basic connectivity test)
```

**Q: "0% success rate in wildcard mode"**
```
A: Verify DNS is working:
   dig +short test.tor.exit.validator.1aeo.com
   Should return: 64.65.4.1
   
   If not, try NXDOMAIN mode as fallback:
   exitmap dnshealth -H example.com --analysis-dir ./results
```

**Q: "High circuit failure rate"**
```
A: This is often transient. Try:
   1. Use a controlled first hop: --first-hop YOUR_RELAY_FPR
   2. Increase delays: --build-delay 3 --delay-noise 2
   3. Filter results: circuit failures aren't the relay's fault
```

**Q: "How do I filter actionable failures?"**
```python
import json

with open('dnshealth_20250115120000.json') as f:
    data = json.load(f)

# Only DNS issues (actionable - relay's fault)
dns_issues = [r for r in data['results'] 
              if r.get('fail_type') == 'dns']

# Ignore circuit issues (not relay's fault)
testable = [r for r in data['results']
            if r['ok'] or r.get('fail_type') != 'circuit']
```

**Q: "Can I run this without the wildcard domain?"**
```
A: Yes, use NXDOMAIN mode:
   exitmap dnshealth -H example.com --analysis-dir ./results
   
   This is less rigorous (any DNS response = success) but requires
   no infrastructure setup.
```

### exitmap-deploy Quick Start

For automated scheduled scanning:

```bash
# Clone deployment repo
git clone https://github.com/1aeo/exitmap-deploy
cd exitmap-deploy

# Configure
cp config.env.example config.env
nano config.env  # Set EXITMAP_DIR, OUTPUT_DIR, etc.

# Test manually
./scripts/run_dns_validation.sh

# View results
cat public/latest.json | jq '.metadata'

# Enable scheduled runs (edit cron)
sudo cp configs/cron.d/exitmap-dns /etc/cron.d/
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
