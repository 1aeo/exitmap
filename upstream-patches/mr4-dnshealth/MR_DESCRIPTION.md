# MR Title: Add dnshealth module: wildcard DNS health validation for exit relays

**Depends on:** MR 1 (bug fixes), MR 2 (relay selection), MR 3 (circuit tracking)

## Description

A new scanning module that detects broken DNS resolution on Tor exit relays using a wildcard DNS technique.

### Why a new module instead of modifying `dnsresolution`?

The existing `dnsresolution` module queries fixed domains (`www.example.com`, `www.torproject.org`). This has two limitations:

1. **Caching**: When scanning thousands of relays, DNS caches (at the relay's resolver or upstream) mean most relays return cached results rather than performing actual resolution. You can't distinguish "relay's DNS works" from "relay's resolver cache has this entry."

2. **No per-relay granularity**: All relays query the same domains, so you can't attribute failures to specific relays vs. transient network issues.

The `dnshealth` module solves both by generating **unique-per-relay DNS queries** against a wildcard DNS record:

```
{uuid}.{fingerprint_prefix}.{wildcard_domain}
```

Since every query is unique, it cannot be cached. The wildcard DNS record resolves `*.domain` to a known IP, so we can verify each relay independently.

### Features

- **Wildcard mode** (default): Query unique subdomain, verify expected IP returned
- **NXDOMAIN mode** (fallback via `-H`): Query random UUID subdomain of a real domain, treat NXDOMAIN as success (proves DNS is working)
- Configurable retry logic with per-attempt timeouts
- Hard timeout protection via SIGALRM
- Structured JSON output per relay for automated analysis
- Circuit failure and terminated relay tracking via `teardown()` callback
- All settings configurable via environment variables

### Configuration

The wildcard domain **must** be configured for your deployment:

```bash
export DNS_WILDCARD_DOMAIN="your.wildcard.domain.com"
export DNS_EXPECTED_IP="1.2.3.4"
```

The domain should have a wildcard DNS record: `*.your.wildcard.domain.com → 1.2.3.4`

### Usage

```bash
# Wildcard mode (requires wildcard DNS infrastructure)
exitmap dnshealth

# NXDOMAIN fallback mode (no infrastructure needed)
exitmap dnshealth -H example.com
```

### Output

Per-relay JSON files in the analysis directory with fields:
- `exit_fingerprint`, `exit_nickname`, `exit_address`
- `status`: success, dns_fail, wrong_ip, timeout, hard_timeout, etc.
- `resolved_ip`, `expected_ip`, `query_domain`
- `timing.total_ms`
- `error` (structured error message if failed)
- `first_hop` (fingerprint of the guard relay used)

### Production Experience

We have been using this module in production to monitor ~1,500 exit relays daily. The wildcard approach reliably identifies relays with broken DNS resolution, with false positive rates well under 1% across multiple scan runs.

## Files

| File | Lines | Description |
|------|-------|-------------|
| `src/modules/dnshealth.py` | 532 | DNS health validation module |
| `test/test_dnshealth.py` | 820 | 60 unit tests |
| `doc/HACKING.md` | +15 | Document `first_hop` and `teardown()` kwargs |

## Testing

87 total tests pass (27 existing + 60 new). flake8 clean.

Tests cover:
- Unique query generation
- Result structure creation
- SOCKS error parsing and classification
- Wildcard vs. NXDOMAIN mode detection
- Retry logic and timeout handling
- Hard timeout (SIGALRM) behavior
- Environment variable configuration
- Teardown with circuit failures and terminated relays

## Checklist

- [x] GPLv3 license header
- [x] Lazy-eval logging style
- [x] Sphinx-style docstrings
- [x] flake8 clean
- [x] 60 unit tests
- [x] Backward compatible (new module, no changes to existing modules)
- [x] `destinations = None` (probes all exit relays)
- [x] `doc/HACKING.md` updated

## Discussion Points

1. **Default wildcard domain**: Currently defaults to `tor.exit.validator.1aeo.com`. Should this be removed (requiring explicit configuration), or should the Tor Project set up its own wildcard domain?

2. **NXDOMAIN fallback**: The `-H` flag enables a mode that doesn't require wildcard infrastructure. This could be useful for quick checks without deploying a DNS record.
