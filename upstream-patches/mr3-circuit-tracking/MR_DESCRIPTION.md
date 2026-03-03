# MR Title: stats/eventhandler: Track circuit failures with relay fingerprints

**Depends on:** MR 1 (bug fixes), MR 2 (relay selection)

## Description

Adds infrastructure so scanning modules can know *which* exit relays had circuit failures and *why*. This is useful for any module that needs post-scan analysis of relay behavior, not just DNS health checking.

### Changes

**`src/stats.py`:**
- Add `CIRCUIT_FAILURE_MAP` translating Tor's circuit failure reasons (TIMEOUT, CONNECTFAILED, etc.) to structured JSON keys and human-readable messages
- Add circuit registry (`register_circuit`/`resolve_circuit`/`complete_circuit`) that maps circuit IDs to their intended first-hop and exit relay fingerprints
- `update_circs()` now records per-relay failure details using the registry
- Add `record_immediate_failure()` for circuits that fail before getting an ID
- Add `get_failed_circuit_relays()` to retrieve all failure details

**`src/eventhandler.py`:**
- Pass `first_hop` fingerprint through `module_call` to probing modules (new kwarg)
- Track `pid_to_fingerprint` mapping to associate child processes with relays
- Grace period in `shutdown()`: wait for straggling processes before forcibly terminating, collecting fingerprints of killed relays
- Enhanced `teardown()` callback: pass `stats`, `controller`, and `terminated_relays` to modules that accept keyword arguments (backward-compatible fallback)

**`src/exitmap.py`:**
- Use `stats.register_circuit()` when creating circuits
- Use `stats.record_immediate_failure()` for instant creation failures
- Rejection sampling for random first-hop selection (avoids O(n) list copy)

### Backward Compatibility

- Existing modules that don't use `first_hop` or `teardown()` kwargs are unaffected
- The `teardown()` call uses try/except to fall back to no-args for old modules
- `update_circs()` gracefully handles circuits not in the registry

### Example Usage (for module authors)

```python
def teardown(stats=None, controller=None, terminated_relays=None, **kwargs):
    """Called after all probes complete."""
    if stats:
        failed = stats.get_failed_circuit_relays()
        for fp, info in failed.items():
            print(f"Relay {fp}: {info['error']} (reason: {info['tor_reason']})")
    if terminated_relays:
        print(f"Terminated {len(terminated_relays)} stalled relays")
```

## Testing

All 27 existing tests pass. flake8 clean. The `test_stats.py` test exercises `update_circs()` with both FAILED and BUILT events.

## Checklist

- [x] Backward compatible with existing modules
- [x] Lazy-eval logging style
- [x] Sphinx-style docstrings
- [x] Tests pass, flake8 clean
- [x] No new dependencies
