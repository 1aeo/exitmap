# First-Hop Filtering A/B Experiment Results

**Date:** March 5, 2026
**Environment:** Cloud VM, Tor 0.4.8.10, exitmap main branch
**Target:** 106 Austria (AT) exit relays, `checktest` module
**Method:** 3 runs per configuration, fresh Tor bootstrap each run

## Configuration

| Config | First-hop pool | Pool size | Selection |
|--------|---------------|-----------|-----------|
| **Baseline** | All consensus relays | 9,740 | Random |
| **Filtered** | GUARD+STABLE+FAST+RUNNING+VALID, ≥5MB/s measured BW | 5,056 | Random from filtered pool |

## Results

### Baseline (random first hops — current upstream default)

| Run | Total | Failed | Rate |
|-----|-------|--------|------|
| 1 | 106 | 7 | 6.60% |
| 2 | 106 | 6 | 5.66% |
| 3 | 106 | 2 | 1.89% |
| **Total** | **318** | **15** | **4.72%** |

### Filtered (quality guards only)

| Run | Total | Failed | Rate |
|-----|-------|--------|------|
| 1 | 106 | 0 | 0.00% |
| 2 | 106 | 3 | 2.83% |
| 3 | 106 | 2 | 1.89% |
| **Total** | **318** | **5** | **1.57%** |

## Summary

| Metric | Baseline | Filtered | Change |
|--------|----------|----------|--------|
| Avg failure rate | 4.72% | 1.57% | **-67%** |
| Total failures | 15 | 5 | **-67%** |
| Best run | 1.89% | 0.00% | Perfect scan achieved |
| Worst run | 6.60% | 2.83% | -57% |

## Notes

- Filtering reduces the first-hop pool from ~9,740 to ~5,056 relays (still large enough for good anonymity)
- The filtered pool requires relays to have GUARD, STABLE, FAST, RUNNING, and VALID flags, plus ≥5MB/s authority-measured bandwidth
- Scan duration was nearly identical (~5:30 per run) — filtering does not slow down scans
- The remaining failures in filtered runs are likely exit-side issues (the exit relay itself is unreachable), not first-hop quality
