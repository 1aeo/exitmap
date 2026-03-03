# Upstream Submission Patches

Patch files for submitting to `gitlab.torproject.org/tpo/network-health/exitmap`.

All patches are based on upstream `main` at commit `b3bedb8` (juga's "Replace % operator in logging by lazy evaluation", Jan 28 2026). The MRs are stacked: each depends on the ones before it.

## Branches

| Branch | Base | Commits | Status |
|--------|------|---------|--------|
| `upstream/mr1-bugfixes` | upstream `main` | 3 | Ready |
| `upstream/mr2-relay-selection` | MR1 | 1 | Ready |
| `upstream/mr3-circuit-tracking` | MR2 | 1 | Ready |
| `upstream/mr4-dnshealth` | MR3 | 1 | Ready |

## How to Apply

```bash
# Clone your GitLab fork of exitmap
git clone git@gitlab.torproject.org:YOUR_USER/exitmap.git
cd exitmap
git remote add upstream https://gitlab.torproject.org/tpo/network-health/exitmap.git
git fetch upstream

# MR 1: Bug fixes
git checkout -b bugfix/race-condition-memleak-regex upstream/main
git am mr1-bugfixes/0*.patch
git push origin bugfix/race-condition-memleak-regex

# MR 2: Relay selection (on top of MR 1)
git checkout -b feature/relay-selection-filtering
git am mr2-relay-selection/0*.patch
git push origin feature/relay-selection-filtering

# MR 3: Circuit tracking (on top of MR 2)
git checkout -b feature/circuit-failure-tracking
git am mr3-circuit-tracking/0*.patch
git push origin feature/circuit-failure-tracking

# MR 4: DNS health module (on top of MR 3)
git checkout -b feature/dnshealth-module
git am mr4-dnshealth/0*.patch
git push origin feature/dnshealth-module
```

Then open 4 Merge Requests on GitLab, each targeting `main`.

---

## MR 1: Bug Fixes (`mr1-bugfixes/`)

Three standalone bug fixes for issues found in production. See `mr1-bugfixes/MR_DESCRIPTION.md`.

| Patch | File(s) | Lines |
|-------|---------|-------|
| Fix SyntaxWarning regex | `src/util.py` | +1/-1 |
| Fix race condition in Attacher.prepare() | `src/eventhandler.py` | +30/-26 |
| Fix memory leak: Manager().Queue() | `src/eventhandler.py`, `src/exitmap.py` | +93/-41 |

## MR 2: Relay Selection (`mr2-relay-selection/`)

Extends `get_fingerprints()` with optional filtering by flags, bandwidth, and country. See `mr2-relay-selection/MR_DESCRIPTION.md`.

| Patch | File(s) | Lines |
|-------|---------|-------|
| Add filtering options to get_fingerprints() | `src/relayselector.py` | +36/-7 |

## MR 3: Circuit Failure Tracking (`mr3-circuit-tracking/`)

Circuit registry, failure tracking, first_hop passing, grace period shutdown. See `mr3-circuit-tracking/MR_DESCRIPTION.md`.

| Patch | File(s) | Lines |
|-------|---------|-------|
| Track circuit failures with relay fingerprints | `src/stats.py`, `src/eventhandler.py`, `src/exitmap.py` | +224/-31 |

## MR 4: DNS Health Module (`mr4-dnshealth/`)

New `dnshealth` module with wildcard DNS validation + 60 tests. See `mr4-dnshealth/MR_DESCRIPTION.md`.

| Patch | File(s) | Lines |
|-------|---------|-------|
| Add dnshealth module | `src/modules/dnshealth.py`, `test/test_dnshealth.py`, `doc/HACKING.md` | +1364/-1 |
