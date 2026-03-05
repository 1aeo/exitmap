# Upstream Submission Patches

Patch files for submitting to `gitlab.torproject.org/tpo/network-health/exitmap`.

All patches are based on upstream `main` at commit `b3bedb8` (juga's "Replace % operator in logging by lazy evaluation", Jan 28 2026).

## Branch

| Branch | Base | Commits | Status |
|--------|------|---------|--------|
| `upstream/mr1-bugfixes` | upstream `main` (`b3bedb8`) | 3 | Ready |

## How to Apply

```bash
# Clone your GitLab fork of exitmap
git clone git@gitlab.torproject.org:YOUR_USER/exitmap.git
cd exitmap
git remote add upstream https://gitlab.torproject.org/tpo/network-health/exitmap.git
git fetch upstream

# Create MR branch from upstream main
git checkout -b bugfix/race-condition-memleak-regex upstream/main

# Apply patches
git am mr1-bugfixes/0*.patch

# Push to your fork
git push origin bugfix/race-condition-memleak-regex
```

Then open a Merge Request on GitLab targeting `main`.

## MR 1: Bug Fixes (`mr1-bugfixes/`)

Three standalone bug fixes for issues found in production. See `mr1-bugfixes/MR_DESCRIPTION.md`.

| # | Patch | File(s) | Lines |
|---|-------|---------|-------|
| 1 | Fix SyntaxWarning regex | `src/util.py` | +1/-1 |
| 2 | Fix race condition in Attacher.prepare() | `src/eventhandler.py` | +30/-26 |
| 3 | Fix memory leak: Manager().Queue() | `src/eventhandler.py`, `src/exitmap.py` | +93/-41 |
