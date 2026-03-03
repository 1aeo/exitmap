# Upstream Submission Patches

Patch files for submitting to `gitlab.torproject.org/tpo/network-health/exitmap`.

## How to Apply

These patches are based on upstream `main` at commit `b3bedb8` (juga's "Replace % operator in logging by lazy evaluation", Jan 28 2026).

```bash
# Clone your GitLab fork of exitmap
git clone git@gitlab.torproject.org:YOUR_USER/exitmap.git
cd exitmap
git remote add upstream https://gitlab.torproject.org/tpo/network-health/exitmap.git
git fetch upstream

# Create MR branch from upstream main
git checkout -b bugfix/race-condition-memleak-regex upstream/main

# Apply patches
git am mr1-bugfixes/*.patch

# Push to your fork
git push origin bugfix/race-condition-memleak-regex
```

Then open a Merge Request on GitLab targeting `main`.

## MR 1: Bug Fixes (`mr1-bugfixes/`)

Three standalone bug fixes for issues found in production:

### Patch 1: Fix SyntaxWarning for invalid escape sequence in regex
- **File:** `src/util.py` (1 line)
- **Issue:** Python 3.12+ raises `SyntaxWarning` for `\.` in non-raw string
- **Fix:** Use raw string `r"..."` for regex pattern

### Patch 2: Fix race condition in Attacher.prepare() causing KeyError crash
- **File:** `src/eventhandler.py` (~30 lines)
- **Issue:** `prepare()` is called from two threads (queue_reader + event thread) with no synchronization. Both can enter `if port in self.unattached`, then both try `del self.unattached[port]`, causing KeyError.
- **Fix:** Add `threading.Lock()` and use atomic `dict.pop()` instead of check-then-delete.
- **Impact:** Fixes rare production crash where scans terminate early (~800/3000 relays).

### Patch 3: Fix memory leak — replace Manager().Queue() with multiprocessing.Queue
- **Files:** `src/eventhandler.py`, `src/exitmap.py` (~90 lines)
- **Issue:** `multiprocessing.Manager().Queue()` spawns a background Manager subprocess that is never shut down, leaking resources.
- **Fix:**
  - Replace with plain `multiprocessing.Queue()`
  - Add sentinel shutdown pattern for queue reader thread
  - Replace `sys.exit()` in `check_finished()` with `threading.Event` signaling
  - Add `wait()` / `shutdown()` lifecycle methods to EventHandler
  - Add `controller.close()` in `finally` block in `exitmap.py`
- **Why the restructure:** The `sys.exit()` calls in `check_finished()` could terminate from a background thread, bypassing cleanup. The new approach signals completion via Event and lets the main thread orchestrate orderly shutdown.
