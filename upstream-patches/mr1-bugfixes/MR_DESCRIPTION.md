# MR Title: Fix three bugs: race condition, regex warning, and memory leak

## Description

Three bug fixes for issues we encountered running exitmap in production scanning ~1,500 exit relays:

### 1. Fix SyntaxWarning for invalid escape sequence in regex (`util.py`)

Python 3.12+ raises `SyntaxWarning` for unescaped `\.` in a non-raw string regex pattern. Fixed by using a raw string (`r"..."`).

### 2. Fix race condition in `Attacher.prepare()` (`eventhandler.py`)

`prepare()` is called concurrently from two threads:
- The `queue_reader` thread (when a module signals a stream is ready)
- The main event thread via `new_stream` (when Tor sends stream events)

The shared `self.unattached` dictionary had no thread protection, causing a check-then-delete race condition: both threads could enter the `if port in self.unattached` block and then both try to `del self.unattached[port]`, raising `KeyError`.

**Fix:** Add `threading.Lock()` and replace the check-then-delete pattern with atomic `dict.pop(port, None)`.

This fixes a rare crash in production where scans would terminate early (~800 relays probed instead of ~3000).

### 3. Fix memory leak from `Manager().Queue()` (`eventhandler.py`, `exitmap.py`)

`multiprocessing.Manager().Queue()` spawns a background Manager subprocess that is never explicitly shut down, leaking a process and its resources on every scan.

**Fix:** Replace with plain `multiprocessing.Queue()`, which requires no background process.

This also required restructuring how scan completion is handled:
- **Before:** `check_finished()` called `sys.exit(0)` from a background thread, which could bypass cleanup.
- **After:** `check_finished()` signals a `threading.Event`, and the main thread calls `handler.wait()` then `handler.shutdown()` for orderly cleanup.

The new `shutdown()` method terminates straggling child processes, calls the module's `teardown()`, signals the queue reader to stop, and removes the event listener. In `exitmap.py`, `controller.close()` is now called in a `finally` block to ensure the Tor controller is always cleaned up.

## Testing

All existing tests pass (`27 passed`). flake8 clean.

## Checklist

- [x] All commits authored correctly
- [x] Lazy-eval logging style used throughout (matches upstream convention)
- [x] No new dependencies
- [x] Backward compatible — no API changes
- [x] Tests pass, flake8 clean
