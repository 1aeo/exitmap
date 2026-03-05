# Remove deprecated APIs, resolve FIXME, and fix naming

## Description

Seven small cleanups to remove deprecated API usage, resolve an in-code FIXME, and fix naming/mode issues in modules.

### 1. Replace DescriptorReader with stem.descriptor.parse_file()

`relay_in_consensus()` uses `DescriptorReader`, which internally calls the deprecated `setDaemon()` method (deprecated since Python 3.10). This produces `DeprecationWarning` on every test run. `stem.descriptor.parse_file()` is simpler and avoids the deprecated call.

### 2. Remove Python 2 urllib2 compatibility shim

The `try: import urllib2 except ImportError: import urllib.request as urllib2` in `util.py` is left over from the Python 2 era. Python 2 support was removed in 9704ff4 but this file was missed.

### 3. Remove time.monotonic fallback and FIXME in rtt module

The comment reads: `# FIXME: Maybe use ctypes to get at clock_gettime(CLOCK_MONOTONIC)?`

`time.monotonic` has been available since Python 3.3. The try/except fallback and FIXME are no longer needed.

### 4. Replace deprecated dns.resolver.query() with resolve()

`dns.resolver.query()` was deprecated in dnspython 2.0 (2020) and emits `DeprecationWarning`. `dns.resolver.resolve()` is a drop-in replacement.

### 5. Rename sha512_file to sha256_file in patchingCheck module

The function is named `sha512_file` but uses `hashlib.sha256()`. The name has been wrong since the function was first written. Renamed to match the actual algorithm. No behavioral change.

### 6. Open files in binary mode in files_identical()

`files_identical()` in patchingCheck reads binary files (executables written with `"wb"`) using text-mode `open()`. Fixed by using `"rb"` mode.

### 7. Optimize first hop selection with rejection sampling

`iter_exit_relays()` creates a full copy of the fingerprints list for every exit relay and calls `.remove()` on it — O(n) per relay, O(n*m) total. With ~2000 exits and ~7000 fingerprints this is significant.

Replaced with rejection sampling: pick a random fingerprint, retry if it matches the exit relay. Expected O(1) per relay since collision probability is ~1/7000.

## Testing

All existing tests pass (27 passed). flake8 clean. DescriptorReader DeprecationWarnings eliminated.
