# Fix five Python 3 compatibility bugs

## Description

Five small bug fixes for Python 3 compatibility issues found by code review. Each is a one-line or two-line change fixing a crash or silent failure.

### 1. Fix TypeError writing to binary temp file in command.py

`NamedTemporaryFile` opens in binary mode by default. The string writes on lines 116-117 raise `TypeError: a bytes-like object is required, not 'str'` in Python 3. Fixed by encoding to bytes.

Triggers when a module calls `run_cmd_over_tor()`.

### 2. Fix TypeError in get_relay_desc() log formatting

`log.warning("Unable to query for %d: %s", fpr, err)` uses `%d` but `fpr` is a hex string fingerprint, not an integer. Raises `TypeError` on the `ControllerError` code path. Fixed by changing `%d` to `%s`.

### 3. Fix gzip decompression in cloudflared module

`io.StringIO(data)` fails because HTTP response data is bytes in Python 3. The `TypeError` is silently caught by the `except Exception: pass` clause, so `decompress()` returns raw compressed data and CAPTCHA detection never matches. Fixed by using `io.BytesIO`.

### 4. Fix ConfigParser.NoSectionError reference

`except ConfigParser.NoSectionError` raises `AttributeError` because Python 3's `ConfigParser` class does not have `NoSectionError` as a class attribute — it lives on the `configparser` module. Fixed by using `configparser.NoSectionError`.

Triggers when `~/.exitmaprc` exists but lacks a `[Defaults]` section.

### 5. Fix NameError in lookup_destinations()

If a module has no `destinations` attribute and `--host`/`--port` are not given, `raw_destinations` is never assigned. The subsequent `if raw_destinations is not None` raises `NameError`. Fixed by initializing `raw_destinations = None` before the conditional chain.

## Testing

All existing tests pass (27 passed). flake8 clean.

## Checklist

- [x] Each patch is a single focused fix
- [x] Lazy-eval logging style preserved (matches upstream convention)
- [x] No new dependencies
- [x] Backward compatible
- [x] Tests pass, flake8 clean
