# Fix resource leaks and relax parent directory check

## Description

Three fixes for resource management issues.

### 1. Relax parent directory permission check for /tmp

The security check added in #47 requires the parent directory of tor_dir to have mode 700 and be owned by the current user. But the default tor_dir is under `/tmp`, which is typically mode 1777. This prevents exitmap from starting on most Linux systems with the default configuration.

The fix keeps strict checks on the tor_dir itself (mode 700, owned by user, not a symlink) but relaxes the parent directory check to only verify it is not a symlink.

### 2. Fix file descriptor leak in dump_to_file()

`tempfile.mkstemp()` returns `(fd, file_name)` where `fd` is an open OS-level file descriptor. The code then opens the file again with `with open(file_name, "wb") as fd:`, shadowing the original fd without closing it. Each call leaks one file descriptor.

Fixed by adding `os.close(fd)` after `mkstemp()`.

### 3. Use context manager for reading exit relay file

`open(args.exit_file)` is not wrapped in a context manager, leaking the file handle. Fixed with `with open(...) as f:`.

## Testing

All existing tests pass (27 passed). flake8 clean.
