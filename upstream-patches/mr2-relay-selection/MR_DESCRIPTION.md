# MR Title: relayselector: Add filtering options to get_fingerprints()

**Depends on:** MR 1 (bug fixes)

## Description

Extends `get_fingerprints()` in `relayselector.py` with optional keyword parameters for filtering relay selection. All new parameters default to `None`/`False`, maintaining full backward compatibility with existing callers.

### New parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `include_flags` | `set` | `stem.Flag` values the relay MUST have ALL of |
| `exclude_flags` | `set` | `stem.Flag` values the relay must have NONE of |
| `min_bandwidth_kb` | `int` | Minimum consensus bandwidth in KB/s |
| `require_measured_bw` | `bool` | Only include authority-measured bandwidth |
| `include_country` | `str` | 2-letter country code filter |

### Use case

This is useful for any scanning module that needs to select relays with specific characteristics. For example, selecting only high-bandwidth guards with the STABLE flag for use as reliable first hops in scanning circuits.

### Example

```python
from relayselector import get_fingerprints
import stem

# Get only high-bandwidth, stable guards
guards = get_fingerprints(
    consensus_path,
    include_flags={stem.Flag.GUARD, stem.Flag.STABLE, stem.Flag.FAST},
    exclude_flags={stem.Flag.BADEXIT},
    min_bandwidth_kb=5000,
    require_measured_bw=True,
)
```

## Testing

All existing relayselector tests pass. flake8 clean.

## Checklist

- [x] Backward compatible (all new params have defaults)
- [x] Sphinx-style docstring
- [x] Lazy-eval logging style
- [x] Tests pass, flake8 clean
