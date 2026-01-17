# DNS Health Validation - Deployment

This directory contains deployment infrastructure for automated DNS health validation of Tor exit relays.

## Directory Structure

```
deploy/
├── README.md                     # This file
├── config.env.example            # Configuration template
├── configs/
│   └── cron.d/
│       └── exitmap-dns           # System cron.d template
└── scripts/
    ├── install.sh                # Setup script (venv, dependencies)
    ├── run_dns_validation.sh     # Main runner (single/cross-validate/split)
    ├── manage_cron.sh            # Crontab management
    ├── aggregate_results.py      # Aggregate results into report
    ├── get_exit_fingerprints.py  # Extract relay fingerprints (for split mode)
    ├── quick_analysis.py         # Quick analysis and comparison tool
    ├── upload_do.sh              # DigitalOcean Spaces upload
    └── upload_r2.sh              # Cloudflare R2 upload
```

## Quick Start

```bash
# 1. Install dependencies
./deploy/scripts/install.sh

# 2. Configure (optional)
cp deploy/config.env.example deploy/config.env
nano deploy/config.env

# 3. Run a scan
./deploy/scripts/run_dns_validation.sh

# 4. View results
cat results/latest.json | python3 -m json.tool
```

## Scan Modes

The scanner supports three modes for different use cases:

### Single Mode (Default)
One instance scans all exit relays sequentially.
```bash
./deploy/scripts/run_dns_validation.sh
```

### Cross-Validation Mode (`-c N`)
N instances scan ALL relays in parallel. A relay passes if it succeeds in ANY instance.
Best for accuracy - recovers transient timeouts/failures.
```bash
./deploy/scripts/run_dns_validation.sh -c 2    # 2 instances
./deploy/scripts/run_dns_validation.sh -c 3    # 3 instances
```

### Split Mode (`-s N`)
Divides relays among N instances for parallel scanning. Each instance scans ~1/N of relays.
Best for speed when you need full coverage quickly.
```bash
./deploy/scripts/run_dns_validation.sh -s 2    # 2 instances
./deploy/scripts/run_dns_validation.sh -s 4    # 4 instances
```

### Mode Comparison

| Mode | Relays Tested | Success Rate | Timeout | Duration | Use Case |
|------|---------------|--------------|---------|----------|----------|
| Single | ~2,600 | ~96% | ~56 | ~6 min | Basic validation |
| Cross-validate (2) | ~3,000 | **~98%** | **~16** | ~7.5 min | Accuracy (reduces false failures) |
| Split (2) | ~2,550 | ~98% | ~19 | **~6.7 min** | Speed (parallel coverage) |

**Recommendation:** Use `-c 2` (cross-validation with 2 instances) for production to maximize accuracy.

## Optimal Settings (Based on Experiments)

The following settings were determined through extensive testing:

| Setting | Value | Notes |
|---------|-------|-------|
| QUERY_TIMEOUT | 45s | Per-query timeout |
| MAX_PENDING_CIRCUITS | 128 | Concurrent circuits |
| MAX_RETRIES | 3 | Retries per relay |
| BOOTSTRAP_TIMEOUT | 90s | Auto-restart if exceeded |

Expected results with cross-validation: ~98% success rate, ~40-50 true failures

## Scripts

### run_dns_validation.sh (Main Runner)
The primary script for running scans. Features:
- **Multiple modes**: single, cross-validation, split
- **Auto-restart** on Tor bootstrap failure (up to 3 attempts)
- **Progress monitoring** with stall detection
- **Result aggregation** with cross-validation semantics
- **Cloud uploads** (if configured)
- **Automatic cleanup** of old results

```bash
# Basic usage
./deploy/scripts/run_dns_validation.sh

# Cross-validation for accuracy
./deploy/scripts/run_dns_validation.sh -c 2

# Split for speed
./deploy/scripts/run_dns_validation.sh -s 4

# Show help
./deploy/scripts/run_dns_validation.sh --help
```

### manage_cron.sh (Cron Management)
Convenient crontab management:
```bash
# Check current status
./deploy/scripts/manage_cron.sh status

# Install cron job (uses CRON_SCHEDULE from config.env)
./deploy/scripts/manage_cron.sh install

# Remove cron job
./deploy/scripts/manage_cron.sh remove
```

### quick_analysis.py (Analysis Tool)
Quick analysis and comparison of scan results:
```bash
# Analyze a single run
./deploy/scripts/quick_analysis.py results/analysis_2024-01-15/

# Compare multiple runs
./deploy/scripts/quick_analysis.py results/ --compare

# Show failure details
./deploy/scripts/quick_analysis.py results/analysis_2024-01-15/ --failures

# Output as JSON
./deploy/scripts/quick_analysis.py results/analysis_2024-01-15/ --json
```

## Configuration

Copy `config.env.example` to `config.env` and customize:

### DNS Validation Settings
By default, the scanner uses `tor.exit.validator.1aeo.com` for wildcard DNS validation.
To use your own infrastructure:

```bash
# In config.env:
DNS_WILDCARD_DOMAIN=your.wildcard.domain.com
DNS_EXPECTED_IP=1.2.3.4
```

Your domain must be configured as a wildcard DNS record where `*.domain` resolves to `DNS_EXPECTED_IP`.

Optional timing overrides:
- `DNS_QUERY_TIMEOUT` - Seconds per DNS query (default: 45)
- `DNS_MAX_RETRIES` - Retry attempts per relay (default: 3)
- `DNS_HARD_TIMEOUT` - Max seconds per probe (default: 180)

### Scan Settings
- `BUILD_DELAY` - Seconds between circuit builds (default: 0)
- `DELAY_NOISE` - Random variance added to delay (default: 0)
- `FIRST_HOP` - Your relay fingerprint for first hop (optional)
- `ALL_EXITS` - Include BadExit relays (default: true)

### Retry Settings
- `BOOTSTRAP_TIMEOUT` - Seconds to wait for Tor bootstrap (default: 90)
- `MAX_BOOTSTRAP_RETRIES` - Retry attempts on failure (default: 3)
- `PROGRESS_CHECK_INTERVAL` - Seconds between progress checks (default: 10)
- `CRON_SCHEDULE` - Cron schedule expression (default: "0 */6 * * *")

### Cloud Storage (optional)
- DigitalOcean Spaces: Set `DO_ENABLED=true` and credentials
- Cloudflare R2: Set `R2_ENABLED=true` and credentials

## Scheduled Runs

### Option 1: manage_cron.sh (Recommended)
```bash
# Edit schedule in config.env first
echo 'CRON_SCHEDULE="0 */4 * * *"' >> deploy/config.env

# Install with cross-validation mode
./deploy/scripts/manage_cron.sh install
```

### Option 2: System cron.d
```bash
sudo cp deploy/configs/cron.d/exitmap-dns /etc/cron.d/
sudo nano /etc/cron.d/exitmap-dns  # Edit paths and add -c 2 for cross-validation
```

## Cross-Validation Details

When using cross-validation mode (`-c N`), the aggregation logic is:

1. Each of N instances scans ALL exit relays independently
2. Results are merged by fingerprint
3. **Best result wins**: If a relay succeeds in ANY instance, it's marked as success
4. This recovers transient failures (timeouts, network errors)

The report includes cross-validation metadata:
```json
{
  "metadata": {
    "cross_validation": {
      "enabled": true,
      "instances": 2,
      "relays_improved": 133
    }
  }
}
```

## Logs

- `logs/dns_validation_*.log` - Main runner logs
- `logs/exitmap_*.log` - Individual exitmap instance logs
- `logs/exitmap_*_cv*.log` - Cross-validation instance logs
- `logs/exitmap_*_split*.log` - Split mode instance logs
