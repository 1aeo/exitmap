#!/bin/bash
# First-Hop Filtering A/B Experiment
# Compares circuit failure rates: random first hops vs filtered guards
#
# Uses checktest module (minimal - just builds circuits)
# Runs each config 3 times, parses logs for failure rates

set -euo pipefail

EXITMAP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
EXP_DIR="/tmp/exitmap-experiment"
mkdir -p "$EXP_DIR/baseline" "$EXP_DIR/filtered" "$EXP_DIR/logs"

cd "$EXITMAP_DIR"

# Use a small country to keep scans bounded (~3-5 min each)
# AT (Austria) typically has 30-60 exits
COUNTRY="AT"
TIMEOUT=300  # 5 min max per scan

run_scan() {
    local label="$1"   # baseline or filtered
    local run="$2"     # run number
    local env_vars="$3" # extra env vars
    
    local logfile="$EXP_DIR/logs/${label}_run${run}.log"
    local analysis_dir="$EXP_DIR/${label}/run${run}"
    mkdir -p "$analysis_dir"
    
    echo "=== $label run $run ==="
    echo "  Log: $logfile"
    
    # Clean tor data dir to force fresh bootstrap each time
    rm -rf /tmp/exitmap_tor_datadir-ubuntu
    
    # Run exitmap
    env $env_vars timeout "$TIMEOUT" python3 bin/exitmap \
        -C "$COUNTRY" \
        -v info \
        -o "$logfile" \
        -a "$analysis_dir" \
        checktest 2>&1 | tail -5 || true
    
    # Parse results from log
    local total=$(grep -c "Circuit.*could not be created\|Circuit.*is built\|failed_circuits\|successful_circuits" "$logfile" 2>/dev/null || echo "0")
    local stats_line=$(grep "Ran.*module.*circuits failed" "$logfile" 2>/dev/null | tail -1)
    
    echo "  Stats: $stats_line"
    echo "$stats_line" > "$EXP_DIR/${label}/run${run}_stats.txt"
    echo ""
}

echo "========================================"
echo "First-Hop Filtering A/B Experiment"
echo "Country: $COUNTRY"
echo "Timeout: ${TIMEOUT}s per scan"
echo "========================================"
echo ""

# --- BASELINE: Random first hops (upstream default) ---
echo "*** BASELINE: Random first hops ***"
echo ""
for run in 1 2 3; do
    run_scan "baseline" "$run" "RELIABLE_FIRST_HOP=false"
done

# --- FILTERED: GUARD+STABLE+FAST, ≥5MB/s ---
echo "*** FILTERED: GUARD+STABLE+FAST ≥5MB/s first hops ***"
echo ""
for run in 1 2 3; do
    run_scan "filtered" "$run" "RELIABLE_FIRST_HOP=true"
done

# --- SUMMARY ---
echo "========================================"
echo "RESULTS SUMMARY"
echo "========================================"
echo ""
echo "BASELINE (random first hops):"
for f in "$EXP_DIR/baseline"/run*_stats.txt; do
    echo "  $(basename $f): $(cat $f)"
done
echo ""
echo "FILTERED (GUARD+STABLE+FAST ≥5MB/s):"
for f in "$EXP_DIR/filtered"/run*_stats.txt; do
    echo "  $(basename $f): $(cat $f)"
done
echo ""
echo "Full logs in: $EXP_DIR/logs/"
