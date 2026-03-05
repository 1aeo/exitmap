#!/bin/bash
# A/B test: random first hops vs filtered guards
set -euo pipefail

cd /workspace
RESULTS="/tmp/exitmap-experiment"
mkdir -p "$RESULTS"

run_scan() {
    local label="$1"
    local run="$2"
    local reliable="$3"
    local logfile="$RESULTS/${label}_run${run}.log"
    
    rm -rf /tmp/exitmap_tor_datadir-ubuntu
    
    echo "[$(date +%H:%M:%S)] $label run $run starting..."
    
    RELIABLE_FIRST_HOP="$reliable" python3 -c "
import sys
sys.path.insert(0, 'src')
from exitmap import main
sys.exit(main() or 0)
" -- -C AT -v info -o "$logfile" checktest 2>/dev/null || true
    
    local result=$(grep "Ran.*module" "$logfile" 2>/dev/null | tail -1)
    echo "[$(date +%H:%M:%S)] $label run $run: $result"
    echo "$result" >> "$RESULTS/summary.txt"
}

echo "========================================" | tee "$RESULTS/summary.txt"
echo "First-Hop Filtering A/B Test" | tee -a "$RESULTS/summary.txt"
echo "$(date)" | tee -a "$RESULTS/summary.txt"
echo "========================================" | tee -a "$RESULTS/summary.txt"
echo "" >> "$RESULTS/summary.txt"

echo "--- BASELINE (random first hops) ---" >> "$RESULTS/summary.txt"
for run in 1 2 3; do
    run_scan "baseline" "$run" "false"
done

echo "" >> "$RESULTS/summary.txt"
echo "--- FILTERED (GUARD+STABLE+FAST ≥5MB/s) ---" >> "$RESULTS/summary.txt"
for run in 1 2 3; do
    run_scan "filtered" "$run" "true"
done

echo ""
echo "========================================" 
echo "RESULTS"
echo "========================================"
cat "$RESULTS/summary.txt"
