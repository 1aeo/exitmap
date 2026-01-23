#!/usr/bin/env python3
"""
Create histogram of failure counts per relay across all scan data.
"""

import json
import os
from collections import defaultdict, Counter
from datetime import datetime
import re

DATA_DIR = 'data'

def parse_timestamp_from_filename(filename):
    match = re.search(r'dns_health_(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})\.json', filename)
    if match:
        y, mo, d, h, mi, s = match.groups()
        return datetime(int(y), int(mo), int(d), int(h), int(mi), int(s))
    return None

def load_all_scans():
    scans = []
    for filename in os.listdir(DATA_DIR):
        if filename.startswith('dns_health_') and filename.endswith('.json'):
            filepath = os.path.join(DATA_DIR, filename)
            ts = parse_timestamp_from_filename(filename)
            if ts:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    scans.append({
                        'filename': filename,
                        'timestamp': ts,
                        'data': data
                    })
    scans.sort(key=lambda x: x['timestamp'])
    return scans

def count_failures_per_relay(scans):
    """Count total failures and tests per relay across all scans."""
    relay_stats = defaultdict(lambda: {
        'nickname': 'unknown',
        'total_tests': 0,
        'failures': 0,
        'successes': 0
    })
    
    for scan in scans:
        results = scan['data'].get('results', [])
        for result in results:
            fp = result.get('exit_fingerprint', 'unknown')
            nickname = result.get('exit_nickname', 'unknown')
            status = result.get('status', 'unknown')
            
            relay_stats[fp]['nickname'] = nickname
            relay_stats[fp]['total_tests'] += 1
            
            if status == 'success':
                relay_stats[fp]['successes'] += 1
            else:
                relay_stats[fp]['failures'] += 1
    
    return relay_stats

def create_histogram_data(relay_stats):
    """Create histogram buckets for failure counts."""
    failure_counts = [stats['failures'] for stats in relay_stats.values()]
    
    # Create buckets - breaking out 6-10 individually
    buckets = [
        (0, 0, "0 (no failures)"),
        (1, 1, "1"),
        (2, 2, "2"),
        (3, 3, "3"),
        (4, 4, "4"),
        (5, 5, "5"),
        (6, 6, "6"),
        (7, 7, "7"),
        (8, 8, "8"),
        (9, 9, "9"),
        (10, 10, "10"),
        (11, 15, "11-15"),
        (16, 20, "16-20"),
        (21, 25, "21-25"),
        (26, 30, "26-30"),
        (31, 35, "31-35"),
        (36, 40, "36-40"),
        (41, 50, "41-50"),
    ]
    
    histogram = []
    for min_val, max_val, label in buckets:
        count = sum(1 for f in failure_counts if min_val <= f <= max_val)
        if count > 0 or min_val <= 10:  # Always show low buckets
            histogram.append({
                'range': label,
                'min': min_val,
                'max': max_val,
                'count': count
            })
    
    return histogram, failure_counts

def print_ascii_histogram(histogram, max_width=60):
    """Print ASCII histogram."""
    max_count = max(h['count'] for h in histogram)
    
    print("\n" + "=" * 80)
    print("HISTOGRAM: Count of Relays by Number of Failures")
    print("=" * 80)
    print(f"\n{'Failures':<20} {'Count':>8}  Distribution")
    print("-" * 80)
    
    for h in histogram:
        bar_width = int((h['count'] / max_count) * max_width) if max_count > 0 else 0
        bar = "█" * bar_width
        print(f"{h['range']:<20} {h['count']:>8}  {bar}")
    
    print("-" * 80)

def print_table(histogram, relay_stats):
    """Print detailed table."""
    print("\n" + "=" * 80)
    print("TABLE: Relay Failure Distribution")
    print("=" * 80)
    
    total_relays = len(relay_stats)
    
    print(f"\n{'Failure Count':<20} {'Relays':>10} {'% of Total':>12} {'Cumulative %':>14}")
    print("-" * 60)
    
    cumulative = 0
    for h in histogram:
        cumulative += h['count']
        pct = (h['count'] / total_relays) * 100
        cum_pct = (cumulative / total_relays) * 100
        print(f"{h['range']:<20} {h['count']:>10} {pct:>11.2f}% {cum_pct:>13.2f}%")
    
    print("-" * 60)
    print(f"{'TOTAL':<20} {total_relays:>10}")

def print_summary_stats(failure_counts, relay_stats):
    """Print summary statistics."""
    print("\n" + "=" * 80)
    print("SUMMARY STATISTICS")
    print("=" * 80)
    
    from statistics import mean, median, stdev
    
    print(f"\nTotal unique relays: {len(failure_counts)}")
    print(f"Total failures across all relays: {sum(failure_counts)}")
    print(f"\nFailure count per relay:")
    print(f"  Min: {min(failure_counts)}")
    print(f"  Max: {max(failure_counts)}")
    print(f"  Mean: {mean(failure_counts):.2f}")
    print(f"  Median: {median(failure_counts)}")
    print(f"  Std Dev: {stdev(failure_counts):.2f}")
    
    # Relays with 0 failures
    zero_failures = sum(1 for f in failure_counts if f == 0)
    print(f"\nRelays with 0 failures: {zero_failures} ({zero_failures/len(failure_counts)*100:.1f}%)")
    
    # Relays with >5 failures
    gt5_failures = sum(1 for f in failure_counts if f > 5)
    print(f"Relays with >5 failures: {gt5_failures} ({gt5_failures/len(failure_counts)*100:.1f}%)")
    
    # Relays with >20 failures
    gt20_failures = sum(1 for f in failure_counts if f > 20)
    print(f"Relays with >20 failures: {gt20_failures} ({gt20_failures/len(failure_counts)*100:.1f}%)")

def list_high_failure_relays(relay_stats, threshold=20):
    """List relays with failures above threshold."""
    print(f"\n" + "=" * 80)
    print(f"RELAYS WITH >{threshold} FAILURES")
    print("=" * 80)
    
    high_failure = [(fp, stats) for fp, stats in relay_stats.items() 
                    if stats['failures'] > threshold]
    high_failure.sort(key=lambda x: x[1]['failures'], reverse=True)
    
    print(f"\n{'Nickname':<25} {'Fingerprint':<20} {'Tests':>7} {'Fails':>7} {'Success%':>10}")
    print("-" * 75)
    
    for fp, stats in high_failure[:50]:
        success_pct = (stats['successes'] / stats['total_tests']) * 100 if stats['total_tests'] > 0 else 0
        print(f"{stats['nickname']:<25} {fp[:18]:<20} {stats['total_tests']:>7} {stats['failures']:>7} {success_pct:>9.1f}%")
    
    if len(high_failure) > 50:
        print(f"\n... and {len(high_failure) - 50} more relays")

def export_histogram_data(histogram, relay_stats, failure_counts):
    """Export histogram data to JSON."""
    from statistics import mean, median, stdev
    
    output = {
        'histogram': histogram,
        'summary': {
            'total_relays': len(failure_counts),
            'total_failures': sum(failure_counts),
            'min_failures': min(failure_counts),
            'max_failures': max(failure_counts),
            'mean_failures': round(mean(failure_counts), 2),
            'median_failures': median(failure_counts),
            'stdev_failures': round(stdev(failure_counts), 2),
            'relays_with_zero_failures': sum(1 for f in failure_counts if f == 0),
            'relays_with_gt5_failures': sum(1 for f in failure_counts if f > 5),
            'relays_with_gt20_failures': sum(1 for f in failure_counts if f > 20)
        },
        'high_failure_relays': [
            {
                'fingerprint': fp,
                'nickname': stats['nickname'],
                'total_tests': stats['total_tests'],
                'failures': stats['failures'],
                'successes': stats['successes'],
                'success_rate': round((stats['successes'] / stats['total_tests']) * 100, 2) if stats['total_tests'] > 0 else 0
            }
            for fp, stats in sorted(relay_stats.items(), key=lambda x: x[1]['failures'], reverse=True)
            if stats['failures'] > 10
        ]
    }
    
    with open('histogram_data.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print("\nHistogram data exported to histogram_data.json")

def main():
    print("Loading scan data...")
    scans = load_all_scans()
    print(f"Loaded {len(scans)} scans")
    print(f"Date range: {scans[0]['timestamp']} to {scans[-1]['timestamp']}")
    
    print("\nCounting failures per relay...")
    relay_stats = count_failures_per_relay(scans)
    
    print("\nCreating histogram...")
    histogram, failure_counts = create_histogram_data(relay_stats)
    
    # Print outputs
    print_ascii_histogram(histogram)
    print_table(histogram, relay_stats)
    print_summary_stats(failure_counts, relay_stats)
    list_high_failure_relays(relay_stats, threshold=20)
    
    # Export data
    export_histogram_data(histogram, relay_stats, failure_counts)

if __name__ == '__main__':
    main()
