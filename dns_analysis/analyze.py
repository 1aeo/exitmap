#!/usr/bin/env python3
"""
DNS Wildcard Scan Analysis
Analyzes historical DNS health scan data to determine optimal scan frequencies
and identify patterns in relay failures.
"""

import json
import os
from collections import defaultdict
from datetime import datetime
import re
from statistics import mean, stdev, median

DATA_DIR = 'data'

def parse_timestamp_from_filename(filename):
    """Extract timestamp from filename like dns_health_2026-01-22_08-15-01.json"""
    match = re.search(r'dns_health_(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})\.json', filename)
    if match:
        y, mo, d, h, mi, s = match.groups()
        return datetime(int(y), int(mo), int(d), int(h), int(mi), int(s))
    return None

def load_all_scans():
    """Load all scan files and return sorted by timestamp."""
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
    
    # Sort by timestamp ascending
    scans.sort(key=lambda x: x['timestamp'])
    return scans

def analyze_scan_intervals(scans):
    """Analyze intervals between scans."""
    intervals = []
    for i in range(1, len(scans)):
        delta = (scans[i]['timestamp'] - scans[i-1]['timestamp']).total_seconds() / 3600
        intervals.append(delta)
    
    return {
        'count': len(intervals),
        'min_hours': min(intervals) if intervals else 0,
        'max_hours': max(intervals) if intervals else 0,
        'avg_hours': mean(intervals) if intervals else 0,
        'median_hours': median(intervals) if intervals else 0,
        'std_hours': stdev(intervals) if len(intervals) > 1 else 0,
        'intervals': intervals
    }

def analyze_relay_consistency(scans):
    """
    Analyze relay behavior across all scans.
    Returns categorization of relays by consistency.
    """
    # Track each relay's history across all scans
    relay_history = defaultdict(lambda: {'successes': 0, 'failures': 0, 'scans': [], 'failure_types': defaultdict(int)})
    
    for scan in scans:
        results = scan['data'].get('results', [])
        for result in results:
            fp = result.get('exit_fingerprint', 'unknown')
            nickname = result.get('exit_nickname', 'unknown')
            status = result.get('status', 'unknown')
            error = result.get('error')
            
            relay_history[fp]['nickname'] = nickname
            
            if status == 'success':
                relay_history[fp]['successes'] += 1
                relay_history[fp]['scans'].append({'ts': scan['timestamp'], 'status': 'success'})
            else:
                relay_history[fp]['failures'] += 1
                relay_history[fp]['failure_types'][status] += 1
                relay_history[fp]['scans'].append({
                    'ts': scan['timestamp'], 
                    'status': status, 
                    'error': error
                })
    
    # Categorize relays
    always_pass = {}
    always_fail = {}
    intermittent = {}
    
    total_scans = len(scans)
    
    for fp, data in relay_history.items():
        total_tests = data['successes'] + data['failures']
        success_rate = data['successes'] / total_tests if total_tests > 0 else 0
        
        relay_info = {
            'fingerprint': fp,
            'nickname': data['nickname'],
            'successes': data['successes'],
            'failures': data['failures'],
            'total_tests': total_tests,
            'success_rate': success_rate,
            'failure_types': dict(data['failure_types']),
            'scans': data['scans']
        }
        
        if data['failures'] == 0:
            always_pass[fp] = relay_info
        elif data['successes'] == 0:
            always_fail[fp] = relay_info
        else:
            intermittent[fp] = relay_info
    
    return {
        'always_pass': always_pass,
        'always_fail': always_fail,
        'intermittent': intermittent,
        'total_relays': len(relay_history),
        'total_scans': total_scans
    }

def classify_failures(scans):
    """Classify all failures by type across all scans."""
    failure_breakdown = defaultdict(lambda: {'count': 0, 'relays': set(), 'examples': []})
    
    for scan in scans:
        results = scan['data'].get('results', [])
        for result in results:
            if result.get('status') != 'success':
                status = result.get('status', 'unknown')
                fp = result.get('exit_fingerprint', 'unknown')
                
                failure_breakdown[status]['count'] += 1
                failure_breakdown[status]['relays'].add(fp)
                
                if len(failure_breakdown[status]['examples']) < 5:
                    failure_breakdown[status]['examples'].append({
                        'fingerprint': fp,
                        'nickname': result.get('exit_nickname'),
                        'error': result.get('error'),
                        'timestamp': str(scan['timestamp'])
                    })
    
    # Convert sets to counts
    for status in failure_breakdown:
        failure_breakdown[status]['unique_relays'] = len(failure_breakdown[status]['relays'])
        del failure_breakdown[status]['relays']
    
    return dict(failure_breakdown)

def analyze_time_of_day_patterns(scans):
    """Analyze if failure rates vary by time of day."""
    hourly_stats = defaultdict(lambda: {'total': 0, 'success': 0, 'fail': 0})
    
    for scan in scans:
        hour = scan['timestamp'].hour
        results = scan['data'].get('results', [])
        
        for result in results:
            hourly_stats[hour]['total'] += 1
            if result.get('status') == 'success':
                hourly_stats[hour]['success'] += 1
            else:
                hourly_stats[hour]['fail'] += 1
    
    hourly_rates = {}
    for hour in sorted(hourly_stats.keys()):
        stats = hourly_stats[hour]
        rate = (stats['success'] / stats['total'] * 100) if stats['total'] > 0 else 0
        hourly_rates[hour] = {
            'total_tests': stats['total'],
            'successes': stats['success'],
            'failures': stats['fail'],
            'success_rate_pct': round(rate, 2)
        }
    
    return hourly_rates

def analyze_scan_to_scan_volatility(scans):
    """Analyze how relay status changes between consecutive scans."""
    transitions = []
    
    for i in range(1, len(scans)):
        prev_scan = scans[i-1]['data'].get('results', [])
        curr_scan = scans[i]['data'].get('results', [])
        
        prev_status = {r['exit_fingerprint']: r['status'] for r in prev_scan}
        curr_status = {r['exit_fingerprint']: r['status'] for r in curr_scan}
        
        common_relays = set(prev_status.keys()) & set(curr_status.keys())
        
        success_to_fail = 0
        fail_to_success = 0
        stable_success = 0
        stable_fail = 0
        
        for fp in common_relays:
            prev = prev_status[fp]
            curr = curr_status[fp]
            
            if prev == 'success' and curr == 'success':
                stable_success += 1
            elif prev != 'success' and curr != 'success':
                stable_fail += 1
            elif prev == 'success' and curr != 'success':
                success_to_fail += 1
            elif prev != 'success' and curr == 'success':
                fail_to_success += 1
        
        interval_hours = (scans[i]['timestamp'] - scans[i-1]['timestamp']).total_seconds() / 3600
        
        transitions.append({
            'from': str(scans[i-1]['timestamp']),
            'to': str(scans[i]['timestamp']),
            'interval_hours': round(interval_hours, 2),
            'common_relays': len(common_relays),
            'stable_success': stable_success,
            'stable_fail': stable_fail,
            'success_to_fail': success_to_fail,
            'fail_to_success': fail_to_success,
            'volatility_rate': round((success_to_fail + fail_to_success) / len(common_relays) * 100, 2) if common_relays else 0
        })
    
    return transitions

def get_scan_metadata_summary(scans):
    """Get summary of metadata across all scans."""
    summaries = []
    for scan in scans:
        meta = scan['data'].get('metadata', {})
        summaries.append({
            'timestamp': str(scan['timestamp']),
            'consensus_relays': meta.get('consensus_relays', 0),
            'tested_relays': meta.get('tested_relays', 0),
            'dns_success': meta.get('dns_success', 0),
            'dns_fail': meta.get('dns_fail', 0),
            'dns_timeout': meta.get('dns_timeout', 0),
            'dns_wrong_ip': meta.get('dns_wrong_ip', 0),
            'dns_success_rate_percent': meta.get('dns_success_rate_percent', 0)
        })
    return summaries

def main():
    print("=" * 80)
    print("DNS WILDCARD SCAN HISTORICAL ANALYSIS")
    print("=" * 80)
    
    scans = load_all_scans()
    print(f"\nLoaded {len(scans)} scan files")
    print(f"Date range: {scans[0]['timestamp']} to {scans[-1]['timestamp']}")
    
    # 1. Scan interval analysis
    print("\n" + "=" * 80)
    print("1. SCAN INTERVAL ANALYSIS")
    print("=" * 80)
    intervals = analyze_scan_intervals(scans)
    print(f"Number of intervals: {intervals['count']}")
    print(f"Min interval: {intervals['min_hours']:.2f} hours")
    print(f"Max interval: {intervals['max_hours']:.2f} hours")
    print(f"Average interval: {intervals['avg_hours']:.2f} hours")
    print(f"Median interval: {intervals['median_hours']:.2f} hours")
    print(f"Std deviation: {intervals['std_hours']:.2f} hours")
    
    # Interval distribution
    interval_buckets = defaultdict(int)
    for i in intervals['intervals']:
        if i < 0.5:
            interval_buckets['<30min'] += 1
        elif i < 1:
            interval_buckets['30min-1h'] += 1
        elif i < 2:
            interval_buckets['1-2h'] += 1
        elif i < 3:
            interval_buckets['2-3h'] += 1
        else:
            interval_buckets['3h+'] += 1
    
    print("\nInterval distribution:")
    for bucket, count in sorted(interval_buckets.items()):
        print(f"  {bucket}: {count}")
    
    # 2. Metadata summary
    print("\n" + "=" * 80)
    print("2. SCAN METADATA SUMMARY")
    print("=" * 80)
    summaries = get_scan_metadata_summary(scans)
    
    success_rates = [s['dns_success_rate_percent'] for s in summaries]
    print(f"Success rate range: {min(success_rates):.2f}% - {max(success_rates):.2f}%")
    print(f"Average success rate: {mean(success_rates):.2f}%")
    print(f"Success rate std dev: {stdev(success_rates):.2f}%")
    
    print("\nPer-scan breakdown:")
    for s in summaries[-10:]:  # Show last 10
        print(f"  {s['timestamp']}: {s['tested_relays']} tested, "
              f"{s['dns_success']} success, {s['dns_fail']} fail, "
              f"{s['dns_timeout']} timeout, {s['dns_wrong_ip']} wrong_ip, "
              f"Rate: {s['dns_success_rate_percent']:.1f}%")
    
    # 3. Relay consistency analysis
    print("\n" + "=" * 80)
    print("3. RELAY CONSISTENCY ANALYSIS")
    print("=" * 80)
    consistency = analyze_relay_consistency(scans)
    
    print(f"Total unique relays seen: {consistency['total_relays']}")
    print(f"Total scans analyzed: {consistency['total_scans']}")
    print(f"\nAlways passing relays: {len(consistency['always_pass'])}")
    print(f"Always failing relays: {len(consistency['always_fail'])}")
    print(f"Intermittent relays: {len(consistency['intermittent'])}")
    
    # Show always failing relays
    print("\n--- ALWAYS FAILING RELAYS ---")
    for fp, info in list(consistency['always_fail'].items())[:20]:
        print(f"  {info['nickname']} ({fp[:16]}...)")
        print(f"    Failures: {info['failures']}, Types: {info['failure_types']}")
    
    # Show intermittent relays
    print("\n--- INTERMITTENT RELAYS (Sample) ---")
    # Sort by failure count (highest first)
    intermittent_sorted = sorted(
        consistency['intermittent'].items(),
        key=lambda x: x[1]['failures'],
        reverse=True
    )
    
    for fp, info in intermittent_sorted[:20]:
        print(f"  {info['nickname']} ({fp[:16]}...)")
        print(f"    Successes: {info['successes']}, Failures: {info['failures']}, "
              f"Rate: {info['success_rate']*100:.1f}%")
        print(f"    Failure types: {info['failure_types']}")
    
    # 4. Failure type classification
    print("\n" + "=" * 80)
    print("4. FAILURE TYPE CLASSIFICATION")
    print("=" * 80)
    failures = classify_failures(scans)
    
    for status, data in sorted(failures.items(), key=lambda x: x[1]['count'], reverse=True):
        print(f"\n{status.upper()}: {data['count']} total failures, {data['unique_relays']} unique relays")
        print("  Examples:")
        for ex in data['examples'][:3]:
            error_snippet = (ex['error'] or 'No error message')[:80]
            print(f"    - {ex['nickname']}: {error_snippet}")
    
    # 5. Time of day patterns
    print("\n" + "=" * 80)
    print("5. TIME OF DAY PATTERNS")
    print("=" * 80)
    hourly = analyze_time_of_day_patterns(scans)
    
    print("Hour | Tests    | Success | Failures | Success Rate")
    print("-" * 55)
    for hour in sorted(hourly.keys()):
        h = hourly[hour]
        print(f" {hour:02d}  | {h['total_tests']:8d} | {h['successes']:7d} | {h['failures']:8d} | {h['success_rate_pct']:6.2f}%")
    
    # 6. Scan-to-scan volatility
    print("\n" + "=" * 80)
    print("6. SCAN-TO-SCAN VOLATILITY")
    print("=" * 80)
    transitions = analyze_scan_to_scan_volatility(scans)
    
    volatility_rates = [t['volatility_rate'] for t in transitions]
    print(f"Volatility rate range: {min(volatility_rates):.2f}% - {max(volatility_rates):.2f}%")
    print(f"Average volatility: {mean(volatility_rates):.2f}%")
    print(f"Volatility std dev: {stdev(volatility_rates):.2f}%")
    
    print("\nPer-transition breakdown:")
    for t in transitions[-15:]:
        print(f"  {t['from']} -> {t['to']}")
        print(f"    Interval: {t['interval_hours']:.2f}h, Common relays: {t['common_relays']}")
        print(f"    Stable OK: {t['stable_success']}, Stable Fail: {t['stable_fail']}")
        print(f"    OK->Fail: {t['success_to_fail']}, Fail->OK: {t['fail_to_success']}")
        print(f"    Volatility: {t['volatility_rate']:.2f}%")
    
    # 7. Correlation analysis: interval vs volatility
    print("\n" + "=" * 80)
    print("7. INTERVAL VS VOLATILITY CORRELATION")
    print("=" * 80)
    
    # Group by interval ranges
    interval_groups = defaultdict(list)
    for t in transitions:
        if t['interval_hours'] < 0.5:
            interval_groups['<30min'].append(t['volatility_rate'])
        elif t['interval_hours'] < 1:
            interval_groups['30min-1h'].append(t['volatility_rate'])
        elif t['interval_hours'] < 2:
            interval_groups['1-2h'].append(t['volatility_rate'])
        elif t['interval_hours'] < 3:
            interval_groups['2-3h'].append(t['volatility_rate'])
        else:
            interval_groups['3h+'].append(t['volatility_rate'])
    
    print("Interval | Transitions | Avg Volatility | Min-Max")
    print("-" * 60)
    for interval in ['<30min', '30min-1h', '1-2h', '2-3h', '3h+']:
        if interval in interval_groups and interval_groups[interval]:
            rates = interval_groups[interval]
            print(f"{interval:10s} | {len(rates):11d} | {mean(rates):14.2f}% | {min(rates):.2f}%-{max(rates):.2f}%")
    
    # 8. Export data for further analysis
    print("\n" + "=" * 80)
    print("8. EXPORTING ANALYSIS DATA")
    print("=" * 80)
    
    analysis_output = {
        'scan_count': len(scans),
        'date_range': {
            'start': str(scans[0]['timestamp']),
            'end': str(scans[-1]['timestamp'])
        },
        'intervals': intervals,
        'success_rates': {
            'min': min(success_rates),
            'max': max(success_rates),
            'avg': mean(success_rates),
            'std': stdev(success_rates)
        },
        'relay_consistency': {
            'total_relays': consistency['total_relays'],
            'always_pass_count': len(consistency['always_pass']),
            'always_fail_count': len(consistency['always_fail']),
            'intermittent_count': len(consistency['intermittent']),
            'always_fail_details': {fp: info for fp, info in list(consistency['always_fail'].items())[:50]},
            'intermittent_details': {fp: info for fp, info in intermittent_sorted[:50]}
        },
        'failure_classification': failures,
        'hourly_patterns': hourly,
        'volatility': {
            'min': min(volatility_rates),
            'max': max(volatility_rates),
            'avg': mean(volatility_rates),
            'std': stdev(volatility_rates),
            'transitions': transitions
        },
        'interval_volatility_correlation': {
            interval: {
                'count': len(rates),
                'avg_volatility': mean(rates) if rates else 0,
                'min_volatility': min(rates) if rates else 0,
                'max_volatility': max(rates) if rates else 0
            }
            for interval, rates in interval_groups.items()
        }
    }
    
    # Remove non-serializable datetime objects from intermittent_details
    for fp in analysis_output['relay_consistency']['intermittent_details']:
        info = analysis_output['relay_consistency']['intermittent_details'][fp]
        info['scans'] = [{'ts': str(s['ts']), 'status': s['status'], 'error': s.get('error')} for s in info['scans']]
    
    for fp in analysis_output['relay_consistency']['always_fail_details']:
        info = analysis_output['relay_consistency']['always_fail_details'][fp]
        info['scans'] = [{'ts': str(s['ts']), 'status': s['status'], 'error': s.get('error')} for s in info['scans']]
    
    with open('analysis_output.json', 'w') as f:
        json.dump(analysis_output, f, indent=2, default=str)
    
    print("Analysis data exported to analysis_output.json")
    
    return analysis_output

if __name__ == '__main__':
    main()
