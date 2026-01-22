#!/usr/bin/env python3
"""
Deep DNS Wildcard Scan Analysis
Focuses on identifying true DNS issues vs transient network issues.
"""

import json
import os
from collections import defaultdict
from datetime import datetime
import re
from statistics import mean, stdev, median

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

def categorize_failure(status, error):
    """Categorize failures into meaningful groups."""
    if status == 'success':
        return 'SUCCESS'
    
    # Tor circuit/network issues (transient)
    if status == 'relay_unreachable':
        return 'TRANSIENT_CIRCUIT'
    if status == 'timeout':
        if error and 'Circuit' in error:
            return 'TRANSIENT_CIRCUIT'
        return 'TRANSIENT_TIMEOUT'
    if status == 'exception':
        if error and ('BrokenPipe' in error or 'ConnectionReset' in error):
            return 'TRANSIENT_CIRCUIT'
        return 'TRANSIENT_OTHER'
    
    # Actual DNS issues
    if status == 'dns_fail':
        return 'DNS_FAIL'
    if status == 'wrong_ip':
        return 'DNS_WRONG_IP'
    
    return f'UNKNOWN_{status}'

def analyze_relay_patterns(scans):
    """Analyze each relay's behavior pattern across all scans."""
    relay_data = defaultdict(lambda: {
        'nickname': 'unknown',
        'tests': [],
        'failure_categories': defaultdict(int),
        'consecutive_patterns': []
    })
    
    for scan in scans:
        results = scan['data'].get('results', [])
        for result in results:
            fp = result.get('exit_fingerprint', 'unknown')
            nickname = result.get('exit_nickname', 'unknown')
            status = result.get('status', 'unknown')
            error = result.get('error', '')
            
            category = categorize_failure(status, error)
            
            relay_data[fp]['nickname'] = nickname
            relay_data[fp]['tests'].append({
                'ts': scan['timestamp'],
                'status': status,
                'category': category,
                'error': error
            })
            relay_data[fp]['failure_categories'][category] += 1
    
    return relay_data

def classify_relay_behavior(relay_data, min_tests=10):
    """Classify relays based on their overall behavior pattern."""
    classifications = {
        'HEALTHY': [],           # Mostly success, rare transient issues
        'TRANSIENT_PRONE': [],   # Many transient issues, but DNS works when reachable
        'DNS_BROKEN': [],        # Consistently fails DNS resolution
        'DNS_MALICIOUS': [],     # Returns wrong IP (potential MITM)
        'MIXED': [],             # Mix of issues
        'INSUFFICIENT_DATA': []  # Not enough tests
    }
    
    for fp, data in relay_data.items():
        total_tests = len(data['tests'])
        
        if total_tests < min_tests:
            classifications['INSUFFICIENT_DATA'].append({
                'fingerprint': fp,
                'nickname': data['nickname'],
                'tests': total_tests,
                'categories': dict(data['failure_categories'])
            })
            continue
        
        cats = data['failure_categories']
        success_count = cats.get('SUCCESS', 0)
        transient_count = cats.get('TRANSIENT_CIRCUIT', 0) + cats.get('TRANSIENT_TIMEOUT', 0) + cats.get('TRANSIENT_OTHER', 0)
        dns_fail_count = cats.get('DNS_FAIL', 0)
        dns_wrong_ip = cats.get('DNS_WRONG_IP', 0)
        
        success_rate = success_count / total_tests
        transient_rate = transient_count / total_tests
        dns_fail_rate = dns_fail_count / total_tests
        
        relay_info = {
            'fingerprint': fp,
            'nickname': data['nickname'],
            'total_tests': total_tests,
            'success_count': success_count,
            'success_rate': round(success_rate * 100, 2),
            'transient_count': transient_count,
            'transient_rate': round(transient_rate * 100, 2),
            'dns_fail_count': dns_fail_count,
            'dns_fail_rate': round(dns_fail_rate * 100, 2),
            'dns_wrong_ip': dns_wrong_ip,
            'categories': dict(data['failure_categories'])
        }
        
        # Classification logic
        if dns_wrong_ip > 0:
            classifications['DNS_MALICIOUS'].append(relay_info)
        elif dns_fail_rate > 0.7:  # More than 70% DNS failures
            classifications['DNS_BROKEN'].append(relay_info)
        elif success_rate > 0.85:  # More than 85% success
            classifications['HEALTHY'].append(relay_info)
        elif transient_rate > 0.5 and dns_fail_rate < 0.1:  # Mostly transient, few DNS issues
            classifications['TRANSIENT_PRONE'].append(relay_info)
        else:
            classifications['MIXED'].append(relay_info)
    
    return classifications

def analyze_consecutive_failures(relay_data):
    """Find relays with consecutive failures to identify persistent issues."""
    persistent_failures = []
    
    for fp, data in relay_data.items():
        tests = data['tests']
        if len(tests) < 5:
            continue
        
        # Find longest streak of consecutive failures
        max_fail_streak = 0
        current_streak = 0
        streak_type = None
        
        for test in tests:
            if test['category'] != 'SUCCESS':
                current_streak += 1
                if current_streak > max_fail_streak:
                    max_fail_streak = current_streak
                    streak_type = test['category']
            else:
                current_streak = 0
        
        if max_fail_streak >= 5:
            persistent_failures.append({
                'fingerprint': fp,
                'nickname': data['nickname'],
                'max_fail_streak': max_fail_streak,
                'streak_type': streak_type,
                'total_tests': len(tests),
                'categories': dict(data['failure_categories'])
            })
    
    return sorted(persistent_failures, key=lambda x: x['max_fail_streak'], reverse=True)

def analyze_flapping_relays(relay_data):
    """Find relays that frequently switch between success and failure."""
    flapping = []
    
    for fp, data in relay_data.items():
        tests = data['tests']
        if len(tests) < 10:
            continue
        
        transitions = 0
        prev_success = None
        
        for test in tests:
            is_success = test['category'] == 'SUCCESS'
            if prev_success is not None and is_success != prev_success:
                transitions += 1
            prev_success = is_success
        
        transition_rate = transitions / (len(tests) - 1)
        
        if transition_rate > 0.3:  # More than 30% state changes
            flapping.append({
                'fingerprint': fp,
                'nickname': data['nickname'],
                'transitions': transitions,
                'total_tests': len(tests),
                'transition_rate': round(transition_rate * 100, 2),
                'categories': dict(data['failure_categories'])
            })
    
    return sorted(flapping, key=lambda x: x['transition_rate'], reverse=True)

def calculate_required_confirmations(relay_data, scans):
    """Determine how many consecutive failures should be required for high confidence."""
    # For each relay that eventually recovered, how many consecutive failures before recovery?
    recovery_patterns = []
    
    for fp, data in relay_data.items():
        tests = data['tests']
        if len(tests) < 5:
            continue
        
        i = 0
        while i < len(tests):
            # Find start of failure streak
            if tests[i]['category'] != 'SUCCESS':
                streak_start = i
                while i < len(tests) and tests[i]['category'] != 'SUCCESS':
                    i += 1
                streak_end = i
                streak_length = streak_end - streak_start
                
                # Did it recover?
                recovered = i < len(tests)
                
                if recovered and streak_length >= 2:
                    recovery_patterns.append({
                        'fingerprint': fp,
                        'nickname': data['nickname'],
                        'streak_length': streak_length,
                        'failure_type': tests[streak_start]['category']
                    })
            else:
                i += 1
    
    return recovery_patterns

def main():
    print("=" * 80)
    print("DEEP DNS WILDCARD SCAN ANALYSIS")
    print("=" * 80)
    
    scans = load_all_scans()
    print(f"\nLoaded {len(scans)} scan files")
    
    relay_data = analyze_relay_patterns(scans)
    print(f"Total unique relays: {len(relay_data)}")
    
    # 1. Classification
    print("\n" + "=" * 80)
    print("1. RELAY BEHAVIOR CLASSIFICATION")
    print("=" * 80)
    
    classifications = classify_relay_behavior(relay_data, min_tests=10)
    
    for category, relays in classifications.items():
        print(f"\n{category}: {len(relays)} relays")
        if relays and category not in ['INSUFFICIENT_DATA', 'HEALTHY']:
            print("  Top examples:")
            for r in relays[:5]:
                print(f"    {r['nickname']} ({r['fingerprint'][:16]}...)")
                print(f"      Success: {r['success_rate']:.1f}%, DNS Fail: {r['dns_fail_rate']:.1f}%, Transient: {r['transient_rate']:.1f}%")
    
    # 2. DNS Broken relays - detailed
    print("\n" + "=" * 80)
    print("2. DNS BROKEN RELAYS (True DNS Issues)")
    print("=" * 80)
    
    dns_broken = classifications.get('DNS_BROKEN', [])
    print(f"Total DNS broken relays: {len(dns_broken)}")
    for r in dns_broken:
        print(f"\n  {r['nickname']} ({r['fingerprint']})")
        print(f"    Tests: {r['total_tests']}, Success: {r['success_count']} ({r['success_rate']:.1f}%)")
        print(f"    DNS Failures: {r['dns_fail_count']} ({r['dns_fail_rate']:.1f}%)")
        print(f"    Categories: {r['categories']}")
    
    # 3. DNS Malicious relays
    print("\n" + "=" * 80)
    print("3. DNS MALICIOUS RELAYS (Wrong IP)")
    print("=" * 80)
    
    dns_malicious = classifications.get('DNS_MALICIOUS', [])
    print(f"Total DNS malicious relays: {len(dns_malicious)}")
    for r in dns_malicious:
        print(f"\n  {r['nickname']} ({r['fingerprint']})")
        print(f"    Tests: {r['total_tests']}, Wrong IP: {r['dns_wrong_ip']}")
        print(f"    Categories: {r['categories']}")
    
    # 4. Consecutive failure analysis
    print("\n" + "=" * 80)
    print("4. PERSISTENT FAILURE ANALYSIS")
    print("=" * 80)
    
    persistent = analyze_consecutive_failures(relay_data)
    print(f"Relays with 5+ consecutive failures: {len(persistent)}")
    for r in persistent[:15]:
        print(f"  {r['nickname']}: {r['max_fail_streak']} consecutive failures ({r['streak_type']})")
    
    # 5. Flapping relays
    print("\n" + "=" * 80)
    print("5. FLAPPING RELAYS (High Volatility)")
    print("=" * 80)
    
    flapping = analyze_flapping_relays(relay_data)
    print(f"Relays with >30% state transition rate: {len(flapping)}")
    for r in flapping[:15]:
        print(f"  {r['nickname']}: {r['transition_rate']:.1f}% transition rate")
        print(f"    Categories: {r['categories']}")
    
    # 6. Recovery pattern analysis
    print("\n" + "=" * 80)
    print("6. RECOVERY PATTERN ANALYSIS")
    print("=" * 80)
    
    recovery_patterns = calculate_required_confirmations(relay_data, scans)
    
    # Group by streak length
    streak_distribution = defaultdict(int)
    for r in recovery_patterns:
        streak_distribution[r['streak_length']] += 1
    
    print("Failure streak lengths before recovery:")
    total_recoveries = len(recovery_patterns)
    cumulative = 0
    for length in sorted(streak_distribution.keys()):
        count = streak_distribution[length]
        cumulative += count
        pct = count / total_recoveries * 100
        cum_pct = cumulative / total_recoveries * 100
        print(f"  {length} consecutive failures: {count} ({pct:.1f}%), Cumulative: {cum_pct:.1f}%")
    
    # 7. Recommendations
    print("\n" + "=" * 80)
    print("7. SCAN FREQUENCY & CONFIDENCE RECOMMENDATIONS")
    print("=" * 80)
    
    # Calculate what % of failures are transient
    total_failures = 0
    transient_failures = 0
    dns_failures = 0
    
    for fp, data in relay_data.items():
        for cat, count in data['failure_categories'].items():
            if cat != 'SUCCESS':
                total_failures += count
                if cat.startswith('TRANSIENT'):
                    transient_failures += count
                elif cat.startswith('DNS'):
                    dns_failures += count
    
    print(f"\nTotal failure events: {total_failures}")
    print(f"  Transient (circuit/network): {transient_failures} ({transient_failures/total_failures*100:.1f}%)")
    print(f"  DNS-related: {dns_failures} ({dns_failures/total_failures*100:.1f}%)")
    
    # Determine confirmation threshold
    print("\n--- CONFIRMATION THRESHOLD ANALYSIS ---")
    print("If we require N consecutive failures before flagging a relay:")
    
    dns_broken_fps = {r['fingerprint'] for r in classifications['DNS_BROKEN']}
    dns_malicious_fps = {r['fingerprint'] for r in classifications['DNS_MALICIOUS']}
    true_bad_fps = dns_broken_fps | dns_malicious_fps
    
    for n in [1, 2, 3, 4, 5]:
        flagged_correctly = 0
        flagged_incorrectly = 0
        missed = 0
        
        for fp, data in relay_data.items():
            tests = data['tests']
            # Check if relay would be flagged with N consecutive failures
            has_n_consecutive = False
            streak = 0
            for test in tests:
                if test['category'] != 'SUCCESS':
                    streak += 1
                    if streak >= n:
                        has_n_consecutive = True
                        break
                else:
                    streak = 0
            
            is_truly_bad = fp in true_bad_fps
            
            if has_n_consecutive:
                if is_truly_bad:
                    flagged_correctly += 1
                else:
                    flagged_incorrectly += 1
            else:
                if is_truly_bad:
                    missed += 1
        
        precision = flagged_correctly / (flagged_correctly + flagged_incorrectly) if (flagged_correctly + flagged_incorrectly) > 0 else 0
        recall = flagged_correctly / (flagged_correctly + missed) if (flagged_correctly + missed) > 0 else 0
        
        print(f"\n  N={n} consecutive failures:")
        print(f"    True positives: {flagged_correctly}, False positives: {flagged_incorrectly}")
        print(f"    Precision: {precision*100:.1f}%, Recall: {recall*100:.1f}%")
    
    # Export analysis
    output = {
        'summary': {
            'total_relays': len(relay_data),
            'healthy': len(classifications['HEALTHY']),
            'transient_prone': len(classifications['TRANSIENT_PRONE']),
            'dns_broken': len(classifications['DNS_BROKEN']),
            'dns_malicious': len(classifications['DNS_MALICIOUS']),
            'mixed': len(classifications['MIXED']),
            'insufficient_data': len(classifications['INSUFFICIENT_DATA'])
        },
        'dns_broken_relays': classifications['DNS_BROKEN'],
        'dns_malicious_relays': classifications['DNS_MALICIOUS'],
        'persistent_failures': persistent[:50],
        'flapping_relays': flapping[:50],
        'recovery_streak_distribution': dict(streak_distribution),
        'failure_breakdown': {
            'total': total_failures,
            'transient': transient_failures,
            'transient_pct': round(transient_failures/total_failures*100, 2),
            'dns': dns_failures,
            'dns_pct': round(dns_failures/total_failures*100, 2)
        }
    }
    
    with open('deep_analysis_output.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print("\nDeep analysis exported to deep_analysis_output.json")

if __name__ == '__main__':
    main()
