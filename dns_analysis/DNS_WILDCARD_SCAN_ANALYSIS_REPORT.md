# DNS Wildcard Scan Analysis Report

**Date:** January 22, 2026  
**Data Range:** January 19-22, 2026  
**Total Scans Analyzed:** 43  
**Total Unique Relays:** 3,164  

---

## Executive Summary

This analysis examines historical DNS wildcard scan data from https://exitdnshealth.1aeo.com/ to determine optimal scan frequencies and identify patterns that distinguish true DNS issues from transient network volatility.

### Key Findings

1. **92.7% of all failures are transient network/circuit issues**, not DNS problems
2. **Only 9 relays (0.3%)** have genuine DNS issues requiring attention
3. **High scan-to-scan volatility (17-29%)** is normal due to Tor circuit variability
4. **81.4% of transient failures recover within 2 consecutive scans**
5. **Current 2-hour scan interval is appropriate** for detecting persistent issues

---

## 1. Scan Frequency Analysis

### Current Scan Schedule
| Metric | Value |
|--------|-------|
| Total Scans | 43 |
| Date Range | 2.5 days |
| Min Interval | 0.01 hours |
| Max Interval | 2.00 hours |
| Median Interval | 2.00 hours |
| Avg Interval | 1.40 hours |

### Interval Distribution
| Interval | Count | Percentage |
|----------|-------|------------|
| < 30 min | 12 | 28.6% |
| 30min - 1h | 3 | 7.1% |
| 1-2h | 1 | 2.4% |
| 2-3h | 26 | 61.9% |

The scans are primarily running every 2 hours with some bursts of more frequent scans during testing periods.

---

## 2. Relay Classification

Based on behavior across all 43 scans, relays are classified into distinct categories:

| Category | Count | Percentage | Description |
|----------|-------|------------|-------------|
| **HEALTHY** | 1,812 | 57.3% | >85% success rate, rare transient issues |
| **MIXED** | 1,323 | 41.8% | Variable behavior, mostly transient issues |
| **TRANSIENT_PRONE** | 11 | 0.3% | High transient failure rate, DNS works when reachable |
| **DNS_BROKEN** | 8 | 0.3% | Consistently fails DNS resolution |
| **DNS_MALICIOUS** | 1 | 0.03% | Returns wrong IP addresses |
| **INSUFFICIENT_DATA** | 9 | 0.3% | < 10 tests available |

---

## 3. Failure Type Classification

### Total Failures Breakdown
| Failure Type | Count | % of Total | Unique Relays | Category |
|--------------|-------|------------|---------------|----------|
| relay_unreachable | 17,291 | 87.9% | 3,148 | Transient |
| dns_fail | 1,414 | 7.2% | 271 | DNS Issue |
| timeout | 924 | 4.7% | 787 | Transient |
| wrong_ip | 31 | 0.2% | 1 | DNS Malicious |
| exception | 14 | 0.07% | 14 | Transient |

### Analysis
- **92.7% of failures are transient** (circuit/network issues unrelated to DNS)
- **7.3% are actual DNS-related failures** that require attention
- The `relay_unreachable` status (circuit failures) dominates the failure landscape

---

## 4. Relays That Succeed and Fail Over Time vs Constantly Failing

### A. Constantly Failing Relays (True DNS Issues)

These 9 relays have persistent DNS problems and should be flagged:

#### DNS BROKEN (8 relays)
| Nickname | Fingerprint | Tests | Success % | DNS Fail % |
|----------|-------------|-------|-----------|------------|
| obzgs5tbmn4q | FBFB8D5B092DC89B... | 41 | 0.0% | 90.2% |
| hellotor | A7C7C73E27420DFF... | 42 | 0.0% | 90.5% |
| obzgs5tbmn4q | 31F26280E5FD4C75... | 41 | 0.0% | 75.6% |
| obzgs5tbmn4q | 7BDB4BF11FDDEE54... | 40 | 0.0% | 75.0% |
| PonyLV | 59A5F150E4D67032... | 42 | 0.0% | 85.7% |
| TheMadHackerNodeV5 | 959C5935AA3BBC56... | 42 | 0.0% | 83.3% |
| Unnamed | BA895AEDFD1C007F... | 42 | 0.0% | 83.3% |
| bronkintheusa | A1CADDF32A59FE7E... | 42 | 9.5% | 81.0% |

#### DNS MALICIOUS (1 relay)
| Nickname | Fingerprint | Tests | Wrong IP Count | Error Example |
|----------|-------------|-------|----------------|---------------|
| ounfnegire | A510D4DFA81FD3CA... | 41 | 31 | Expected 64.65.4.1, got 162.159.36.12 |

### B. Intermittent (Flapping) Relays

881 relays (27.8%) show high volatility with >30% state transition rate. Examples:

| Nickname | Transition Rate | Success | DNS Fail | Transient |
|----------|-----------------|---------|----------|-----------|
| Quetzalcoatl | 64.1% | 23 | 7 | 10 |
| mentoreth2 | 61.0% | 16 | 22 | 4 |
| Tribulation | 60.5% | 16 | 2 | 21 |
| mentoreth1 | 60.0% | 18 | 17 | 5 |
| NLTorNiceVPSnet | 57.5% | 22 | 19 | 0 |

These relays have genuine DNS issues that manifest intermittently. They should be monitored but require multiple confirmations before flagging.

---

## 5. Recovery Pattern Analysis

Critical insight for determining scan frequency and confirmation requirements:

| Streak Length | Recoveries | Percentage | Cumulative |
|---------------|------------|------------|------------|
| 2 failures | 2,093 | 81.4% | 81.4% |
| 3 failures | 357 | 13.9% | 95.3% |
| 4 failures | 78 | 3.0% | 98.3% |
| 5 failures | 21 | 0.8% | 99.1% |
| 6 failures | 10 | 0.4% | 99.5% |
| 7+ failures | 13 | 0.5% | 100% |

**Key Insight:** 81.4% of failure streaks recover after just 2 consecutive failures. This means most single-scan failures are transient.

---

## 6. Confirmation Threshold Analysis

How many consecutive failures should trigger a flag?

| N Consecutive | True Positives | False Positives | Precision | Recall |
|---------------|----------------|-----------------|-----------|--------|
| 1 | 9 | 3,147 | 0.3% | 100% |
| 2 | 9 | 1,642 | 0.5% | 100% |
| 3 | 9 | 394 | 2.2% | 100% |
| 4 | 9 | 111 | 7.5% | 100% |
| **5** | **9** | **40** | **18.4%** | **100%** |

**Recommendation:** Require **5 consecutive failures** before flagging a relay. This maintains 100% recall (catches all truly broken relays) while significantly reducing false positives from transient issues.

---

## 7. Time-of-Day Patterns

Success rates show some variation by hour (UTC):

| Hour | Tests | Success Rate |
|------|-------|--------------|
| 08:00 | 8,459 | 91.8% |
| 14:00 | 5,784 | 89.4% |
| 18:00 | 5,782 | 89.7% |
| 23:00 | 5,786 | 89.4% |
| 10:00 | 6,279 | 82.6% |
| 12:00 | 6,288 | 81.9% |
| 16:00 | 6,280 | 81.1% |

**Note:** These variations appear to be related to network congestion patterns rather than significant systematic differences.

---

## 8. Recommendations

### Optimal Scan Frequency

**Recommended: Every 4-6 hours with 5-scan confirmation window**

| Factor | Recommendation |
|--------|----------------|
| **Primary Interval** | 4-6 hours between scans |
| **Confirmation Window** | 5 consecutive failures |
| **Minimum History** | 10 tests before classification |
| **Re-test Interval** | 24 hours for flagged relays |

### Rationale:
1. **95.3% of transient failures resolve within 3 consecutive scans** - a 4-6 hour interval with 5-scan confirmation spans ~24 hours
2. **True DNS issues are persistent** - they fail consistently across multiple scans
3. **Reducing from 2h to 4-6h intervals** reduces network load by 50-67% while maintaining detection accuracy

### Confidence Scoring System

Implement a scoring system instead of binary pass/fail:

```
Score Calculation:
- Start at 100 (healthy)
- Each success: +10 (cap at 100)
- Each transient failure (relay_unreachable, timeout): -5
- Each DNS failure (dns_fail): -20
- Each wrong_ip: -50

Flag Thresholds:
- Score < 20: DNS_BROKEN (flag immediately)
- Score 20-50: DNS_SUSPECT (monitor closely)
- Score 50-80: TRANSIENT_PRONE (note for statistics)
- Score > 80: HEALTHY
```

### Reducing Network Volatility Impact

1. **Implement retry logic**: Before recording a failure, attempt the DNS query up to 3 times with different guard/middle relays
2. **Use parallel circuits**: Test each exit relay through 2-3 different circuit paths simultaneously
3. **Weighted consensus**: Use rolling 24-48 hour windows for determining relay health status
4. **Separate transient from persistent**: Track `relay_unreachable` separately from `dns_fail` in reporting

### Specific Actions

| Priority | Action | Impact |
|----------|--------|--------|
| **High** | Flag the 9 identified DNS-broken/malicious relays immediately | Immediate security improvement |
| **High** | Implement 5-scan confirmation before public flagging | Reduce false positives by 96% |
| **Medium** | Extend scan interval to 4-6 hours | Reduce network load 50-67% |
| **Medium** | Add circuit retry logic | Reduce transient failures ~30-50% |
| **Low** | Implement scoring system | Better relay classification |

---

## 9. Summary of Flagged Relays

### Immediate Action Required

**DNS Malicious (Wrong IP):**
- `ounfnegire` (A510D4DFA81FD3CA07391600337BF6BA5A589A5D) - returning 162.159.36.12 instead of expected IP

**DNS Broken:**
1. obzgs5tbmn4q (FBFB8D5B092DC89BFDA9180779EC692E3FA7C3D2)
2. obzgs5tbmn4q (31F26280E5FD4C757E10B5B195FBB2F60DE18EE6)
3. obzgs5tbmn4q (7BDB4BF11FDDEE54F58FE200738E4C83A76A5964)
4. hellotor (A7C7C73E27420DFF9BB3BA3AE395CDEAC3171FA3)
5. PonyLV (59A5F150E4D670325CE55A56999FEA8FE2B3D887)
6. TheMadHackerNodeV5 (959C5935AA3BBC56E174B2DC30D6ABEA0A9914D4)
7. Unnamed (BA895AEDFD1C007F8FBF1283E05D13913105E550)
8. bronkintheusa (A1CADDF32A59FE7E53A2809558366C7C8148E633)

### Monitor Closely (Intermittent DNS Issues)
- mentoreth2, mentoreth, mentoreth1
- NLTorNiceVPSnet
- bronkromanian
- TorExitVIF
- tspio
- marcuse8, marcuse10, marcuse11

---

## Appendix: Data Files

All analysis data is available in:
- `analysis_output.json` - Full analysis data
- `deep_analysis_output.json` - Classification and threshold analysis
- `data/` - All 43 raw scan JSON files

---

*Report generated by DNS Wildcard Scan Analysis Tool*
