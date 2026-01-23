# Histogram: Relay Failure Distribution

**Data Period:** January 19-22, 2026 (43 scans)  
**Total Unique Relays:** 3,164  
**Total Failures:** 19,674  

---

## Histogram: Count of Relays by Number of Failures

```
Failures          Count    Distribution
─────────────────────────────────────────────────────────────────────────────
0 (no failures)       8    █
1                    60    ███████
2                   176    ██████████████████████
3                   351    ████████████████████████████████████████████
4                   462    ██████████████████████████████████████████████████████████
5                   472    ████████████████████████████████████████████████████████████
6                   455    █████████████████████████████████████████████████████████
7                   374    ███████████████████████████████████████████████
8                   244    ███████████████████████████████
9                   193    ████████████████████████
10                  112    ██████████████
11-15               191    ████████████████████████
16-20                38    ████
21-25                14    █
26-30                 3    ▏
31-35                 1    ▏
36-40                 3    ▏
41-50                 7    ▏
─────────────────────────────────────────────────────────────────────────────
```

---

## Distribution Table

| Failure Count | Relay Count | % of Total | Cumulative % |
|---------------|-------------|------------|--------------|
| 0 (no failures) | 8 | 0.25% | 0.25% |
| 1 | 60 | 1.90% | 2.15% |
| 2 | 176 | 5.56% | 7.71% |
| 3 | 351 | 11.09% | 18.81% |
| 4 | 462 | 14.60% | 33.41% |
| 5 | 472 | 14.92% | 48.32% |
| 6 | 455 | 14.38% | 62.71% |
| 7 | 374 | 11.82% | 74.53% |
| 8 | 244 | 7.71% | 82.24% |
| 9 | 193 | 6.10% | 88.34% |
| 10 | 112 | 3.54% | 91.88% |
| 11-15 | 191 | 6.04% | 97.91% |
| 16-20 | 38 | 1.20% | 99.12% |
| 21-25 | 14 | 0.44% | 99.56% |
| 26-30 | 3 | 0.09% | 99.65% |
| 31-35 | 1 | 0.03% | 99.68% |
| 36-40 | 3 | 0.09% | 99.78% |
| 41-50 | 7 | 0.22% | 100.00% |
| **TOTAL** | **3,164** | **100%** | |

---

## Summary Statistics

| Statistic | Value |
|-----------|-------|
| Total unique relays | 3,164 |
| Total failures | 19,674 |
| Min failures | 0 |
| Max failures | 42 |
| **Mean** | **6.22** |
| **Median** | **6.0** |
| Std deviation | 3.80 |

### Key Observations

| Category | Count | Percentage |
|----------|-------|------------|
| Relays with 0 failures | 8 | 0.3% |
| Relays with 1-5 failures | 1,521 | 48.1% |
| Relays with 6-10 failures | 1,378 | 43.6% |
| Relays with >10 failures | 257 | 8.1% |
| Relays with >20 failures | 28 | 0.9% |

---

## Why Recommend 5 Consecutive Failures?

### The Problem: High False Positive Rate

With a single-scan approach, **3,147 healthy relays would be incorrectly flagged** due to transient Tor circuit issues. We need multiple confirmations to distinguish real DNS problems from network volatility.

### Confirmation Threshold Analysis

| N Consecutive Failures | True Positives | False Positives | Precision | FP Reduction vs N=1 |
|------------------------|----------------|-----------------|-----------|---------------------|
| 1 | 9 | 3,147 | 0.3% | — |
| 2 | 9 | 1,642 | 0.5% | 47.8% |
| 3 | 9 | 394 | 2.2% | 87.5% |
| 4 | 9 | 111 | 7.5% | 96.5% |
| **5** | **9** | **40** | **18.4%** | **98.7%** |

### Why 5 is the Sweet Spot

1. **100% Recall Maintained**: All 9 truly broken relays are still detected at N=5
2. **98.7% False Positive Reduction**: From 3,147 false positives down to just 40
3. **Recovery Pattern Data**: 95.3% of transient failure streaks end within 3 scans; 99.1% end within 5 scans
4. **Practical Tradeoff**: Going to N=6 or higher provides diminishing returns while risking delayed detection

### Recovery Pattern Distribution (Supporting Evidence)

| Streak Length Before Recovery | Count | % of Recoveries | Cumulative % |
|-------------------------------|-------|-----------------|--------------|
| 2 consecutive failures | 2,093 | 81.4% | 81.4% |
| 3 consecutive failures | 357 | 13.9% | 95.3% |
| 4 consecutive failures | 78 | 3.0% | 98.3% |
| 5 consecutive failures | 21 | 0.8% | 99.1% |
| 6+ consecutive failures | 23 | 0.9% | 100% |

**Interpretation**: If a relay fails 5 times consecutively, there's only a 0.9% chance it will recover — meaning 99.1% of the time, it's a genuine persistent issue.

---

## Relays with >20 Failures (High Concern)

| Nickname | Fingerprint | Tests | Failures | Success Rate |
|----------|-------------|-------|----------|--------------|
| hellotor | A7C7C73E27420DFF... | 42 | 42 | 0.0% |
| PonyLV | 59A5F150E4D67032... | 42 | 42 | 0.0% |
| TheMadHackerNodeV5 | 959C5935AA3BBC56... | 42 | 42 | 0.0% |
| Unnamed | BA895AEDFD1C007F... | 42 | 42 | 0.0% |
| ounfnegire | A510D4DFA81FD3CA... | 41 | 41 | 0.0% |
| obzgs5tbmn4q | FBFB8D5B092DC89B... | 41 | 41 | 0.0% |
| obzgs5tbmn4q | 31F26280E5FD4C75... | 41 | 41 | 0.0% |
| obzgs5tbmn4q | 7BDB4BF11FDDEE54... | 40 | 40 | 0.0% |
| bronkintheusa | A1CADDF32A59FE7E... | 42 | 38 | 9.5% |
| WepZone | 3E4066785EECA6AB... | 37 | 37 | 0.0% |
| TorExitVIF | 77299CB6688C4ACE... | 39 | 35 | 10.3% |
| bronkromanian | 50C94FC6730FEACA... | 40 | 29 | 27.5% |
| mentoreth2 | 0E29222CA653CE4F... | 42 | 26 | 38.1% |
| GuruKopi | 35449EB3D025CC24... | 34 | 26 | 23.5% |
| tspio | 1532A36172C70012... | 40 | 24 | 40.0% |
| mentoreth | 30626238638AE651... | 42 | 24 | 42.9% |
| unknown | 42A05472952923D7... | 37 | 24 | 35.1% |
| mentoreth1 | A3093B729A57672A... | 41 | 23 | 43.9% |
| Tribulation | 1BEFC4EBB62BF063... | 39 | 23 | 41.0% |
| marcuse11 | 11C7F8EEEE744561... | 41 | 22 | 46.3% |
| Quetzalcoatl | 7644B57DD86305F3... | 41 | 22 | 46.3% |
| Polyphemus4 | 41C106EAEB0B968C... | 39 | 22 | 43.6% |
| Quetzalcoatl | DD68CED74414FF44... | 41 | 22 | 46.3% |
| unknown | C7A82B462EFEF446... | 30 | 22 | 26.7% |
| UnredactedDrake | 114D0851404015C0... | 35 | 22 | 37.1% |
| Quetzalcoatl | F33ECAB340E61175... | 40 | 21 | 47.5% |
| CasjaysDevExit | A771385B8EAE7683... | 38 | 21 | 44.7% |
| UnredactedAlien | 3A19D784D1DBDE1E... | 29 | 21 | 27.6% |

---

## Interpretation

The histogram shows a **roughly normal distribution centered around 5-6 failures per relay**, which aligns with:

1. **43 scans** over 2.5 days
2. **~5-10% transient failure rate** per scan due to Tor circuit volatility

### Distribution Shape Analysis:

- **Peak at 5-6 failures** (14.9% and 14.4% respectively) - this is the expected transient failure rate
- **Sharp dropoff after 10 failures** - relays with >10 failures are statistical outliers
- **Long tail of 28 relays with >20 failures** - these are genuinely problematic

The distribution confirms that requiring 5 consecutive failures effectively separates the "normal noise" (centered at 5-6 total failures spread across 43 scans) from persistent issues (consecutive failures in a row).
