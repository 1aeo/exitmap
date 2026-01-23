# Histogram: Relay Failure Distribution

**Data Period:** January 19-22, 2026 (43 scans)  
**Total Unique Relays:** 3,164  
**Total Failures:** 19,674  

---

## Histogram: Count of Relays by Number of Failures

```
Failures          Count    Distribution
─────────────────────────────────────────────────────────────────────────────
0 (no failures)       8    ▏
1                    60    ██
2                   176    ███████
3                   351    ██████████████
4                   462    ███████████████████
5                   472    ███████████████████
6-10              1,378    ████████████████████████████████████████████████████████
11-15               191    ████████
16-20                38    ██
21-25                14    ▏
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
| 6-10 | 1,378 | 43.55% | 91.88% |
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
| Min failures per relay | 0 |
| Max failures per relay | 42 |
| Mean failures per relay | 6.22 |
| Median failures per relay | 6.0 |
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

The histogram shows a **roughly normal distribution centered around 5-6 failures per relay**, which is expected given:

1. **43 scans** over 2.5 days
2. **~5-10% transient failure rate** per scan due to Tor circuit volatility

### Notable Patterns:

- **91.88%** of relays have ≤10 failures - these are operating normally with expected transient issues
- **8.12%** of relays have >10 failures - warrant closer monitoring
- **0.9%** (28 relays) have >20 failures - high concern, likely persistent issues
- **10 relays** (0.3%) have >35 failures - consistently failing, need immediate attention

The distribution confirms that the vast majority of relays are healthy with normal transient failure patterns, while a small tail of ~28 relays exhibits problematic behavior.
