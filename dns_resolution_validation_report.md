# Tor Exit Relay DNS Resolution Validation Report

**Generated:** January 1, 2026

This report validates DNS resolution functionality through Tor exit relays operated by various organizations. Testing was performed using the `exitmap` tool with the `dnsresolution` module, which attempts to resolve `www.example.com` and `www.torproject.org` through each exit relay.

---

## Summary

| Operator | Fingerprints Retrieved | In Consensus | DNS Issues | Issue Rate | Circuit Failures |
|----------|------------------------|--------------|------------|------------|------------------|
| [prsv.ch](https://metrics.1aeo.com/prsv.ch/) | 368 | 178 | 9 | 5.1% | 26 (14.61%) |
| [nothingtohide.nl](https://metrics.1aeo.com/nothingtohide.nl/) | 294 | 252 | 0 | 0% | 39 (15.48%) |
| [applied-privacy.net](https://metrics.1aeo.com/applied-privacy.net/) | 105 | 104 | 0 | 0% | 10 (9.62%) |
| [tor.r0cket.net](https://metrics.1aeo.com/tor.r0cket.net/) | 120 | 120 | 6 | 5.0% | 30 (25.00%) |

---

## Detailed Results

### 1. prsv.ch

**Source:** https://metrics.1aeo.com/prsv.ch/

| Metric | Value |
|--------|-------|
| Total fingerprints retrieved | 368 |
| Fingerprints in current Tor consensus | 178 |
| Exit relays with DNS issues | 9 |
| Issue rate | 5.1% |
| Circuits that failed to build | 26 (14.61%) |

#### Failure Reasons
| Count | Reason |
|-------|--------|
| 18 | SOCKS Server error 4 (Host unreachable - DNS resolution failed) |

#### Exit Relays with DNS Resolution Issues (9)

| # | Fingerprint | IP Address | Link |
|---|-------------|------------|------|
| 1 | `0910C1183D6BB135FF6CD17904CE02677A161594` | 147.45.51.193 | [View](https://metrics.1aeo.com/relay/0910C1183D6BB135FF6CD17904CE02677A161594) |
| 2 | `097ECA79574121EF47B114DE34F0E8F9CFD62663` | 147.45.51.193 | [View](https://metrics.1aeo.com/relay/097ECA79574121EF47B114DE34F0E8F9CFD62663) |
| 3 | `3CC3D13C530CD8729FAA7301FBF5951DC21FB432` | 93.94.51.243 | [View](https://metrics.1aeo.com/relay/3CC3D13C530CD8729FAA7301FBF5951DC21FB432) |
| 4 | `599108C8458349C196A71503FDF050DA2B65072B` | 93.94.51.243 | [View](https://metrics.1aeo.com/relay/599108C8458349C196A71503FDF050DA2B65072B) |
| 5 | `5F14199FA8BEA09EFB2A77B634E68117CF45F00B` | 93.94.51.243 | [View](https://metrics.1aeo.com/relay/5F14199FA8BEA09EFB2A77B634E68117CF45F00B) |
| 6 | `740070FBCEA6C82CCB312B7FA7F60724BB50EF03` | 93.94.51.243 | [View](https://metrics.1aeo.com/relay/740070FBCEA6C82CCB312B7FA7F60724BB50EF03) |
| 7 | `CFEE6F0E9941273B8A0F440E6E048544D32BB1A9` | 147.45.116.17 | [View](https://metrics.1aeo.com/relay/CFEE6F0E9941273B8A0F440E6E048544D32BB1A9) |
| 8 | `DE4B81D2331C5304A293442A0F9A087788B8B3F3` | 147.45.51.193 | [View](https://metrics.1aeo.com/relay/DE4B81D2331C5304A293442A0F9A087788B8B3F3) |
| 9 | `ECF8256CAD3D6E32F3A5090BF620401F46F839F0` | 147.45.51.193 | [View](https://metrics.1aeo.com/relay/ECF8256CAD3D6E32F3A5090BF620401F46F839F0) |

#### IP Address Analysis
| IP Address | Failed Relays |
|------------|---------------|
| 147.45.51.193 | 4 |
| 93.94.51.243 | 4 |
| 147.45.116.17 | 1 |

---

### 2. nothingtohide.nl

**Source:** https://metrics.1aeo.com/nothingtohide.nl/

| Metric | Value |
|--------|-------|
| Total fingerprints retrieved | 294 |
| Fingerprints in current Tor consensus | 252 |
| Exit relays with DNS issues | 0 |
| Issue rate | 0% |
| Circuits that failed to build | 39 (15.48%) |

#### Result
✅ **All tested exit relays passed DNS resolution validation.**

No DNS resolution issues were detected for any nothingtohide.nl exit relays.

---

### 3. applied-privacy.net

**Source:** https://metrics.1aeo.com/applied-privacy.net/

| Metric | Value |
|--------|-------|
| Total fingerprints retrieved | 105 |
| Fingerprints in current Tor consensus | 104 |
| Exit relays with DNS issues | 0 |
| Issue rate | 0% |
| Circuits that failed to build | 10 (9.62%) |

#### Result
✅ **All tested exit relays passed DNS resolution validation.**

No DNS resolution issues were detected for any applied-privacy.net exit relays.

---

### 4. tor.r0cket.net

**Source:** https://metrics.1aeo.com/tor.r0cket.net/

| Metric | Value |
|--------|-------|
| Total fingerprints retrieved | 120 |
| Fingerprints in current Tor consensus | 120 |
| Exit relays with DNS issues | 6 |
| Issue rate | 5.0% |
| Circuits that failed to build | 30 (25.00%) |

#### Failure Reasons
| Count | Reason |
|-------|--------|
| 6 | SOCKS Server error 4 (Host unreachable - DNS resolution failed) |
| 2 | Socket timeout |

#### Exit Relays with DNS Resolution Issues (6)

| # | Fingerprint | IP Address | Failure Reason | Link |
|---|-------------|------------|----------------|------|
| 1 | `287A1C40B818DF6C45E8496CDE5026F11563CF10` | 45.84.107.47 | SOCKS Server error 4 | [View](https://metrics.1aeo.com/relay/287A1C40B818DF6C45E8496CDE5026F11563CF10) |
| 2 | `C9CC8B881E2D7E8C44B895CA841C194621907603` | 45.84.107.101 | Socket timeout | [View](https://metrics.1aeo.com/relay/C9CC8B881E2D7E8C44B895CA841C194621907603) |
| 3 | `CC0EB5E62E75E138283C233DAEBAA3615E1DC894` | 45.84.107.47 | SOCKS Server error 4 | [View](https://metrics.1aeo.com/relay/CC0EB5E62E75E138283C233DAEBAA3615E1DC894) |
| 4 | `CDA71E2FAEE3F0A33DA344E254AF5E30A8926F88` | 45.84.107.47 | SOCKS Server error 4 | [View](https://metrics.1aeo.com/relay/CDA71E2FAEE3F0A33DA344E254AF5E30A8926F88) |
| 5 | `D80F923E3F04A69485446AA7F70D55FD745E9086` | 45.84.107.172 | SOCKS Server error 4 | [View](https://metrics.1aeo.com/relay/D80F923E3F04A69485446AA7F70D55FD745E9086) |
| 6 | `ED2E34869CCCBCE9321DEBBB957507A85A155CEF` | 45.84.107.198 | SOCKS Server error 4 | [View](https://metrics.1aeo.com/relay/ED2E34869CCCBCE9321DEBBB957507A85A155CEF) |

---

## Error Code Reference

| Error | Description |
|-------|-------------|
| SOCKS Server error 4 | "Host unreachable" - The exit relay cannot resolve the domain name via DNS |
| Socket timeout | The DNS resolution request timed out (10 second timeout) |

---

## Methodology

1. Relay fingerprints were retrieved from the 1AEO metrics pages for each operator
2. The `exitmap` tool was used with the `dnsresolution` module
3. Each exit relay was tested by attempting to resolve `www.example.com` and `www.torproject.org`
4. DNS resolution uses Tor's SOCKS5 RESOLVE extension
5. A 10-second timeout was applied to each resolution attempt
6. Only relays present in the current Tor consensus were tested

---

## Notes

- Fingerprints not in the current Tor consensus may represent relays that are offline or no longer functioning as exits
- Circuit build failures are separate from DNS resolution failures and may indicate network connectivity issues
- Some relays may have intermittent DNS issues; a single test may not capture all problems
- The prsv.ch DNS issues are concentrated on specific IP addresses (147.45.51.193 and 93.94.51.243), suggesting server-specific DNS configuration problems
