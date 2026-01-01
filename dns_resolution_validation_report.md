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
| [tor.r0cket.net](https://metrics.1aeo.com/tor.r0cket.net/) | 120 | 120 | 4 | 3.3% | 10 (8.33%) |

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
| Exit relays with DNS issues | 4 |
| Issue rate | 3.3% |
| Circuits that failed to build | 10 (8.33%) |

#### Failure Reasons
| Count | Reason |
|-------|--------|
| 8 | SOCKS Server error 4 (Host unreachable - DNS resolution failed) |

#### Exit Relays with DNS Resolution Issues (4)

| # | Exit Fingerprint | Exit IP | Middle Relay Fingerprint | Middle Relay AS | Failure Reason | Link |
|---|------------------|---------|--------------------------|-----------------|----------------|------|
| 1 | `20A2D0A0C53B6A461C6D97889DAAC47894A78F64` | 45.84.107.97 | `8F4BF2EE1246D243B7EACC014D39BB3EB388E972` | AS210558 | SOCKS Server error 4 | [View](https://metrics.1aeo.com/relay/20A2D0A0C53B6A461C6D97889DAAC47894A78F64) |
| 2 | `8F22F5F09E5249096B98EF389D9040FEF1D61F82` | 45.84.107.97 | `F6F2DBDEA4EE1C08C3F950743C86419F370EFDF6` | AS197540 | SOCKS Server error 4 | [View](https://metrics.1aeo.com/relay/8F22F5F09E5249096B98EF389D9040FEF1D61F82) |
| 3 | `A145DF21981626EF868F9BE79946A68ED4CF4275` | 45.84.107.97 | `09CA1957EC0671044DAD2EEA282A348FFD7D271E` | AS53667 | SOCKS Server error 4 | [View](https://metrics.1aeo.com/relay/A145DF21981626EF868F9BE79946A68ED4CF4275) |
| 4 | `C42FF9E0D0CE6B5D83E27C35026D14E402572AE6` | 45.84.107.97 | `0BF171D0984EEF35B9ED9D7801941C833DD3853B` | AS54290 | SOCKS Server error 4 | [View](https://metrics.1aeo.com/relay/C42FF9E0D0CE6B5D83E27C35026D14E402572AE6) |

#### Analysis
- All 4 failed relays are on the same IP address: **45.84.107.97**
- Different middle relays were used (from different AS networks), ruling out middle relay as the cause
- This confirms the DNS issue is specific to the exit relay/server, not the circuit path

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
