# Tor Exit Relay DNS Resolution Validation Report

**Generated:** January 1, 2026

This report validates DNS resolution functionality through Tor exit relays operated by various organizations. Testing was performed using the `exitmap` tool with the `dnsresolution` module, which attempts to resolve `www.example.com` and `www.torproject.org` through each exit relay.

---

## Summary

| Operator | Fingerprints Retrieved | In Consensus | DNS Issues | Issue Rate | Circuit Failures |
|----------|------------------------|--------------|------------|------------|------------------|
| [prsv.ch](https://metrics.1aeo.com/prsv.ch/) | 368 | 178 | 81 | 45.5% | 14 (7.87%) |
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
| Exit relays with DNS issues | 81 |
| Issue rate | 45.5% |
| Circuits that failed to build | 14 (7.87%) |

#### Failure Reasons
| Count | Reason |
|-------|--------|
| 150 | SOCKS Server error 4 (Host unreachable - DNS resolution failed) |

#### Exit Relays with DNS Resolution Issues (81)

| # | Fingerprint | Metrics Link |
|---|-------------|--------------|
| 1 | `00EF3D748D860E3A3745E3F6CA5FB49C32A7CFD4` | [View](https://metrics.torproject.org/rs.html#details/00EF3D748D860E3A3745E3F6CA5FB49C32A7CFD4) |
| 2 | `0288BCA70749C447D1D40C28EA871C7A34CC90D7` | [View](https://metrics.torproject.org/rs.html#details/0288BCA70749C447D1D40C28EA871C7A34CC90D7) |
| 3 | `06329ADBB2961CCA3C19FF98437AFA4746CEB820` | [View](https://metrics.torproject.org/rs.html#details/06329ADBB2961CCA3C19FF98437AFA4746CEB820) |
| 4 | `071C2330B45FCFE8228161CAEED4E6AADE60841B` | [View](https://metrics.torproject.org/rs.html#details/071C2330B45FCFE8228161CAEED4E6AADE60841B) |
| 5 | `0A5D5076C8DF92D3511B7C981CE169E702FA8061` | [View](https://metrics.torproject.org/rs.html#details/0A5D5076C8DF92D3511B7C981CE169E702FA8061) |
| 6 | `0C68F2E1EA70B006694BB6B45AC76CBB82E09CDC` | [View](https://metrics.torproject.org/rs.html#details/0C68F2E1EA70B006694BB6B45AC76CBB82E09CDC) |
| 7 | `0CD26FF2F8B8AB85845BBEA97AA709EEE0590016` | [View](https://metrics.torproject.org/rs.html#details/0CD26FF2F8B8AB85845BBEA97AA709EEE0590016) |
| 8 | `0D016BB6BDBEA0FA19E3F70DB500765A3DC57C46` | [View](https://metrics.torproject.org/rs.html#details/0D016BB6BDBEA0FA19E3F70DB500765A3DC57C46) |
| 9 | `1393A08210E59E38A62FD0CBD9D38287EFE11BD9` | [View](https://metrics.torproject.org/rs.html#details/1393A08210E59E38A62FD0CBD9D38287EFE11BD9) |
| 10 | `1677C01D2E0A2FB0A4A674E45CCB8AE231654F89` | [View](https://metrics.torproject.org/rs.html#details/1677C01D2E0A2FB0A4A674E45CCB8AE231654F89) |
| 11 | `1725572936427B431C44F3AFE8EB5CD0769BC850` | [View](https://metrics.torproject.org/rs.html#details/1725572936427B431C44F3AFE8EB5CD0769BC850) |
| 12 | `1BF79AA4CF170310E389AD3299997BA1BC48C7B0` | [View](https://metrics.torproject.org/rs.html#details/1BF79AA4CF170310E389AD3299997BA1BC48C7B0) |
| 13 | `1DAA1C8A4BE0483ECB3358C6356E22845B3C403E` | [View](https://metrics.torproject.org/rs.html#details/1DAA1C8A4BE0483ECB3358C6356E22845B3C403E) |
| 14 | `21077DCF56FD15C69BA5C772D394D3B1FA1B8708` | [View](https://metrics.torproject.org/rs.html#details/21077DCF56FD15C69BA5C772D394D3B1FA1B8708) |
| 15 | `253754DE51E09E4A72B5BEC7EF63095CC0FE836A` | [View](https://metrics.torproject.org/rs.html#details/253754DE51E09E4A72B5BEC7EF63095CC0FE836A) |
| 16 | `27075D39F1449D6E0147674E51F360DDBFBAD91B` | [View](https://metrics.torproject.org/rs.html#details/27075D39F1449D6E0147674E51F360DDBFBAD91B) |
| 17 | `27F6AD0910BD90228C5D182F1F9BA199BAE54249` | [View](https://metrics.torproject.org/rs.html#details/27F6AD0910BD90228C5D182F1F9BA199BAE54249) |
| 18 | `2AB5A3EBE7E21B1FE29561F87B54571F99A9D4F8` | [View](https://metrics.torproject.org/rs.html#details/2AB5A3EBE7E21B1FE29561F87B54571F99A9D4F8) |
| 19 | `2E075C48E6C324751E41E29FB4A8B37532680398` | [View](https://metrics.torproject.org/rs.html#details/2E075C48E6C324751E41E29FB4A8B37532680398) |
| 20 | `2EE6DF7252EBA49FC1364083B76C35F04E3FE084` | [View](https://metrics.torproject.org/rs.html#details/2EE6DF7252EBA49FC1364083B76C35F04E3FE084) |
| 21 | `307EBA10AFB082C69C0B9AEB8182A968A478ECAE` | [View](https://metrics.torproject.org/rs.html#details/307EBA10AFB082C69C0B9AEB8182A968A478ECAE) |
| 22 | `35DA49574189D2DF20174EDC0E328CDD5BE2D26A` | [View](https://metrics.torproject.org/rs.html#details/35DA49574189D2DF20174EDC0E328CDD5BE2D26A) |
| 23 | `44C0AA0B88181CFD72DC16ECFD8D9971AD6BADFB` | [View](https://metrics.torproject.org/rs.html#details/44C0AA0B88181CFD72DC16ECFD8D9971AD6BADFB) |
| 24 | `4548B52F2C0DF4374BA598D770EDE151E44F994A` | [View](https://metrics.torproject.org/rs.html#details/4548B52F2C0DF4374BA598D770EDE151E44F994A) |
| 25 | `480ACEB3C98BCE801B495504A5FFFA6189FDDD70` | [View](https://metrics.torproject.org/rs.html#details/480ACEB3C98BCE801B495504A5FFFA6189FDDD70) |
| 26 | `5817BB147AB398A63F7EC8DB5899C5A1B5056AD4` | [View](https://metrics.torproject.org/rs.html#details/5817BB147AB398A63F7EC8DB5899C5A1B5056AD4) |
| 27 | `599108C8458349C196A71503FDF050DA2B65072B` | [View](https://metrics.torproject.org/rs.html#details/599108C8458349C196A71503FDF050DA2B65072B) |
| 28 | `667BD196E39C299B31675AB6D82787CAE2CB8723` | [View](https://metrics.torproject.org/rs.html#details/667BD196E39C299B31675AB6D82787CAE2CB8723) |
| 29 | `66ABF3EF21E15C63EDF6FD941D2E0D788AEA57C4` | [View](https://metrics.torproject.org/rs.html#details/66ABF3EF21E15C63EDF6FD941D2E0D788AEA57C4) |
| 30 | `67037BC9FEA6251A1E6542433564EA297E64DC9F` | [View](https://metrics.torproject.org/rs.html#details/67037BC9FEA6251A1E6542433564EA297E64DC9F) |
| 31 | `69F834B846BC75282CF6C498DE4E046E2D97D9C1` | [View](https://metrics.torproject.org/rs.html#details/69F834B846BC75282CF6C498DE4E046E2D97D9C1) |
| 32 | `6BDBF511F54269D25541D74A2F39B56B6A3BC4EA` | [View](https://metrics.torproject.org/rs.html#details/6BDBF511F54269D25541D74A2F39B56B6A3BC4EA) |
| 33 | `729CC57A8BC097E3B90A728D398ACD03074B225E` | [View](https://metrics.torproject.org/rs.html#details/729CC57A8BC097E3B90A728D398ACD03074B225E) |
| 34 | `72D7561CA7E5CADF1FC4EA8D99A6A74D081B831B` | [View](https://metrics.torproject.org/rs.html#details/72D7561CA7E5CADF1FC4EA8D99A6A74D081B831B) |
| 35 | `740070FBCEA6C82CCB312B7FA7F60724BB50EF03` | [View](https://metrics.torproject.org/rs.html#details/740070FBCEA6C82CCB312B7FA7F60724BB50EF03) |
| 36 | `748631B8E59394339393D3C28465DE36F86428F9` | [View](https://metrics.torproject.org/rs.html#details/748631B8E59394339393D3C28465DE36F86428F9) |
| 37 | `756CC9D0F475F17EA3C09F76C1145E5A8C995744` | [View](https://metrics.torproject.org/rs.html#details/756CC9D0F475F17EA3C09F76C1145E5A8C995744) |
| 38 | `76CB2A385410AC707AC1C9CFE20CB0E633E526BA` | [View](https://metrics.torproject.org/rs.html#details/76CB2A385410AC707AC1C9CFE20CB0E633E526BA) |
| 39 | `7736E950BB9A8B27DCBB7A9B5C63324867E2608E` | [View](https://metrics.torproject.org/rs.html#details/7736E950BB9A8B27DCBB7A9B5C63324867E2608E) |
| 40 | `783EC950C7109BD966311A35FC9EEE80A6824F87` | [View](https://metrics.torproject.org/rs.html#details/783EC950C7109BD966311A35FC9EEE80A6824F87) |
| 41 | `7AE7F80D74E97D54904CEBF9500922ABBEEDC8BC` | [View](https://metrics.torproject.org/rs.html#details/7AE7F80D74E97D54904CEBF9500922ABBEEDC8BC) |
| 42 | `815C1AB1F4FE8D256EEAA64CF47315C04A4756A4` | [View](https://metrics.torproject.org/rs.html#details/815C1AB1F4FE8D256EEAA64CF47315C04A4756A4) |
| 43 | `838DA217A3B09C8CABD3A0B137E3F5F58FB9BFAC` | [View](https://metrics.torproject.org/rs.html#details/838DA217A3B09C8CABD3A0B137E3F5F58FB9BFAC) |
| 44 | `88673C4E2EF9EE75DFE48A9A8306064AFB9BBE29` | [View](https://metrics.torproject.org/rs.html#details/88673C4E2EF9EE75DFE48A9A8306064AFB9BBE29) |
| 45 | `8B2EAA9D05FFAFD54228F764637312D0AD46D52E` | [View](https://metrics.torproject.org/rs.html#details/8B2EAA9D05FFAFD54228F764637312D0AD46D52E) |
| 46 | `8B8A8A1F7608DFCE2607D2DE37E96434302EBA58` | [View](https://metrics.torproject.org/rs.html#details/8B8A8A1F7608DFCE2607D2DE37E96434302EBA58) |
| 47 | `9002E01C0A23349E46B0C3F104FEFFFA53645762` | [View](https://metrics.torproject.org/rs.html#details/9002E01C0A23349E46B0C3F104FEFFFA53645762) |
| 48 | `9019CB92C4945631BF1953AEF56E8FD739EFDF1F` | [View](https://metrics.torproject.org/rs.html#details/9019CB92C4945631BF1953AEF56E8FD739EFDF1F) |
| 49 | `935FF2F8954267EF2854A67955E2A82F8D833045` | [View](https://metrics.torproject.org/rs.html#details/935FF2F8954267EF2854A67955E2A82F8D833045) |
| 50 | `964E22185B7D1E97B3DE6A65596A201816464244` | [View](https://metrics.torproject.org/rs.html#details/964E22185B7D1E97B3DE6A65596A201816464244) |
| 51 | `9C34AEE75142BE6CCE779FD8C07E5609ECEECBE5` | [View](https://metrics.torproject.org/rs.html#details/9C34AEE75142BE6CCE779FD8C07E5609ECEECBE5) |
| 52 | `9E2E162267A5F615AD8942EBAF90DC4297BC3D72` | [View](https://metrics.torproject.org/rs.html#details/9E2E162267A5F615AD8942EBAF90DC4297BC3D72) |
| 53 | `A0F2BD66095E58E865807E31FEA404842B168E30` | [View](https://metrics.torproject.org/rs.html#details/A0F2BD66095E58E865807E31FEA404842B168E30) |
| 54 | `A3E6C31A5D2A0F3DB1953415C30470504CF902B1` | [View](https://metrics.torproject.org/rs.html#details/A3E6C31A5D2A0F3DB1953415C30470504CF902B1) |
| 55 | `A73407217CE5E42B687BA383112C6A86AFCF128F` | [View](https://metrics.torproject.org/rs.html#details/A73407217CE5E42B687BA383112C6A86AFCF128F) |
| 56 | `A790090AC5AEBC79EAA000C5C698F0149F96E120` | [View](https://metrics.torproject.org/rs.html#details/A790090AC5AEBC79EAA000C5C698F0149F96E120) |
| 57 | `B17B88B1CD132D713B4B70366D61DA2C41A1ACC5` | [View](https://metrics.torproject.org/rs.html#details/B17B88B1CD132D713B4B70366D61DA2C41A1ACC5) |
| 58 | `B1CEFD88EE34C0B5611FF044D61C695D1E178B61` | [View](https://metrics.torproject.org/rs.html#details/B1CEFD88EE34C0B5611FF044D61C695D1E178B61) |
| 59 | `B3C3F80B5135DC58C4C2EAD051607FC61E85B339` | [View](https://metrics.torproject.org/rs.html#details/B3C3F80B5135DC58C4C2EAD051607FC61E85B339) |
| 60 | `B9C35B4EEF3175172D7E066D6182248E5C668DE8` | [View](https://metrics.torproject.org/rs.html#details/B9C35B4EEF3175172D7E066D6182248E5C668DE8) |
| 61 | `C03929407052808E6C653A761C34CF341F7AB20A` | [View](https://metrics.torproject.org/rs.html#details/C03929407052808E6C653A761C34CF341F7AB20A) |
| 62 | `C03C107CFE7D23FD335D3DCEA64C50D659E411C3` | [View](https://metrics.torproject.org/rs.html#details/C03C107CFE7D23FD335D3DCEA64C50D659E411C3) |
| 63 | `C1BC46E87DD5F00C7F118103F26D126631D9220A` | [View](https://metrics.torproject.org/rs.html#details/C1BC46E87DD5F00C7F118103F26D126631D9220A) |
| 64 | `C30AA591DB2EFCDFAD534B64D839C6864EAA1ECF` | [View](https://metrics.torproject.org/rs.html#details/C30AA591DB2EFCDFAD534B64D839C6864EAA1ECF) |
| 65 | `C4C808272FB6D648EDA24949D26832E8933DB334` | [View](https://metrics.torproject.org/rs.html#details/C4C808272FB6D648EDA24949D26832E8933DB334) |
| 66 | `C55C1FD8D89EE59DEC685E472B0824B48C94D4AE` | [View](https://metrics.torproject.org/rs.html#details/C55C1FD8D89EE59DEC685E472B0824B48C94D4AE) |
| 67 | `C7CBB1D0CA7CC7805C258ACD8FAF3D1FA64FB835` | [View](https://metrics.torproject.org/rs.html#details/C7CBB1D0CA7CC7805C258ACD8FAF3D1FA64FB835) |
| 68 | `CEAC921D73D3B431DD969545B30DD32B687DB0AF` | [View](https://metrics.torproject.org/rs.html#details/CEAC921D73D3B431DD969545B30DD32B687DB0AF) |
| 69 | `D9991DC0A994D93F88CAE7D641F94A04194F9872` | [View](https://metrics.torproject.org/rs.html#details/D9991DC0A994D93F88CAE7D641F94A04194F9872) |
| 70 | `D9B8761D9D553B08716E0A24AEBF7D5808E175BF` | [View](https://metrics.torproject.org/rs.html#details/D9B8761D9D553B08716E0A24AEBF7D5808E175BF) |
| 71 | `DD8087B74C736C51013BA69635A11F0642F8E51F` | [View](https://metrics.torproject.org/rs.html#details/DD8087B74C736C51013BA69635A11F0642F8E51F) |
| 72 | `DE2558BCEE2BD7B3E148FEB7DCB394FEDA64113F` | [View](https://metrics.torproject.org/rs.html#details/DE2558BCEE2BD7B3E148FEB7DCB394FEDA64113F) |
| 73 | `DF5152157BFF60455E6E02486F4CAB856FC376B6` | [View](https://metrics.torproject.org/rs.html#details/DF5152157BFF60455E6E02486F4CAB856FC376B6) |
| 74 | `E28F6BE58CADF14BF0A8B4F4079BABE3D113B6F8` | [View](https://metrics.torproject.org/rs.html#details/E28F6BE58CADF14BF0A8B4F4079BABE3D113B6F8) |
| 75 | `E397C2A7D3F294BD022EF09FAA68B5F5AB176D3B` | [View](https://metrics.torproject.org/rs.html#details/E397C2A7D3F294BD022EF09FAA68B5F5AB176D3B) |
| 76 | `EA91C1A796290359654A6A31443AFB72B8D8C65E` | [View](https://metrics.torproject.org/rs.html#details/EA91C1A796290359654A6A31443AFB72B8D8C65E) |
| 77 | `EB25CA31C2DA93E6E9AD99E66ECF717C803D3CA6` | [View](https://metrics.torproject.org/rs.html#details/EB25CA31C2DA93E6E9AD99E66ECF717C803D3CA6) |
| 78 | `F34A89F2FE1D2155A7749887107C51B2F8C4FF01` | [View](https://metrics.torproject.org/rs.html#details/F34A89F2FE1D2155A7749887107C51B2F8C4FF01) |
| 79 | `F41CE3D5B84A187AF09F11869327C5438C2CDA9F` | [View](https://metrics.torproject.org/rs.html#details/F41CE3D5B84A187AF09F11869327C5438C2CDA9F) |
| 80 | `F6BC74448939635E0040B2219A1DC4C49C825D50` | [View](https://metrics.torproject.org/rs.html#details/F6BC74448939635E0040B2219A1DC4C49C825D50) |
| 81 | `FDAA835B2657CA8B815817916920D23BDDA18B52` | [View](https://metrics.torproject.org/rs.html#details/FDAA835B2657CA8B815817916920D23BDDA18B52) |

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

| # | Fingerprint | Failure Reason | Metrics Link |
|---|-------------|----------------|--------------|
| 1 | `287A1C40B818DF6C45E8496CDE5026F11563CF10` | SOCKS Server error 4 | [View](https://metrics.torproject.org/rs.html#details/287A1C40B818DF6C45E8496CDE5026F11563CF10) |
| 2 | `C9CC8B881E2D7E8C44B895CA841C194621907603` | Socket timeout | [View](https://metrics.torproject.org/rs.html#details/C9CC8B881E2D7E8C44B895CA841C194621907603) |
| 3 | `CC0EB5E62E75E138283C233DAEBAA3615E1DC894` | SOCKS Server error 4 | [View](https://metrics.torproject.org/rs.html#details/CC0EB5E62E75E138283C233DAEBAA3615E1DC894) |
| 4 | `CDA71E2FAEE3F0A33DA344E254AF5E30A8926F88` | SOCKS Server error 4 | [View](https://metrics.torproject.org/rs.html#details/CDA71E2FAEE3F0A33DA344E254AF5E30A8926F88) |
| 5 | `D80F923E3F04A69485446AA7F70D55FD745E9086` | SOCKS Server error 4 | [View](https://metrics.torproject.org/rs.html#details/D80F923E3F04A69485446AA7F70D55FD745E9086) |
| 6 | `ED2E34869CCCBCE9321DEBBB957507A85A155CEF` | SOCKS Server error 4 | [View](https://metrics.torproject.org/rs.html#details/ED2E34869CCCBCE9321DEBBB957507A85A155CEF) |

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
- The high DNS failure rate for prsv.ch (45.5%) suggests a systematic DNS configuration issue across many of their relays
