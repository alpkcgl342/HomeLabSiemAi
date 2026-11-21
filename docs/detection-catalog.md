# Detection catalog

All detections map to [MITRE ATT&CK](https://attack.mitre.org/). The Suricata rules are
replay-tested in CI against a synthetic PCAP (`rules/tests/run_rule_tests.sh`), the Sigma rules
are validated with `sigma check`, and the analytics have unit tests with injected scenarios.

## Suricata (network signatures) - `rules/suricata/homenet.rules`

| SID | Detection | Technique | Tactic |
|---|---|---|---|
| 9100001 | Possible internal TCP SYN port scan | [T1046](https://attack.mitre.org/techniques/T1046/) | TA0007 |
| 9100002 | ICMP ping sweep on LAN | [T1018](https://attack.mitre.org/techniques/T1018/) | TA0007 |
| 9100003 | DNS query bypassing local resolver | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | TA0011 |
| 9100004 | DNS-over-HTTPS provider contacted (possible DNS bypass) | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | TA0011 |
| 9100014 | DNS-over-HTTPS provider contacted (possible DNS bypass) | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | TA0011 |
| 9100005 | Unusually long DNS query (possible tunneling) | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | TA0010 |
| 9100006 | DNS lookup of dynamic DNS / tunnel service | [T1568](https://attack.mitre.org/techniques/T1568/) | TA0011 |
| 9100007 | Inbound Telnet attempt to home device | [T1190](https://attack.mitre.org/techniques/T1190/) | TA0001 |
| 9100008 | Inbound remote access/SMB port reachable from internet | [T1133](https://attack.mitre.org/techniques/T1133/) | TA0001 |
| 9100009 | Possible SSH brute force | [T1110](https://attack.mitre.org/techniques/T1110/) | TA0006 |
| 9100010 | SSDP/UPnP request from internet | [T1190](https://attack.mitre.org/techniques/T1190/) | TA0001 |
| 9100011 | Cleartext FTP password sent | [T1552](https://attack.mitre.org/techniques/T1552/) | TA0006 |
| 9100012 | Windows executable downloaded over plain HTTP | [T1105](https://attack.mitre.org/techniques/T1105/) | TA0011 |
| 9100013 | Remote access tool (AnyDesk) connection | [T1219](https://attack.mitre.org/techniques/T1219/) | TA0011 |
| 9100015 | Remote access tool (TeamViewer) connection | [T1219](https://attack.mitre.org/techniques/T1219/) | TA0011 |
| 9100016 | Cryptomining Stratum protocol detected | [T1496](https://attack.mitre.org/techniques/T1496/) | TA0040 |
| 9100017 | Possible Tor connection | [T1090.003](https://attack.mitre.org/techniques/T1090/003/) | TA0011 |
| 9100018 | Outbound Telnet/SMB to internet | [T1021](https://attack.mitre.org/techniques/T1021/) | TA0008 |

## Sigma (Zeek logs) - `rules/sigma/zeek/`

| Rule | Log source | Level | Technique |
|---|---|---|---|
| [Large Single Upload to Internet (Possible Exfiltration)](../rules/sigma/zeek/zeek_conn_large_upload.yml) | zeek/conn | medium | [T1048](https://attack.mitre.org/techniques/T1048/) |
| [Outbound Connection to Port Commonly Used by Malware](../rules/sigma/zeek/zeek_conn_outbound_suspicious_port.yml) | zeek/conn | medium | [T1571](https://attack.mitre.org/techniques/T1571/) |
| [Device With Offensive-Security OS Hostname Joined Network](../rules/sigma/zeek/zeek_dhcp_offensive_os_hostname.yml) | zeek/dhcp | medium | [T1200](https://attack.mitre.org/techniques/T1200/) |
| [DNS Lookup of Cryptocurrency Mining Pool](../rules/sigma/zeek/zeek_dns_crypto_mining_pool.yml) | zeek/dns | high | [T1496](https://attack.mitre.org/techniques/T1496/) |
| [DNS Lookup of Dynamic DNS or Tunnelling Service](../rules/sigma/zeek/zeek_dns_dynamic_dns_or_tunnel_service.yml) | zeek/dns | medium | [T1568](https://attack.mitre.org/techniques/T1568/) |
| [Long Random TXT DNS Query (Possible DNS Tunneling)](../rules/sigma/zeek/zeek_dns_long_txt_query.yml) | zeek/dns | high | [T1071.004](https://attack.mitre.org/techniques/T1071/004/), [T1048](https://attack.mitre.org/techniques/T1048/) |
| [Executable or Script Downloaded From Raw IP Address](../rules/sigma/zeek/zeek_http_executable_from_raw_ip.yml) | zeek/http | high | [T1105](https://attack.mitre.org/techniques/T1105/) |
| [Scripting Tool User-Agent From Home Device](../rules/sigma/zeek/zeek_http_scripting_user_agent.yml) | zeek/http | low | [T1105](https://attack.mitre.org/techniques/T1105/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |

## Behavioural analytics - `ai-assistant/homesiem/analytics/`

| Detector | Idea | Default threshold | Technique |
|---|---|---|---|
| Beaconing | Connections from one host to one external host:port at a near-constant interval (coefficient of variation of the gaps) | ≥ 12 connections, CV ≤ 0.15, spanning ≥ 1 h | [T1071](https://attack.mitre.org/techniques/T1071/), [T1573](https://attack.mitre.org/techniques/T1573/) |
| DNS tunneling | Many unique, long, high-entropy sub-domains under one parent domain | ≥ 30 sub-domains, entropy ≥ 3.8, ≥ 50 % random | [T1071.004](https://attack.mitre.org/techniques/T1071/004/), [T1048](https://attack.mitre.org/techniques/T1048/) |
| Port scan / sweep | Distinct host:port pairs per source in a sliding window | ≥ 40 in 5 min | [T1046](https://attack.mitre.org/techniques/T1046/), [T1018](https://attack.mitre.org/techniques/T1018/) |
| Large / night upload | Outbound bytes per host→destination, extra weight between 01:00-05:59 local | ≥ 500 MB | [T1048](https://attack.mitre.org/techniques/T1048/), [T1567](https://attack.mitre.org/techniques/T1567/) |
| Rogue device | DHCP MAC not in `assets.yaml`; randomised (privacy) MACs get lower severity | any | [T1200](https://attack.mitre.org/techniques/T1200/) |
| Host anomaly (ML) | Isolation Forest on hourly per-host features (connections, bytes, unique destinations/ports, external ratio, night flag) | contamination 2 % | - |

All thresholds are configurable in `config/config.yaml`.
