> Example output of `homesiem demo` on synthetic data (rule-based triage, Ollama offline). With Ollama running, the summary and analysis columns are written by the LLM.

# Home Network Security Report

| | |
|---|---|
| **Period** | 2026-11-18 12:00 → 2026-11-21 11:59 |
| **Generated** | 2026-11-21 12:34 UTC |
| **AI model** | rule-based fallback (Ollama offline) |

## Executive summary

**15 findings** across 5 host(s). Highest risk: Periodic beaconing from 192.168.1.30 to 203.0.113.66:8443 every ~300s.
- Identify the device and the destination (whois/VirusTotal); block it on the router if unknown.
- Check which process on the host makes these queries; block the parent domain in Pi-hole/router DNS.
- Confirm whether you ran a scan; otherwise isolate the device and check it for malware.

_AI summary unavailable (Ollama offline) - rule-based summary shown._

## Overview

| Metric | Value |
|---|---:|
| Connections | 12,989 |
| DNS queries | 11,132 |
| DHCP leases | 6 |
| Suricata alerts (deduplicated) | 6 |
| Total findings | 15 |
| Internal hosts seen | 6 |

### Findings by severity

| critical | high | medium | low | info |
|---:|---:|---:|---:|---:|
| 0 | 6 | 8 | 1 | 0 |

## Findings

| # | Risk | Severity | Finding | Host | Source | MITRE |
|---:|:---:|---|---|---|---|---|
| 1 | **8**/10 | high | Port scan from 192.168.1.66: 1031 host:port pairs in 5 min | 192.168.1.66 | analytics:port_scan | [T1046](https://attack.mitre.org/techniques/T1046/) |
| 2 | **8**/10 | high | Periodic beaconing from 192.168.1.30 to 203.0.113.66:8443 every ~300s | 192.168.1.30 | analytics:beaconing | [T1071](https://attack.mitre.org/techniques/T1071/), [T1573](https://attack.mitre.org/techniques/T1573/) |
| 3 | **8**/10 | high | Possible DNS tunneling from 192.168.1.10 via *.cdn-sync.example | 192.168.1.10 | analytics:dns | [T1071.004](https://attack.mitre.org/techniques/T1071/004/), [T1048](https://attack.mitre.org/techniques/T1048/) |
| 4 | **7**/10 | high | Large upload: 2.40 GB from 192.168.1.40 to 198.51.100.200 (mostly at night) | 192.168.1.40 | analytics:exfil | [T1048](https://attack.mitre.org/techniques/T1048/), [T1567](https://attack.mitre.org/techniques/T1567/) |
| 5 | **7**/10 | high | HOMENET Inbound Telnet attempt to home device | 203.0.113.9 | suricata | [T1190](https://attack.mitre.org/techniques/T1190/) |
| 6 | **7**/10 | high | HOMENET Possible SSH brute force | 192.168.1.66 | suricata | [T1110](https://attack.mitre.org/techniques/T1110/) |
| 7 | **5**/10 | medium | HOMENET Unusually long DNS query (possible tunneling) | 192.168.1.10 | suricata | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) |
| 8 | **5**/10 | medium | Unusual traffic profile for 192.168.1.20 (4 anomalous hour(s)) | 192.168.1.20 | analytics:anomaly | - |
| 9 | **5**/10 | medium | Unusual traffic profile for 192.168.1.30 (2 anomalous hour(s)) | 192.168.1.30 | analytics:anomaly | - |
| 10 | **5**/10 | medium | HOMENET Remote access tool (AnyDesk) connection | 192.168.1.10 | suricata | [T1219](https://attack.mitre.org/techniques/T1219/) |
| 11 | **5**/10 | medium | HOMENET Possible internal TCP SYN port scan | 192.168.1.66 | suricata | [T1046](https://attack.mitre.org/techniques/T1046/) |
| 12 | **5**/10 | medium | Unknown device joined the network: kali (3c:22:fb:66:00:66) | 192.168.1.66 | analytics:new_devices | [T1200](https://attack.mitre.org/techniques/T1200/) |
| 13 | **5**/10 | medium | Unusual traffic profile for 192.168.1.40 (1 anomalous hour(s)) | 192.168.1.40 | analytics:anomaly | - |
| 14 | **5**/10 | medium | Unusual traffic profile for 192.168.1.66 (1 anomalous hour(s)) | 192.168.1.66 | analytics:anomaly | - |
| 15 | **3**/10 | low | HOMENET DNS-over-HTTPS provider contacted (possible DNS bypass) | 192.168.1.11 | suricata | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) |

## Details

### 1. Port scan from 192.168.1.66: 1031 host:port pairs in 5 min

- **Risk:** 8/10 · **Severity:** high · **Count:** 1031
- **Time:** 2026-11-21 09:15 → 2026-11-21 09:16
- **AI analysis:** One device probed many ports/hosts in a short time.
- **Recommended action:** Confirm whether you ran a scan; otherwise isolate the device and check it for malware.

<details><summary>Evidence</summary>

```json
{
  "unique_targets": 1031,
  "target_hosts": [
    "192.168.1.40"
  ],
  "failed_or_rejected": 1031
}
```
</details>

### 2. Periodic beaconing from 192.168.1.30 to 203.0.113.66:8443 every ~300s

- **Risk:** 8/10 · **Severity:** high · **Count:** 841
- **Time:** 2026-11-18 14:00 → 2026-11-21 11:58
- **AI analysis:** Regular, machine-like connections to one external server - typical of malware check-ins, but also of update/telemetry agents.
- **Recommended action:** Identify the device and the destination (whois/VirusTotal); block it on the router if unknown.

<details><summary>Evidence</summary>

```json
{
  "dest_ip": "203.0.113.66",
  "dest_port": 8443,
  "mean_interval_s": 299.9,
  "coefficient_of_variation": 0.011,
  "avg_bytes_out": 320
}
```
</details>

### 3. Possible DNS tunneling from 192.168.1.10 via *.cdn-sync.example

- **Risk:** 8/10 · **Severity:** high · **Count:** 420
- **Time:** 2026-11-20 02:00 → 2026-11-20 02:17
- **AI analysis:** Many random-looking sub-domains under one domain - a classic sign of DNS tunneling or DGA malware.
- **Recommended action:** Check which process on the host makes these queries; block the parent domain in Pi-hole/router DNS.

<details><summary>Evidence</summary>

```json
{
  "parent_domain": "cdn-sync.example",
  "unique_subdomains": 420,
  "high_entropy_ratio": 0.64,
  "avg_entropy": 3.87,
  "txt_queries": 420,
  "example": "0151052a8626b2c33d82710ae90ec9.c9ada3fc1adb00f23d.147.t.cdn-sync.example"
}
```
</details>

### 4. Large upload: 2.40 GB from 192.168.1.40 to 198.51.100.200 (mostly at night)

- **Risk:** 7/10 · **Severity:** high · **Count:** 45
- **Time:** 2026-11-19 03:00 → 2026-11-19 03:44
- **AI analysis:** A device uploaded an unusually large amount of data to the internet.
- **Recommended action:** Verify it is a known backup/sync job; if not, disconnect the device and investigate.

<details><summary>Evidence</summary>

```json
{
  "dest_ip": "198.51.100.200",
  "bytes_out": 2403231965,
  "night_bytes_out": 2403231965,
  "upload_download_ratio": 180.6,
  "dest_ports": [
    443
  ]
}
```
</details>

### 5. HOMENET Inbound Telnet attempt to home device

- **Risk:** 7/10 · **Severity:** high · **Count:** 1
- **Time:** 2026-11-18 17:00 → 2026-11-18 17:00
- **AI analysis:** Suricata signature matched network traffic.
- **Recommended action:** Open the alert in Security Onion (Alerts/Hunt), inspect the PCAP and tune or escalate.

<details><summary>Evidence</summary>

```json
{
  "sid": 9100007,
  "category": "Attempted Administrator Privilege Gain",
  "src_ip": "203.0.113.9",
  "dest_ip": "192.168.1.30",
  "dest_port": 23
}
```
</details>

### 6. HOMENET Possible SSH brute force

- **Risk:** 7/10 · **Severity:** high · **Count:** 1
- **Time:** 2026-11-21 09:16 → 2026-11-21 09:16
- **AI analysis:** Suricata signature matched network traffic.
- **Recommended action:** Open the alert in Security Onion (Alerts/Hunt), inspect the PCAP and tune or escalate.

<details><summary>Evidence</summary>

```json
{
  "sid": 9100009,
  "category": "Attempted Administrator Privilege Gain",
  "src_ip": "192.168.1.66",
  "dest_ip": "192.168.1.40",
  "dest_port": 22
}
```
</details>

### 7. HOMENET Unusually long DNS query (possible tunneling)

- **Risk:** 5/10 · **Severity:** medium · **Count:** 7
- **Time:** 2026-11-20 02:00 → 2026-11-20 02:15
- **AI analysis:** Suricata signature matched network traffic.
- **Recommended action:** Open the alert in Security Onion (Alerts/Hunt), inspect the PCAP and tune or escalate.

<details><summary>Evidence</summary>

```json
{
  "sid": 9100005,
  "category": "Potentially Bad Traffic",
  "src_ip": "192.168.1.10",
  "dest_ip": "192.168.1.1",
  "dest_port": 53,
  "dest_ips": [
    "192.168.1.1"
  ]
}
```
</details>

### 8. Unusual traffic profile for 192.168.1.20 (4 anomalous hour(s))

- **Risk:** 5/10 · **Severity:** medium · **Count:** 4
- **Time:** - → -
- **AI analysis:** This host's traffic deviates strongly from the normal pattern of your network.
- **Recommended action:** Review its connections for the listed hours in Security Onion Hunt.

<details><summary>Evidence</summary>

```json
{
  "worst_hour": "2026-11-20 08:00",
  "anomaly_score": 0.616,
  "top_reasons": [],
  "anomalous_hours": [
    "2026-11-20 08:00",
    "2026-11-20 05:00",
    "2026-11-20 04:00",
    "2026-11-19 03:00"
  ]
}
```
</details>

### 9. Unusual traffic profile for 192.168.1.30 (2 anomalous hour(s))

- **Risk:** 5/10 · **Severity:** medium · **Count:** 2
- **Time:** - → -
- **AI analysis:** This host's traffic deviates strongly from the normal pattern of your network.
- **Recommended action:** Review its connections for the listed hours in Security Onion Hunt.

<details><summary>Evidence</summary>

```json
{
  "worst_hour": "2026-11-20 20:00",
  "anomaly_score": 0.638,
  "top_reasons": [
    "bytes_in_mb=19.5 (network median 3.6)",
    "connections=82.0 (network median 36.0)",
    "unique_dsts=46.0 (network median 25.0)"
  ],
  "anomalous_hours": [
    "2026-11-20 20:00",
    "2026-11-19 03:00"
  ]
}
```
</details>

### 10. HOMENET Remote access tool (AnyDesk) connection

- **Risk:** 5/10 · **Severity:** medium · **Count:** 1
- **Time:** 2026-11-19 23:00 → 2026-11-19 23:00
- **AI analysis:** Suricata signature matched network traffic.
- **Recommended action:** Open the alert in Security Onion (Alerts/Hunt), inspect the PCAP and tune or escalate.

<details><summary>Evidence</summary>

```json
{
  "sid": 9100013,
  "category": "Potential Corporate Privacy Violation",
  "src_ip": "192.168.1.10",
  "dest_ip": "198.51.100.90",
  "dest_port": 443
}
```
</details>

### 11. HOMENET Possible internal TCP SYN port scan

- **Risk:** 5/10 · **Severity:** medium · **Count:** 1
- **Time:** 2026-11-21 09:16 → 2026-11-21 09:16
- **AI analysis:** Suricata signature matched network traffic.
- **Recommended action:** Open the alert in Security Onion (Alerts/Hunt), inspect the PCAP and tune or escalate.

<details><summary>Evidence</summary>

```json
{
  "sid": 9100001,
  "category": "Attempted Information Leak",
  "src_ip": "192.168.1.66",
  "dest_ip": "192.168.1.40",
  "dest_port": 445
}
```
</details>

### 12. Unknown device joined the network: kali (3c:22:fb:66:00:66)

- **Risk:** 5/10 · **Severity:** medium · **Count:** 1
- **Time:** 2026-11-21 09:13 → 2026-11-21 09:13
- **AI analysis:** A device not in your asset inventory joined the network.
- **Recommended action:** Identify it; add it to assets.yaml if legitimate or change the Wi-Fi password if not.

<details><summary>Evidence</summary>

```json
{
  "mac": "3c:22:fb:66:00:66",
  "ip": "192.168.1.66",
  "hostname": "kali",
  "randomised_mac": false
}
```
</details>

### 13. Unusual traffic profile for 192.168.1.40 (1 anomalous hour(s))

- **Risk:** 5/10 · **Severity:** medium · **Count:** 1
- **Time:** - → -
- **AI analysis:** This host's traffic deviates strongly from the normal pattern of your network.
- **Recommended action:** Review its connections for the listed hours in Security Onion Hunt.

<details><summary>Evidence</summary>

```json
{
  "worst_hour": "2026-11-19 03:00",
  "anomaly_score": 0.757,
  "top_reasons": [
    "bytes_out_mb=2403.3 (network median 0.2)",
    "bytes_in_mb=16.4 (network median 3.6)",
    "night=1.0 (network median 0.0)"
  ],
  "anomalous_hours": [
    "2026-11-19 03:00"
  ]
}
```
</details>

### 14. Unusual traffic profile for 192.168.1.66 (1 anomalous hour(s))

- **Risk:** 5/10 · **Severity:** medium · **Count:** 1
- **Time:** - → -
- **AI analysis:** This host's traffic deviates strongly from the normal pattern of your network.
- **Recommended action:** Review its connections for the listed hours in Security Onion Hunt.

<details><summary>Evidence</summary>

```json
{
  "worst_hour": "2026-11-21 09:00",
  "anomaly_score": 0.789,
  "top_reasons": [
    "unique_ports=1031.0 (network median 4.0)",
    "connections=1031.0 (network median 36.0)"
  ],
  "anomalous_hours": [
    "2026-11-21 09:00"
  ]
}
```
</details>

### 15. HOMENET DNS-over-HTTPS provider contacted (possible DNS bypass)

- **Risk:** 3/10 · **Severity:** low · **Count:** 3
- **Time:** 2026-11-19 08:00 → 2026-11-21 08:00
- **AI analysis:** Suricata signature matched network traffic.
- **Recommended action:** Open the alert in Security Onion (Alerts/Hunt), inspect the PCAP and tune or escalate.

<details><summary>Evidence</summary>

```json
{
  "sid": 9100004,
  "category": "Potential Corporate Privacy Violation",
  "src_ip": "192.168.1.11",
  "dest_ip": "198.51.100.77",
  "dest_port": 443,
  "dest_ips": [
    "198.51.100.77"
  ]
}
```
</details>


## Top talkers (internal hosts)

| Host | Connections | Out | In |
|---|---:|---:|---:|
| 192.168.1.40 | 2541 | 2.3 GB | 312.9 MB |
| 192.168.1.10 | 2668 | 15.6 MB | 296.0 MB |
| 192.168.1.30 | 3305 | 14.4 MB | 309.1 MB |
| 192.168.1.11 | 2488 | 13.3 MB | 275.9 MB |
| 192.168.1.20 | 956 | 5.1 MB | 104.7 MB |
| 192.168.1.66 | 1031 | 0 B | 0 B |

## Most queried domains

| Domain | Queries |
|---|---:|
| ntp.org | 769 |
| cloudflare.com | 768 |
| youtube.com | 745 |
| instagram.com | 738 |
| github.com | 735 |
| apple.com | 720 |
| hepsiburada.com | 716 |
| wikipedia.org | 715 |
| google.com | 709 |
| netflix.com | 695 |

## MITRE ATT&CK coverage

| Technique | Findings |
|---|---:|
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | 3 |
| [T1046](https://attack.mitre.org/techniques/T1046/) | 2 |
| [T1048](https://attack.mitre.org/techniques/T1048/) | 2 |
| [T1071](https://attack.mitre.org/techniques/T1071/) | 1 |
| [T1573](https://attack.mitre.org/techniques/T1573/) | 1 |
| [T1567](https://attack.mitre.org/techniques/T1567/) | 1 |
| [T1190](https://attack.mitre.org/techniques/T1190/) | 1 |
| [T1110](https://attack.mitre.org/techniques/T1110/) | 1 |
| [T1219](https://attack.mitre.org/techniques/T1219/) | 1 |
| [T1200](https://attack.mitre.org/techniques/T1200/) | 1 |

---
_Generated by homenet-siem-ai. AI output can be wrong - always verify in Security Onion._