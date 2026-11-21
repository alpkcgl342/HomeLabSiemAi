# Testing the detections

A rule you have never seen fire is a rule you can't trust. This project tests detections at three levels.

## 1. Offline / CI (no network needed)

| What | Command | Proves |
|---|---|---|
| Suricata syntax + replay | `rules/tests/run_rule_tests.sh` | Every SID loads in Suricata 7 **and fires** on a synthetic PCAP built with Scapy (`rules/tests/make_test_pcap.py`) |
| Sigma | `sigma check rules/sigma` | Rules follow the Sigma spec and convert to Elasticsearch/Lucene |
| Analytics + AI plumbing | `cd ai-assistant && python -m pytest -q` | All five injected attack scenarios are found, no beaconing false positive on normal devices, both report languages render, LLM JSON handling |

Quick end-to-end check from **Windows** (PowerShell) - no Linux machine needed:

```powershell
curl.exe -A "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)" http://example.com
```

Within 1-2 minutes Security Onion → *Alerts* shows **ET SCAN Possible Nmap User-Agent Observed**
(sid 2024364). This proves capture → Suricata → Elasticsearch → SOC works. (The classic
`testmynids.org` check no longer works - the domain expired.)

Expected output of the replay test:

```
Rules: 18  fired: 18
All custom rules fired ✔
```

## 2. Live, on your own LAN

`scripts/simulation/run_safe_tests.sh` generates harmless traffic from a Linux machine
on the monitored network (nmap scan of **your** NAS, SSH attempts, DoH request, random TXT
lookups, ...). It asks for confirmation first.

```bash
TARGET=192.168.1.40 scripts/simulation/run_safe_tests.sh            # all tests
TARGET=192.168.1.40 scripts/simulation/run_safe_tests.sh portscan doh # selected tests
```

Then check, in this order:

1. Security Onion → *Alerts*: the `HOMENET ...` alerts appear within 1-2 minutes.
2. Security Onion → *Hunt*: `event.dataset:dns AND dns.query.name:*tunnel-test.example` shows the Zeek side.
3. `homesiem analyze` → the report lists the scenario with a risk score and recommended action.

Record the results in the table below for your project report:

| Test | Suricata alert? | Sigma alert? | Analytics finding? | AI risk | Notes / tuning |
|---|---|---|---|---|---|
| portscan | | – | | | |
| pingsweep | | – | – | | |
| ssh_bruteforce | | – | – | | |
| dns_bypass | | – | – | | |
| doh | | – | – | | |
| dns_tunnel | | | | | |
| dyndns | | | – | | |
| remote_tool | | – | – | | |
| ids_sanity (ET) | | – | – | | |

## 3. Tuning false positives

After a week of normal family use you will see noise (smart TVs that beacon to their vendor,
cloud backups that look like exfiltration). Tune instead of disabling:

* Suricata: *Detections → rule → Tuning* (threshold/suppress by IP).
* Sigma: add a `filter_...` block, e.g. the NAS's backup destination.
* Analytics: raise thresholds in `config/config.yaml` or add the device to `assets.yaml`.

Document every tuning decision - it's one of the most valuable parts of the project write-up.
