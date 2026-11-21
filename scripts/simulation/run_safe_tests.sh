#!/usr/bin/env bash
# =============================================================================
#  Safe detection tests for YOUR OWN home network.
#  Run from a Linux machine (or Kali VM) on the monitored LAN, then check
#  Security Onion -> Alerts. Every test is harmless: no exploit, no malware,
#  no traffic to third-party systems beyond normal HTTPS/DNS requests.
#
#    TARGET=192.168.1.40 scripts/simulation/run_safe_tests.sh [test ...]
#
#  Only scan devices you own. Scanning other people's networks is illegal
#  (TR: 5237 TCK md. 243-244, EU/US equivalents).
# =============================================================================
set -uo pipefail
TARGET="${TARGET:?set TARGET to one of YOUR devices, e.g. TARGET=192.168.1.40}"
SUBNET="${SUBNET:-$(echo "$TARGET" | cut -d. -f1-3).0/24}"
need() { command -v "$1" >/dev/null || { echo "missing tool: $1"; return 1; }; }
banner() { printf '\n\033[1;36m==> %s\033[0m  (expect: %s)\n' "$1" "$2"; }

t_ids_sanity() {
  banner "IDS sanity check (testmynids.org)" "ET/GPL 'id check returned root' (sid 2100498)"
  curl -s --max-time 10 http://testmynids.org/uid/index.html >/dev/null
}
t_portscan() {
  need nmap || return
  banner "TCP SYN port scan of $TARGET" "sid 9100001 + analytics:port_scan"
  sudo nmap -sS -T4 -p 1-1024 "$TARGET" >/dev/null
}
t_pingsweep() {
  need nmap || return
  banner "ICMP sweep of $SUBNET" "sid 9100002"
  sudo nmap -sn -PE "$SUBNET" >/dev/null
}
t_ssh_bruteforce() {
  banner "15 SSH connection attempts to $TARGET" "sid 9100009"
  for _ in $(seq 15); do timeout 2 bash -c "exec 3<>/dev/tcp/$TARGET/22" 2>/dev/null; done
}
t_dns_bypass() {
  need dig || return
  banner "DNS query straight to 1.1.1.1" "sid 9100003"
  dig +short @1.1.1.1 example.com >/dev/null
}
t_doh() {
  banner "DNS-over-HTTPS request" "sid 9100004"
  curl -s --max-time 10 -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name=example.com' >/dev/null
}
t_dns_tunnel() {
  need dig || return
  banner "Simulated DNS tunneling (80 random TXT queries, NXDOMAIN)" "sid 9100005 + analytics:dns + Sigma TXT rule"
  for i in $(seq 80); do
    chunk=$(head -c 48 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 64)
    dig +short +tries=1 +time=1 TXT "${chunk:0:40}.${chunk:40}.$i.tunnel-test.example" >/dev/null
  done
}
t_dyndns() {
  need dig || return
  banner "Dynamic DNS lookup" "sid 9100006 + Sigma dynamic DNS rule"
  dig +short homesiem-test.duckdns.org >/dev/null
}
t_remote_tool() {
  banner "HTTPS to anydesk.com (just the homepage)" "sid 9100013"
  curl -s --max-time 10 https://anydesk.com >/dev/null
}
t_beacon() {
  banner "Beacon simulation: 15 requests every 30 s to example.com (7.5 min)" "analytics:beaconing (set min_duration_s: 300 to see it)"
  for _ in $(seq 15); do curl -s --max-time 5 https://example.com >/dev/null; sleep 30; done
}

ALL=(ids_sanity portscan pingsweep ssh_bruteforce dns_bypass doh dns_tunnel dyndns remote_tool)
TESTS=("${@:-${ALL[@]}}")
echo "Target: $TARGET   Subnet: $SUBNET   Tests: ${TESTS[*]}"
read -r -p "These devices are mine and I am allowed to test them [y/N] " ok
[[ "$ok" =~ ^[yY]$ ]] || exit 1
for t in "${TESTS[@]}"; do "t_$t"; done
echo -e "\nDone. Wait ~1-2 min, then open Security Onion -> Alerts and run: homesiem analyze"
