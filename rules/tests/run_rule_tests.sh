#!/usr/bin/env bash
# Replays a synthetic PCAP through Suricata and checks that every custom rule fired.
# Usage: rules/tests/run_rule_tests.sh   (needs suricata + python3 scapy)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
RULES="$ROOT/rules/suricata/homenet.rules"
SURICATA_ARGS=(-c "${SURICATA_YAML:-/etc/suricata/suricata.yaml}" -S "$RULES" -l "$WORK"
  --set 'vars.address-groups.HOME_NET=[192.168.1.0/24]'
  --set 'vars.address-groups.EXTERNAL_NET=!$HOME_NET'
  --set 'vars.address-groups.DNS_SERVERS=[192.168.1.1]'
  -k none)

echo "[1/3] Syntax check"
suricata -T "${SURICATA_ARGS[@]}" >/dev/null

echo "[2/3] Building test PCAP"
python3 "$ROOT/rules/tests/make_test_pcap.py" "$WORK/test.pcap"

echo "[3/3] Replaying PCAP"
suricata "${SURICATA_ARGS[@]}" -r "$WORK/test.pcap" >/dev/null 2>&1

expected=$(grep -oE 'sid:[0-9]+' "$RULES" | cut -d: -f2 | sort -u)
fired=$(grep -oE '\[1:[0-9]+:' "$WORK/fast.log" | cut -d: -f2 | sort -u || true)
missing=$(comm -23 <(echo "$expected") <(echo "$fired"))
echo
echo "Rules: $(echo "$expected" | wc -l)  fired: $(echo "$fired" | grep -c . || true)"
if [[ -n "$missing" ]]; then
  echo "NOT FIRED:"; for s in $missing; do grep -oE "msg:\"[^\"]+\"; .*sid:$s;" "$RULES" | cut -d'"' -f2 | sed "s/^/  $s  /"; done
  exit 1
fi
echo "All custom rules fired ✔"
