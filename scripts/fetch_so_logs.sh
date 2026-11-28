#!/usr/bin/env bash
# (Linux/macOS; on Windows use scripts/fetch_so_logs.ps1)
# Copy the last N days of Zeek + Suricata logs from the Security Onion VM to ./so-logs
# so the AI assistant can analyse them in "files" mode.
#
#   SO_HOST=192.168.1.250 SO_USER=analyst DAYS=7 scripts/fetch_so_logs.sh
#
# Security Onion 2.4 keeps logs under /nsm (paths may differ slightly between versions;
# check with: sudo ls /nsm/zeek/logs /nsm/suricata). Your SO user needs sudo or read
# access to these folders; using an SSH key is recommended.
set -euo pipefail
SO_HOST="${SO_HOST:?set SO_HOST to the Security Onion IP}"
SO_USER="${SO_USER:-$USER}"
DAYS="${DAYS:-7}"
DEST="$(cd "$(dirname "$0")/.." && pwd)/so-logs"
mkdir -p "$DEST/zeek" "$DEST/suricata"

echo "Packing logs on $SO_HOST (last $DAYS days)..."
ssh "$SO_USER@$SO_HOST" "sudo bash -s" <<REMOTE
set -e
cd /nsm
find zeek/logs -type f \( -name 'conn*' -o -name 'dns*' -o -name 'dhcp*' \) -mtime -$DAYS > /tmp/homesiem.list
find suricata -maxdepth 2 -type f -name 'eve*.json*' -mtime -$DAYS >> /tmp/homesiem.list
tar czf /tmp/homesiem-logs.tgz -T /tmp/homesiem.list
chown $SO_USER /tmp/homesiem-logs.tgz
REMOTE

scp "$SO_USER@$SO_HOST:/tmp/homesiem-logs.tgz" "$DEST/"
ssh "$SO_USER@$SO_HOST" "rm -f /tmp/homesiem-logs.tgz /tmp/homesiem.list"
tar xzf "$DEST/homesiem-logs.tgz" -C "$DEST"
rm "$DEST/homesiem-logs.tgz"
# eve.json may be rotated into several files: merge them for the assistant
find "$DEST/suricata" -name 'eve*.json*' -print0 | sort -z | xargs -0 -I{} sh -c 'case "{}" in *.gz) zcat "{}";; *) cat "{}";; esac' > "$DEST/eve.merged.json"
echo "Done. Point config.yaml at:"
echo "  zeek_dir: ../so-logs/zeek"
echo "  suricata_eve: ../so-logs/eve.merged.json"
