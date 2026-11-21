#!/usr/bin/env python3
"""Anonymise JSON-lines logs (Zeek, Suricata eve.json, findings) before sharing them.

NEVER push real home-network logs to GitHub. This script replaces, consistently
across all files (same input -> same pseudonym, so analysis still works):

* IPv4 addresses   private -> 10.99.x.y      public -> 198.18.x.y (RFC 2544 benchmark range)
* MAC addresses    -> 02:xx:xx:xx:xx:xx (locally administered, hashed)
* host names       DHCP/host fields -> host-<hash>
* (optional) DNS names with --hash-domains -> <hash>.example

Usage:
    python scripts/sanitize_logs.py --key "my-secret" -o sanitized/ so-logs/zeek/*.log so-logs/suricata/eve.json
The key makes the mapping non-reversible for others; keep it private and constant.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import re
import sys
from pathlib import Path

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
HOST_FIELDS = {"host_name", "hostname", "client_fqdn", "domain", "host.hostname", "dhcp.hostname"}
LAN_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                              "169.254.0.0/16", "100.64.0.0/10")]
DNS_FIELDS = {"query", "server_name", "host", "dns.query.name", "rrname"}


class Sanitizer:
    def __init__(self, key: str, hash_domains: bool = False):
        self.key = key.encode()
        self.hash_domains = hash_domains

    def _h(self, value: str, n: int = 4) -> bytes:
        return hmac.new(self.key, value.encode(), hashlib.sha256).digest()[:n]

    def ip(self, m: re.Match) -> str:
        s = m.group(0)
        try:
            addr = ipaddress.ip_address(s)
        except ValueError:
            return s
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast or str(addr) == "255.255.255.255":
            return s
        h = self._h(s)
        is_lan = any(addr in n for n in LAN_NETS)
        return f"10.99.{h[0]}.{h[1]}" if is_lan else f"198.18.{h[0] & 1}.{h[1]}"

    def mac(self, m: re.Match) -> str:
        h = self._h(m.group(0).lower().replace("-", ":"), 5)
        return "02:" + ":".join(f"{b:02x}" for b in h)

    def text(self, s: str) -> str:
        return MAC.sub(self.mac, IPV4.sub(self.ip, s))

    def walk(self, obj, key: str = ""):
        if isinstance(obj, dict):
            return {k: self.walk(v, k) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.walk(v, key) for v in obj]
        if isinstance(obj, str):
            if key in HOST_FIELDS and obj:
                return "host-" + self._h(obj.lower()).hex()
            if self.hash_domains and key in DNS_FIELDS and "." in obj and not IPV4.fullmatch(obj):
                return self._h(obj.lower(), 6).hex() + ".example"
            return self.text(obj)
        return obj


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("files", nargs="+", type=Path)
    p.add_argument("-o", "--out-dir", type=Path, required=True)
    p.add_argument("--key", required=True, help="secret used for the keyed hash")
    p.add_argument("--hash-domains", action="store_true", help="also pseudonymise DNS/TLS/HTTP names")
    args = p.parse_args()

    s = Sanitizer(args.key, args.hash_domains)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for f in args.files:
        out = args.out_dir / f.name
        n = 0
        with f.open(encoding="utf-8", errors="replace") as src, out.open("w", encoding="utf-8") as dst:
            for line in src:
                line = line.strip()
                if not line:
                    continue
                try:
                    dst.write(json.dumps(s.walk(json.loads(line))) + "\n")
                except json.JSONDecodeError:
                    dst.write(s.text(line) + "\n")
                n += 1
        print(f"{f} -> {out} ({n} lines)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
