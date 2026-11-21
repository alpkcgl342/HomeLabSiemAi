"""Port scans, large/odd-hour uploads and unknown devices."""
from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable
from pathlib import Path

import logging

import yaml

from ..models import Conn, DhcpLease, Finding

log = logging.getLogger(__name__)


def detect_port_scans(conns: list[Conn], cfg: dict) -> list[Finding]:
    """Many distinct destination ports (or hosts) touched by one source in a short window."""
    by_src: dict[str, list[Conn]] = defaultdict(list)
    for c in conns:
        by_src[c.src_ip].append(c)

    window = cfg["window_s"]
    findings = []
    for src, items in by_src.items():
        items.sort(key=lambda c: c.ts)
        best: tuple[int, int, int] = (0, 0, 0)  # (unique ports, start idx, end idx)
        left = 0
        in_window: Counter = Counter()  # sliding window, O(n) per source
        for right, c in enumerate(items):
            in_window[(c.dst_ip, c.dst_port)] += 1
            while (c.ts - items[left].ts).total_seconds() > window:
                key = (items[left].dst_ip, items[left].dst_port)
                in_window[key] -= 1
                if in_window[key] == 0:
                    del in_window[key]
                left += 1
            if len(in_window) > best[0]:
                best = (len(in_window), left, right)
        if best[0] < cfg["min_unique_ports"]:
            continue
        chunk = items[best[1]:best[2] + 1]
        targets = sorted({c.dst_ip for c in chunk})
        failed = sum(1 for c in chunk if c.conn_state in {"S0", "REJ", "RSTOS0", "RSTR"})
        kind = "Host sweep" if len(targets) > 10 else "Port scan"
        findings.append(Finding(
            id=f"scan-{src}",
            title=f"{kind} from {src}: {best[0]} host:port pairs in {window // 60} min",
            severity="high" if best[0] > 200 else "medium",
            source="analytics:port_scan",
            host=src,
            first_seen=chunk[0].ts,
            last_seen=chunk[-1].ts,
            count=len(chunk),
            mitre=["T1046"] if kind == "Port scan" else ["T1018", "T1046"],
            evidence={
                "unique_targets": best[0],
                "target_hosts": targets[:15],
                "failed_or_rejected": failed,
            },
        ))
    return findings


def detect_exfiltration(conns: list[Conn], cfg: dict, night_hours: list[int],
                        is_home: Callable[[str], bool], tz=None) -> list[Finding]:
    """Large outbound volume per host->external pair; extra weight at night."""
    totals: dict[tuple[str, str], list[Conn]] = defaultdict(list)
    for c in conns:
        if is_home(c.src_ip) and not is_home(c.dst_ip):
            totals[(c.src_ip, c.dst_ip)].append(c)

    start_h, end_h = night_hours
    findings = []
    for (src, dst), items in totals.items():
        out = sum(c.orig_bytes for c in items)
        if out < cfg["min_bytes_out"]:
            continue
        night = sum(c.orig_bytes for c in items if start_h <= c.ts.astimezone(tz).hour <= end_h)
        ratio = out / max(1, sum(c.resp_bytes for c in items))
        items.sort(key=lambda c: c.ts)
        findings.append(Finding(
            id=f"exfil-{src}-{dst}",
            title=f"Large upload: {out / 1e9:.2f} GB from {src} to {dst}"
                  + (" (mostly at night)" if night > out / 2 else ""),
            severity="high" if night > out / 2 else "medium",
            source="analytics:exfil",
            host=src,
            first_seen=items[0].ts,
            last_seen=items[-1].ts,
            count=len(items),
            mitre=["T1048", "T1567"],
            evidence={
                "dest_ip": dst,
                "bytes_out": out,
                "night_bytes_out": night,
                "upload_download_ratio": round(ratio, 1),
                "dest_ports": sorted({c.dst_port for c in items})[:10],
            },
        ))
    return findings


def load_assets(path: str | None) -> dict[str, dict]:
    if not path or not Path(path).exists():
        return {}
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return {d["mac"].lower(): d for d in data.get("devices", []) if d.get("mac")}


def detect_new_devices(leases: list[DhcpLease], assets_file: str | None) -> list[Finding]:
    """Any MAC seen via DHCP that is not in the asset inventory (assets.yaml)."""
    known = load_assets(assets_file)
    if not known:
        log.warning("No asset inventory at %s - new-device detection skipped "
                    "(copy assets.example.yaml to assets.yaml)", assets_file)
        return []  # without an inventory every device would be "new"
    seen: dict[str, list[DhcpLease]] = defaultdict(list)
    for l in leases:
        if l.mac not in known:
            seen[l.mac].append(l)
    findings = []
    for mac, items in seen.items():
        items.sort(key=lambda l: l.ts)
        last = items[-1]
        # Locally administered bit => randomised MAC (modern phones do this per network)
        randomised = int(mac.split(":")[0], 16) & 0b10 != 0 if ":" in mac else False
        findings.append(Finding(
            id=f"newdevice-{mac}",
            title=f"Unknown device joined the network: {last.hostname or 'no hostname'} ({mac})",
            severity="low" if randomised else "medium",
            source="analytics:new_devices",
            host=last.ip,
            first_seen=items[0].ts,
            last_seen=last.ts,
            count=len(items),
            mitre=["T1200"],
            evidence={"mac": mac, "ip": last.ip, "hostname": last.hostname,
                      "randomised_mac": randomised},
        ))
    return findings
