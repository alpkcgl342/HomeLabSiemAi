"""C2 beaconing detection.

Malware often "phones home" at a fixed interval (e.g. every 60 s). Human traffic
is bursty. For each (internal host -> external host:port) pair we measure the
time between connections; a very low coefficient of variation (stddev / mean)
over many connections means machine-like regularity.
"""
from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Callable

from ..models import Conn, Finding


def detect_beaconing(conns: list[Conn], cfg: dict, is_home: Callable[[str], bool]) -> list[Finding]:
    groups: dict[tuple[str, str, int], list[Conn]] = defaultdict(list)
    for c in conns:
        if is_home(c.src_ip) and not is_home(c.dst_ip):
            groups[(c.src_ip, c.dst_ip, c.dst_port)].append(c)

    findings = []
    for (src, dst, port), items in groups.items():
        if len(items) < cfg["min_connections"]:
            continue
        items.sort(key=lambda c: c.ts)
        if (items[-1].ts - items[0].ts).total_seconds() < cfg.get("min_duration_s", 3600):
            continue  # a single burst (e.g. a backup job) is not beaconing
        deltas = [(b.ts - a.ts).total_seconds() for a, b in zip(items, items[1:])]
        deltas = [d for d in deltas if d > 0]
        if len(deltas) < cfg["min_connections"] - 1:
            continue
        mean = statistics.mean(deltas)
        if mean < cfg["min_interval_s"]:
            continue  # very chatty streaming/keep-alive traffic, not beaconing
        cv = statistics.pstdev(deltas) / mean
        if cv > cfg["max_cv"]:
            continue
        sizes = [c.orig_bytes for c in items]
        findings.append(Finding(
            id=f"beacon-{src}-{dst}-{port}",
            title=f"Periodic beaconing from {src} to {dst}:{port} every ~{mean:.0f}s",
            severity="high" if cv < 0.05 else "medium",
            source="analytics:beaconing",
            host=src,
            first_seen=items[0].ts,
            last_seen=items[-1].ts,
            count=len(items),
            mitre=["T1071", "T1573"],
            evidence={
                "dest_ip": dst,
                "dest_port": port,
                "mean_interval_s": round(mean, 1),
                "coefficient_of_variation": round(cv, 3),
                "avg_bytes_out": int(statistics.mean(sizes)) if sizes else 0,
            },
        ))
    return findings
