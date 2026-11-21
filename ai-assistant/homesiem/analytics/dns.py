"""DNS tunneling / DGA detection.

Data smuggled through DNS shows up as many unique, long, random-looking
sub-domains under a single parent domain (e.g. ``a8f3...e1.t.evil.example``).
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict

from ..models import DnsQuery, Finding

# Very common CDNs / services that legitimately use long random labels.
ALLOWLIST_SUFFIXES = (
    "in-addr.arpa", "ip6.arpa", "akamaiedge.net", "cloudfront.net", "amazonaws.com",
    "googlevideo.com", "1e100.net", "apple.com", "icloud.com", "microsoft.com",
    "windows.net", "msftncsi.com", "spotify.com", "netflix.com", "nflxvideo.net",
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def parent_domain(name: str) -> str:
    """Rough registered-domain guess (last 2 labels, 3 for co.uk / com.tr style)."""
    parts = name.split(".")
    if len(parts) >= 3 and len(parts[-2]) <= 3 and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def detect_dns_tunneling(queries: list[DnsQuery], cfg: dict) -> list[Finding]:
    by_parent: dict[tuple[str, str], list[DnsQuery]] = defaultdict(list)
    for q in queries:
        if q.query.endswith(ALLOWLIST_SUFFIXES) or q.query.count(".") < 2:
            continue
        by_parent[(q.src_ip, parent_domain(q.query))].append(q)

    findings = []
    for (src, parent), items in by_parent.items():
        subs = {q.query[: -len(parent) - 1] for q in items}
        if len(subs) < cfg["min_unique_subdomains"]:
            continue
        long_random = [s for s in subs
                       if len(s.replace(".", "")) >= cfg["min_label_len"]
                       and shannon_entropy(s.replace(".", "")) >= cfg["min_entropy"]]
        ratio = len(long_random) / len(subs)
        if ratio < 0.5:
            continue
        txt = sum(1 for q in items if (q.qtype or "").upper() == "TXT")
        avg_entropy = sum(shannon_entropy(s.replace(".", "")) for s in long_random) / len(long_random)
        items.sort(key=lambda q: q.ts)
        findings.append(Finding(
            id=f"dnstunnel-{src}-{parent}",
            title=f"Possible DNS tunneling from {src} via *.{parent}",
            severity="high" if len(subs) > 200 or txt > 20 else "medium",
            source="analytics:dns",
            host=src,
            first_seen=items[0].ts,
            last_seen=items[-1].ts,
            count=len(items),
            mitre=["T1071.004", "T1048"],
            evidence={
                "parent_domain": parent,
                "unique_subdomains": len(subs),
                "high_entropy_ratio": round(ratio, 2),
                "avg_entropy": round(avg_entropy, 2),
                "txt_queries": txt,
                "example": sorted(long_random)[0] + "." + parent,
            },
        ))
    return findings
