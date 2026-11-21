"""Unsupervised anomaly detection (machine learning part of the project).

For every internal host and every hour we build a feature vector
(connections, bytes out/in, unique destinations, unique ports, night-time flag)
and let an Isolation Forest point out the host-hours that look least like the
rest of the network's normal behaviour. No labelled data is needed.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable

from ..models import Conn, Finding

FEATURES = ["connections", "bytes_out_mb", "bytes_in_mb", "unique_dsts", "unique_ports",
            "external_ratio", "night"]


def build_features(conns: list[Conn], is_home: Callable[[str], bool], night_hours: list[int], tz=None):
    buckets: dict[tuple[str, str], list[Conn]] = defaultdict(list)
    for c in conns:
        if is_home(c.src_ip):
            buckets[(c.src_ip, c.ts.astimezone(tz).strftime("%Y-%m-%d %H:00"))].append(c)
    rows, keys = [], []
    for (host, hour), items in buckets.items():
        ext = sum(1 for c in items if not is_home(c.dst_ip))
        h = items[0].ts.astimezone(tz).hour
        rows.append([
            len(items),
            sum(c.orig_bytes for c in items) / 1e6,
            sum(c.resp_bytes for c in items) / 1e6,
            len({c.dst_ip for c in items}),
            len({c.dst_port for c in items}),
            ext / len(items),
            1.0 if night_hours[0] <= h <= night_hours[1] else 0.0,
        ])
        keys.append((host, hour))
    return keys, rows


def detect_host_anomalies(conns: list[Conn], acfg: dict, is_home: Callable[[str], bool]) -> list[Finding]:
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return []
    keys, rows = build_features(conns, is_home, acfg["night_hours"], acfg.get("_tz"))
    if len(rows) < 30:
        return []  # not enough history to learn "normal"
    X = np.log1p(np.array(rows, dtype=float))
    model = IsolationForest(n_estimators=200, contamination=acfg["anomaly"]["contamination"],
                            random_state=42)
    labels = model.fit_predict(X)
    scores = -model.score_samples(X)
    medians = np.median(np.array(rows), axis=0)

    per_host: dict[str, list[tuple[float, str, list[float]]]] = defaultdict(list)
    for (host, hour), label, score, row in zip(keys, labels, scores, rows):
        if label == -1:
            per_host[host].append((float(score), hour, row))

    findings = []
    for host, hits in per_host.items():
        hits.sort(reverse=True)
        score, hour, row = hits[0]
        # Explain *why*: which features are furthest above the network median
        reasons = sorted(
            ((FEATURES[i], row[i], medians[i]) for i in range(len(FEATURES)) if row[i] > medians[i]),
            key=lambda t: (t[1] + 1) / (t[2] + 1), reverse=True)[:3]
        findings.append(Finding(
            id=f"anomaly-{host}",
            title=f"Unusual traffic profile for {host} ({len(hits)} anomalous hour(s))",
            severity="medium" if score > 0.6 else "low",
            source="analytics:anomaly",
            host=host,
            count=len(hits),
            mitre=[],
            evidence={
                "worst_hour": hour,
                "anomaly_score": round(score, 3),
                "top_reasons": [f"{n}={v:.1f} (network median {m:.1f})" for n, v, m in reasons],
                "anomalous_hours": [h for _, h, _ in hits[:10]],
            },
        ))
    return findings
