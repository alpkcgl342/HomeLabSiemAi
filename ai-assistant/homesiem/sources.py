"""Data sources: raw log files or Security Onion's Elasticsearch.

* ``FileSource`` reads Zeek JSON logs (conn/dns/dhcp, optionally .gz rotated)
  and Suricata ``eve.json``. Security Onion keeps these under ``/nsm/zeek/logs``
  and ``/nsm/suricata``; copy them to your PC (rsync/scp) or point at the sample data.
* ``ElasticsearchSource`` queries Security Onion's Elasticsearch REST API.
  Field names vary slightly between Security Onion versions, so every field is
  looked up through a list of candidates (see ``FIELD_CANDIDATES``).
"""
from __future__ import annotations

import gzip
import json
import logging
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .models import Conn, Dataset, DhcpLease, DnsQuery, Finding

log = logging.getLogger(__name__)

SURICATA_SEVERITY = {1: "high", 2: "medium", 3: "low", 4: "info"}


# --------------------------------------------------------------------------- helpers
def parse_ts(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        v = value.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(v)
        except ValueError:
            # Suricata style: 2026-11-20T10:00:00.123456+0300
            dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    raise ValueError(f"Unsupported timestamp: {value!r}")


def dig(doc: dict, path: str, default: Any = None) -> Any:
    """Get ``a.b.c`` from nested dicts, also accepting flat dotted keys (Zeek style)."""
    if path in doc:
        return doc[path]
    node: Any = doc
    for part in path.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return default
    return node


def first(doc: dict, candidates: list[str], default: Any = None) -> Any:
    for c in candidates:
        v = dig(doc, c)
        if v not in (None, "", "-"):
            return v
    return default


def _int(v: Any) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def _float(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _first_str(v: Any) -> Any:
    return v[0] if isinstance(v, list) and v else v


def _read_jsonl(path: Path) -> Iterator[dict]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                log.debug("Skipping non-JSON line %s:%d", path, line_no)


# Candidate field names: raw Zeek first, then Security Onion / ECS style.
FIELD_CANDIDATES = {
    "ts": ["ts", "@timestamp", "timestamp"],
    "src_ip": ["id.orig_h", "source.ip", "src_ip"],
    "src_port": ["id.orig_p", "source.port", "src_port"],
    "dst_ip": ["id.resp_h", "destination.ip", "dest_ip"],
    "dst_port": ["id.resp_p", "destination.port", "dest_port"],
    "proto": ["proto", "network.transport", "network.protocol"],
    "service": ["service", "network.protocol", "connection.service"],
    "duration": ["duration", "event.duration", "connection.duration"],
    "orig_bytes": ["orig_bytes", "client.bytes", "source.bytes", "client.ip_bytes"],
    "resp_bytes": ["resp_bytes", "server.bytes", "destination.bytes", "server.ip_bytes"],
    "conn_state": ["conn_state", "connection.state"],
    "query": ["query", "dns.query.name", "dns.question.name"],
    "qtype": ["qtype_name", "dns.query.type_name", "dns.question.type"],
    "rcode": ["rcode_name", "dns.response.code_name", "dns.response_code"],
    "mac": ["mac", "host.mac", "client.mac", "source.mac"],
    "assigned_ip": ["assigned_addr", "assigned_ip", "client.address", "host.ip"],
    "hostname": ["host_name", "host.hostname", "dhcp.hostname", "client_fqdn"],
}


def to_conn(doc: dict) -> Conn | None:
    src, dst = first(doc, FIELD_CANDIDATES["src_ip"]), first(doc, FIELD_CANDIDATES["dst_ip"])
    ts = first(doc, FIELD_CANDIDATES["ts"])
    if not (src and dst and ts):
        return None
    return Conn(
        ts=parse_ts(ts),
        src_ip=str(src),
        src_port=_int(first(doc, FIELD_CANDIDATES["src_port"])),
        dst_ip=str(dst),
        dst_port=_int(first(doc, FIELD_CANDIDATES["dst_port"])),
        proto=str(first(doc, FIELD_CANDIDATES["proto"], "")).lower(),
        service=_first_str(first(doc, FIELD_CANDIDATES["service"])),
        duration=_float(first(doc, FIELD_CANDIDATES["duration"])),
        orig_bytes=_int(first(doc, FIELD_CANDIDATES["orig_bytes"])),
        resp_bytes=_int(first(doc, FIELD_CANDIDATES["resp_bytes"])),
        conn_state=first(doc, FIELD_CANDIDATES["conn_state"]),
    )


def to_dns(doc: dict) -> DnsQuery | None:
    q, src, ts = (first(doc, FIELD_CANDIDATES[k]) for k in ("query", "src_ip", "ts"))
    if not (q and src and ts):
        return None
    return DnsQuery(
        ts=parse_ts(ts),
        src_ip=str(src),
        query=str(_first_str(q)).lower().rstrip("."),
        qtype=_first_str(first(doc, FIELD_CANDIDATES["qtype"])),
        rcode=first(doc, FIELD_CANDIDATES["rcode"]),
    )


def to_dhcp(doc: dict) -> DhcpLease | None:
    mac, ts = first(doc, FIELD_CANDIDATES["mac"]), first(doc, FIELD_CANDIDATES["ts"])
    if not (mac and ts):
        return None
    return DhcpLease(
        ts=parse_ts(ts),
        mac=str(_first_str(mac)).lower(),
        ip=first(doc, FIELD_CANDIDATES["assigned_ip"]),
        hostname=first(doc, FIELD_CANDIDATES["hostname"]),
    )


def to_alert(doc: dict) -> Finding | None:
    """Suricata eve.json alert (raw) or Security Onion alert document -> Finding."""
    sig = first(doc, ["alert.signature", "rule.name", "message"])
    if not sig:
        return None
    sid = first(doc, ["alert.signature_id", "rule.uuid", "rule.id"], "0")
    sev_raw = first(doc, ["alert.severity", "event.severity"], 3)
    if isinstance(sev_raw, str) and not sev_raw.isdigit():
        severity = sev_raw.lower()
    else:
        # Suricata: 1=high ... Security Onion event.severity: 1=low ... 4=critical
        sev = _int(sev_raw)
        severity = SURICATA_SEVERITY.get(sev, "low") if "alert" in doc else {
            1: "low", 2: "medium", 3: "high", 4: "critical"}.get(sev, "low")
    mitre: list[str] = []
    meta = first(doc, ["alert.metadata", "rule.metadata"], {}) or {}
    if isinstance(meta, dict):
        for key in ("mitre_technique_id", "mitre_technique"):
            vals = meta.get(key) or []
            mitre += vals if isinstance(vals, list) else [vals]
    ts = parse_ts(first(doc, FIELD_CANDIDATES["ts"]))
    src = first(doc, ["src_ip", "source.ip"])
    return Finding(
        id=f"suricata-{sid}-{src}",
        title=str(sig),
        severity=severity,
        source="suricata",
        host=src,
        first_seen=ts,
        last_seen=ts,
        mitre=sorted(set(mitre)),
        evidence={
            "sid": sid,
            "category": first(doc, ["alert.category", "rule.category"]),
            "src_ip": src,
            "dest_ip": first(doc, ["dest_ip", "destination.ip"]),
            "dest_port": first(doc, ["dest_port", "destination.port"]),
        },
    )


def merge_alerts(alerts: list[Finding]) -> list[Finding]:
    """Collapse repeated alerts (same signature + source host) into one finding."""
    merged: dict[str, Finding] = {}
    for a in sorted(alerts, key=lambda x: x.first_seen or datetime.min.replace(tzinfo=timezone.utc)):
        if a.id in merged:
            m = merged[a.id]
            m.count += 1
            m.last_seen = a.last_seen
            dests = set(m.evidence.get("dest_ips", [m.evidence.get("dest_ip")]))
            dests.add(a.evidence.get("dest_ip"))
            m.evidence["dest_ips"] = sorted(d for d in dests if d)[:20]
        else:
            merged[a.id] = a
    return list(merged.values())


# --------------------------------------------------------------------------- sources
class FileSource:
    def __init__(self, zeek_dir: str | None, suricata_eve: str | None):
        self.zeek_dir = Path(zeek_dir) if zeek_dir else None
        self.eve = Path(suricata_eve) if suricata_eve else None

    def _zeek(self, name: str) -> Iterator[dict]:
        if not self.zeek_dir or not self.zeek_dir.exists():
            return
        for path in sorted(self.zeek_dir.rglob(f"{name}*.log*")):
            yield from _read_jsonl(path)

    def load(self) -> Dataset:
        ds = Dataset()
        ds.conns = [c for d in self._zeek("conn") if (c := to_conn(d))]
        ds.dns = [q for d in self._zeek("dns") if (q := to_dns(d))]
        ds.dhcp = [l for d in self._zeek("dhcp") if (l := to_dhcp(d))]
        if self.eve and self.eve.exists():
            raw = [a for d in _read_jsonl(self.eve) if d.get("event_type") == "alert" and (a := to_alert(d))]
            ds.alerts = merge_alerts(raw)
        log.info("Loaded from files: %s", ds.summary())
        return ds


class ElasticsearchSource:
    """Reads directly from Security Onion's Elasticsearch.

    Requirements on the Security Onion side (see docs/setup-security-onion.md):
    the analyst PC must be allowed through the firewall to port 9200 and you
    need a Security Onion user that can read the ``logs-*`` indices.
    """

    def __init__(self, cfg: dict):
        import requests  # imported lazily so file mode works without network libs

        self.cfg = cfg
        self.session = requests.Session()
        if cfg.get("username"):
            self.session.auth = (cfg["username"], cfg["password"])
        self.session.verify = cfg.get("verify_tls", False)
        if not self.session.verify:
            import urllib3

            urllib3.disable_warnings()

    def _search(self, query: str) -> Iterator[dict]:
        since = datetime.now(timezone.utc) - timedelta(hours=self.cfg["lookback_hours"])
        body: dict[str, Any] = {
            "size": 2000,
            "sort": [{"@timestamp": "asc"}],
            "query": {"bool": {"filter": [
                {"query_string": {"query": query}},
                {"range": {"@timestamp": {"gte": since.isoformat()}}},
            ]}},
        }
        url = f"{self.cfg['url'].rstrip('/')}/{self.cfg['index']}/_search"
        fetched = 0
        while fetched < self.cfg["max_docs"]:
            r = self.session.post(url, json=body, timeout=60)
            r.raise_for_status()
            hits = r.json()["hits"]["hits"]
            if not hits:
                break
            for h in hits:
                yield h["_source"]
            fetched += len(hits)
            body["search_after"] = hits[-1]["sort"]

    def load(self) -> Dataset:
        q = self.cfg["queries"]
        ds = Dataset()
        ds.conns = [c for d in self._search(q["conn"]) if (c := to_conn(d))]
        ds.dns = [x for d in self._search(q["dns"]) if (x := to_dns(d))]
        ds.dhcp = [x for d in self._search(q["dhcp"]) if (x := to_dhcp(d))]
        ds.alerts = merge_alerts([a for d in self._search(q["alerts"]) if (a := to_alert(d))])
        log.info("Loaded from Elasticsearch: %s", ds.summary())
        return ds


def build_source(cfg: dict) -> FileSource | ElasticsearchSource:
    src = cfg["source"]
    if src["type"] == "elasticsearch":
        return ElasticsearchSource(src["elasticsearch"])
    return FileSource(src["files"]["zeek_dir"], src["files"]["suricata_eve"])
