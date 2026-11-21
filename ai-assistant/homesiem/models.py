"""Normalized data models shared by every part of the pipeline.

Security Onion (Elasticsearch), raw Zeek JSON logs and Suricata eve.json all use
different field names. Every source is converted into these small dataclasses so
analytics, AI triage and reporting never care where an event came from.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Conn:
    ts: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    service: str | None = None
    duration: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0
    conn_state: str | None = None


@dataclass
class DnsQuery:
    ts: datetime
    src_ip: str
    query: str
    qtype: str | None = None
    rcode: str | None = None


@dataclass
class DhcpLease:
    ts: datetime
    mac: str
    ip: str | None = None
    hostname: str | None = None


@dataclass
class Finding:
    """A single thing worth a human's attention (IDS alert or analytics result)."""

    id: str
    title: str
    severity: str  # info | low | medium | high | critical
    source: str  # suricata | sigma | analytics:<name>
    host: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    count: int = 1
    mitre: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    # Filled in by the AI triage step
    ai_risk: int | None = None
    ai_explanation: str | None = None
    ai_action: str | None = None

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for key in ("first_seen", "last_seen"):
            if d[key] is not None:
                d[key] = d[key].isoformat()
        return d


@dataclass
class Dataset:
    conns: list[Conn] = field(default_factory=list)
    dns: list[DnsQuery] = field(default_factory=list)
    dhcp: list[DhcpLease] = field(default_factory=list)
    alerts: list[Finding] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        return {
            "connections": len(self.conns),
            "dns_queries": len(self.dns),
            "dhcp_leases": len(self.dhcp),
            "ids_alerts": len(self.alerts),
        }
