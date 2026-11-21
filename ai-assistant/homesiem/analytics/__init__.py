"""Behavioural detections that signature rules (Suricata/Sigma) cannot express well.

Each detector takes a ``Dataset`` + config and returns a list of ``Finding``.
"""
from __future__ import annotations

import ipaddress
import logging
from zoneinfo import ZoneInfo

from ..models import Dataset, Finding
from .anomaly import detect_host_anomalies
from .beaconing import detect_beaconing
from .dns import detect_dns_tunneling
from .network import detect_exfiltration, detect_new_devices, detect_port_scans

log = logging.getLogger(__name__)


def make_home_check(home_net: list[str]):
    nets = [ipaddress.ip_network(n) for n in home_net]

    def is_home(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in nets)

    return is_home


def run_all(ds: Dataset, cfg: dict) -> list[Finding]:
    acfg = dict(cfg["analytics"])
    acfg["_tz"] = ZoneInfo(cfg.get("timezone", "UTC"))
    is_home = make_home_check(cfg["home_net"])
    findings: list[Finding] = []
    detectors = [
        ("beaconing", lambda: detect_beaconing(ds.conns, acfg["beaconing"], is_home)),
        ("dns", lambda: detect_dns_tunneling(ds.dns, acfg["dns"])),
        ("port_scan", lambda: detect_port_scans(ds.conns, acfg["port_scan"])),
        ("exfil", lambda: detect_exfiltration(ds.conns, acfg["exfil"], acfg["night_hours"], is_home,
                                              acfg["_tz"])),
        ("new_devices", lambda: detect_new_devices(ds.dhcp, cfg.get("assets_file"))),
    ]
    if acfg["anomaly"]["enabled"]:
        detectors.append(("anomaly", lambda: detect_host_anomalies(ds.conns, acfg, is_home)))
    for name, fn in detectors:
        try:
            out = fn()
            log.info("analytics:%s -> %d finding(s)", name, len(out))
            findings += out
        except Exception:  # one broken detector must not kill the report
            log.exception("Detector %s failed", name)
    return findings
