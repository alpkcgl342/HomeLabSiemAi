"""End-to-end and unit tests. Run from ai-assistant/:  python -m pytest -q"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from homesiem import report
from homesiem.analytics import make_home_check, run_all
from homesiem.analytics.beaconing import detect_beaconing
from homesiem.analytics.dns import parent_domain, shannon_entropy
from homesiem.config import load_config
from homesiem.demo import generate
from homesiem.llm import OllamaClient, _parse_json
from homesiem.models import Conn
from homesiem.sources import FileSource, to_alert, to_conn

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def dataset(tmp_path_factory):
    out = generate(tmp_path_factory.mktemp("data"), days=3, seed=1)
    return FileSource(str(out / "zeek"), str(out / "suricata" / "eve.json")).load()


@pytest.fixture()
def cfg(tmp_path):
    c = load_config()
    c["assets_file"] = str(ROOT / "assets.example.yaml")
    c["output_dir"] = str(tmp_path)
    c["llm"]["enabled"] = False
    return c


def test_all_injected_scenarios_are_detected(dataset, cfg):
    findings = run_all(dataset, cfg)
    sources = {f.source for f in findings}
    for expected in ("analytics:beaconing", "analytics:dns", "analytics:port_scan",
                     "analytics:exfil", "analytics:new_devices"):
        assert expected in sources, f"{expected} missed"
    beacon = next(f for f in findings if f.source == "analytics:beaconing")
    assert beacon.host == "192.168.1.30" and beacon.evidence["dest_ip"] == "203.0.113.66"
    assert next(f for f in findings if f.source == "analytics:new_devices").evidence["hostname"] == "kali"


def test_no_beaconing_false_positive_on_normal_devices(dataset, cfg):
    beacons = [f for f in run_all(dataset, cfg) if f.source == "analytics:beaconing"]
    assert {f.host for f in beacons} == {"192.168.1.30"}


def test_suricata_alerts_are_deduplicated(dataset):
    doh = [a for a in dataset.alerts if "DNS-over-HTTPS" in a.title]
    assert len(doh) == 1 and doh[0].count == 3


def test_report_renders_in_both_languages(dataset, cfg):
    is_home = make_home_check(cfg["home_net"])
    findings = dataset.alerts + run_all(dataset, cfg)
    for lang, title in (("en", "Home Network Security Report"), ("tr", "Ev Ağı Güvenlik Raporu")):
        cfg["language"] = lang
        llm = OllamaClient(cfg["llm"], lang)
        llm.triage(findings)
        stats = report.build_stats(dataset, findings, is_home)
        md, data = report.render(dataset, findings, llm.summarize(stats, findings), stats, cfg, "test", is_home)
        assert md.startswith(f"# {title}")
        assert all(f["ai_risk"] for f in data["findings"])
        json.dumps(data)  # serialisable


def test_beaconing_ignores_human_like_traffic():
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    import random
    rng = random.Random(0)
    t, conns = t0, []
    for _ in range(50):
        t += timedelta(seconds=rng.expovariate(1 / 120))
        conns.append(Conn(t, "192.168.1.5", 1, "198.51.100.1", 443, "tcp"))
    cfg = {"min_connections": 12, "max_cv": 0.15, "min_interval_s": 10, "min_duration_s": 600}
    assert detect_beaconing(conns, cfg, make_home_check(["192.168.0.0/16"])) == []


def test_helpers():
    assert parent_domain("a.b.example.com") == "example.com"
    assert parent_domain("x.y.example.com.tr") == "example.com.tr"
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("0123456789abcdef") == 4.0


def test_security_onion_style_documents():
    conn = to_conn({"@timestamp": "2026-11-20T10:00:00.000Z", "source": {"ip": "192.168.1.5", "port": 5000},
                    "destination": {"ip": "198.51.100.1", "port": 443}, "network": {"transport": "tcp"},
                    "client": {"bytes": 100}, "server": {"bytes": 2000}})
    assert conn and conn.dst_port == 443 and conn.orig_bytes == 100
    alert = to_alert({"@timestamp": "2026-11-20T10:00:00Z", "rule": {"name": "ET SCAN test", "uuid": "2001"},
                      "event": {"severity": 3}, "source": {"ip": "192.168.1.5"}})
    assert alert and alert.severity == "high"


def test_llm_json_parsing_tolerates_chatter():
    assert _parse_json('Sure! {"results": [{"id": "x", "risk": 3}]} hope this helps') == \
        {"results": [{"id": "x", "risk": 3}]}


def test_llm_triage_with_mocked_ollama(dataset, cfg, monkeypatch):
    findings = run_all(dataset, cfg)
    cfg["llm"]["enabled"] = True
    client = OllamaClient(cfg["llm"], "tr")
    monkeypatch.setattr(client, "available", lambda: True)

    def fake_chat(prompt, json_mode=False):
        ids = [line.split('"id": "')[1].split('"')[0] for line in prompt.splitlines() if '"id": "' in line]
        return json.dumps({"results": [{"id": i, "risk": 9, "explanation": "test", "action": "izole et"}
                                       for i in ids]})

    monkeypatch.setattr(client, "chat", fake_chat)
    client.triage(findings)
    assert all(f.ai_risk == 9 and f.ai_action == "izole et" for f in findings)
