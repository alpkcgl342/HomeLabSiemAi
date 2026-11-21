"""Web panel API tests (real HTTP server on a random port)."""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from homesiem.cli import pipeline, use_demo_data
from homesiem.config import load_config
from homesiem.web import PanelState, make_handler

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("panel")
    cfg = load_config()
    cfg["llm"]["enabled"] = False
    cfg["output_dir"] = str(tmp / "reports")
    cfg["assets_file"] = str(ROOT / "assets.example.yaml")
    use_demo_data(cfg, tmp / "sample-data")
    pipeline(cfg)
    state = PanelState(cfg)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state, {"127.0.0.1", "localhost"}))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", state
    httpd.shutdown()


def req(url, data=None, headers=None, method=None):
    r = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def test_index_has_security_headers(server):
    base, _ = server
    status, body, headers = req(base + "/")
    assert status == 200 and b"HomeLabSiemAi" in body
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_latest_contains_chart_data(server):
    base, _ = server
    status, body, _ = req(base + "/api/latest")
    data = json.loads(body)
    assert status == 200 and data["findings"]
    charts = data["charts"]
    assert charts["timeline"] and charts["events"] and charts["host_risk"]
    assert sum(charts["severity"].values()) == len(data["findings"])


def test_dns_rebinding_blocked(server):
    base, _ = server
    status, _, _ = req(base + "/api/latest", headers={"Host": "attacker.example"})
    assert status == 403


def test_post_requires_json(server):
    base, _ = server
    status, _, _ = req(base + "/api/analyze", data=b"mode=demo",
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert status == 415


def test_ask_without_llm_returns_hint(server):
    base, _ = server
    status, body, _ = req(base + "/api/ask", data=json.dumps({"question": "test"}).encode(),
                          headers={"Content-Type": "application/json"})
    assert status == 200 and json.loads(body)["online"] is False


def test_analyze_runs_in_background(server):
    base, state = server
    before = len(state.findings_files())
    time.sleep(1.1)  # file names have second resolution
    status, _, _ = req(base + "/api/analyze", data=json.dumps({"mode": "demo"}).encode(),
                       headers={"Content-Type": "application/json"})
    assert status == 202
    for _ in range(100):
        if not state.running:
            break
        time.sleep(0.2)
    assert state.last_error is None
    assert len(state.findings_files()) == before + 1
    _, body, _ = req(base + "/api/history")
    assert len(json.loads(body)) == before + 1
