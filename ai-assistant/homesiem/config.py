"""Configuration loading (YAML file + environment variable overrides)."""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

DEFAULTS: dict[str, Any] = {
    "home_net": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
    "language": "en",  # report language: en | tr
    "timezone": "UTC",  # used for "night time" logic, e.g. Europe/Istanbul
    "source": {
        "type": "files",  # files | elasticsearch
        "files": {
            "zeek_dir": "../sample-data/zeek",
            "suricata_eve": "../sample-data/suricata/eve.json",
            "metadata": "auto",  # auto | zeek | suricata
        },
        "elasticsearch": {
            "url": "https://securityonion.local:9200",
            "username": "",
            "password": "",
            "verify_tls": False,
            "lookback_hours": 168,
            "max_docs": 20000,
            "index": "logs-*",
            # Security Onion 3.x with Suricata metadata (default EVAL install).
            # With Zeek use: conn: "event.dataset:zeek.conn" (check Hunt for your names).
            "queries": {
                "alerts": "event.dataset:suricata.alert OR event.dataset:sigma.alert",
                "conn": "event.dataset:suricata.conn",
                "dns": "event.dataset:suricata.dns AND dns.query.type:request",
                "dhcp": "event.dataset:suricata.dhcp",
            },
        },
    },
    "assets_file": "../assets.example.yaml",
    "analytics": {
        "beaconing": {"min_connections": 12, "max_cv": 0.15, "min_interval_s": 10, "min_duration_s": 3600},
        "dns": {"min_entropy": 3.8, "min_label_len": 25, "min_unique_subdomains": 30},
        "port_scan": {"min_unique_ports": 40, "window_s": 300},
        "exfil": {"min_bytes_out": 500_000_000},
        "night_hours": [1, 5],
        "anomaly": {"enabled": True, "contamination": 0.02},
    },
    "llm": {
        "enabled": True,
        "provider": "ollama",
        "url": "http://localhost:11434",
        "model": "llama3.1:8b",
        "timeout_s": 180,
        "max_findings": 25,
    },
    "output_dir": "../reports",
}

ENV_OVERRIDES = {
    "HOMESIEM_OLLAMA_URL": ("llm", "url"),
    "HOMESIEM_OLLAMA_MODEL": ("llm", "model"),
    "HOMESIEM_LLM_ENABLED": ("llm", "enabled"),
    "HOMESIEM_LANGUAGE": ("language",),
    "HOMESIEM_TIMEZONE": ("timezone",),
    "HOMESIEM_ES_URL": ("source", "elasticsearch", "url"),
    "HOMESIEM_ES_USER": ("source", "elasticsearch", "username"),
    "HOMESIEM_ES_PASSWORD": ("source", "elasticsearch", "password"),
}


def _deep_merge(base: dict, extra: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (extra or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _coerce(value: str) -> Any:
    if value.lower() in {"true", "yes", "1"}:
        return True
    if value.lower() in {"false", "no", "0"}:
        return False
    return value


def load_config(path: str | os.PathLike | None = None) -> dict[str, Any]:
    cfg = copy.deepcopy(DEFAULTS)
    base_dir = Path.cwd()
    if path:
        p = Path(path)
        with p.open(encoding="utf-8") as fh:
            cfg = _deep_merge(cfg, yaml.safe_load(fh) or {})
        base_dir = p.resolve().parent

    for env, keys in ENV_OVERRIDES.items():
        if env in os.environ:
            node = cfg
            for k in keys[:-1]:
                node = node[k]
            node[keys[-1]] = _coerce(os.environ[env])

    # Resolve relative paths against the config file's folder
    def _abs(p: str | None) -> str | None:
        if not p:
            return p
        return str((base_dir / p).resolve()) if not os.path.isabs(p) else p

    files = cfg["source"]["files"]
    files["zeek_dir"] = _abs(files.get("zeek_dir"))
    files["suricata_eve"] = _abs(files.get("suricata_eve"))
    cfg["assets_file"] = _abs(cfg.get("assets_file"))
    cfg["output_dir"] = _abs(cfg.get("output_dir"))
    return cfg
