"""Command line interface.

    homesiem demo                    # generate synthetic data, analyze it, write a report
    homesiem analyze -c config.yaml  # analyze real Security Onion data
    homesiem ask "Which device is the most suspicious and why?"
    homesiem serve                   # web panel on http://127.0.0.1:8080
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from . import __version__, report
from .analytics import make_home_check, run_all
from .config import load_config
from .demo import generate
from .llm import OllamaClient
from .sources import build_source


def pipeline(cfg: dict) -> tuple[Path, Path]:
    is_home = make_home_check(cfg["home_net"])
    source = build_source(cfg)
    ds = source.load()
    if not any(ds.summary().values()):
        # Never let the LLM write "everything looks fine" about an empty dataset.
        where = (f"eve={cfg['source']['files']['suricata_eve']} "
                 f"({len(source._eve_files())} file(s) matched), zeek_dir={cfg['source']['files']['zeek_dir']}"
                 if cfg["source"]["type"] == "files" else cfg["source"]["elasticsearch"]["url"])
        raise RuntimeError(f"No log data found - check the source paths in config.yaml: {where}")
    findings = ds.alerts + run_all(ds, cfg)
    stats = report.build_stats(ds, findings, is_home)
    llm = OllamaClient(cfg["llm"], cfg["language"])
    llm.triage(findings)
    summary = llm.summarize(stats, findings)
    model = cfg["llm"]["model"] if llm.available() else "rule-based fallback (Ollama offline)"
    md, data = report.render(ds, findings, summary, stats, cfg, model, is_home)
    return report.write(md, data, cfg["output_dir"], cfg["language"])


def use_demo_data(cfg: dict, out: Path, days: int = 3) -> Path:
    """Generate synthetic logs and point the config at them."""
    out = generate(out, days=days, tz=cfg.get("timezone", "UTC"))
    cfg["source"]["type"] = "files"
    cfg["source"]["files"].update(zeek_dir=str(out / "zeek"), suricata_eve=str(out / "suricata/eve.json"))
    if not cfg.get("assets_file") or not Path(cfg["assets_file"]).exists():
        for cand in (out.resolve().parent, Path.cwd().parent, Path.cwd()):
            if (cand / "assets.example.yaml").exists():
                cfg["assets_file"] = str(cand / "assets.example.yaml")
                break
    return out


def findings_from_json(data: dict) -> list:
    from .models import Finding

    findings = []
    for f in data.get("findings", []):
        f = dict(f)
        f.pop("first_seen", None)
        f.pop("last_seen", None)
        findings.append(Finding(**f))
    return findings


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="homesiem", description="AI assistant for a home Security Onion SIEM")
    p.add_argument("-c", "--config", help="YAML config file (default: built-in defaults)")
    p.add_argument("-l", "--language", choices=["en", "tr"], help="report language")
    p.add_argument("--no-llm", action="store_true", help="skip Ollama, use rule-based triage only")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="generate synthetic data and build a report from it")
    d.add_argument("--out", default="../sample-data", help="where to write synthetic logs")
    d.add_argument("--days", type=int, default=3)
    sub.add_parser("analyze", help="load data, run analytics + AI triage, write report")
    a = sub.add_parser("ask", help="ask the AI a question about the latest findings file")
    a.add_argument("question")
    a.add_argument("--findings", help="findings-*.json (default: newest in output_dir)")
    s = sub.add_parser("serve", help="start the local web panel")
    s.add_argument("--host", default="127.0.0.1", help="bind address (0.0.0.0 only inside Docker)")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--allow-host", action="append", default=[],
                   help="extra Host header to accept, e.g. the PC's LAN name")

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    config_path = args.config or os.environ.get("HOMESIEM_CONFIG")
    if config_path and not Path(config_path).exists():
        if args.config:
            p.error(f"config file not found: {config_path}")
        logging.warning("HOMESIEM_CONFIG=%s not found - using built-in defaults", config_path)
        config_path = None
    cfg = load_config(config_path)
    if args.language:
        cfg["language"] = args.language
    if args.no_llm:
        cfg["llm"]["enabled"] = False

    if args.cmd == "demo":
        out = use_demo_data(cfg, Path(args.out), days=args.days)
        print(f"Synthetic logs written to {out.resolve()}")

    if args.cmd == "serve":
        from .web import serve

        serve(cfg, host=args.host, port=args.port, extra_hosts=args.allow_host,
              config_path=config_path, overrides={"no_llm": args.no_llm})
        return 0

    if args.cmd in ("demo", "analyze"):
        md_path, json_path = pipeline(cfg)
        print(f"Report:   {md_path}\nFindings: {json_path}")
        return 0

    if args.cmd == "ask":
        files = [Path(args.findings)] if args.findings else sorted(Path(cfg["output_dir"]).glob("findings-*.json"))
        if not files:
            print("No findings file found - run `homesiem analyze` first.", file=sys.stderr)
            return 1
        data = json.loads(files[-1].read_text(encoding="utf-8"))
        findings = findings_from_json(data)
        print(OllamaClient(cfg["llm"], cfg["language"]).ask(args.question, data["stats"], findings))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
