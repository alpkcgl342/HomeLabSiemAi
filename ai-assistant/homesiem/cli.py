"""Command line interface.

    homesiem demo                    # generate synthetic data, analyze it, write a report
    homesiem analyze -c config.yaml  # analyze real Security Onion data
    homesiem ask "Which device is the most suspicious and why?"
"""
from __future__ import annotations

import argparse
import json
import logging
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
    ds = build_source(cfg).load()
    findings = ds.alerts + run_all(ds, cfg)
    stats = report.build_stats(ds, findings, is_home)
    llm = OllamaClient(cfg["llm"], cfg["language"])
    llm.triage(findings)
    summary = llm.summarize(stats, findings)
    model = cfg["llm"]["model"] if llm.available() else "rule-based fallback (Ollama offline)"
    md, data = report.render(ds, findings, summary, stats, cfg, model, is_home)
    return report.write(md, data, cfg["output_dir"], cfg["language"])


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

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    cfg = load_config(args.config)
    if args.language:
        cfg["language"] = args.language
    if args.no_llm:
        cfg["llm"]["enabled"] = False

    if args.cmd == "demo":
        out = generate(args.out, days=args.days, tz=cfg.get("timezone", "UTC"))
        cfg["source"]["type"] = "files"
        cfg["source"]["files"].update(zeek_dir=str(out / "zeek"), suricata_eve=str(out / "suricata/eve.json"))
        if not args.config:
            for cand in (out.resolve().parent, Path.cwd().parent, Path.cwd()):
                if (cand / "assets.example.yaml").exists():
                    cfg["assets_file"] = str(cand / "assets.example.yaml")
                    break
        print(f"Synthetic logs written to {out.resolve()}")

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
        from .models import Finding

        findings = []
        for f in data["findings"]:
            f.pop("first_seen", None), f.pop("last_seen", None)
            findings.append(Finding(**f))
        print(OllamaClient(cfg["llm"], cfg["language"]).ask(args.question, data["stats"], findings))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
