"""Local web panel (dashboard) for homesiem.

    homesiem -c ../config/config.yaml serve            # http://127.0.0.1:8080

Uses only the Python standard library. The browser never sees raw logs, only the
pre-aggregated ``findings-*.json`` files written by ``analyze``.

Security model (the panel shows attacker-controlled strings such as DNS names):
* binds to 127.0.0.1 by default; Docker publishes it on the host's loopback only
* the front-end renders every value with ``textContent`` (no innerHTML) -> no XSS
* state-changing endpoints require ``Content-Type: application/json`` (a cross-site
  form cannot send that without a CORS pre-flight, which this server never approves)
* the ``Host`` header is checked against an allow-list (DNS-rebinding protection)
* strict Content-Security-Policy: no external scripts, styles, fonts or connections
"""
from __future__ import annotations

import json
import logging
import threading
import traceback
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__
from .llm import OllamaClient

log = logging.getLogger(__name__)
STATIC = Path(__file__).parent / "templates" / "dashboard.html"
CSP = ("default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class PanelState:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.running = False
        self.last_error: str | None = None
        self.last_run: str | None = None
        self.out_dir = Path(cfg["output_dir"])

    def findings_files(self) -> list[Path]:
        return sorted(self.out_dir.glob("findings-*.json"))

    def latest(self) -> dict | None:
        files = self.findings_files()
        if not files:
            return None
        data = json.loads(files[-1].read_text(encoding="utf-8"))
        data["file"] = files[-1].name
        return data

    def history(self) -> list[dict]:
        out = []
        for f in self.findings_files()[-30:]:
            try:
                d = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            sev = d.get("charts", {}).get("severity", {})
            out.append({"file": f.name, "generated": d.get("generated"),
                        "findings": len(d.get("findings", [])),
                        "high_or_critical": sev.get("high", 0) + sev.get("critical", 0)})
        return out

    def start_run(self, mode: str, language: str | None) -> bool:
        with self.lock:
            if self.running:
                return False
            self.running = True
            self.last_error = None
        threading.Thread(target=self._run, args=(mode, language), daemon=True).start()
        return True

    def _run(self, mode: str, language: str | None) -> None:
        from .cli import pipeline, use_demo_data

        try:
            cfg = json.loads(json.dumps(self.cfg))  # deep copy
            if language in ("en", "tr"):
                cfg["language"] = language
            if mode == "demo":
                use_demo_data(cfg, Path(cfg["output_dir"]).parent / "sample-data")
            pipeline(cfg)
            self.last_run = datetime.now(timezone.utc).isoformat()
        except Exception as exc:  # surfaced in the UI
            log.error("Analysis failed: %s", traceback.format_exc())
            self.last_error = f"{type(exc).__name__}: {exc}"
        finally:
            self.running = False


def make_handler(state: PanelState, allowed_hosts: set[str]):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"homesiem/{__version__}"

        def log_message(self, fmt, *args):  # route to logging instead of stderr
            log.debug("%s - %s", self.address_string(), fmt % args)

        # ------------------------------------------------------------ helpers
        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
            return host in allowed_hosts

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CSP)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, status: int = 200) -> None:
            self._send(status, json.dumps(obj, ensure_ascii=False, default=str).encode(),
                       "application/json; charset=utf-8")

        def _body(self) -> dict:
            if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                raise PermissionError("JSON body required")
            n = min(int(self.headers.get("Content-Length") or 0), 64_000)
            return json.loads(self.rfile.read(n) or b"{}")

        # ------------------------------------------------------------ routes
        def do_GET(self):
            if not self._host_ok():
                return self._json({"error": "host not allowed"}, HTTPStatus.FORBIDDEN)
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                return self._send(200, STATIC.read_bytes(), "text/html; charset=utf-8")
            if path == "/api/status":
                llm = OllamaClient(state.cfg["llm"], state.cfg["language"])
                return self._json({
                    "version": __version__, "running": state.running, "last_error": state.last_error,
                    "last_run": state.last_run, "language": state.cfg["language"],
                    "source": state.cfg["source"]["type"], "llm_enabled": llm.enabled,
                    "llm_online": llm.available(), "llm_model": llm.model,
                })
            if path == "/api/latest":
                return self._json(state.latest() or {})
            if path == "/api/history":
                return self._json(state.history())
            return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def do_POST(self):
            if not self._host_ok():
                return self._json({"error": "host not allowed"}, HTTPStatus.FORBIDDEN)
            try:
                body = self._body()
            except PermissionError as exc:
                return self._json({"error": str(exc)}, HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            except (ValueError, json.JSONDecodeError):
                return self._json({"error": "bad json"}, HTTPStatus.BAD_REQUEST)

            if self.path == "/api/analyze":
                mode = "demo" if body.get("mode") == "demo" else "analyze"
                started = state.start_run(mode, body.get("language"))
                return self._json({"started": started, "running": True},
                                  HTTPStatus.ACCEPTED if started else HTTPStatus.CONFLICT)
            if self.path == "/api/ask":
                question = str(body.get("question", "")).strip()[:500]
                data = state.latest()
                if not question or not data:
                    return self._json({"error": "question and a findings file are required"},
                                      HTTPStatus.BAD_REQUEST)
                from .cli import findings_from_json

                lang = body.get("language") if body.get("language") in ("en", "tr") else state.cfg["language"]
                llm = OllamaClient(state.cfg["llm"], lang)
                try:
                    answer = llm.ask(question, data["stats"], findings_from_json(data))
                except Exception as exc:
                    return self._json({"error": f"LLM error: {exc}"}, HTTPStatus.BAD_GATEWAY)
                return self._json({"answer": answer, "model": llm.model, "online": llm.available()})
            return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    return Handler


def serve(cfg: dict, host: str = "127.0.0.1", port: int = 8080, extra_hosts: list[str] | None = None) -> None:
    state = PanelState(cfg)
    allowed = {"127.0.0.1", "localhost", "::1", *(h.lower() for h in (extra_hosts or []))}
    if host not in ("0.0.0.0", "::"):
        allowed.add(host.lower())
    httpd = ThreadingHTTPServer((host, port), make_handler(state, allowed))
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    print(f"homesiem panel: http://{shown}:{port}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
