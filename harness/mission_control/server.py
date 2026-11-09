#!/usr/bin/env python3
"""Harness Mission Control: a local, read-only, realtime dashboard for the agent fleet (GoodQA #15585).

    server.py serve [--port P] [--initiatives PATH] [--no-remote]   run the server (launchd runs this)
    server.py url                                                   print a single-use launch URL (60 s)
    server.py open                                                  open a launch URL in the default browser
    server.py status                                                health and launchd state
    server.py install-launchd [--apply] | uninstall-launchd [--apply]
    server.py rotate-secret                                         invalidate every launch code and session

Security model (docs/mission-control.md): binds 127.0.0.1 only; a launch code minted from the 0600 install
secret is exchanged once for an HttpOnly SameSite=Strict session cookie; exact Host allowlist (DNS rebinding);
Sec-Fetch-Site/Origin checks on every data read; exact Origin plus a per-session CSRF header on writes; strict
CSP and no CORS. The server never writes to repos, tickets or hosts.
"""

from __future__ import annotations

import argparse
import base64
import glob
import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import secrets
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent


def _hooks_dir() -> Path:
    for candidate in (os.environ.get("MC_HOOKS"), str(Path.home() / ".claude" / "hooks"), str(HERE.parent / "hooks")):
        if candidate and (Path(candidate) / "mc_chat.py").is_file() and (Path(candidate) / "redact.py").is_file():
            return Path(candidate)
    return HERE.parent / "hooks"


HOOKS = _hooks_dir()
sys.path.insert(0, str(HERE))
sys.path.insert(1, str(HOOKS))

import collectors as col  # noqa: E402
import events as ev  # noqa: E402
import mc_chat  # noqa: E402
from codex_responder import CodexResponder  # noqa: E402
from safeio import Reader, Runner  # noqa: E402

VERSION = "1"
DEFAULT_PORT = 47615
LABEL = "com.agent-harness.mission-control"
LAUNCH_TTL_S = 60
SESSION_TTL_S = 12 * 3600
MAX_SESSIONS = 16
MAX_CONNECTIONS = 48
MAX_BODY = 16 * 1024
IO_TIMEOUT_S = 10
SSE_HEARTBEAT_S = 15
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                 ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
                 ".svg": "image/svg+xml", ".png": "image/png", ".json": "application/json", ".txt": "text/plain"}
CSP = ("default-src 'self'; img-src 'self' data:; connect-src 'self'; style-src 'self'; script-src 'self'; "
       "font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


# ---------------------------------------------------------------- launch codes and sessions

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def mint_code(key: bytes, now: float | None = None) -> str:
    now = time.time() if now is None else now
    payload = int(now).to_bytes(8, "big") + secrets.token_bytes(16)
    mac = hmac.new(key, b"mc-launch|" + payload, hashlib.sha256).digest()[:16]
    return _b64(payload) + "." + _b64(mac)


class Auth:
    def __init__(self, key_loader, port: int):
        self.key_loader = key_loader
        self.port = port
        self.lock = threading.Lock()
        self.used: dict[bytes, float] = {}
        self.sessions: dict[str, dict] = {}
        self.failures: list[float] = []
        self.hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        self.origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}

    def redeem(self, code: str, now: float | None = None) -> str | None:
        """A fresh session id for a valid, unexpired, unused launch code; else None (rate limited)."""
        now = time.time() if now is None else now
        with self.lock:
            self.failures = [t for t in self.failures if now - t < 60]
            if len(self.failures) >= 10:
                return None
            sid = self._redeem_locked(code, now)
            if sid is None:
                self.failures.append(now)
            return sid

    def _redeem_locked(self, code, now):
        try:
            left, right = str(code).split(".", 1)
            payload, mac = _unb64(left), _unb64(right)
        except (ValueError, TypeError):
            return None
        if len(payload) != 24 or len(mac) != 16:
            return None
        expected = hmac.new(self.key_loader(), b"mc-launch|" + payload, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(expected, mac):
            return None
        minted = int.from_bytes(payload[:8], "big")
        if not -5 <= now - minted <= LAUNCH_TTL_S:
            return None
        self.used = {k: t for k, t in self.used.items() if now - t < 2 * LAUNCH_TTL_S}
        if payload in self.used:
            return None
        self.used[payload] = now
        if len(self.sessions) >= MAX_SESSIONS:
            oldest = min(self.sessions, key=lambda s: self.sessions[s]["last"])
            self.sessions.pop(oldest, None)
        sid = secrets.token_urlsafe(32)
        self.sessions[sid] = {"csrf": secrets.token_urlsafe(32), "created": now, "last": now}
        return sid

    def session(self, cookie_header: str | None, now: float | None = None):
        now = time.time() if now is None else now
        sid = None
        for part in (cookie_header or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == "mc_sid":
                sid = value
        if not sid:
            return None, None
        with self.lock:
            info = self.sessions.get(sid)
            if not info or now - info["last"] > SESSION_TTL_S:
                self.sessions.pop(sid, None)
                return None, None
            info["last"] = now
            return sid, info

    def revoke_all(self) -> None:
        with self.lock:
            self.sessions.clear()


# ---------------------------------------------------------------- the application (state + collectors)

def default_initiatives() -> str | None:
    explicit = os.environ.get("MC_INITIATIVES")
    if explicit:
        return explicit
    config = mc_chat.read_json(mc_chat.home() / "config.json")
    if isinstance(config, dict) and isinstance(config.get("initiatives"), str):
        return config["initiatives"]
    found = glob.glob(str(Path.home() / ".agent-harness" / "work" / "*" / "dashboard" / "initiatives.json"))
    return max(found, key=os.path.getmtime) if found else None


def codex_binary() -> str | None:
    for candidate in (os.environ.get("MC_CODEX_BIN"), shutil.which("codex"),
                      "/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex"):
        if candidate and os.access(candidate, os.X_OK):
            return candidate
    return None


class App:
    def __init__(self, *, port: int, root: Path, initiatives: str | None, remote: bool, fabric_bin: str | None,
                 runner: Runner | None = None, wal_roots=None, start_threads: bool = True, codex: bool = True):
        self.port, self.root = port, root
        mc_chat.ensure_dirs(root)
        (root / "sources").mkdir(mode=0o700, exist_ok=True)
        (root / "log").mkdir(mode=0o700, exist_ok=True)
        self.key = mc_chat.secret(root)
        self.auth = Auth(lambda: mc_chat.secret(root, create=False), port)
        self.hub = ev.Hub()
        self.health = col.Health(self.hub)
        self.started = time.time()
        home = Path.home()
        wal_roots = wal_roots or [(home / ".claude" / "wals", "claude"), (home / ".agent-harness" / "codex-wals", "codex")]
        read_roots = [r for r, _ in wal_roots] + [root]
        if initiatives:
            read_roots.append(Path(initiatives).parent)
        self.reader = Reader(read_roots)
        self.runner = runner or Runner(python=sys.executable, ah=str(HOOKS / "ah.py"), codex=codex_binary(),
                                       fabric_bin=fabric_bin)
        self.tailer = col.WalTailer(self.hub, self.health, self.reader, wal_roots)
        self.initiatives = col.Initiatives(self.hub, self.health, self.reader, initiatives)
        self.owners = col.Owners(self.hub, self.health, self.runner, self.tailer)
        self.github = col.GitHub(self.hub, self.health, self.runner)
        self.tickets = col.Tickets(self.hub, self.health, self.runner, self.tracked_tickets)
        self.remote = col.Remote(self.hub, self.health, self.runner, enabled=remote, fabric=bool(fabric_bin),
                                 drop_dir=root / "sources")
        self.drop = col.FileDrop(self.hub, self.health, self.reader, root / "sources")
        self.collectors = [self.tailer, self.initiatives, self.drop, self.owners, self.github, self.tickets,
                           self.remote]
        self.codex = CodexResponder(self.hub, self.health, self.runner, codex_binary(), root,
                                    disabled="" if codex else "Codex chat is turned off for this instance")
        self.chat_sig = None
        self.stop = threading.Event()
        self.threads: list[threading.Thread] = []
        if start_threads:
            self.start()

    def tracked_tickets(self):
        refs = [i.get("ticket") for i in self.initiatives.items if i.get("ticket")]
        return refs + self.owners.tickets()

    def start(self) -> None:
        for target, name in ((self.loop, "collectors"), (self.codex.loop, "codex"), (self.chat_loop, "chat")):
            thread = threading.Thread(target=target, name=name, daemon=True)
            thread.start()
            self.threads.append(thread)

    def loop(self) -> None:
        while not self.stop.is_set():
            now = time.time()
            for collector in self.collectors:
                if collector.due(now) and not self.stop.is_set():
                    collector.run(now)
            self.stop.wait(0.5)

    def chat_loop(self) -> None:
        while not self.stop.wait(1.0):
            try:
                self.refresh_chat()
            except Exception as exc:  # noqa: BLE001
                self.health.error("chat", f"{type(exc).__name__}: {str(exc)[:160]}")

    def refresh_chat(self, force: bool = False) -> None:
        chat = mc_chat.chat_dir(self.root)
        sig = []
        for sub in ("inbox", "outbox", "state", "targets"):
            try:
                info = os.stat(chat / sub)
                sig.append((info.st_mtime_ns, len(os.listdir(chat / sub))))
            except OSError:
                sig.append(None)
        if sig == self.chat_sig and not force:
            return
        self.chat_sig = sig
        self.hub.snapshot("chat", self.chat_snapshot())

    def chat_snapshot(self) -> dict:
        messages = []
        for record in mc_chat.inbox(self.root, limit=60):
            messages.append({"id": record.get("id"), "from": "user", "to": record.get("to"),
                             "client_key": record.get("client_key") if record.get("verified") else "",
                             "session": record.get("session"), "thread": record.get("thread"),
                             "text": str(record.get("text", ""))[:mc_chat.MAX_TEXT], "ts": record.get("created"),
                             "status": "forged" if not record.get("verified") else record.get("state"),
                             "reason": mc_chat.state(record.get("id", ""), self.root).get("reason", ""),
                             "label": "you · via dashboard" if record.get("verified") else "FORGED"})
        replies = {}
        for reply in mc_chat.outbox(self.root, limit=120):
            replies[reply.get("id")] = {"id": reply.get("id"), "from": reply.get("from"),
                                        "reply_to": reply.get("reply_to"), "text": str(reply.get("text", ""))[:65536],
                                        "ts": reply.get("created"), "final": bool(reply.get("final"))}
        return {"messages": messages, "replies": list(replies.values())[-60:],
                "targets": mc_chat.targets(self.root), "main_session": self.owners.session,
                "codex": {"available": self.codex.available[0], "reason": self.codex.available[1],
                          "busy": self.codex.busy}}

    def state(self) -> dict:
        return {"version": VERSION, "started": ev.iso(self.started), "host": ev.HOST,
                "initiatives": self.initiatives.snapshot(), "owners": self.owners.rows,
                "health": self.health.snapshot(), "events": self.hub.recent(limit=200),
                "chat": self.chat_snapshot(), "limits": {"chat_max": mc_chat.MAX_TEXT}}

    def post_chat(self, body: dict) -> tuple[int, dict]:
        if not isinstance(body, dict):
            return 400, {"error": "bad-json"}
        to = body.get("to")
        if to == "codex":
            ok, reason = self.codex.availability()
            if not ok:
                return 409, {"error": "unavailable", "message": reason}
        try:
            record, created = mc_chat.new_message(to, body.get("text"), client_key=body.get("client_key"),
                                                  session=body.get("session"), thread=body.get("thread"),
                                                  root=self.root)
        except mc_chat.ChatError as exc:
            status = 409 if exc.code == "no-target" else 400
            return status, {"error": exc.code, "message": str(exc)}
        self.hub.publish(ev.make("chat", "dashboard", f"you → {to}", eid=f"chat:{record['id']}",
                                 actor={"runtime": "dashboard"}, subject={"initiative": record.get("thread") or ""}))
        self.refresh_chat(force=True)
        return (201 if created else 200), {"id": record["id"], "created": created,
                                           "status": mc_chat.state(record["id"], self.root).get("status")}


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "MissionControl/" + VERSION
    sys_version = ""
    protocol_version = "HTTP/1.0"
    timeout = IO_TIMEOUT_S

    # -- plumbing
    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt, *args):  # never log query strings or bodies
        path = urlsplit(getattr(self, "path", "") or "").path[:120]
        self.server.log.info("%s %s %s", getattr(self, "command", "-"), path, args[1] if len(args) > 1 else "-")

    def send_secure(self, status: int, body: bytes = b"", ctype: str = "application/json; charset=utf-8",
                    extra: dict | None = None) -> None:
        self.send_response(status)
        headers = {"Content-Type": ctype, "Content-Length": str(len(body)), "Cache-Control": "no-store",
                   "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                   "Content-Security-Policy": CSP, "X-Frame-Options": "DENY",
                   "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin"}
        headers.update(extra or {})
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, status: int, value) -> None:
        self.send_secure(status, json.dumps(value, ensure_ascii=False).encode("utf-8"))

    def deny(self, status: int, reason: str) -> None:
        self.send_json(status, {"error": reason})

    def host_ok(self) -> bool:
        return (self.headers.get("Host") or "") in self.app.auth.hosts

    def same_origin_read(self, document: bool = False) -> bool:
        site = self.headers.get("Sec-Fetch-Site")
        origin = self.headers.get("Origin")
        if origin is not None:
            return origin in self.app.auth.origins
        if site == "same-origin":
            return True
        return document and site == "none"  # a top-level navigation the user typed or the launch redirect

    def authed(self):
        sid, info = self.app.auth.session(self.headers.get("Cookie"))
        if sid:
            self.server.mark_authed(self.connection)  # type: ignore[attr-defined]
        return sid, info

    # -- routes
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self.host_ok():
            return self.deny(403, "host")
        url = urlsplit(self.path)
        if url.path == "/healthz":
            return self.send_json(200, {"ok": True, "version": VERSION})
        if url.path == "/launch":
            return self.launch(url)
        document = url.path in ("/", "/index.html")
        if not self.same_origin_read(document=document):
            return self.deny(403, "cross-site")
        sid, info = self.authed()
        if not sid:
            if document:
                page = (b"<!doctype html><meta charset=utf-8><title>Mission Control</title>"
                        b"<p>Open Mission Control with <code>python3 ~/.claude/mission-control/server.py open</code>."
                        b" Launch links work once and expire after 60 seconds.</p>")
                return self.send_secure(401, page, "text/html; charset=utf-8")
            return self.deny(401, "session")
        if url.path == "/api/state":
            state = self.app.state()
            state["csrf"] = info["csrf"]
            return self.send_json(200, state)
        if url.path == "/api/events":
            return self.stream(info)
        return self.static(url.path)

    def do_POST(self):
        if not self.host_ok():
            return self.deny(403, "host")
        if self.headers.get("Origin") not in self.app.auth.origins:
            return self.deny(403, "origin")
        sid, info = self.authed()
        if not sid:
            return self.deny(401, "session")
        if not hmac.compare_digest(str(self.headers.get("X-MC-CSRF") or ""), info["csrf"]):
            return self.deny(403, "csrf")
        if urlsplit(self.path).path != "/api/chat":
            return self.deny(404, "not-found")
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            return self.deny(415, "content-type")
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            return self.deny(400, "length")
        if length <= 0 or length > MAX_BODY:
            return self.deny(413, "body-size")
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self.deny(400, "bad-json")
        status, value = self.app.post_chat(body)
        return self.send_json(status, value)

    def do_PUT(self):
        self.deny(405, "method")

    do_DELETE = do_PATCH = do_OPTIONS = do_PUT

    def launch(self, url):
        code = (parse_qs(url.query).get("c") or [""])[0]
        sid = self.app.auth.redeem(code)
        if not sid:
            return self.deny(401, "launch-code")
        cookie = f"mc_sid={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL_S}"
        return self.send_secure(303, b"", "text/plain", {"Location": "/", "Set-Cookie": cookie})

    def static(self, path: str):
        files = self.server.static_files  # type: ignore[attr-defined]
        rel = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
        real = files.get(rel)
        if real is None:
            return self.deny(404, "not-found")
        ctype = CONTENT_TYPES.get(Path(rel).suffix, "application/octet-stream")
        return self.send_secure(200, real.read_bytes(), ctype)

    def stream(self, info) -> None:
        client = self.app.hub.attach()
        if client is None:
            return self.deny(503, "too-many-streams")
        try:
            last = int(self.headers.get("Last-Event-ID") or "0")
        except ValueError:
            last = 0
        self.connection.settimeout(None)
        self.send_response(200)
        for key, value in {"Content-Type": "text/event-stream; charset=utf-8", "Cache-Control": "no-store",
                           "X-Content-Type-Options": "nosniff", "Content-Security-Policy": CSP,
                           "Referrer-Policy": "no-referrer", "X-Accel-Buffering": "no"}.items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(b"retry: 3000\n\n")
            for event in self.app.hub.recent(after=last, limit=100) if last else []:
                self.wfile.write(self.app.hub.frame(0, "event", event))
            self.wfile.flush()
            while not self.app.stop.is_set():
                frames = client.take(SSE_HEARTBEAT_S)
                if frames is None:
                    break  # dropped as a slow client
                if not frames:
                    self.wfile.write(b": keepalive\n\n")
                for frame in frames:
                    self.wfile.write(frame)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.app.hub.detach(client)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, app: App, web_dir: Path, log: logging.Logger):
        self.app, self.log = app, log
        self.static_files = self._index(web_dir)
        self.conn_lock = threading.Lock()
        self.live: dict[socket.socket, list] = {}  # socket -> [accepted_at, authed]
        super().__init__(("127.0.0.1", app.port), Handler)

    @staticmethod
    def _index(web_dir: Path) -> dict[str, Path]:
        files = {}
        if web_dir.is_dir():
            for path in web_dir.rglob("*"):
                if path.is_file() and not path.is_symlink() and path.suffix in CONTENT_TYPES and \
                        "tests" not in path.relative_to(web_dir).parts:
                    files[path.relative_to(web_dir).as_posix()] = path
        return files

    def mark_authed(self, sock) -> None:
        with self.conn_lock:
            if sock in self.live:
                self.live[sock][1] = True

    def process_request(self, request, client_address):
        with self.conn_lock:
            if len(self.live) >= MAX_CONNECTIONS:
                victims = sorted((v[0], s) for s, v in self.live.items() if not v[1])
                if victims:  # evict the oldest unauthenticated connection, never an authenticated one
                    _, victim = victims[0]
                    self.live.pop(victim, None)
                    try:
                        victim.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                else:
                    self.shutdown_request(request)
                    return
            self.live[request] = [time.monotonic(), False]
        request.settimeout(IO_TIMEOUT_S)
        super().process_request(request, client_address)

    def shutdown_request(self, request):
        with self.conn_lock:
            self.live.pop(request, None)
        super().shutdown_request(request)


def make_logger(root: Path) -> logging.Logger:
    log = logging.getLogger("mission-control." + hashlib.sha256(str(root).encode()).hexdigest()[:12])
    log.propagate = False
    if not log.handlers:
        (root / "log").mkdir(mode=0o700, parents=True, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(root / "log" / "server.log", maxBytes=5 * 1024 * 1024,
                                                       backupCount=2)
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)
    return log


# ---------------------------------------------------------------- CLI

def launch_url(port: int) -> str:
    return f"http://127.0.0.1:{port}/launch?c={mint_code(mc_chat.secret())}"


def plist_text(port: int, python: str) -> str:
    root = mc_chat.home()
    path = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin:" + str(Path.home() / ".local" / "bin")
    args = "".join(f"<string>{a}</string>" for a in (python, str(HERE / "server.py"), "serve", "--port", str(port)))
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{LABEL}</string>
<key>ProgramArguments</key><array>{args}</array>
<key>EnvironmentVariables</key><dict><key>PATH</key><string>{path}</string></dict>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>15</integer>
<key>ProcessType</key><string>Background</string>
<key>LowPriorityIO</key><true/>
<key>StandardOutPath</key><string>{root}/log/launchd.out.log</string>
<key>StandardErrorPath</key><string>{root}/log/launchd.err.log</string>
</dict></plist>
"""


def plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def cmd_install(args) -> int:
    text = plist_text(args.port, args.python or "/usr/bin/python3")
    target = plist_path()
    domain = f"gui/{os.getuid()}"
    if not args.apply:
        print(f"would write {target} and run: launchctl bootout {domain}/{LABEL}; launchctl bootstrap {domain} {target}")
        return 0
    mc_chat.ensure_dirs()
    (mc_chat.home() / "log").mkdir(mode=0o700, exist_ok=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    mc_chat.atomic_write(target, text.encode("utf-8"))
    os.chmod(target, 0o644)
    subprocess.run(["launchctl", "bootout", f"{domain}/{LABEL}"], capture_output=True)
    done = subprocess.run(["launchctl", "bootstrap", domain, str(target)], capture_output=True, text=True)
    if done.returncode != 0:
        print(f"launchctl bootstrap failed: {done.stderr.strip()[:300]}", file=sys.stderr)
        return 1
    print(f"installed {LABEL}: start/stop with `launchctl kickstart -k {domain}/{LABEL}` / "
          f"`launchctl bootout {domain}/{LABEL}`; logs in {mc_chat.home() / 'log'}")
    return 0


def cmd_uninstall(args) -> int:
    domain = f"gui/{os.getuid()}"
    if not args.apply:
        print(f"would run launchctl bootout {domain}/{LABEL} and remove {plist_path()}")
        return 0
    subprocess.run(["launchctl", "bootout", f"{domain}/{LABEL}"], capture_output=True)
    try:
        plist_path().unlink()
    except OSError:
        pass
    print(f"uninstalled {LABEL} (data in {mc_chat.home()} kept)")
    return 0


def cmd_status(args) -> int:
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{args.port}/healthz", timeout=3) as resp:
            health = json.loads(resp.read())
    except OSError as exc:
        health = {"ok": False, "error": str(exc)[:120]}
    launchd = subprocess.run(["launchctl", "print", f"gui/{os.getuid()}/{LABEL}"], capture_output=True, text=True)
    state = next((ln.strip() for ln in launchd.stdout.splitlines() if ln.strip().startswith(("state =", "pid ="))), "")
    print(json.dumps({"health": health, "launchd": state or "not loaded", "port": args.port,
                      "log": str(mc_chat.home() / "log" / "server.log")}, indent=1))
    return 0 if health.get("ok") else 1


def cmd_serve(args) -> int:
    root = mc_chat.home()
    log = make_logger(root)
    initiatives = args.initiatives or default_initiatives()
    try:
        app = App(port=args.port, root=root, initiatives=initiatives, remote=not args.no_remote,
                  fabric_bin=args.fabric_bin, start_threads=False, codex=not args.no_codex)
        server = Server(app, Path(args.web or (HERE / "web")), log)
    except OSError as exc:
        log.error("cannot bind 127.0.0.1:%s: %s", args.port, exc)
        print(f"mission-control: cannot bind 127.0.0.1:{args.port}: {exc}", file=sys.stderr)
        return 2
    app.start()
    log.info("serving on 127.0.0.1:%s initiatives=%s", args.port, initiatives or "-")
    print(f"mission-control: serving on http://127.0.0.1:{args.port} (open with `server.py open`)", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        app.stop.set()
        app.codex.stop.set()
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="mission-control", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("serve")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--initiatives")
    p.add_argument("--no-remote", action="store_true")
    p.add_argument("--no-codex", action="store_true", help="never run codex exec (disposable or test instances)")
    p.add_argument("--fabric-bin")
    p.add_argument("--web")
    for name in ("url", "open", "status"):
        q = sub.add_parser(name)
        q.add_argument("--port", type=int, default=DEFAULT_PORT)
    for name in ("install-launchd", "uninstall-launchd"):
        q = sub.add_parser(name)
        q.add_argument("--port", type=int, default=DEFAULT_PORT)
        q.add_argument("--python")
        q.add_argument("--apply", action="store_true")
    sub.add_parser("rotate-secret")
    args = parser.parse_args(argv)
    if args.cmd == "serve":
        return cmd_serve(args)
    if args.cmd == "url":
        print(launch_url(args.port))
        return 0
    if args.cmd == "open":
        subprocess.run(["open", launch_url(args.port)], check=False)
        print("opened a single-use launch link in your default browser (valid 60 s)")
        return 0
    if args.cmd == "status":
        return cmd_status(args)
    if args.cmd == "install-launchd":
        return cmd_install(args)
    if args.cmd == "uninstall-launchd":
        return cmd_uninstall(args)
    if args.cmd == "rotate-secret":
        mc_chat.rotate_secret()
        print("rotated: every launch code and inbox signature from the old secret is now invalid; restart the server")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
