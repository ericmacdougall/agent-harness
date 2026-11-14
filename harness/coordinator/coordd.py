#!/usr/bin/env python3
"""coordd: the host-side coordinator service (GoodQA goodqa#16043), minimal slice.

One long-running process under the OS service manager (systemd user unit on Linux). It holds the task
ledger, the routing decision and the report duty, so none of them depend on a chat session or on the laptop.

    coordd.py serve [--port P]          run the service (loopback only)
    coordd.py submit --kind K --text T [--ticket REF] [--key KEY]
    coordd.py chat TEXT...              direct chat with the coordinator
    coordd.py status | tasks | show ID

Design rules (same as the ahc spec: deterministic control plane, LLMs only as bounded workers):
- No LLM call decides routing, retries or reporting. `route()` is a table.
- Every task and every external effect (worker run, ticket comment) is a ledger row written BEFORE the
  action (intent) and updated after it (readback). A finished task is never run again.
- On start, tasks left `running` by a dead process are requeued once (attempt budget 2), then failed.
- A task that no lane can serve fails with the reason. It is never dropped silently.
- Listens on 127.0.0.1 only. Every request needs the bearer token in STATE/token (0600).

State lives in ~/.agent-harness/coordinator (override with COORD_HOME): ledger.sqlite, token, runs/<id>/.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DEFAULT_PORT = 47625
MAX_TEXT = 8000
MAX_ATTEMPTS = 2
WORKER_TIMEOUT_S = 900
KINDS = ("status", "agent", "chat")
TICKET_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}#[0-9]{1,9}$")
KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{3,80}$")
ID_RE = re.compile(r"^t-[0-9a-f]{12}$")
HELP = ("Commands: status | tasks | show <id> | run <task text> [ticket:<slug>#<n>] | help. "
        "Anything else is free-form chat, which needs a subscription-signed-in agent CLI on this host.")


def home() -> Path:
    return Path(os.environ.get("COORD_HOME") or (Path.home() / ".agent-harness" / "coordinator"))


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_home() -> Path:
    root = home()
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    (root / "runs").mkdir(exist_ok=True)
    token = root / "token"
    if not token.exists():
        fd = os.open(token, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(24))
    return root


def db(root: Path) -> sqlite3.Connection:
    con = sqlite3.connect(root / "ledger.sqlite", timeout=30, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript("""
        CREATE TABLE IF NOT EXISTS tasks(
            id TEXT PRIMARY KEY, key TEXT UNIQUE, kind TEXT NOT NULL, text TEXT NOT NULL, ticket TEXT,
            origin TEXT NOT NULL, state TEXT NOT NULL, lane TEXT, attempts INTEGER NOT NULL DEFAULT 0,
            result TEXT, error TEXT, created TEXT NOT NULL, updated TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS effects(
            key TEXT PRIMARY KEY, task TEXT NOT NULL, effect TEXT NOT NULL, state TEXT NOT NULL,
            detail TEXT, created TEXT NOT NULL, updated TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events(
            n INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, task TEXT, what TEXT NOT NULL, detail TEXT);
    """)
    return con


def log_event(con, task, what, detail="") -> None:
    con.execute("INSERT INTO events(ts,task,what,detail) VALUES(?,?,?,?)", (now_iso(), task, what, detail[:2000]))


def mc_drop(task_id: str, what: str, summary: str, ticket: str | None, severity: str = "info") -> None:
    """Tell Mission Control (event drop, mc.event/1). Best effort: the ledger is the record."""
    try:
        drop = Path.home() / ".agent-harness" / "mission-control" / "sources"
        drop.mkdir(parents=True, exist_ok=True)
        ev = {"schema": "mc.event/1", "id": f"coordinator:{task_id}:{what}", "ts": now_iso(), "kind": "system",
              "summary": summary[:270], "severity": severity,
              "actor": {"runtime": "coordinator", "session": "coordd", "agent": "coordd"}}
        if ticket:
            ev["subject"] = {"ticket": ticket}
        with open(drop / "coordinator.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(ev) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------- intake
def submit(con, kind: str, text: str, ticket: str | None, origin: str, key: str | None) -> dict:
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    text = (text or "").strip()
    if not text or len(text) > MAX_TEXT:
        raise ValueError("text is empty or too long")
    if ticket and not TICKET_RE.match(ticket):
        raise ValueError("ticket must look like slug#123")
    if key and not KEY_RE.match(key):
        raise ValueError("bad key")
    if key:
        row = con.execute("SELECT * FROM tasks WHERE key=?", (key,)).fetchone()
        if row:  # idempotent resubmit: same key returns the same task, nothing runs twice
            return dict(row) | {"deduplicated": True}
    tid = "t-" + secrets.token_hex(6)
    ts = now_iso()
    con.execute("INSERT INTO tasks(id,key,kind,text,ticket,origin,state,created,updated) VALUES(?,?,?,?,?,?,?,?,?)",
                (tid, key, kind, text, ticket, origin, "queued", ts, ts))
    log_event(con, tid, "accepted", f"kind={kind} origin={origin}")
    mc_drop(tid, "accepted", f"coordinator accepted {kind} task {tid}", ticket)
    return dict(con.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone())


# ---------------------------------------------------------------- lanes
def codex_pool_bin() -> str | None:
    for cand in (os.environ.get("COORD_CODEX_POOL"), str(Path.home() / ".claude" / "hooks" / "codex_pool.py")):
        if cand and os.path.isfile(cand):
            return cand
    return None


def subscription_cli() -> tuple[str, str] | None:
    """A CLI signed in with a subscription, for free-form chat. API keys are never used for chat."""
    claude = shutil.which("claude")
    if claude:
        try:
            out = subprocess.run([claude, "auth", "status"], capture_output=True, text=True, timeout=20).stdout
            if json.loads(out or "{}").get("loggedIn") is True:
                return "claude", claude
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    codex = shutil.which("codex")
    if codex:
        try:
            out = subprocess.run([codex, "login", "status"], capture_output=True, text=True, timeout=20)
            if "chatgpt" in (out.stdout + out.stderr).lower():
                return "codex", codex
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def route(task: dict) -> tuple[str | None, str]:
    """Deterministic routing table: (lane, reason). No model call."""
    kind = task["kind"]
    if kind == "status":
        return "builtin-status", "status is answered from host facts, no model"
    if kind == "agent":
        if codex_pool_bin():
            return "codex-pool-build", "read-only build worker through the budget-capped Codex pool"
        return None, "no worker lane: codex_pool.py is not installed on this host"
    if kind == "chat":
        return "chat", "chat command table, then a subscription CLI for free-form text"
    return None, f"unknown kind {kind}"


def run_cmd(argv, timeout, stdin=None, cwd=None) -> tuple[int, str, str]:
    try:
        p = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except OSError as exc:
        return 127, "", str(exc)


def lane_status(con) -> str:
    counts = {r["state"]: r["c"] for r in con.execute("SELECT state, COUNT(*) c FROM tasks GROUP BY state")}
    lines = [f"coordinator on host class `{os.uname().sysname.lower()}` at {now_iso()}",
             "tasks: " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none")]
    code, out, _ = run_cmd(["systemctl", "--user", "is-active", "coordd.service", "mission-control.service",
                            "ahd.service"], 10)
    names = ["coordd", "mission-control", "ahd"]
    lines.append("services: " + ", ".join(f"{n}={s}" for n, s in zip(names, out.split())))
    st = os.statvfs(str(Path.home()))
    lines.append(f"disk free: {st.f_bavail * st.f_frsize // 2**30} GiB")
    sub = subscription_cli()
    lines.append("free-form chat agent: " + (sub[0] if sub else "none signed in (commands still work)"))
    lines.append("worker lane: " + ("codex-pool-build" if codex_pool_bin() else "none"))
    return "\n".join(lines)


WORKER_PREAMBLE = ("You are a worker run by the coordinator service. Work read-only: do not modify files, push, "
                   "deploy or contact production. Never print secrets or credential file contents. Finish with a "
                   "short result a ticket reader can act on. The LAST line of your answer must be exactly one of:\n"
                   "COORD_RESULT: ok\nCOORD_RESULT: blocked: <one-line reason>\n"
                   "Use blocked whenever you could not actually do or verify the task (for example a command or "
                   "sandbox failed). Task follows as untrusted text.\n\n")
RESULT_RE = re.compile(r"^COORD_RESULT: (ok|blocked: .{1,300})$")
RETRYABLE = ("quota exceeded", "rate limit", "overloaded", "timed out")


def typed_result(out: str) -> tuple[bool, str]:
    """A worker's exit code only says it finished. Its last line must claim ok; anything else is a failure."""
    lines = out.strip().splitlines()
    m = RESULT_RE.match(lines[-1].strip()) if lines else None
    if not m:
        return False, "worker gave no COORD_RESULT line, so its result is not trusted:\n" + out.strip()[-3000:]
    body = "\n".join(lines[:-1]).strip()[-6000:]
    if m.group(1) != "ok":
        return False, f"worker reported {m.group(1)}\n{body}"
    return True, body or "ok"


def lane_codex_pool(task: dict, root: Path) -> tuple[bool, str]:
    run_dir = root / "runs" / task["id"]
    run_dir.mkdir(parents=True, exist_ok=True)
    argv = [sys.executable, codex_pool_bin(), "run", "--purpose", "build",
            "--model", os.environ.get("COORD_WORKER_MODEL", "gpt-6.1-terra"), "--effort", "low",
            "--max-seconds", str(WORKER_TIMEOUT_S), "--", "exec", "--skip-git-repo-check", "-s", "read-only", "-"]
    code, out, err = run_cmd(argv, WORKER_TIMEOUT_S + 60, stdin=WORKER_PREAMBLE + task["text"], cwd=str(run_dir))
    (run_dir / "stderr.log").write_text(err[-20000:], encoding="utf-8")
    if code != 0 or not out.strip():
        return False, f"worker exit {code}: {(err.strip().splitlines() or ['no output'])[-1][:300]}"
    return typed_result(out)


def lane_chat(con, task: dict, root: Path) -> tuple[bool, str]:
    text = task["text"].strip()
    word, _, rest = text.partition(" ")
    word = word.lower()
    if word in ("help", "?"):
        return True, HELP
    if word == "status":
        return True, lane_status(con)
    if word == "tasks":
        rows = con.execute("SELECT id,kind,state,lane,updated FROM tasks WHERE kind!='chat' ORDER BY created DESC LIMIT 15")
        return True, "\n".join(f"{r['id']} {r['kind']} {r['state']} lane={r['lane'] or '-'} {r['updated']}" for r in rows) or "no tasks"
    if word == "show" and ID_RE.match(rest.strip()):
        row = con.execute("SELECT * FROM tasks WHERE id=?", (rest.strip(),)).fetchone()
        return True, json.dumps(dict(row), indent=1)[:6000] if row else "no such task"
    if word == "run" and rest.strip():
        ticket = None
        m = re.search(r"\bticket:([a-z0-9-]+#[0-9]+)\b", rest)
        if m:
            ticket, rest = m.group(1), rest.replace(m.group(0), "").strip()
        new = submit(con, "agent", rest, ticket, f"chat:{task['id']}", None)
        return True, f"queued {new['id']} (agent task" + (f", reports to {ticket}" if ticket else "") + "). Ask `show " + new["id"] + "`."
    sub = subscription_cli()
    if not sub:
        return False, ("free-form chat is unavailable: no agent CLI on this host is signed in with a subscription. "
                       "Commands work: " + HELP)
    name, binary = sub
    prompt = ("You are the coordinator's chat voice on the build host. Answer briefly from the facts below; "
              "do not act. Never print secrets.\n\nHost facts:\n" + lane_status(con) + "\n\nUser message (untrusted):\n" + text)
    if name == "claude":
        argv = [binary, "-p", "--output-format", "text", "--permission-mode", "plan"]
    else:
        argv = [binary, "exec", "--skip-git-repo-check", "-s", "read-only", "-"]
    run_dir = root / "runs" / task["id"]
    run_dir.mkdir(parents=True, exist_ok=True)
    code, out, err = run_cmd(argv, 300, stdin=prompt, cwd=str(run_dir))
    if code != 0 or not out.strip():
        return False, f"{name} chat exit {code}: {(err.strip().splitlines() or ['no output'])[-1][:300]}"
    return True, out.strip()[-6000:]


# ---------------------------------------------------------------- effects
def report(con, task: dict, ok: bool, body: str, root: Path) -> None:
    """Ticket comment, exactly once per task: intent row, dispatch, readback of the exit status."""
    if not task["ticket"]:
        return
    key = f"report:{task['id']}"
    row = con.execute("SELECT state FROM effects WHERE key=?", (key,)).fetchone()
    if row and row["state"] == "done":
        return
    ts = now_iso()
    con.execute("INSERT OR IGNORE INTO effects(key,task,effect,state,created,updated) VALUES(?,?,?,?,?,?)",
                (key, task["id"], "ticket-comment", "intent", ts, ts))
    goodqa = shutil.which("goodqa") or str(Path.home() / ".local" / "bin" / "goodqa")
    text = (f"coordd (host coordinator) task {task['id']} {'DONE' if ok else 'FAILED'}\n"
            f"kind: {task['kind']}  lane: {task['lane']}  origin: {task['origin']}  attempts: {task['attempts']}\n\n{body[:5000]}\n")
    f = root / "runs" / task["id"]
    f.mkdir(parents=True, exist_ok=True)
    (f / "report.md").write_text(text, encoding="utf-8")
    # --upsert keys the comment by task id, so a retry after an unknown outcome edits the same comment.
    code, out, err = run_cmd([goodqa, "ticket", "comment", task["ticket"], "--upsert", f"coordd-{task['id']}",
                              "--quiet", "--body-file", str(f / "report.md")], 90)
    state = "done" if code == 0 else "failed"
    con.execute("UPDATE effects SET state=?, detail=?, updated=? WHERE key=?",
                (state, (out or err).strip()[-300:], now_iso(), key))
    log_event(con, task["id"], f"report-{state}", (out or err).strip()[-300:])


def retry_reports(con, root: Path) -> None:
    for e in con.execute("SELECT task FROM effects WHERE effect='ticket-comment' AND state!='done'").fetchall():
        t = con.execute("SELECT * FROM tasks WHERE id=?", (e["task"],)).fetchone()
        if t and t["state"] in ("done", "failed"):
            report(con, dict(t), t["state"] == "done", t["result"] or t["error"] or "", root)


# ---------------------------------------------------------------- loop
def recover(con) -> None:
    for row in con.execute("SELECT id, attempts FROM tasks WHERE state='running'").fetchall():
        if row["attempts"] < MAX_ATTEMPTS:
            con.execute("UPDATE tasks SET state='queued', updated=? WHERE id=?", (now_iso(), row["id"]))
            log_event(con, row["id"], "requeued-after-restart", f"attempts={row['attempts']}")
        else:
            con.execute("UPDATE tasks SET state='failed', error=?, updated=? WHERE id=?",
                        ("interrupted by a restart and out of attempts", now_iso(), row["id"]))
            log_event(con, row["id"], "failed", "restart, attempt budget spent")


def run_one(con, root: Path, chat_only: bool) -> bool:
    cond = "kind='chat'" if chat_only else "kind!='chat'"
    con.execute("BEGIN IMMEDIATE")
    row = con.execute(f"SELECT * FROM tasks WHERE state='queued' AND {cond} ORDER BY created LIMIT 1").fetchone()
    if not row:
        con.execute("COMMIT")
        return False
    task = dict(row)
    lane, reason = route(task)
    task["lane"], task["attempts"] = lane, task["attempts"] + 1
    con.execute("UPDATE tasks SET state='running', lane=?, attempts=?, updated=? WHERE id=?",
                (lane, task["attempts"], now_iso(), task["id"]))
    log_event(con, task["id"], "routed", f"lane={lane} reason={reason}")
    con.execute("COMMIT")
    if lane is None:
        ok, body = False, reason
    else:
        try:
            if lane == "builtin-status":
                ok, body = True, lane_status(con)
            elif lane == "codex-pool-build":
                ok, body = lane_codex_pool(task, root)
            else:
                ok, body = lane_chat(con, task, root)
        except Exception as exc:  # noqa: BLE001 - a lane crash is a failed task, never a dead service
            ok, body = False, f"{type(exc).__name__}: {str(exc)[:300]}"
    if (not ok and lane == "codex-pool-build" and task["attempts"] < MAX_ATTEMPTS
            and any(w in body.lower() for w in RETRYABLE)):
        # Provider-transient class: one more attempt (the pool rotates keys); never an unbounded loop.
        con.execute("UPDATE tasks SET state='queued', error=?, updated=? WHERE id=?", (body, now_iso(), task["id"]))
        log_event(con, task["id"], "retry-transient", body[:300])
        return True
    con.execute("UPDATE tasks SET state=?, result=?, error=?, updated=? WHERE id=?",
                ("done" if ok else "failed", body if ok else None, None if ok else body, now_iso(), task["id"]))
    log_event(con, task["id"], "done" if ok else "failed", body[:300])
    if task["kind"] != "chat":
        mc_drop(task["id"], "finished", f"coordinator task {task['id']} {'done' if ok else 'FAILED'} via {lane}",
                task["ticket"], "info" if ok else "warn")
    report(con, task, ok, body, root)
    return True


def worker_loop(root: Path, stop: threading.Event, chat_only: bool) -> None:
    con = db(root)
    last_retry = 0.0
    while not stop.is_set():
        try:
            busy = run_one(con, root, chat_only)
            if not chat_only and time.time() - last_retry > 120:
                last_retry = time.time()
                retry_reports(con, root)
        except Exception as exc:  # noqa: BLE001
            try:
                con.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            print(f"coordd: loop error {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
            busy = False
        if not busy:
            stop.wait(1.0)


# ---------------------------------------------------------------- http
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Coordinator</title><style>
:root{--bg:#f6f7f9;--fg:#15181d;--mut:#5b6472;--card:#fff;--line:#d5dae1;--acc:#1f5fbf}
@media(prefers-color-scheme:dark){:root{--bg:#111418;--fg:#e8ebef;--mut:#9aa4b2;--card:#1a1f26;--line:#2c3440;--acc:#7fb0ff}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:16px}h1{font-size:20px;margin:8px 0}
pre,.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;white-space:pre-wrap;overflow-wrap:anywhere}
form{display:flex;gap:8px;margin:12px 0}input[type=text],input[type=password]{flex:1;min-width:0;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);font:inherit}
button{padding:10px 16px;border:0;border-radius:8px;background:var(--acc);color:#fff;font:inherit;cursor:pointer}
button:focus-visible,input:focus-visible{outline:3px solid var(--acc);outline-offset:2px}
.me{color:var(--mut)}.err{color:#c0392b}label{display:block;color:var(--mut);font-size:13px}
</style></head><body><main>
<h1>Coordinator (host service)</h1>
<p class="me">Direct chat with the coordinator process on this host. Commands: status, tasks, show &lt;id&gt;, run &lt;task&gt; [ticket:slug#n], help.</p>
<div id="auth"><label for="tok">Access token (from <code>coordd.py token</code> on the host; kept in this tab only)</label>
<form id="tf"><input id="tok" type="password" autocomplete="off" required><button>Unlock</button></form></div>
<div id="log" aria-live="polite"></div>
<form id="cf" hidden><label for="msg" style="position:absolute;left:-9999px">Message</label>
<input id="msg" type="text" maxlength="4000" placeholder="Message the coordinator" required><button>Send</button></form>
<script>
let tok="";const log=document.getElementById("log");
function add(cls,t){const d=document.createElement("pre");d.className=cls;d.textContent=t;log.appendChild(d);d.scrollIntoView()}
async function api(path,body){const r=await fetch(path,{method:body?"POST":"GET",headers:{"Authorization":"Bearer "+tok,"Content-Type":"application/json"},body:body?JSON.stringify(body):undefined});
 if(!r.ok)throw new Error((await r.json().catch(()=>({}))).error||("HTTP "+r.status));return r.json()}
document.getElementById("tf").onsubmit=async e=>{e.preventDefault();tok=document.getElementById("tok").value.trim();
 try{const s=await api("/api/status");document.getElementById("auth").hidden=true;document.getElementById("cf").hidden=false;add("card",s.text);document.getElementById("msg").focus()}
 catch(x){add("err","Could not unlock: "+x.message)}};
document.getElementById("cf").onsubmit=async e=>{e.preventDefault();const m=document.getElementById("msg");const text=m.value.trim();if(!text)return;m.value="";add("me","you: "+text);
 const btn=e.target.querySelector("button");btn.disabled=true;
 try{const t=await api("/api/chat",{text,key:"web-"+crypto.randomUUID()});let cur=t;
  for(let i=0;i<300&&cur.state!=="done"&&cur.state!=="failed";i++){await new Promise(r=>setTimeout(r,1000));cur=await api("/api/tasks/"+t.id)}
  add(cur.state==="done"?"card":"err",cur.state==="done"?cur.result:(cur.error||"no answer yet; ask: show "+t.id))}
 catch(x){add("err","Send failed: "+x.message+". Your message was not lost if it shows under `tasks`.")}
 finally{btn.disabled=false;m.focus()}};
</script></main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "coordd/0.1"
    root: Path = None  # type: ignore[assignment]
    token: str = ""

    def log_message(self, fmt, *args):  # quiet: journald gets errors only
        return

    def _send(self, code, obj, ctype="application/json"):
        body = obj.encode() if isinstance(obj, str) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _authed(self) -> bool:
        got = self.headers.get("Authorization", "")
        return got.startswith("Bearer ") and hmac.compare_digest(got[7:].strip(), self.token)

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        return host in ("127.0.0.1", "localhost")  # DNS-rebinding guard

    def do_GET(self):  # noqa: N802
        if not self._host_ok():
            return self._send(403, {"error": "bad host"})
        if self.path == "/healthz":
            return self._send(200, {"ok": True, "service": "coordd", "ts": now_iso()})
        if self.path == "/":
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if not self._authed():
            return self._send(401, {"error": "token required"})
        con = db(self.root)
        if self.path == "/api/status":
            return self._send(200, {"text": lane_status(con)})
        if self.path == "/api/tasks":
            rows = con.execute("SELECT id,kind,state,lane,ticket,origin,attempts,created,updated FROM tasks ORDER BY created DESC LIMIT 50")
            return self._send(200, {"tasks": [dict(r) for r in rows]})
        m = re.match(r"^/api/tasks/(t-[0-9a-f]{12})$", self.path)
        if m:
            row = con.execute("SELECT * FROM tasks WHERE id=?", (m.group(1),)).fetchone()
            return self._send(200, dict(row)) if row else self._send(404, {"error": "no such task"})
        return self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if not self._host_ok():
            return self._send(403, {"error": "bad host"})
        if not self._authed():
            return self._send(401, {"error": "token required"})
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            return self._send(415, {"error": "json only"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > 64_000:
                raise ValueError("bad length")
            body = json.loads(self.rfile.read(n))
            if not isinstance(body, dict):
                raise ValueError("object expected")
            con = db(self.root)
            if self.path == "/api/chat":
                task = submit(con, "chat", str(body.get("text") or ""), None, "chat", body.get("key"))
            elif self.path == "/api/tasks":
                task = submit(con, str(body.get("kind") or ""), str(body.get("text") or ""), body.get("ticket"),
                              str(body.get("origin") or "api")[:80], body.get("key"))
            else:
                return self._send(404, {"error": "not found"})
            return self._send(200, task)
        except (ValueError, json.JSONDecodeError) as exc:
            return self._send(400, {"error": str(exc)[:200]})


def cmd_serve(args) -> int:
    root = ensure_home()
    con = db(root)
    recover(con)
    Handler.root, Handler.token = root, (root / "token").read_text().strip()
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    except OSError as exc:
        print(f"coordd: cannot bind 127.0.0.1:{args.port}: {exc}", file=sys.stderr)
        return 2
    stop = threading.Event()
    # Two loops so a long worker run never blocks chat (the lesson of a coordinator stuck behind one call).
    for chat_only in (False, True):
        threading.Thread(target=worker_loop, args=(root, stop, chat_only), daemon=True).start()
    log_event(con, None, "started", f"port={args.port} pid={os.getpid()}")
    mc_drop("service", f"started-{int(time.time())}", "coordinator service started", None)
    print(f"coordd: serving on http://127.0.0.1:{args.port}", flush=True)
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
    return 0


def client(args, path: str, body: dict | None = None) -> dict:
    root = ensure_home()
    req = urllib.request.Request(f"http://127.0.0.1:{args.port}{path}", method="POST" if body is not None else "GET",
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + (root / "token").read_text().strip(),
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"coordd: {exc.code} {exc.read().decode()[:200]}")
    except OSError as exc:
        raise SystemExit(f"coordd: service not reachable on 127.0.0.1:{args.port}: {exc}")


def wait_task(args, tid: str, seconds: int) -> dict:
    end = time.time() + seconds
    while True:
        t = client(args, f"/api/tasks/{tid}")
        if t["state"] in ("done", "failed") or time.time() > end:
            return t
        time.sleep(1)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="coordd")
    ap.add_argument("--port", type=int, default=int(os.environ.get("COORD_PORT") or DEFAULT_PORT))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve")
    s = sub.add_parser("submit")
    s.add_argument("--kind", required=True, choices=KINDS)
    s.add_argument("--text", required=True)
    s.add_argument("--ticket")
    s.add_argument("--key")
    s.add_argument("--origin", default="cli")
    s.add_argument("--wait", type=int, default=0)
    c = sub.add_parser("chat")
    c.add_argument("text", nargs="+")
    for name in ("status", "tasks", "token"):
        sub.add_parser(name)
    sh = sub.add_parser("show")
    sh.add_argument("id")
    args = ap.parse_args(argv)
    if args.cmd == "serve":
        return cmd_serve(args)
    if args.cmd == "token":  # for the web page; printed to the caller's own terminal only
        print((ensure_home() / "token").read_text().strip())
        return 0
    if args.cmd == "submit":
        t = client(args, "/api/tasks", {"kind": args.kind, "text": args.text, "ticket": args.ticket,
                                        "key": args.key, "origin": args.origin})
        if args.wait:
            t = wait_task(args, t["id"], args.wait)
        print(json.dumps(t, indent=1))
        return 0 if t["state"] != "failed" else 1
    if args.cmd == "chat":
        t = client(args, "/api/chat", {"text": " ".join(args.text)})
        t = wait_task(args, t["id"], 320)
        print(t.get("result") or t.get("error") or f"no answer yet (task {t['id']} is {t['state']})")
        return 0 if t["state"] == "done" else 1
    if args.cmd == "status":
        print(client(args, "/api/status")["text"])
    elif args.cmd == "tasks":
        for t in client(args, "/api/tasks")["tasks"]:
            print(t["id"], t["kind"], t["state"], t["lane"] or "-", t["ticket"] or "-", t["updated"])
    elif args.cmd == "show":
        print(json.dumps(client(args, f"/api/tasks/{args.id}"), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
