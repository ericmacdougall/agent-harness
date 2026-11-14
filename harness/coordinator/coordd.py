#!/usr/bin/env python3
"""coordd: the host-side coordinator service (GoodQA goodqa#16043), minimal slice.

One long-running process under the OS service manager (systemd user unit on Linux). It holds the task
ledger, the routing decision and the report duty, so none of them depend on a chat session or on the laptop.

    coordd.py serve [--port P]          run the service (loopback only)
    coordd.py submit --kind K --text T [--ticket REF] [--key KEY]
    coordd.py chat TEXT...              direct chat with the coordinator
    coordd.py status | tasks | show ID
    coordd.py logins | approve CODE | logout-all     browser sign-ins (device approval)

Design rules (same as the ahc spec: deterministic control plane, LLMs only as bounded workers):
- No LLM call decides routing, retries or reporting. `route()` is a table.
- Every task and every external effect (worker run, ticket comment) is a ledger row written BEFORE the
  action (intent) and updated after it (readback). A finished task is never run again.
- On start, tasks left `running` by a dead process are requeued once (attempt budget 2), then failed.
- A task that no lane can serve fails with the reason. It is never dropped silently.
- Listens on 127.0.0.1 only. The CLI authenticates with the token in STATE/token (0600), which never leaves the
  host. A browser signs in by device approval: it shows a code, `coordd.py approve CODE` on the host approves it.

State lives in ~/.agent-harness/coordinator (override with COORD_HOME): ledger.sqlite, token, runs/<id>/.
"""

from __future__ import annotations

import argparse
import hashlib
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
CAPS = ("answer", "run-commands", "write-worktree", "browser")  # what a task may require of a lane
# What each lane can do today. A capability is listed only when it has been shown to work on this host.
LANE_CAPS = {"codex-pool-build": {"answer"}}
# Lanes whose rerun cannot repeat an external effect (read-only; the ticket report is an upsert by task id).
REPLAY_SAFE = ("builtin-status", "codex-pool-build", "chat")
TERMINAL = ("done", "failed", "blocked", "outcome-unknown")
LOGIN_TTL_S = 300          # a shown code can be approved for this long
SESSION_TTL_S = 12 * 3600  # an approved browser session
LOGIN_MAX_PENDING = 10     # unapproved logins kept at once
LOGIN_STARTS_PER_MIN = 6
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"  # no 0/O, 1/I/L, U: look-alikes cannot be confused
CODE_RE = re.compile(r"^[A-HJKMNP-TV-Z2-9]{4}-[A-HJKMNP-TV-Z2-9]{4}$")
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
        CREATE TABLE IF NOT EXISTS logins(
            code TEXT PRIMARY KEY, poll_hash TEXT NOT NULL, state TEXT NOT NULL, client TEXT NOT NULL,
            created REAL NOT NULL, approved_by TEXT);
        CREATE TABLE IF NOT EXISTS sessions(
            sid_hash TEXT PRIMARY KEY, created REAL NOT NULL, expires REAL NOT NULL, client TEXT NOT NULL, code TEXT);
        CREATE TABLE IF NOT EXISTS events(
            n INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, task TEXT, what TEXT NOT NULL, detail TEXT);
    """)
    if "needs" not in [r["name"] for r in con.execute("PRAGMA table_info(tasks)")]:
        con.execute("ALTER TABLE tasks ADD COLUMN needs TEXT NOT NULL DEFAULT 'answer'")
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


# ---------------------------------------------------------------- web login (device approval)
# The browser never receives or types a secret that exists anywhere else. It shows a short code; someone who is
# already authenticated on the host approves that exact code; only the browser that started the login (it alone
# holds the poll secret) receives the session cookie. Codes expire, are single use, and starts are rate limited.
def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def login_start(con, client: str, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    con.execute("DELETE FROM logins WHERE created < ?", (now - LOGIN_TTL_S,))
    con.execute("DELETE FROM sessions WHERE expires < ?", (now,))
    pending = con.execute("SELECT COUNT(*) FROM logins WHERE state='pending'").fetchone()[0]
    recent = con.execute("SELECT COUNT(*) FROM logins WHERE created > ?", (now - 60,)).fetchone()[0]
    if pending >= LOGIN_MAX_PENDING or recent >= LOGIN_STARTS_PER_MIN:
        raise PermissionError("too many sign-in attempts; wait a minute")
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
    code, poll = raw[:4] + "-" + raw[4:], secrets.token_urlsafe(32)
    con.execute("INSERT INTO logins(code,poll_hash,state,client,created) VALUES(?,?,?,?,?)",
                (code, _h(poll), "pending", client[:300], now))
    log_event(con, None, "login-started", client[:300])
    return {"code": code, "poll": poll, "expires_in": LOGIN_TTL_S}


def login_pending(con, now: float | None = None) -> list[dict]:
    now = time.time() if now is None else now
    rows = con.execute("SELECT code, client, created FROM logins WHERE state='pending' AND created >= ? ORDER BY created",
                       (now - LOGIN_TTL_S,))
    return [{"code": r["code"], "client": r["client"], "age_s": int(now - r["created"])} for r in rows]


def login_approve(con, code: str, approver: str, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    code = (code or "").strip().upper()
    if not CODE_RE.match(code):
        raise ValueError("a code looks like ABCD-EFGH")
    cur = con.execute("UPDATE logins SET state='approved', approved_by=? WHERE code=? AND state='pending' AND created >= ?",
                      (approver[:80], code, now - LOGIN_TTL_S))
    if cur.rowcount != 1:
        raise ValueError("no pending sign-in has that code (expired, already used, or mistyped)")
    row = con.execute("SELECT client FROM logins WHERE code=?", (code,)).fetchone()
    log_event(con, None, "login-approved", f"code={code} by={approver[:80]} client={row['client']}")
    return {"approved": code, "client": row["client"]}


def login_poll(con, poll: str, now: float | None = None) -> tuple[str, str | None]:
    """('pending'|'approved'|'gone', session id or None). The approved login is consumed here, exactly once."""
    now = time.time() if now is None else now
    row = con.execute("SELECT code, state, client, created FROM logins WHERE poll_hash=?", (_h(poll or ""),)).fetchone()
    if not row or row["created"] < now - LOGIN_TTL_S:
        return "gone", None
    if row["state"] == "pending":
        return "pending", None
    if row["state"] != "approved":
        return "gone", None
    cur = con.execute("UPDATE logins SET state='used' WHERE code=? AND state='approved'", (row["code"],))
    if cur.rowcount != 1:
        return "gone", None
    sid = secrets.token_urlsafe(32)
    con.execute("INSERT INTO sessions(sid_hash,created,expires,client,code) VALUES(?,?,?,?,?)",
                (_h(sid), now, now + SESSION_TTL_S, row["client"], row["code"]))
    log_event(con, None, "session-created", f"code={row['code']}")
    return "approved", sid


def session_ok(con, sid: str, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    if not sid:
        return False
    return con.execute("SELECT 1 FROM sessions WHERE sid_hash=? AND expires > ?", (_h(sid), now)).fetchone() is not None


def allowed_hosts() -> set[str]:
    """Loopback names plus this machine's own private-network name, read from the network daemon at start.
    Nothing is written to a file. COORD_ALLOWED_HOSTS can add names (comma list)."""
    hosts = {"127.0.0.1", "localhost"}
    hosts |= {h.strip().lower() for h in (os.environ.get("COORD_ALLOWED_HOSTS") or "").split(",") if h.strip()}
    ts = shutil.which("tailscale")
    if ts:
        try:
            out = subprocess.run([ts, "status", "--json", "--peers=false"], capture_output=True, text=True, timeout=10).stdout
            name = (json.loads(out or "{}").get("Self") or {}).get("DNSName") or ""
            if name:
                hosts.add(name.rstrip(".").lower())
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    return hosts


# ---------------------------------------------------------------- intake
def submit(con, kind: str, text: str, ticket: str | None, origin: str, key: str | None,
           needs: str | None = None) -> dict:
    wanted = sorted(set((needs or "answer").replace(" ", "").split(",")))
    if any(w not in CAPS for w in wanted):
        raise ValueError(f"needs must be a comma list of {CAPS}")
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
    con.execute("INSERT INTO tasks(id,key,kind,text,ticket,origin,state,created,updated,needs) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)", (tid, key, kind, text, ticket, origin, "queued", ts, ts, ",".join(wanted)))
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
        needs = set((task.get("needs") or "answer").split(","))
        able = [lane for lane, caps in LANE_CAPS.items() if needs <= caps]
        if not able:
            missing = sorted(needs - set().union(*LANE_CAPS.values()))
            return None, "blocked-unavailable: no lane on this host provides " + ", ".join(missing or sorted(needs))
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
        needs = None
        m = re.search(r"\bneeds:([a-z,-]+)\b", rest)
        if m:
            needs, rest = m.group(1), rest.replace(m.group(0), "").strip()
        # Keyed by the chat task, so a replay of this chat message after a restart queues nothing twice.
        new = submit(con, "agent", rest, ticket, f"chat:{task['id']}", f"chatrun:{task['id']}", needs)
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
    text = (f"coordd (host coordinator) task {task['id']} {str(task.get('state') or ('done' if ok else 'failed')).upper()}\n"
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
        if t and t["state"] in TERMINAL:
            report(con, dict(t), t["state"] == "done", t["result"] or t["error"] or "", root)


# ---------------------------------------------------------------- loop
def recover(con) -> None:
    """A task found running after a restart is requeued only when its lane is replay-safe and it has budget.
    Anything else becomes outcome-unknown: it is never declared failed, and never rerun, without a readback."""
    for row in con.execute("SELECT id, attempts, lane FROM tasks WHERE state='running'").fetchall():
        if row["lane"] in REPLAY_SAFE and row["attempts"] < MAX_ATTEMPTS:
            con.execute("UPDATE tasks SET state='queued', updated=? WHERE id=?", (now_iso(), row["id"]))
            log_event(con, row["id"], "requeued-after-restart", f"attempts={row['attempts']} lane={row['lane']}")
        else:
            why = ("interrupted by a restart; lane is not replay-safe" if row["lane"] not in REPLAY_SAFE
                   else "interrupted by a restart with the attempt budget spent")
            con.execute("UPDATE tasks SET state='outcome-unknown', error=?, updated=? WHERE id=?",
                        (why + "; needs a readback before any rerun", now_iso(), row["id"]))
            log_event(con, row["id"], "outcome-unknown", why)


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
    # blocked (could not be attempted or verified) is kept apart from failed (attempted and went wrong).
    state = "done" if ok else ("blocked" if body.startswith(("blocked-unavailable", "worker reported blocked")) else "failed")
    con.execute("UPDATE tasks SET state=?, result=?, error=?, updated=? WHERE id=?",
                (state, body if ok else None, None if ok else body, now_iso(), task["id"]))
    log_event(con, task["id"], state, body[:300])
    if task["kind"] != "chat":
        mc_drop(task["id"], "finished", f"coordinator task {task['id']} {state.upper()} via {lane}",
                task["ticket"], "info" if ok else "warn")
    task["state"] = state
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
<div id="auth" class="card" role="status"><p id="authmsg">Checking sign-in...</p>
<p id="codebox" hidden>Sign-in code: <strong id="code" style="font-size:22px;letter-spacing:2px"></strong></p>
<p id="authhelp" class="me" hidden>Ask someone already signed in to approve this exact code (on the host: <code>coordd.py approve CODE</code>). Check that the code matches before approving. It expires in 5 minutes and works once, for this browser only.</p>
<button id="again" hidden>Get a new code</button></div>
<div id="log" aria-live="polite"></div>
<form id="cf" hidden><label for="msg" style="position:absolute;left:-9999px">Message</label>
<input id="msg" type="text" maxlength="4000" placeholder="Message the coordinator" required><button>Send</button></form>
<script>
const log=document.getElementById("log");const $=i=>document.getElementById(i);
function add(cls,t){const d=document.createElement("pre");d.className=cls;d.textContent=t;log.appendChild(d);d.scrollIntoView()}
async function api(path,body){const r=await fetch(path,{method:body?"POST":"GET",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:body?JSON.stringify(body):undefined});
 if(!r.ok)throw new Error((await r.json().catch(()=>({}))).error||("HTTP "+r.status));return r.json()}
async function enter(){const s=await api("/api/status");$("auth").hidden=true;$("cf").hidden=false;add("card",s.text);$("msg").focus()}
async function signin(){$("again").hidden=true;
 try{await enter();return}catch(x){}
 let L;try{L=await api("/api/login/start",{})}catch(x){$("authmsg").textContent="Cannot start sign-in: "+x.message;$("again").hidden=false;return}
 $("authmsg").textContent="Not signed in on this browser.";$("code").textContent=L.code;$("codebox").hidden=false;$("authhelp").hidden=false;
 const end=Date.now()+L.expires_in*1000;
 while(Date.now()<end){await new Promise(r=>setTimeout(r,2000));
  let r;try{r=await api("/api/login/poll",{poll:L.poll})}catch(x){continue}
  if(r.state==="approved"){$("codebox").hidden=true;$("authhelp").hidden=true;try{await enter()}catch(x){$("authmsg").textContent="Signed in, but the page could not load: "+x.message}return}
  if(r.state==="gone")break}
 $("authmsg").textContent="That code expired or was already used.";$("codebox").hidden=true;$("authhelp").hidden=true;$("again").hidden=false;$("again").focus()}
$("again").onclick=signin;signin();
document.getElementById("cf").onsubmit=async e=>{e.preventDefault();const m=document.getElementById("msg");const text=m.value.trim();if(!text)return;m.value="";add("me","you: "+text);
 const btn=e.target.querySelector("button");btn.disabled=true;
 try{const t=await api("/api/chat",{text,key:"web-"+crypto.randomUUID()});let cur=t;
  for(let i=0;i<300&&!["done","failed","blocked","outcome-unknown"].includes(cur.state);i++){await new Promise(r=>setTimeout(r,1000));cur=await api("/api/tasks/"+t.id)}
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
        self.send_header("Referrer-Policy", "no-referrer")
        if self.set_cookie:
            self.send_header("Set-Cookie", self.set_cookie)
            self.set_cookie = None
        self.end_headers()
        self.wfile.write(body)

    hosts: set = {"127.0.0.1", "localhost"}
    set_cookie: str | None = None

    def _bearer(self) -> bool:
        got = self.headers.get("Authorization", "")
        return got.startswith("Bearer ") and hmac.compare_digest(got[7:].strip(), self.token)

    def _sid(self) -> str:
        for part in (self.headers.get("Cookie") or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == "coord_sid":
                return value
        return ""

    def _authed(self) -> bool:
        """The host token (CLI) or an approved browser session. A session POST must also come from this page:
        the cookie is SameSite=Strict and the Origin, when sent, must name the host that was asked."""
        if self._bearer():
            return True
        if not session_ok(db(self.root), self._sid()):
            return False
        origin = self.headers.get("Origin")
        if self.command == "POST" and origin is not None:
            if origin.split("://", 1)[-1].rsplit(":", 1)[0].lower() != self._host():
                return False
        return True

    def _host(self) -> str:
        return (self.headers.get("Host") or "").rsplit(":", 1)[0].lower()

    def _host_ok(self) -> bool:
        return self._host() in self.hosts  # DNS-rebinding guard: only names this service is published under

    def _client(self) -> str:
        """Shown to the approver so a code started by someone else can be recognized. Display only, never auth."""
        who = self.headers.get("Tailscale-User-Login") or "unknown user"
        via = self.headers.get("X-Forwarded-For") or self.client_address[0]
        agent = (self.headers.get("User-Agent") or "unknown browser")[:120]
        return f"{who} from {via} using {agent}"

    def do_GET(self):  # noqa: N802
        if not self._host_ok():
            return self._send(403, {"error": "bad host"})
        if self.path == "/healthz":
            return self._send(200, {"ok": True, "service": "coordd", "ts": now_iso()})
        if self.path == "/":
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if not self._authed():
            return self._send(401, {"error": "sign-in required"})
        con = db(self.root)
        if self.path == "/api/logins":
            return self._send(200, {"pending": login_pending(con)}) if self._bearer() else self._send(403, {"error": "host CLI only"})
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
            if self.path == "/api/login/start":  # the only unauthenticated writes: start and poll
                try:
                    return self._send(200, login_start(con, self._client()))
                except PermissionError as exc:
                    return self._send(429, {"error": str(exc)})
            if self.path == "/api/login/poll":
                state, sid = login_poll(con, str(body.get("poll") or ""))
                if sid:
                    secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" or self._host() not in ("127.0.0.1", "localhost") else ""
                    self.set_cookie = f"coord_sid={sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL_S}{secure}"
                return self._send(200, {"state": state})
            if not self._authed():
                return self._send(401, {"error": "sign-in required"})
            if self.path == "/api/login/approve":
                if not self._bearer():  # a browser session cannot mint another session; approval is a host action
                    return self._send(403, {"error": "approve from the host CLI"})
                return self._send(200, login_approve(con, str(body.get("code") or ""), "host-cli"))
            if self.path == "/api/logout-all":
                if not self._bearer():
                    return self._send(403, {"error": "host CLI only"})
                con.execute("DELETE FROM sessions")
                con.execute("DELETE FROM logins")
                return self._send(200, {"ok": True})
            if self.path == "/api/chat":
                task = submit(con, "chat", str(body.get("text") or ""), None, "chat", body.get("key"))
            elif self.path == "/api/tasks":
                task = submit(con, str(body.get("kind") or ""), str(body.get("text") or ""), body.get("ticket"),
                              str(body.get("origin") or "api")[:80], body.get("key"), body.get("needs"))
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
    Handler.hosts = allowed_hosts()
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
        if t["state"] in TERMINAL or time.time() > end:
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
    s.add_argument("--needs", help="comma list of required capabilities, e.g. run-commands")
    s.add_argument("--origin", default="cli")
    s.add_argument("--wait", type=int, default=0)
    c = sub.add_parser("chat")
    c.add_argument("text", nargs="+")
    for name in ("status", "tasks", "logins", "logout-all"):
        sub.add_parser(name)
    apv = sub.add_parser("approve", help="approve a sign-in code shown in a browser; check the client line first")
    apv.add_argument("code")
    sh = sub.add_parser("show")
    sh.add_argument("id")
    args = ap.parse_args(argv)
    if args.cmd == "serve":
        return cmd_serve(args)
    if args.cmd == "logins":
        for r in client(args, "/api/logins")["pending"]:
            print(f"{r['code']}  started {r['age_s']}s ago  by {r['client']}")
        return 0
    if args.cmd == "approve":
        r = client(args, "/api/login/approve", {"code": args.code})
        print(f"approved {r['approved']} for: {r['client']}")
        return 0
    if args.cmd == "logout-all":
        client(args, "/api/logout-all", {"all": True})
        print("all browser sessions and pending sign-ins removed")
        return 0
    if args.cmd == "submit":
        t = client(args, "/api/tasks", {"kind": args.kind, "text": args.text, "ticket": args.ticket,
                                        "key": args.key, "origin": args.origin, "needs": args.needs})
        if args.wait:
            t = wait_task(args, t["id"], args.wait)
        print(json.dumps(t, indent=1))
        return 0 if t["state"] in ("done", "queued", "running") else 1
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
