"""Demo mode for Mission Control: fixture data only, for click-tests and screenshots (GoodQA #15585).

`server.py serve --demo` builds the App with:
- a DemoRunner (canned output, no subprocess), so `ah`, `gh`, ssh and `codex` are never run;
- fixture WALs and initiatives under MC_HOME/demo;
- no remote probe and no Codex.

A demo thread keeps the page alive:
- pulses through a drop source;
- new WAL lines;
- target heartbeats;
- a canned echo reply to each Claude chat message.

Chat lands only in the disposable MC_HOME; nothing ever reaches an agent.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path

import mc_chat  # noqa: F401  (importable through server.py's hook-path setup)

DEMO_SESSION = "demo-main-0000-4000-8000-000000000000"
DESKTOP_SESSION = "claude-desktop"
DEMO_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+ts\.net$")
ECHO_AFTER_S = 4.0
BURST_EVERY = 20  # pulses (about one minute)
BURST_SIZE = 30
ECHO_TEXT = ("Demo instance: your message was received and stored in a disposable inbox. "
             "Nothing was sent to any agent.")


class DemoError(ValueError):
    pass


def check_demo_host(host: str | None, demo: bool) -> str | None:
    """--demo-host is accepted only with --demo, and only for a *.ts.net name (a Tailscale Funnel host)."""
    if host is None:
        return None
    if not demo:
        raise DemoError("--demo-host needs --demo")
    host = host.strip().lower()
    if not DEMO_HOST_RE.match(host):
        raise DemoError("--demo-host must be a *.ts.net host name, with no scheme, port or path")
    return host


def check_demo_home(env_home: str | None) -> Path:
    """Demo data must live in a disposable MC_HOME: never the real ~/.agent-harness/mission-control (or anything
    containing it), and never ~/.agent-harness itself."""
    if not env_home:
        raise DemoError("--demo needs MC_HOME set to a disposable directory")
    real_root = (Path.home() / ".agent-harness").resolve()
    real_home = (real_root / "mission-control").resolve()
    home = Path(env_home).expanduser().resolve()
    if home == real_root or home == real_home or real_home in home.parents or home in real_home.parents:
        raise DemoError(f"refusing --demo with the real Mission Control home ({home})")
    return home


MARKER = ".mc-demo-home"


def prepare_home(root: Path) -> Path:
    """Claim root as a demo home before anything is written to it.

    It is refused when it is non-empty without our marker (an unrelated directory) or when a working subdirectory is
    a symlink or resolves outside it, so fixture writes cannot land in the real Mission Control home."""
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    marker = root / MARKER
    if marker.is_symlink() or not marker.is_file():
        if marker.is_symlink() or any(root.iterdir()):
            raise DemoError(f"refusing --demo: {root} is not empty and is not a demo home")
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
    # No symlink anywhere under the home: a nested link (demo/wals, a session folder, log/server.log) would let fixture
    # or log writes land outside it. os.walk does not follow directory links, so each link is seen once, as an entry.
    # A hard-linked file (st_nlink > 1) is refused too: O_NOFOLLOW does not stop writes through a hard link.
    for top, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = os.path.join(top, name)
            if os.path.islink(path):
                raise DemoError(f"refusing --demo: {path} is a symlink inside the demo home")
            if name in files and os.lstat(path).st_nlink > 1:
                raise DemoError(f"refusing --demo: {path} is hard-linked to a file elsewhere")
    return root


def is_demo_home(root: Path) -> bool:
    marker = root / MARKER
    return marker.is_file() and not marker.is_symlink()


def _write(path: Path, text: str, append: bool = False) -> None:
    """Write without following a symlink at the final component (fixture files only)."""
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "a" if append else "w") as handle:
        handle.write(text)


def _checkout_commit(start: Path) -> str | None:
    """HEAD of the checkout holding start, read from the repository files (demo mode starts no processes)."""
    sha = re.compile(r"[0-9a-f]{40}")
    for top in (start, *start.parents):
        dot = top / ".git"
        if not dot.exists():
            continue
        try:
            gitdir = dot
            if dot.is_file():
                pointer = dot.read_text().strip()
                if not pointer.startswith("gitdir: "):
                    return None
                gitdir = (top / pointer[len("gitdir: "):]).resolve()
            common = gitdir
            if (gitdir / "commondir").is_file():
                common = (gitdir / (gitdir / "commondir").read_text().strip()).resolve()
            head = (gitdir / "HEAD").read_text().strip()
            if sha.fullmatch(head):
                return head
            ref = head[5:] if head.startswith("ref: ") else ""
            for base in (gitdir, common):
                if ref and (base / ref).is_file():
                    value = (base / ref).read_text().strip()
                    return value if sha.fullmatch(value) else None
            packed = common / "packed-refs"
            if ref and packed.is_file():
                for line in packed.read_text().splitlines():
                    value, _, name = line.partition(" ")
                    if name == ref and sha.fullmatch(value):
                        return value
        except (OSError, ValueError):
            return None
        return None
    return None


def build_identity(app_dir: Path, hooks_dir: Path) -> dict:
    """What code this demo instance serves: the commit (when run from a checkout) and a digest of the files.

    No paths: /healthz is reachable without a session behind a Funnel, and paths carry the user name."""
    digest = hashlib.sha256()
    files = sorted(p for p in app_dir.rglob("*") if p.is_file() and p.suffix in (".py", ".js", ".css", ".html")
                   and "__pycache__" not in p.parts and "vendor" not in p.parts)
    files += [hooks_dir / "mc_chat.py", hooks_dir / "redact.py"]
    for path in files:
        try:
            digest.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
        except OSError:
            digest.update(path.name.encode() + b"\0missing\0")
    commit = _checkout_commit(app_dir)
    hooks_from = "checkout" if hooks_dir.resolve() == (app_dir.parent / "hooks").resolve() else "installed"
    return {"commit": commit, "digest": digest.hexdigest()[:16], "hooks": hooks_from}


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


OWNERS = [
    # agent, state, task, ticket, idle seconds, disposition, last WAL note
    ("a1live0demo", "live", "Build the checkout page", "demo#101", 20, None, "intent: wiring the payment form"),
    ("a2work0demo", "working", "Fix the flaky login test", "demo#102", 90, None, "check: 41 of 42 tests pass"),
    ("a3fini0demo", "finishing", "Release notes for 0.4", "demo#103", 300, None, "result: draft ready for review"),
    ("a4held0demo", "DROPPED", "Migrate the reports table", "demo#104", 2400,
     {"kind": "waiting", "ref": "demo#104", "reason": "waiting on the nightly backup before migrating",
      "until": None, "live": True}, "decision: hold until the backup lands"),
    ("a5drop0demo", "DROPPED", "Retry the search index", "demo#105", 5400, None, "blocker: index build failed twice"),
    ("a6sile0demo", "SILENT", "Watch the canary", "demo#106", 1900, None,
     "status: waiting on own background work (canary soak, 30 min)"),
    ("a7retd0demo", "returned", "Spec review for demo#107", "demo#107", 3600, None, "handoff: review posted"),
    ("a8done0demo", "done", "Docs typo sweep", "demo#108", 4000, None, "result: merged"),
]

INITIATIVES = [
    {"id": "demo#101", "initiative": "Checkout redesign", "state": "In progress", "milestones_done": 5,
     "milestones_total": 8, "milestones": "Done: Spec · Done: Design · Done: API · Done: Form · Done: Payments · "
                                          "Not yet: Review · Not yet: Click-test · Not yet: Live",
     "owner": "a1live0demo", "ticket": "demo#101", "next_step": "Finish the payment form and its error states",
     "next_eta": "~2 h", "full_eta": "~1 day", "estimate_by": "main", "note": "Demo data"},
    {"id": "demo#104", "initiative": "Reports table migration", "state": "At risk",
     "milestones_done": 1, "milestones_total": 4,
     "milestones": "Done: Spec · Not yet: Backup · Not yet: Canary · Not yet: Live", "owner": "a4held0demo", "ticket": "demo#104",
     "next_step": "Wait for the nightly backup, then migrate in a canary", "next_eta": "~8 h",
     "full_eta": "~2 days", "estimate_by": "owner"},
    {"id": "demo#103", "initiative": "Release 0.4", "state": "Merged, not live", "milestones_done": 6,
     "milestones_total": 7, "owner": "a3fini0demo", "ticket": "demo#103", "next_step": "Deploy and test live",
     "next_eta": "~1 h", "full_eta": "~1 h"},
    {"id": "demo#109", "initiative": "Onboarding emails", "state": "Not started", "ticket": "demo#109",
     "next_step": "Write the spec", "note": "No owner yet"},
    {"id": "demo#108", "initiative": "Docs refresh", "state": "Done", "milestones_done": 3,
     "milestones_total": 3, "ticket": "demo#108"},
]

PULSES = [
    ("push", "pushed 2 commits to feat/checkout-form", {"repo": "demo/shop", "branch": "feat/checkout-form"}),
    ("wal", "check: payment form unit tests pass", {"ticket": "demo#101"}),
    ("release", "released demo/shop v0.4.0-rc.1", {"repo": "demo/shop"}),
    ("deploy", "demo/shop 0.4.0-rc.1 deployed to staging", {"repo": "demo/shop"}),
    ("ticket", "demo#102: new comment from the reviewer", {"ticket": "demo#102"}),
    ("push", "pushed 1 commit to main", {"repo": "demo/docs", "branch": "main"}),
]


class DemoRunner:
    """Canned answers for the collectors' allowlisted command shapes. It never starts a process; any other shape
    raises, exactly like the real Runner refusing an unknown command."""

    def __init__(self, started: float | None = None):
        self.started = time.time() if started is None else started
        self.calls: list[tuple] = []

    def run(self, kind, *args, timeout=20.0, limit=0):
        self.calls.append((kind, args))
        if kind == "ah-owners" and not args:
            return 0, json.dumps(owners_payload(time.time()))
        if kind == "ah-ticket-comments" and len(args) == 1:
            return 0, json.dumps({"comments": [
                {"id": f"{args[0]}-c1", "body": "Demo comment: looks good, one nit on naming.",
                 "createdAt": _iso(self.started - 3600)}]})
        if kind == "gh-user" and not args:
            return 1, ""  # the GitHub source shows as failing, so the page's error notice can be checked
        raise PermissionError(f"demo mode runs no commands ({kind})")


def owners_payload(now: float) -> dict:
    rows = []
    for agent, state, task, ticket, idle, disposition, _note in OWNERS:
        row = {"agent_id": agent, "state": state, "task": task, "ticket": ticket, "idle_s": idle,
               "type": "task-owner", "last_activity": _iso(now - idle)}
        if disposition:
            row["disposition"] = {**disposition, "until": now + 6 * 3600}
        rows.append(row)
    return {"session": DEMO_SESSION, "owners": rows}


def seed(root: Path) -> dict:
    """Write the fixture WALs and initiatives under root/demo and return the App arguments that use them."""
    base = root / "demo"
    wals = base / "wals" / DEMO_SESSION
    wals.mkdir(mode=0o700, parents=True, exist_ok=True)
    now = time.time()
    for agent, _state, _task, ticket, idle, _disposition, note in OWNERS:
        event, _, text = note.partition(": ")
        line = {"at": _iso(now - idle), "event": event, "note": text, "ticket": ticket}
        _write(wals / f"agent-{agent}.jsonl", json.dumps(line) + "\n")
    _write(wals / "main.jsonl", json.dumps({"at": _iso(now - 60), "event": "status",
                                            "note": "demo main: 3 owners live"}) + "\n")
    _write(base / "initiatives.json", json.dumps({"initiatives": INITIATIVES}, indent=1))
    return {"wal_roots": [(base / "wals", "claude")], "initiatives": str(base / "initiatives.json")}


class DemoLoop:
    """Live activity for the demo page, and the chat echo. Runs only in demo mode, only inside MC_HOME."""

    def __init__(self, root: Path, stop: threading.Event):
        self.root, self.stop = root, stop
        self.n = 0
        self.seen: dict[str, float] = {}

    def heartbeat(self) -> None:
        mc_chat.register_target(DEMO_SESSION, os.getpid(), root=self.root, waiting=True)
        mc_chat.register_target(DESKTOP_SESSION, os.getpid(), root=self.root, waiting=False)

    def pulse(self, now: float) -> None:
        kind, summary, subject = PULSES[self.n % len(PULSES)]
        self.n += 1
        line = {"schema": "mc.event/1", "id": f"demo:{int(now)}:{self.n}", "ts": _iso(now), "kind": kind,
                "summary": summary, "subject": subject}
        _write(self.root / "sources" / "demo.jsonl", json.dumps(line) + "\n", append=True)
        # Tool activity: two tool-call records for a2 each pulse, shown only with 'Show tool activity'.
        tools = self.root / "demo" / "wals" / DEMO_SESSION / f"agent-{OWNERS[1][0]}.jsonl"
        _write(tools, "".join(json.dumps({"at": _iso(now), "event": "pretool", "tool": name}) + "\n"
                              for name in ("Read", "Bash")), append=True)
        if self.n % BURST_EVERY == 0:
            # A burst: more lines at once than the hub's 20-per-second budget, so a burst summary row appears.
            burst = "".join(json.dumps({"schema": "mc.event/1", "id": f"demo:{int(now)}:{self.n}:b{i}", "ts": _iso(now),
                                        "kind": "wal", "summary": f"check: burst line {i + 1} of {BURST_SIZE}",
                                        "subject": {"ticket": "demo#101"}}) + "\n" for i in range(BURST_SIZE))
            _write(self.root / "sources" / "demo.jsonl", burst, append=True)
        if self.n % 3 == 0:
            agent = OWNERS[self.n % 3][0]
            wal = self.root / "demo" / "wals" / DEMO_SESSION / f"agent-{agent}.jsonl"
            _write(wal, json.dumps({"at": _iso(now), "event": "check", "note": summary}) + "\n", append=True)

    def echo(self, now: float) -> None:
        for session in (DEMO_SESSION, DESKTOP_SESSION):
            for record in mc_chat.pending("claude", session, root=self.root):
                first = self.seen.setdefault(record["id"], now)
                if now - first >= ECHO_AFTER_S and mc_chat.claim(record["id"], root=self.root):
                    mc_chat.write_reply(record["id"], "claude", ECHO_TEXT, root=self.root)
                    self.seen.pop(record["id"], None)

    def run(self) -> None:
        last_beat = 0.0
        while not self.stop.wait(1.0):
            now = time.time()
            try:
                if now - last_beat > 20:  # inside WAITER_FRESH_S, so demo-main reads as ready, not busy
                    self.heartbeat()
                    last_beat = now
                if int(now) % 3 == 0:
                    self.pulse(now)
                self.echo(now)
            except Exception:  # noqa: BLE001 - demo activity must never take the server down
                continue
