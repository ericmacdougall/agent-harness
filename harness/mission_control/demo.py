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

# Sub-agents and reviewers for the org graph: agent, type, parent, state, task, ticket, idle s, model, effort.
# a9cycl0demo exists only in odd minutes, so the page shows a spawn and a finish without any real agent.
SUBAGENTS = [
    ("b1sub00demo", "general-purpose", "a1live0demo", "live", "Payment form error states", "demo#110", 15,
     "claude-sonnet-5", "medium"),
    ("b2rev00demo", "red-team", "a1live0demo", "live", "Adversarial review of the payment form", "demo#110", 40,
     "claude-opus-5-5", "high"),
    ("b3sub00demo", "fixer", "a2work0demo", "working", "Stabilise the login test fixture", "demo#102", 60,
     "claude-sonnet-5", "low"),
    ("b4rev00demo", "click-tester", "a2work0demo", "returned", "Click-test login on staging", "demo#102", 700,
     "claude-sonnet-5", "medium"),
    ("b5orph0demo", "red-team", None, "live", "Spec review with no matching sub-agent", "demo#199", 30,
     "claude-opus-5-5", "medium"),
]
CYCLING = ("a9cycl0demo", "general-purpose", "a1live0demo", "live", "Wire the receipt email", "demo#111", 5,
           "claude-sonnet-5", "medium")
OWNER_MODELS = {"a1live0demo": ("claude-opus-5-5", "high"), "a2work0demo": ("claude-opus-5-5", "medium")}
# a3fini0demo has no model or effort in its transcript on purpose: the page must say "unknown".
DEMO_TICKETS = {
    "demo#101": {"title": "Checkout redesign", "status": "in_progress", "links": {"blocks": [109], "blockedBy": []}},
    "demo#110": {"title": "Payment form error states", "status": "in_progress", "parent": 101,
                 "links": {"blocks": [112], "blockedBy": []}},
    "demo#112": {"title": "Checkout click-test on staging", "status": "todo", "links": {"blocks": [113], "blockedBy": [110]}},
    "demo#113": {"title": "Checkout live for everyone", "status": "todo", "links": {"blocks": [], "blockedBy": [112]}},
    "demo#111": {"title": "Receipt email", "status": "in_progress", "links": {"blocks": [112], "blockedBy": []}},
    "demo#102": {"title": "Fix the flaky login test", "status": "in_review", "links": {"blocks": [], "blockedBy": []}},
    "demo#109": {"title": "Onboarding emails", "status": "todo", "links": {"blocks": [], "blockedBy": [101]}},
}


def cycling_live(now: float) -> bool:
    return int(now // 60) % 2 == 1


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

# Open asks for the "Needs you" list. The third is hostile on purpose: ask text is agent-written and must render as
# text, never as markup.
ASKS = [
    ({"id": "wdemoask0001", "kind": "traced", "note": "Ship the checkout redesign behind a flag first, or straight to "
      "everyone? (demo#101)", "reason": "Recommended: flag first, 10% for a day"}, 1500),
    ({"id": "wdemoask0002", "kind": "assumption", "note": "Keep the nightly backup window at 02:00, or move it to "
      "04:00 for the migration? (demo#104)", "reason": "Blocks the reports migration"}, 7200),
    ({"id": "wdemoask0003", "kind": "traced", "note": "<img src=x onerror=alert(1)> Approve the docs copy? (demo#108)",
      "reason": "<script>alert(2)</script>"}, 300),
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
        if kind == "provenance-asks" and len(args) == 1:
            return 0, json.dumps({"counts": {"traced": len(ASKS), "blocked": 1}, "items": [
                {**ask, "at": _iso(time.time() - age), "owner": "main"} for ask, age in ASKS] + [
                # four days old with no answer: the sweeper moves it to Stale
                {"id": "wdemoask0004", "kind": "traced", "owner": "main", "at": _iso(time.time() - 4 * 86400),
                 "note": "Archive the old onboarding email templates? (demo#109)", "reason": "Nobody has opened them since March"},
                # same words as the first ask: the sweeper clears it as a duplicate
                {"id": "wdemoask0005", "kind": "traced", "owner": "main", "at": _iso(time.time() - 600),
                 "note": ASKS[0][0]["note"], "reason": ASKS[0][0]["reason"]}],
                "blocked": [{"id": "wdemoask0006", "owner": "main", "at": _iso(time.time() - 900),
                             "note": "Rotate the staging API keys now? (demo#105)", "reason": "",
                             "problem": "source rejected (message-not-found): no such user message"}],
                "resolved": [{"id": "wdemoask0900", "at": _iso(time.time() - 90000), "owner": "main",
                              "note": "Use the staging database for the reports rehearsal? (demo#104)",
                              "resolved_at": _iso(time.time() - 86000), "decision": "approved",
                              "resolved_by": "wdemores0900",
                              "resolution": "answered by the user: yes, staging first"}]})
        if kind == "ah-goals" and not args:
            return 0, json.dumps(goals_payload(time.time()))
        if kind == "ah-requirements" and len(args) == 1:
            return 0, json.dumps(requirements_payload(time.time()))
        if kind == "ah-status" and len(args) == 1:
            return 0, json.dumps(status_payload(time.time()))
        if kind == "ah-ticket-get" and len(args) == 1:
            ticket = DEMO_TICKETS.get(str(args[0]).replace("GoodQA ", ""))
            if ticket:
                number = int(str(args[0]).split("#")[1])
                links = {k: [{"number": n, "projectSlug": "demo"} for n in v] for k, v in ticket["links"].items()}
                parent = {"number": ticket["parent"], "projectSlug": "demo"} if ticket.get("parent") else None
                return 0, json.dumps({"issue": {"number": number, "title": ticket["title"], "status": ticket["status"],
                                                "closedAt": None, "archivedAt": None, "links": links, "parent": parent,
                                                "childrenCount": 0}})
            return 0, json.dumps({"issue": {"closedAt": None, "archivedAt": None}})
        if kind == "gh-user" and not args:
            return 1, ""  # the GitHub source shows as failing, so the page's error notice can be checked
        raise PermissionError(f"demo mode runs no commands ({kind})")


def goals_payload(now: float) -> dict:
    """Mission goals for the demo: one live-tested, one in progress, one with a failing test, one hostile title."""
    def proof(ident, kind, verdict, age, check, note):
        return {"id": ident, "kind": kind, "verdict": verdict, "at": _iso(now - age), "check": check, "by": "main", "note": note}
    return {"generated": _iso(now), "session": DEMO_SESSION, "state": "OK", "warnings": [], "goals": [
        {"id": "checkout", "title": "Checkout redesign live for everyone", "ticket": "demo#101", "ledger_status": "active",
         "state": "IN_PROGRESS", "priority": 1, "target": "checkout redesign live and click-tested", "owners": ["a1live0demo"],
         "deferral": None, "missing": [], "tampered": [], "unpinned": [],
         "evidence": [proof("wev0001", "live_test", "PASS", 5400, "checkout-staging", "REALLY_TESTED checkout-staging: PASS on staging")]},
        {"id": "reports", "title": "Reports table migrated without downtime", "ticket": "demo#104", "ledger_status": "active",
         "state": "BLOCKED", "priority": 2, "target": "reports migration live", "owners": ["a4held0demo"], "deferral": None,
         "missing": ["backup"], "tampered": [], "unpinned": [],
         "evidence": [proof("wev0002", "live_test", "FAIL", 7200, "reports-canary", "REALLY_TESTED reports-canary: FAIL, 3 rows differ")]},
        {"id": "release", "title": "Release 0.4 deployed and tested live", "ticket": "demo#103", "ledger_status": "active",
         "state": "LIVE_TESTED", "priority": 2, "target": "0.4 live", "owners": [], "deferral": None, "missing": [],
         "tampered": [], "unpinned": [],
         "evidence": [proof("wev0003", "deploy", "PASS", 9000, "release-0.4", "DEPLOYED demo/shop 0.4.0 to live"),
                      proof("wev0004", "live_test", "PASS", 8400, "release-0.4-live", "REALLY_TESTED release-0.4-live: PASS")]},
        {"id": "xss", "title": "<img src=x onerror=alert(1)> goal title", "ticket": "", "ledger_status": "imported",
         "state": "UNKNOWN", "priority": 3, "target": "<script>alert(2)</script>", "owners": [], "deferral": None,
         "missing": [], "tampered": [], "unpinned": [], "evidence": []}]}


def requirements_payload(now: float) -> dict:
    """Recorded requirements: live ones, a done one, a superseded pair, an old unowned one that has expired."""
    def row(ident, text, age, state="recorded", **extra):
        return {"id": ident, "session": DEMO_SESSION, "text": text, "source": 'user:demo/' + ident + ' "..."',
                "at": _iso(now - age), "state": state, "ticket": None, "owner": None, "evidence": None, **extra}
    return {"generated": _iso(now), "total": 7, "truncated": False, "requirements": [
        row("wdemoreq001", "Checkout must show a clear error state when the payment fails.", 3600, ticket="demo#101"),
        row("wdemoreq002", "Back up all transcripts and keep the status of all work in tickets.", 2 * 86400),
        row("wdemoreq003", "Back up all transcripts and keep  the status of all work in tickets.", 5 * 86400),
        row("wdemoreq004", "Release notes ship with every release.", 6 * 86400, state="done"),
        row("wdemoreq005", "Use the staging database for the reports rehearsal.", 40 * 86400),
        row("wdemoreq006", "<img src=x onerror=alert(1)> must stay text.", 3600),
        row("wdemoreq007", "Release 0.4 is deployed and tested live.", 86400,
            evidence={"id": "wev0004", "kind": "live_test", "verdict": "PASS", "at": _iso(now - 8400)})]}


def status_payload(now: float) -> dict:
    def entry(ident, agent, event, note, age, **extra):
        return {"agent": agent, "at": _iso(now - age), "id": ident, "event": event, "note": note, **extra}
    return {"session": DEMO_SESSION, "since_s": 43200, "generated": _iso(now), "entries": 240, "unread": 0,
            "verified": [entry("wst001", "a3fini0demo", "check", "REALLY_TESTED release-0.4-live: PASS on live", 8400,
                               check="release-0.4-live", verdict="PASS")],
            "live": [entry("wst002", "a3fini0demo", "deploy", "DEPLOYED demo/shop 0.4.0 to live", 9000)],
            "live_legacy": [], "pending": [entry("wst003", "a1live0demo", "check", "PENDING_REAL_TEST checkout-staging: error state shown", 1200,
                                                 check="checkout-staging", verdict="")],
            "failed": [entry("wst004", "a4held0demo", "check", "REALLY_TESTED reports-canary: FAIL, 3 rows differ", 7200,
                             check="reports-canary", verdict="FAIL")],
            "claimed": [entry("wst005", "main", "status", "Merged demo#103; deploy still to do", 3000)],
            "blockers": [entry("wst006", "a5drop0demo", "blocker", "index build failed twice; needs a larger disk", 5400),
                         entry("wst007", "a4held0demo", "blocker", "<script>alert(3)</script> waiting on the nightly backup", 2400)],
            "commits": [entry("wst008", "a1live0demo", "commit", "feat(checkout): payment form errors", 1800)],
            "asks_open": [], "decisions": [entry("wst009", "main", "decision", "Flag first, 10 percent for a day", 4000)],
            "assumptions": [],
            "owners": {"counts": {"live": 1, "working": 1, "DROPPED": 2, "done": 4}, "undisposed": ["a5drop0demo"],
                       "attention": ["a5drop0demo"], "live": ["a1live0demo"]}}


def owners_payload(now: float) -> dict:
    rows = []
    for agent, state, task, ticket, idle, disposition, _note in OWNERS:
        row = {"agent_id": agent, "state": state, "task": task, "ticket": ticket, "idle_s": idle,
               "type": "task-owner", "last_activity": _iso(now - idle)}
        if disposition:
            row["disposition"] = {**disposition, "until": now + 6 * 3600}
        rows.append(row)
    for agent, kind, parent, state, task, ticket, idle, _model, _effort in SUBAGENTS + ([CYCLING] if cycling_live(now) else []):
        rows.append({"agent_id": agent, "state": state, "task": task, "ticket": ticket, "idle_s": idle, "type": kind,
                     "last_activity": _iso(now - idle), "parent": parent})
    return {"session": DEMO_SESSION, "owners": rows}


def _transcript(model: str | None, effort: str | None, at: float, messages=()) -> str:
    """A fixture transcript tail: the fields the org graph reads, and nothing else of interest."""
    lines = [{"type": "user", "timestamp": _iso(at - 30), "message": {"role": "user", "content": "demo task"}}]
    record = {"type": "assistant", "timestamp": _iso(at), "message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": f"toolu_demo_{i}", "name": "SendMessage", "input": {"to": to, "message": "demo"}}
        for i, to in enumerate(messages)]}}
    if model:
        record["message"]["model"] = model
    if effort:
        record["effort"] = effort
        record["advisorModel"] = "claude-fable-5-2"
    lines.append(record)
    return "".join(json.dumps(line) + "\n" for line in lines)


def seed_transcripts(base: Path, now: float) -> Path:
    """Fixture transcripts under MC_HOME/demo/projects only (never ~/.claude)."""
    projects = base / "projects"
    session_dir = projects / "-demo" / DEMO_SESSION
    subagents = session_dir / "subagents"
    subagents.mkdir(mode=0o700, parents=True, exist_ok=True)
    _write(projects / "-demo" / f"{DEMO_SESSION}.jsonl", _transcript("claude-opus-5-5", "medium", now - 20))
    for agent, _state, _task, _ticket, idle, _d, _n in OWNERS:
        model, effort = OWNER_MODELS.get(agent, (None, None))
        _write(subagents / f"agent-{agent}.jsonl", _transcript(model, effort, now - idle))
        _write(subagents / f"agent-{agent}.meta.json", json.dumps({"agentType": "task-owner", "spawnDepth": 1}))
    for agent, kind, parent, _state, _task, _ticket, idle, model, effort in SUBAGENTS + [CYCLING]:
        _write(subagents / f"agent-{agent}.jsonl", _transcript(model, effort, now - idle))
        meta = {"agentType": kind, "spawnDepth": 2 if parent else 1}
        if parent:
            meta["parentAgentId"] = parent
        _write(subagents / f"agent-{agent}.meta.json", json.dumps(meta))
    return projects


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
    projects = seed_transcripts(base, now)
    return {"wal_roots": [(base / "wals", "claude")], "initiatives": str(base / "initiatives.json"),
            "projects_root": projects}


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
        if self.n % 4 == 0:
            # An owner messages its sub-agent or reviewer: a SendMessage record in the fixture transcript only.
            sender, to = (("a1live0demo", "b1sub00demo"), ("a1live0demo", "b2rev00demo"),
                          ("a2work0demo", "b3sub00demo"))[(self.n // 4) % 3]
            transcript = self.root / "demo" / "projects" / "-demo" / DEMO_SESSION / "subagents" / f"agent-{sender}.jsonl"
            model, effort = OWNER_MODELS.get(sender, (None, None))
            _write(transcript, json.dumps({"type": "assistant", "timestamp": _iso(now), "effort": effort,
                                           "message": {"role": "assistant", "model": model, "content": [
                                               {"type": "tool_use", "id": f"toolu_demo_{self.n}", "name": "SendMessage",
                                                "input": {"to": to, "message": "demo"}}]}}) + "\n", append=True)
        if self.n % 3 == 0:
            agent = OWNERS[self.n % 3][0]
            wal = self.root / "demo" / "wals" / DEMO_SESSION / f"agent-{agent}.jsonl"
            _write(wal, json.dumps({"at": _iso(now), "event": "check", "note": summary}) + "\n", append=True)

    def echo(self, now: float) -> None:
        for session in (DEMO_SESSION, DESKTOP_SESSION):
            for record in mc_chat.pending("claude", session, root=self.root, consumer="demo-responder"):
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
