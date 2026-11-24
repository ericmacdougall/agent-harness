#!/usr/bin/env python3
"""The recorded supervisor and its reviewer-only top-rung grants (GoodQA goodqa#17156, INC 1c of goodqa#16944).

Source: queue:1eaed05e-9884-44ca-a537-09a25d215e7c/2026-11-24T22:35:40.582Z#3862575e22f5 "create another script that
adds reviewer-level grant abilities so citations from supervisor are sufficient", and the "Top rung" bullet of the
supervisor-standing-authority section of ~/.claude/CLAUDE.md: the supervisor may grant Fable or Astra as the reviewer
for a named task and record that grant itself; writer use still needs the user's own words.

What it does
  - `ah supervisor set --session S --source SRC` records ONE supervisor session. SRC must be the user's own words
    (user:, answer: or queue:) in S's own transcript asking S to supervise; a new set replaces the old one.
  - `ah grant-reviewer --task T --reason R --ticket K --wal W` lets the recorded supervisor record, with no new
    sentence from the user, a grant that peer_review honours for the reviewer at a rung that needs user permission
    (R5 and R6 today) for task T, for at most 7 days. It writes a WAL decision row first, then the grant.
  - The grant lives in the task ledger's own `review_grants` field. Every writer path (an Agent spawn, a model launch,
    rescue, a central publish, codex_pool) reads only `permission`, so a grant never authorizes writing.
    `escalation.live_review_grant` is the one reader that decides, and only the reviewer checks call it.
  - "Reviewer" here means a peer_review.py run. An Agent-spawned reviewer sub-agent has write tools, so it stays on
    approve-top (owner decision D1, accepted by main; narrower than the CLAUDE.md wording).

Limits, stated rather than controlled (goodqa#17019, goodqa#17155): the main-agent stamp, the supervisor record, the
ledger and CLAUDE.md are all files this user's processes can write. Today nothing refuses an agent's write to
~/.claude/CLAUDE.md, so the marker check stops careless use (a host where the user never ran the enable script, or
a section he removed), not an agent that appends the block. Self-authored detection is best effort: dispatch records
are evicted and dropped on a reset, so "not detected" never means "not self-authored".
"""
from __future__ import annotations

import ast
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import escalation as esc  # noqa: E402

MARKER_BEGIN = "<!-- supervisor-standing-authority:begin -->"
MARKER_END = "<!-- supervisor-standing-authority:end -->"
CLAUDE_MD_MAX = 1 << 20
RECORD_MAX = 64 << 10
AUDIT_MAX = 4 << 20
SET_STAMP = "supervisor-set"
GRANT_STAMP = "grant-reviewer"
GRANT_HOURS_MAX = 7 * 24
DAILY_CAP = 10
REASON_MIN, REASON_MAX = 20, 400
SESSION_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
TICKET = re.compile(r"^GoodQA [a-z0-9][a-z0-9_-]{0,63}#[1-9][0-9]{0,8}$")
SUPERVISE_TERMS = re.compile(r"\bsupervis(?:e|es|ed|ing|or|ors|ion)\b", re.I)
SUPERVISE_REQUEST = re.compile(r"\b(?:take over|takeover|take charge|become|act as|be the|you are|you're|"
                               r"you will be|from now on)\b", re.I)
ROLE_END = re.compile(r"\b(?:stop|stopp\w*|quit|cease|no longer|not|never|don'?t|do not|step down|stand down|"
                      r"revoke[ds]?|cancel(?:led)?|no)\b|n't\b", re.I)
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class SupervisorError(RuntimeError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def now_ts():
    return datetime.now(timezone.utc).timestamp()


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


# ---------------------------------------------------------------- roots

def state_dir(ledger) -> Path:
    """The supervisor record and the audit log live beside the task ledger they govern, so a test ledger
    (AGENT_HARNESS_ESCALATION_DIR) carries its own and the installed ledger has exactly one."""
    path = Path(ledger.root) / "supervisor"
    if path.is_symlink():
        raise SupervisorError("state_unreadable", "the supervisor state directory cannot be a symlink")
    path.mkdir(mode=0o700, exist_ok=True)
    return path


def claude_home(ledger) -> Path:
    """The installed ~/.claude (from the passwd database) for the installed ledger. Only a non-default test ledger
    honours CLAUDE_CONFIG_DIR, so a main session cannot point the checks at a planted CLAUDE.md or transcript."""
    if ledger._non_default_root():
        configured = os.environ.get("CLAUDE_CONFIG_DIR")
        return Path(configured) if configured else Path.home() / ".claude"
    return esc.installed_home() / ".claude"


def wals_root(ledger) -> Path:
    override = os.environ.get("AGENT_HARNESS_WALS_DIR") if ledger._non_default_root() else None
    return Path(override or esc.installed_home() / ".claude" / "wals").resolve()


def _read_regular(path: Path, limit: int) -> bytes:
    """Bytes of a regular file this user owns (no symlink, no FIFO, at most `limit` bytes), or SupervisorError."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise SupervisorError("missing", "%s does not exist" % path) from None
    except OSError as error:
        raise SupervisorError("unreadable", "%s cannot be read (%s)" % (path, type(error).__name__)) from None
    if stat.S_ISLNK(info.st_mode):
        raise SupervisorError("not_regular", "%s is a symlink" % path)
    if not stat.S_ISREG(info.st_mode):
        raise SupervisorError("not_regular", "%s is not a regular file" % path)
    if info.st_uid != os.getuid():
        raise SupervisorError("foreign_owner", "%s is not owned by this user" % path)
    if info.st_size > limit:
        raise SupervisorError("oversized", "%s is larger than %d bytes" % (path, limit))
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise SupervisorError("not_regular", "%s changed while it was opened" % path)
        return os.read(fd, limit + 1)[:limit]
    finally:
        os.close(fd)


# ---------------------------------------------------------------- the CLAUDE.md marker

def marker_problem(home: Path):
    """None when CLAUDE.md holds the supervisor-standing-authority block with a Top rung bullet naming a reviewer,
    else the reason. The markers must each be a whole line, the end after the begin. See the module doc for what
    this cannot stop."""
    path = Path(home) / "CLAUDE.md"
    try:
        text = _read_regular(path, CLAUDE_MD_MAX).decode("utf-8", "replace")
    except SupervisorError as error:
        return "CLAUDE.md is not usable: " + error.message
    lines = text.splitlines()
    stripped = [line.strip() for line in lines]
    if MARKER_BEGIN not in stripped:
        return "CLAUDE.md has no begin line %s (the user's enable-supervisor-authority.sh writes it)" % MARKER_BEGIN
    begin = stripped.index(MARKER_BEGIN)
    end = next((i for i in range(begin + 1, len(stripped)) if stripped[i] == MARKER_END), None)
    if end is None:
        return "CLAUDE.md has no end line %s after the begin line" % MARKER_END
    block = "\n".join(lines[begin + 1:end])
    bullets = re.split(r"\n(?=\s*[-*] )", block)
    if not any(re.search(r"\bTop rung\b", b, re.I) and re.search(r"\breviewer\b", b, re.I) for b in bullets):
        return "the supervisor-standing-authority block has no Top rung item that names a reviewer"
    return None


# ---------------------------------------------------------------- the supervisor record

def supervise_assent(text):
    """The sentence of the user's words that asks this session to supervise, else None. Like escalation.top_assent:
    the last sentence naming supervision must hold a take-over request, no negation or condition, and no question,
    and no later sentence of the same turn may negate or retract."""
    sentences = [part.strip() for part in esc._SENTENCES.split(text or "") if part.strip()]
    mentions = [index for index, sentence in enumerate(sentences) if SUPERVISE_TERMS.search(sentence)]
    if not mentions:
        return None
    candidate = sentences[mentions[-1]]
    if "?" in candidate or not SUPERVISE_REQUEST.search(candidate) or esc.TOP_NEGATION.search(candidate):
        return None
    for later in sentences[mentions[-1] + 1:]:
        if esc.TOP_NEGATION.search(later) or esc.TOP_RETRACT.search(later):
            return None
    return candidate


def ends_supervision(text):
    """True when a later turn of the user names supervision and ends or refuses it in the same sentence."""
    for sentence in esc._SENTENCES.split(text or ""):
        if SUPERVISE_TERMS.search(sentence) and (ROLE_END.search(sentence) or esc.TOP_RETRACT.search(sentence)):
            return True
    return False


def verify_supervise_source(ledger, session, source, later_texts=()):
    """Re-read the cited turn and prove it is the user's own words, said to `session`, asking it to supervise."""
    import provenance as prov  # noqa: PLC0415
    session = str(session or "").lower()
    if not SESSION_ID.match(session):
        raise SupervisorError("bad_request", "--session must be a Claude session id (a lower-case UUID)")
    fix = " Nothing was recorded. Cite the user's message that asks this session to supervise (ah user-msg --session %s --text-match supervis)." % session
    try:
        parsed = prov.parse_source(source)
    except prov.Problem as error:
        raise SupervisorError("no_assent", "the source does not parse (%s).%s" % (error, fix)) from None
    if parsed.get("kind") != "user" or not esc.user_sourced(source):
        raise SupervisorError("no_assent", "the source must be user:, answer: or queue: (the user's own words)." + fix)
    if str(parsed.get("session") or "").lower() != session:
        raise SupervisorError("no_assent", "the cited words belong to session %s, not %s: only words said to a session "
                                           "can make it the supervisor.%s" % (parsed.get("session"), session, fix))
    try:
        turn = esc._turn_for(parsed, claude_home(ledger))
    except prov.Problem as error:
        raise SupervisorError("no_assent", "the cited turn could not be read (%s).%s" % (error, fix)) from None
    sentence = supervise_assent(turn.get("text") or "")
    if sentence is None:
        raise SupervisorError("no_assent", "the cited turn does not ask this session to supervise in a plain sentence "
                                           "(supervise or supervisor with take over, become or act as, and no negation, "
                                           "condition or question)." + fix)
    if prov.excerpt_in(sentence, parsed.get("excerpt") or ""):
        raise SupervisorError("no_assent", 'the cited excerpt is not part of that sentence; cite "%s".%s' % (sentence[:160], fix))
    for later in later_texts:
        if ends_supervision(later):
            raise SupervisorError("no_assent", "a later message of the user ends or refuses supervision; the latest "
                                               "words decide." + fix)
    return {"sentence": sentence, "timestamp": turn.get("timestamp")}


def current_supervisor(ledger):
    """The recorded supervisor ({session, source, ...}) or None when there is none or the record is unusable."""
    try:
        raw = _read_regular(state_dir(ledger) / "supervisor.json", RECORD_MAX)
        record = json.loads(raw.decode("utf-8"))
    except (SupervisorError, OSError, ValueError, UnicodeError):
        return None
    if not isinstance(record, dict) or not SESSION_ID.match(str(record.get("session") or "")):
        return None
    return record


def _write_record(path: Path, record: dict):
    tmp = path.with_name(".%s.%s.tmp" % (path.name, uuid.uuid4().hex[:8]))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(record, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(str(tmp), str(path))


class _AuditLock:
    """flock on the audit log's lock file: grants and sets are counted and appended under it."""

    def __init__(self, folder: Path):
        self.path = folder / "audit.lock"

    def __enter__(self):
        self.fd = os.open(str(self.path), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        os.close(self.fd)


def audit_rows(ledger):
    try:
        raw = _read_regular(state_dir(ledger) / "audit.jsonl", AUDIT_MAX)
    except SupervisorError:
        return []
    rows = []
    for line in raw.decode("utf-8", "replace").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _audit(folder: Path, row: dict):
    fd = os.open(str(folder / "audit.jsonl"), os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def set_supervisor(ledger, session, source, caller_session, later_texts=(), at=None):
    """Record `session` as the one supervisor (replacing any other), after verify_supervise_source."""
    proof = verify_supervise_source(ledger, session, source, later_texts)
    folder = state_dir(ledger)
    with _AuditLock(folder):
        old = current_supervisor(ledger)
        record = {"id": "sv-" + uuid.uuid4().hex[:12], "session": str(session).lower(), "source": source,
                  "sentence": proof["sentence"][:300], "turn_at": proof["timestamp"], "set_at": at or iso(now_ts()),
                  "set_by": str(caller_session).lower(), "replaced": (old or {}).get("session")}
        _write_record(folder / "supervisor.json", record)
        _audit(folder, {"event": "supervisor-set", **record})
    return record


# ---------------------------------------------------------------- grants

def stamp_parts_grant(task, reason, ticket, wal, self_authored, hours):
    """What a grant-reviewer stamp is bound to: the task, the reason's SHA-256, the ticket, the WAL's real path, the
    self-authored flag and the hours. A stamp for one argument list is never taken for another (NEG-4)."""
    return ["grant", str(task).lower(), hashlib.sha256(str(reason).encode("utf-8")).hexdigest(), str(ticket).lower(),
            os.path.realpath(str(wal)), "1" if self_authored else "0", str(int(hours))]


def stamp_parts_set(session, source):
    return ["set", str(session).lower(), hashlib.sha256(str(source).encode("utf-8")).hexdigest()]


def dispatch_sessions(state, home: Path) -> set:
    """Sessions whose sub-agents the ledger's dispatch records name (best effort; see the module doc)."""
    ids = {d.get("agent_id") for d in (state or {}).get("dispatches") or []
           if isinstance(d, dict) and isinstance(d.get("agent_id"), str) and esc.AGENT_ID.match(d["agent_id"])}
    if not ids:
        return set()
    found = set()
    projects = Path(home) / "projects"
    try:
        project_dirs = [p for p in projects.iterdir() if p.is_dir() and not p.is_symlink()]
    except OSError:
        return found
    for project in project_dirs:
        try:
            sessions = [s for s in project.iterdir() if s.is_dir() and not s.is_symlink()]
        except OSError:
            continue
        for folder in sessions:
            sub = folder / "subagents"
            if any((sub / ("agent-%s.jsonl" % agent)).is_file() for agent in ids):
                found.add(folder.name.lower())
    return found


def _reason_problem(reason):
    if not isinstance(reason, str) or not (REASON_MIN <= len(reason.strip()) <= REASON_MAX):
        return "--reason must be %d to %d characters" % (REASON_MIN, REASON_MAX)
    if CONTROL.search(reason):
        return "--reason holds control characters"
    try:
        import redact  # noqa: PLC0415
        if redact.redact(reason) != reason:
            return "--reason holds credential-like text"
    except ImportError:
        pass
    if re.search(r"\S{40,}", reason):
        return "--reason holds a long opaque token"
    return None


def grant_review(ledger, *, stamp_session, task, reason, ticket, wal, self_authored, hours, write_row, at_ts=None):
    """Record one reviewer-only grant. write_row(note, source) writes the WAL decision row and returns its id.
    Every check runs before anything is written."""
    session = str(stamp_session or "").lower()
    if not SESSION_ID.match(session):
        raise SupervisorError("main_only", "only the main agent grants: its own hook stamps this exact command when the "
                                           "Bash call starts. None was found (a sub-agent, a script, a replay, a "
                                           "background call, or the hook is not installed). Nothing was written")
    problem = marker_problem(claude_home(ledger))
    if problem:
        raise SupervisorError("no_standing_authority", problem + ". Nothing was written")
    record = current_supervisor(ledger)
    if record is None:
        raise SupervisorError("no_supervisor", "no supervisor is recorded; the user's chosen session runs `ah supervisor "
                                               "set --session <id> --source <its user message>` first. Nothing was written")
    if record["session"] != session:
        raise SupervisorError("not_supervisor", "this session (%s) is not the recorded supervisor session (%s). Nothing "
                                                "was written" % (session, record["session"]))
    if not isinstance(task, str) or not esc.SAFE_KEY.fullmatch(task):
        raise SupervisorError("bad_request", "--task must match [A-Za-z0-9][A-Za-z0-9._-]{0,63} (one task per grant)")
    problem = _reason_problem(reason)
    if problem:
        raise SupervisorError("bad_request", problem + ". Nothing was written")
    if not isinstance(ticket, str) or not TICKET.match(ticket):
        raise SupervisorError("bad_request", "--ticket must look like 'GoodQA goodqa#17156'")
    if not isinstance(hours, int) or not 1 <= hours <= GRANT_HOURS_MAX:
        raise SupervisorError("bad_request", "--hours must be 1 to %d (7 days)" % GRANT_HOURS_MAX)
    expected = wals_root(ledger) / session / "main.jsonl"
    try:
        given = Path(wal).expanduser().resolve()
    except (OSError, RuntimeError):
        given = None
    if given != expected or not expected.is_file():
        raise SupervisorError("bad_request", "--wal must be this session's own main WAL (%s)" % expected)
    state = ledger.load(task)
    detected = session in dispatch_sessions(state, claude_home(ledger))
    if detected and not self_authored:
        raise SupervisorError("self_authored", "task %s has dispatches from this session, so it is self-authored: rerun "
                                               "with --self-authored so the WAL row says so. Nothing was written" % task)
    t = now_ts() if at_ts is None else at_ts
    folder = state_dir(ledger)
    with _AuditLock(folder):
        day = iso(t)[:10]
        today = [r for r in audit_rows(ledger) if r.get("event") == "grant" and r.get("by") == session
                 and str(r.get("at", ""))[:10] == day]
        if len(today) >= DAILY_CAP:
            raise SupervisorError("daily_cap", "%d reviewer grants already recorded by this session today (UTC %s); the "
                                               "cap is %d. Nothing was written" % (len(today), day, DAILY_CAP))
        rungs = permission_rungs(ledger.policy)
        grant_id = "rg-" + uuid.uuid4().hex[:12]
        expires = iso(t + hours * 3600)
        authored = "self-authored (declared%s)" % (", detected" if detected else "") if self_authored else \
            "self-authored: not detected (best effort)"
        note = ("[task:%s] reviewer-only top-rung grant %s for %s, by the recorded supervisor %s, until %s; %s. "
                "Reviewer runs of peer_review.py only: never a writer, never an Agent-spawned reviewer. Reason: %s"
                % (task, grant_id, "/".join(rungs), session, expires, authored, reason.strip()))
        row = write_row(note, "ticket:" + ticket)
        grant = {"id": grant_id, "task": task, "scope": "review", "rungs": rungs, "by": session, "wal": str(expected),
                 "wal_row": row, "source": "supervisor:%s/%s" % (session, row), "reason": reason.strip(),
                 "ticket": ticket, "self_authored": bool(self_authored), "self_authored_detected": detected,
                 "at": iso(t), "expires_at": expires}
        ledger.add_review_grant(task, grant)
        _audit(folder, {"event": "grant", "id": grant_id, "task": task, "by": session, "at": grant["at"],
                        "expires_at": expires, "wal_row": row, "ticket": ticket})
    return grant


def _ledger_files(ledger):
    try:
        names = sorted(os.listdir(ledger.root))
    except OSError:
        return []
    return [name[:-5] for name in names if name.endswith(".json") and esc.SAFE_KEY.fullmatch(name[:-5])]


def _peek(ledger, task):
    """A read-only look at one ledger file for listing (no lock, no write); None when unusable."""
    try:
        raw = _read_regular(Path(ledger.root) / (task + ".json"), esc.MAX_STATE)
        state = json.loads(raw.decode("utf-8"))
    except (SupervisorError, OSError, ValueError, UnicodeError):
        return None
    return state if isinstance(state, dict) and state.get("task") == task else None


def grant_state(grant, t):
    if grant.get("revoked_at"):
        return "revoked"
    end = esc._grant_time(grant.get("expires_at"))
    return "live" if end is not None and t < end else "expired"


def list_grants(ledger, at_ts=None):
    t = now_ts() if at_ts is None else at_ts
    out = []
    for task in _ledger_files(ledger):
        state = _peek(ledger, task)
        for grant in (state or {}).get("review_grants") or []:
            if isinstance(grant, dict):
                out.append({"state": grant_state(grant, t), **{k: grant.get(k) for k in (
                    "id", "task", "by", "reason", "ticket", "at", "expires_at", "revoked_at", "revoked_by", "wal_row",
                    "self_authored", "self_authored_detected", "rungs")}})
    return sorted(out, key=lambda g: str(g.get("at")))


def revoke(ledger, grant_id, actor, at_ts=None):
    if not isinstance(grant_id, str) or not re.fullmatch(r"rg-[0-9a-f]{12}", grant_id):
        raise SupervisorError("bad_request", "--revoke takes a grant id (rg- and 12 hex digits) from --list")
    for task in _ledger_files(ledger):
        state = _peek(ledger, task)
        if any(isinstance(g, dict) and g.get("id") == grant_id for g in (state or {}).get("review_grants") or []):
            at = iso(now_ts() if at_ts is None else at_ts)
            grant = ledger.revoke_review_grant(task, grant_id, actor, at=at)
            folder = state_dir(ledger)
            with _AuditLock(folder):
                _audit(folder, {"event": "revoke", "id": grant_id, "task": task, "by": str(actor)[:80], "at": at})
            return grant
    raise SupervisorError("not_found", "no reviewer grant %s in the ledger" % grant_id)


def summary(ledger, at_ts=None):
    """For ah status: the recorded supervisor and every grant, with the D1 narrowing stated."""
    record = current_supervisor(ledger)
    rows = audit_rows(ledger)
    return {"supervisor": ({k: record.get(k) for k in ("session", "set_at", "set_by", "replaced", "source")}
                           if record else None),
            "supervisor_sets_audited": sum(1 for r in rows if r.get("event") == "supervisor-set"),
            "grants": list_grants(ledger, at_ts),
            "scope": "reviewer runs of peer_review.py only (%s); never a writer and never an Agent-spawned reviewer"
                     % "/".join(permission_rungs(ledger.policy))}


def permission_rungs(policy):
    """Every rung that needs the user's permission (R5 and R6 today), derived from model_tiers.json."""
    return [name for name in esc.tiers.rung_order(policy) if policy["rungs"][name]["needs_user_permission"]]


# ---------------------------------------------------------------- reader classifier (AC-2)

KEYS = ("permission", "review_grants")
GRANT_READER = "live_review_grant"


def readers(source: str, filename: str = "<source>"):
    """Every place a module reads or writes a ledger `permission` or `review_grants` key, or calls
    live_review_grant: [(function qualname, what)] where what is e.g. "get:permission", "load:review_grants",
    "store:permission", "dict:permission" or "call:live_review_grant"."""
    tree = ast.parse(source, filename)
    found = []

    def visit(node, scope):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit(child, scope + [child.name])
                continue
            name = ".".join(scope) or "<module>"
            if isinstance(child, ast.Call):
                func = child.func
                attr = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else None
                if attr in ("get", "pop", "setdefault") and child.args and isinstance(child.args[0], ast.Constant) \
                        and child.args[0].value in KEYS:
                    found.append((name, "get:" + child.args[0].value))
                if attr == GRANT_READER:
                    found.append((name, "call:" + GRANT_READER))
            elif isinstance(child, ast.Subscript):
                key = child.slice.value if isinstance(child.slice, ast.Constant) else None
                if key in KEYS:
                    found.append((name, ("store:" if isinstance(child.ctx, ast.Store) else "load:") + key))
            elif isinstance(child, ast.Dict):
                for key in child.keys:
                    if isinstance(key, ast.Constant) and key.value in KEYS:
                        found.append((name, "dict:" + key.value))
            visit(child, scope)

    visit(tree, [])
    return found


# file -> {(qualname, what): why}. A reader not listed here fails tests/test_grant_reviewer.py, and so does a listed
# one that is gone. Only the two reviewer checks may call live_review_grant.
CLASSIFIED = {
    "escalation.py": {
        ("Ledger.fresh", "dict:permission"): "a new state has no user permission",
        ("ladder_status", "get:permission"): "copies the user permission into status; never a review grant",
        ("ladder_status", "dict:permission"): "the status key that every writer path reads",
        ("Ledger.reset", "store:permission"): "carries the user permission over a reset",
        ("Ledger.reset", "get:permission"): "carries the user permission over a reset",
        ("Ledger.reset", "get:review_grants"): "carries the review grants over a reset",
        ("Ledger.reset", "load:review_grants"): "carries the review grants over a reset",
        ("Ledger.reset", "store:review_grants"): "carries the review grants over a reset",
        ("Ledger.approve_top", "store:permission"): "writes the user permission (approve-top)",
        ("Ledger.add_review_grant", "get:review_grants"): "appends a review grant",
        ("Ledger.add_review_grant", "store:review_grants"): "appends a review grant",
        ("Ledger.revoke_review_grant", "get:review_grants"): "marks one review grant revoked",
        ("live_review_grant", "get:review_grants"): "the one reader of review grants that decides",
    },
    "tier_gate.py": {
        ("decide_spawn.permitted", "get:permission"): "writer: an Agent spawn at a permission rung (user permission only)",
        ("_decide_launch", "get:permission"): "the peer_review launch branch and the model-launch branch (user permission)",
        ("_decide_launch", "call:live_review_grant"): "reviewer: the peer_review launch branch only",
    },
    "peer_review.py": {
        ("main", "get:permission"): "the reviewer rung check: the user permission",
        ("main", "call:live_review_grant"): "the reviewer rung check: a live review grant",
        ("main", "dict:permission"): "options: the user permission for the report header",
    },
    "rescue.py": {
        ("rescue_rung", "get:permission"): "writer: a rescue at a permission rung (user permission only)",
    },
    "central_decisions.py": {
        ("publish", "get:permission"): "publishes the user permission only; a review grant is never published",
    },
    "supervisor.py": {
        ("list_grants", "get:review_grants"): "listing only",
        ("revoke", "get:review_grants"): "finds the grant to revoke",
    },
}
GRANT_CALLERS = {("tier_gate.py", "_decide_launch"), ("peer_review.py", "main")}
# Installed-only modules (not in this repository) known to read `permission`: classified, never changed here.
INSTALLED_ONLY = {
    "codex_pool.py": {("astra_approved", "get:permission"): "writer: codex_pool run of an Astra model (user permission only)"},
}


def scan(folder: Path, classified=None):
    """[(file, qualname, what, why or None)] for every reader in the .py files of `folder`; why is None when the
    reader is not classified (CLASSIFIED and INSTALLED_ONLY)."""
    table = dict(CLASSIFIED if classified is None else classified)
    for name, entries in INSTALLED_ONLY.items():
        table.setdefault(name, {}).update(entries)
    out = []
    for path in sorted(Path(folder).glob("*.py")):
        try:
            source = path.read_text(encoding="utf-8")  # input-ok: hook sources, bounded by the repo
            found = readers(source, str(path))
        except (OSError, SyntaxError, UnicodeError, ValueError):
            out.append((path.name, "<unparsed>", "unreadable", None))
            continue
        for qualname, what in found:
            why = table.get(path.name, {}).get((qualname, what))
            if what == "call:" + GRANT_READER and (path.name, qualname) not in GRANT_CALLERS and path.name != "escalation.py":
                why = None
            out.append((path.name, qualname, what, why))
    return out


def main(argv=None):
    import argparse  # noqa: PLC0415
    parser = argparse.ArgumentParser(description="Reader classifier for the ledger permission and review grants")
    sub = parser.add_subparsers(dest="action", required=True)
    rd = sub.add_parser("readers", help="list every reader of permission and review_grants in DIR; exit 1 on an "
                                        "unclassified one")
    rd.add_argument("dir", type=Path)
    args = parser.parse_args(argv)
    rows = scan(args.dir)
    unknown = [r for r in rows if r[3] is None]
    for name, qualname, what, why in rows:
        print("%-22s %-34s %-26s %s" % (name, qualname, what, why or "UNCLASSIFIED"))
    print("readers %d, unclassified %d" % (len(rows), len(unknown)))
    return 1 if unknown else 0


if __name__ == "__main__":
    raise SystemExit(main())
