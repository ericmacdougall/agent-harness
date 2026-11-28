#!/usr/bin/env python3
"""The one approvals store: what the owner (or a supervisor session) has already said yes to.

Everyone looks here before asking the owner: `ah approvals` lists the live approvals, `ah approvals check` answers
one question with exit 0 (approved, prints the record) or 1 (not approved). docs/approvals.md has the model.

STABLE API (sibling guards import this through a guarded import; keep these signatures):

    allowed(kind, **facts) -> dict | None
        The newest live approval of `kind` whose scope covers `facts`, else None. Never raises.
        facts (all optional): project (absolute dir or "owner/name"), repo ("owner/name"), pr (int or str),
        path (absolute path), task, pids (iterable of int) or pid, host, head (commit sha), now (epoch seconds).
        A record's empty scope field covers every value of that fact; a set field needs the fact and a match.
        A record with no pr/path/task covers the whole project for that kind. exact_head, when the record has one,
        must equal the `head` fact (prefix of 7+ characters accepted); records have none by default, so a PR approval
        survives later commits.
    command_hint(kind, **facts) -> str
        The exact `ah approve ...` line that would record an approval covering `facts` (the same fact names as
        allowed(); repo becomes --project). Refusal messages quote it. Never raises.
    grant(kind, scope, granted_by, reason, expires=None, exact_head=None, source=None, home=None) -> dict
    revoke(id, by, home=None) -> dict
    list(project=None, kind=None, live=True, home=None) -> [dict]

    Guarded import in a consumer:
        try:
            import ah_approvals
        except Exception:
            ah_approvals = None
        record = ah_approvals.allowed("merge", repo="owner/name", pr=12) if ah_approvals else None

Kinds: merge, delete, kill, top-rung, release, secret, spend, harness, other.
Who grants: the owner, and a supervisor session inside the projects it supervises. Who is calling comes from the
launch (ah_roles.launch_role: AH_ROLE from the session's settings or Codex profile; without it, the owner at a terminal
or a session the owner recorded in roles.json), never from the model. The projects are the supervisor's own roles.json
entry, else the role default entry (`ah supervisor set --role-default --project DIR`). `secret`, `spend` and `harness`
stay with the owner. A `harness` approval lets a harness-maintaining supervisor change (or weaken) the rule named in
`what`; without `what` it is standing for every harness change. For `harness` the `what` fact is matched
(case-insensitive, globs allowed); for other kinds `what` is description. The CLI decides who is calling (caller());
grant() checks that a supervisor's scope sits inside its projects.

The operating system backs the roles: a worker's sandbox keeps this store and roles.json read-only, so a worker that
claims a role it was not launched with still cannot write here. The CLI turns that OSError into a refusal (exit 3)
that names the path and the one command the owner or a supervisor session runs.

Store: ~/.agent-harness/approvals.jsonl, mode 0600, append-only (a revoke is a new line), written under an flock.
The reader skips lines it cannot parse. Threat model as everywhere: careless or misled agents, not one that edits this
file. Standard library only.
"""
from __future__ import annotations

import builtins
import fnmatch
import json
import os
import re
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

KINDS = ("merge", "delete", "kill", "top-rung", "release", "secret", "spend", "harness", "other")
OWNER_ONLY_KINDS = ("secret", "spend", "harness")
SCOPE_KEYS = ("project", "pr", "path", "task", "pids", "host", "what")
STORE_NAME = "approvals.jsonl"
MAX_STORE_BYTES = 8 << 20
SLUG = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
TASK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SHA = re.compile(r"^[0-9a-fA-F]{7,40}$")
DURATION = re.compile(r"^(\d{1,5})([mhdw])$")
REMOTE = re.compile(r"github\.com[:/]+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?\s*$", re.M)
# Environment markers of a command run inside an agent's tool call (ah_roles.AGENT_MARKERS is the same list).
# CODEX_HOME is not one: people export it in their shell profile. AH_ROLE also marks an agent (in_agent): only a
# launch sets it.
AGENT_MARKERS = ("CLAUDECODE", "CODEX_THREAD_ID", "CODEX_TOOL_CALL_ID", "CODEX_SANDBOX", "AI_AGENT")
ROLE_DEFAULT_KEY = "(role default)"  # `ah supervisor list`: the entry a launched supervisor uses without its own


class Refused(Exception):
    """A grant or revoke that is not allowed; the message names the one command that proceeds."""


# ---- store ------------------------------------------------------------------------------------------------------

def store_path(home=None) -> Path:
    return Path(home or os.environ.get("AH_HOME") or Path.home()) / ".agent-harness" / STORE_NAME


def _iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _epoch(text) -> float | None:
    if not isinstance(text, str) or not text:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            import calendar
            return float(calendar.timegm(time.strptime(text, fmt)))
        except ValueError:
            continue
    return None


def _append(row: dict, home=None) -> None:
    import fcntl
    path = store_path(home)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, (json.dumps(row, sort_keys=True) + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)  # closing releases the lock
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _rows(home=None):
    """Every parseable row; a corrupt or foreign line is skipped, never fatal."""
    path = store_path(home)
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_STORE_BYTES)
    except OSError:
        return []
    out = []
    for raw in data.splitlines():
        try:
            row = json.loads(raw)
        except ValueError:
            continue
        if isinstance(row, dict) and row.get("op") in ("grant", "revoke") and isinstance(row.get("id"), str):
            out.append(row)
    return out


def records(home=None) -> list:
    """Grants with their revocation folded in, oldest first."""
    grants, revoked = {}, {}
    for row in _rows(home):
        if row["op"] == "grant" and row.get("kind") in KINDS and isinstance(row.get("scope"), dict):
            grants.setdefault(row["id"], {k: v for k, v in row.items() if k != "op"})
        elif row["op"] == "revoke":
            revoked.setdefault(row["id"], {"by": row.get("by"), "at": row.get("at")})
    out = []
    for rid, record in grants.items():
        record = dict(record, revoked=revoked.get(rid))
        out.append(record)
    return out


def is_live(record: dict, now: float | None = None) -> bool:
    if record.get("revoked"):
        return False
    expires = _epoch(record.get("expires"))
    return expires is None or (time.time() if now is None else now) < expires


# ---- scope matching ---------------------------------------------------------------------------------------------

def _real(path) -> str:
    return os.path.realpath(os.path.expanduser(str(path)))


def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def repo_slugs(directory) -> set:
    """owner/name of the GitHub remotes in a checkout's .git/config (lower case); empty when unreadable."""
    try:
        import safe_input  # noqa: PLC0415 - bounded reads: this runs inside guards
        git = Path(_real(directory)) / ".git"
        if git.is_file():  # a linked worktree: "gitdir: <main>/.git/worktrees/<name>"
            pointer = safe_input.read_bounded(git, 4096).decode("utf-8", "replace").strip()
            if pointer.startswith("gitdir:"):
                git = Path(pointer.split(":", 1)[1].strip()).parent.parent
        text = safe_input.read_bounded(git / "config", 1 << 20).decode("utf-8", "replace")
    except (OSError, ValueError):
        return set()
    except Exception:  # noqa: BLE001 - safe_input.InputRejected (oversized or not a regular file): no slugs
        return set()
    return {m.lower() for m in REMOTE.findall(text)}


def _project_covers(project: str, facts: dict) -> bool:
    fact_project, fact_repo, fact_path = facts.get("project"), facts.get("repo"), facts.get("path")
    if SLUG.match(project):
        wanted = project.lower()
        for value in (fact_repo, fact_project):
            if isinstance(value, str) and SLUG.match(value) and value.lower() == wanted:
                return True
        for value in (fact_project, fact_path):
            if isinstance(value, str) and value.startswith(("/", "~")) and wanted in repo_slugs(
                    value if os.path.isdir(_real(value)) else os.path.dirname(_real(value))):
                return True
        return False
    root = _real(project)
    for value in (fact_project, fact_path):
        if isinstance(value, str) and value.startswith(("/", "~")) and _inside(_real(value), root):
            return True
    return isinstance(fact_repo, str) and fact_repo.lower() in repo_slugs(root)


def _path_covers(pattern: str, project, path) -> bool:
    if not isinstance(path, str) or not path:
        return False
    target = _real(path)
    candidates = [target]
    if isinstance(project, str) and project.startswith(("/", "~")) and not pattern.startswith(("/", "~")):
        root = _real(project)
        if _inside(target, root):
            candidates.append(os.path.relpath(target, root))
    absolute = pattern.startswith(("/", "~"))
    pattern = _real(pattern) if absolute and not any(c in pattern for c in "*?[") else os.path.expanduser(pattern)
    for value in candidates:
        if fnmatch.fnmatchcase(value, pattern) or (not any(c in pattern for c in "*?[") and _inside(value, pattern)):
            return True
    return False


def covers(record: dict, kind: str, facts: dict, now: float | None = None) -> bool:
    if record.get("kind") != kind or not is_live(record, now):
        return False
    scope = record.get("scope") or {}
    project = scope.get("project")
    if project and not _project_covers(project, facts):
        return False
    if scope.get("pr") not in (None, ""):
        if str(facts.get("pr", "")).lstrip("#") != str(scope["pr"]).lstrip("#"):
            return False
    if scope.get("path") and not _path_covers(scope["path"], project or facts.get("project"), facts.get("path")):
        return False
    if scope.get("task") and facts.get("task") != scope["task"]:
        return False
    if scope.get("pids"):
        wanted = facts.get("pids")
        if wanted is None and facts.get("pid") is not None:
            wanted = [facts["pid"]]
        try:
            asked = {int(p) for p in wanted or []}
        except (TypeError, ValueError):
            return False
        if not asked or not asked <= {int(p) for p in scope["pids"]}:
            return False
    if scope.get("host") and str(facts.get("host") or "").lower() != str(scope["host"]).lower():
        return False
    if kind == "harness" and scope.get("what"):
        given = str(facts.get("what") or "").strip().lower()
        wanted = str(scope["what"]).strip().lower()
        if not given or not (given == wanted or fnmatch.fnmatchcase(given, wanted)):
            return False
    head = record.get("exact_head")
    if head:
        given = str(facts.get("head") or "").lower()
        if len(given) < 7 or not (given.startswith(head.lower()) or head.lower().startswith(given)):
            return False
    return True


def allowed(kind, **facts):
    """The newest live approval of `kind` covering `facts`, or None. Never raises (any error means None)."""
    try:
        home = facts.pop("home", None)
        now = facts.pop("now", None)
        for record in reversed(records(home)):
            if covers(record, kind, facts, now):
                return record
    except Exception:  # noqa: BLE001 - a broken store is "no approval", never a crash in a guard
        return None
    return None


def command_hint(kind, **facts) -> str:
    """`ah approve <kind> --project .. --pr .. --path .. --task .. --pids .. --host .. --reason "<why>"` for `facts`.
    `repo` stands in for --project when no project is given; head, now and unknown facts are left out (an approval
    survives later commits unless the owner opts into --exact-head). Never raises."""
    import shlex
    try:
        words = ["ah", "approve", str(kind if kind in KINDS else "other")]
        project = facts.get("project") or facts.get("repo")
        pids = facts.get("pids")
        if pids is None and facts.get("pid") is not None:
            pids = [facts.get("pid")]
        for flag, value in (("--project", project), ("--pr", facts.get("pr")), ("--path", facts.get("path")),
                            ("--task", facts.get("task")), ("--host", facts.get("host")), ("--what", facts.get("what"))):
            if value not in (None, ""):
                words += [flag, shlex.quote(str(value))]
        if pids:
            words += ["--pids"] + [str(int(p)) for p in pids]
        return " ".join(words + ["--reason", '"<why>"'])
    except Exception:  # noqa: BLE001
        return 'ah approve %s --reason "<why>"' % (kind if kind in KINDS else "other")


def list_approvals(project=None, kind=None, live=True, home=None) -> list:
    out = []
    for record in records(home):
        if kind and record.get("kind") != kind:
            continue
        if live and not is_live(record):
            continue
        if project:
            scoped = (record.get("scope") or {}).get("project")
            if scoped and not (_project_covers(scoped, {"project": project, "repo": project})
                               or str(scoped).lower() == str(project).lower()):
                continue
        out.append(record)
    return out


# ---- who may grant ----------------------------------------------------------------------------------------------

def _supervisor_projects(session: str, home=None) -> list:
    """The supervisor's own roles.json entry, else the role default entry (ah_roles.supervisor_entry)."""
    import ah_roles
    entry = ah_roles.supervisor_entry(session, home)
    return [p for p in entry.get("projects") or [] if isinstance(p, str)]


def _scope_in(scope: dict, roots: list) -> bool:
    project = scope.get("project")
    if not project:
        return False
    if SLUG.match(project):
        return any(project.lower() in repo_slugs(root) for root in roots)
    real = _real(project)
    return any(_inside(real, _real(root)) for root in roots)


def parse_expires(value, now: float | None = None):
    """'7d', '12h', '30m', '2w' or an ISO date/time; None for none. Raises ValueError otherwise."""
    if value in (None, "", "none", "never"):
        return None
    now = time.time() if now is None else now
    match = DURATION.match(str(value))
    if match:
        seconds = int(match.group(1)) * {"m": 60, "h": 3600, "d": 86400, "w": 604800}[match.group(2)]
        return _iso(now + seconds)
    epoch = _epoch(str(value))
    if epoch is None:
        raise ValueError("--expires takes 30m, 12h, 7d, 2w or an ISO date (YYYY-MM-DD)")
    return _iso(epoch)


def _clean_scope(scope: dict) -> dict:
    out = {}
    for key in SCOPE_KEYS:
        value = (scope or {}).get(key)
        if value in (None, "", []):
            continue
        if key == "project":
            value = str(value)
            if not SLUG.match(value):
                if not value.startswith(("/", "~")):
                    raise ValueError("--project is an absolute directory or owner/name")
                value = _real(value)
        elif key == "pr":
            value = str(value).lstrip("#")
            if not value.isdigit():
                raise ValueError("--pr is a number")
            value = int(value)
        elif key == "task":
            if not TASK.match(str(value)):
                raise ValueError("--task must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}")
        elif key == "pids":
            value = sorted({int(p) for p in (value if isinstance(value, (builtins.list, tuple, set)) else [value])})
        else:
            value = str(value)[:500]
        out[key] = value
    return out


def grant(kind, scope, granted_by, reason, expires=None, exact_head=None, source=None, home=None) -> dict:
    """Append one approval. `granted_by` is "user" or "supervisor:<session>" (the CLI decided which); a supervisor's
    scope must name a project inside the projects it supervises. Raises Refused or ValueError; writes nothing then."""
    if kind not in KINDS:
        raise ValueError("kind must be one of " + ", ".join(KINDS))
    scope = _clean_scope(scope)
    if kind == "top-rung" and not scope.get("task"):
        raise ValueError("a top-rung approval names one task (--task T); there is no session-wide grant")
    if exact_head is not None and not SHA.match(str(exact_head)):
        raise ValueError("--exact-head is a commit sha (7 to 40 hex characters)")
    if granted_by != "user":
        session = granted_by.split(":", 1)[1] if granted_by.startswith("supervisor:") else ""
        if not session:
            raise Refused("approvals are granted by the user or by a supervisor session")
        if kind in OWNER_ONLY_KINDS:
            raise Refused(f"a supervisor cannot approve {kind}; the owner runs `ah approve {kind} ...` or the request "
                          "goes to the owner")
        roots = _supervisor_projects(session, home)
        if not _scope_in(scope, roots):
            raise Refused("a supervisor approves only inside the projects it supervises (" + (", ".join(roots) or "none")
                          + "); pass --project <one of them>, or ask the owner")
    record = {"op": "grant", "id": uuid.uuid4().hex[:8], "kind": kind, "scope": scope, "granted_by": granted_by,
              "reason": str(reason or "")[:2000], "created": _iso(time.time()),
              "expires": parse_expires(expires) if expires is not None else None}
    if exact_head:
        record["exact_head"] = str(exact_head).lower()
    if source:
        record["source"] = str(source)[:400]
    _append(record, home)
    return {k: v for k, v in record.items() if k != "op"}


def revoke(approval_id, by, home=None) -> dict:
    """Revoke one approval. The owner revokes anything; a supervisor revokes what it or anyone granted inside its
    projects (revoking only narrows, so it is never refused for lack of authority there)."""
    found = next((r for r in records(home) if r["id"] == approval_id), None)
    if found is None:
        raise ValueError(f"no approval {approval_id}; `ah approvals --all` lists them")
    if by != "user":
        session = by.split(":", 1)[1] if by.startswith("supervisor:") else ""
        if not (session and (found.get("granted_by") == by
                             or _scope_in(found.get("scope") or {}, _supervisor_projects(session, home)))):
            raise Refused("only the owner, or a supervisor of the approval's project, revokes it")
    if found.get("revoked"):
        return found
    _append({"op": "revoke", "id": approval_id, "by": by, "at": _iso(time.time())}, home)
    return dict(found, revoked={"by": by, "at": _iso(time.time())})


# ---- who is calling (CLI) ---------------------------------------------------------------------------------------

def in_agent(env=None) -> bool:
    """The command runs inside an agent: an agent marker, a session id only an agent runtime exports, or an AH_ROLE
    that only a launch sets."""
    env = os.environ if env is None else env
    return (any(env.get(name) for name in AGENT_MARKERS + ("CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID"))
            or "AH_ROLE" in env)


def calling_session(env=None) -> str:
    env = os.environ if env is None else env
    return env.get("CLAUDE_CODE_SESSION_ID") or env.get("CLAUDE_SESSION_ID") or env.get("CODEX_THREAD_ID") or ""


def verify_user_msg(session: str, msg_id: str) -> str:
    """The cited message's text when `msg_id` is a human turn (uuid:, answer: or queue:) of `session`, as
    `ah user-msg` prints it. Raises Refused otherwise."""
    import ah
    try:
        rows = ah.user_msgs(ah.home_dir(), session, full=True, everything=True)["matches"]
    except Exception as error:  # noqa: BLE001
        raise Refused(f"cannot read the session transcript ({type(error).__name__}); run `ah user-msg --recent 3`")
    match = next((m for m in rows if m.get("id") == msg_id), None)
    if match is None:
        raise Refused(f"{msg_id} is not a human turn of session {session}; run `ah user-msg --recent 3` and pass the "
                      "printed id")
    return str(match.get("text") or "")


PATH_HINT = ("Fix: ask the owner or a supervisor session to run it; the owner runs the same `ah approve ...` in a "
             "terminal, or, citing the owner's own message, you add `--as-user --user-msg <id from ah user-msg "
             "--recent 3>`.")
ASK = "ask the owner or a supervisor session"


def caller(as_user=False, user_msg=None, env=None, home=None, verify=None, kind=None):
    """("user" | "supervisor:<session>", source or None). Raises Refused for a worker or a reviewer.

    The role is the launch role (ah_roles.launch_role), never the model. The owner: no AH_ROLE and no agent marker
    (a person in a terminal), or an agent that passed --as-user with the id of the owner's message that asks for it. A
    supervisor: launched with AH_ROLE=supervisor, or an agent session the owner recorded in roles.json. The OS backs
    this: a worker's sandbox cannot write the store, whatever it claims. Limit: a sub-agent's shell carries its
    parent's environment, so a supervisor's sub-agents can grant inside the supervisor's projects too."""
    import ah_roles
    env = os.environ if env is None else env
    role, source = ah_roles.role_and_source(env, home)
    if role == "owner":
        return "user", None
    session = calling_session(env)
    if as_user:
        if kind in OWNER_ONLY_KINDS:
            # The cited message is checked only for being one of the owner's turns, not for asking for this grant,
            # so an agent cannot record an owner-only approval this way (release 1001 red team).
            raise Refused(f"--as-user cannot record a {kind} approval: the owner runs `ah approve {kind} ...` in his "
                          "own terminal")
        if not user_msg:
            raise Refused("--as-user needs --user-msg <id from `ah user-msg --recent 3`>")
        if not session:
            raise Refused("--as-user needs the calling session (CLAUDE_CODE_SESSION_ID)")
        text = (verify or verify_user_msg)(session, user_msg)
        return "user", (f'{user_msg} "{" ".join(text.split())[:200]}" (recorded by {role} session {session}, '
                        f'{source})')
    if role == "supervisor":
        if not session:
            raise Refused("a supervisor grants under its session id, and CLAUDE_CODE_SESSION_ID (or CODEX_THREAD_ID) is "
                          "not set; " + ASK)
        return "supervisor:" + session, None
    raise Refused(f"this session is a {role} ({source}); a {role} does not grant approvals. " + PATH_HINT)


def session_model(session: str, home=None) -> str:
    """The model of a session's last assistant turn, from its Claude transcript; '' when not found."""
    import glob
    import ah_roles
    if not ah_roles.SESSION_ID.match(session or ""):
        return ""
    base = Path(home or os.environ.get("AH_HOME") or Path.home()) / ".claude" / "projects"
    for path in glob.glob(str(base / "*" / (session + ".jsonl")))[:3]:
        model = ah_roles._last_model(Path(path))
        if model:
            return model
    return ""


def supervisors_view(home=None) -> dict:
    """Each recorded supervisor session, plus the role default entry under ROLE_DEFAULT_KEY. `model` is shown for the
    reader only; no permission reads it."""
    import ah_roles
    data = ah_roles.load_roles(home)
    out = {}
    for session, entry in data["supervisors"].items():
        entry = entry if isinstance(entry, dict) else {}
        out[session] = {"projects": entry.get("projects") or [], "harness": entry.get("harness") is True,
                        "model": session_model(session, home) or "unknown", "set_at": entry.get("set_at"),
                        "by": entry.get("by")}
    default = data.get(ah_roles.DEFAULT_KEY)
    if default:
        out[ROLE_DEFAULT_KEY] = {"projects": default.get("projects") or [], "harness": default.get("harness") is True,
                                 "set_at": default.get("set_at"), "by": default.get("by"),
                                 "for": "sessions launched with AH_ROLE=supervisor that have no entry of their own"}
    return out


# ---- CLI --------------------------------------------------------------------------------------------------------

def _scope_text(scope: dict) -> str:
    parts = []
    for key in SCOPE_KEYS:
        if key in scope:
            value = scope[key]
            parts.append(f"{key}={','.join(map(str, value)) if isinstance(value, builtins.list) else value}")
    return " ".join(parts) or "(everything)"


def table(rows: list) -> str:
    if not rows:
        return "no approvals recorded (ask the owner; record the answer with `ah approve`)"
    lines = []
    for r in rows:
        state = "revoked" if r.get("revoked") else ("expired" if not is_live(r) else "live")
        until = r.get("expires") or "standing"
        head = f" head={r['exact_head'][:12]}" if r.get("exact_head") else ""
        lines.append(f"{r['id']}  {r['kind']:<8}  {state:<7}  by {r['granted_by']:<20} {r['created'][:16]}  "
                     f"until {until[:16]:<16}  {_scope_text(r.get('scope') or {})}{head}")
        if r.get("reason"):
            lines.append(" " * 10 + "reason: " + " ".join(str(r["reason"]).split())[:200])
    return "\n".join(lines)


def _parser():
    import argparse
    p = argparse.ArgumentParser(prog="ah", description="the one approvals store (docs/approvals.md)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def facts(q, with_text=True):
        q.add_argument("--project", help="absolute directory or owner/name")
        q.add_argument("--pr")
        q.add_argument("--path", help="path or glob (relative globs are relative to --project)")
        q.add_argument("--task")
        q.add_argument("--pids", nargs="+", type=int)
        q.add_argument("--host")
        if with_text:
            q.add_argument("--what", help="free text: what is approved")

    a = sub.add_parser("approve", help="record an approval (owner, or a supervisor inside its projects)")
    a.add_argument("kind", choices=KINDS)
    facts(a)
    a.add_argument("--reason", default="")
    a.add_argument("--expires", help="30m, 12h, 7d, 2w or YYYY-MM-DD (default: standing)")
    a.add_argument("--exact-head", help="opt in: valid only while the head is this commit")
    a.add_argument("--as-user", action="store_true", help="record as the owner, citing --user-msg")
    a.add_argument("--user-msg", help="id from `ah user-msg --recent 3` (with --as-user)")
    a.add_argument("--json", action="store_true")

    ls = sub.add_parser("approvals", help="list approvals; `revoke <id>`; `check <kind> [facts]`")
    ls.add_argument("action", nargs="?", default="list", choices=("list", "revoke", "check"))
    ls.add_argument("target", nargs="?", help="the id to revoke, or the kind to check")
    facts(ls, with_text=False)
    ls.add_argument("--what", help="the guard or rule being changed (check harness)")
    ls.add_argument("--repo", help="owner/name (check)")
    ls.add_argument("--head", help="the current head sha (check)")
    ls.add_argument("--kind", choices=KINDS)
    ls.add_argument("--all", action="store_true", help="include revoked and expired")
    ls.add_argument("--json", action="store_true")
    ls.add_argument("--as-user", action="store_true")
    ls.add_argument("--user-msg")

    s = sub.add_parser("supervisor", help="make a session a supervisor of projects (owner only)")
    s.add_argument("action", choices=("set", "clear", "list"))
    s.add_argument("--session")
    s.add_argument("--role-default", action="store_true",
                   help="the entry for sessions launched with AH_ROLE=supervisor that have no entry of their own")
    s.add_argument("--project", action="append", default=[])
    s.add_argument("--harness", action="store_true", help="this supervisor also maintains the harness "
                                                          "(changes still need an `ah approve harness` from the owner)")
    return p


def _out(data, as_json=True):
    sys.stdout.write((json.dumps(data, indent=2, sort_keys=True) if as_json else str(data)) + "\n")


def _unwritable(error: OSError, path, hint: str) -> str:
    """The refusal for a store the sandbox keeps read-only: the path, the error, and who runs the one command."""
    where = error.filename if isinstance(getattr(error, "filename", None), str) else str(path)
    reason = error.strerror or type(error).__name__
    return (f"cannot write {where} ({reason}): this session's sandbox keeps it read-only, so {ASK} to run "
            f"`{hint}`")


def _approve_hint(args) -> str:
    return command_hint(args.kind, project=args.project, pr=args.pr, path=args.path, task=args.task, pids=args.pids,
                        host=args.host, what=args.what)


def main(argv=None, env=None, home=None) -> int:
    import shlex
    argv = [*(sys.argv[1:] if argv is None else argv)]
    args = _parser().parse_args(argv)
    try:
        return _run(args, env, home)
    except Refused as error:
        _out({"ok": False, "code": "refused", "message": str(error)})
        return 3
    except ValueError as error:
        _out({"ok": False, "code": "bad_request", "message": str(error)})
        return 2
    except OSError as error:  # the sandbox (or a read-only disk) refused a write: a refusal, never a traceback
        import ah_roles
        if args.cmd == "supervisor":
            path, hint = ah_roles.state_dir(home) / ah_roles.ROLES_NAME, "ah " + " ".join(map(shlex.quote, argv))
        elif args.cmd == "approve":
            path, hint = store_path(home), _approve_hint(args)
        else:
            path, hint = store_path(home), "ah " + " ".join(map(shlex.quote, argv))
        _out({"ok": False, "code": "refused", "message": _unwritable(error, path, hint)})
        return 3


def _run(args, env, home) -> int:
    """One dispatch; main() turns Refused, ValueError and OSError into exit codes 3, 2 and 3."""
    if args.cmd == "approve":
        try:
            who, source = caller(args.as_user, args.user_msg, env=env, home=home, kind=args.kind)
        except Refused as error:
            raise Refused(f"{error} The command to run: `{_approve_hint(args)}`.") from None
        scope = {"project": args.project, "pr": args.pr, "path": args.path, "task": args.task, "pids": args.pids,
                 "host": args.host, "what": args.what}
        record = grant(args.kind, scope, who, args.reason, expires=args.expires, exact_head=args.exact_head,
                       source=source, home=home)
        _out({"ok": True, "approval": record} if args.json else "approved " + table([record]), args.json)
        return 0
    if args.cmd == "approvals":
        if args.action == "revoke":
            if not args.target:
                raise ValueError("ah approvals revoke <id>")
            who, _ = caller(args.as_user, args.user_msg, env=env, home=home)
            record = revoke(args.target, who, home=home)
            _out({"ok": True, "revoked": record} if args.json else "revoked " + table([record]), args.json)
            return 0
        if args.action == "check":
            kind = args.target or args.kind
            if kind not in KINDS:
                raise ValueError("ah approvals check <kind> [--project P --pr N --path X --task T ...]")
            found = allowed(kind, project=args.project, repo=args.repo, pr=args.pr, path=args.path, task=args.task,
                            pids=args.pids, host=args.host, head=args.head, what=args.what, home=home)
            if args.json:
                _out({"approved": bool(found), "approval": found})
            else:
                _out(("approved: " + table([found])) if found else
                     f"not approved: no live {kind} approval covers this; ask the owner (and record the answer "
                     "with `ah approve`)", False)
            return 0 if found else 1
        rows = list_approvals(project=args.project, kind=args.kind, live=not args.all, home=home)
        _out(rows if args.json else table(rows), args.json)
        return 0
    if args.cmd == "supervisor":
        return _supervisor(args, env, home)
    return 2


def _supervisor(args, env, home) -> int:
    import ah_roles
    if args.action == "list":
        _out(supervisors_view(home))
        return 0
    if ah_roles.launch_role(os.environ if env is None else env, home) != "owner":
        raise Refused("only the owner, in a terminal, names supervisors: `python3 ~/.claude/hooks/ah.py "
                      "supervisor set --session <id> --project <dir>` (or `--role-default --project <dir>`)")
    if args.role_default == bool(args.session):
        raise ValueError("pass --session <id> or --role-default (one of them)")
    if args.action == "clear":
        cleared = (ah_roles.clear_role_default(home=home) if args.role_default
                   else ah_roles.clear_supervisor(args.session, home=home))
        _out({"ok": True, "cleared": cleared})
        return 0
    if not args.project:
        raise ValueError("--project <dir> (repeatable) is required")
    if args.role_default:
        entry = ah_roles.set_role_default(args.project, by="user", harness=args.harness, home=home)
        _out({"ok": True, "supervisor": ROLE_DEFAULT_KEY, "entry": entry})
        return 0
    entry = ah_roles.set_supervisor(args.session, args.project, by="user", home=home)
    if args.harness:  # stored beside the projects; ah_roles.may_edit_harness reads it
        data = ah_roles.load_roles(home)
        data["supervisors"][args.session]["harness"] = True
        ah_roles.save_roles(data, home)
        entry = data["supervisors"][args.session]
    _out({"ok": True, "supervisor": args.session, "entry": entry})
    return 0


list = list_approvals  # noqa: A001 - the documented API name; this module never calls the builtin list()

if __name__ == "__main__":
    sys.exit(main())



