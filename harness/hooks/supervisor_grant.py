"""Supervisor power: a main agent asks for it, the user grants it at his own terminal, and guards check it at every use.

The user's words, as relayed by the coordinator on 2026-11-24 (goodqa#16944):
  "you are allowed to merge things. in all projects you supervise." / "you are allowed to delete things, in all
  projects you supervise." / "make a way for an agent to request supervisor power from me, record i granted it, and then
  its able to do these things" / "a supervisor agent must be sol,opus,fable or astra.. sonnet terra and luna haiku etc
  are not qualified to be granted supervisor power".

The flow:

  request  `ah supervisor request --project owner/repo:host[,host] ... --power merge|delete ... --reason TEXT
           [--user-source SRC]`, run by the main agent as ONE plain foreground `ah` command. Main's PreToolUse hook
           (mission_gate -> ah_ops.pretool) stamps exactly that argument list, bound to the running tool call; this
           process takes the stamp before it parses anything. A sub-agent's call gets no stamp, so it cannot request.
           The session, the transcript and the model come from that stamp and the transcript record of that one call,
           never from argv, the environment or anything the agent says. A request grants nothing.
  grant    `python3 scripts/enable-agent-ops.py --grant-supervisor <rid>` (installed as
           ~/.agent-harness/bin/ah_enable_self_serve.py), run by the user. It runs the enabler's human checks, shows
           the text in terminal_text(), and signs a grant with the self-serve key under this module's own domain.
           The request file is only a pointer to the call: load_request computes every field the user sees again
           from the recorded command (derive_request) and refuses a file whose fields differ. One call, one grant.
  check    check(payload, power, project, ...) from a consuming guard (merge_gate for merge, the sanctioned delete
           routes for delete). It re-verifies the signature, the session, the project, the host, the power, the expiry,
           revocation and the kill switch, and it re-reads the model of the very call being checked.
  revoke   `ah supervisor revoke <gid>|all`. Anyone may revoke, an agent included: it only takes power away. Rows go
           to their own append-only log (revocation_state reads it); a log that cannot be read safely revokes every
           grant, and `all` revokes the grants issued up to its time.

Why an agent cannot grant itself the power (each has a test in tests/test_supervisor_grant.py):
  * The grant is an Ed25519 signature by the self-serve key under DOMAIN. Without the private key a grant cannot be
    written, and a signature over a self-serve policy (another domain) never verifies as a grant.
  * The enabler refuses without a terminal, with an agent ancestor or environment marker, and without the code shown
    in the native dialog.
  * The model is read from the transcript record of the call being checked, found by payload.tool_use_id. The API
    assigns that id when the call is made, so no earlier line can carry it. A line the agent appends while the call runs
    makes two records with that id, and check() then refuses; the whole file is searched, so padding cannot hide the
    real record. An in-place edit leaves one record, so the control is that no agent route writes the transcript: the
    command guard's `transcript-forgery` rule (class LOG_DELETE) refuses shell writes under ~/.claude/projects, and
    transcript_guard.py refuses Write, Edit, MultiEdit and NotebookEdit there. A script that computes the path at run
    time is outside both, the same-user limit stated below.
  * home=, now= and the proof root are clamped by self_serve (_resolve_home, _clock, _claude_dir).

What a grant never covers, whatever it says (NEVER_COVERED, also copied into every grant): rules 1 to 4, permission
prompts and modes, guard files, logs and WALs, production data, and yates, apex_app_pos and OptinRouter. merge and
delete are the only powers that exist, so no call can ask for anything else. A merge ok means only "no need to ask the
user": merge_gate still requires the review of record.

Same-user trust: like self_serve, the files here are local and same-user writable. The signature and the guard's
protection of policy/ and private/ are the controls. Never raises from check(); any error is a refusal.
Python 3.9+, stdlib plus `cryptography` (for signatures). Importing this module has no side effects.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import mmap
import os
import re
import secrets
import socket
import stat
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import self_serve as ss  # noqa: E402

REQUEST_SCHEMA = "supervisor-request/1"
GRANT_SCHEMA = "supervisor-grant/1"
POLICY_SCHEMA = "supervisor-policy/1"
GRANT_PURPOSE = "supervisor-grant"
DOMAIN = b"agent-harness-supervisor-grant/1\x00"
POWERS = ("merge", "delete")
DELETE_KINDS = ("worktree", "clone", "branch", "build", "scratch")
OWNED_KINDS = ("worktree", "clone", "branch")  # these need created_by_session == the grant's session
DEFAULT_EXPIRY = "8h"
EXPIRY_CHOICES = {"1h": 3600, "8h": 8 * 3600, "24h": 24 * 3600, "7d": 7 * 86400}
UNTIL_REVOKED = "until revoked"  # never a default: the user must type these words
REQUEST_MAX_AGE = 24 * 3600
MAX_PROJECTS = 20
MAX_REASON = 1000
TRANSCRIPT_MAX = 4 << 30  # the whole transcript is scanned (mmap) for the call's id; a larger file is refused
NEEDLE_LINES_MAX = 64  # lines naming one tool_use id (its call, its result, progress rows); more is refused
REVOCATIONS_MAX = 4 << 20  # only `revoke` appends to the revocation log, so it stays small; larger is all-revoked
WALK_MAX = 500_000  # entries read inside a local delete target before it is refused as too large to check
EVIDENCE_MAX_FILE = 256 << 20
EVIDENCE_MAX_TOTAL = 1 << 30
STAMP_SUB = "supervisor"

CODES = ("no_grant", "expired", "revoked", "disabled", "wrong_session", "subagent_not_included", "wrong_project",
         "wrong_host", "power_not_granted", "model_unqualified", "model_unknown", "never_covered", "bad_signature",
         "bad_input")

POWER_TEXT = {
    "merge": ("merge pull requests without asking you each time. It still needs the review of record: an exact-HEAD "
              "PASS, or a BLOCK with every finding triaged and ticketed, or an audited waiver. This replaces your "
              "per-merge question, never the review."),
    "delete": ("delete worktrees, clones and branches that this session or its agents created, build output and "
               "scratch, through the sanctioned routes, without the publication-proof or backup step."),
}

NEVER_COVERED = (
    "secrets, production accounts and passwords (rules 1 and 2)",
    "evading a guard; force-push or rewriting published refs (rules 3 and 4)",
    "deleting Claude or Codex logs, WALs or sessions without a verified Dropbox copy",
    "permission prompts and permission modes",
    "installing or changing guard files",
    "production data, yates, OptinRouter, and anything outside the projects above",
)

# What a supervisor delete must never touch on top of the delete guard's own Tier A list (read from command_guard, see
# never_covered_roots): the harness logs, policy, private keys, state and installed tools, the installed hooks and the
# settings. Logs are never deleted without a verified backup (the user's rule), so ~/.agent-harness/logs is here.
SUPERVISOR_EXTRA_ROOTS = ("{home}/.agent-harness/logs", "{home}/.agent-harness/policy", "{home}/.agent-harness/private",
                          "{home}/.agent-harness/state", "{home}/.agent-harness/bin", "{home}/.agent-harness/codex-wals",
                          "{home}/.claude/hooks", "{home}/.claude/settings.json", "{home}/.claude/settings.local.json",
                          "{home}/.claude/CLAUDE.md", "{home}/.claude/projects", "{home}/.claude/wals",
                          "{home}/.claude/sessions", "{home}/.claude/transcripts", "{home}/.codex")
REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")
HOST_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")
HEX16, HEX32 = re.compile(r"^[0-9a-f]{16}$"), re.compile(r"^[0-9a-f]{32}$")
AGENT_ID = re.compile(r"^[A-Za-z0-9_-]{6,64}$")
TOOL_USE_ID = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
SESSION_ID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SECRETISH = re.compile(r"(?i)(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|"
                       r"(token|secret|password|passwd|apikey|api_key)\s*[=:]\s*\S+|Bearer\s+\S+|BEGIN [A-Z ]*PRIVATE KEY)")
GRANT_KEYS = {"schema", "purpose", "gid", "rid", "key_id", "session", "include_subagents", "projects", "powers",
              "issued_at", "expires_at", "user_source", "never_covered", "model_at_grant", "signature"}


class Refusal(Exception):
    """A refused step: code is one of CODES (or a request code), message is safe to print."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# ------------------------------------------------------------------ paths (all under the real home, see self_serve)

def _home(home=None) -> str:
    return ss._resolve_home(home)


def grants_dir(home=None) -> Path:
    return ss.policy_dir(home) / "supervisor"


def revocations_path(home=None) -> Path:
    return grants_dir(home) / "revocations.jsonl"


def requests_dir(home=None) -> Path:
    return ss._root(home) / "state" / "supervisor" / "requests"


def audit_path(home=None) -> Path:
    return ss._root(home) / "state" / "supervisor-audit.jsonl"


def _claude_dir() -> Path:
    return Path(ss._claude_dir())


# ------------------------------------------------------------------ small readers

def _read_regular(path: Path, limit: int, private: bool = False) -> bytes:
    """A regular file of this user's (never a symlink or FIFO), at most `limit` bytes. private=True also needs no
    group or other bits. Raises Refusal('bad_input')."""
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        raise Refusal("bad_input", "%s cannot be read" % path.name) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in (os.getuid(), 0) or info.st_mode & 0o022 \
                or (private and info.st_mode & 0o077):
            raise Refusal("bad_input", "%s is not a plain file of this user's" % path.name)
        if info.st_size > limit:
            raise Refusal("bad_input", "%s is larger than %d bytes" % (path.name, limit))
        return os.read(fd, limit + 1)[:limit]
    finally:
        os.close(fd)


def load_policy() -> dict:
    """supervisor_policy.json beside this file: the qualified families, the known hosts and the never-covered names."""
    data = ss._strict_json(_read_regular(HERE / "supervisor_policy.json", 65536))
    if not isinstance(data, dict) or data.get("schema") != POLICY_SCHEMA or not isinstance(data.get("qualified"), dict) \
            or not isinstance(data.get("hosts"), dict) or not isinstance(data.get("never_covered_names"), list):
        raise Refusal("bad_input", "supervisor_policy.json is malformed")
    return data


def _families() -> dict:
    data = ss._strict_json(_read_regular(HERE / "model_tiers.json", 1 << 20))
    families = data.get("families") if isinstance(data, dict) else None
    if not isinstance(families, dict):
        raise Refusal("model_unknown", "model_tiers.json has no families table")
    return families


def _normalize(model):
    try:
        import model_tiers  # noqa: PLC0415
        return model_tiers.normalize_model(model)
    except Exception:  # noqa: BLE001
        return model.strip().lower() if isinstance(model, str) and model.strip() else None


def model_family(model):
    """(harness, family) for a model id from the tiers table, or None when it matches no family."""
    name = _normalize(model)
    if not name:
        return None
    for harness, table in _families().items():
        if not isinstance(table, dict):
            continue
        for family, spec in table.items():
            if not isinstance(spec, dict):
                continue
            aliases = [str(a).lower() for a in spec.get("aliases", []) if isinstance(a, str)]
            pattern = spec.get("id_pattern")
            if name in aliases or (isinstance(pattern, str) and pattern.startswith("^") and re.search(pattern, name)):
                return harness, family
    return None


def qualify(model, policy=None) -> tuple:
    """(True, family) for a qualified supervisor model, else (False, code). Unknown models are never qualified."""
    policy = policy or load_policy()
    found = model_family(model)
    if found is None:
        return False, "model_unknown"
    harness, family = found
    allowed = policy["qualified"].get(harness)
    if isinstance(allowed, list) and family in allowed:
        return True, family
    return False, "model_unqualified"


def qualified_names(policy=None) -> list:
    policy = policy or load_policy()
    return sorted(f for names in policy["qualified"].values() if isinstance(names, list) for f in names)


# ------------------------------------------------------------------ the transcript record of one call

def _within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def resolve_transcripts(payload) -> tuple:
    """(session, agent_id or None, main transcript, the caller's own transcript), proven against the real
    ~/.claude/projects: the main transcript must be <projects>/<dir>/<session>.jsonl (caller_identity.is_main on the
    payload without its agent fields), and a sub-agent's must be <dir>/<session>/subagents/agent-<id>.jsonl beside it.
    Raises Refusal('bad_input')."""
    if not isinstance(payload, dict):
        raise Refusal("bad_input", "no hook payload")
    session, agent, path = payload.get("session_id"), payload.get("agent_id"), payload.get("transcript_path")
    if not isinstance(session, str) or not SESSION_ID.match(session) or not isinstance(path, str) or "\x00" in path:
        raise Refusal("bad_input", "the hook payload has no session and transcript")
    if agent is not None and (not isinstance(agent, str) or not AGENT_ID.match(agent)):
        raise Refusal("bad_input", "the hook payload's agent id is malformed")
    real = Path(os.path.realpath(path))
    main = real
    if agent and real.name == "agent-%s.jsonl" % agent and real.parent.name == "subagents":
        main = real.parent.parent.parent / (session + ".jsonl")
    import caller_identity  # noqa: PLC0415
    bare = {"session_id": session, "transcript_path": str(main)}
    if not caller_identity.is_main(bare, str(_claude_dir())):
        raise Refusal("bad_input", "the transcript is not a session transcript under ~/.claude/projects")
    own = main
    if agent:
        own = main.parent / session / "subagents" / ("agent-%s.jsonl" % agent)
        projects = os.path.realpath(str(_claude_dir() / "projects"))
        if os.path.islink(str(own)) or not own.is_file() or not _within(os.path.realpath(str(own)), projects):
            raise Refusal("bad_input", "the sub-agent's transcript cannot be found beside the session transcript")
    return session, agent or None, main, own


def _lines_with(path: Path, needle: bytes) -> list:
    """Every line of the WHOLE transcript that contains `needle` (a tool_use id). The file is scanned end to end
    through mmap, so padding appended after a forged copy cannot push the real record out of view (no tail window).
    More than NEEDLE_LINES_MAX matches, a file over TRANSCRIPT_MAX, or anything but a regular file is a refusal."""
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        raise Refusal("model_unknown", "the transcript cannot be read") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Refusal("model_unknown", "the transcript is not a regular file")
        if info.st_size > TRANSCRIPT_MAX:
            raise Refusal("model_unknown", "the transcript is larger than %d bytes; refusing" % TRANSCRIPT_MAX)
        if info.st_size == 0:
            return []
        with mmap.mmap(fd, info.st_size, access=mmap.ACCESS_READ) as view:
            lines, pos = [], view.find(needle)
            while pos != -1:
                if len(lines) >= NEEDLE_LINES_MAX:
                    raise Refusal("model_unknown", "the tool call's id appears more than %d times; refusing" % NEEDLE_LINES_MAX)
                start = view.rfind(b"\n", 0, pos) + 1
                end = view.find(b"\n", pos)
                end = info.st_size if end == -1 else end
                lines.append(view[start:end])
                pos = view.find(needle, end)
            return lines
    except (OSError, ValueError):
        raise Refusal("model_unknown", "the transcript cannot be read") from None
    finally:
        os.close(fd)


def call_record(transcript: Path, tool_use_id) -> dict:
    """The one assistant record whose content holds the tool_use with this id. Only the client's own record shape
    counts: type and message.role 'assistant', a message.model string, a uuid, not an API error message. None found,
    or two of them (a forged copy appended while the call runs, anywhere in the file), is a refusal."""
    if not isinstance(tool_use_id, str) or not TOOL_USE_ID.match(tool_use_id):
        raise Refusal("model_unknown", "the hook payload names no tool call, so the model cannot be read")
    needle = tool_use_id.encode()
    found = []
    for raw in _lines_with(transcript, needle):
        if needle not in raw:
            continue
        try:
            record = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue
        message = record.get("message") if isinstance(record, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            continue
        uses = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("id") == tool_use_id]
        if not uses:
            continue
        found.append((record, message, uses))
    if not found:
        raise Refusal("model_unknown", "no transcript record of this tool call was found, so the model is unknown")
    if len(found) > 1 or len(found[0][2]) > 1:
        raise Refusal("model_unknown", "more than one transcript record claims this tool call; refusing")
    record, message, uses = found[0]
    if record.get("type") != "assistant" or message.get("role") != "assistant" or record.get("isApiErrorMessage") \
            or not isinstance(record.get("uuid"), str) or not isinstance(message.get("model"), str):
        raise Refusal("model_unknown", "the record of this tool call is not an assistant record written by the client")
    return {"model": message["model"], "uuid": record["uuid"], "input": uses[0].get("input"),
            "name": uses[0].get("name"), "timestamp": record.get("timestamp")}


def observed_model(payload) -> tuple:
    """(model id, family) of the call this payload describes, read from its own transcript record; Refusal otherwise.
    Nothing the agent typed or set is read."""
    _session, _agent, _main, own = resolve_transcripts(payload)
    record = call_record(own, payload.get("tool_use_id"))
    ok, family = qualify(record["model"])
    if not ok:
        raise Refusal(family, "the model of this call (%s) is not qualified for supervisor power; only %s are"
                      % (str(record["model"])[:60], ", ".join(qualified_names())))
    return record["model"], family


# ------------------------------------------------------------------ hosts

def local_host(policy=None) -> str | None:
    policy = policy or load_policy()
    try:
        short = socket.gethostname().split(".")[0].lower()
    except OSError:
        short = ""
    darwin = sys.platform == "darwin"
    for name, spec in policy["hosts"].items():
        if isinstance(spec, dict) and short and short in [str(n).lower() for n in spec.get("names", [])]:
            return name
    for name, spec in policy["hosts"].items():
        if isinstance(spec, dict) and spec.get("darwin") is darwin and not spec.get("names"):
            return name
    return None


# ------------------------------------------------------------------ request

def _forbidden_name(text, policy) -> str | None:
    low = str(text or "").lower()
    for name in policy["never_covered_names"]:
        if isinstance(name, str) and name.lower() in low:
            return name
    return None


def parse_projects(values, policy) -> list:
    """[{name, repo, hosts}] from `owner/repo:host[,host]` words. Wildcards, unknown hosts and never-covered names are
    refused; every project and host must be named."""
    if not values:
        raise Refusal("bad_input", "name at least one project: --project owner/repo:host[,host]")
    out, seen = [], set()
    for value in values:
        text = str(value)
        if any(ch in text for ch in "*?[]{}") or text.lower() in ("all", "any", "everything"):
            raise Refusal("bad_input", "projects are named one by one; a wildcard (%s) is refused" % text[:60])
        repo, sep, hosts = text.partition(":")
        if not sep or not REPO.match(repo):
            raise Refusal("bad_input", "a project is owner/repo:host[,host], not %s" % text[:80])
        names = [h.strip().lower() for h in hosts.split(",") if h.strip()]
        if not names or any(not HOST_NAME.match(h) or h not in policy["hosts"] for h in names):
            raise Refusal("bad_input", "hosts for %s must be among %s" % (repo, ", ".join(sorted(policy["hosts"]))))
        blocked = _forbidden_name(repo, policy)
        if blocked:
            raise Refusal("never_covered", "%s is never covered by supervisor power" % blocked)
        if repo.lower() in seen:
            raise Refusal("bad_input", "%s is named twice" % repo)
        seen.add(repo.lower())
        out.append({"name": repo.split("/", 1)[1], "repo": repo, "hosts": sorted(set(names))})
    if len(out) > MAX_PROJECTS:
        raise Refusal("bad_input", "at most %d projects in one request" % MAX_PROJECTS)
    return out


def _slug_pattern(repo: str):
    return re.compile(rb"(?i)(?<![A-Za-z0-9._-])" + re.escape(repo.encode()) + rb"(?![A-Za-z0-9_-])")


def _evidence_files(session: str, home: str) -> list:
    """The session's own WAL files and the brief files in its work directory (*.md), regular files only."""
    files = []
    for folder, pattern in ((Path(home) / ".claude" / "wals" / session, "*.jsonl"),
                            (Path(home) / ".agent-harness" / "work" / session, "**/*.md")):
        try:
            if folder.is_symlink() or not folder.is_dir():
                continue
            for path in sorted(folder.glob(pattern))[:2000]:
                if not path.is_symlink() and path.is_file():
                    files.append(path)
        except OSError:
            continue
    return files


def supervised_evidence(session: str, repos, home: str) -> dict:
    """{repo: the file of the session's own WAL or brief that names it}. A repo with no such file is missing."""
    patterns = {repo: _slug_pattern(repo) for repo in repos}
    found, total = {}, 0
    for path in _evidence_files(session, home):
        if len(found) == len(patterns) or total > EVIDENCE_MAX_TOTAL:
            break
        try:
            size = path.stat().st_size
            if size > EVIDENCE_MAX_FILE:
                continue
            data = _read_regular(path, EVIDENCE_MAX_FILE)
        except (OSError, Refusal):
            continue
        total += len(data)
        for repo, pattern in patterns.items():
            if repo not in found and pattern.search(data):
                found[repo] = str(path)
    return found


def _verify_user_source(source: str) -> str:
    """The cited sentence, when provenance verifies the source as the user's own typed words; Refusal otherwise."""
    import provenance  # noqa: PLC0415
    result = provenance.resolve(source)
    if not result.get("ok") or result.get("origin") != "user" or result.get("weak") or result.get("kind") not in ("user", "uuid", "answer"):
        codes = ", ".join(str(p.get("code", "?")) for p in result.get("problems") or []) or "not the user's own turn"
        raise Refusal("bad_input", "--user-source does not verify as the user's own words (%s)" % codes)
    match = re.search(r'"(.{1,400})"', source)
    return match.group(1) if match else ""


class _ArgError(Exception):
    pass


def _parse_request_argv(argv) -> dict:
    import argparse  # noqa: PLC0415

    class Parser(argparse.ArgumentParser):
        def error(self, message):  # never exit or print: a bad argument list is a refusal
            raise _ArgError(message)

    parser = Parser(prog="ah supervisor request", allow_abbrev=False, add_help=False)
    parser.add_argument("--project", action="append", required=True, help="owner/repo:host[,host] (repeat per project)")
    parser.add_argument("--power", action="append", choices=POWERS, required=True)
    parser.add_argument("--include-subagents", action="store_true", help="ask for this session's sub-agents too")
    parser.add_argument("--reason", required=True, help="why, shown to the user as data (at most %d chars)" % MAX_REASON)
    parser.add_argument("--user-source", help="optional user:/uuid:/answer: citation of the user's words")
    try:
        return vars(parser.parse_args([str(a) for a in argv]))
    except _ArgError as error:
        raise Refusal("bad_input", "ah supervisor request: %s" % str(error)[:200]) from None


def recorded_argv(command) -> list:
    """The argument list after `ah supervisor request` in the recorded Bash command, read with the same parser main's
    stamping hook uses (ah_ops.stamped_argvs). The command must be exactly ONE plain simple command that runs
    `ah supervisor request ...`: `echo supervisor request`, a pipe, a list, a wrapper or a word only the shell can
    compute is refused."""
    if not isinstance(command, str) or not command.strip() or "\x00" in command:
        raise Refusal("not_main", "the recorded tool call has no command")
    import ah_ops  # noqa: PLC0415
    shellwords = ah_ops.load_sibling("shellwords")
    simple = list(shellwords.simple_commands(command))
    argvs = ah_ops.stamped_argvs(command)
    if len(simple) != 1 or len(argvs) != 1 or argvs[0][:2] != [STAMP_SUB, "request"]:
        raise Refusal("not_main", "the recorded tool call is not one plain `ah supervisor request ...` command")
    return argvs[0][2:]


def request_id(session: str, tool_use_id: str) -> str:
    """One call gives one request id: a second request file, or a second grant, for the same call is refused."""
    return hashlib.sha256(("%s\0%s" % (session, tool_use_id)).encode()).hexdigest()[:16]


def derive_request(record: dict, session: str, home: str, policy: dict) -> dict:
    """Every field the user is shown and signs, computed from the client's own record of the call: its model and its
    exact command (re-parsed), plus the session's own WAL and brief for evidence and provenance for --user-source. The
    request file never supplies any of these. Raises Refusal."""
    ok, family = qualify(record["model"], policy)
    if not ok:
        raise Refusal(family, "this session runs %s, which is not qualified for supervisor power; only %s are"
                      % (str(record["model"])[:60], ", ".join(qualified_names(policy))))
    tool_input = record.get("input") if isinstance(record.get("input"), dict) else {}
    argv = recorded_argv(tool_input.get("command"))
    options = _parse_request_argv(argv)
    projects = parse_projects(options["project"], policy)
    evidence = supervised_evidence(session, [p["repo"] for p in projects], home)
    missing = [p["repo"] for p in projects if p["repo"] not in evidence]
    if missing:
        raise Refusal("not_supervised", "this session's own WAL and brief never name %s, so it cannot show it supervises "
                      "it; name only projects your WAL or brief records" % ", ".join(missing))
    reason = str(options["reason"]).strip()
    if not reason or len(reason) > MAX_REASON or "\x00" in reason:
        raise Refusal("bad_input", "--reason must be 1 to %d characters" % MAX_REASON)
    if SECRETISH.search(reason):
        raise Refusal("bad_input", "--reason looks like it holds a secret; it was not recorded")
    user_source, excerpt = options.get("user_source"), ""
    if user_source:
        excerpt = _verify_user_source(user_source)
    return {"argv": argv, "model": record["model"], "model_family": family, "projects": projects,
            "powers": sorted(set(options["power"])), "include_subagents": bool(options["include_subagents"]),
            "reason": reason, "user_source": user_source or None, "user_excerpt": excerpt or None,
            "evidence": evidence}


# The request file is a pointer to one call. These fields must equal what derive_request computes again from that call;
# any difference means the file was edited, and the request is refused.
REQUEST_DERIVED = ("model", "model_family", "projects", "powers", "include_subagents", "reason", "user_source",
                   "user_excerpt")
REQUEST_KEYS = {"schema", "rid", "at", "session", "transcript", "tool_use_id", "record_uuid", "evidence"} | set(REQUEST_DERIVED)


def build_request(argv, stamp: dict, *, home=None, now=None) -> dict:
    """The request record for `ah supervisor request ARGV`, proven by `stamp` (the bound stamp main's hook wrote for this
    exact argument list). Raises Refusal. Writes nothing."""
    now = ss._clock(now)
    home = _home(home)
    policy = load_policy()
    if not isinstance(stamp, dict) or not isinstance(stamp.get("session"), str) or not stamp.get("tool_use_id"):
        raise Refusal("not_main", "only the main agent requests supervisor power: run ONE plain foreground "
                      "`ah supervisor request ...` command (no wrapper, no $(...)) so main's hook can stamp it. A "
                      "sub-agent's call gets no stamp. If main ran it, the stamping hook is not installed yet: the user "
                      "installs the merged hook files with his pinned install line")
    _parse_request_argv(argv)  # a malformed argument list is refused before anything is read
    payload = {"session_id": stamp["session"], "transcript_path": stamp.get("transcript"),
               "tool_use_id": stamp["tool_use_id"]}
    session, agent, _main, own = resolve_transcripts(payload)
    if agent:
        raise Refusal("not_main", "only the main agent requests supervisor power")
    record = call_record(own, stamp["tool_use_id"])
    derived = derive_request(record, session, home, policy)
    if derived.pop("argv") != [str(a) for a in argv]:
        raise Refusal("not_main", "the stamped tool call is not this `ah supervisor request` command")
    return dict(derived, schema=REQUEST_SCHEMA, rid=request_id(session, stamp["tool_use_id"]), at=ss.iso(now),
                session=session, transcript=str(own), tool_use_id=stamp["tool_use_id"], record_uuid=record["uuid"])


def write_request(request: dict, home=None) -> Path:
    folder = requests_dir(_home(home))
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = folder / (request["rid"] + ".json")
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, json.dumps(request, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    finally:
        os.close(fd)
    return path


def load_request(rid: str, *, home=None, now=None) -> dict:
    """The request the user is shown, rebuilt from the call it points at. The file supplies only the pointer (session,
    transcript, tool_use_id, record uuid). Everything shown and signed is computed again by derive_request from the
    client's own record of that call, and every derived field the file holds must equal it exactly. The age comes from
    the record's own timestamp. A hand-written or edited request file is refused."""
    if not isinstance(rid, str) or not HEX16.match(rid):
        raise Refusal("bad_input", "a request id is 16 hex characters")
    now = ss._clock(now)
    home = _home(home)
    stored = ss._strict_json(_read_regular(requests_dir(home) / (rid + ".json"), 65536, private=True))
    if not isinstance(stored, dict) or set(stored) != REQUEST_KEYS or stored.get("schema") != REQUEST_SCHEMA \
            or stored.get("rid") != rid:
        raise Refusal("bad_input", "request %s is malformed" % rid)
    if not isinstance(stored.get("session"), str) or not isinstance(stored.get("tool_use_id"), str) \
            or request_id(stored["session"], stored["tool_use_id"]) != rid:
        raise Refusal("bad_input", "request %s does not name the call it was made from" % rid)
    if already_granted(rid, home):
        raise Refusal("bad_input", "request %s was already granted once; the agent asks again for a new grant" % rid)
    payload ={"session_id": stored["session"], "transcript_path": stored.get("transcript"),
               "tool_use_id": stored["tool_use_id"]}
    session, agent, _main, own = resolve_transcripts(payload)
    if agent or str(own) != stored.get("transcript"):
        raise Refusal("bad_input", "request %s does not point at the main session's own transcript" % rid)
    record = call_record(own, stored["tool_use_id"])
    if record["uuid"] != stored.get("record_uuid"):
        raise Refusal("bad_input", "request %s does not match the session's own record of that call" % rid)
    try:
        asked = ss.parse_time(record.get("timestamp"))
    except ss._Deny:
        raise Refusal("bad_input", "the record of request %s has no time, so its age is unknown" % rid) from None
    age = now - asked
    if age < -ss.CLOCK_SKEW_SECONDS or age > REQUEST_MAX_AGE:
        raise Refusal("expired", "request %s is older than 24 hours; ask again" % rid)
    derived = derive_request(record, session, home, load_policy())
    derived.pop("argv")
    changed = [field for field in REQUEST_DERIVED if stored.get(field) != derived[field]]
    if changed:
        raise Refusal("bad_input", "request %s was changed after it was made (%s differ from the recorded command); "
                      "refused" % (rid, ", ".join(changed)))
    return dict(derived, schema=REQUEST_SCHEMA, rid=rid, at=ss.iso(asked), session=session, transcript=str(own),
                tool_use_id=stored["tool_use_id"], record_uuid=record["uuid"])


# ------------------------------------------------------------------ grant (body built here, signed by the enabler)

def signed_message(body: dict) -> bytes:
    return DOMAIN + ss.canonical(body)


def grant_body(request: dict, *, key_id: str, expiry: str, include_subagents: bool, drop_projects=(), drop_powers=(),
               now=None) -> dict:
    """The grant the user's choices produce. Choices can only remove what was requested, never add."""
    if expiry != UNTIL_REVOKED and expiry not in EXPIRY_CHOICES:
        raise Refusal("bad_input", "expiry is one of %s or the words '%s'" % (", ".join(EXPIRY_CHOICES), UNTIL_REVOKED))
    if include_subagents and not request.get("include_subagents"):
        raise Refusal("bad_input", "sub-agents were not requested, so they cannot be added")
    projects = [p for p in request["projects"] if p["repo"] not in set(drop_projects)]
    powers = [p for p in request["powers"] if p not in set(drop_powers)]
    if not projects or not powers:
        raise Refusal("bad_input", "nothing is left to grant")
    now = time.time() if now is None else now
    return {"schema": GRANT_SCHEMA, "purpose": GRANT_PURPOSE, "gid": secrets.token_hex(16), "rid": request["rid"],
            "key_id": key_id, "session": request["session"], "include_subagents": bool(include_subagents),
            "projects": projects, "powers": sorted(powers), "issued_at": ss.iso(now),
            "expires_at": None if expiry == UNTIL_REVOKED else ss.iso(now + EXPIRY_CHOICES[expiry]),
            "user_source": request.get("user_source") or "granted at terminal", "never_covered": list(NEVER_COVERED),
            "model_at_grant": request.get("model")}


def _local_time(iso_text) -> str:
    if not iso_text:
        return "until you revoke it"
    return time.strftime("%Y-%m-%d %H:%M local", time.localtime(ss.parse_time(iso_text)))


def terminal_text(request: dict, body: dict) -> str:
    """The exact text the user reads before typing the code."""
    lines = ["SUPERVISOR POWER: read this before typing the code.", "",
             "Session   %s  (main agent, model %s, qualified)" % (body["session"], request.get("model")),
             "Asked at  %s, by that session's own hook (not by what the agent typed)" % _local_time(request.get("at")),
             "Reason    %s" % json.dumps(request.get("reason", ""))[:1100] + "   (the agent's words, shown as data)"]
    if request.get("user_excerpt"):
        lines.append('Your words cited: "%s"' % request["user_excerpt"])
    lines += ["", "It may, in these projects only:"]
    for p in body["projects"]:
        lines.append("  %-22s %-40s on %s" % (p["name"], p["repo"], ", ".join(p["hosts"])))
    lines.append("these powers:")
    for power in body["powers"]:
        words, row = POWER_TEXT[power].split(), ""
        first = True
        for word in words:
            if len(row) + len(word) + 1 > 92:
                lines.append(("  %-8s %s" % (power, row)) if first else ("           %s" % row))
                row, first = word, False
            else:
                row = (row + " " + word).strip()
        lines.append(("  %-8s %s" % (power, row)) if first else ("           %s" % row))
    if "delete" in body["powers"]:
        lines.append("  Uncommitted and unpushed work in those worktrees can be lost.")
    lines.append("Sub-agents of this session: %s" % ("included" if body["include_subagents"] else "NOT included"))
    if body["expires_at"]:
        hours = round((ss.parse_time(body["expires_at"]) - ss.parse_time(body["issued_at"])) / 3600)
        lines.append("Until: %s (%d hours)" % (_local_time(body["expires_at"]), hours))
    else:
        lines.append("Until: you revoke it (you typed '%s')" % UNTIL_REVOKED)
    lines += ["Model rule: only while the session runs Sol, Opus, Fable or Astra. If it switches to",
              "Sonnet, Terra, Luna, Haiku or an unknown model, the power stops until it switches back.",
              "", "Never covered, whatever this grant says:"]
    lines += ["  - %s" % item for item in NEVER_COVERED]
    lines += ["Revoke at any time:  ah supervisor revoke %s     Status: ah supervisor status" % body["gid"], ""]
    return "\n".join(lines)


def already_granted(rid, home=None) -> bool:
    """Whether a verified grant (live, expired or revoked) was already made from this request: one call, one grant."""
    return any(g is not None and g.get("rid") == rid for g, _problem, _path in load_grants(_home(home)))


def write_grant(signed: dict, home=None) -> Path:
    if already_granted(signed.get("rid"), home):
        raise Refusal("bad_input", "request %s was already granted once; the agent asks again for a new grant"
                      % str(signed.get("rid"))[:16])
    folder = grants_dir(_home(home))
    for directory in (ss.policy_dir(_home(home)), folder):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = folder / (signed["gid"] + ".json")
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, json.dumps(signed, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    finally:
        os.close(fd)
    _audit(_home(home), {"event": "granted", "gid": signed["gid"], "rid": signed["rid"], "session": signed["session"],
                         "powers": signed["powers"], "projects": [p["repo"] for p in signed["projects"]],
                         "expires_at": signed["expires_at"]})
    return path


# ------------------------------------------------------------------ verification

def _audit(home, row: dict):
    row = dict(row, at=ss.iso(time.time()))
    path = audit_path(home)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, ss.canonical(row) + b"\n")
    finally:
        os.close(fd)


def revocation_state(home) -> dict:
    """The one reader of revocations: {"all": bool, "problem": str|None, "gids": set, "all_at": [times]}.

    Revocations live in their own append-only log, policy/supervisor/revocations.jsonl, which only `revoke` writes
    (checks never grow it) and which sits in the guarded policy tree. A missing log means nothing is revoked. A log
    that exists but cannot be read safely (not a regular private file of this user's, larger than REVOCATIONS_MAX, a
    malformed or torn row) means EVERY grant is revoked: a safety read never fails open. A revoke-all row carries its
    time and revokes only grants issued at or before it."""
    state = {"all": False, "problem": None, "gids": set(), "all_at": []}
    path = revocations_path(home)
    try:
        if ss._absent(path):
            return state
        raw = _read_regular(path, REVOCATIONS_MAX, private=True)
        if raw and not raw.endswith(b"\n"):
            raise Refusal("bad_input", "the revocation log ends in a torn row")
        for line in raw.split(b"\n")[:-1] if raw else []:
            row = json.loads(line.decode("utf-8"))
            if not isinstance(row, dict) or set(row) != {"target", "at"}:
                raise Refusal("bad_input", "the revocation log has a row of the wrong shape")
            at = ss.parse_time(row["at"])
            if row["target"] == "all":
                state["all_at"].append(at)
            elif isinstance(row["target"], str) and HEX32.match(row["target"]):
                state["gids"].add(row["target"])
            else:
                raise Refusal("bad_input", "the revocation log names an unknown target")
    except Refusal as refusal:
        state.update({"all": True, "problem": refusal.message})
    except (OSError, ValueError, UnicodeDecodeError, ss._Deny) as error:
        state.update({"all": True, "problem": "the revocation log cannot be read (%s)" % type(error).__name__})
    return state


def _is_revoked(grant, revoked) -> bool:
    if revoked["all"] or grant["gid"] in revoked["gids"]:
        return True
    if not revoked["all_at"]:
        return False
    try:
        issued = ss.parse_time(grant["issued_at"])
    except ss._Deny:
        return True
    return any(issued <= at for at in revoked["all_at"])


def _verify(grant, pins) -> None:
    if not isinstance(grant, dict) or set(grant) != GRANT_KEYS or grant.get("schema") != GRANT_SCHEMA \
            or grant.get("purpose") != GRANT_PURPOSE or not isinstance(grant.get("gid"), str) or not HEX32.match(grant["gid"]):
        raise Refusal("bad_signature", "a grant file has the wrong shape")
    public = pins.get(grant.get("key_id"))
    if public is None:
        raise Refusal("bad_signature", "a grant is signed by a key that is not pinned")
    ed25519, _serialization, invalid = ss._crypto()
    body = {k: v for k, v in grant.items() if k != "signature"}
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(ss.b64url_decode(grant["signature"]), signed_message(body))
    except (invalid, ValueError, ss._Deny):
        raise Refusal("bad_signature", "a grant's signature does not verify") from None
    if not isinstance(grant["projects"], list) or not isinstance(grant["powers"], list) \
            or any(p not in POWERS for p in grant["powers"]):
        raise Refusal("bad_signature", "a grant names an unknown power")


def load_grants(home) -> list:
    """[(grant or None, problem code or None, path)] for every grant file. Never raises."""
    out = []
    folder = grants_dir(home)
    try:
        if folder.is_symlink() or not folder.is_dir():
            return out
        paths = sorted(folder.glob("*.json"))[:500]
    except OSError:
        return out
    try:
        pins = ss._load_pins(home)
    except Exception:  # noqa: BLE001
        pins = {}
    for path in paths:
        try:
            grant = ss._strict_json(_read_regular(path, 65536, private=True))
            _verify(grant, pins)
            out.append((grant, None, path))
        except Exception:  # noqa: BLE001 - unreadable, unsafe or unsigned: never a grant
            out.append((None, "bad_signature", path))
    return out


def _grant_state(grant, now, revoked) -> str | None:
    if _is_revoked(grant, revoked):
        return "revoked"
    try:
        issued = ss.parse_time(grant["issued_at"])
        if issued > now + ss.CLOCK_SKEW_SECONDS:
            return "expired"
        if grant["expires_at"] is not None and now >= ss.parse_time(grant["expires_at"]):
            return "expired"
    except ss._Deny:
        return "expired"
    return None


def _norm_target_path(value, home) -> str:
    text = os.path.expanduser(str(value))
    if not os.path.isabs(text):
        raise Refusal("bad_input", "a delete target path must be absolute")
    return os.path.realpath(text)


GLOB = re.compile(r"[*?\[]")


def delete_guard_policy() -> dict:
    """The delete guard's own policy (command_guard.load_policy: built-in defaults plus the installed additive file).
    Supervisor deletes read the same lists the guard enforces, so the two cannot drift. Raises Refusal when it
    cannot be loaded."""
    try:
        import command_guard  # noqa: PLC0415
        policy = command_guard.load_policy()
    except Exception as error:  # noqa: BLE001
        raise Refusal("never_covered", "the delete guard's protected list cannot be read (%s); refused"
                      % type(error).__name__) from None
    for key in ("protected_log_roots", "guard_files", "protected_roots", "generic_homes", "protected_segment_names",
                "protected_file_names", "protected_file_suffixes", "keep_names", "keep_suffixes", "keep_segments"):
        if not isinstance(policy.get(key), list):
            raise Refusal("never_covered", "the delete guard's policy has no %s list; refused" % key)
    if not isinstance(policy.get("protected_work_wal_regex"), str):
        raise Refusal("never_covered", "the delete guard's policy has no WAL pattern; refused")
    return policy


def never_covered_roots(guard_policy) -> list:
    """Templates ({home}) of everything a supervisor delete never touches. These are the delete guard's Tier A log
    roots and its guard files, plus SUPERVISOR_EXTRA_ROOTS."""
    out = []
    for template in list(guard_policy["protected_log_roots"]) + list(guard_policy["guard_files"]) + list(SUPERVISOR_EXTRA_ROOTS):
        if isinstance(template, str) and template and template not in out:
            out.append(template)
    return out


def _homes_for(real: str, home: str, generic) -> list:
    """This user's home, plus the home a path names on another machine (/home/x, /Users/x, /root), so a target on
    t2-dev is checked against that host's harness roots too."""
    homes = [os.path.realpath(home)]
    parts = real.split("/")
    for pattern in generic:
        if not isinstance(pattern, str) or not pattern.startswith("/"):
            continue
        depth = len(pattern.strip("/").split("/"))
        if len(parts) > depth:
            prefix = "/".join(parts[:depth + 1])
            if fnmatch.fnmatchcase(prefix.lower(), pattern.lower()) and prefix not in homes:
                homes.append(prefix)
    return homes


def _covers(real: str, pattern: str) -> bool:
    """Whether deleting `real` would delete `pattern` or anything below it, or delete something inside it. Compared
    without case (macOS file systems), which can only refuse more."""
    real = real.lower()
    if not GLOB.search(pattern):
        for root in {os.path.normpath(pattern).lower(), os.path.realpath(pattern).lower()}:
            if _within(real, root) or _within(root, real):
                return True
        return False
    head, base = os.path.split(os.path.normpath(pattern))
    if GLOB.search(head):
        return True  # a glob above the last segment: refuse rather than guess
    for folder in {head.lower(), os.path.realpath(head).lower()}:
        if _within(folder, real):
            return True  # the target is the folder that holds the matches, or above it
        if _within(real, folder) and real != folder \
                and fnmatch.fnmatchcase(os.path.relpath(real, folder).split("/")[0], base.lower()):
            return True
    return False


def _lower_list(values) -> list:
    return [v.lower() for v in values if isinstance(v, str) and v]


def _wal_name(name: str, policy) -> bool:
    name = name.lower()
    return name in _lower_list(policy["protected_segment_names"]) or name in _lower_list(policy["protected_file_names"]) \
        or any(name.endswith(s) for s in _lower_list(policy["protected_file_suffixes"]))


def _kept_name(name: str, policy) -> bool:
    """A name the delete guard never lets go anywhere under a harness root: state, run kits, JSONL logs."""
    name = name.lower()
    return name in _lower_list(policy["keep_segments"]) or name in _lower_list(policy["keep_names"]) \
        or any(name.endswith(s) for s in _lower_list(policy["keep_suffixes"]))


def _harness_deletable(path: str, home_dir: str, policy) -> bool:
    """Inside a harness tree (the guard's Tier B roots) only two places are ever deletable: the guard's own scratch
    subtrees (allow_subtrees) and one task folder or deeper under ~/.agent-harness/work/<session>/<task>/..."""
    for template in policy.get("allow_subtrees") or []:
        if not isinstance(template, str):
            continue
        pattern = os.path.normpath(template.replace("{home}", home_dir)).lower()
        depth = len(pattern.strip("/").split("/"))
        parts = path.strip("/").split("/")
        if len(parts) >= depth and fnmatch.fnmatchcase("/" + "/".join(parts[:depth]), pattern):
            return True
    work = os.path.join(home_dir, ".agent-harness", "work").lower()
    return _within(path, work) and len(os.path.relpath(path, work).split("/")) >= 2


def _path_reason(form: str, home: str, policy) -> str | None:
    """Path rules for one spelling of the target (as written, or resolved)."""
    lowered = [s.lower() for s in form.split("/") if s]
    if any(_wal_name(s, policy) for s in lowered):
        return "%s is or is inside a WAL" % form
    for home_dir in _homes_for(form, home, policy["generic_homes"]):
        for template in never_covered_roots(policy):
            if _covers(form, template.replace("{home}", home_dir)):
                return "%s is or holds a protected log, WAL, transcript, session, policy or guard location" % form
        try:
            wal = re.compile(policy["protected_work_wal_regex"].replace("{home}", re.escape(home_dir)), re.I)
        except re.error:
            return "the delete guard's WAL pattern does not compile; refused"
        if wal.match(form):
            return "%s is or is inside a WAL in a work folder" % form
        for template in policy["protected_roots"]:
            root = os.path.normpath(str(template).replace("{home}", home_dir)).lower()
            low = form.lower()
            if _within(root, low):
                return "%s is or holds the harness tree %s" % (form, root)
            if not _within(low, root):
                continue
            below = os.path.relpath(low, root).split("/")
            if any(_kept_name(s, policy) for s in below):
                return "%s is state, a run kit or a JSONL log under a harness root" % form
            if not _harness_deletable(low, home_dir.lower(), policy):
                return "%s is inside the harness tree %s, where only scratch and work task folders are deletable" % (form, root)
            if os.path.realpath(home_dir) != os.path.realpath(home):
                return "%s is in another host's harness tree, whose contents cannot be checked from here" % form
    return None


def _contents_reason(real: str, home: str, policy) -> str | None:
    """For a local folder that exists: refuse when anything inside it is a WAL, or (under a harness root) state, a
    run kit or a JSONL log. A folder too large to read within WALK_MAX entries is refused."""
    if os.path.islink(real) or not os.path.isdir(real):
        return None
    local = os.path.realpath(home)
    harness = any(_within(real.lower(), os.path.normpath(str(t).replace("{home}", local)).lower())
                  for t in policy["protected_roots"])
    try:
        work_wal = re.compile(policy["protected_work_wal_regex"].replace("{home}", re.escape(local)), re.I)
    except re.error:
        return "the delete guard's WAL pattern does not compile; refused"
    seen = 0
    for folder, dirs, files in os.walk(real, followlinks=False):
        for name in dirs + files:
            seen += 1
            if seen > WALK_MAX:
                return "%s holds more than %d entries, too many to check; refused" % (real, WALK_MAX)
            full = os.path.join(folder, name)
            if _wal_name(name, policy) or (harness and _kept_name(name, policy)) or work_wal.match(full):
                return "%s holds %s, which is never deleted" % (real, full)
    return None


def protected_reason(target: str, home: str, guard_policy=None) -> str | None:
    """Why deleting `target` (absolute) would reach a log, WAL, transcript, session, state, policy or guard location,
    or None. The lists come from the delete guard's own policy. The path is checked both as written and resolved
    (macOS resolves /home, so a t2-dev path is only recognisable as written), and an existing local folder is read."""
    policy = guard_policy or delete_guard_policy()
    written = os.path.normpath(os.path.expanduser(target))
    real = os.path.realpath(written)
    for form in dict.fromkeys((written, real)):
        why = _path_reason(form, home, policy)
        if why:
            return why
    return _contents_reason(real, home, policy)


def never_covered_target(target, session, home, policy) -> str | None:
    """Why a delete target is never covered, or None. Checked whatever the grant says."""
    if not isinstance(target, dict):
        return "a delete needs a target"
    kind = target.get("kind")
    if kind not in DELETE_KINDS:
        return "kind %s is not one of %s" % (str(kind)[:20], ", ".join(DELETE_KINDS))
    for field in ("path", "ref"):
        blocked = _forbidden_name(target.get(field), policy)
        if blocked:
            return "%s is never covered" % blocked
    if kind in OWNED_KINDS and target.get("created_by_session") != session:
        return "a %s is covered only when this session or its agents created it" % kind
    if kind == "branch":
        ref = target.get("ref")
        if not isinstance(ref, str) or not ref.strip():
            return "a branch delete names its ref"
        short = ref.strip()
        for prefix in ("refs/heads/", "origin/", "refs/remotes/origin/"):
            if short.startswith(prefix):
                short = short[len(prefix):]
        if short in ("main", "master", "HEAD", "develop", "production", "release") or ref.startswith("refs/tags/"):
            return "the default, release or tag ref %s is never deleted under this grant" % short
        return None
    path = target.get("path")
    if not isinstance(path, str) or not path.strip() or "\x00" in path:
        return "a %s delete names its absolute path" % kind
    if not os.path.isabs(os.path.expanduser(path)):
        return "a %s delete names an absolute path" % kind
    real = _norm_target_path(path, home)
    if real in ("/", os.path.realpath(home)) or real.count("/") < 3:
        return "%s is too broad to delete" % real
    try:
        why = protected_reason(path, home)
    except Refusal as refusal:
        return refusal.message
    if why:
        return why
    try:
        import guard_files  # noqa: PLC0415
        if kind in ("build", "scratch") and guard_files.is_guard_file(os.path.basename(real)):
            return "%s is a guard file" % os.path.basename(real)
    except ImportError:
        pass
    return None


def _refuse(code, message) -> dict:
    return {"ok": False, "code": code if code in CODES else "bad_input", "message": str(message)[:500]}


def check(payload, power, project, *, host=None, target=None, now=None) -> dict:
    """Whether the caller of this hook payload holds `power` for `project` right now. Never raises.

    payload: the consuming hook's own stdin payload (never argv or the environment). power: 'merge' or 'delete'.
    project: 'owner/repo'. host: a host name from supervisor_policy.json (default: this host). target (delete only):
    {"kind", "path", "ref", "created_by_session"}. Returns {"ok": True, "gid", "session", "power", "project",
    "expires_at", "audit_id"} or {"ok": False, "code", "message"}; an audit row is written for every allow."""
    try:
        return _check(payload, power, project, host, target, now)
    except Refusal as refusal:
        return _refuse(refusal.code, refusal.message)
    except BaseException as error:  # noqa: BLE001 - a crash is never permission
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return _refuse("bad_input", "supervisor check error (%s); refused" % type(error).__name__)


def _check(payload, power, project, host, target, now) -> dict:
    if power not in POWERS:
        raise Refusal("bad_input", "power is merge or delete; nothing else can be granted")
    if not isinstance(project, str) or not REPO.match(project):
        raise Refusal("bad_input", "project is one owner/repo slug")
    try:
        now = ss._clock(now)
        home = _home(None)
    except ss._Deny as denied:
        raise Refusal("bad_input", str(denied)) from None
    policy = load_policy()
    if _forbidden_name(project, policy):
        raise Refusal("never_covered", "%s is never covered by supervisor power" % project)
    if ss.kill_switch_active(home):
        raise Refusal("disabled", "the kill switch ~/.agent-harness/policy/disabled is on")
    session, agent, _main, _own = resolve_transcripts(payload)
    host = host if host is not None else local_host(policy)
    if host is None or host not in policy["hosts"]:
        raise Refusal("wrong_host", "this host is not one supervisor power knows")
    revoked = revocation_state(home)
    grants = load_grants(home)
    mine = [g for g, problem, _p in grants if g is not None and g["session"] == session]
    if not mine:
        if any(problem == "bad_signature" for _g, problem, _p in grants):
            raise Refusal("bad_signature", "no grant for this session verifies")
        if any(g is not None for g, _problem, _p in grants):
            raise Refusal("wrong_session", "supervisor power is granted to another session, not this one")
        raise Refusal("no_grant", "no supervisor grant; ask with `ah supervisor request` and the user grants it")
    states = [(g, _grant_state(g, now, revoked)) for g in mine]
    live = [g for g, state in states if state is None]
    if not live:
        raise Refusal("revoked" if any(s == "revoked" for _g, s in states) else "expired",
                      "this session's supervisor grant is %s" % ("revoked" if any(s == "revoked" for _g, s in states)
                                                                 else "expired"))
    if agent and not any(g["include_subagents"] for g in live):
        raise Refusal("subagent_not_included", "the grant does not include this session's sub-agents")
    if agent:
        live = [g for g in live if g["include_subagents"]]
    for_project = [g for g in live if any(isinstance(p, dict) and str(p.get("repo", "")).lower() == project.lower()
                                          for p in g["projects"])]
    if not for_project:
        raise Refusal("wrong_project", "%s is not one of the granted projects" % project)
    on_host = [g for g in for_project if any(str(p.get("repo", "")).lower() == project.lower() and host in (p.get("hosts") or [])
                                             for p in g["projects"])]
    if not on_host:
        raise Refusal("wrong_host", "%s is not granted on %s" % (project, host))
    with_power = [g for g in on_host if power in g["powers"]]
    if not with_power:
        raise Refusal("power_not_granted", "%s is not granted for %s" % (power, project))
    if power == "delete":
        why = never_covered_target(target, session, home, policy)
        if why:
            raise Refusal("never_covered", why)
    model, family = observed_model(payload)
    grant = with_power[0]
    audit_id = secrets.token_hex(8)
    _audit(home, {"event": "allow", "audit_id": audit_id, "gid": grant["gid"], "session": session,
                  "agent": agent, "power": power, "project": project, "host": host, "model": model,
                  "target": {k: target.get(k) for k in ("kind", "path", "ref")} if isinstance(target, dict) else None})
    return {"ok": True, "gid": grant["gid"], "session": session, "power": power, "project": project,
            "expires_at": grant["expires_at"], "audit_id": audit_id, "model_family": family}


# ------------------------------------------------------------------ status and revoke

def status(session=None, *, home=None, now=None) -> dict:
    """Every grant and its state. Safe to print: no key material, only ids, projects, powers and times."""
    out = {"kill_switch": False, "grants": [], "unreadable": 0}
    try:
        home, now = _home(home), ss._clock(now)
        out["kill_switch"] = ss.kill_switch_active(home)
        revoked = revocation_state(home)
        if revoked["problem"]:
            out["revocation_log"] = "unreadable, so every grant counts as revoked: %s" % revoked["problem"]
        for grant, problem, path in load_grants(home):
            if grant is None:
                out["unreadable"] += 1
                continue
            if session and grant["session"] != session:
                continue
            state = "disabled" if out["kill_switch"] else (_grant_state(grant, now, revoked) or "live")
            out["grants"].append({"gid": grant["gid"], "session": grant["session"], "state": state,
                                  "powers": grant["powers"], "include_subagents": grant["include_subagents"],
                                  "projects": ["%s on %s" % (p.get("repo"), ",".join(p.get("hosts") or []))
                                               for p in grant["projects"] if isinstance(p, dict)],
                                  "expires_at": grant["expires_at"]})
    except Exception as error:  # noqa: BLE001
        out["error"] = type(error).__name__
    return out


def revoke(target: str, *, home=None, now=None) -> bool:
    """Revoke one grant (32-hex gid) or 'all' grants issued up to now. Appends one row to the revocation log (and an
    audit row for information); nothing removes a row. Anyone may revoke: it only takes power away."""
    if not (target == "all" or (isinstance(target, str) and HEX32.match(target))):
        return False
    try:
        home = _home(home)
        now = ss._clock(now)
        for directory in (ss.policy_dir(home), grants_dir(home)):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(revocations_path(home)), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, ss.canonical({"target": target, "at": ss.iso(now)}) + b"\n")
        finally:
            os.close(fd)
        _audit(home, {"event": "revoked", "gid": target})
        return True
    except Exception:  # noqa: BLE001
        return False


def session_start_context(payload, *, home=None, now=None) -> str:
    """The session-start line: a live grant this session holds, or one another session holds (a replacement session
    must ask again: a grant never moves to a new session id)."""
    session = payload.get("session_id") if isinstance(payload, dict) else None
    report = status(home=home, now=now)
    live = [g for g in report.get("grants", []) if g["state"] == "live"]
    if not live:
        return ""
    lines = []
    for g in live:
        until = g["expires_at"] or "until revoked"
        if g["session"] == session:
            lines.append("SUPERVISOR GRANT live for this session: %s, powers %s, projects %s, sub-agents %s, until %s. "
                         "Check `ah supervisor status`; the model rule (Sol, Opus, Fable or Astra) is re-checked at every use."
                         % (g["gid"][:12], ",".join(g["powers"]), "; ".join(g["projects"]),
                            "included" if g["include_subagents"] else "not included", until))
        else:
            lines.append("A supervisor grant (%s) is live for session %s, not this one; it gives this session nothing. Ask "
                         "with `ah supervisor request` if this session replaces it." % (g["gid"][:12], g["session"]))
    return "\n".join(lines[:5])


# ------------------------------------------------------------------ CLI (`ah supervisor ...`) and hook entry points

def _stamp_for(argv) -> dict | None:
    """The bound stamp main's hook wrote for exactly `ah supervisor ARGV`, consumed (ah_ops.claim_main)."""
    try:
        import ah_ops  # noqa: PLC0415
        ah_ops.claim_main([STAMP_SUB] + list(argv))
        stamp = ah_ops._PROOF.get("stamp")
        return stamp if isinstance(stamp, dict) else None
    except Exception:  # noqa: BLE001
        return None


def cli(argv, *, out=print, stamp=None) -> int:
    argv = [str(a) for a in argv]
    sub = argv[:1]
    if sub == ["request"]:
        proof = stamp if stamp is not None else _stamp_for(argv)
        try:
            request = build_request(argv[1:], proof)
            path = write_request(request)
        except Refusal as refusal:
            out(json.dumps({"ok": False, "code": refusal.code, "message": refusal.message}))
            return 3
        except ss._Deny as denied:
            out(json.dumps({"ok": False, "code": "bad_input", "message": str(denied)}))
            return 3
        out(json.dumps({"ok": True, "rid": request["rid"], "request": str(path), "model": request["model"],
                        "projects": [p["repo"] for p in request["projects"]], "powers": request["powers"],
                        "user_runs": "python3 ~/.agent-harness/bin/ah_enable_self_serve.py --grant-supervisor %s"
                                     % request["rid"],
                        "note": "a request grants nothing; the user reads the summary and types the code"}, indent=2))
        return 0
    if sub == ["status"]:
        session = argv[1] if len(argv) > 1 else None
        out(json.dumps(status(session), indent=2, sort_keys=True))
        return 0
    if sub == ["revoke"] and len(argv) == 2:
        done = revoke(argv[1])
        out(json.dumps({"ok": done, "revoked": argv[1] if done else None}))
        return 0 if done else 3
    out("usage: ah supervisor request --project owner/repo:host[,host] --power merge|delete --reason TEXT "
        "[--include-subagents] [--user-source SRC] | status [SESSION] | revoke GID|all")
    return 2


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["session-start"]:
        try:
            import safe_input  # noqa: PLC0415
            payload = safe_input.safe_json_loads(safe_input.read_stdin_bounded(1 << 20).decode("utf-8", "replace"))
            text = session_start_context(payload if isinstance(payload, dict) else {})
        except Exception:  # noqa: BLE001 - context only; never fails the session start
            text = ""
        if text:
            sys.stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart",
                                                                "additionalContext": text}}) + "\n")
        return 0
    return cli(args)


if __name__ == "__main__":
    sys.exit(main())
