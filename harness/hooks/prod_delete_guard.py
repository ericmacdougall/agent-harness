#!/usr/bin/env python3
"""PreToolUse hook: refuse destructive SQL aimed at a PRODUCTION database unless a recorded,
user-sourced grant covers it (goodqa#14908, ported from Hawkeye's hawkeye-prod-delete-guard.py).

Why: on 2026-09-12 an agent deleted rows from a live D1 database after announcing the intent in
chat, with no recorded approval. Hawkeye made that a hard gate on dev2; T2 and the Mac had no
equivalent. This port keeps Hawkeye's detection rules unchanged (including its H-1, H-1b, H-1c and
F6 fixes) and swaps Hawkeye's hawk_ask grant store for a harness grant file whose every entry
cites a real user turn or AskUserQuestion answer. Each grant's source is resolved again through
provenance.py whenever a matching command is checked.

Scope is deliberately narrow, per Eric's 2026-09-03 ruling against hooks that prompt on every
call. The guard looks only for a destructive verb (DELETE FROM, DROP TABLE/DATABASE/INDEX,
TRUNCATE) together with an identifiable production target:
  - wrangler d1 execute ... --remote;
  - a connection string whose own text names prod/production;
  - a recognised DB client (psql, mysql, mongosh, ...) whose -h/--host/-d/--dbname/--database/--db
    value names prod/production;
  - a tool that is production by construction (mcp__*__d1_database_query, mcp__*__hyperdrive_*).
Prose that merely mentions these words, such as a heredoc that writes up a bug, does not count
as a target. A heredoc that runs psql against a prod host still matches, because the text is
scanned as a whole. Hawkeye documented and accepted that over-refusal (H-2 retraction); a grant
lifts it.

Fail direction is asymmetric on purpose:
  - Before a match, any error allows. A parser bug must not block ordinary work.
  - After a match, any error denies. A broken checker is no reason to let a prod DELETE through.
  - A grant file that exists but cannot be read or parsed gives "ask". The grant store could not
    be consulted, so a human confirms; this is Hawkeye's F6 "unreachable" state.
    A missing grant file just means no grant, which is a deny.

Grants
  prod_delete_guard.py grant --user-source answer:<session>/<uuid> --target <literal> --wal <WAL>
                             [--ttl SECONDS] [--note TEXT]
  prod_delete_guard.py list
- --user-source must be a user:<session>/<uuid> or answer:<session>/<uuid> id (ah user-msg finds
  one) that provenance.py resolves to a human-authored turn no older than 24 hours.
  An inferred:, wal: or ticket: source is refused.
- --target is a literal of at least 3 characters, for example the host or the database name. A
  grant covers a command only when that literal appears in the command text. Nothing grants
  "all of production".
- The TTL defaults to 900 seconds; the most allowed is 3600. Expired grants are pruned whenever
  the file is written.
- The grant is recorded in the session WAL through wal_note.py, citing the user source.
Residual, disclosed: provenance proves the cited turn is a real human turn. It cannot prove the
turn approves this particular delete. The WAL record and the --target binding keep that claim
auditable and narrow.

Contract (https://code.claude.com/docs/en/hooks): stdin carries {"tool_name", "tool_input", ...}.
The output is hookSpecificOutput.permissionDecision "deny" or "ask", returned on exit 0. Register
this hook without onFailure=block, because it fails open before a match.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:  # python3 -I does not put the script's directory on sys.path
    sys.path.insert(0, str(HERE))

# ---- detection: verbatim from Hawkeye (see its comments for the H-1/H-1b/H-1c/F6 history) ----
DESTRUCTIVE = re.compile(r"\b(DELETE\s+FROM|DROP\s+(TABLE|DATABASE|INDEX)|TRUNCATE)\b", re.I)
PROD_TOKEN = re.compile(r"(?:^|[\s_.\-/=@\"'])(prod|production)(?:$|[\s_.\-/:?#\"'])", re.I)
D1_EXECUTE = re.compile(r"\bwrangler\b[^\n|;&]*\bd1\b[^\n|;&]*\bexecute\b", re.I)
REMOTE_FLAG = re.compile(r"--remote\b")
FILE_FLAG = re.compile(r"--file[=\s]+(\S+)")
DB_CLIENT = re.compile(
    r"\b(psql|pg_dump|pg_restore|dropdb|createdb|mysql|mysqldump|mysqladmin|"
    r"mariadb|mongo|mongosh|mongodump|mongorestore|redis-cli|sqlite3)\b", re.I)
DB_TARGET_FLAG = re.compile(r"(?:--dbname|--database|--db|--host|-h|-d)[=\s]+(\S+)", re.I)
CONN_STRING = re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://\S+", re.I)

# Every tool path a destructive statement can take. All listed keys are read together, so a
# harmless `command` next to a destructive `payload` is still judged on both.
TOOL_COMMAND_FIELDS = (
    (re.compile(r"^Bash$"), ("command",)),
    (re.compile(r"^mcp__hawkeye__run$"), ("payload", "command", "cmd", "script", "shell", "code")),
    (re.compile(r"(?i)d1_database_query$"), ("sql", "query")),
    (re.compile(r"(?i)^mcp__.*__(execute_sql|run_sql|query|sql)$"), ("sql", "query", "statement")),
)
TOOL_IS_PRODUCTION_BY_CONSTRUCTION = re.compile(r"(?i)^mcp__.*__(d1_database_query|hyperdrive_.*)$")
# The matcher install.py registers; tests pin that it covers every TOOL_COMMAND_FIELDS shape.
MATCHER = r"Bash|mcp__hawkeye__run|.*d1_database_query|mcp__.*__(execute_sql|run_sql|query|sql)|mcp__.*__hyperdrive_.*"

FILE_READ_LIMIT = 200000
GRANTS_NAME = "prod-delete-grants.json"
GRANT_SCOPE = "prod-db"
DEFAULT_TTL = 900
MAX_TTL = 3600
MAX_SOURCE_AGE = 86400
MIN_TARGET = 3
MAX_GRANTS = 64
GRANTS_MAX_BYTES = 256 * 1024
SOURCE_RE = re.compile(r"^(user|answer):([A-Za-z0-9._-]{1,120})/([0-9a-fA-F-]{8,64})$")


def sql_text_for(command: str) -> str:
    """The SQL this command will run, including a --file's contents (how the 2026-09-12 delete was issued)."""
    text = command
    m = FILE_FLAG.search(command)
    if m:
        path = m.group(1).strip("'\"")
        try:
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    text += "\n" + fh.read(FILE_READ_LIMIT)
        except OSError:
            text += "\n[unreadable --file]"
    return text


def targets_production(command: str) -> str:
    """The identifiable production TARGET this command names, or "". Never a bare 'prod appears somewhere' match."""
    if D1_EXECUTE.search(command) and REMOTE_FLAG.search(command):
        return "a --remote Cloudflare D1 database"
    m = CONN_STRING.search(command)
    if m and PROD_TOKEN.search(m.group(0)):
        return "a connection string naming a prod/production database"
    client = DB_CLIENT.search(command)
    if client:
        # Short forms (-h, -d) count only next to a recognised client: -d also means docker/tar/curl/diff.
        for m in DB_TARGET_FLAG.finditer(command):
            value = m.group(1).strip("'\"")
            if PROD_TOKEN.search(value):
                return "a %s target (%s) naming prod/production" % (client.group(1), value)
    return ""


def _as_text(value, _depth: int = 0) -> str:
    """Every string a tool_input value carries; lists flattened, objects serialised (a server may coerce them)."""
    if value is None or _depth > 8:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return "\n".join(_as_text(v, _depth + 1) for v in value)
    if isinstance(value, (int, float, bool)):
        return str(value)
    try:
        return json.dumps(value, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def command_text_for_event(ev: dict) -> str:
    tool = str(ev.get("tool_name") or "")
    ti = ev.get("tool_input")
    if not tool or not isinstance(ti, dict):
        return ""
    for pat, keys in TOOL_COMMAND_FIELDS:
        if pat.search(tool):
            return "\n".join(v for v in (_as_text(ti.get(k)) for k in keys) if v.strip())
    return ""


# ---- grants -------------------------------------------------------------------------------------
class Unreachable(Exception):
    """The grant store exists but cannot be consulted."""


def home_dir(home=None) -> Path:
    return Path(home) if home else Path.home()


def grants_path(home=None) -> Path:
    return home_dir(home) / ".agent-harness" / "state" / GRANTS_NAME


def load_grants(home=None) -> list:
    import safe_input  # noqa: PLC0415 - only a matched command reads the grant file
    path = grants_path(home)
    if not os.path.lexists(path):
        return []
    try:
        raw = safe_input.read_bounded(path, GRANTS_MAX_BYTES)
    except safe_input.InputRejected as exc:
        raise Unreachable("grant file %s could not be read (%s)" % (path, exc.code)) from exc
    try:
        data = safe_input.safe_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise Unreachable("grant file %s is not valid JSON" % path) from exc
    grants = data.get("grants") if isinstance(data, dict) else None
    if not isinstance(grants, list):
        raise Unreachable("grant file %s has no grants list" % path)
    return [g for g in grants if isinstance(g, dict)]


def resolve_user_source(source: str, home=None) -> dict:
    """{"text", "timestamp"} of the human turn or answer the source names; raises ValueError otherwise."""
    m = SOURCE_RE.match(source or "")
    if not m:
        raise ValueError("source must be user:<session>/<uuid> or answer:<session>/<uuid>")
    import provenance  # loaded lazily: the allow path never needs it
    kind, session, uid = m.groups()
    claude = home_dir(home) / ".claude"
    try:
        turn = (provenance.user_turn if kind == "user" else provenance.answer_turn)(session, uid, claude)
    except provenance.Problem as exc:
        raise ValueError("%s: %s" % (exc.code, exc)) from exc
    return turn


def _epoch(ts) -> float:
    if not isinstance(ts, str) or not ts:
        raise ValueError("source turn has no timestamp")
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def matching_grant(command: str, home=None, now=None, resolver=None):
    """(grant, "") for a live grant whose target appears in the command, else (None, why). Raises Unreachable."""
    now = time.time() if now is None else now
    resolver = resolver or resolve_user_source
    why = "no grant recorded"
    for grant in load_grants(home):
        target = grant.get("target")
        if grant.get("scope") != GRANT_SCOPE or not isinstance(target, str) or len(target) < MIN_TARGET:
            continue
        try:
            expires = float(grant.get("expires_at"))
        except (TypeError, ValueError):
            continue
        if expires <= now:
            why = "the matching grant has expired" if target in command else why
            continue
        if target not in command:
            continue
        try:
            resolver(str(grant.get("user_source") or ""), home)
        except Exception as exc:  # noqa: BLE001 - a grant whose source no longer resolves is no grant
            why = "a grant names this target but its user source no longer resolves (%s)" % str(exc)[:160]
            continue
        return grant, ""
    return None, why


def _write_grants(grants: list, home=None) -> None:
    path = grants_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".%d.tmp" % os.getpid())
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({"schema": 1, "grants": grants}, fh, indent=1, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def _record_wal(wal: Path, note: str, source: str) -> bool:
    helper = HERE / "wal_note.py"
    try:
        r = subprocess.run([sys.executable, str(helper), "--wal", str(wal), "--event", "decision", "--note", note,
                            "--source", source], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


def grant(user_source: str, target: str, wal, ttl: int = DEFAULT_TTL, note: str = "", home=None, now=None,
          resolver=None, record=None) -> dict:
    """Record one grant. Raises ValueError with a reason on refusal."""
    now = time.time() if now is None else now
    resolver = resolver or resolve_user_source
    record = record or _record_wal
    if not wal:
        raise ValueError("--wal is required: every grant is recorded in the session WAL")
    if not isinstance(target, str) or len(target.strip()) < MIN_TARGET or target != target.strip() or "\n" in target:
        raise ValueError("--target must be a literal of at least %d characters with no surrounding space" % MIN_TARGET)
    if not 1 <= int(ttl) <= MAX_TTL:
        raise ValueError("--ttl must be between 1 and %d seconds" % MAX_TTL)
    turn = resolver(user_source, home)
    age = now - _epoch(turn.get("timestamp"))
    if age > MAX_SOURCE_AGE:
        raise ValueError("the user source is older than %d hours; ask again" % (MAX_SOURCE_AGE // 3600))
    try:
        grants = load_grants(home)
    except Unreachable:
        raise ValueError("the existing grant file is unreadable; fix or move it before granting")
    grants = [g for g in grants if _live(g, now)]
    if len(grants) >= MAX_GRANTS:
        raise ValueError("too many live grants (%d)" % MAX_GRANTS)
    entry = {"scope": GRANT_SCOPE, "target": target, "user_source": user_source, "granted_at": int(now),
             "expires_at": int(now) + int(ttl), "note": (note or "")[:300]}
    if not record(Path(wal), "prod_delete_guard grant: scope=%s target=%s ttl=%ss note=%s" % (
            GRANT_SCOPE, target, int(ttl), entry["note"]), user_source):
        raise ValueError("the WAL record failed, so no grant was written")
    grants.append(entry)
    _write_grants(grants, home)
    return entry


def _live(g: dict, now: float) -> bool:
    try:
        return float(g.get("expires_at")) > now
    except (TypeError, ValueError):
        return False


# ---- hook ---------------------------------------------------------------------------------------
def decision(kind: str, reason: str) -> str:
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": kind,
                                              "permissionDecisionReason": reason}})


def evaluate(ev, home=None, now=None, resolver=None):
    """None to allow, else (kind, reason). The only entry point that can deny."""
    try:
        if not isinstance(ev, dict):
            return None
        command = command_text_for_event(ev)
        if not command.strip():
            return None
        sql = sql_text_for(command)
        match = DESTRUCTIVE.search(sql)
        if not match:
            return None
        target = targets_production(command)
        tool = str(ev.get("tool_name") or "")
        if not target and TOOL_IS_PRODUCTION_BY_CONSTRUCTION.search(tool):
            target = "a live cloud database, reached directly through %s" % tool
        if not target:
            return None
    except Exception:  # noqa: BLE001 - before a match every error allows
        return None
    # A destructive production statement is on the wire: every remaining failure denies.
    try:
        verb = match.group(0).upper()
        try:
            found, why = matching_grant(command, home, now, resolver)
        except Unreachable as exc:
            return ("ask", "This command runs %s against %s. A recorded, user-sourced grant is required before a "
                           "production delete, but the grant store could not be consulted (%s). Confirm only if the "
                           "user has approved this deletion." % (verb, target, exc))
        if found:
            return None
        return ("deny", "REFUSED: this command runs %s against %s, and no recorded grant covers it (%s).\n\n"
                        "Production deletes need a RECORDED approval, not one announced in chat. Ask the user with "
                        "AskUserQuestion, then record the answer:\n  python3 ~/.claude/hooks/prod_delete_guard.py "
                        "grant --user-source answer:<session>/<uuid> --target <host-or-db literal in the command> "
                        "--wal <session WAL>\n(ah user-msg finds the answer id.) Once granted, do the work; do not "
                        "refuse after approval." % (verb, target, why))
    except Exception as exc:  # noqa: BLE001
        return ("deny", "REFUSED: a destructive statement aimed at a production database was detected and the grant "
                        "check failed (%s). Failing closed is deliberate." % type(exc).__name__)


def hook_main() -> int:
    try:
        import safe_input  # noqa: PLC0415
        # Bounded: a payload over the stdin limit cannot be judged and allows, like any pre-match error.
        ev = safe_input.safe_json_loads(safe_input.read_stdin_bounded().decode("utf-8", "replace") or "{}")
    except Exception:  # noqa: BLE001 - before a match every error allows
        return 0
    result = evaluate(ev)
    if result:
        sys.stdout.write(decision(*result))
    return 0


def cli(argv) -> int:
    parser = argparse.ArgumentParser(prog="prod_delete_guard.py", description="Recorded grants for production deletes.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("grant", help="record a user-sourced grant for one production target")
    g.add_argument("--user-source", required=True)
    g.add_argument("--target", required=True)
    g.add_argument("--wal", required=True)
    g.add_argument("--ttl", type=int, default=DEFAULT_TTL)
    g.add_argument("--note", default="")
    sub.add_parser("list", help="print live grants")
    args = parser.parse_args(argv)
    if args.cmd == "list":
        try:
            now = time.time()
            print(json.dumps([g for g in load_grants() if _live(g, now)], indent=1, sort_keys=True))
        except Unreachable as exc:
            print(json.dumps({"status": "UNREADABLE", "problem": str(exc)}), file=sys.stderr)
            return 1
        return 0
    try:
        entry = grant(args.user_source, args.target, args.wal, args.ttl, args.note)
    except (ValueError, OSError) as exc:
        print(json.dumps({"status": "REFUSED", "problem": str(exc)[:400]}), file=sys.stderr)
        return 2
    print(json.dumps({"status": "GRANTED", **entry}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:]) if len(sys.argv) > 1 else hook_main())
