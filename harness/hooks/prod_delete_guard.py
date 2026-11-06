#!/usr/bin/env python3
"""PreToolUse hook: refuse destructive SQL aimed at a PRODUCTION database unless a recorded,
user-sourced, signed grant names that exact database (goodqa#14908, ported from Hawkeye's
hawkeye-prod-delete-guard.py).

Why: on 2026-09-12 an agent deleted rows from a live D1 database after announcing the intent in
chat, with no recorded approval. Hawkeye made that a hard gate on dev2; T2 and the Mac had none.
This port keeps Hawkeye's detection (its H-1, H-1b, H-1c and F6 fixes) and widens it for the
bypasses a native review found (2026-11-06, native-reviews/hk-wave1-07d89d59.md F3). It replaces
Hawkeye's hawk_ask grant store with a signed harness grant file.

What counts as destructive (after `/* ... */` comments and shell quote characters are removed, so
`DEL""ETE` and `DELETE/**/FROM` still match): DELETE FROM, DROP TABLE|DATABASE|INDEX|SCHEMA,
TRUNCATE, and UPDATE ... SET with no WHERE in the same statement.

What counts as a production TARGET (each yields the exact target value a grant must name):
  - wrangler d1 execute <db> ... --remote                  -> <db>
  - a connection string naming prod/production              -> its host or its database (one target,
                                                               either name covers it)
  - a DB client (psql, mysql, mongosh, ...) whose -h/--host/-d/--dbname/--database/--db value names
    prod (attached forms like -hprod-db too), or a positional argument naming prod -> that value
  - PGHOST= / PGDATABASE= / DATABASE_URL= / MYSQL_HOST= assignments in the command, or (when the
    command references or relies on them) the same variables in the hook's environment
  - ssh <prod-host> running a DB client or wrangler        -> the host
  - docker exec <prod-container> running a DB client        -> the container
  - mcp__*__d1_database_query / hyperdrive_* (production by construction) -> the database id field
The SQL is read from the command and, with a DB client in it, from --file / psql -f files (also -1f,
-Xf, --fi=), `< file`, `$(< file)`, `$(cat file)` inside -c/-e or a here-string, `cat file | client`, psql
`\i`/`\ir`/`\include`/`\include_relative`, mysql `source`/`\.`, and sqlite `.read`/`-init`. Relative paths
resolve against the event's cwd, and ~ is expanded. Files are opened as regular files only (a FIFO or device
cannot hang the hook). A prod-targeted command is denied when one of its SQL files cannot be judged at hook
time: missing, not a regular file, unreadable, over 200,000 bytes, more than 8 files, written by the same
command, or the command has any other step besides a pipeline (; && || & newline cd pushd), which could
change the file first. A client fed by a pipe from anything but cat/echo/printf, with no -c/-e/-f of its
own, is denied the same way. Commands over 64 KiB are split on whitespace; every prod-looking word after a
client is then a target. Scans are bounded (512 characters, 256 words after a client, 64 clients), and a
command too long to judge its database is denied when it carries a destructive statement.
Prose that merely mentions these words does not count; a heredoc that runs psql against a prod host
does (Hawkeye's accepted over-refusal, H-2). Out of scope, disclosed: SQL built at run time
(`base64 -d | psql`, variables holding the statement, scripts run by name), unnamed targets
(a default PGHOST that is not in the hook's environment, PGSERVICE), non-SQL deletes (API calls, rm on a
data directory), statements DESTRUCTIVE does not cover (MySQL multi-table `DELETE t FROM t`, mongosh
`deleteMany`/`drop`, redis-cli `FLUSHALL`/`FLUSHDB`/`DEL`), and `mcp__*__execute_sql`-style tools whose text
does not name prod.

Fail direction:
  - Before a match, any error allows. A parser bug must not block ordinary work.
  - After a match, any error denies, including an unreadable, corrupt or unsigned grant store.

Grants
  prod_delete_guard.py grant --user-source answer:<session>/<uuid> --target <exact host or db> --wal <WAL>
                             [--ttl SECONDS] [--note TEXT]
  prod_delete_guard.py list
- --user-source must be an answer:<session>/<uuid> id (an AskUserQuestion answer; ah user-msg finds
  it) that provenance.py resolves, from the pinned ~/.claude, at most 1 hour old. The user's own selected
  answer must name the target as a whole name ("Approve DELETE on <target>") and must not decline (no,
  not, keep, cancel, ...). The agent's question text never counts; typed user: turns are refused.
- --target must equal, case-folded, one of the target values the guard extracts from the command
  (for example `prod-db.example.com`, or `app_production`). It is never a substring match. SQL
  words, client names, bare prod/production and names starting with "-" are refused as targets. A
  connection string to a prod host is covered only by a grant on that host. A command with several
  prod targets needs a grant for each one.
- The TTL defaults to 900 seconds and cannot exceed 3600. The grant can be reused until it expires.
- Each grant is HMAC-signed with ~/.agent-harness/state/prod-delete.key (0600, created on first
  use). At check time the guard re-verifies the signature and the TTL and source-age bounds, and
  resolves the source again. command_guard refuses shell writes to the grant file and the key.
  The key is used only when it is a regular file, mode 0600, owned by the caller, with one link; it is
  opened without following a symlink, and the store is replaced through an O_EXCL|O_NOFOLLOW temp file.
  Residual, disclosed: a same-user process, or the Write and Edit tools (command_guard judges Bash only),
  can read or plant the key and so sign a grant, skipping only the WAL record; provenance proves
  the cited answer is real and names the target, not what the user believed the option meant. The WAL record
  and the exact-target binding keep the claim auditable and narrow.

Contract (https://code.claude.com/docs/en/hooks): stdin carries {"tool_name", "tool_input", "cwd", ...}.
The output is hookSpecificOutput.permissionDecision "deny", returned on exit 0. Register this hook
without onFailure=block, because it fails open before a match.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import stat
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:  # python3 -I does not put the script's directory on sys.path
    sys.path.insert(0, str(HERE))

# ---- detection ----------------------------------------------------------------------------------
DESTRUCTIVE = re.compile(
    r"\b(DELETE\s+FROM|DROP\s+(?:TABLE|DATABASE|INDEX|SCHEMA)|TRUNCATE)\b"
    r"|\bUPDATE\s+[\w.\"`\[\]]+\s+SET\b(?![^;]*\bWHERE\b)"
    r"|\bdropdb\b|\bmysqladmin\b[^\n|;&]{0,512}?\bdrop\b", re.I)
SQL_COMMENT = re.compile(r"/\*.*?\*/", re.S)
LINE_COMMENT = re.compile(r"--[^\n]*")
SHELL_ESCAPE = re.compile(r"\\(?:x20|x09|x0a|040|t|n)", re.I)
PROD_TOKEN = re.compile(r"(?:^|[\s_.\-/=@\"'])(prod|production)(?:$|[\s_.\-/:?#\"'])", re.I)
D1_EXECUTE = re.compile(r"\bwrangler\b[^\n|;&]{0,512}?\bd1\b\s+execute\s+"
                        r"(?:(?:--(?:env|config|persist-to|command|file)|-[ec])(?:=\S*|\s+(?:'[^']*'|\"[^\"]*\"|\S+))\s+"
                        r"|--?[\w-]+(?:=\S*)?\s+)*([^\s;|&-][^\s;|&]*)?", re.I)
REMOTE_FLAG = re.compile(r"--remote\b")
FILE_FLAG = re.compile(r"--file[=\s]+(\S+)")
DB_CLIENT = re.compile(
    r"\b(psql|pg_dump|pg_restore|dropdb|createdb|mysql|mysqldump|mysqladmin|"
    r"mariadb|mongo|mongosh|mongodump|mongorestore|redis-cli|sqlite3)\b", re.I)
DB_TARGET_FLAG = re.compile(r"(?:(?:--dbname|--database|--db|--host)[=\s]+|(?<![\w-])-[hd](?:\s+|(?=[^\s-])))(\S+)", re.I)
CLIENT_NAMES = {"psql", "pg_dump", "pg_restore", "dropdb", "createdb", "mysql", "mysqldump", "mysqladmin", "mariadb",
                "mongo", "mongosh", "mongodump", "mongorestore", "redis-cli", "sqlite3"}
# -f, grouped short flags ending in f (-1f, -Xf), and getopt_long prefixes of --file (--fi, --fil)
PSQL_FILE_FLAG = re.compile(r"\bpsql\b[^\n|;&]{0,512}?(?<![\w-])(?:-[A-Za-z0-9]*f|--fil?e?(?==))[=\s]*([^\s;|&]+)")
SQLITE_INIT = re.compile(r"\bsqlite3\b[^\n|;&]{0,512}?\s-init\s+([^\s;|&]+)")
REDIRECT_IN = re.compile(r"(?<![<\d])<\s*(?![<(])([^\s;|&<>]+)")
# cat counts as SQL input only inside a client's -c/-e or a here-string; a cat that pipes into a client is
# handled by the pipe check (N1: other cat calls are not SQL input)
SUBST_CAT = re.compile(r"(?:-[ce]|--command|--execute|<<<)\s*[\"']?\$\(\s*cat\s+([^\s)]+)")
PIPE_CLIENT = re.compile(r"^\s*(?:\w+=\S*\s+)*(?:\S*/)?(psql|mysql|mariadb|sqlite3|mongosh|mongo|redis-cli)\b", re.I)
SCRIPT_FLAG = re.compile(r"(?<![\w-])(?:-[ce]|--command|--execute|-f|--file|-cmd|-init|--eval)\b|(?<![<\d])<\s*\S")
SUBST_IN = re.compile(r"\$\(\s*<\s*([^\s)]+)\s*\)")
# psql \i \ir \include \include_relative, mysql \. and source, sqlite .read; a quoted argument is accepted
CLIENT_INCLUDE = re.compile(r"(?:\\(?:include_relative|include|ir|i|\.)|(?<![\w$])\.read)\s+['\"]?([^\s;'\"]+)")
MYSQL_SOURCE = re.compile(r"\b(?:mysql|mariadb)\b[^\n|&]{0,512}?\bsource\s+['\"]?([^\s;'\"]+)", re.I)
WRITE_DEST = (
    re.compile(r"(?<![<\d&])>{1,2}\|?\s*([^\s;|&<>]+)"),
    re.compile(r"\btee\s+(?:-[a-z]+\s+)*([^\s;|&<>]+)"),
    re.compile(r"\b(?:cp|mv|install|ln|rsync)\s+[^;|&\n]{0,4096}?\s([^\s;|&<>]+)[ \t]*(?=$|[;|&\n])"),
    re.compile(r"\bsed\s+(?:-[a-zA-Z]*i[a-zA-Z]*|--in-place)\b[^;|&\n]{0,4096}?\s([^\s;|&<>]+)[ \t]*(?=$|[;|&\n])"),
)
SHLEX_LIMIT = 64 * 1024
CONN_STRING = re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://\S+", re.I)
ENV_ASSIGN = re.compile(r"(?:^|[\s;&|(])(PGHOST|PGDATABASE|DATABASE_URL|MYSQL_HOST)=([^\s;&|]+)")
ENV_NAMES = ("PGHOST", "PGDATABASE", "DATABASE_URL", "MYSQL_HOST")
SSH_OPTS_WITH_VALUE = set("bcDEeFIiJLlmOopQRSWw")
DOCKER_EXEC_OPTS_WITH_VALUE = {"-e", "--env", "-u", "--user", "-w", "--workdir", "--env-file", "--detach-keys"}
CLIENT_OPTS_WITH_VALUE = {"-c", "-e", "-f", "-U", "-u", "-p", "-P", "--command", "--execute", "--file", "--user",
                          "--username", "--port", "-v", "--set", "--eval", "-o", "--output", "-h", "-d", "--host",
                          "--dbname", "-cmd", "-init"}
RESERVED_TARGETS = {"prod", "production", "delete", "drop", "truncate", "update", "table", "database", "schema",
                    "index", "from", "set", "where", "remote", "execute", "d1", "wrangler", "ssh", "docker", "exec"}

TOOL_COMMAND_FIELDS = (
    (re.compile(r"^Bash$"), ("command",)),
    (re.compile(r"^mcp__hawkeye__run$"), ("payload", "command", "cmd", "script", "shell", "code")),
    (re.compile(r"(?i)d1_database_query$"), ("sql", "query")),
    (re.compile(r"(?i)^mcp__.*__(execute_sql|run_sql|query|sql)$"), ("sql", "query", "statement")),
)
TOOL_IS_PRODUCTION_BY_CONSTRUCTION = re.compile(r"(?i)^mcp__.*__(d1_database_query|hyperdrive_.*)$")
TOOL_DB_FIELDS = ("database_id", "databaseId", "database", "database_name", "databaseName", "id")
# The matcher install.py registers; tests pin that it covers every TOOL_COMMAND_FIELDS shape.
MATCHER = r"Bash|mcp__hawkeye__run|.*d1_database_query|mcp__.*__(execute_sql|run_sql|query|sql)|mcp__.*__hyperdrive_.*"

FILE_READ_LIMIT = 200000
GRANTS_NAME = "prod-delete-grants.json"
KEY_NAME = "prod-delete.key"
LOCK_NAME = "prod-delete-grants.lock"
GRANT_SCOPE = "prod-db"
DEFAULT_TTL = 900
MAX_TTL = 3600
MAX_SOURCE_AGE = 3600
CLOCK_SLACK = 60
MIN_TARGET = 3
MAX_GRANTS = 64
GRANTS_MAX_BYTES = 256 * 1024
DECLINE = re.compile(r"\b(?:no|not|don'?t|never|keep|cancel|skip|stop|leave|hold|wait|later|instead)\b", re.I)
SOURCE_RE = re.compile(r"^(user|answer):([A-Za-z0-9._-]{1,120})/([0-9a-fA-F-]{8,64})$")


def destructive_match(sql: str):
    """The destructive statement in `sql`, after SQL comments, shell escapes and quote characters are removed. The
    text is also checked with `--` line comments removed, so a comment cannot split a verb (`DELETE--x\nFROM`)."""
    text = SHELL_ESCAPE.sub(lambda m: "\n" if m.group(0).lower() in ("\\n", "\\x0a") else " ",
                            SQL_COMMENT.sub(" ", sql))
    text = text.replace("\\", "").replace('"', "").replace("'", "")
    return DESTRUCTIVE.search(text) or DESTRUCTIVE.search(LINE_COMMENT.sub(" ", text))


def _resolve_path(raw: str, cwd) -> str:
    path = os.path.expanduser(raw.strip("'\""))
    if not os.path.isabs(path) and cwd:
        path = os.path.join(str(cwd), path)
    return path


def _read_sql_file(path: str):
    """The file's text, or None when it is missing, not a regular file (a FIFO cannot hang the hook) or unreadable:
    then it cannot be judged."""
    import safe_input  # noqa: PLC0415
    try:
        fd = safe_input.open_regular_file(path)
    except safe_input.InputRejected:
        return None
    try:
        with os.fdopen(fd, "rb") as fh:
            body = fh.read(FILE_READ_LIMIT + 1)
        if len(body) > FILE_READ_LIMIT:
            return None  # only part could be read: the rest is unjudged
        return body.decode("utf-8", "replace")
    except (OSError, ValueError):
        return None


def _written_paths(command: str, cwd=None) -> set:
    """Paths this command writes (>, >>, tee, cp/mv/install/ln/rsync destination, sed -i)."""
    out = set()
    for rx in WRITE_DEST:
        for m in rx.finditer(command):
            out.add(os.path.realpath(_resolve_path(m.group(1), cwd)))
    return out


def sql_text_for(command: str, cwd=None, unread=None) -> str:
    """The SQL this command will run: the text itself plus --file, psql -f and `< file` contents.
    Paths that could not be read are appended to `unread` when a list is given."""
    paths = [m.group(1) for m in FILE_FLAG.finditer(command)]
    paths += [m.group(1) for m in PSQL_FILE_FLAG.finditer(command)]
    piped = []
    if DB_CLIENT.search(command) or D1_EXECUTE.search(command):
        paths += [m.group(1) for m in REDIRECT_IN.finditer(command)]
        paths += [m.group(1) for m in SUBST_IN.finditer(command)]
        paths += [m.group(1) for m in SUBST_CAT.finditer(command)]
        paths += [m.group(1) for m in CLIENT_INCLUDE.finditer(command)]
        paths += [m.group(1) for m in MYSQL_SOURCE.finditer(command)]
        paths += [m.group(1) for m in SQLITE_INIT.finditer(command)]
        paths += _piped_inputs(command, piped)
    if unread is not None:
        unread.extend(piped)
    # File inputs are judged as they are now. Any other step in the same command (a write by any tool, a cd, a
    # download) could change them first, and no list of writers is complete: then they cannot be judged at all.
    if paths and _multi_step(command):
        if unread is not None:
            unread.extend("%s (the same command has other steps)" % p for p in paths[:8])
        return command
    written = _written_paths(command, cwd) if paths else set()
    text = command
    for raw in paths[:8]:
        resolved = _resolve_path(raw, cwd)
        # a file this same command writes is judged in its old state at hook time, so it cannot be judged at all
        body = None if os.path.realpath(resolved) in written else _read_sql_file(resolved)
        if body is None:
            if unread is not None:
                unread.append(raw)
            continue
        text += "\n" + body
    if unread is not None and len(paths) > 8:
        unread.extend(paths[8:])
    return text


def _multi_step(command: str) -> bool:
    """True when the command has more than one step besides a pipeline: ; && || & or a newline outside quotes,
    or a cd/pushd."""
    bare = re.sub(r"'[^']*'|\"[^\"]*\"", " ", command[:SHLEX_LIMIT])
    bare = re.sub(r"\d?[<>]&\d?-?", " ", bare)
    return bool(re.search(r"[;&\n]|(?:^|\s)(?:cd|pushd)(?:\s|$)", bare)) or len(command) > SHLEX_LIMIT


def _piped_inputs(command: str, unjudged: list) -> list:
    """Files fed by `cat file | client`. A client fed by any other producer (head, sed, curl, a script) with no
    -c/-e/-f of its own reads SQL the guard cannot see, so that stdin is listed in `unjudged`; echo and printf
    text is in the command itself."""
    paths = []
    segments = re.split(r"(?<!\|)\|(?!\|)", command[:SHLEX_LIMIT])
    for i in range(1, min(len(segments), 64)):
        seg = segments[i]
        if not PIPE_CLIENT.match(seg) or SCRIPT_FLAG.search(seg):
            continue
        bare = re.sub(r"'[^']*'|\"[^\"]*\"", " Q ", segments[i - 1])  # quoted text is data, not a separator
        producer = re.split(r"[;&\n]", bare)[-1].split()
        name = producer[0].rsplit("/", 1)[-1] if producer else ""
        if name == "cat":
            paths += [w for w in producer[1:] if not w.startswith("-")]
        elif name not in ("echo", "printf"):
            unjudged.append("stdin from %s" % (name or "a pipe"))
    return paths


def _words(command: str) -> list:
    """Shell words. shlex is quadratic in one long quoted token, so a command over SHLEX_LIMIT is split on
    whitespace instead: the hook must decide well inside its 30 s budget (R1)."""
    if len(command) > SHLEX_LIMIT:
        return command.split()
    try:
        return shlex.split(command, comments=False, posix=True)
    except ValueError:
        return command.split()


def _prod(value: str) -> bool:
    return bool(value) and bool(PROD_TOKEN.search(value))


def _conn_parts(conn: str) -> list:
    """Host and database name of a connection string."""
    m = re.match(r"^[a-z+]+://(?:[^@/]*@)?([^/:?#]+)(?::\d+)?(?:/([^?#\s'\"]*))?", conn, re.I)
    if not m:
        return []
    return [p for p in (m.group(1), (m.group(2) or "").strip("/")) if p]


AFTER_SCAN = 256  # words _after looks at; past it the result is TOO_MANY_OPTIONS
TOO_MANY_OPTIONS = "\0too-many-options"


def _after(words: list, index: int, opts_with_value) -> str:
    """The first non-option word after words[index], skipping options and their values. Bounded: after
    AFTER_SCAN option words it returns TOO_MANY_OPTIONS, and the caller fails closed."""
    i = index + 1
    while i < len(words):
        if i - index > AFTER_SCAN:
            return TOO_MANY_OPTIONS
        w = words[i]
        if w.startswith("-") and len(w) > 1:
            if w in opts_with_value:
                i += 2
                continue
            flag = w if w.startswith("--") else w[:2]
            if (flag in opts_with_value or (not w.startswith("--") and w[1:2] in opts_with_value)) and len(w) <= 2 \
                    and "=" not in w:
                i += 2
            else:
                i += 1
            continue
        return w
    return ""


def targets_production(command: str, env=None):
    """(description, [target groups]) of the production targets this command names, or ("", []).
    Each group is a tuple of alternative names for one target (a connection string's host and its
    database); a grant naming any one of them covers that target."""
    env = os.environ if env is None else env
    found, why = [], []

    def add(desc, values):
        why.append(desc)
        group = tuple(v for v in values if v)
        if group:
            found.append(group)

    for m in D1_EXECUTE.finditer(command):
        if REMOTE_FLAG.search(command):
            add("a --remote Cloudflare D1 database", [m.group(1) or ""])
    for m in CONN_STRING.finditer(command):
        conn = m.group(0).rstrip("'\"")
        if _prod(conn):
            parts = _conn_parts(conn)
            if parts and _prod(parts[0]):
                parts = parts[:1]  # a database-only grant ("app") never covers a prod host
            add("a connection string naming a prod/production database", parts)
    assigned = {}
    for m in ENV_ASSIGN.finditer(command):
        assigned[m.group(1)] = m.group(2).strip("'\"")
    client = DB_CLIENT.search(command)
    words = _words(command)
    if client:
        for m in DB_TARGET_FLAG.finditer(command):
            value = m.group(1).strip("'\"")
            if _prod(value):
                add("a %s target (%s) naming prod/production" % (client.group(1), value), [value])
        clients = 0
        for i, w in enumerate(words):
            if w[w.rfind("/") + 1:].casefold() in CLIENT_NAMES:  # a set lookup: commands can hold 600k words
                clients += 1
                pos = _after(words, i, CLIENT_OPTS_WITH_VALUE) if clients <= 64 else TOO_MANY_OPTIONS
                if pos == TOO_MANY_OPTIONS:
                    # cannot tell which database a client uses: a destructive match then denies (no exact target)
                    add("a %s command too long to judge its database" % w, [])
                    break
                if pos and not pos.startswith("-") and _prod(pos) and "://" not in pos and " " not in pos:
                    add("a %s positional database (%s) naming prod/production" % (w, pos), [pos])
        if len(command) > SHLEX_LIMIT:
            for w in words:
                if "prod" in w.casefold():
                    v = w.strip("'\"();,")
                    if v and _prod(v) and "://" not in v:
                        add("a word naming prod/production in an oversized %s command (%s)" % (client.group(1), v),
                            [v])
        for name in ENV_NAMES:
            referenced = ("$" + name) in command or ("${" + name) in command
            # The hook's own environment counts when the command references the variable, or when psql would
            # fall back to it because the command names no host (PGHOST) or database (PGDATABASE) itself.
            implicit = ((name == "PGHOST" and not re.search(r"--host|(?<![\w-])-h", command))
                        or (name == "PGDATABASE" and not re.search(r"--dbname|(?<![\w-])-d", command)))
            value = assigned.get(name) or (env.get(name) if (referenced or implicit) else None)
            if value and _prod(value):
                parts = _conn_parts(value) if "://" in value else [value]
                add("%s names prod/production (%s)" % (name, value), parts)
    for i, w in enumerate(words):
        base = w[w.rfind("/") + 1:]
        if base == "ssh":
            host = _after(words, i, {"-" + c for c in SSH_OPTS_WITH_VALUE})
            rest = " ".join(words[i + 1:])
            if host and _prod(host) and (DB_CLIENT.search(rest) or "wrangler" in rest):
                add("ssh to a prod host (%s) running a database client" % host, [host.split("@")[-1]])
        if base == "docker" and i + 1 < len(words) and words[i + 1] == "exec":
            box = _after(words, i + 1, DOCKER_EXEC_OPTS_WITH_VALUE)
            rest = " ".join(words[i + 2:])
            if box and _prod(box) and DB_CLIENT.search(rest):
                add("docker exec into a prod container (%s) running a database client" % box, [box])
    if not why:
        return "", []
    seen, groups = set(), []
    for g in found:
        k = tuple(v.casefold() for v in g)
        if k not in seen:
            seen.add(k)
            groups.append(g)
    return "; ".join(dict.fromkeys(why)), groups


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
class StoreBroken(Exception):
    """The grant store exists but cannot be trusted; a matched command is denied."""


def home_dir(home=None) -> Path:
    return Path(home) if home else Path.home()


def state_dir(home=None) -> Path:
    return home_dir(home) / ".agent-harness" / "state"


def grants_path(home=None) -> Path:
    return state_dir(home) / GRANTS_NAME


def key_path(home=None) -> Path:
    return state_dir(home) / KEY_NAME


def _read_key(home=None, create=False):
    import safe_input  # noqa: PLC0415
    path = key_path(home)
    if create and not os.path.lexists(path):
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(secrets.token_bytes(32))
        except FileExistsError:
            pass
    if not os.path.lexists(path):
        return None
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600 or st.st_uid != os.getuid() \
                or st.st_nlink != 1:
            raise StoreBroken("grant key is not a private regular file (a symlink, a link, another owner or "
                              "mode %o); only `grant` creates it" % stat.S_IMODE(st.st_mode))
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as fh:
            key = fh.read(257)
    except OSError as exc:
        raise StoreBroken("grant key unreadable (%s)" % type(exc).__name__) from exc
    if len(key) > 256:
        raise StoreBroken("grant key is too long")
    if len(key) < 32:
        raise StoreBroken("grant key is too short")
    return key


def _mac(key: bytes, entry: dict) -> str:
    body = json.dumps({k: v for k, v in entry.items() if k != "mac"}, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def load_grants(home=None) -> list:
    """Every grant in the store; [] when there is no store. Raises StoreBroken on anything untrustworthy."""
    import safe_input  # noqa: PLC0415 - only a matched command reads the grant file
    path = grants_path(home)
    if not os.path.lexists(path):
        return []
    try:
        raw = safe_input.read_bounded(path, GRANTS_MAX_BYTES)
    except safe_input.InputRejected as exc:
        raise StoreBroken("grant file %s could not be read (%s)" % (path, exc.code)) from exc
    try:
        data = safe_input.safe_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise StoreBroken("grant file %s is not valid JSON" % path) from exc
    grants = data.get("grants") if isinstance(data, dict) else None
    if not isinstance(grants, list) or not all(isinstance(g, dict) for g in grants):
        raise StoreBroken("grant file %s has no valid grants list" % path)
    return grants


def resolve_user_source(source: str, home=None) -> dict:
    """{"text", "timestamp"} of the human turn or answer the source names, read from the pinned
    <home>/.claude (never CLAUDE_CONFIG_DIR); raises ValueError otherwise."""
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
    return dict(turn, kind=kind)


def names_target(turn: dict, target: str) -> bool:
    """The user's own selected answer names the exact target as a whole name (not inside a host, port or path),
    and does not decline. The agent's question text never counts: it is not the user's words."""
    said = str(turn.get("text") or "")
    if DECLINE.search(said):
        return False
    return bool(re.search(r"(?<![\w.:/@-])%s(?![\w-]|[.:/@]\w)" % re.escape(target.casefold()), said.casefold()))


def _epoch(ts) -> float:
    if not isinstance(ts, str) or not ts:
        raise ValueError("source turn has no timestamp")
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def valid_target(target) -> str:
    """'' when the grant target is acceptable, else why not."""
    if not isinstance(target, str) or len(target) < MIN_TARGET or target != target.strip():
        return "--target must be at least %d characters with no surrounding space" % MIN_TARGET
    if target.startswith("-") or any(ch.isspace() for ch in target) or any(ch in target for ch in "*?[]$`;|&<>'\"#"):
        return "--target must be one host or database name, with no spaces, quotes or wildcards"
    if target.casefold() in RESERVED_TARGETS or DB_CLIENT.fullmatch(target):
        return "--target %r is a keyword, a client name or bare prod; name the exact host or database" % target
    return ""


def _grant_ok(grant: dict, key, now: float):
    """'' when the stored grant is signed and within its bounds, else why not."""
    try:
        granted, expires, source_ts = (float(grant.get(k)) for k in ("granted_at", "expires_at", "source_ts"))
    except (TypeError, ValueError):
        return "a grant has missing or non-numeric times"
    if key is None or not hmac.compare_digest(_mac(key, grant), str(grant.get("mac", ""))):
        return "a grant's signature does not verify"
    if grant.get("scope") != GRANT_SCOPE or valid_target(grant.get("target")):
        return "a grant has the wrong scope or an invalid target"
    if expires <= now:
        return "the matching grant has expired"
    if granted > now + CLOCK_SLACK or expires - granted > MAX_TTL or granted - source_ts > MAX_SOURCE_AGE \
            or source_ts > granted + CLOCK_SLACK:
        return "a grant is outside the TTL or source-age bounds"
    return ""


def matching_grants(targets: list, home=None, now=None, resolver=None):
    """({target group: grant} for each covered target, why-not for the first uncovered one). Each entry
    of `targets` is a group of alternative names (or one name). Raises StoreBroken."""
    now = time.time() if now is None else now
    resolver = resolver or resolve_user_source
    grants = load_grants(home)
    key = _read_key(home) if grants else None
    covered, why = {}, "no grant recorded"
    for target in targets:
        names = {n.casefold() for n in ((target,) if isinstance(target, str) else target)}
        for grant in grants:
            if str(grant.get("target", "")).casefold() not in names:
                continue
            problem = _grant_ok(grant, key, now)
            if problem:
                why = problem
                continue
            try:
                turn = resolver(str(grant.get("user_source") or ""), home)
                if abs(_epoch(turn.get("timestamp")) - float(grant["source_ts"])) > 1:
                    raise ValueError("source timestamp differs from the one granted")
            except Exception as exc:  # noqa: BLE001 - a grant whose source no longer resolves is no grant
                why = "a grant names %s but its user source no longer resolves (%s)" % (grant.get("target"), str(exc)[:160])
                continue
            covered[target] = grant
            break
        else:
            if target not in covered:
                return covered, "%s: %s" % ("/".join((target,) if isinstance(target, str) else target), why)
    return covered, ""


def _write_grants(grants: list, home=None) -> None:
    path = grants_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".%d.%s.tmp" % (os.getpid(), secrets.token_hex(4)))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({"schema": 2, "grants": grants}, fh, indent=1, sort_keys=True)
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
    """Record one signed grant. Raises ValueError with a reason on refusal."""
    import fcntl  # noqa: PLC0415
    now = time.time() if now is None else now
    resolver = resolver or resolve_user_source
    record = record or _record_wal
    if not wal:
        raise ValueError("--wal is required: every grant is recorded in the session WAL")
    problem = valid_target(target)
    if problem:
        raise ValueError(problem)
    if not 1 <= int(ttl) <= MAX_TTL:
        raise ValueError("--ttl must be between 1 and %d seconds" % MAX_TTL)
    if not str(user_source or "").startswith("answer:"):
        raise ValueError("--user-source must be an AskUserQuestion answer (answer:<session>/<uuid>): a typed turn "
                         "cannot be told apart from a refusal")
    turn = resolver(user_source, home)
    if not names_target(turn, target):
        raise ValueError("the cited answer does not name %s (or it declines): ask with AskUserQuestion and an option "
                         "label naming the exact target, such as 'Approve DELETE on %s', then cite that answer"
                         % (target, target))
    source_ts = _epoch(turn.get("timestamp"))
    if now - source_ts > MAX_SOURCE_AGE or source_ts > now + CLOCK_SLACK:
        raise ValueError("the user source is older than %d hours (or in the future); ask again" % (MAX_SOURCE_AGE // 3600))
    sd = state_dir(home)
    sd.mkdir(parents=True, exist_ok=True)
    lock = os.open(str(sd / LOCK_NAME), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            grants = load_grants(home)
            key = _read_key(home, create=True)
        except StoreBroken as exc:
            raise ValueError("the grant store is unreadable (%s); fix or move it before granting" % exc)
        grants = [g for g in grants if not _grant_ok(g, key, now)]  # drop expired and unsigned entries
        if len(grants) >= MAX_GRANTS:
            raise ValueError("too many live grants (%d)" % MAX_GRANTS)
        entry = {"scope": GRANT_SCOPE, "target": target, "user_source": user_source, "source_ts": source_ts,
                 "granted_at": int(now), "expires_at": int(now) + int(ttl), "note": (note or "")[:300],
                 "nonce": secrets.token_hex(8)}
        entry["mac"] = _mac(key, entry)
        if not record(Path(wal), "prod_delete_guard grant: scope=%s target=%s ttl=%ss note=%s" % (
                GRANT_SCOPE, target, int(ttl), entry["note"]), user_source):
            raise ValueError("the WAL record failed, so no grant was written")
        grants.append(entry)
        _write_grants(grants, home)
    finally:
        os.close(lock)
    return entry


# ---- hook ---------------------------------------------------------------------------------------
def decision(kind: str, reason: str) -> str:
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": kind,
                                              "permissionDecisionReason": reason}})


def evaluate(ev, home=None, now=None, resolver=None, env=None):
    """None to allow, else ("deny", reason). The only entry point that can deny."""
    try:
        if not isinstance(ev, dict):
            return None
        command = command_text_for_event(ev)
        if not command.strip():
            return None
        unread = []
        sql = sql_text_for(command, ev.get("cwd"), unread)
        match = destructive_match(sql)
        if not match and not unread:
            return None
        target, values = targets_production(command, env)
        tool = str(ev.get("tool_name") or "")
        if not target and TOOL_IS_PRODUCTION_BY_CONSTRUCTION.search(tool):
            ti = ev.get("tool_input") or {}
            target = "a live cloud database, reached directly through %s" % tool
            values = [(str(ti.get(k)),) for k in TOOL_DB_FIELDS if isinstance(ti.get(k), (str, int)) and str(ti.get(k))][:1]
        if not target:
            return None
    except Exception:  # noqa: BLE001 - before a match every error allows
        return None
    # A destructive production statement is on the wire: every remaining failure denies.
    try:
        if not match:
            return ("deny", "REFUSED: this command runs SQL from %s against %s, and the guard cannot read that file "
                            "(missing at hook time, or unreadable), so it cannot tell whether it deletes data. Write "
                            "the file in an earlier command, then run it." % (", ".join(unread[:3]), target))
        verb = " ".join(match.group(0).upper().split())[:40]
        if not values:
            return ("deny", "REFUSED: this command runs %s against %s, and the guard cannot extract an exact target "
                            "name, so no grant can cover it. Name the host or database explicitly." % (verb, target))
        try:
            covered, why = matching_grants(values, home, now, resolver)
        except StoreBroken as exc:
            return ("deny", "REFUSED: this command runs %s against %s, and the grant store cannot be trusted (%s). "
                            "Failing closed." % (verb, target, exc))
        if not why:
            return None
        return ("deny", "REFUSED: this command runs %s against %s (targets: %s), and no recorded grant covers it "
                        "(%s).\n\nProduction deletes need a RECORDED approval, not one announced in chat. Ask the user "
                        "with AskUserQuestion, then record the answer for each exact target:\n  python3 "
                        "~/.claude/hooks/prod_delete_guard.py grant --user-source answer:<session>/<uuid> --target "
                        "<exact target> --wal <session WAL>\n(ah user-msg finds the answer id.) Once granted, do the "
                        "work; do not refuse after approval." % (verb, target, ", ".join("/".join(g) for g in values), why))
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
    g = sub.add_parser("grant", help="record a user-sourced grant for one exact production target")
    g.add_argument("--user-source", required=True)
    g.add_argument("--target", required=True)
    g.add_argument("--wal", required=True)
    g.add_argument("--ttl", type=int, default=DEFAULT_TTL)
    g.add_argument("--note", default="")
    sub.add_parser("list", help="print live, signed grants")
    args = parser.parse_args(argv)
    if args.cmd == "list":
        try:
            now = time.time()
            grants = load_grants()
            key = _read_key() if grants else None
            print(json.dumps([g for g in grants if not _grant_ok(g, key, now)], indent=1, sort_keys=True))
        except StoreBroken as exc:
            print(json.dumps({"status": "UNREADABLE", "problem": str(exc)}), file=sys.stderr)
            return 1
        return 0
    try:
        entry = grant(args.user_source, args.target, args.wal, args.ttl, args.note)
    except (ValueError, OSError) as exc:
        print(json.dumps({"status": "REFUSED", "problem": str(exc)[:400]}), file=sys.stderr)
        return 2
    print(json.dumps({"status": "GRANTED", **{k: v for k, v in entry.items() if k != "mac"}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:]) if len(sys.argv) > 1 else hook_main())
