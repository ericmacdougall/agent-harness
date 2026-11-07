#!/usr/bin/env python3
r"""PreToolUse hook: refuse destructive SQL aimed at a PRODUCTION database unless a recorded,
user-sourced, signed grant names that exact database (goodqa#14908, ported from Hawkeye's
hawkeye-prod-delete-guard.py).

Why: on 2026-09-12 an agent deleted rows from a live D1 database after announcing the intent in
chat, with no recorded approval. Hawkeye made that a hard gate on dev2; T2 and the Mac had none.
This port keeps Hawkeye's detection (its H-1, H-1b, H-1c and F6 fixes) and widens it for the
bypasses a native review found (2026-11-06, native-reviews/hk-wave1-07d89d59.md F3). It replaces
Hawkeye's hawk_ask grant store with a signed harness grant file.

What counts as destructive (after `/* ... */` comments and shell quote characters are removed, so
`DEL""ETE` and `DELETE/**/FROM` still match): DELETE FROM,
DROP TABLE|DATABASE|INDEX|SCHEMA|VIEW|FUNCTION|PROCEDURE|TRIGGER|ROLE|USER, TRUNCATE, and UPDATE ... SET with no
top-level WHERE in the same statement. A bounded lexer masks quoted text and comments, supports ONLY and an alias,
and treats an UPDATE ... SET it cannot parse (or an unterminated quote or comment) as unfiltered. MySQL/MariaDB
executable comments (/*! ... */, /*M! ... */) are judged as SQL (goodqa#15036).

What counts as a production TARGET (each yields the exact target value a grant must name):
  - wrangler d1 execute <db> ... --remote                  -> <db>
  - a connection string naming prod/production              -> its host or its database (one target,
                                                               either name covers it)
  - a DB client (psql, mysql, mongosh, ...) whose -h/--host/-d/--dbname/--database/--db value names
    prod (attached forms like -hprod-db too), or a positional argument naming prod -> that value
  - PGHOST= / PGDATABASE= / DATABASE_URL= / MYSQL_HOST= assignments in the command, or (when the
    command references or relies on them) the same variables in the hook's environment
  - ssh <prod-host> running a DB client or wrangler        -> the host; also a prod -o HostName, or a prod
    HostName that ~/.ssh/config (or -F file, with Include, Match and %h) could give the alias -> that name.
    The config is read over-approximately (every block that could apply); /etc/ssh/ssh_config is not read
  - docker exec <prod-container> running a DB client        -> the container
  - mcp__*__d1_database_query / hyperdrive_* (production by construction) -> the database id field
The SQL is read from the command and, with a DB client in it, from --file / psql -f files (also -1f,
-Xf, --fi=), `< file`, `$(< file)`, every `cat` argument anywhere in the command (a pipe into ssh, docker
exec, sudo or env, `$(cat ...)`, backticks), psql
`\i`/`\ir`/`\include`/`\include_relative`, mysql `source`/`\.`, and sqlite `.read`/`-init`. Includes inside those
files are followed too: \ir/\include_relative resolve against the including file, the others against the event's
cwd; ~ is expanded. Files are opened as regular files only (a FIFO or device cannot hang the hook). A prod-targeted
command is denied when its SQL file closure cannot be judged at hook time: a file is missing, not a regular file,
unreadable, or over 200,000 bytes; the closure has more than 8 files, 200,000 bytes, depth 8, 64 expansions, or a
cycle; a file is written by the same
command, or the command has any other step besides a plain pipeline (; && || & newline cd pushd, xargs,
<( >(, or a $(...)/backtick substitution that is not a cat or `< file` read), which could change the file
first. A client fed by a pipe from anything but cat/echo/printf is denied the same way unless its own flag
replaces stdin (psql -c/-f, mysql -e, mongosh --eval/--file) or a `<` redirect does; so is a $(...) or
backtick substitution after the client that is not a cat or `< file` read. Because every cat counts, a
read-only prod command that also cats a file it writes or a missing file is denied (split the command). Commands over 64 KiB are split on whitespace; every prod-looking word after a
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
  nope, not, keep, reject, untouched, ... outside the target name). The agent's question text never
  counts; typed user: turns are refused.
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
    r"\b(DELETE\s+FROM|DROP\s+(?:TABLE|DATABASE|INDEX|SCHEMA|VIEW|FUNCTION|PROCEDURE|TRIGGER|ROLE|USER)|TRUNCATE)\b"
    r"|\bdropdb\b|\bmysqladmin\b[^\n|;&]{0,512}?\bdrop\b", re.I)
UPDATE_SCOPE_LIMIT = 256  # UPDATE keywords judged per statement (each SET/WHERE walks the open ones)
UPDATE_WORD = re.compile(r"\bUPDATE\b", re.I)
SET_WORD = re.compile(r"\bSET\b", re.I)
# One linear pass per dialect reading finds these events; see _unfiltered_update.
UPDATE_EVENTS = re.compile(r"\b(UPDATE|SET|WHERE)\b|[();]", re.I)
NOT_AN_UPDATE = re.compile(r"\b(?:DO|ON|FOR|KEY)\s*$", re.I)  # ON CONFLICT DO UPDATE, ON UPDATE, FOR UPDATE, KEY UPDATE
EXEC_HEAD = re.compile(r"(?:!|M!)\d{0,6}", re.I)
DOLLAR_QUOTE = re.compile(r"\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$")
HASH_COMMENT = re.compile(r"#[^\n]*")

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
# Every `cat` argument in a command that has a DB client is SQL input, wherever the cat sits: piped into ssh,
# docker exec, sudo or env, inside $(...) or backticks, after --command=. This is ca56501's rule; r4 (N1) read cat
# in only two positions and let `cat f.sql | ssh prod-db psql` through (r4 review H1). The cost is N1: a read-only
# prod query that also cats a file it writes, or a missing file, is denied (disclosed).
CAT_ARGS = re.compile(r"(?:^|[\s;&|(`\"'=])cat\s+((?:[^\s|;&<>()`\"']+[ \t]*)+)")
# a substitution whose command is not `cat` or `< file`: its output (or side effects) cannot be judged
OTHER_SUBST = re.compile(r"\$\((?!\()\s*([^\s)]*)|`\s*([^`\s]*)[^`]*`")
# the flags that make each client take its SQL from an argument or file instead of stdin (r4 review H2);
# a client not listed here (sqlite3, redis-cli, pg_restore, ...) reads a piped stdin whatever its flags
# Judged on shell words, each as a whole: a short cluster may hold only that client's boolean letters before the
# flag, so an attached value (mysql -pchangeme, -Dstore, -pe; psql -Usvc) or text inside a value (-v x=-f) never
# counts (r5 review H5).
STDIN_REPLACED = {
    "psql": (re.compile(r"-[aAbeEnqsSxX1lw]*[cf]"), ("--command", "--file")),
    "mysql": (re.compile(r"-[BNnrstvVwXq]*e"), ("--execute",)),
    "mariadb": (re.compile(r"-[BNnrstvVwXq]*e"), ("--execute",)),
    "mongosh": (re.compile(r"-f"), ("--eval", "--file")),
    "mongo": (None, ("--eval",)),
}
STDIN_REDIRECT = re.compile(r"(?<![<\d])<\s*[^\s<(]")
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
    (re.compile(r"(?i)^mcp__.*__hyperdrive_"), ("sql", "query", "statement")),
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
DECLINE = re.compile(r"\b(?:no|nope|nah|not|don'?t|never|keep|kept|cancel|skip|stop|leave|hold|wait|later|instead|"
                     r"abort|reject|deny|denied|untouched|preserved?|spare|only\s+after)\b", re.I)
SOURCE_RE = re.compile(r"^(user|answer):([A-Za-z0-9._-]{1,120})/([0-9a-fA-F-]{8,64})$")


MASK_LIMIT = 1 << 20  # characters the UPDATE lexer reads; past it an UPDATE ... SET counts as unfiltered
# How each client reads quotes and comments: (backslash escapes, nested /* */, [ ] quotes, # comments, $$ quotes,
# runs /*! */). An UPDATE is filtered only when EVERY reading finds its WHERE (goodqa#15036 review F1): a reading
# that ends a string or comment earlier than the real database would otherwise reveal a WHERE it never sees.
SQL_READINGS = (
    (False, True, False, False, True, False),   # PostgreSQL
    (True, True, False, False, True, False),    # PostgreSQL E'' strings
    (True, False, False, True, False, True),    # MySQL/MariaDB, /*! */ runs
    (True, False, False, True, False, False),   # MySQL, version-gated /*!NNNNN */ skipped
    (False, False, False, True, False, True),   # MySQL NO_BACKSLASH_ESCAPES
    (False, False, True, False, False, False),  # SQLite / D1
    (False, True, True, False, False, False),   # SQL Server
)


def _strip_block_comments(text: str, run_exec: bool) -> str:
    """/* ... */ (not nested) replaced by a space, in one linear pass; an unterminated /* is left as text. With
    run_exec, /*! ... */ and /*M! ... */ keep their body, because MySQL runs it."""
    out, i = [], 0
    while True:
        s = text.find("/*", i)
        e = text.find("*/", s + 2) if s >= 0 else -1
        if e < 0:
            break
        out.append(text[i:s])
        body = text[s + 2:e]
        head = EXEC_HEAD.match(body) if run_exec else None
        out.append(" %s " % body[head.end():] if head else " ")
        i = e + 2
    out.append(text[i:])
    return "".join(out)


def _open_exec_comments(text: str) -> str:
    """/*! body */ -> body, other comments untouched (for a MySQL reading of the lexer). Linear."""
    out, i = [], 0
    while True:
        s = text.find("/*", i)
        while s >= 0 and not EXEC_HEAD.match(text, s + 2):
            s = text.find("/*", s + 2)
        e = text.find("*/", s + 2) if s >= 0 else -1
        if e < 0:
            break
        head = EXEC_HEAD.match(text, s + 2)
        out.append(text[i:s] + " " + text[head.end():e] + " ")
        i = e + 2
    out.append(text[i:])
    return "".join(out)


def _mask_sql(text: str, backslash=True, nested=True, bracket=True, hash_comment=False, dollar=True):
    """(masked, uncertain): comments blanked and quoted contents replaced by x for one dialect reading, positions
    and newlines kept. `uncertain` is true for an unterminated quote, dollar quote or comment. Linear in len(text)."""
    out = list(text)
    uncertain = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if (ch == "-" and text.startswith("--", i)) or (ch == "#" and hash_comment):
            end = text.find("\n", i + 1)
            end = n if end < 0 else end
            for pos in range(i, end):
                out[pos] = " "
            i = end
            continue
        if ch == "/" and text.startswith("/*", i):
            if not nested:
                end = text.find("*/", i + 2)
                pos = n if end < 0 else end + 2
                depth = 1 if end < 0 else 0
            else:
                depth, pos = 1, i + 2
                while pos < n and depth:
                    if text.startswith("/*", pos):
                        depth += 1
                        pos += 2
                    elif text.startswith("*/", pos):
                        depth -= 1
                        pos += 2
                    else:
                        pos += 1
            for at in range(i, pos):
                if out[at] != "\n":
                    out[at] = " "
            uncertain = uncertain or bool(depth)
            i = pos
            continue
        if ch == "$" and dollar:
            m = DOLLAR_QUOTE.match(text, i)
            if m:
                marker = m.group(0)
                end = text.find(marker, i + len(marker))
                if end < 0:
                    uncertain, end = True, n
                else:
                    end += len(marker)
                for pos in range(i, end):
                    if out[pos] != "\n":
                        out[pos] = "x"
                i = end
                continue
        if ch in ("'", '"', "`") or (ch == "[" and bracket):
            closer = "]" if ch == "[" else ch
            pos, closed = i + 1, False
            while pos < n:
                if backslash and ch != "[" and text[pos] == "\\" and pos + 1 < n:
                    out[pos] = out[pos + 1] = "x"
                    pos += 2
                    continue
                if text[pos] == closer:
                    if ch != "[" and pos + 1 < n and text[pos + 1] == closer:
                        out[pos] = out[pos + 1] = "x"
                        pos += 2
                        continue
                    out[pos] = "x"
                    pos += 1
                    closed = True
                    break
                if out[pos] != "\n":
                    out[pos] = "x"
                pos += 1
            out[i] = "x"
            uncertain = uncertain or not closed
            i = pos
            continue
        i += 1
    return "".join(out), uncertain


def _unfiltered_update(masked: str):
    """The first UPDATE ... SET with no WHERE at its own parenthesis depth in its statement, else None. One linear
    pass with a scope stack, so a CTE `(UPDATE ... WHERE ...)` is judged inside its parentheses and a WHERE in a
    subquery never filters the outer UPDATE. ON CONFLICT DO UPDATE, ON UPDATE, FOR UPDATE and KEY UPDATE are not
    UPDATE statements. Unbalanced parentheses make any UPDATE ... SET in that statement unfiltered."""
    depth, malformed, scopes, open_scopes = 0, False, [], []

    def verdict():
        for sc in scopes:
            if sc[1] and (malformed or depth or not sc[2]):
                return sc[3]
        return None

    for m in UPDATE_EVENTS.finditer(masked):
        tok = m.group(0)
        if tok == "(":
            depth += 1
        elif tok == ")":
            open_scopes = [sc for sc in open_scopes if sc[0] < depth]
            depth -= 1
            if depth < 0:
                malformed, depth = True, 0
        elif tok == ";":
            found = verdict()
            if found:
                return found
            depth, malformed, scopes, open_scopes = 0, False, [], []
        else:
            word = tok.upper()
            if word == "UPDATE":
                if not NOT_AN_UPDATE.search(masked[max(0, m.start() - 16):m.start()]):
                    if len(scopes) >= UPDATE_SCOPE_LIMIT:
                        return m  # too many UPDATEs in one statement to judge in linear time: unfiltered
                    sc = [depth, False, False, m]
                    scopes.append(sc)
                    open_scopes.append(sc)
            else:
                for sc in open_scopes:
                    if sc[0] == depth:
                        sc[1 if word == "SET" else 2] = True
    return verdict()


def _update_match(text: str):
    """An UPDATE ... SET that some dialect reading of `text` leaves without a top-level WHERE, else None. Text over
    MASK_LIMIT, or that a reading leaves inside an unterminated quote or comment, counts as unfiltered when it holds
    UPDATE and SET at all (goodqa#15036)."""
    first = UPDATE_WORD.search(text)
    if not first or not SET_WORD.search(text, first.end()):
        return None
    if len(text) > MASK_LIMIT:
        return first
    for backslash, nested, bracket, hash_comment, dollar, run_exec in SQL_READINGS:
        source = _open_exec_comments(text) if run_exec else text
        masked, uncertain = _mask_sql(source, backslash, nested, bracket, hash_comment, dollar)
        if uncertain:
            return first
        found = _unfiltered_update(masked)
        if found:
            return found
    return None


def destructive_match(sql: str, pieces=None):
    """The destructive statement in `sql`, else None. DELETE/DROP/TRUNCATE are matched after SQL comments, shell
    escapes and quote characters are removed (also with `--` or `#` line comments removed, so a comment cannot split a
    verb: `DELETE--x\nFROM`), once with MySQL executable comments run and once with them dropped. UPDATE is judged by
    the dialect readings above, on each source separately (`pieces`: the command and each SQL file, so a stray quote
    in one cannot hide another) and, for a client command, on its shell words."""
    for run_exec in (True, False):
        text = SHELL_ESCAPE.sub(lambda m: "\n" if m.group(0).lower() in ("\\n", "\\x0a") else " ",
                                _strip_block_comments(sql, run_exec))
        text = text.replace("\\", "").replace('"', "").replace("'", "")
        quick = (DESTRUCTIVE.search(text) or DESTRUCTIVE.search(LINE_COMMENT.sub(" ", text))
                 or DESTRUCTIVE.search(HASH_COMMENT.sub(" ", text)))
        if quick:
            return quick
    for piece in (pieces if pieces else [sql]):
        candidates = [piece]
        if DB_CLIENT.search(piece) or D1_EXECUTE.search(piece):
            candidates.append("\n".join(_words(piece)))
        for candidate in candidates:
            found = _update_match(candidate)
            if found:
                return found
    return None

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


INCLUDE_DEPTH_LIMIT = 8
INCLUDE_FILE_LIMIT = 8
INCLUDE_EXPANSION_LIMIT = 64
INCLUDE_TOTAL_LIMIT = FILE_READ_LIMIT
SOURCE_INCLUDE = re.compile(r"(?im)^\s*source\s+['\"]?([^\s;'\"]+)")
RELATIVE_INCLUDE = re.compile(r"\\(?:include_relative|ir)\b", re.I)


def _includes(text: str, command=False):
    """(path, relative-to-including-file) pairs. Only psql's \\ir and \\include_relative resolve against the
    including file's directory; every other include uses the event cwd."""
    out = [(m.group(1), bool(RELATIVE_INCLUDE.match(m.group(0)))) for m in CLIENT_INCLUDE.finditer(text)]
    source = MYSQL_SOURCE if command else SOURCE_INCLUDE
    out.extend((m.group(1), False) for m in source.finditer(text))
    return out


def sql_text_for(command: str, cwd=None, unread=None, pieces=None) -> str:
    """The command plus its complete, bounded SQL file closure (--file, psql -f, `< file`, cat inputs and nested
    includes). Unreadable files, cycles, excess depth/files/bytes/expansions and files the same command writes are
    appended to `unread` when a list is given, which makes a production command fail closed (goodqa#15036)."""
    paths = [m.group(1) for m in FILE_FLAG.finditer(command)]
    paths += [m.group(1) for m in PSQL_FILE_FLAG.finditer(command)]
    piped = []
    if DB_CLIENT.search(command) or D1_EXECUTE.search(command):
        paths += [m.group(1) for m in REDIRECT_IN.finditer(command)]
        paths += [m.group(1) for m in SUBST_IN.finditer(command)]
        for m in CAT_ARGS.finditer(command):
            paths += [w for w in m.group(1).split() if not w.startswith("-")]
        client = DB_CLIENT.search(command) or D1_EXECUTE.search(command)
        piped.extend("the output of %s" % x for x in _other_substitutions(command[client.start():SHLEX_LIMIT]))
        paths += [m.group(1) for m in SQLITE_INIT.finditer(command)]
        paths += _piped_inputs(command, piped)
        paths += [raw for raw, _relative in _includes(command, command=True)]
    paths = list(dict.fromkeys(paths))
    if unread is not None:
        unread.extend(piped)
    # File inputs are judged as they are now. Any other step in the same command (a write by any tool, a cd, a
    # download) could change them first, and no list of writers is complete: then they cannot be judged at all.
    if paths and _multi_step(command):
        if unread is not None:
            unread.extend("%s (the same command has other steps)" % p for p in paths[:INCLUDE_FILE_LIMIT])
        return command
    written = _written_paths(command, cwd) if paths else set()
    if pieces is not None:
        pieces.append(command)
    budget = {"files": 0, "bytes": 0, "expansions": 0}
    accounted, active, cache = set(), set(), {}

    def reject(raw, why=""):
        if unread is not None:
            unread.append("%s%s" % (raw, " (%s)" % why if why else ""))
        return ""

    def load(raw, including=None, depth=0):
        # Every include directive costs one expansion, so a dense DAG of 8 files stops after 64 (not 2**8) visits.
        if budget["expansions"] >= INCLUDE_EXPANSION_LIMIT:
            return reject(raw, "include expansion over %d" % INCLUDE_EXPANSION_LIMIT)
        budget["expansions"] += 1
        if depth > INCLUDE_DEPTH_LIMIT:
            return reject(raw, "include depth over %d" % INCLUDE_DEPTH_LIMIT)
        resolved = _resolve_path(raw, os.path.dirname(including) if including else cwd)
        real = os.path.realpath(resolved)
        if real in active:
            return reject(raw, "include cycle")
        first = real not in accounted
        if first and budget["files"] >= INCLUDE_FILE_LIMIT:
            return reject(raw, "more than %d files in the include closure" % INCLUDE_FILE_LIMIT)
        if real in written:
            body = None  # judged in its old state at hook time, so it cannot be judged at all
        elif real in cache:
            body = cache[real]
        else:
            body = cache[real] = _read_sql_file(resolved)
        if body is None:
            return reject(raw)
        size = len(body.encode("utf-8"))
        if first:
            if budget["bytes"] + size > INCLUDE_TOTAL_LIMIT:
                return reject(raw, "include closure over %d bytes" % INCLUDE_TOTAL_LIMIT)
            accounted.add(real)
            budget["files"] += 1
            budget["bytes"] += size
        active.add(real)  # only file text is cached; the cycle check follows the active include path
        try:
            # A file's text is joined once: a repeated include adds nothing new to judge, and joining every
            # expansion could build megabytes from one 200 KB file (review F2). Its includes are still walked.
            parts = [body] if first else []
            if first and pieces is not None:
                pieces.append(body)
            for child, relative in _includes(body):
                parts.append(load(child, resolved if relative else None, depth + 1))
            return "\n".join(p for p in parts if p)
        finally:
            active.discard(real)

    return "\n".join([command] + [load(raw) for raw in paths])


def _other_substitutions(text: str) -> list:
    """$(...) and `...` whose command is not cat and not a `< file` read (both of those are judged as input)."""
    out = []
    for m in OTHER_SUBST.finditer(text):
        word = m.group(1) if m.group(1) is not None else (m.group(2) or "")
        if word.rsplit("/", 1)[-1] != "cat" and not word.startswith("<"):
            out.append(m.group(0)[:40])
            if len(out) >= 8:
                break
    return out


def _multi_step(command: str) -> bool:
    """True when the command has more than one step besides a plain pipeline: ; && || & or a newline outside
    quotes, a cd/pushd, xargs (it runs after the producer exits), process substitution, or a command substitution
    that is not a cat or `< file` read (it runs before the client, r4 review H3)."""
    head = command[:SHLEX_LIMIT]
    bare = re.sub(r"'[^']*'|\"[^\"]*\"", " ", head)
    bare = re.sub(r"\d?[<>]&\d?-?|&>>?", " ", bare)
    return (bool(re.search(r"[;&\n]|(?:^|\s)(?:cd|pushd|xargs)(?:\s|$)|[<>]\(", bare))
            or bool(_other_substitutions(head)) or len(command) > SHLEX_LIMIT)


def _stdin_replaced(client: str, rest: str) -> bool:
    """True when one of the client's own shell words makes it take SQL from an argument or file, not stdin."""
    short, longs = STDIN_REPLACED.get(client, (None, ()))
    for w in _words(rest)[:AFTER_SCAN]:
        if (short is not None and short.fullmatch(w)) or w in longs or w.split("=", 1)[0] in longs and "=" in w:
            return True
    return False


def _piped_inputs(command: str, unjudged: list) -> list:
    """Files fed by `cat file | ... client`, the client anywhere in the next segment (ssh, docker exec, sudo, env).
    A client fed by any other producer (head, sed, curl, a script) reads SQL the guard cannot see unless its own
    flags or a `<` redirect replace stdin, so that stdin is listed in `unjudged`; echo and printf text is in the
    command itself."""
    paths = []
    segments = re.split(r"(?<!\|)\|(?!\|)", command[:SHLEX_LIMIT])
    for i in range(1, min(len(segments), 64)):
        seg = segments[i]
        client = DB_CLIENT.search(seg)
        if not client:
            continue
        rest = seg[client.end():]
        if _stdin_replaced(client.group(1).casefold(), rest) or \
                STDIN_REDIRECT.search(re.sub(r"'[^']*'|\"[^\"]*\"", " Q ", rest)):
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


SSH_CONFIG_LIMIT = 64 * 1024
SSH_CONFIG_FILES = 16
SSH_CONFIG_DEPTH = 4
SSH_CONFIG_LINES = 4096
SSH_INCLUDE_ENTRIES = 1024
HOSTNAME_OPTION = re.compile(r"(?i)\s*hostname\s*(?:=\s*|\s+)(\S+)")
SSH_OPTION_LETTERS = set(SSH_OPTS_WITH_VALUE)


def _ssh_route(words: list, index: int):
    """(alias, [command-line HostName values], [-F paths], certain) for the ssh at words[index]. Options are read
    letter by letter (-tF cfg, -qoHostName=x) before AND after the destination, as OpenSSH does, up to the remote
    command; ssh://[user@]host[:port] is parsed. Past AFTER_SCAN words the route is uncertain (goodqa#15037)."""
    alias, names, configs, seen_host = "", [], [], False
    i = index + 1
    while i < len(words):
        if i - index > AFTER_SCAN:
            return alias, names, configs, False
        w = words[i]
        if w == "--":
            if not seen_host and i + 1 < len(words):
                alias = words[i + 1]
            break
        if not w.startswith("-") or w == "-":
            if seen_host:
                break  # the remote command starts here
            alias, seen_host = w, True
            i += 1
            continue
        i += 1
        for j in range(1, len(w)):
            letter = w[j]
            if letter in SSH_OPTION_LETTERS:
                value = w[j + 1:]
                if not value:
                    value = words[i] if i < len(words) else ""
                    i += 1
                if letter == "o":
                    m = HOSTNAME_OPTION.match(value)
                    if m:
                        names.append(m.group(1))
                elif letter == "F":
                    configs.append(value)
                break
    if alias.startswith("ssh://"):
        rest = alias[len("ssh://"):].split("/", 1)[0].split("@")[-1]
        alias = rest[1:].split("]", 1)[0] if rest.startswith("[") else rest.split(":", 1)[0]
    alias = alias.split("@")[-1]
    return alias, [n.replace("%h", alias).replace("%%", "%") for n in names], configs, bool(alias)


def _ssh_host_matches(alias: str, patterns: list) -> bool:
    """OpenSSH Host matching: shell * and ?, a matching !pattern excludes the block. Matched both as typed and
    case-folded, so the guard sees every block ssh could apply (it only adds candidates)."""
    import fnmatch  # noqa: PLC0415
    hit = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        value = pattern[1:] if negated else pattern
        if fnmatch.fnmatchcase(alias, value) or fnmatch.fnmatchcase(alias.casefold(), value.casefold()):
            if negated:
                return False
            hit = True
    return hit


def _ssh_config_hostnames(alias: str, configs=(), home=None, cwd=None):
    """(every HostName ssh config could give `alias`, certain). Candidates come from matching Host blocks, Match
    host/originalhost blocks, every other Match block and Include files, with %h expanded: over-approximate, so an
    extra candidate can only add a prod target. The read is bounded (SSH_CONFIG_FILES files of SSH_CONFIG_LIMIT
    bytes, SSH_CONFIG_LINES lines, depth SSH_CONFIG_DEPTH, Include wildcards only in the last path part). A missing
    ~/.ssh/config is certain and empty; a missing -F file, an unreadable or oversized file, a reached cap or any
    error is uncertain, and the caller then denies a destructive command (review F3/F4)."""
    import fnmatch  # noqa: PLC0415
    import safe_input  # noqa: PLC0415
    sshdir = home_dir(home) / ".ssh"
    starts = []
    for c in configs:
        path = os.path.expanduser(c)
        starts.append(path if os.path.isabs(path) else os.path.join(str(cwd or os.getcwd()), path))
    required = bool(starts)
    starts = starts or [str(sshdir / "config")]
    out, seen, state = [], set(), {"files": 0, "certain": True}

    def read(path, depth, active, must_exist):
        if depth > SSH_CONFIG_DEPTH or state["files"] >= SSH_CONFIG_FILES:
            state["certain"] = False
            return
        real = os.path.realpath(path)
        if real in seen:
            return
        seen.add(real)
        if not os.path.lexists(path):
            if must_exist:
                state["certain"] = False
            return
        state["files"] += 1
        try:
            text = safe_input.read_bounded(path, SSH_CONFIG_LIMIT).decode("utf-8", "replace")
        except (safe_input.InputRejected, OSError, ValueError):
            state["certain"] = False
            return
        lines = text.splitlines()
        if len(lines) > SSH_CONFIG_LINES:
            state["certain"] = False
            return
        for line in lines:
            parts = re.split(r"\s*=\s*|\s+", line.split("#", 1)[0].strip(), maxsplit=1)
            key = parts[0].casefold()
            args = parts[1].split() if len(parts) > 1 else []
            if key == "host":
                active = _ssh_host_matches(alias, [a.strip("\"'") for a in args[:64]])
            elif key == "match":
                # host/originalhost criteria are checked; any other criterion (exec, user, all ...) may apply
                lowered = [a.casefold() for a in args]
                active = True
                for crit in ("host", "originalhost"):
                    if crit in lowered and lowered.index(crit) + 1 < len(args):
                        active = _ssh_host_matches(alias, args[lowered.index(crit) + 1].split(","))
                        break
            elif key == "hostname" and active and args:
                out.append(args[0].strip("\"'").replace("%h", alias).replace("%%", "%"))
            elif key == "include" and active:
                for pattern in args[:16]:
                    pattern = os.path.expanduser(pattern.strip("\"'"))
                    if not os.path.isabs(pattern):
                        pattern = str(sshdir / pattern)
                    head, tail = os.path.split(pattern)
                    if any(ch in head for ch in "*?["):
                        state["certain"] = False  # a wildcard directory could walk the whole disk
                        continue
                    if not any(ch in tail for ch in "*?["):
                        read(pattern, depth + 1, active, False)
                        continue
                    try:
                        entries = os.listdir(head)
                    except OSError:
                        continue  # ssh ignores an Include that matches nothing
                    if len(entries) > SSH_INCLUDE_ENTRIES:
                        state["certain"] = False
                        continue
                    for name in sorted(e for e in entries if not e.startswith(".") and fnmatch.fnmatch(e, tail)):
                        read(os.path.join(head, name), depth + 1, active, False)

    for start in starts:
        read(start, 0, True, required)
    return out, state["certain"]

def targets_production(command: str, env=None, home=None, cwd=None):
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
            rest = " ".join(words[i + 1:])
            if DB_CLIENT.search(rest) or "wrangler" in rest:
                # The destination is the alias, a command-line HostName (first wins in ssh, but every one is
                # judged) or a HostName the ssh config gives the alias (goodqa#15037).
                alias, names, configs, certain = _ssh_route(words, i)
                if alias and _prod(alias):
                    add("ssh to a prod host (%s) running a database client" % alias, [alias])
                if certain and not names:
                    try:
                        names, certain = _ssh_config_hostnames(alias, configs, home, cwd)
                    except Exception:  # noqa: BLE001 - a reader error must not erase the targets found so far
                        names, certain = [], False
                for name in names[:16]:
                    name = name.split("@")[-1]
                    if _prod(name):
                        add("ssh to %s, which reaches a prod host (%s), running a database client" % (alias, name),
                            [name])
                if not certain:
                    add("ssh whose destination cannot be established (options, ssh config) running a database "
                        "client", [])
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
    said = str(turn.get("text") or "").replace("\u2019", "'").replace("\u2018", "'").casefold()
    whole = r"(?<![\w.:/@-])%s(?![\w-]|[.:/@]\w)" % re.escape(target.casefold())
    if not re.search(whole, said):
        return False
    # decline words count outside the target name only, so a target such as hold-db can still be granted
    return not DECLINE.search(re.sub(whole, " ", said))


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


def _record_wal(wal: Path, note: str, source: str):
    """True when wal_note.py recorded the decision, else its reason (bounded). Only True counts as recorded."""
    helper = HERE / "wal_note.py"
    try:
        r = subprocess.run([sys.executable, str(helper), "--wal", str(wal), "--event", "decision", "--note", note,
                            "--source", source], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return type(exc).__name__
    return True if r.returncode == 0 else ((r.stderr or r.stdout).strip()[-300:] or "exit %d" % r.returncode)


def wal_source(user_source: str, answer_text: str) -> str:
    """The provenance source for the grant's WAL decision: the answer id plus a verbatim quoted excerpt of the
    selected answer (wal_note.py refuses an answer: source without one). The excerpt is the longest run of the
    answer that has no double quote or `...` (provenance's segment marker), at most 300 characters."""
    pieces = [x.strip() for chunk in str(answer_text or "").split('"') for x in chunk.split("...")]
    excerpt = max(pieces, key=len, default="")[:300].strip()
    if len(excerpt) < 12:
        raise ValueError("the selected answer is too short to cite in the WAL (12+ characters without quotes): use "
                         "an option label such as 'Approve DELETE on <target>'")
    return '%s "%s"' % (user_source, excerpt)


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
    cited = wal_source(user_source, turn.get("text"))
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
        recorded = record(Path(wal), "prod_delete_guard grant: scope=%s target=%s ttl=%ss note=%s" % (
            GRANT_SCOPE, target, int(ttl), entry["note"]), cited)
        if recorded is not True:
            raise ValueError("the WAL record failed, so no grant was written (%s)" % str(recorded)[:300])
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
        pieces = []
        sql = sql_text_for(command, ev.get("cwd"), unread, pieces)
        match = destructive_match(sql, pieces)
        if not match and not unread:
            return None
        target, values = targets_production(command, env, home, ev.get("cwd"))
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
