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
# One decision must end well inside the hook's timeout. Past DECISION_BUDGET seconds the guard stops reading and a
# command that looks database-related is denied (Kimi PR-C F8: a 40 KB `ssh ssh ...` chain ran past 10 s and the
# killed hook allowed it). Anything else is still allowed: the budget never blocks ordinary commands.
DECISION_BUDGET = 5.0
_DEADLINE = [None]
SSH_HOP_LIMIT = 16  # ssh words in front of a client that are judged; past it the destination is uncertain


class DeadlineExceeded(Exception):
    pass


def _tick():
    if _DEADLINE[0] is not None and time.monotonic() > _DEADLINE[0]:
        raise DeadlineExceeded()


DESTRUCTIVE = re.compile(
    r"\b(DELETE\s+FROM|DROP\s+(?:TABLE|DATABASE|INDEX|SCHEMA|VIEW|FUNCTION|PROCEDURE|TRIGGER|ROLE|USER)|TRUNCATE)\b"
    r"|\bdropdb\b|\bmysqladmin\b[^\n|;&]{0,512}?\bdrop\b", re.I)
UPDATE_SCOPE_LIMIT = 256  # UPDATE keywords judged per statement; past it the statement counts as unfiltered
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
# OpenSSH 9 options that take a value (-B bind interface and -P tag included, Kimi PR-C F5), and the boolean ones;
# any other letter makes the destination uncertain.
SSH_OPTS_WITH_VALUE = set("BbcDEeFIiJLlmOoPpQRSWw")
SSH_FLAG_LETTERS = set("46AaCfGgKkMNnqsTtVvXxYy")
PROXY_OPTION = re.compile(r"(?i)\s*proxy(?:command|jump)\s*(?:=|\s)\s*(?!none\s*$)\S")
KUBECTL_EXEC_OPTS_WITH_VALUE = {"-c", "--container", "-n", "--namespace", "--context", "--kubeconfig"}
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


def _strip_block_comments(text: str, run_exec: bool, nested: bool = False) -> str:
    """/* ... */ replaced by a space, in one linear pass; an unterminated /* is left as text. With nested, an inner
    /* opens another level, as in PostgreSQL (Kimi PR-C F1); MySQL does not nest. With run_exec, /*! ... */ and
    /*M! ... */ keep their body, because MySQL runs it."""
    out, i = [], 0
    while True:
        s = text.find("/*", i)
        e = text.find("*/", s + 2) if s >= 0 else -1
        if nested and e >= 0:
            depth, pos = 1, s + 2
            while depth:
                o, c = text.find("/*", pos), text.find("*/", pos)
                if c < 0:
                    e = -1
                    break
                if 0 <= o < c:
                    depth, pos = depth + 1, o + 2
                else:
                    depth, pos = depth - 1, c + 2
            if depth == 0:
                e = pos - 2
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


MASK_SPECIAL = re.compile(r"--|/\*|[$'\"`\[#]")
NOT_NEWLINE = re.compile(r"[^\n]")


def _mask_sql(text: str, backslash=True, nested=True, bracket=True, hash_comment=False, dollar=True):
    """(masked, uncertain): comments blanked and quoted contents replaced by x for one dialect reading, positions
    and newlines kept. `uncertain` is true for an unterminated quote, dollar quote or comment. Linear in len(text):
    ordinary text is skipped by one regex search per special character (Kimi PR-C F8)."""
    out = []
    uncertain = False
    i, n, done = 0, len(text), 0
    steps = 0

    def blank(a, b, fill):
        out.append(NOT_NEWLINE.sub(fill, text[a:b]))

    while i < n:
        steps += 1
        if steps % 4096 == 0:
            _tick()
        m = MASK_SPECIAL.search(text, i)
        if not m:
            break
        i = m.start()
        ch = text[i]
        if (ch == "-" and text.startswith("--", i)) or (ch == "#" and hash_comment):
            end = text.find("\n", i + 1)
            end = n if end < 0 else end
            out.append(text[done:i])
            blank(i, end, " ")
            i = done = end
            continue
        if ch == "/":
            if not nested:
                end = text.find("*/", i + 2)
                pos = n if end < 0 else end + 2
                depth = 1 if end < 0 else 0
            else:
                depth, pos = 1, i + 2
                while pos < n and depth:
                    o = text.find("/*", pos)
                    c = text.find("*/", pos)
                    if c < 0:
                        pos = n
                        break
                    if 0 <= o < c:
                        depth += 1
                        pos = o + 2
                    else:
                        depth -= 1
                        pos = c + 2
            out.append(text[done:i])
            blank(i, pos, " ")
            uncertain = uncertain or bool(depth)
            i = done = pos
            continue
        if ch == "$":
            dq = DOLLAR_QUOTE.match(text, i) if dollar else None
            if not dq:
                i += 1
                continue
            marker = dq.group(0)
            end = text.find(marker, i + len(marker))
            if end < 0:
                uncertain, end = True, n
            else:
                end += len(marker)
            out.append(text[done:i])
            blank(i, end, "x")
            i = done = end
            continue
        if ch == "#" or (ch == "[" and not bracket):
            i += 1
            continue
        closer = "]" if ch == "[" else ch
        pos, closed = i + 1, False
        esc = -1  # the next backslash at or after pos, searched again only once pos passes it (review R4)
        nxt = -1
        while pos < n:
            steps += 1
            if steps % 4096 == 0:
                _tick()
            if nxt < pos:
                nxt = text.find(closer, pos)
            if backslash and ch != "[":
                if esc < pos:
                    esc = text.find("\\", pos)
                    if esc < 0:
                        esc = n
                if esc < (nxt if nxt >= 0 else n) and esc + 1 < n:
                    pos = esc + 2
                    continue
            if nxt < 0:
                pos = n
                break
            if ch != "[" and nxt + 1 < n and text[nxt + 1] == closer:
                pos = nxt + 2
                continue
            pos, closed = nxt + 1, True
            break
        out.append(text[done:i])
        blank(i, pos, "x")
        uncertain = uncertain or not closed
        i = done = pos
    out.append(text[done:])
    return "".join(out), uncertain


def _unfiltered_update(masked: str):
    """The first UPDATE ... SET with no WHERE at its own parenthesis depth in its statement, else None. One linear
    pass, so a CTE `(UPDATE ... WHERE ...)` is judged inside its parentheses and a WHERE in a subquery never filters
    the outer UPDATE. ON CONFLICT DO UPDATE, ON UPDATE, FOR UPDATE and KEY UPDATE are not UPDATE statements.
    Unbalanced parentheses make any UPDATE ... SET in that statement unfiltered. Per depth, `sets` and `wheres` count
    the SET and WHERE events seen while that depth is open; a scope compares them with the counts at its start
    when its depth closes or the statement ends, so each event costs O(1) (Kimi PR-C F8)."""
    depth, malformed = 0, False
    open_at = {}  # depth -> [[set_count_at_start, where_count_at_start, match], ...]
    sets, wheres = {}, {}
    results = []  # (has_set, has_where, match)
    steps = updates = 0

    def close(d):
        for set0, where0, m in open_at.pop(d, ()):
            results.append((sets.get(d, 0) > set0, wheres.get(d, 0) > where0, m))
        sets.pop(d, None)
        wheres.pop(d, None)

    def verdict(dirty):
        for d in sorted(open_at, reverse=True):
            close(d)
        for has_set, has_where, m in results:
            if has_set and (dirty or not has_where):
                return m
        return None

    for m in UPDATE_EVENTS.finditer(masked):
        steps += 1
        if steps % 4096 == 0:
            _tick()
        tok = m.group(0)
        if tok == "(":
            depth += 1
        elif tok == ")":
            close(depth)
            depth -= 1
            if depth < 0:
                malformed, depth = True, 0
        elif tok == ";":
            found = verdict(malformed or depth != 0)
            if found:
                return found
            depth, malformed, open_at, sets, wheres, results, updates = 0, False, {}, {}, {}, [], 0
        else:
            word = tok.upper()
            if word == "UPDATE":
                if not NOT_AN_UPDATE.search(masked[max(0, m.start() - 16):m.start()]):
                    updates += 1
                    if updates > UPDATE_SCOPE_LIMIT:
                        return m  # more UPDATEs in one statement than are judged: unfiltered
                    open_at.setdefault(depth, []).append([sets.get(depth, 0), wheres.get(depth, 0), m])
            elif word == "SET":
                sets[depth] = sets.get(depth, 0) + 1
            else:
                wheres[depth] = wheres.get(depth, 0) + 1
    return verdict(malformed or depth != 0)


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


SHELL_PROGRAMS = CLIENT_NAMES | {"ssh", "bash", "sh", "zsh", "dash", "ksh", "docker", "podman", "kubectl", "sudo",
                                 "doas", "env", "su", "runuser", "nice", "nohup", "timeout", "time", "exec", "eval",
                                 "command", "wrangler", "xargs", "nerdctl"}
SHELL_LEVEL_LIMIT = 4
SHELL_WORD_LIMIT = 20000
SEPARATOR_WORDS = {"|", "||", "&&", ";", "&", "|&", ";;"}
CONTAINER_RUNNERS = {"docker", "podman", "nerdctl", "kubectl", "lxc", "incus"}
ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
# A runner that joins its arguments into one string for another shell to parse again (ssh, eval): what the client
# finally receives is not the local shell word, so no SQL argument there is read as SQL with its quotes kept.
REPARSING_RUNNERS = {"ssh", "eval"}
# The SQL each client takes from an argument: (short cluster, long option and its accepted getopt prefixes)
SQL_ARG_FLAGS = {
    "psql": (re.compile(r"-[aAbeEnqsSxX1lw]*c"), "--command", 4),
    "mysql": (re.compile(r"-[BNnrstvVwXq]*e"), "--execute", 4),
    "mariadb": (re.compile(r"-[BNnrstvVwXq]*e"), "--execute", 4),
    "wrangler": (None, "--command", 9),
}
# The files each client reads SQL from (Kimi PR-C F3: --fi''le and "--file" are --file to the shell)
SQL_FILE_FLAGS = {
    "psql": (re.compile(r"-[A-Za-z0-9]*f"), "--file", 4),
    "wrangler": (None, "--file", 6),
}
SQL_SOURCE_ANY = re.compile(r"(?im)(?:^|;)\s*(?:source|\\\.)\s+['\"]?([^\s;'\"]+)")
PSQL_CD = re.compile(r"\\cd\b", re.I)
DO_BODY = re.compile(r"(?is)\bDO\s+(?:LANGUAGE\s+\w+\s+)?(E?)'((?:[^'\\]|''|\\.)*)'")
DO_DEPTH = 3


def _runner_exec(words, i):
    """The index of `exec` when words[i] is a container runner running one: `docker exec`, `docker compose exec`,
    `docker container exec`, `kubectl -n ns exec` (review R3). None otherwise."""
    for j in range(i + 1, min(i + 64, len(words))):
        if words[j] == "exec" or (words[j] == "run" and words[i] != "kubectl"):
            return j
        if words[j] in SEPARATOR_WORDS:
            return None
    return None


class CommandParts:
    """What the shell hands each database client, read from shell words (Kimi PR-C F3, F4, F9).
    residual  the command without the SQL arguments that were taken out, judged as before (quotes stripped)
    args      (client, sql, remote) for -c/--command/-e/--execute values that are plain text (no $ or `)
    files     (path, remote) for client file flags and, inside a remote command, `<` redirects
    certain   false when a level cannot be split as shell words or a budget ran out; then the whole command is
              judged as before
    `remote` is true after ssh, or docker/podman/nerdctl/kubectl exec: a file named there is read on the other
    machine or container, never the local file of that name."""

    def __init__(self):
        self.residual, self.args, self.files, self.certain = "", [], [], True


def _option_value(words, i, short, long_name, min_len):
    """(value, next index) when words[i] is the option, else (None, i)."""
    w = words[i]
    if short is not None and short.fullmatch(w):
        return (words[i + 1] if i + 1 < len(words) else ""), i + 2
    if short is not None and len(w) > 2 and short.fullmatch(w[:2]) and not w.startswith("--"):
        return w[2:], i + 1
    name, eq, value = w.partition("=")
    if name.startswith("--") and len(name) >= min_len and long_name.startswith(name):
        if eq:
            return value, i + 1
        return (words[i + 1] if i + 1 < len(words) else ""), i + 2
    return None, i


_PARTS_CACHE = {}


def _command_parts(command: str) -> CommandParts:
    cached = _PARTS_CACHE.get(command)
    if cached is not None:
        return cached
    parts = CommandParts()
    budget = [SHELL_WORD_LIMIT]

    def walk(text, level, remote, reparsed):
        _tick()
        if len(text) > SHLEX_LIMIT:
            parts.certain = False
            return text
        try:
            words = shlex.split(text, comments=False, posix=True)
        except ValueError:
            parts.certain = False
            return text
        budget[0] -= len(words)
        if budget[0] < 0:
            parts.certain = False
            return text
        out, client, here_remote, here_reparsed = [], None, remote, reparsed
        i = 0
        while i < len(words):
            w = words[i]
            if w in SEPARATOR_WORDS:
                client, here_remote, here_reparsed = None, remote, reparsed
                out.append(w)
                i += 1
                continue
            base = w.lstrip("\\").rsplit("/", 1)[-1]
            if base in ("ssh", "mosh"):
                here_remote = here_reparsed = True
            elif base in CONTAINER_RUNNERS and _runner_exec(words, i) is not None:
                here_remote = True
            elif base in ("nsenter", "chroot", "systemd-nspawn", "machinectl"):
                here_remote = True  # another filesystem view: a named file is not the local one
            elif base == "eval":
                here_reparsed = True
            if base in SQL_ARG_FLAGS or base in CLIENT_NAMES:
                client = base
                out.append(w)
                i += 1
                continue
            if client in SQL_ARG_FLAGS:
                value, nxt = _option_value(words, i, *SQL_ARG_FLAGS[client])
                if value is not None:
                    if value and not here_reparsed and "$" not in value and "`" not in value:
                        parts.args.append((client, value, here_remote))
                        out.append(" ")
                    else:
                        parts.args.append((client, value, here_remote))
                        out.extend(words[i:nxt])
                    i = nxt
                    continue
            if client in SQL_FILE_FLAGS:
                value, nxt = _option_value(words, i, *SQL_FILE_FLAGS[client])
                if value:
                    parts.files.append((value, here_remote))
                    out.extend(words[i:nxt])
                    i = nxt
                    continue
            if level > 0 and remote and w.startswith("<") and not w.startswith("<<") and not w.startswith("<("):
                target = w[1:] or (words[i + 1] if i + 1 < len(words) else "")
                if target:
                    parts.files.append((target, True))
            if level < SHELL_LEVEL_LIMIT and w.strip() and any(c.isspace() for c in w):
                head = w.split(None, 1)[0].strip("'\"\\")
                # Behind ssh or a container runner every multi-word value can be a command for the far side
                # (`ssh h 'cd /srv && psql -f a.sql'`), so it is walked whatever it starts with (review R3).
                if (here_remote or head.rsplit("/", 1)[-1] in SHELL_PROGRAMS
                        or re.match(r"^[A-Za-z_]\w*=", head)):
                    out.append(walk(w, level + 1, here_remote, here_reparsed))
                    i += 1
                    continue
            out.append(w)
            i += 1
        return " ".join(out)

    try:
        parts.residual = walk(command, 0, False, False)
    except DeadlineExceeded:
        raise
    except Exception:  # noqa: BLE001 - a parser error must never become an allow (review R1)
        parts.certain = False
    if not parts.certain:
        parts.residual = command
    if len(_PARTS_CACHE) > 16:
        _PARTS_CACHE.clear()
    _PARTS_CACHE[command] = parts
    return parts


def _do_bodies(text: str, depth=0) -> list:
    """The bodies of single-quoted DO blocks, which PostgreSQL runs at once (Kimi PR-C F2); nested ones too."""
    out = []
    for m in DO_BODY.finditer(text):
        body = m.group(2).replace("''", "'")
        if m.group(1):
            body = body.replace("\\'", "'").replace("\\\\", "\\")
        out.append(body)
        if depth < DO_DEPTH:
            out.extend(_do_bodies(body, depth + 1))
        if len(out) >= 64:
            break
    return out


def _unescape_shell(text: str) -> str:
    return SHELL_ESCAPE.sub(lambda m: "\n" if m.group(0).lower() in ("\\n", "\\x0a") else " ", text)


def _quick_match(text: str):
    """The pre-mask reading: comments (nested and not) and quote characters removed, so DEL""ETE matches."""
    for nested in (True, False):
        for run_exec in (True, False):
            t = _unescape_shell(_strip_block_comments(text, run_exec, nested))
            t = t.replace("\\", "").replace('"', "").replace("'", "")
            found = (DESTRUCTIVE.search(t) or DESTRUCTIVE.search(LINE_COMMENT.sub(" ", t))
                     or DESTRUCTIVE.search(HASH_COMMENT.sub(" ", t)))
            if found:
                return found
    return None


def _shell_match(text: str):
    """Shell text the guard cannot take apart is judged with every quote removed: a destructive verb anywhere is
    destructive, and an UPDATE ... SET needs a WHERE that no quote can hide (the rule before PR-C r2)."""
    found = _quick_match(text)
    if found or not UPDATE_WORD.search(text):
        return found
    bare = _unescape_shell(text).replace("\\", "").replace('"', "").replace("'", "")
    return _judge_text(bare)


def _judge_text(text: str):
    """A destructive statement in `text` read as SQL by any dialect: DELETE/DROP/TRUNCATE outside strings and
    comments, or an UPDATE ... SET without a top-level WHERE. A reading that leaves a quote or comment open falls
    back to the quick reading (and an UPDATE with SET counts as unfiltered): unsure means destructive."""
    first_update = UPDATE_WORD.search(text)
    has_update = bool(first_update and SET_WORD.search(text, first_update.end()))
    variants = [text]
    if SHELL_ESCAPE.search(text):
        variants.append(_unescape_shell(text))
    for v in variants:
        if len(v) > MASK_LIMIT:
            return _quick_match(v) or (first_update if has_update else None)
        for backslash, nested, bracket, hash_comment, dollar, run_exec in SQL_READINGS:
            source = _open_exec_comments(v) if run_exec else v
            masked, uncertain = _mask_sql(source, backslash, nested, bracket, hash_comment, dollar)
            if uncertain:
                found = _quick_match(source) or (first_update if has_update else None)
                if found:
                    return found
                continue
            found = DESTRUCTIVE.search(masked) or (_unfiltered_update(masked) if has_update else None)
            if found:
                return found
    return None


STRING_SINKS = re.compile(
    r"(?is)\b(?:PREPARE|EXECUTE|EXEC|CALL|DO|DBLINK\w*|SYSTEM|"
    r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE|TRIGGER|RULE|EVENT|AGGREGATE))\b"
    r"|\bCOPY\b[^;]*\bPROGRAM\b|\\(?:g\w*|o|w|set|if|elif|echo|qecho|!)|\\!|(?<![:\w]):['\"]?[A-Za-z_]\w*"
    r"|\b(?:QUERY_TO_XML\w*|RUN_COMMAND\w*|PG_BACKGROUND\w*|DBMS_\w+|SP_EXECUTESQL|XP_CMDSHELL)\b")


# A literal counts as plain data only right after one of these: a select-list item or a comparison operand. After
# `(` or `,` it may be an argument to a function that runs it (Citus run_command_on_workers, pg_background_launch,
# query_to_xml_and_xmlschema, any extension), and no list of such functions is complete (delta review D1).
DATA_LITERAL_LEAD = re.compile(r"(?is)(?:\bSELECT|\bDISTINCT|=|<>|!=|\bI?LIKE)\s*$")
SINGLE_LITERAL = re.compile(r"'(?:[^']|'')*'")
META_OR_SHELL = re.compile(r"[\\`]|^\s*\.", re.M)


def _plain_data_strings(text: str) -> bool:
    """True when the masked reading may judge `text` (Kimi PR-C F9 opt-in, delta review D1): no psql or mysql
    meta-command, backtick or sqlite dot-command, no known string-execution sink, every quote closed in every
    reading, and every single-quoted literal holding destructive text sits where SQL treats it as data."""
    if META_OR_SHELL.search(text) or STRING_SINKS.search(text):
        return False
    if any(_mask_sql(text, *reading[:5])[1] for reading in SQL_READINGS):
        return False
    for m in SINGLE_LITERAL.finditer(text):
        inner = m.group(0)[1:-1]
        if (_quick_match(inner) or UPDATE_WORD.search(inner)) and not DATA_LITERAL_LEAD.search(text[:m.start()]):
            return False
    return True


def _judge_arg(text: str):
    """A -c/-e/--command value: the quote-stripped verdict, unless its strings are plain data, then the masked
    one (so `SELECT 'DELETE FROM x' AS example` is a string). The masked reading never clears more than that."""
    stripped = _shell_match(text)
    if stripped and not _plain_data_strings(text):
        return stripped
    return _judge_sql(text)


def _judge_sql(text: str):
    """SQL judged with strings masked, unless it can run a string as SQL or shell (review R2): then every quote is
    stripped first, so the string is read as the statement it becomes."""
    if STRING_SINKS.search(text) or META_OR_SHELL.search(text):
        found = _shell_match(text)
        if found:
            return found
    for t in [text] + _do_bodies(text):
        found = _judge_text(t)
        if found:
            return found
    return None


def destructive_match(sql: str, pieces=None):
    """The destructive statement, else None (Kimi PR-C F1, F2, F9). `pieces` are the command and each SQL file
    (sql_text_for fills them); without pieces `sql` is read as a command. The command is split into shell words:
    a plain -c/--command/-e/--execute value is SQL and is judged as SQL (strings and comments masked, per dialect,
    nested comments both ways, single-quoted DO bodies too), so `SELECT 'DELETE FROM x'` is a string; everything
    else in the command is judged as before, with every quote stripped, so DEL""ETE and a verb in a python -c
    string still count. A command that cannot be split is judged entirely the old way. Files are SQL."""
    if pieces is None:
        found = _judge_sql(sql)  # a direct caller may hand plain SQL: judge it as SQL as well as a command
        if found:
            return found
    sources = pieces if pieces else [sql]
    for index, piece in enumerate(sources):
        if index > 0:
            # SQL files keep the quote-stripped rule: a file can run its strings in more ways than any list names
            # (\\o |, \\w |, \\gx |, backticks, .shell, extension functions; delta review D1)
            found = _shell_match(piece) or _judge_sql(piece)
            if found:
                return found
            continue
        # What bash removes or decodes before a client sees the text: a backslash-newline continuation and $'..'
        # escapes (review: present at base too). Each is judged the old way as well; it can only add denies.
        for variant in _shell_decoded(piece):
            found = _shell_match(variant)
            if found:
                return found
        parts = _command_parts(piece)
        if not parts.certain:
            found = _shell_match(piece)
            if found:
                return found
            continue
        found = _shell_match(parts.residual)
        if found:
            return found
        for _client, text, _remote in parts.args:
            found = _judge_arg(text)
            if found:
                return found
            if any(_mask_sql(text, *reading[:5])[1] for reading in SQL_READINGS):
                # a value that leaves a quote or comment open was split differently than the guard assumed:
                # judge the whole command the old way (review: nested_blank_bash)
                found = _shell_match(piece)
                if found:
                    return found
    return None


def _shell_decoded(command: str) -> list:
    import warnings  # noqa: PLC0415
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return _shell_decoded_inner(command)


def _shell_decoded_inner(command: str) -> list:
    out = []
    if "\\\n" in command:
        out.append(command.replace("\\\n", ""))
    if "$'" in command:
        def decode(m):
            try:
                return m.group(1).encode("latin-1", "backslashreplace").decode("unicode_escape")
            except Exception:  # noqa: BLE001 - incl. a DeprecationWarning raised as an error (delta review D3)
                return m.group(1)
        out.append(ANSI_C.sub(lambda m: decode(m), command))
    return out


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
        paths += _substituted_cats(command[:SHLEX_LIMIT])
    parts = _command_parts(command)
    for raw, remote in parts.files:
        if remote:
            piped.append("%s (read on the remote host or in the container, not the local file of that name)" % raw)
        else:
            paths.append(raw)
    for client, text, remote in parts.args:
        found = [m.group(1) for m in CLIENT_INCLUDE.finditer(text)]
        if client in ("mysql", "mariadb"):
            found += [m.group(1) for m in SQL_SOURCE_ANY.finditer(text)]
        for raw in found:
            if remote:
                piped.append("%s (read on the remote host or in the container, not the local file of that name)"
                             % raw)
            else:
                paths.append(raw)
    paths = list(dict.fromkeys(paths))
    if paths and PSQL_CD.search(command):
        piped.append("psql \\cd in the same command (it changes where its files are read from)")
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
            children = _file_includes(body)
            if children and PSQL_CD.search(body):
                return reject(raw, "psql \\cd changes where its includes are read from")
            for child, relative in children:
                parts.append(load(child, resolved if relative else None, depth + 1))
            return "\n".join(p for p in parts if p)
        finally:
            active.discard(real)

    return "\n".join([command] + [load(raw) for raw in paths])


SUBST_BODY = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")


def _substituted_cats(text: str) -> list:
    """Files read by `$(cat f)` and backtick cat, with the substitution split as shell words: quoted names, /bin/cat
    and \\cat included (Kimi PR-C F3)."""
    out = []
    for m in SUBST_BODY.finditer(text):
        body = m.group(1) if m.group(1) is not None else m.group(2)
        try:
            words = shlex.split(body, posix=True)
        except ValueError:
            continue
        if words and words[0].lstrip("\\").rsplit("/", 1)[-1] == "cat":
            out += [w for w in words[1:] if not w.startswith("-")]
        if len(out) >= INCLUDE_FILE_LIMIT:
            break
    return out


def _file_includes(body: str):
    """Includes in a SQL file that some dialect reading leaves outside comments and strings (Kimi PR-C F9): a
    commented-out `\\i absent.sql` is not an include. A reading that cannot close a quote or comment keeps them all."""
    every = _includes(body)
    if not every:
        return every
    found = []
    for backslash, nested, bracket, hash_comment, dollar, run_exec in SQL_READINGS:
        source = _open_exec_comments(body) if run_exec else body
        masked, uncertain = _mask_sql(source, backslash, nested, bracket, hash_comment, dollar)
        if uncertain:
            return every
        for rx in (CLIENT_INCLUDE, SOURCE_INCLUDE):
            for m in rx.finditer(masked):
                real = rx.match(source, m.start())
                if real:
                    found.append((real.group(1), bool(RELATIVE_INCLUDE.match(real.group(0)))))
    return list(dict.fromkeys(found))


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
    alias, names, configs, seen_host, sure = "", [], [], False, True
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
                    if PROXY_OPTION.match(value):
                        sure = False  # the connection goes wherever the proxy sends it (Kimi PR-C F6)
                elif letter == "F":
                    configs.append(value)
                elif letter == "J":
                    sure = False
                break
            if letter not in SSH_FLAG_LETTERS:
                sure = False  # an option this guard does not know could take the host as its value (F5)
                break
    if alias.startswith("ssh://"):
        rest = alias[len("ssh://"):].split("/", 1)[0].split("@")[-1]
        alias = rest[1:].split("]", 1)[0] if rest.startswith("[") else rest.split(":", 1)[0]
    alias = alias.split("@")[-1]
    return alias, [n.replace("%h", alias).replace("%%", "%") for n in names], configs, bool(alias) and sure


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
            # OpenSSH reads double-quoted arguments ("conf.d/prod route", Kimi PR-C F7); an unbalanced quote is
            # uncertain
            try:
                args = shlex.split(parts[1], posix=True) if len(parts) > 1 else []
            except ValueError:
                state["certain"] = False
                args = parts[1].split()
            if key in ("proxycommand", "proxyjump") and active and args and args[0].casefold() != "none":
                state["certain"] = False  # the real endpoint is chosen by the proxy (Kimi PR-C F6)
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
    # later_client[i]: some word after words[i] names a DB client or wrangler. One backward pass instead of joining
    # the rest of the command for every ssh word, which was quadratic (`ssh ssh ssh ...`, Kimi PR-C F8).
    later_client = [False] * (len(words) + 1)
    for i in range(len(words) - 1, -1, -1):
        w = words[i]
        later_client[i] = later_client[i + 1] or bool(DB_CLIENT.search(w)) or "wrangler" in w
    hops = 0
    for i, w in enumerate(words):
        if i % 4096 == 0:
            _tick()
        base = w[w.rfind("/") + 1:]
        if base == "ssh" and later_client[i + 1]:
            hops += 1
            if hops > SSH_HOP_LIMIT:
                add("more than %d ssh hops in front of a database client: the destination cannot be established"
                    % SSH_HOP_LIMIT, [])
                break
            # The destination is the alias, a command-line HostName (first wins in ssh, but every one is
            # judged) or a HostName the ssh config gives the alias (goodqa#15037).
            alias, names, configs, certain = _ssh_route(words, i)
            if alias and _prod(alias):
                add("ssh to a prod host (%s) running a database client" % alias, [alias])
            if alias:
                # The config is read even when -o HostName is given: it can still add a ProxyCommand or
                # ProxyJump that picks the real endpoint (Kimi PR-C F6). Extra names only add targets.
                try:
                    more, read_ok = _ssh_config_hostnames(alias, configs, home, cwd)
                except Exception:  # noqa: BLE001 - a reader error must not erase the targets found so far
                    more, read_ok = [], False
                names, certain = names + more, certain and read_ok
            for name in names[:16]:
                name = name.split("@")[-1]
                if _prod(name):
                    add("ssh to %s, which reaches a prod host (%s), running a database client" % (alias, name),
                        [name])
            if not certain:
                add("ssh whose destination cannot be established (options, ssh config) running a database "
                    "client", [])
        exec_at = _runner_exec(words, i) if base in CONTAINER_RUNNERS else None
        if exec_at is not None:
            # podman, nerdctl and kubectl exec name the container or pod the same way (kubectl adds -c/-n)
            box = _after(words, exec_at, DOCKER_EXEC_OPTS_WITH_VALUE | KUBECTL_EXEC_OPTS_WITH_VALUE)
            if box and _prod(box) and later_client[min(exec_at + 1, len(words))]:
                add("%s exec into a prod container (%s) running a database client" % (base, box), [box])
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
        return _evaluate(ev, home, now, resolver, env)
    finally:
        _DEADLINE[0] = None  # the budget belongs to one decision; direct calls of the readers have none


def _evaluate(ev, home=None, now=None, resolver=None, env=None):
    command = ""
    _DEADLINE[0] = time.monotonic() + DECISION_BUDGET
    try:
        if not isinstance(ev, dict):
            return None
        command = command_text_for_event(ev)
        if not command.strip():
            return None
        _tick()
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
    except DeadlineExceeded:
        _DEADLINE[0] = None
        tool = str((ev or {}).get("tool_name") or "") if isinstance(ev, dict) else ""
        if (DB_CLIENT.search(command[:SHLEX_LIMIT]) or D1_EXECUTE.search(command[:SHLEX_LIMIT])
                or _prod(command[:SHLEX_LIMIT]) or TOOL_IS_PRODUCTION_BY_CONSTRUCTION.search(tool)):
            return ("deny", "REFUSED: this database command could not be judged within %.0f s (it is too long or "
                            "too nested), so the guard cannot tell whether it changes production data. Failing "
                            "closed: split it into smaller commands." % DECISION_BUDGET)
        return None
    except Exception:  # noqa: BLE001 - before a match every error allows
        return None
    _DEADLINE[0] = None
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
