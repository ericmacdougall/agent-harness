#!/usr/bin/env python3
r"""PreToolUse hook on the named database tools: refuse destructive SQL aimed at a PRODUCTION database unless a
live approval of the approvals store names that exact database or host (goodqa#14908, docs/approvals.md).

Release 1001: registered on the MCP database tools and the local `db_tool_patterns` only, never on Bash (a Bash
call starts no harness hook). It stays until production credentials are scoped (docs/direction.md).

Why: an agent once deleted rows from a live database after announcing the intent in chat, with no
recorded approval.

What counts as destructive (after `/* ... */` comments and shell quote characters are removed, so
`DEL""ETE` and `DELETE/**/FROM` still match): DELETE FROM, DROP TABLE|DATABASE|INDEX|SCHEMA,
TRUNCATE, and UPDATE ... SET with no WHERE in the same statement.

What counts as a production TARGET (each yields the exact target value an approval must name):
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
  - any extra tool named in ~/.agent-harness/local.json `db_tool_patterns` ([{"tool": "<name regex>",
    "fields": [...]}]) has those input fields read as a command
The SQL is read from the command and, with a DB client in it, from --file / psql -f files (also -1f,
-Xf, --fi=), `< file`, `$(< file)`, every `cat` argument anywhere in the command (a pipe into ssh, docker
exec, sudo or env, `$(cat ...)`, backticks), psql
`\i`/`\ir`/`\include`/`\include_relative`, mysql `source`/`\.`, and sqlite `.read`/`-init`. Relative paths
resolve against the event's cwd, and ~ is expanded. Files are opened as regular files only (a FIFO or device
cannot hang the hook). A prod-targeted command is denied when one of its SQL files cannot be judged at hook
time: missing, not a regular file, unreadable, over 200,000 bytes, more than 8 files, written by the same
command, or the command has any other step besides a plain pipeline (; && || & newline cd pushd, xargs,
<( >(, or a $(...)/backtick substitution that is not a cat or `< file` read), which could change the file
first. A client fed by a pipe from anything but cat/echo/printf is denied the same way unless its own flag
replaces stdin (psql -c/-f, mysql -e, mongosh --eval/--file) or a `<` redirect does; so is a $(...) or
backtick substitution after the client that is not a cat or `< file` read. Because every cat counts, a
read-only prod command that also cats a file it writes or a missing file is denied (split the command). Commands over 64 KiB are split on whitespace; every prod-looking word after a
client is then a target. Scans are bounded (512 characters, 256 words after a client, 64 clients), and a
command too long to judge its database is denied when it carries a destructive statement.
Prose that merely mentions these words does not count; a heredoc that runs psql against a prod host
does (an accepted over-refusal). Out of scope, disclosed: SQL built at run time
(`base64 -d | psql`, variables holding the statement, scripts run by name), unnamed targets
(a default PGHOST that is not in the hook's environment, PGSERVICE), non-SQL deletes (API calls, rm on a
data directory), statements DESTRUCTIVE does not cover (MySQL multi-table `DELETE t FROM t`, mongosh
`deleteMany`/`drop`, redis-cli `FLUSHALL`/`FLUSHDB`/`DEL`), and `mcp__*__execute_sql`-style tools whose text
does not name prod.

Fail direction:
  - Before a match, any error allows. A parser bug must not block ordinary work.
  - After a match, any error denies, including an unreadable approvals store.

Approvals
  ah approve delete --host <exact host or db> --reason "<why>" [--expires 1h]
- The owner (or a supervisor, inside its projects) records it; `ah approvals` lists it. The approval's host must equal,
  case-folded, one of the target values the guard extracts (for example `prod-db.example.com`, or `app_production`).
  It is never a substring match, and an approval without a host covers nothing here. A command with several prod
  targets needs an approval for each one.
- Release 1001 removed `prod_delete_guard.py grant` and its signed grant file: the approvals store is the one record.

Contract (https://code.claude.com/docs/en/hooks): stdin carries {"tool_name", "tool_input", "cwd", ...}.
The output is hookSpecificOutput.permissionDecision "deny", returned on exit 0. Register this hook
without onFailure=block, because it fails open before a match.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
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
    (re.compile(r"(?i)d1_database_query$"), ("sql", "query")),
    (re.compile(r"(?i)^mcp__.*__(execute_sql|run_sql|query|sql)$"), ("sql", "query", "statement")),
)
TOOL_IS_PRODUCTION_BY_CONSTRUCTION = re.compile(r"(?i)^mcp__.*__(d1_database_query|hyperdrive_.*)$")
TOOL_DB_FIELDS = ("database_id", "databaseId", "database", "database_name", "databaseName", "id")
# The built-in matcher; install.py registers matcher(), which adds the local db_tool_patterns. No Bash (release 1001).
# Anchored (Claude Code reads an unanchored matcher as a substring regex): the release 1001 red team found the old one
# firing on mcp__claude_ai_Claude_Docs__query and on any mcp__*__query_* tool.
MATCHER = r"^(?:.*d1_database_query|mcp__.+__(?:execute_sql|run_sql|sql)|mcp__(?!claude_ai_Claude_Docs__).+__query|mcp__.+__hyperdrive_.+)$"
LOCAL_DEFAULT_FIELDS = ("command", "cmd", "script", "sql", "query", "payload")


def local_tool_fields() -> tuple:
    """(compiled full-name regex, fields) for each valid ~/.agent-harness/local.json `db_tool_patterns` entry."""
    out = []
    try:
        import ah_local  # noqa: PLC0415
        for entry in ah_local.get("db_tool_patterns", []):
            if not isinstance(entry, dict) or not isinstance(entry.get("tool"), str) or not entry["tool"]:
                continue
            try:
                pattern = re.compile("^(?:%s)$" % entry["tool"])
            except re.error:
                continue
            fields = tuple(f for f in (entry.get("fields") or LOCAL_DEFAULT_FIELDS) if isinstance(f, str) and f)
            out.append((pattern, fields or LOCAL_DEFAULT_FIELDS, entry["tool"]))
    except Exception:  # noqa: BLE001 - a broken local file adds nothing
        return ()
    return tuple(out)


def matcher() -> str:
    """MATCHER plus every local db tool pattern: the matcher install.py registers. A local pattern that could match
    Bash is left out, so no configuration puts a hook back on Bash."""
    return "|".join([MATCHER] + [raw for pattern, _, raw in local_tool_fields() if not pattern.match("Bash")])

FILE_READ_LIMIT = 200000
MIN_TARGET = 3
DECLINE = re.compile(r"\b(?:no|nope|nah|not|don'?t|never|keep|kept|cancel|skip|stop|leave|hold|wait|later|instead|"
                     r"abort|reject|deny|denied|untouched|preserved?|spare|only\s+after)\b", re.I)
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
        for m in CAT_ARGS.finditer(command):
            paths += [w for w in m.group(1).split() if not w.startswith("-")]
        client = DB_CLIENT.search(command) or D1_EXECUTE.search(command)
        piped.extend("the output of %s" % x for x in _other_substitutions(command[client.start():SHLEX_LIMIT]))
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


def targets_production(command: str, env=None):
    """(description, [target groups]) of the production targets this command names, or ("", []).
    Each group is a tuple of alternative names for one target (a connection string's host and its
    database); an approval naming any one of them covers that target."""
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
                parts = parts[:1]  # a database-only approval ("app") never covers a prod host
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
    for pat, keys in TOOL_COMMAND_FIELDS + tuple((p, f) for p, f, _ in local_tool_fields() if not p.match("Bash")):
        if pat.search(tool):
            return "\n".join(v for v in (_as_text(ti.get(k)) for k in keys) if v.strip())
    return ""


# ---- approvals ----------------------------------------------------------------------------------
def valid_target(target) -> str:
    """'' when a target name can be approved, else why not."""
    if not isinstance(target, str) or len(target) < MIN_TARGET or target != target.strip():
        return "the target must be at least %d characters with no surrounding space" % MIN_TARGET
    if target.startswith("-") or any(ch.isspace() for ch in target) or any(ch in target for ch in "*?[]$`;|&<>'\"#"):
        return "the target must be one host or database name, with no spaces, quotes or wildcards"
    if target.casefold() in RESERVED_TARGETS or DB_CLIENT.fullmatch(target):
        return "%r is a keyword, a client name or bare prod; name the exact host or database" % target
    return ""


def matching_approvals(targets: list, home=None, now=None, records=None):
    """({target group: approval record} for each covered group, why-not for the first uncovered one). Each entry of
    `targets` is a group of alternative names (or one name). A group is covered by a live `delete` approval whose host
    equals one of its names (case-folded) and is a valid target. Raises on an unreadable store (the caller denies)."""
    import ah_approvals  # noqa: PLC0415 - only a matched command reads the store
    rows = list(ah_approvals.records(home) if records is None else records)
    covered = {}
    for target in targets:
        names = (target,) if isinstance(target, str) else tuple(target)
        wanted = {n.casefold() for n in names}
        for record in reversed(rows):
            host = str((record.get("scope") or {}).get("host") or "")
            if host.casefold() in wanted and not valid_target(host) \
                    and ah_approvals.covers(record, "delete", {"host": host}, now):
                covered[target] = record
                break
        else:
            return covered, "%s: no live delete approval names it" % "/".join(names)
    return covered, ""


def approve_hint(target: str) -> str:
    try:
        import ah_approvals  # noqa: PLC0415
        return ah_approvals.command_hint("delete", host=target)
    except Exception:  # noqa: BLE001
        return 'ah approve delete --host %s --reason "<why>"' % target


# ---- hook ---------------------------------------------------------------------------------------
def decision(kind: str, reason: str) -> str:
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": kind,
                                              "permissionDecisionReason": reason}})


def evaluate(ev, home=None, now=None, env=None, records=None):
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
                            "name, so no approval can cover it. Name the host or database explicitly." % (verb, target))
        covered, why = matching_approvals(values, home, now, records)
        if not why:
            return None
        first = next((g for g in values if g not in covered), values[0])
        name = first if isinstance(first, str) else first[0]
        return ("deny", "REFUSED: this command runs %s against %s (targets: %s), and no approval covers it (%s).\n\n"
                        "Production deletes need a RECORDED approval, not one announced in chat. The owner records one "
                        "for each exact target:\n  %s\nOnce approved, do the work; do not refuse after approval."
                        % (verb, target, ", ".join("/".join(g) for g in values), why, approve_hint(name)))
    except Exception as exc:  # noqa: BLE001
        return ("deny", "REFUSED: a destructive statement aimed at a production database was detected and the "
                        "approval check failed (%s). Failing closed is deliberate." % type(exc).__name__)


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
    if argv[:1] in (["grant"], ["list"]):
        print(json.dumps({"status": "REMOVED", "problem": "prod_delete_guard.py %s was removed in release 1001: record "
                          "the approval with `ah approve delete --host <exact target>` and list it with `ah approvals`"
                          % argv[0]}), file=sys.stderr)
        return 2
    print("usage: prod_delete_guard.py (a PreToolUse hook; reads the event on stdin)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:]) if len(sys.argv) > 1 else hook_main())
