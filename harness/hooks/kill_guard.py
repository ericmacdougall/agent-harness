#!/usr/bin/env python3
"""PreToolUse guard against stopping processes the caller does not own (GoodQA #14506; redesign 2026-11-24).

Why: on 2026-11-04 an owner piped `pgrep -f` into `xargs kill` and another ran `pkill -f`; both stopped other owners'
test runs on a shared dev host.

The rule judges EFFECT, not words. It refuses a command only when running it would send a signal to, or stop, a process
the caller may not stop:
  * a broad pattern: `pkill`, `killall`, `pgrep`/`pidof`/`ps | grep`/`lsof -t` fed into `kill`, `fuser -k`, whose matches
    (resolved against the live process table) include a process that is not the caller's;
  * every process at once: `kill -1`, `kill -9 -1`, `kill -- -1`, `killall5`, `tmux kill-server`, `pm2 kill`,
    `docker system prune`, `docker container prune`, `docker kill $(docker ps -q)` and the like;
  * a literal pid (or process group) that is not the caller's and that the caller's role does not cover;
  * a protected process (the harness's own daemons and log backup, and what kill_guard_policy.json marks as
    staging/live), which keeps needing the owner's approval whoever asks.

Who may stop what (roles come from ah_roles; nothing here keeps its own idea of a role):
  * anyone: its own processes, with no approval: descendants of its agent process, pids it started with
    `kill_guard.py spawn`, processes whose cwd or program is in its own work dir, scratch or git worktree, `$!`, `$$`,
    job specs (`%1`), `kill 0`, `pkill -P $$`;
  * a supervisor: also processes whose cwd or program is under a project it supervises;
  * a top-rung caller (Fable or Astra): any process except the protected list.

Never refused: reads (`ps`, `pgrep`, `lsof`, `docker ps`, `ah task list`, grep of an audit log), `--help`/`-l`
forms, prose, quoted text, here-document text, file contents (a test file run by pytest or node is not judged), a
program signalling itself (`os.kill(os.getpid(), ...)`, `kill $$`), `ah kill ...` (ah kill judges and audits itself).
When the analysis cannot parse, times out, fails or is unsure (a pid read from a file, a variable it cannot follow, a
remote host), the command is ALLOWED and one line is logged to ~/.agent-harness/state/kill-guard/audit.jsonl.
A refusal names the one command that proceeds.

Entry points: `hook` (PreToolUse), `analyze` (same, kept for old registrations), `spawn`, `explain`.
Python 3.9+, standard library only.
"""

import hashlib
import hmac
import json
import os
import pwd
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

MAX_STDIN = 8 * 1024 * 1024
MAX_PID = 4194304
MAX_DEPTH = 6
COMMAND_KEYS = ('command', 'cmd', 'script', 'chars', 'input')
EDIT_TOOLS = frozenset({'apply_patch', 'write', 'edit', 'multiedit', 'notebookedit'})
SHELL_TOOLS = ('bash', 'powershell', 'shell', 'local_shell', 'exec_command', 'unified_exec', 'write_stdin',
               'container.exec')
# Cheap prefilter: a command with none of these words cannot stop a process, so it is never parsed.
MAYBE_STOP = re.compile(r'(?i)kill|stop|down|\brm\b|prune|terminate|signal|bootout|unload|remove|delete|restart|pause|'
                        r'taskkill|fuser')

DEFAULT_POLICY = {
    'mode': 'enforce',
    # The harness's own daemons and log backup: regexes searched in a process's command line, a launchd label, a
    # systemd unit, a tmux session, a pm2 app or a container name. Stopping one needs the owner's approval.
    'protected': [r'\bahd(?:\.py)?\b', r'\bahd_peek\b', r'log[_-]backup', r'backup[_-]watch', r'ops[_-]watch',
                  r'\bnetwatch\b', r'\bhookd\b', r'\brclone\b', r'mission[_-]control', r'harness-console',
                  r'com\.agent-harness\.'],  # user-specific labels live in kill_guard_policy.json
    # Staging and live services (the owner fills this in): same matching as `protected`.
    'staging_live': [],
    'child_timeout_seconds': 10,
    'ledger_max_lines': 2000,
}
# Never signalled by anyone: the machine itself and the user's session.
SYSTEM_NAMES = {'launchd', 'init', 'systemd', 'sshd', 'kernel_task', 'windowserver', 'loginwindow', 'login',
                'systemd-logind', 'dbus-daemon'}
AGENT_NAMES = {'claude', 'codex'}
REJECT_ROOTS = {'/', '/tmp', '/private/tmp', '/var', '/private/var', '/var/tmp', '/opt', '/usr', '/private', '/etc',
                '/home', '/Users', '/mnt', '/srv', '/root'}
AH_KILL = 'python3 -I ~/.claude/hooks/ah.py kill --pid %s --reason "<why>"'


# --------------------------------------------------------------------------- policy, state and the audit line

def load_policy(path=None):
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    try:
        with open(path or HERE / 'kill_guard_policy.json', 'rb') as handle:
            loaded = json.loads(handle.read(65536).decode('utf-8', 'replace'))
        if isinstance(loaded, dict):
            for key in DEFAULT_POLICY:
                if key in loaded and type(loaded[key]) is type(DEFAULT_POLICY[key]):
                    policy[key] = loaded[key]
    except (OSError, ValueError):
        pass
    if policy['mode'] not in ('enforce', 'warn', 'off'):
        policy['mode'] = 'enforce'
    try:  # the owner's own launchd label prefixes (~/.agent-harness/local.json)
        import ah_local  # noqa: PLC0415
        if isinstance(policy.get('protected'), list):
            policy['protected'] = policy['protected'] + [re.escape(p) for p in ah_local.protected_label_prefixes()
                                                         if re.escape(p) not in policy['protected']]
    except Exception:  # noqa: BLE001 - a broken local file adds nothing
        pass
    return policy


def one_line(text, limit=400):
    text = ''.join(ch if 32 <= ord(ch) < 127 else ' ' for ch in str(text))
    return re.sub(r'\s+', ' ', text).strip()[:limit]


def state_dir(home=None):
    return Path(home or os.path.expanduser('~')) / '.agent-harness' / 'state' / 'kill-guard'


def _secure_dir_ok(path):
    import stat as stat_mod
    try:
        st = os.lstat(str(path))
    except OSError:
        return False
    return stat_mod.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not (st.st_mode & 0o022)


def audit(rule, raw, pids, home=None, verdict='block'):
    """One redacted line per refusal or unsure allow: no command text, only its hash. Best effort, never raises."""
    try:
        sdir = state_dir(home)
        os.makedirs(str(sdir), mode=0o700, exist_ok=True)
        if not _secure_dir_ok(sdir):
            return
        line = json.dumps({'ts': int(time.time()), 'verdict': verdict, 'rule': rule, 'pids': list(pids)[:16],
                           'sha256': hashlib.sha256(str(raw).encode('utf-8', 'replace')).hexdigest()[:16]})
        fd = os.open(str(sdir / 'audit.jsonl'), os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0),
                     0o600)
        try:
            os.write(fd, (line + '\n').encode('utf-8'))
        finally:
            os.close(fd)
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------- spawn ledger (pids the caller started)

def _read_secure_file(path, limit, tail=False):
    """Bytes of a regular file owned by us that is not group/world writable; None otherwise. Never follows links."""
    import stat as stat_mod
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat_mod.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
            return None
        if tail and st.st_size > limit:
            os.lseek(fd, st.st_size - limit, os.SEEK_SET)
        return os.read(fd, limit)
    except OSError:
        return None
    finally:
        os.close(fd)


def read_key(home=None):
    sdir = state_dir(home)
    if not _secure_dir_ok(sdir):
        return None
    data = _read_secure_file(sdir / 'ledger.key', 256)
    return data if data and 32 <= len(data) <= 128 else None


def ensure_key(home=None):
    sdir = state_dir(home)
    os.makedirs(str(sdir), mode=0o700, exist_ok=True)
    if not _secure_dir_ok(sdir):
        raise OSError('kill_guard state directory is a link, not yours, or group/world writable')
    key = read_key(home)
    if key:
        return key
    fd = os.open(str(sdir / 'ledger.key'), os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        os.write(fd, os.urandom(32))
    finally:
        os.close(fd)
    key = read_key(home)
    if not key:
        raise OSError('kill_guard ledger key could not be created safely')
    return key


def ledger_path(root, home=None):
    return state_dir(home) / ('ledger-%s.jsonl' % hashlib.sha256(root.encode('utf-8', 'replace')).hexdigest()[:16])


def ledger_mac(key, root, pid, start, ts):
    return hmac.new(key, ('%s\n%d\n%s\n%d' % (root, pid, start, ts)).encode('utf-8', 'replace'),
                    hashlib.sha256).hexdigest()


def read_ledger(root, home=None, max_lines=2000):
    """Valid entries (pid, start) for this root. Anything unreadable, unsafe or unauthenticated yields nothing."""
    key = read_key(home)
    if not key:
        return []
    data = _read_secure_file(ledger_path(root, home), 1 << 20, tail=True)
    out = []
    for line in (data or b'').decode('utf-8', 'replace').splitlines()[-max_lines:]:
        try:
            entry = json.loads(line)
            pid, start, ts, mac = int(entry['pid']), str(entry['start']), int(entry['ts']), str(entry['mac'])
            entry_root = str(entry['root'])
        except (ValueError, KeyError, TypeError):
            continue
        if entry_root == root and hmac.compare_digest(mac, ledger_mac(key, root, pid, start, ts)):
            out.append((pid, start))
    return out


def append_ledger(root, pid, start, home=None):
    key = ensure_key(home)
    ts = int(time.time())
    entry = {'pid': pid, 'start': start, 'ts': ts, 'root': root, 'mac': ledger_mac(key, root, pid, start, ts)}
    fd = os.open(str(ledger_path(root, home)), os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0),
                 0o600)
    try:
        os.write(fd, (json.dumps(entry, sort_keys=True) + '\n').encode('utf-8'))
    finally:
        os.close(fd)


CLEAN_ENV = {'PATH': '/usr/sbin:/usr/bin:/bin:/sbin', 'LC_ALL': 'C'}


def _run(argv, timeout=2.0, cwd=None, env=None):
    try:
        done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=timeout, cwd=cwd, env=env or CLEAN_ENV, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    return done.stdout[:1 << 20].decode('utf-8', 'replace')


class Probe:
    """Start time of one pid in the spawn ledger's format (ah_kill.spawn_start uses it)."""

    def start(self, pid):
        if os.path.isdir('/proc/self'):
            try:
                with open('/proc/%d/stat' % pid, 'rb') as handle:
                    text = handle.read(4096).decode('utf-8', 'replace')
            except OSError:
                return None
            fields = text[text.rfind(')') + 2:].split()
            return fields[19] if len(fields) > 20 else None
        out = _run(['ps', '-o', 'lstart=', '-p', str(pid)])
        return out.strip() if out and out.strip() else None


def under(path, root):
    fold = (lambda s: s.casefold()) if sys.platform == 'darwin' else (lambda s: s)
    p, r = fold(path), fold(root)
    return p == r or p.startswith(r.rstrip('/') + '/')


def find_worktree(cwd, home=None, runner=None):
    """(root, nested_worktree_roots) for the git worktree containing cwd, or (None, []). A root that is `/`, HOME or an
    ancestor of HOME is refused: it would 'own' everything."""
    runner = runner or _run
    if not cwd:
        return None, []
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(CLEAN_ENV)
    top = runner(['git', '-C', cwd, 'rev-parse', '--show-toplevel'], 3.0, None, env)
    if not top or not top.strip():
        return None, []
    root = os.path.realpath(top.strip().splitlines()[0])
    home_path = os.path.realpath(home or os.path.expanduser('~'))
    if root in REJECT_ROOTS or under(home_path, root) or root.count('/') < 2:
        return None, []
    nested = []
    for line in (runner(['git', '-C', root, 'worktree', 'list', '--porcelain'], 3.0, None, env) or '').splitlines():
        if line.startswith('worktree '):
            other = os.path.realpath(line[9:].strip())
            if other != root and under(other, root):
                nested.append(other)
    return root, nested


# --------------------------------------------------------------------------- the shell text, read just enough

class Word:
    __slots__ = ('text', 'quoted', 'dynamic', 'subs', 'vars')

    def __init__(self):
        self.text, self.quoted, self.dynamic, self.subs, self.vars = '', False, False, [], []

    def __repr__(self):
        return 'Word(%r)' % self.text


OPERATORS = ('&&', '||', ';;', '|&', ';', '&', '|', '(', ')')
REDIRS = ('<<<', '<<-', '<<', '>>', '>&', '&>>', '&>', '<&', '>|', '<>', '<', '>')
SPECIAL_VARS = '$!?#@*-0123456789'


def _balanced(text, i, open_ch='(', close_ch=')'):
    """Index just past the close that matches the open at text[i-1]; quote-aware. len(text) when unterminated."""
    depth, n = 1, len(text)
    while i < n:
        c = text[i]
        if c == '\\':
            i += 2
            continue
        if c == "'":
            j = text.find("'", i + 1)
            i = n if j < 0 else j + 1
            continue
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == '\\' else 1
            i += 1
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _dollar(text, i, word):
    """Read a $-expansion at text[i] == '$' into word; return the next index."""
    n = len(text)
    nxt = text[i + 1] if i + 1 < n else ''
    if text.startswith('$((', i):
        end = _balanced(text, i + 3)
        end = end + 1 if end < n and text[end] == ')' else end
        word.text += text[i:end]
        word.dynamic = True
        return end
    if nxt == '(':
        end = _balanced(text, i + 2)
        word.subs.append(text[i + 2:end - 1])
        word.text += '$(%s)' % text[i + 2:end - 1]
        word.dynamic = True
        return end
    if nxt == '{':
        end = _balanced(text, i + 2, '{', '}')
        inner = text[i + 2:end - 1]
        name = re.match(r'[!#]?([A-Za-z_][A-Za-z0-9_]*|[%s])' % re.escape(SPECIAL_VARS), inner)
        word.vars.append(name.group(1) if name else inner)
        word.text += '${%s}' % inner
        word.dynamic = True
        return end
    match = re.match(r'[A-Za-z_][A-Za-z0-9_]*', text[i + 1:])
    if match:
        word.vars.append(match.group(0))
        word.text += '$' + match.group(0)
        word.dynamic = True
        return i + 1 + match.end()
    if nxt and nxt in SPECIAL_VARS:
        word.vars.append(nxt)
        word.text += '$' + nxt
        word.dynamic = True
        return i + 2
    word.text += '$'
    return i + 1


ANSI = {'n': '\n', 't': '\t', 'r': '\r', 'a': '\a', 'b': '\b', 'e': '\x1b', 'f': '\f', 'v': '\v', '\\': '\\',
        "'": "'", '"': '"'}


def lex(text):
    """Tokens of a shell text: ('w', Word), ('op', str), ('redir', str), ('body', str) for a here-document or a
    here-string. Never raises on odd input; an unterminated quote just ends the word."""
    tokens, pending_heredocs, i, n = [], [], 0, len(text)
    while i < n:
        c = text[i]
        if c in ' \t':
            i += 1
            continue
        if c == '\\' and i + 1 < n and text[i + 1] == '\n':
            i += 2
            continue
        if c == '\n':
            tokens.append(('op', '\n'))
            i += 1
            for delim, strip in pending_heredocs:
                lines, body = [], ''
                while i < n:
                    j = text.find('\n', i)
                    line = text[i:] if j < 0 else text[i:j]
                    i = n if j < 0 else j + 1
                    if (line.lstrip('\t') if strip else line) == delim:
                        break
                    lines.append(line)
                body = '\n'.join(lines)
                tokens.append(('heredoc', body))
            pending_heredocs = []
            continue
        if c == '#':
            j = text.find('\n', i)
            i = n if j < 0 else j
            continue
        redir = next((r for r in REDIRS if text.startswith(r, i)), None)
        if redir and not (redir == '<' and text.startswith('<(', i)) and not (redir == '>' and text.startswith('>(', i)):
            i += len(redir)
            if redir in ('<<', '<<-'):
                while i < n and text[i] in ' \t':
                    i += 1
                word, i = _word(text, i)
                pending_heredocs.append((word.text, redir == '<<-'))
                continue
            tokens.append(('redir', redir))
            continue
        op = next((o for o in OPERATORS if text.startswith(o, i)), None)
        if op:
            tokens.append(('op', op))
            i += len(op)
            continue
        word, i = _word(text, i)
        if re.fullmatch(r'\d+', word.text) and not word.quoted and i < n and text[i] in '<>':
            continue  # 2>&1: the fd number belongs to the redirection that follows
        tokens.append(('w', word))
    # redirection targets are not argv words; here-strings are bodies
    out, skip = [], False
    for k, tok in enumerate(tokens):
        if skip:
            skip = False
            if tok[0] == 'w':
                if tokens[k - 1][1] == '<<<':
                    out.append(('herestring', tok[1].text))
                continue
        if tok[0] == 'redir':
            skip = True
            continue
        out.append(tok)
    return out


def _word(text, i):
    word, n = Word(), len(text)
    while i < n:
        c = text[i]
        if c in ' \t\n;&|()<>' and not (c in '<>' and i + 1 < n and text[i + 1] == '(' and not word.text):
            break
        if c in '<>':  # process substitution <(...) / >(...)
            end = _balanced(text, i + 2)
            word.subs.append(text[i + 2:end - 1])
            word.text += text[i:end]
            word.dynamic = True
            i = end
            continue
        if c == '\\':
            if i + 1 < n and text[i + 1] != '\n':
                word.text += text[i + 1]
            i += 2
            continue
        if c == "'":
            j = text.find("'", i + 1)
            j = n if j < 0 else j
            word.text += text[i + 1:j]
            word.quoted = True
            i = j + 1
            continue
        if c == '$' and i + 1 < n and text[i + 1] == "'":
            i += 2
            while i < n and text[i] != "'":
                if text[i] == '\\' and i + 1 < n:
                    word.text += ANSI.get(text[i + 1], text[i + 1])
                    i += 2
                else:
                    word.text += text[i]
                    i += 1
            word.quoted = True
            i += 1
            continue
        if c == '"':
            word.quoted = True
            i += 1
            while i < n and text[i] != '"':
                d = text[i]
                if d == '\\' and i + 1 < n:
                    word.text += text[i + 1] if text[i + 1] in '$`"\\\n' else '\\' + text[i + 1]
                    i += 2
                elif d == '$':
                    i = _dollar(text, i, word)
                elif d == '`':
                    j = text.find('`', i + 1)
                    j = n if j < 0 else j
                    word.subs.append(text[i + 1:j])
                    word.text += '`%s`' % text[i + 1:j]
                    word.dynamic = True
                    i = j + 1
                else:
                    word.text += d
                    i += 1
            i += 1
            continue
        if c == '$':
            i = _dollar(text, i, word)
            continue
        if c == '`':
            j = text.find('`', i + 1)
            j = n if j < 0 else j
            word.subs.append(text[i + 1:j])
            word.text += '`%s`' % text[i + 1:j]
            word.dynamic = True
            i = j + 1
            continue
        word.text += c
        i += 1
    return word, i


class Cmd:
    __slots__ = ('words', 'bodies', 'source')

    def __init__(self):
        self.words, self.bodies, self.source = [], [], None  # source: the Cmd list piped into this one


OPENERS = {'while', 'until', 'for', 'if', 'case', 'select', '{'}
CLOSERS = {'done', 'fi', 'esac', '}'}
RESERVED = {'then', 'do', 'else', 'elif', '!', 'time', 'in'} | OPENERS | CLOSERS


def commands(text):
    """Simple commands in order. A command after a pipe gets `source`: the earlier stages of its pipeline; the commands
    inside a loop or group that is a pipeline stage (`pgrep x | while read p; do kill $p; done`) inherit it."""
    out, cur, stages, group, depth = [], Cmd(), [], None, 0  # group: (depth, source) of a compound pipeline stage

    def finish(pipe=False):
        nonlocal cur, stages
        if cur.words or cur.bodies:
            if cur.source is None:
                cur.source = list(stages) if stages else (group[1] if group else None)
            out.append(cur)
            if pipe:
                stages.append(cur)
        if not pipe:
            stages = []
        cur = Cmd()

    for kind, value in lex(text):
        if kind == 'w':
            if not cur.words and not value.quoted:
                if value.text in OPENERS:
                    if stages and group is None:
                        group = (depth, list(stages))
                    depth += 1
                elif value.text in CLOSERS:
                    depth = max(0, depth - 1)
                    if group and depth <= group[0]:
                        cur.source, group = group[1], None
            cur.words.append(value)
        elif kind in ('heredoc', 'herestring'):
            # a here-document belongs to the last command that asked for one
            target = cur if (cur.words or not out) else out[-1]
            target.bodies.append(value)
        elif value in ('|', '|&'):
            finish(pipe=True)
        elif value == '(':
            finish()
            depth += 1
        elif value == ')':
            finish()
            depth = max(0, depth - 1)
        else:
            finish()
    finish()
    return out


# --------------------------------------------------------------------------- the process table and who owns what

class Proc:
    __slots__ = ('pid', 'ppid', 'pgid', 'uid', 'command', 'name')

    def __init__(self, pid, ppid, pgid, uid, command):
        self.pid, self.ppid, self.pgid, self.uid, self.command = pid, ppid, pgid, uid, command
        first = command.split(' ', 1)[0] if command else ''
        self.name = os.path.basename(first).lstrip('-').casefold()


def read_table():
    out = _run(['ps', '-axww', '-o', 'pid=,ppid=,pgid=,uid=,command='], timeout=4.0)
    table = {}
    for line in (out or '').splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4 and all(p.lstrip('-').isdigit() for p in parts[:4]):
            pid = int(parts[0])
            table[pid] = Proc(pid, int(parts[1]), int(parts[2]), int(parts[3]), parts[4] if len(parts) > 4 else '')
    return table


def read_cwds(pids):
    """{pid: cwd} for the pids whose cwd can be read; one lsof call on macOS."""
    pids = [p for p in pids if p > 1][:64]
    found = {}
    if not pids:
        return found
    if os.path.isdir('/proc/self'):
        for pid in pids:
            try:
                found[pid] = os.readlink('/proc/%d/cwd' % pid)
            except OSError:
                pass
        return found
    out = _run(['lsof', '-a', '-d', 'cwd', '-p', ','.join(map(str, pids)), '-Fpn'], timeout=5.0) or ''
    current = None
    for line in out.splitlines():
        if line.startswith('p') and line[1:].isdigit():
            current = int(line[1:])
        elif line.startswith('n') and current is not None:
            found[current] = line[1:]
    return found


class Context:
    """Everything the judge needs to know about the caller and the machine. Tests build one with fixed facts."""

    def __init__(self, payload=None, cwd=None, home=None, policy=None, table=None, ancestors=None, roles=None,
                 cwds=None, ledger=None, own_roots=None, lsof=None, start=None):
        self.payload = payload if isinstance(payload, dict) else {}
        self.cwd = cwd or self.payload.get('cwd') or os.getcwd()
        self.home = home
        self.policy = policy or load_policy()
        self._table, self._ancestors, self._roles, self._cwds = table, ancestors, roles, dict(cwds or {})
        self._ledger, self._own_roots, self._lsof = ledger, own_roots, lsof
        self._start, self._worktree = start or Probe().start, None
        self.notes = []  # allowed stops worth one audit line (a maintainer stopping a protected process)
        self.harness = [re.compile(p) for p in self.policy.get('protected', []) if _compiles(p)]
        self.live = [re.compile(p) for p in self.policy.get('staging_live', []) if _compiles(p)]
        self.patterns = self.harness + self.live

    # ---- facts, read once and lazily
    def table(self):
        if self._table is None:
            self._table = read_table()
        return self._table

    def ancestors(self):
        """The hook's own process chain: the agent session that runs this command and everything above it."""
        if self._ancestors is None:
            chain, pid, table = [], os.getpid(), self.table()
            for _ in range(64):
                if pid is None or pid <= 1 or pid in chain:
                    break
                chain.append(pid)
                pid = table[pid].ppid if pid in table else None
            self._ancestors = chain
        return self._ancestors

    def agent_pid(self):
        """Nearest ancestor that is a claude or codex process: its descendants are the caller's own."""
        table = self.table()
        for pid in self.ancestors():
            proc = table.get(pid)
            if proc and (proc.name in AGENT_NAMES or (proc.name in ('node', 'bun') and re.search(
                    r'(?i)claude|codex', proc.command.split(' ', 2)[1] if ' ' in proc.command else ''))):
                return pid
        return None

    def roles(self):
        if self._roles is None:
            try:
                import ah_roles  # noqa: PLC0415
                fn = getattr(ah_roles, 'may_edit_harness', None)
                maintainer = bool(fn(self.payload) if fn else (ah_roles.is_top_rung(self.payload)
                                                               and ah_roles.is_supervisor(self.payload, self.home)))
                self._roles = {'top': ah_roles.is_top_rung(self.payload), 'maintainer': maintainer,
                               'supervised': [os.path.realpath(str(p)) for p in ah_roles.supervised_roots(self.payload, self.home)],
                               'own': [os.path.realpath(str(p)) for p in ah_roles.own_roots(self.payload, self.home)]}
            except Exception:  # noqa: BLE001 - unknown means the least privilege
                self._roles = {'top': False, 'maintainer': False, 'supervised': [], 'own': []}
        return self._roles

    def own_roots(self):
        """(roots, excluded): the caller's work dir and scratch (ah_roles) and the git worktree of its cwd, minus
        worktrees nested inside it (those are other owners')."""
        if self._own_roots is None:
            roots = list(self.roles()['own'])
            self._worktree, nested = find_worktree(self.cwd, self.home)
            if self._worktree:
                roots.append(self._worktree)
            self._own_roots = (roots, nested)
        return self._own_roots

    def ledger(self):
        if self._ledger is None:
            self.own_roots()
            root = self._worktree
            self._ledger = set(read_ledger(root, self.home)) if root else set()
        return self._ledger

    def cwd_of(self, pids):
        missing = [p for p in pids if p not in self._cwds]
        if missing:
            found = read_cwds(missing)
            for p in missing:
                self._cwds[p] = found.get(p)
        return {p: self._cwds.get(p) for p in pids}

    def lsof_pids(self, args):
        if self._lsof is not None:
            return self._lsof(args)
        out = _run(['lsof', '-t'] + [a for a in args if a not in ('-t',)], timeout=5.0)
        if out is None:
            return None
        return [int(x) for x in out.split() if x.isdigit()]

    # ---- the decisions
    def protected_text(self, text):
        return any(p.search(text or '') for p in self.patterns)

    def _paths(self, proc, cwd):
        words = proc.command.split()[:4]
        return [w for w in [cwd] + words if w and w.startswith('/')]

    def judge(self, pids):
        """{pid: (ok, why)} for literal pids. ok is True when the caller may stop it without approval."""
        table, ancestors, out = self.table(), set(self.ancestors()), {}
        agent = self.agent_pid()
        need_paths = []
        for pid in pids:
            proc = table.get(pid)
            if pid <= 1:
                out[pid] = (False, 'pid %d is init or invalid' % pid)
            elif proc is None:
                out[pid] = (True, 'no such process')  # kill of a gone pid fails harmlessly
            elif pid in ancestors:
                out[pid] = (False, 'pid %d is the agent session that runs this command' % pid)
            elif proc.name in SYSTEM_NAMES:
                out[pid] = (False, 'pid %d is a system process (%s)' % (pid, proc.name))
            elif agent and self._descends(pid, agent):
                out[pid] = (True, 'started by this agent session')
            else:
                need_paths.append(pid)
        if need_paths:
            cwds = self.cwd_of(need_paths)
            roots, nested = self.own_roots()
            roles = self.roles()
            for pid in need_paths:
                proc = table[pid]
                paths = self._paths(proc, cwds.get(pid))
                protected = self.protected_text(proc.command)
                if not protected and any(_inside(p, roots, nested) for p in paths):
                    out[pid] = (True, 'runs in your own work dir or worktree')
                elif not protected and self._in_ledger(pid):
                    out[pid] = (True, 'started with kill_guard.py spawn')
                elif protected and roles.get('maintainer') and not any(r.search(proc.command) for r in self.live):
                    self.notes.append('harness maintainer stops protected pid %d' % pid)
                    out[pid] = (True, 'harness maintainer (Fable/Astra supervisor) may stop a harness daemon')
                elif protected:
                    out[pid] = (False, 'pid %d is protected (harness daemon, log backup or staging/live): %s' % (
                        pid, one_line(proc.name, 40)))
                elif roles['supervised'] and any(_inside(p, roles['supervised'], []) for p in paths):
                    out[pid] = (True, 'in a project you supervise')
                elif roles['top']:
                    out[pid] = (True, 'top rung (Fable/Astra) may stop it')
                elif proc.uid != os.getuid():
                    out[pid] = (False, 'pid %d belongs to another user' % pid)
                else:
                    out[pid] = (False, 'pid %d (%s) is not yours: not started by this session, not in your work dir '
                                'or worktree' % (pid, one_line(proc.name, 40)))
        return out

    def _descends(self, pid, root):
        table, seen = self.table(), set()
        while pid in table and pid not in seen and pid > 1:
            if pid == root:
                return True
            seen.add(pid)
            pid = table[pid].ppid
        return pid == root

    def _in_ledger(self, pid):
        ledger = self.ledger()
        if not ledger:
            return False
        return (pid, self._start(pid)) in ledger

    def named_unit(self, name):
        """(ok, why) for a named service, container, session or label (no pid to judge)."""
        if self.protected_text(name):
            if self.roles().get('maintainer') and not any(r.search(name or '') for r in self.live):
                self.notes.append('harness maintainer stops protected unit %s' % one_line(name, 60))
                return True, 'harness maintainer'
            return False, '%s is protected (harness daemon, log backup or staging/live)' % one_line(name, 60)
        return True, 'named unit'


def _compiles(pattern):
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def _inside(path, roots, nested):
    norm = os.path.normpath(path)
    return any(under(norm, r) for r in roots) and not any(under(norm, n) for n in nested)


# --------------------------------------------------------------------------- the analysis

class Finding(Exception):
    """A refusal: rule, reason, the one command that proceeds, the pids."""

    def __init__(self, rule, reason, proceed, pids=()):
        super().__init__(reason)
        self.rule, self.reason, self.proceed, self.pids = rule, reason, proceed, tuple(pids)


WRAPPERS_WITH_VALUES = {
    'sudo': {'-u', '-g', '-C', '-D', '-h', '-p', '-r', '-t', '-U'},
    'env': {'-u', '-C', '-S', '--unset', '--chdir'},
    'nice': {'-n', '--adjustment'},
    'ionice': {'-c', '-n', '-p'},
    'timeout': {'-s', '-k', '--signal', '--kill-after'},
    'stdbuf': {'-i', '-o', '-e'},
    'chrt': set(), 'taskset': set(), 'nohup': set(), 'time': set(), 'command': set(), 'builtin': set(),
    'exec': {'-a'}, 'setsid': set(), 'caffeinate': {'-t', '-w'}, 'unbuffer': set(), 'doas': {'-u'},
    'flock': {'-w', '-E', '-c'}, 'xargs': {'-I', '-i', '-n', '-P', '-L', '-d', '-E', '-s', '-a'},
}
SHELL_NAMES = {'sh', 'bash', 'zsh', 'dash', 'ksh', 'fish'}
INTERP_CODE = {'python': '-c', 'python3': '-c', 'node': '-e', 'nodejs': '-e', 'perl': '-e', 'ruby': '-e', 'bun': '-e',
               'deno': 'eval'}
HELP_FLAGS = {'--help', '-h', '-help', '--version', '-V', '-l', '-L', '--list', '-t', '--table'}
VERBS = {'kill': 'kill', 'pkill': 'pkill', 'killall': 'killall', 'killall5': 'killall5', 'fuser': 'fuser',
         'docker': 'docker', 'podman': 'docker', 'nerdctl': 'docker', 'docker-compose': 'compose',
         'podman-compose': 'compose', 'systemctl': 'systemctl', 'launchctl': 'launchctl', 'tmux': 'tmux', 'pm2': 'pm2',
         'netwatch': 'netwatch', 'loginctl': 'loginctl', 'taskkill': 'taskkill', 'taskkill.exe': 'taskkill',
         'stop-process': 'taskkill'}


def basename(word):
    return os.path.basename(word.text).casefold() if word.text else ''


class Analyzer:
    def __init__(self, ctx, remote=False):
        self.ctx = ctx
        self.remote = remote
        self.vars = {}  # name -> ('own'|'finder'|'literal'|'unknown', value or finder stages)
        self.unsure = []  # one-line reasons for an allow that could not be proven either way

    # ---- walking
    def script(self, text, depth=0):
        if depth > MAX_DEPTH:
            self.unsure.append('nested too deep')
            return
        for cmd in commands(text):
            self.command(cmd, depth)

    def command(self, cmd, depth):
        words = list(cmd.words)
        while words and not words[0].quoted and words[0].text in RESERVED:
            if words[0].text == 'for' and len(words) >= 2:
                self.bind_for(words)
                return
            words = words[1:]
        assigns = []
        while words and re.match(r'[A-Za-z_][A-Za-z0-9_]*=', words[0].text) and not words[0].text.startswith('='):
            assigns.append(words.pop(0))
        for w in words:  # substitutions run wherever they stand
            for sub in w.subs:
                self.script(sub, depth + 1)
        for w in assigns:
            for sub in w.subs:
                self.script(sub, depth + 1)
        if not words:
            for w in assigns:
                self.assign(w)
            return
        self.run(words, cmd, depth)

    def assign(self, word):
        name, _, value = word.text.partition('=')
        if word.vars and set(word.vars) <= {'!', '$', 'BASHPID'} and not word.subs:
            self.vars[name] = ('own', None)
        elif word.subs:
            finder = self.finder_of_text(word.subs[0])
            self.vars[name] = ('finder', finder) if finder else ('unknown', None)
        elif word.dynamic:
            self.vars[name] = ('unknown', None)
        else:
            self.vars[name] = ('literal', value)

    def bind_for(self, words):
        name = words[1].text
        items = words[3:] if len(words) > 2 and words[2].text == 'in' else []
        finder = None
        for w in items:
            for sub in w.subs:
                finder = finder or self.finder_of_text(sub)
        if finder:
            self.vars[name] = ('finder', finder)
        elif items and all(not w.dynamic for w in items):
            self.vars[name] = ('literal', ' '.join(w.text for w in items))
        else:
            self.vars[name] = ('unknown', None)

    def run(self, words, cmd, depth):
        name = basename(words[0])
        args = words[1:]
        if name.startswith('g') and name[1:] in ('kill', 'timeout', 'xargs', 'env', 'nice', 'nohup'):
            name = name[1:]  # Homebrew coreutils
        if name == 'read':
            for w in args:
                if not w.text.startswith('-') and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', w.text):
                    finder = self.finder_of_stages(cmd.source) if cmd.source else None
                    self.vars[w.text] = ('finder', finder) if finder else ('unknown', None)
            return
        if name in ('export', 'declare', 'local', 'readonly', 'typeset'):
            for w in args:
                if '=' in w.text and not w.text.startswith('-'):
                    self.assign(w)
            return
        if name in WRAPPERS_WITH_VALUES:
            rest = self.unwrap(name, args)
            if rest is None:
                return
            if name == 'xargs':
                self.xargs(rest, cmd, depth)
                return
            if rest:
                self.run(rest, cmd, depth)
            return
        if name == 'watch':
            texts = [a.text for a in args]
            i = 0
            while i < len(texts) and texts[i].startswith('-'):
                i += 2 if texts[i] in ('-n', '-d', '--interval') else 1
            self.script(' '.join(texts[i:]), depth + 1)
            return
        if name in SHELL_NAMES:
            self.shell(args, cmd, depth)
            return
        if name in ('eval',):
            self.script(' '.join(a.text for a in args), depth + 1)
            return
        if name in ('ssh', 'mosh'):
            self.ssh(args, depth)
            return
        if name in ('kubectl', 'oc') and 'exec' in [a.text for a in args[:2]]:
            texts = [a.text for a in args]
            if '--' in texts:
                self.remote_command(args[texts.index('--') + 1:], depth, argv=True)
            return
        base = re.sub(r'[0-9.]+$', '', name)
        if base in INTERP_CODE or name in INTERP_CODE:
            self.interpreter(base if base in INTERP_CODE else name, args)
            return
        if name in ('docker', 'podman', 'nerdctl') and args and args[0].text == 'exec':
            self.container_exec(args[1:], depth)
            return
        verb = VERBS.get(name)
        if verb:
            getattr(self, 'verb_' + verb)(args, cmd)
        elif name in ('kill_guard.py', 'kill_guard'):
            self.spawned(args, depth)

    def container_exec(self, args, depth):
        texts, i = [a.text for a in args], 0
        while i < len(texts) and texts[i].startswith('-'):
            i += 2 if texts[i] in ('-u', '--user', '-w', '--workdir', '-e', '--env', '--env-file') else 1
        if i + 1 < len(args):
            self.remote_command(args[i + 1:], depth, argv=True)

    def unwrap(self, name, args):
        """The words after a wrapper's own options, or None when nothing runs."""
        takes = WRAPPERS_WITH_VALUES[name]
        i = 0
        while i < len(args):
            t = args[i].text
            if name in ('env',) and re.match(r'[A-Za-z_][A-Za-z0-9_]*=', t):
                i += 1
                continue
            if t == '--':
                i += 1
                break
            if not t.startswith('-') or t == '-':
                break
            if t in HELP_FLAGS and name != 'xargs' and t in ('--help', '--version'):
                return None
            if t in takes or (len(t) == 2 and t in takes):
                i += 2
                continue
            if name == 'env' and t.startswith('-S'):
                return None
            i += 1
        rest = args[i:]
        if name == 'timeout' and rest:
            rest = rest[1:]  # the duration
        if name == 'nice' and rest and re.fullmatch(r'-?\d+', rest[0].text):
            rest = rest[1:]
        if name in ('chrt', 'taskset') and rest:
            rest = rest[1:]
        return rest

    def shell(self, args, cmd, depth):
        texts = [a.text for a in args]
        for i, t in enumerate(texts):
            if re.fullmatch(r'-[a-zA-Z]*c[a-zA-Z]*', t) and i + 1 < len(texts):
                self.script(texts[i + 1], depth + 1)
                return
            if not t.startswith('-'):
                return  # a script file: its contents are not judged
        for body in cmd.bodies:  # bash <<EOF ... EOF, bash -s <<< "..."
            self.script(body, depth + 1)

    def ssh(self, args, depth):
        texts, i = [a.text for a in args], 0
        value_opts = set('bcDEeFIiJLlmOopQRSWw')
        while i < len(texts):
            t = texts[i]
            if t.startswith('-') and len(t) > 1:
                i += 2 if t[-1] in value_opts and len(t) == 2 else 1
                continue
            break
        rest = args[i + 1:]
        if rest and rest[0].text == '--':
            rest = rest[1:]
        if rest:
            self.remote_command(rest, depth)

    def remote_command(self, words, depth, argv=False):
        """ssh joins its words with spaces and the remote shell reads them again; an exec gets them as argv."""
        sub = Analyzer(self.ctx, remote=True)
        sub.vars = dict(self.vars)
        sub.script(' '.join((_requote(w) if argv else w.text) for w in words), depth + 1)
        self.unsure.extend(sub.unsure)

    def interpreter(self, name, args):
        """Inline code only (python -c, node -e ...); a script file or a test runner is never read."""
        flag = INTERP_CODE[name]
        texts = [a.text for a in args]
        if flag not in texts:
            return
        k = texts.index(flag)
        code = texts[k + 1] if k + 1 < len(texts) else ''
        for match in re.finditer(r'\b(?:os\.kill|os\.killpg|process\.kill|Process\.kill|posix\.kill)\s*\(\s*([^,)]*)', code):
            target = match.group(1).strip()
            if re.fullmatch(r'-?\d+', target):
                n = int(target)
                if n == -1:
                    raise Finding('broad-kill', 'inline code signals every process (pid -1)', 'kill <pid> for each of yours')
                if n == 0:
                    continue
                self.check_pids([abs(n)], group=n < 0)
            elif re.search(r'getpid|process\.pid|\$\$|getppid', target):
                continue  # itself (getppid: the shell that runs it, also the caller's)
            else:
                self.unsure.append('inline code signals a computed pid')

    def spawned(self, args, depth):
        texts = [a.text for a in args]
        if 'spawn' in texts and '--' in texts and args[texts.index('--') + 1:]:
            self.run(args[texts.index('--') + 1:], Cmd(), depth + 1)

    # ---- verbs
    def verb_kill(self, args, cmd):
        texts = [a.text for a in args]
        if not args or texts[0] in HELP_FLAGS or texts[0] in ('-0', '-s0') or texts[:2] in (['-s', '0'], ['-n', '0']):
            return
        i, signal_given = 0, False
        if texts[0] in ('-s', '-n', '--signal'):
            i, signal_given = 2, True
        elif texts[0].startswith('--signal=') or re.fullmatch(r'-(?:SIG)?[A-Za-z0-9+]{1,12}', texts[0]):
            i, signal_given = 1, True
            if texts[0] == '-1' and len(args) == 1:
                raise Finding('broad-kill', '`kill -1` signals every process you can reach in some shells',
                              'kill <pid> for each process of yours')
        if i < len(texts) and texts[i] == '--':
            i += 1
        targets = args[i:]
        if not targets and signal_given:
            return
        pids, groups = [], []
        for w in targets:
            t = w.text
            if t in ('-1', '--1'):
                raise Finding('broad-kill', '`kill -1` signals every process you own, other owners\' included',
                              'kill <pid> for each process of yours')
            if t.startswith('%') and not w.dynamic:
                continue  # a job of this shell
            if not w.dynamic and re.fullmatch(r'-?\d{1,10}', t):
                n = int(t)
                if n == 0:
                    continue  # this shell's own process group
                (groups if n < 0 else pids).append(abs(n))
                continue
            self.dynamic_target(w)
        if self.remote:
            if pids or groups:
                self.unsure.append('kill on a remote host: ownership cannot be read from here')
            return
        if pids:
            self.check_pids(pids)
        if groups:
            self.check_pids(groups, group=True)

    def dynamic_target(self, word):
        """A kill target the text does not spell out."""
        if re.fullmatch(r'-?\$\{?(?:\$|!|BASHPID)\}?', word.text):
            return  # this shell, its last background job or its parent: the caller's own
        kinds = [self.vars.get(v, ('unknown', None)) for v in word.vars]
        if word.vars and all(k[0] == 'own' or v in ('$', '!', 'BASHPID') for k, v in zip(kinds, word.vars)) and not word.subs:
            return
        for v, (kind, value) in zip(word.vars, kinds):
            if kind == 'finder':
                self.resolve_finder(value)
                return
            if kind == 'literal' and value:
                pids = [int(x) for x in value.split() if re.fullmatch(r'\d{1,10}', x)]
                if pids and not self.remote:
                    self.check_pids(pids)
                    return
        for sub in word.subs:
            finder = self.finder_of_text(sub)
            if finder:
                self.resolve_finder(finder)
                return
        self.unsure.append('a kill target comes from a variable or command the guard does not follow')

    def xargs(self, rest, cmd, depth):
        if not rest:
            return
        name = basename(rest[0])
        if name == 'kill' or (name in SHELL_NAMES and any('kill' in a.text for a in rest[1:])):
            if name == 'kill':
                self.verb_kill([a for a in rest[1:]], cmd)  # its literal targets, if any
            finder = self.finder_of_stages(cmd.source) if cmd.source else None
            if finder:
                self.resolve_finder(finder)
            else:
                self.unsure.append('xargs kill reads its targets from a command the guard does not follow')
            return
        self.run(rest, cmd, depth)

    def verb_pkill(self, args, cmd):
        texts = [a.text for a in args]
        if not texts or any(t in ('--help', '-h', '-V', '--version') for t in texts):
            return
        spec = self.pgrep_spec(args)
        if spec is None:
            return
        if self.remote:
            self.remote_broad('pkill')
            return
        self.resolve_spec(spec, 'pkill')

    def verb_killall(self, args, cmd):
        texts = [a.text for a in args]
        if not texts or any(t in ('--help', '-h', '-l', '--list', '-V', '--version') for t in texts):
            return
        names, regex, ignore, user, i = [], False, False, None, 0
        while i < len(texts):
            t = texts[i]
            if t in ('-s', '--signal', '-u', '--user', '-o', '-y', '--older-than', '--younger-than', '-c', '-t', '-n'):
                if t in ('-u', '--user'):
                    user = texts[i + 1] if i + 1 < len(texts) else None
                i += 2
                continue
            if t.startswith('-') and len(t) > 1:
                regex = regex or t in ('-r', '--regexp')
                ignore = ignore or t in ('-I', '--ignore-case')
                i += 1
                continue
            names.append(t)
            i += 1
        if not names:
            if user is not None or '-m' in texts:
                raise Finding('broad-kill', '`killall` without a name signals every process it matches',
                              'kill <pid> for each process of yours')
            return
        if self.remote:
            self.remote_broad('killall')
            return
        flags = re.I if ignore else 0
        if regex:
            pats = [_regex(n, flags) for n in names]
            match = lambda p: any(r.search(p.name) for r in pats)  # noqa: E731
        else:
            wanted = {n.casefold() for n in names}
            match = lambda p: p.name in wanted or (ignore and p.name.casefold() in wanted)  # noqa: E731
        self.resolve_matches([p for p in self.ctx.table().values() if match(p) and _uid_ok(p, user)], 'killall')

    def verb_killall5(self, args, cmd):
        raise Finding('broad-kill', '`killall5` signals every process on the machine', 'kill <pid> for each process of yours')

    def verb_fuser(self, args, cmd):
        texts = [a.text for a in args]
        if not any(re.fullmatch(r'-[a-zA-Z]*k[a-zA-Z]*', t) or t == '--kill' for t in texts):
            return
        targets = [t for t in texts if not t.startswith('-')]
        lsof_args = []
        for t in targets:
            m = re.fullmatch(r'(\d+)/(tcp|udp)', t)
            lsof_args += ['-i', '%s:%s' % (m.group(2), m.group(1))] if m else [t]
        self.resolve_lsof(lsof_args, 'fuser -k')

    def verb_netwatch(self, args, cmd):
        texts = [a.text.lower() for a in args]
        if 'orphans' not in texts or not any(t in ('--kill', '-kill') for t in texts):
            return
        pids = []
        for i, t in enumerate(texts):
            value = texts[i + 1] if t in ('--pid', '-pid') and i + 1 < len(texts) else (
                t.split('=', 1)[1] if t.startswith(('--pid=', '-pid=')) else None)
            if value is not None:
                pids += [int(p) for p in value.split(',') if p.isdigit()]
        if not pids:
            raise Finding('broad-kill', '`netwatch orphans --kill` without --pid signals every orphan',
                          'netwatch orphans --kill --pid <pid>')
        if not self.remote:
            self.check_pids(pids)

    def verb_docker(self, args, cmd):
        texts = [a.text for a in args]
        if not texts or any(t in ('--help', '-h') for t in texts):
            return
        if texts[0] == 'compose':
            self.verb_compose(args[1:], cmd)
            return
        sub = texts[0] if texts[0] != 'container' else (texts[1] if len(texts) > 1 else '')
        rest = args[1:] if texts[0] != 'container' else args[2:]
        if texts[:2] in (['system', 'prune'], ['container', 'prune']) or texts[:1] == ['prune']:
            if not any(t.startswith('--filter') for t in texts):
                raise Finding('broad-kill', '`docker %s` removes every stopped container, other owners\' included'
                              % ' '.join(texts[:2]), 'docker rm <container> for each container of yours')
            return
        if sub not in ('kill', 'stop', 'rm', 'restart', 'pause'):
            return
        for w in rest:
            if w.text.startswith('-'):
                continue
            if w.dynamic:
                subs = ' '.join(w.subs)
                if re.search(r'\bdocker\s+(?:container\s+)?(?:ps|ls)\b', subs) and '--filter' not in subs \
                        and not re.search(r'\s-f\s', subs):
                    raise Finding('broad-kill', '`docker %s $(docker ps -q)` stops every container, other owners\' '
                                  'included' % sub, 'docker %s <container> for each container of yours' % sub)
                self.unsure.append('docker %s of a computed container' % sub)
                continue
            ok, why = self.ctx.named_unit(w.text)
            if not ok:
                self.protected(why, 'docker %s %s' % (sub, w.text))

    def verb_compose(self, args, cmd):
        texts = [a.text for a in args]
        if not any(t in ('down', 'stop', 'kill', 'rm', 'restart', 'pause') for t in texts):
            return
        for i, t in enumerate(texts):
            name = texts[i + 1] if t in ('-p', '--project-name') and i + 1 < len(texts) else (
                t.split('=', 1)[1] if t.startswith('--project-name=') else None)
            if name:
                ok, why = self.ctx.named_unit(name)
                if not ok:
                    self.protected(why, 'docker compose -p %s down' % name)

    def verb_systemctl(self, args, cmd):
        texts = [a.text for a in args]
        actions = {'stop', 'kill', 'restart', 'disable', 'mask', 'isolate', 'poweroff', 'reboot', 'halt'}
        verbs = [t for t in texts if t in actions]
        if not verbs:
            return
        if any(t in ('isolate', 'poweroff', 'reboot', 'halt') for t in verbs):
            raise Finding('broad-kill', '`systemctl %s` stops everything on the machine' % verbs[0], 'systemctl --user stop <unit>')
        units = [t for t in texts if not t.startswith('-') and t not in actions and t != '--now']
        for unit in units:
            ok, why = self.ctx.named_unit(unit)
            if not ok:
                self.protected(why, 'systemctl --user stop %s' % unit)
        if '--user' not in texts and units and not self.ctx.roles()['top']:
            raise Finding('not-yours', 'a system unit (%s) is not the caller\'s; only a --user unit is'
                          % one_line(units[0], 60), 'systemctl --user stop <your unit>')

    def verb_launchctl(self, args, cmd):
        texts = [a.text for a in args]
        if not texts or texts[0] not in ('kill', 'stop', 'bootout', 'remove', 'unload', 'disable'):
            return
        for t in texts[1:]:
            if not t.startswith('-'):
                ok, why = self.ctx.named_unit(t)
                if not ok:
                    self.protected(why, 'launchctl %s %s' % (texts[0], t))

    def verb_tmux(self, args, cmd):
        texts = [a.text for a in args]
        if 'kill-server' in texts:
            raise Finding('broad-kill', '`tmux kill-server` ends every tmux session, other owners\' included',
                          'tmux kill-session -t <your session>')
        if 'kill-session' in texts or 'kill-window' in texts or 'kill-pane' in texts:
            for i, t in enumerate(texts):
                if t == '-t' and i + 1 < len(texts):
                    ok, why = self.ctx.named_unit(texts[i + 1])
                    if not ok:
                        self.protected(why, 'tmux kill-session -t %s' % texts[i + 1])

    def verb_pm2(self, args, cmd):
        texts = [a.text for a in args]
        if texts[:1] == ['kill']:
            raise Finding('broad-kill', '`pm2 kill` stops the pm2 daemon and every app it runs', 'pm2 stop <your app>')
        if texts[:1] and texts[0] in ('stop', 'delete', 'restart'):
            for t in texts[1:]:
                if t == 'all':
                    raise Finding('broad-kill', '`pm2 %s all` stops every pm2 app' % texts[0], 'pm2 %s <your app>' % texts[0])
                ok, why = self.ctx.named_unit(t)
                if not ok:
                    self.protected(why, 'pm2 %s %s' % (texts[0], t))

    def verb_loginctl(self, args, cmd):
        texts = [a.text for a in args]
        if texts[:1] and texts[0] in ('kill-session', 'kill-user', 'terminate-user', 'terminate-session'):
            raise Finding('broad-kill', '`loginctl %s` ends a whole login session' % texts[0], 'kill <pid> for each process of yours')

    def verb_taskkill(self, args, cmd):
        texts = [a.text.lower() for a in args]
        if any(t in ('/im', '-name', '-processname') for t in texts):
            raise Finding('broad-kill', 'stopping processes by image name hits every process of that name',
                          'Stop-Process -Id <pid> for each process of yours')
        self.unsure.append('a Windows stop by pid: ownership cannot be read from here')

    def protected(self, why, command):
        raise Finding('protected', why + '; it keeps needing the owner\'s approval',
                      'register an ask (wal_note.py --event ask), then after the owner answers: %s' % command)

    def remote_broad(self, verb):
        if self.ctx.roles()['top']:
            self.unsure.append('a top-rung %s on a remote host' % verb)
            return
        raise Finding('broad-kill', '`%s` on a remote host signals by pattern and can hit other owners there' % verb,
                      'ssh <host> pgrep -fl <pattern>, then ssh <host> kill <pid> for each of yours')

    # ---- finders (what produces pids for kill)
    def finder_of_text(self, text):
        cmds = commands(text)
        return self.finder_of_stages(cmds) if cmds else None

    def finder_of_stages(self, stages):
        """A description of the pid producer: ('pgrep', spec) | ('lsof', args) | ('ps', pattern) | ('own',) | None."""
        if not stages:
            return None
        first = stages[0].words
        if not first:
            return None
        name, args = basename(first[0]), first[1:]
        if name in WRAPPERS_WITH_VALUES and name != 'xargs':
            args = self.unwrap(name, args) or []
            if not args:
                return None
            name, args = basename(args[0]), args[1:]
        texts = [a.text for a in args]
        if name == 'jobs':
            return ('own',)
        if name == 'pgrep':
            spec = self.pgrep_spec(args)
            return ('pgrep', spec) if spec else None
        if name == 'pidof':
            return ('names', [t for t in texts if not t.startswith('-')])
        if name == 'lsof':
            return ('lsof', texts)
        if name == 'fuser':
            return ('lsof', [t for t in texts if not t.startswith('-')])
        if name in ('ps', 'pstree'):
            pattern, invert = None, []
            for stage in stages[1:]:
                sw = stage.words
                if not sw:
                    continue
                sname, sargs = basename(sw[0]), [a.text for a in sw[1:]]
                if sname in ('grep', 'egrep', 'rg'):
                    ops = [a for a in sargs if not a.startswith('-')]
                    if not ops:
                        continue
                    if '-v' in sargs:
                        invert.append(ops[0])
                    elif pattern is None:
                        pattern = ops[0]
                elif sname == 'awk' and pattern is None:
                    m = re.search(r'/((?:[^/\\]|\\.)+)/', ' '.join(sargs))
                    if m:
                        pattern = m.group(1)
            return ('ps', pattern, invert, texts)
        if name == 'cat' or name == 'head' or name == 'tail':
            return None
        return None

    def resolve_finder(self, finder):
        if finder is None:
            self.unsure.append('a pid producer the guard does not follow')
            return
        if self.remote:
            if finder[0] in ('pgrep', 'ps', 'names', 'lsof'):
                self.remote_broad(finder[0])
            return
        kind = finder[0]
        if kind == 'own':
            return
        if kind == 'pgrep':
            self.resolve_spec(finder[1], 'pgrep | kill')
        elif kind == 'names':
            wanted = {n.casefold() for n in finder[1]}
            self.resolve_matches([p for p in self.ctx.table().values() if p.name in wanted], 'pidof | kill')
        elif kind == 'lsof':
            self.resolve_lsof(finder[1], 'lsof -t | kill')
        elif kind == 'ps':
            _, pattern, invert, _texts = finder
            if pattern is None:
                raise Finding('broad-kill', 'kill fed from `ps` with no filter signals every process it lists',
                              'kill <pid> for each process of yours')
            pat = _regex(pattern, 0)
            inv = [_regex(x, 0) for x in invert]
            self.resolve_matches([p for p in self.ctx.table().values()
                                  if pat.search(p.command) and not any(r.search(p.command) for r in inv)], 'ps | grep | kill')

    def resolve_lsof(self, args, label):
        if any(re.search(r'[`$;|&]', a) for a in args):
            self.unsure.append('%s with a computed selection' % label)
            return
        pids = self.ctx.lsof_pids(args)
        if pids is None:
            self.unsure.append('%s: lsof could not be run' % label)
            return
        self.check_pids(sorted(set(pids)), label=label)

    def pgrep_spec(self, args):
        """{'pattern', 'full', 'exact', 'ignore', 'parents', 'user', 'invert'} or None when pgrep/pkill would match
        nothing it can be judged on (only options)."""
        spec = {'pattern': None, 'full': False, 'exact': False, 'ignore': False, 'parents': None, 'user': None,
                'invert': False, 'own_parent': False, 'pidfile': False}
        i = 0
        while i < len(args):
            w = args[i]
            t = w.text
            if t in ('-P', '--parent', '-u', '--euid', '-U', '--uid', '-g', '--pgroup', '-G', '--group', '-s',
                     '--session', '-t', '--terminal', '-F', '--pidfile', '--signal', '-q'):
                value = args[i + 1] if i + 1 < len(args) else None
                if t in ('-P', '--parent') and value is not None:
                    if re.fullmatch(r'\$\{?(?:\$|BASHPID)\}?', value.text):
                        spec['own_parent'] = True
                    elif not value.dynamic:
                        spec['parents'] = {int(x) for x in value.text.split(',') if x.isdigit()}
                    else:
                        spec['own_parent'] = value.vars and all(self.vars.get(v, ('',))[0] == 'own' for v in value.vars)
                elif t in ('-u', '--euid', '-U', '--uid') and value is not None:
                    spec['user'] = value.text
                elif t in ('-F', '--pidfile'):
                    spec['pidfile'] = True
                i += 2
                continue
            if t.startswith('-') and len(t) > 1 and not w.dynamic:
                if re.fullmatch(r'-(?:SIG)?[A-Z0-9]+|-\d+', t) or t.startswith('--signal='):
                    i += 1
                    continue
                for letter in t[1:] if not t.startswith('--') else []:
                    spec['full'] |= letter == 'f'
                    spec['exact'] |= letter == 'x'
                    spec['ignore'] |= letter == 'i'
                    spec['invert'] |= letter == 'v'
                spec['full'] |= t == '--full'
                spec['exact'] |= t == '--exact'
                spec['ignore'] |= t == '--ignore-case'
                spec['invert'] |= t == '--inverse'
                i += 1
                continue
            if spec['pattern'] is None:
                spec['pattern'] = w
            i += 1
        return spec

    def resolve_spec(self, spec, label):
        if spec['own_parent']:
            return  # pkill -P $$: children of this shell
        if spec['pidfile']:
            self.unsure.append('%s -F reads its pid from a file' % label)
            return
        pattern = spec['pattern']
        if pattern is not None and pattern.dynamic:
            self.unsure.append('%s with a computed pattern' % label)
            return
        if pattern is None and spec['parents'] is None and spec['user'] is None:
            return  # pkill with nothing to match is a usage error
        flags = re.I if spec['ignore'] else 0
        regex = _regex(pattern.text, flags) if pattern is not None else None
        out = []
        for p in self.ctx.table().values():
            hit = True
            if regex is not None:
                subject = p.command if spec['full'] else p.name
                hit = bool(regex.fullmatch(subject) if spec['exact'] else regex.search(subject))
            if spec['parents'] is not None:
                hit = hit and p.ppid in spec['parents']
            if spec['user'] is not None:
                hit = hit and _uid_ok(p, spec['user'])
            if spec['invert']:
                hit = not hit
            if hit:
                out.append(p)
        self.resolve_matches(out, label)

    def resolve_matches(self, procs, label):
        ancestors = set(self.ctx.ancestors())
        procs = [p for p in procs if p.pid != os.getpid()]
        if not procs:
            return  # nothing matches now: nothing would be signalled
        self.check_pids([p.pid for p in procs], label=label, ancestors=ancestors)

    def check_pids(self, pids, group=False, label=None, ancestors=None):
        if group:
            table = self.ctx.table()
            members = sorted({p.pid for p in table.values() if p.pgid in set(pids)})
            if not members:
                return
            pids = members
        verdicts = self.ctx.judge(sorted(set(pids)))
        bad = [(pid, why) for pid, (ok, why) in verdicts.items() if not ok]
        if not bad:
            return
        good = [pid for pid, (ok, _why) in verdicts.items() if ok and pid in self.ctx.table()]
        what = ('%s matches %d process(es); ' % (label, len(verdicts))) if label else ''
        reason = what + '; '.join(why for _pid, why in bad[:3]) + (' (+%d more)' % (len(bad) - 3) if len(bad) > 3 else '')
        protected = [pid for pid, why in bad if 'protected' in why]
        hard = [pid for pid, why in bad if 'init or invalid' in why or 'agent session' in why or 'system process' in why]
        if label:
            proceed = ('kill %s   (only the matches that are yours)' % ' '.join(map(str, good[:20])) if good else
                       'list the matches (pgrep -fl <pattern>) and stop only yours by pid')
            raise Finding('broad-kill', reason, proceed, [p for p, _w in bad])
        if hard:
            proceed = ('kill %s' % ' '.join(map(str, good))) if good else 'nothing: these are never stopped from an agent'
            raise Finding('never', reason, proceed, [p for p, _w in bad])
        if protected:
            proceed = ('register an ask (wal_note.py --event ask); after the owner answers: '
                       + AH_KILL % ','.join(map(str, protected)) + ' --approved-by <ask id>')
            raise Finding('protected', reason, proceed, protected)
        proceed = ('register an ask (wal_note.py --event ask); after the owner answers: '
                   + AH_KILL % ','.join(str(p) for p, _w in bad[:20]) + ' --foreign --approved-by <ask id>')
        raise Finding('not-yours', reason, proceed, [p for p, _w in bad])


def _regex(pattern, flags):
    try:
        return re.compile(pattern, flags)
    except re.error:
        return re.compile(re.escape(pattern), flags)


def _uid_ok(proc, user):
    if user is None:
        return True
    for name in str(user).split(','):
        if name.isdigit() and proc.uid == int(name):
            return True
        try:
            if pwd.getpwnam(name).pw_uid == proc.uid:
                return True
        except KeyError:
            continue
    return False


def _requote(word):
    if re.fullmatch(r'[A-Za-z0-9_./:=@%+,-]+', word.text or 'x'):
        return word.text
    return "'" + word.text.replace("'", "'\\''") + "'"


def powershell_findings(text):
    if re.search(r'(?i)\bstop-process\b[^\n;|]*-(?:name|processname)\b|get-process\b[^\n;]*\|\s*stop-process', text) \
            or re.search(r'(?i)\btaskkill\b[^\n;]*/im\b', text):
        raise Finding('broad-kill', 'stopping processes by name hits every process of that name',
                      'Stop-Process -Id <pid> for each process of yours')


def decide(command, cwd=None, ps=False, policy=None, home=None, payload=None, context=None, **_ignored):
    """(verdict, rule, message, pids): verdict is 'allow', 'warn' or 'block'. Never raises; anything unexpected
    allows and logs one line."""
    policy = policy or load_policy()
    raw = ' '.join(map(str, command)) if isinstance(command, (list, tuple)) else str(command or '')
    if policy['mode'] == 'off' or not MAYBE_STOP.search(raw):
        return 'allow', '', '', ()
    ctx = context or Context(payload=payload, cwd=cwd, home=home, policy=policy)
    analyzer = Analyzer(ctx)
    try:
        if ps:
            powershell_findings(raw)
        else:
            analyzer.script(raw)
    except Finding as found:
        message = one_line('kill_guard refused [%s]: %s. To proceed: %s' % (found.rule, found.reason, found.proceed), 900)
        if policy['mode'] == 'warn':
            audit(found.rule, raw, found.pids, home, verdict='warn')
            return 'warn', found.rule, message.replace('refused', 'WARNING (would refuse)', 1), found.pids
        audit(found.rule, raw, found.pids, home)
        return 'block', found.rule, message, found.pids
    except Exception as error:  # noqa: BLE001 - never block on "could not read"
        audit('analysis-error:%s' % type(error).__name__, raw, (), home, verdict='allow')
        return 'allow', '', '', ()
    for note in ctx.notes[:4]:
        audit('maintainer:' + one_line(note, 80), raw, (), home, verdict='allow')
    if analyzer.unsure:
        audit('unsure:' + one_line(analyzer.unsure[0], 80), raw, (), home, verdict='allow')
    return 'allow', '', '', ()


# --------------------------------------------------------------------------- hook entry points

def command_of(payload):
    """(text, powershell) for a shell tool payload; (None, False) for anything else."""
    tool = str(payload.get('tool_name') or payload.get('toolName') or '').casefold()
    if tool in EDIT_TOOLS:
        return None, False
    tool_input = payload.get('tool_input') or payload.get('toolInput') or {}
    if isinstance(tool_input, str):
        return tool_input, tool == 'powershell'
    if not isinstance(tool_input, dict):
        return None, False
    has_command = any(k in tool_input for k in COMMAND_KEYS[:3])
    if tool and not tool.startswith(SHELL_TOOLS) and tool not in SHELL_TOOLS and not has_command:
        return None, False
    parts = []
    for key in COMMAND_KEYS:
        value = tool_input.get(key)
        if isinstance(value, list):
            parts.append(' '.join(_requote_text(str(v)) for v in value))
        elif isinstance(value, str):
            parts.append(value)
    return ('\n'.join(parts) or None), tool == 'powershell'


def _requote_text(text):
    return text if re.fullmatch(r'[A-Za-z0-9_./:=@%+,-]+', text or 'x') else "'" + text.replace("'", "'\\''") + "'"


def emit(verdict, message):
    if verdict == 'block':
        sys.stderr.write(message + '\n')
        return 2
    if verdict == 'warn':
        print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'additionalContext': message}}))
    return 0


def hook_main(data=None):
    """PreToolUse: allow unless the command would stop a process the caller may not stop. Any failure allows."""
    raw = ''
    try:
        try:
            import ah_roles  # noqa: PLC0415
            if ah_roles.harness_off():
                return 0
        except Exception:  # noqa: BLE001
            pass
        data = data if data is not None else sys.stdin.buffer.read(MAX_STDIN + 1)
        raw = data[:MAX_STDIN].decode('utf-8', 'replace')
        try:
            payload = json.loads(raw)
        except ValueError:
            return 0
        if not isinstance(payload, dict):
            return 0
        text, powershell = command_of(payload)
        if not text or not MAYBE_STOP.search(text):
            return 0
        policy = load_policy()
        if hasattr(signal, 'SIGALRM'):
            def _timeout(_s, _f):
                raise TimeoutError('kill_guard time limit')
            signal.signal(signal.SIGALRM, _timeout)
            signal.alarm(max(2, int(policy['child_timeout_seconds']) - 2))
        verdict, _rule, message, _pids = decide(text, ps=powershell, policy=policy, payload=payload,
                                                cwd=payload.get('cwd'))
        return emit(verdict, message)
    except BaseException as error:  # noqa: BLE001 - a timeout or a bug allows, with one line
        audit('guard-failure:%s' % type(error).__name__, raw, (), verdict='allow')
        return 0
    finally:
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)


# --------------------------------------------------------------------------- spawn and explain

def spawn_remote_main(host, argv):
    """`kill_guard.py spawn --host HOST [--log REMOTE_FILE] -- CMD ARGS...`: start CMD detached on HOST over ssh and
    print the pid. The command is passed as single-quoted words, never re-parsed here."""
    import shlex  # noqa: PLC0415
    log, args = '/dev/null', list(argv)
    if args[:1] == ['--log'] and len(args) >= 2:
        log, args = args[1], args[2:]
    if args[:1] == ['--']:
        args = args[1:]
    if not args or not re.match(r'^(?:[A-Za-z0-9._-]{1,64}@)?[A-Za-z0-9][A-Za-z0-9._-]{0,127}$', host) \
            or not re.match(r'^[A-Za-z0-9._/-]{1,512}$', log):
        sys.stderr.write('usage: kill_guard.py spawn --host HOST [--log REMOTE_FILE] -- CMD [ARGS...]\n')
        return 2
    script = ('nohup %s >%s 2>&1 </dev/null & p=$!; printf \'%%s\\n\' "$p"; ps -o lstart= -p "$p"'
              % (' '.join(shlex.quote(a) for a in args), shlex.quote(log)))
    try:
        done = subprocess.run(['ssh', '-o', 'BatchMode=yes', host, script], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as error:
        sys.stderr.write('kill_guard spawn: ssh to %s failed (%s)\n' % (host, type(error).__name__))
        return 1
    lines = [line.strip() for line in (done.stdout or '').splitlines() if line.strip()]
    if done.returncode != 0 or not lines or not lines[0].isdigit():
        sys.stderr.write('kill_guard spawn: %s did not report a pid (exit %s)\n' % (host, done.returncode))
        return 1
    start = ' '.join(lines[1].split()) if len(lines) > 1 else ''
    append_ledger('remote:' + host, int(lines[0]), start)
    print(json.dumps({'host': host, 'pid': int(lines[0]), 'start': start, 'log': log}))
    return 0


def spawn_main(argv):
    """`kill_guard.py spawn [--log FILE] -- CMD ARGS...`: start CMD detached and record it in this worktree's ledger,
    so a later `kill PID` from any shell of the caller is known to be its own."""
    log, args = None, list(argv)
    if args[:1] == ['--host'] and len(args) >= 2:
        return spawn_remote_main(args[1], args[2:])
    if args[:1] == ['--log'] and len(args) >= 2:
        log, args = args[1], args[2:]
    if args[:1] == ['--']:
        args = args[1:]
    if not args:
        sys.stderr.write('usage: kill_guard.py spawn [--host HOST] [--log FILE] -- CMD [ARGS...]\n')
        return 2
    cwd = os.getcwd()
    root, _nested = find_worktree(cwd)
    if not root:
        sys.stderr.write('kill_guard spawn: run it inside a git worktree (not / or HOME); nothing was started\n')
        return 2
    try:
        ensure_key()
    except OSError as error:
        sys.stderr.write('kill_guard spawn: %s; nothing was started\n' % error)
        return 2
    if log:
        log_real = os.path.realpath(os.path.join(cwd, log))
        if not under(log_real, root):
            sys.stderr.write('kill_guard spawn: --log must be a file inside the worktree; nothing was started\n')
            return 2
        out = os.fdopen(os.open(log_real, os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600), 'ab')
    else:
        out = subprocess.DEVNULL
    try:
        child = subprocess.Popen(args, cwd=cwd, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                 start_new_session=True, close_fds=True)
    except OSError as error:
        sys.stderr.write('kill_guard spawn: could not start the command (%s)\n' % type(error).__name__)
        return 1
    finally:
        if log:
            out.close()
    start = Probe().start(child.pid)
    if start is None:
        sys.stderr.write('kill_guard spawn: the command exited before it could be recorded (pid %d)\n' % child.pid)
        return 1
    append_ledger(root, child.pid, start)
    print(json.dumps({'pid': child.pid, 'worktree': root}))
    return 0


def explain_main(argv):
    """`kill_guard.py explain FILE [--cwd DIR]`: FILE holds a command (text) or a hook payload (JSON). Runs nothing."""
    if not argv:
        sys.stderr.write('usage: kill_guard.py explain FILE [--cwd DIR]\n')
        return 2
    cwd = argv[argv.index('--cwd') + 1] if '--cwd' in argv and argv.index('--cwd') + 1 < len(argv) else os.getcwd()
    with open(argv[0], 'rb') as handle:
        text = handle.read(MAX_STDIN).decode('utf-8', 'replace')
    payload = None
    try:
        payload = json.loads(text)
        text = command_of(payload)[0] or '' if isinstance(payload, dict) else text
    except ValueError:
        pass
    verdict, rule, message, pids = decide(text, cwd=cwd, payload=payload if isinstance(payload, dict) else None)
    print(json.dumps({'verdict': verdict, 'rule': rule, 'message': message, 'pids': list(pids)}))
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ('-h', '--help'):
        sys.stdout.write(__doc__.split('Entry points')[0] + 'Commands: hook | analyze | spawn | explain\n')
        return 0
    command, rest = argv[0], argv[1:]
    if command in ('hook', 'analyze'):
        return hook_main()
    if command == 'spawn':
        return spawn_main(rest)
    if command == 'explain':
        return explain_main(rest)
    sys.stderr.write('unknown command %s\n' % one_line(command, 30))
    return 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:  # noqa: BLE001 - a launcher bug allows (the redesign: never block on "could not read")
        sys.exit(0)
