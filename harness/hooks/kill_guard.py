#!/usr/bin/env python3
"""PreToolUse guard against broad process kills and kills of processes the caller does not own (GoodQA #14506).

Why: on 2026-11-04 an owner piped pgrep -f into xargs kill and an earlier owner ran pkill -f; both stopped other
owners' test runs on a shared dev host.

What it blocks, before the command runs, on Claude Code (Bash, PowerShell) and Codex (every shell tool):
  * pkill, killall, killall5, skill, slay, fuser -k, taskkill, Stop-Process, systemctl/launchctl kill, interpreter
    code that signals processes (os.kill, process.kill, psutil ...), find -exec / parallel running those verbs;
  * kill whose targets come from a pid finder (xargs, $(...), backticks, read or for loops with a variable);
  * text that names a kill and is run as shell code: the left side of a pipe into a shell, or a substitution given to
    eval or a shell; the guard does not compute what that text becomes;
  * a plain `kill PID` unless every target is a literal PID that is provably the caller's own: its cwd, or argv[0]
    or argv[1], is inside the caller's own git worktree (the toplevel of the tool call's cwd), or it is in the
    per-worktree spawn ledger written by `kill_guard.py spawn -- CMD...`;
  * every kill inside ssh, mosh, docker exec and kubectl exec (ownership cannot be checked locally) except
    `netwatch orphans --kill --pid N[,N...]`.
Allowed: kill -0 on literal targets or one quoted simple variable, kill -l, job specs (%N, %%, %+, %-, %name), process
listing, and text that merely contains the word. Every kill word must fit the closed grammar below; anything else fails
closed, including $!, a variable with a known value and a brace list.

It reuses command_guard.Analyzer for lexing, parsing, wrappers, aliases, heredocs, ssh and script files, and only
overrides the methods listed in OVERRIDDEN (a test pins their signatures). Threat model: careless agents and common
obfuscation, not an agent that edits its own hooks. See docs/operations.md, "Kill guard".

Entry points: `hook` (PreToolUse launcher, fails closed), `analyze` (child process), `spawn`, `explain`.
Python 3.9+, standard library only.
"""

import hashlib
import hmac
import json
import os
import re
import signal
import subprocess
import sys
import time
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

ALTERNATIVE = 'netwatch orphans --kill --pid <pid>'
MAX_STDIN = 8 * 1024 * 1024
MAX_PID = 4194304
GUARDED_TOOLS = {'bash', 'powershell', 'shell', 'local_shell', 'exec_command', 'unified_exec', 'write_stdin',
                 'container.exec'}
COMMAND_KEYS = ('command', 'cmd', 'script', 'chars', 'input')
PROTECTED_COMM = {'claude', 'codex', 'sshd', 'launchd', 'systemd', 'init', 'tmux', 'screen', 'netwatch', 'login',
                  'terminal', 'iterm2', 'alacritty', 'kitty', 'wezterm', 'gnome-terminal', 'sudo'}
SHELL_COMM = {'zsh', 'bash', 'sh', 'fish', 'dash', 'ksh', 'tcsh', 'csh'}  # protected when interactive
REJECT_ROOTS = {'/', '/tmp', '/private/tmp', '/var', '/private/var', '/var/tmp', '/opt', '/usr', '/private', '/etc',
                '/home', '/Users', '/mnt', '/srv', '/root'}
INTERPRETER_COMM = {'python', 'python3', 'node', 'nodejs', 'ruby', 'perl', 'php', 'deno', 'bun', 'bash', 'sh', 'zsh',
                    'dash', 'ksh', 'lua', 'pypy', 'pypy3', 'uv', 'java'}
# commands that run another command: the rest of their words are scanned for a kill verb
WRAPPER_NAMES = {'sudo', 'doas', 'env', 'nohup', 'timeout', 'nice', 'ionice', 'time', 'command', 'builtin', 'exec',
                 'setsid', 'stdbuf', 'chrt', 'taskset', 'unbuffer', 'strace', 'ltrace', 'runuser', 'su', 'sg', 'chroot',
                 'nsenter', 'flock', 'unshare', 'watch', 'xargs', 'parallel', 'systemd-run', 'caffeinate', 'gosu',
                 'firejail', 'tmux', 'screen', 'at', 'batch', 'uv', 'uvx', 'pipx', 'npx', 'bunx', 'pnpx', 'dtruss', 'script',
                 'arch', 'start', 'call', 'busybox', 'toybox', 'poetry', 'pipenv', 'conda', 'pdm', 'rye', 'hatch', 'sshpass', 'fakeroot', 'entr', 'bundle'}
REMOTE_WRAPPERS = {'docker-compose', 'oc', 'wsl', 'limactl', 'multipass', 'vagrant', 'colima', 'orb', 'adb', 'gcloud',
                   'aws', 'podman-compose', 'lxc', 'incus', 'ctr', 'crictl'}
REMOTE_EXEC = {'ssh', 'mosh', 'docker', 'podman', 'kubectl', 'nerdctl', 'oc'}
GNU_PREFIXED = {'timeout', 'xargs', 'find', 'nohup', 'env', 'nice', 'stdbuf', 'time', 'sudo', 'parallel', 'kill'}
STOP_COMMANDS = {'grep', 'egrep', 'fgrep', 'rg', 'ag', 'echo', 'printf', 'cat', 'git', 'gh', 'ls', 'sed', 'awk', 'head',
                 'tail', 'less', 'more', 'man', 'which', 'type', 'whereis', 'apt', 'apt-get', 'brew', 'pip', 'pip3',
                 'cp', 'mv', 'rm', 'mkdir', 'touch', 'chmod', 'chown', 'make', 'cargo', 'go', 'docker', 'kubectl',
                 'python', 'python3', 'node', 'ruby', 'perl', 'sleep', 'true', 'false', 'test', 'wc', 'sort', 'uniq',
                 'tee', 'diff', 'find', 'curl', 'wget', 'pytest', 'ssh', 'scp', 'rsync', 'tar', 'zip', 'unzip', 'date'}
OVERRIDDEN = ('apply', 'command', 'inner_words', 'script', 'ssh', 'container', 'check_tokens', 'resolve', 'bind_loop_var')

DEFAULT_POLICY = {
    'mode': 'enforce',
    'broad_verbs': ['pkill', 'killall', 'killall5', 'skill', 'slay', 'fkill', 'kill-port', 'killport'],
    'windows_verbs': ['taskkill', 'stop-process', 'spps', 'wmic'],
    'service_kill': {'systemctl': ['kill'], 'launchctl': ['kill'], 'tmux': ['kill-server'], 'pm2': ['kill'],
                     'loginctl': ['kill-session', 'kill-user', 'terminate-user', 'terminate-session']},
    'script_kill_pattern': r'(?i)(?<![a-z])(?:p|f|posix_)?kill(?![a-z])|killpg|terminate\(|send_signal|taskkill|killall|invoke-cimmethod|getprocessbyid|raise_signal|sigqueue|pidfd_send_signal',
    'pid_finders': ['pgrep', 'pidof', 'ps', 'lsof', 'fuser', 'pstree', 'cat', 'awk', 'grep'],
    'ledger_max_lines': 2000,
    'child_timeout_seconds': 10,
}

KILLISH = re.compile(r'kill|fuser|stop-process|spps|slay|wmic')
INDIRECT = re.compile(r"\$'|\\x[0-9a-fA-F]{2}|\\[0-7]{3}|\beval\b|base64|\bxxd\b", re.I)
CLOBBER_TEXT = re.compile(r'>&?!')  # >!, >>!, &>!, &>>!, >&!, >>&!: zsh and bash read these apart (GoodQA #14657)
LINE_JOIN = re.compile(r'\\\r?\n')  # a backslash-newline the shell removes, so `>\` then `!` is still `>!`
LIST_FLAGS = {'-l', '-L', '--list', '-t', '--table', '-Ll', '-lL'}
# The closed grammar of a kill command line. Each pattern is matched against text that word_text() has first tied to the
# word's exact source, so a form the lexer does not understand (zsh ${=x}, $=x, ${(z)x}, =(cmd), a glob qualifier, the
# unquoted $x in $x"") can never pass as a literal. Add a form only by showing it is one literal word in bash and zsh.
INTEGER = re.compile(r'0|[1-9][0-9]{0,9}')
JOB_SPEC = re.compile(r'%(?:[0-9]{1,10}|[%+-]|[A-Za-z_][A-Za-z0-9_.-]*)')
SIGNAL_OPTION = re.compile(r'-(?:[Ss][Ii][Gg])?([A-Za-z0-9+]{1,32})')
SIGNAL_VALUE = re.compile(r'[A-Za-z0-9+]{1,32}')
PAREN_REASON = 'a kill word is followed by a parenthesis, which zsh reads as a glob qualifier that can drop the word or run code'
FEED_REASON = 'text that names a kill is run as shell code, so the guard cannot tell which targets it reaches'
WORDS_NOT_VERBS_IN_TEXT = {'skill', 'slay', 'spps', 'wmic'}
TEXT_ESCAPE = re.compile(r'\\(?:[abefnrtv]|[0-7]{1,3}|x[0-9a-fA-F]{1,2})')
INERT_COMMANDS = {'echo', 'printf', 'print', 'ls', 'cat', 'head', 'tail', 'wc', 'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack'}
ASSIGNMENT_WORD = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)(\[[^\]]*\])?(\+?)=(.*)', re.S)
QUOTED_VARIABLE = re.compile(r'"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})"')
FUNCTION_KW = re.compile(r'\bfunction\s+([A-Za-z_][\w.:-]*)\s*(?:\(\s*\))?\s*\{')
COPROC_KW = re.compile(r'\bcoproc\s+(?:[A-Za-z_]\w*\s*)?\{')
INTERPRETER_NAME = re.compile(r'(?:python|pypy)[0-9.]*|node(?:js)?[0-9]*|ruby[0-9.]*|perl[0-9.]*|php[0-9.]*|deno|bun|lua[0-9.]*')
RUN_OPTS = {'-c', '-s', '-i', '-e', '-lc', '-ic', '--command', '-l', '-S'}  # options that take a command to run
LAUNCHERS = {'tmux', 'screen', 'at', 'batch', 'watch'}
CLASSIC_VERBS = {'pkill', 'killall', 'killall5', 'skill', 'slay', 'taskkill', 'stop-process', 'spps'}
PID_OPT_VALUE = re.compile(r'[0-9]+(?:,[0-9]+)*')
# Harness CLIs whose arguments are data (a note, a search text), never code. ah.py kill is judged by is_ah_kill.
AH_SUBCOMMANDS = {'owners', 'user-msg', 'ticket', 'disk', 'task', 'doctor', 'spool', 'write'}
PY_LITERAL = re.compile(r"""('\'\'[\s\S]*?\'\'\'|"{3}[\s\S]*?"{3}|'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*")""")
# Inline Python that only formats data (a closed set of syntax, calls and modules): its string literals are prose.
PY_SAFE_IMPORTS = {'json', 're', 'datetime', 'time', 'textwrap'}
PY_SAFE_CALLS = {'print', 'str', 'len', 'dict', 'list', 'sorted', 'int', 'repr', 'tuple', 'set', 'range', 'sum', 'min',
                 'max', 'bool', 'float', 'enumerate', 'zip'}
PY_SAFE_NODES = ('Module', 'Expr', 'Assign', 'Name', 'Load', 'Store', 'Constant', 'Call', 'keyword', 'Attribute', 'Dict',
                 'List', 'Tuple', 'Set', 'Subscript', 'Index', 'Slice', 'BinOp', 'JoinedStr', 'FormattedValue', 'Import',
                 'ImportFrom', 'alias', 'Add', 'Sub', 'Mult', 'Mod', 'Div')
# Module members a data-only program may reach, as full dotted paths. Every other attribute of a module (re.enum,
# json.decoder, textwrap.re ...) is a route to sys/os, so a chain must be a prefix of one of these or equal to it.
PY_SAFE_MEMBERS = {'json.dumps', 'json.loads', 'json.load', 're.sub', 're.match', 're.search', 're.findall', 're.split',
                   're.compile', 're.escape', 're.I', 're.IGNORECASE', 'datetime.datetime.now', 'datetime.datetime.utcnow',
                   'datetime.datetime.fromisoformat', 'datetime.datetime.strptime', 'datetime.timedelta',
                   'datetime.date.today', 'datetime.timezone.utc', 'time.time', 'time.strftime', 'time.gmtime',
                   'time.localtime', 'textwrap.dedent', 'textwrap.indent', 'textwrap.fill', 'textwrap.shorten'}
PY_SAFE_PREFIXES = {'.'.join(m.split('.')[:i]) for m in PY_SAFE_MEMBERS for i in range(1, len(m.split('.')) + 1)}
# Methods of plain values (str, list, dict, dates, match objects). None of them returns a module or a function.
PY_SAFE_METHODS = {'join', 'get', 'items', 'keys', 'values', 'upper', 'lower', 'strip', 'lstrip', 'rstrip', 'split',
                   'splitlines', 'replace', 'startswith', 'endswith', 'append', 'extend', 'isoformat', 'strftime',
                   'group', 'groups', 'title', 'count', 'index', 'find', 'ljust', 'rjust', 'center', 'zfill'}


def _dotted(node, aliases):
    """Real dotted path of a Name/Attribute chain rooted at an imported module, else None."""
    import ast
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name) and node.id in aliases:
        return '.'.join([aliases[node.id]] + parts[::-1])
    return None


def pure_data_python(code):
    """True when the program is built only from print/json-style calls on literals, so it cannot reach the OS. An
    allowlist over the syntax tree: sys.modules, exec*/spawn*, getattr, dunders, every other module and every module
    member outside PY_SAFE_MEMBERS (re.enum.sys...) are out."""
    import ast
    import builtins
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    aliases = {}  # local name -> real dotted path of an imported module or member
    for node in ast.walk(tree):
        kind = type(node).__name__
        if kind not in PY_SAFE_NODES:
            return False
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name not in PY_SAFE_IMPORTS:  # `import os.path` or `import a.b` is never needed here
                    return False
                aliases[a.asname or a.name] = a.name
        elif isinstance(node, ast.ImportFrom):
            if node.level or node.module not in PY_SAFE_IMPORTS:
                return False
            for a in node.names:
                path = node.module + '.' + a.name
                if path not in PY_SAFE_PREFIXES:
                    return False
                aliases[a.asname or a.name] = path
    # A builtin or module is only ever safe as the thing being called or the head of a vetted attribute chain. In
    # value position (key=eval, print = eval, repl=exec) a data program could hand code to a pure helper.
    called = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    heads = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Attribute):
            h = n.value
            while isinstance(h, ast.Attribute):
                h = h.value
            heads.add(id(h))
    stored = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            if node.id.startswith('_'):
                return False
            if isinstance(node.ctx, ast.Store):
                if node.id in aliases or hasattr(builtins, node.id):
                    return False  # rebinding print/eval/an imported name could hide a different object
            elif node.id in aliases:
                if id(node) not in called and id(node) not in heads:
                    return False
            elif node.id in stored:
                pass  # the program's own variable, only ever bound to vetted expressions
            elif node.id in PY_SAFE_CALLS:
                if id(node) not in called:
                    return False
            else:
                return False  # any other builtin or unknown name (eval, exec, open, getattr, vars ...)
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith('_'):
                return False
            path = _dotted(node, aliases)
            if path is not None:
                if path not in PY_SAFE_PREFIXES:
                    return False
            elif node.attr not in PY_SAFE_METHODS:
                return False
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id not in PY_SAFE_CALLS \
                and node.func.id not in aliases:
            return False
    return True


def hook_script_ok(raw, names):
    """The raw word names ~/.claude/hooks/<name>.py or the same path under the caller's real HOME, nothing else."""
    home = re.escape(str(Path.home()))
    return bool(re.fullmatch(r'(?:~|%s)/\.claude/hooks/(?:%s)\.py' % (home, '|'.join(names)), raw or ''))


# --------------------------------------------------------------------------- policy and small helpers

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
    return policy


DELETE_CHARS = {ord(c): None for c in '\'"\\${}`'}
DELETE_CHARS.update({c: None for c in list(range(0x200B, 0x2010)) + list(range(0x2060, 0x2065)) +
                     [0xFEFF, 0x00AD]})


def norm_raw(text):
    """Raw text with quoting, backslashes, braces and $ removed, NFKC and case-folded: the loose probe used where
    the parser is unavailable. `pk""ill`, `p\\kill` and `$'\\x70kill'` all still contain `kill`."""
    return unicodedata.normalize('NFKC', text).translate(DELETE_CHARS).casefold()


def fallback_blocks(raw):
    """Used when the analyser cannot run: block kill-looking or indirect input, allow the rest. A hook payload is
    reduced to its command text first, so a cwd such as .../kill-notes does not make `ls` look like a kill."""
    text = raw
    try:
        text = guarded_text(text)[1] or text
    except Exception:  # noqa: BLE001
        pass
    return bool(KILLISH.search(norm_raw(text)) or INDIRECT.search(text))


def one_line(text, limit=400):
    text = ''.join(ch if 32 <= ord(ch) < 127 else ' ' for ch in str(text))
    return re.sub(r'\s+', ' ', text).strip()[:limit]


def state_dir(home=None):
    return Path(home or os.path.expanduser('~')) / '.agent-harness' / 'state' / 'kill-guard'


def block_message(rule, reason):
    text = 'kill_guard BLOCKED [%s]: %s. Safe alternative: %s; processes you start with `kill_guard.py spawn -- CMD` ' \
           'are yours to kill.' % (rule, one_line(reason, 220), ALTERNATIVE)
    return one_line(text, 500)


# --------------------------------------------------------------------------- secure state (key and ledger)

def _secure_dir_ok(path):
    try:
        st = os.lstat(str(path))
    except OSError:
        return False
    import stat as stat_mod
    return stat_mod.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not (st.st_mode & 0o022)


def _read_secure_file(path, limit, tail=False):
    """Bytes of a regular file owned by us that is not group/world writable; None otherwise. Never follows links."""
    import stat as stat_mod
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(str(path), flags)
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
    """Valid entries (pid, start) for this worktree. Anything unreadable, unsafe or unauthenticated yields nothing."""
    key = read_key(home)
    if not key:
        return []
    data = _read_secure_file(ledger_path(root, home), 1 << 20, tail=True)
    if not data:
        return []
    out = []
    for line in data.decode('utf-8', 'replace').splitlines()[-max_lines:]:
        try:
            entry = json.loads(line)
            pid, start, ts, mac, entry_root = int(entry['pid']), str(entry['start']), int(entry['ts']), \
                str(entry['mac']), str(entry['root'])
        except (ValueError, KeyError, TypeError):
            continue
        if entry_root == root and hmac.compare_digest(mac, ledger_mac(key, root, pid, start, ts)):
            out.append((pid, start))
    return out


def append_ledger(root, pid, start, home=None):
    key = ensure_key(home)
    ts = int(time.time())
    entry = {'pid': pid, 'start': start, 'ts': ts, 'root': root, 'mac': ledger_mac(key, root, pid, start, ts)}
    path = ledger_path(root, home)
    fd = os.open(str(path), os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        os.write(fd, (json.dumps(entry, sort_keys=True) + '\n').encode('utf-8'))
    finally:
        os.close(fd)


def audit(rule, raw, pids, home=None):
    """Append one redacted line per block: no command text, only its hash. Best effort, never raises."""
    try:
        sdir = state_dir(home)
        os.makedirs(str(sdir), mode=0o700, exist_ok=True)
        if not _secure_dir_ok(sdir):
            return
        line = json.dumps({'ts': int(time.time()), 'rule': rule, 'pids': list(pids)[:16],
                           'sha256': hashlib.sha256(raw.encode('utf-8', 'replace')).hexdigest()[:16]})
        fd = os.open(str(sdir / 'audit.jsonl'), os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0),
                     0o600)
        try:
            os.write(fd, (line + '\n').encode('utf-8'))
        finally:
            os.close(fd)
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------- process probes

CLEAN_ENV = {'PATH': '/usr/sbin:/usr/bin:/bin:/sbin', 'LC_ALL': 'C'}


def _run(argv, timeout=2.0, cwd=None, env=None):
    try:
        done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=timeout, cwd=cwd, env=env or CLEAN_ENV, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    return done.stdout[:65536].decode('utf-8', 'replace')


class Probe:
    """Reads facts about a PID. Every method returns None when the fact cannot be read (then the PID is unprovable)."""

    def __init__(self):
        self.proc = os.path.isdir('/proc/self')

    def _stat_fields(self, pid):
        try:
            with open('/proc/%d/stat' % pid, 'rb') as handle:
                text = handle.read(4096).decode('utf-8', 'replace')
        except OSError:
            return None
        tail = text[text.rfind(')') + 2:].split()
        return tail if len(tail) > 20 else None

    def uid(self, pid):
        if self.proc:
            try:
                with open('/proc/%d/status' % pid, 'rb') as handle:
                    for line in handle.read(8192).decode('utf-8', 'replace').splitlines():
                        if line.startswith('Uid:'):
                            return int(line.split()[1])
            except (OSError, ValueError, IndexError):
                return None
            return None
        out = _run(['ps', '-o', 'uid=', '-p', str(pid)])
        try:
            return int(out.strip()) if out and out.strip() else None
        except ValueError:
            return None

    def ppid(self, pid):
        if self.proc:
            fields = self._stat_fields(pid)
            try:
                return int(fields[1]) if fields else None
            except ValueError:
                return None
        out = _run(['ps', '-o', 'ppid=', '-p', str(pid)])
        try:
            return int(out.strip()) if out and out.strip() else None
        except ValueError:
            return None

    def start(self, pid):
        if self.proc:
            fields = self._stat_fields(pid)
            return fields[19] if fields else None
        out = _run(['ps', '-o', 'lstart=', '-p', str(pid)])
        return out.strip() if out and out.strip() else None

    def comm(self, pid):
        if self.proc:
            try:
                with open('/proc/%d/comm' % pid, 'rb') as handle:
                    return handle.read(256).decode('utf-8', 'replace').strip().casefold()
            except OSError:
                return None
        out = _run(['ps', '-o', 'comm=', '-p', str(pid)])
        return os.path.basename(out.strip()).casefold() if out and out.strip() else None

    def cwd(self, pid):
        if self.proc:
            try:
                return os.readlink('/proc/%d/cwd' % pid)
            except OSError:
                return None
        out = _run(['lsof', '-a', '-d', 'cwd', '-p', str(pid), '-Fn'])
        for line in (out or '').splitlines():
            if line.startswith('n') and len(line) > 1:
                return line[1:]
        return None

    def argv(self, pid):
        """argv[0:4] as a list. On macOS only the whitespace-split `ps` command is available, so paths with spaces
        are not recognised there (unprovable, which is the safe side)."""
        if self.proc:
            try:
                with open('/proc/%d/cmdline' % pid, 'rb') as handle:
                    raw = handle.read(65536)
            except OSError:
                return None
            parts = [p.decode('utf-8', 'replace') for p in raw.split(b'\0') if p]
            return parts[:4] or None
        out = _run(['ps', '-ww', '-o', 'command=', '-p', str(pid)])
        parts = out.split() if out else []
        return parts[:4] or None


# --------------------------------------------------------------------------- ownership

def _fold(path):
    return path.casefold() if sys.platform == 'darwin' else path


def under(path, root):
    p, r = _fold(path), _fold(root)
    return p == r or p.startswith(r.rstrip('/') + '/')


def find_worktree(cwd, home=None, runner=None):
    """(root, nested_worktree_roots) for the git worktree containing cwd, or (None, []). Root is realpath-normalised
    and refused when it is `/`, HOME or an ancestor of HOME: such a root would 'own' everything."""
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
    listing = runner(['git', '-C', root, 'worktree', 'list', '--porcelain'], 3.0, None, env) or ''
    for line in listing.splitlines():
        if line.startswith('worktree '):
            other = os.path.realpath(line[9:].strip())
            if other != root and under(other, root):
                nested.append(other)
    return root, nested


class Ownership:
    """Decides whether a literal PID is provably the caller's own. check() returns (ok, code, detail)."""

    def __init__(self, cwd, home=None, probe=None, runner=None, policy=None):
        self.cwd = cwd
        self.home = home
        self.probe = probe or Probe()
        self.runner = runner
        self.policy = policy or DEFAULT_POLICY
        self._tree = None
        self._ancestors = None
        self._ledger = None
        self._memo = {}

    def tree(self):
        if self._tree is None:
            self._tree = find_worktree(self.cwd, self.home, self.runner)
        return self._tree

    def ancestors(self):
        if self._ancestors is None:
            chain, pid = set(), os.getpid()
            for _ in range(64):
                if pid is None or pid <= 1 or pid in chain:
                    break
                chain.add(pid)
                pid = self.probe.ppid(pid)
            self._ancestors = chain
        return self._ancestors

    def _inside(self, path, root, nested):
        if not path or not path.startswith('/'):
            return False
        norm = os.path.normpath(path)
        return under(norm, root) and not any(under(norm, n) for n in nested)

    def check(self, pid):
        if pid not in self._memo:
            self._memo[pid] = self._check(pid)
        return self._memo[pid]

    def _check(self, pid):
        if pid <= 1:
            return False, 'protected', 'pid %d is init or invalid' % pid
        if pid in self.ancestors():
            return False, 'ancestor', 'pid %d is the agent session that runs this command' % pid
        uid = self.probe.uid(pid)
        if uid is None:
            return False, 'uninspectable', 'pid %d does not exist or cannot be inspected' % pid
        if uid != os.getuid():
            return False, 'other-user', 'pid %d belongs to another user' % pid
        comm = self.probe.comm(pid)
        if comm is None:
            return False, 'uninspectable', 'pid %d cannot be inspected' % pid
        comm = comm.lstrip('-')
        if comm in PROTECTED_COMM:
            return False, 'protected', 'pid %d is a protected process (%s)' % (pid, one_line(comm, 20))
        if comm in SHELL_COMM:
            shell_argv = self.probe.argv(pid) or []
            if len(shell_argv) <= 1 or shell_argv[0].startswith('-'):
                return False, 'protected', 'pid %d is an interactive shell' % pid
        root, nested = self.tree()
        if not root:
            return False, 'no-worktree', 'pid %d is not provably yours: this call is not in a git worktree' % pid
        if self._ledger is None:
            self._ledger = read_ledger(root, self.home, int(self.policy.get('ledger_max_lines', 2000)))
        start = self.probe.start(pid)
        if start is not None and (pid, start) in self._ledger:
            return True, 'ledger', 'spawned by this worktree'
        cwd = self.probe.cwd(pid)
        if cwd and self._inside(cwd, root, nested):
            return True, 'cwd', 'cwd is inside this worktree'
        argv = self.probe.argv(pid) or []
        if argv and '/' in argv[0] and self._inside(argv[0], root, nested):
            return True, 'argv', 'runs a program inside this worktree'
        if len(argv) > 1 and os.path.basename(argv[0]).casefold().rstrip('0123456789.-') in INTERPRETER_COMM:
            script = next((a for a in argv[1:] if not a.startswith('-')), '')
            if '/' in script and self._inside(script, root, nested):
                return True, 'argv', 'runs a script inside this worktree'
        return False, 'outside', 'pid %d is not provably yours: its cwd and program are outside worktree %s' % (
            pid, one_line(os.path.basename(root), 40))


# --------------------------------------------------------------------------- analysis

def _import_base():
    import command_guard as cg
    return cg


def make_analyzer_class(cg):
    class KillAnalyzer(cg.Analyzer):
        def __init__(self, compiled, cwd, ps, ownership, policy, raw):
            super().__init__(compiled, cwd=cwd, ps=ps)
            self.own = ownership
            self.policy = policy
            self.raw = raw
            self.kf = []          # (rule, reason, pids)
            self.remote = 0
            self.xargs = 0
            self.before_paren = {}  # id -> word, holding the word so its id stays unique
            self.fed = {}           # id -> (word, sink stage): its text goes down a pipe, maybe into a shell
            self.broad = set(policy['broad_verbs'])
            self.windows = set(policy['windows_verbs'])
            self.script_kill = re.compile(policy['script_kill_pattern']) if policy['script_kill_pattern'] else None
            self.finders = set(policy['pid_finders'])
            verbs = (self.broad | self.windows | {'kill', 'gkill', 'fuser'}) - WORDS_NOT_VERBS_IN_TEXT
            self.kill_word = re.compile(r'(?<![\w.*?\[\]-])(?:%s)(?![\w.*?\[\]/-])' % '|'.join(
                map(re.escape, sorted(verbs, key=len, reverse=True))))

        # ---- findings
        def block(self, rule, reason, pids=()):
            self.kf.append((rule, reason, tuple(pids)))

        def run_kill_scan(self, text):
            self.script(text, depth=0)
            return self.kf

        # ---- overridden traversal hooks (OVERRIDDEN lists them; a test pins the base signatures)
        def script(self, text, depth, tail_visible=None, ps=None):
            saved, self.xargs = self.xargs, 0
            text = FUNCTION_KW.sub(lambda m: m.group(1) + '() {', text)
            text = COPROC_KW.sub('{', text)
            try:
                return super().script(text, depth, tail_visible=tail_visible, ps=ps)
            finally:
                self.xargs = saved

        def names_kill(self, text):
            # norm_raw deletes a backslash so k\\ill still reads kill; a printf escape in front of a verb must split instead.
            return bool(self.kill_word.search(norm_raw(text)) or self.kill_word.search(norm_raw(TEXT_ESCAPE.sub(' ', text))))

        def check_tokens(self, tokens):
            # Tokens come before variables are bound, so this only tags words and normalises assignments; command() judges
            # the tagged words once their values are known. PowerShell parentheses and pipes mean something else.
            if self.ctx.ps:
                return
            flat = cg._strip_case_patterns(tokens)
            self.tag_paren_cuts(flat)
            self.normalize_assignments(flat)
            self.tag_shell_feeders(flat)

        def tag_paren_cuts(self, tokens):
            # parse() ends a command at `(`, so the words after it are never seen. `kill 4001(N) 4004` is a syntax error in
            # bash, but in zsh (N) is a glob qualifier: the word vanishes and 4004 is signalled, and (e:...:) runs code. Not a
            # cut: `name()` defines a function, `name=(` is an array, and `[[ ]]` groups with parentheses.
            words = []
            for k, (kind, value) in enumerate(tokens):
                if kind == 'w':
                    words.append(value)
                elif kind == 'op':
                    if value == '(' and words:
                        definition = len(words) == 1 and tokens[k + 1:k + 2] == [('op', ')')]
                        array = bool(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=', words[-1].raw or ''))
                        conditional = cg.strip_reserved(words)[:1] and cg.strip_reserved(words)[0].text == '[['
                        if not (definition or array or conditional):
                            for w in words:
                                self.before_paren[id(w)] = w
                    words = []

        def normalize_assignments(self, tokens):
            # The base reads NAME=value only. `K=(kill)` would leave K empty and `$K 4004` unjudged, so give the first word
            # of an array literal, an append and a subscripted assignment the value the variable holds afterwards; the head
            # resolution every other variable gets then applies. The literal's own words still parse as a command, as before.
            for k, (kind, word) in enumerate(tokens):
                if kind != 'w':
                    continue
                match = ASSIGNMENT_WORD.fullmatch(word.text)
                if not match or not (word.raw or '').startswith(match.group(1)):
                    continue
                name, subscript, plus, value = match.groups()
                items = self.array_items(tokens, k) if not value else None
                prev = tokens[k - 1] if k else None
                at_start = prev is None or prev[0] == 'op' or (prev[0] == 'w' and (
                    prev[1].text in cg.RESERVED or ASSIGNMENT_WORD.fullmatch(prev[1].text)))
                if items is None and not ((subscript or plus) and at_start):
                    continue
                parts = [] if items is None else [re.sub(r'^\[[^\]]*\]\+?=', '', it.text) for it in items]
                text = ' '.join(parts) if items is not None else value
                if subscript or plus:  # keeps what the variable held; when that is unknown the value stays a hint
                    joiner = ' ' if subscript or items is not None else ''
                    text = cg.VAR_OPEN + name + cg.VAR_CLOSE + joiner + text
                    word.vars.append(name)
                word.alts = ['%s=%s' % (name, text)]
                word.glob = False
                for it in items or ():
                    word.vars.extend(it.vars)
                    word.subs.extend(it.subs)
                    word.dynamic = word.dynamic or it.dynamic

        @staticmethod
        def array_items(tokens, k):
            if tokens[k + 1:k + 2] != [('op', '(')]:
                return None
            items = []
            for kind, value in tokens[k + 2:]:
                if kind == 'w':
                    items.append(value)
                elif kind == 'op' and value == ')':
                    return items
                elif not (kind == 'op' and value == '\n'):
                    return None
            return None

        def tag_shell_feeders(self, tokens):
            # `for p in A B; do echo "kill $p"; done | sh`: what comes out of the left side is the program, and the guard
            # does not compute program output. Every word on that side is judged by command(), however it is nested.
            for k, (kind, value) in enumerate(tokens):
                if kind == 'op' and value in ('|', '|&'):
                    stage = []
                    for later_kind, later in tokens[k + 1:]:
                        if later_kind == 'op' and later == '\n' and not stage:
                            continue  # a newline after a pipe continues the pipeline
                        if later_kind == 'op':
                            break
                        if later_kind == 'w':
                            stage.append(later)
                    if self.reads_program(stage) or (stage and cg.VAR_OPEN in stage[0].text):  # S=sh; ... | $S
                        for w in self.feeder_words(tokens, k):
                            self.fed[id(w)] = (w, stage)

        @staticmethod
        def feeder_words(tokens, pipe):
            """The words left of a pipe, back to the start of the statement it belongs to."""
            out, depth = [], 0
            for j in range(pipe - 1, -1, -1):
                kind, value = tokens[j]
                if kind == 'w':
                    out.append(value)
                    prev = tokens[j - 1] if j else None
                    keyword = not value.quoted and (prev is None or prev[0] == 'op' or (
                        prev[0] == 'w' and not prev[1].quoted and prev[1].text in cg.RESERVED))
                    if keyword and value.text in ('done', 'fi', 'esac', '}'):
                        depth += 1
                    elif keyword and value.text in ('for', 'select', 'while', 'until', 'if', 'case', '{'):
                        if depth == 0:
                            break
                        depth -= 1
                elif kind == 'op':
                    if value == ')':
                        depth += 1
                    elif value == '(':
                        if depth == 0:
                            break
                        depth -= 1
                    elif value == '\n' and j and tokens[j - 1] in (('op', '|'), ('op', '|&')):
                        continue
                    elif depth == 0 and value in (';', '\n', '&&', '||', '&'):
                        break
            return out

        def reads_program(self, words):
            """True when this pipeline stage runs its stdin as shell code."""
            words = self._skip_assigns(cg.strip_reserved(words))[1]
            if not words:
                return False
            name, args = cg.norm_name(words[0].text), words[1:]
            if name.startswith('g') and name[1:] in GNU_PREFIXED:
                name = name[1:]
            if name in cg.SHELLS and name != 'busybox':
                i = 0
                while i < len(args):
                    t = args[i].text
                    if t in ('-s', '-', '/dev/stdin', '/dev/fd/0'):
                        return True
                    if re.fullmatch(r'-[a-zA-Z]*[cn][a-zA-Z]*', t) or t.startswith('--command') or not t.startswith(('-', '+')):
                        return False  # -c gives the program, -n only parses, and a first operand is a script file
                    i += 2 if re.fullmatch(r'[-+][a-zA-Z]*[oO]', t) or t in ('--rcfile', '--init-file') else 1
                return True
            if name in ('at', 'batch'):
                return not any(a.text == '-f' for a in args)
            if name == 'parallel' and all(a.text.startswith('-') for a in args):
                return True
            if name in WRAPPER_NAMES or name in REMOTE_EXEC or name in REMOTE_WRAPPERS:
                for i, a in enumerate(args):
                    n = cg.norm_name(a.text)
                    if n in cg.SHELLS:
                        if name in ('xargs', 'parallel'):  # the text reaches the shell only when it is the whole -c program
                            marks = {args[j + 1].text for j in range(i) if args[j].text == '-I'} | {'{}'} | {
                                t.text[2:] for t in args[:i] if t.text.startswith('-I') and len(t.text) > 2}
                            return any(re.fullmatch(r'-[a-zA-Z]*c[a-zA-Z]*', args[j].text) and args[j + 1].text.strip() in marks
                                       for j in range(i + 1, len(args) - 1))
                        return self.reads_program(args[i:])
                    if re.search(r'\s', a.text.strip()) and name not in ('xargs', 'parallel'):  # ssh host 'cd /srv && bash -s'
                        for bang in (True, False):  # the remote shell may be zsh or bash, which read `>! sh` apart
                            lexed = cg.Lexer(self.ctx, self.ctx.ps, bang_operators=bang).lex(a.text)
                            if any(self.reads_program(c.words) for pl in cg.parse(lexed) for c in pl.cmds):
                                return True
                    if n in STOP_COMMANDS:
                        return False
            return False

        def command(self, cmd, pl, idx, depth):
            self.judge_reread(cmd)
            return super().command(cmd, pl, idx, depth)

        def judge_reread(self, cmd):
            """The one rule for words that can be read again as code after this parse, whatever the command is called:
            they were cut at a parenthesis, or their text goes down a pipe into a shell. If they name a kill, or may hold
            one because the value is unknown and the input names one, nothing about the targets can be proven. A command
            that only prints or searches its words, with no pipe into a shell, leaves them as data."""
            cut = any(id(w) in self.before_paren for w in cmd.words)
            fed = any(id(w) in self.fed and self.reads_program([self.resolve(s) for s in self.fed[id(w)][1]])
                      for w in cmd.words)
            if not (cut or fed):
                return
            words = [self.resolve(w) for w in cg.strip_reserved(cmd.words)]
            reason = FEED_REASON if fed else PAREN_REASON
            rule = 'text-to-shell' if fed else 'unprovable-target'
            bodies = []
            if fed:
                bodies = [r.body or (r.target.text if r.op == '<<<' and r.target is not None else '') for r in cmd.redirs]
            rest = self._skip_assigns(words)[1]
            name = cg.norm_name(rest[0].text) if rest else ''
            if not fed and (not rest or name in INERT_COMMANDS):
                return
            if self.names_kill(' '.join([p for w in words for p in (w.text, w.raw or '', *w.subs)] + bodies)):
                self.block(rule, reason)
                return
            unknown = any(w.dynamic or w.subs for w in words) or any('$' in b or '`' in b for b in bodies)
            runs_text = fed or (rest and (rest[0].dynamic or rest[0].subs or self.runs_text(name)))
            if unknown and runs_text and self.names_kill(self.raw):
                self.block(rule, reason)

        @staticmethod
        def runs_text(name):
            return name in cg.SHELLS or name in ('eval', 'source', '.', 'trap') or name in WRAPPER_NAMES \
                or name in REMOTE_EXEC or name in REMOTE_WRAPPERS

        def resolve(self, word):
            # resolve() builds a new Word for any word holding a variable, so a tag has to follow it.
            out = super().resolve(word)
            if out is not word and word is not None:
                if id(word) in self.before_paren:
                    self.before_paren[id(out)] = out
                if id(word) in self.fed:
                    self.fed[id(out)] = (out, self.fed[id(word)][1])
            return out

        def bind_loop_var(self, words):
            # `for p in A B; do kill $p`: the base binds only one item; make the variable unresolvable instead so
            # the kill is judged as dynamic, never as the first item only.
            if len(words) >= 2:
                self.ctx.tainted.add(words[1].text)
                self.ctx.vars.pop(words[1].text, None)

        def inner_words(self, words, depth, pl, idx, via_xargs=False):
            if via_xargs:
                self.xargs += 1
            try:
                return super().inner_words(words, depth, pl, idx, via_xargs)
            finally:
                if via_xargs:
                    self.xargs -= 1

        def _ssh_host_index(self, texts):
            value_opts = set('bcDEeFIiJLlmOopQRSWwBP')
            i = 0
            while i < len(texts):
                t = texts[i]
                if t.startswith('-') and len(t) > 1:
                    consumed = 1
                    for k, letter in enumerate(t[1:]):
                        if letter in value_opts:
                            consumed = 2 if k == len(t) - 2 else 1  # value glued on, or the next word
                            break
                    i += consumed
                    continue
                return i
            return None

        def ssh(self, args, depth):
            texts = [a.text for a in args]
            for i, t in enumerate(texts):  # these run on THIS machine, before the connection
                value = texts[i + 1] if t == '-o' and i + 1 < len(texts) else (t[2:] if t.startswith('-o') and len(t) > 2 else None)
                match = re.match(r'(?i)\s*(?:proxycommand|localcommand)\s*[= ]\s*(.+)', value or '')
                if match:
                    self.script(match.group(1), depth + 1)
            host = self._ssh_host_index(texts)
            if host is not None and host + 1 < len(texts) and texts[host + 1] == '--':
                args = args[:host + 1] + args[host + 2:]  # `mosh host -- cmd`, `ssh host -- cmd`
            self.remote += 1
            try:
                result = super().ssh(args, depth)
                host = self._ssh_host_index(texts)
                if host is not None and host + 1 < len(args):  # the base joins words unquoted; judge the quoted form too
                    self.script(' '.join(cg._quote_for_rebuild(a.text) for a in args[host + 1:]), depth + 1)
                return result
            finally:
                self.remote -= 1

        def container(self, name, args, words, depth, pl, idx):
            self.remote += 1
            try:
                return super().container(name, args, words, depth, pl, idx)
            finally:
                self.remote -= 1

        def apply(self, name, words, cmd, pl, idx, depth):
            if words[0].vars and name.endswith(']'):
                name = re.sub(r'\[[^\]]*\]$', '', name)  # zsh subscript on an array head: $K[1], $K[@]
            if name.startswith('g') and name[1:] in GNU_PREFIXED:
                return self.apply(name[1:], words, cmd, pl, idx, depth)  # Homebrew coreutils: gtimeout, gxargs ...
            args = words[1:]
            if name in ('command', 'builtin', 'type', 'which', 'whereis', 'hash') and (
                    name in ('type', 'which', 'whereis', 'hash') or leading_lookup(args)):
                return None  # asks where a program is; runs nothing
            if name in ('export', 'declare', 'local', 'readonly', 'typeset'):
                for a in args:
                    if '=' in a.text and not a.dynamic and not a.text.startswith('-'):
                        key, _, value = a.text.partition('=')
                        self.ctx.vars[key] = value
                        self.ctx.tainted.discard(key)
            head_text = words[0].text.strip()
            if ' ' in head_text and not head_text.startswith('-'):
                self.script(head_text + ' ' + ' '.join(cg._quote_for_rebuild(a.text) for a in args), depth + 1)
            self.inspect(name, words, cmd, pl, idx, depth)
            if name in WRAPPER_NAMES or name.startswith('-') or name in REMOTE_WRAPPERS:
                self.scan_tail(name, args, pl, idx, depth)
            elif name not in STOP_COMMANDS and name not in cg.SHELLS and name not in self.broad \
                    and name not in self.windows and name != 'netwatch':
                if any(cg.norm_name(a.text) in CLASSIC_VERBS for a in args):  # pnpm exec pkill x, bundle exec ..., entr -r ...
                    self.block('indirect-kill', '`%s` runs a process-killing command by name' % one_line(name, 30))
            return super().apply(name, words, cmd, pl, idx, depth)

        def scan_tail(self, name, args, pl, idx, depth):
            """After a wrapper (or the option left over once `time` was stripped): the first later word that is a
            kill verb starts the real command, whatever options the wrapper takes. Words that are a known ordinary
            command end the scan, and a word holding a whole command line (`sudo -i 'pkill x'`) is re-parsed."""
            verbs = self.broad | self.windows | {'kill'}
            remote = name in REMOTE_WRAPPERS
            via_xargs = name in ('xargs', 'parallel')
            for i, w in enumerate(args):
                if cg.norm_name(w.text).lstrip('g') in ('xargs', 'parallel'):
                    via_xargs = True
                if i and args[i - 1].text in ('-s', '--signal', '-k', '--kill-after', '-S'):
                    continue  # a signal name given to timeout and friends, not a command
                n = cg.norm_name(w.text)
                if n.startswith('g') and n[1:] in GNU_PREFIXED:
                    n = n[1:]
                if n in verbs:
                    if remote:
                        self.remote += 1
                    try:
                        self.inner_words(args[i:], depth, pl, idx, via_xargs=via_xargs)
                    finally:
                        if remote:
                            self.remote -= 1
                    return
                if n in ('ssh', 'mosh') and name == 'sshpass':
                    self.inner_words(args[i:], depth, pl, idx)  # sshpass -p x ssh host ...
                    return
                if INTERPRETER_NAME.fullmatch(n) or n in cg.SHELLS:
                    self.inner_words(args[i:], depth, pl, idx, via_xargs=via_xargs)  # uv run python -c ..., tmux new sh -c ...
                    return
                if not remote and n in STOP_COMMANDS:
                    return
                if w.text.startswith(('--split-string=', '-S')) and len(w.text) > 2 and name == 'env':
                    self.script(w.text.split('=', 1)[1] if '=' in w.text else w.text[2:], depth + 1)
                prev = args[i - 1].text if i else ''
                # `--command` runs a command only for su and runuser; `wrangler d1 execute --command "SELECT count(*)"`
                # takes SQL. A value that mentions a kill verb is still re-read as a command line.
                sql_like = prev == '--command' and name not in ('su', 'runuser') and not KILLISH.search(w.text)
                value_of_other_option = prev.startswith('-') and (prev not in RUN_OPTS or sql_like) \
                    and name not in LAUNCHERS and not re.fullmatch(r'-[A-Za-z]*c', prev)
                if (' ' in w.text.strip() or ';' in w.text) and not w.text.startswith('-') \
                        and name not in ('xargs', 'parallel') and not value_of_other_option:
                    if remote:
                        self.remote += 1
                    try:
                        self.script(w.text, depth + 1)
                    finally:
                        if remote:
                            self.remote -= 1

        # ---- the checks
        def finder_before(self, pl, idx, subs=()):
            for prev in pl.cmds[:idx]:
                head = self._skip_assigns(cg.strip_reserved(prev.words))[1]
                if head and cg.norm_name(head[0].text) in self.finders:
                    return True
            return any(re.search(r'\b(?:%s)\b' % '|'.join(map(re.escape, self.finders - {'cat', 'awk', 'grep'})), s)
                       for s in subs)

        def inspect(self, name, words, cmd, pl, idx, depth):
            args = words[1:]
            texts = [a.text for a in args]
            head = words[0]
            if re.fullmatch(r'\$[@*0-9]', head.text) and KILLISH.search(norm_raw(self.raw)):
                self.block('dynamic-head', 'positional parameters run a command and the input mentions kill')
            if head.dynamic:
                hints = ' '.join(self.ctx.var_hints.values()) + ' ' + ' '.join(head.subs) + ' ' + ' '.join(
                    self.ctx.vars.get(v, '') for v in head.vars)  # ${K[@]} reads a variable the guard does know
                try:
                    hints += ' ' + cg.decode_ansi(hints)
                except Exception:  # noqa: BLE001
                    pass
                if args and any(cg.norm_name(a.text) in (self.broad | self.windows | {'kill'}) for a in args[:2]):
                    self.block('dynamic-head', 'a command name built at run time is followed by a kill verb')  # $x kill 4242
                spliced = re.sub('[\ue000-\uf8ff]', '', cg.VAR_MARKER.sub('', head.text))
                elided = any(cg.norm_name(spliced[:p] + spliced[e:]) in (self.broad | self.windows | {'kill'})
                             for p in range(len(spliced)) if spliced[p] == '$'
                             for e in range(p + 2, min(len(spliced), p + 40) + 1))  # k${x}ill, k$@ill
                if elided or KILLISH.search(norm_raw(spliced + ' ' + hints)) or INDIRECT.search(hints):
                    self.block('dynamic-head', 'the command name is built at run time and the input mentions kill')
            if name in self.broad:
                self.block('broad-kill', '`%s` signals processes by name or pattern and can hit other owners' % name)
            elif name in self.windows:
                if name != 'wmic' or any(t.casefold() in ('delete', 'terminate') for t in texts):
                    self.block('windows-kill', '`%s` cannot be checked for ownership' % name)
            elif name == 'kill':
                if self.ctx.ps:
                    self.block('windows-kill', 'PowerShell kill is Stop-Process and cannot be checked for ownership')
                elif any(id(w) in self.before_paren for w in words):
                    self.block('unprovable-target', PAREN_REASON)
                else:
                    self.check_kill(args, pl, idx)
            elif name == 'fuser':
                if any(re.fullmatch(r'-[A-Za-z]*k[A-Za-z]*', t) or t == '--kill' for t in texts):
                    self.block('broad-kill', '`fuser -k` kills whatever holds a file or port')
            elif name in self.policy['service_kill']:
                if any(t in self.policy['service_kill'][name] for t in texts):
                    self.block('service-kill', '`%s kill` stops processes the guard cannot attribute' % name)
            elif name == 'netwatch':
                self.check_netwatch(args)
            elif name in cg.SHELLS or name in ('eval', 'source', '.'):
                if any(INDIRECT.search(' '.join(a.subs)) for a in args if a.subs):
                    self.block('obfuscated-input', 'a shell is fed decoded text, so the guard cannot see what runs')
                elif any(self.names_kill(' '.join(a.subs)) for a in args if a.subs):
                    self.block('text-to-shell', FEED_REASON)  # eval "$(for p in A B; do echo "kill $p"; done)"
            elif name == 'trap':
                rest = [t for t in texts if t not in ('--',)]
                if rest and rest[0] not in ('-p', '-l', '-', ''):
                    self.script(rest[0], depth + 1)
            elif name in ('find', 'parallel'):
                self.check_indirect(name, args, texts)
            elif name in ('busybox', 'toybox', 'systemd-run') and args:
                rest = [a for a in args if not a.text.startswith('-')][:1]
                if rest:
                    self.inner_words(args[args.index(rest[0]):], depth, pl, idx)
            elif name in cg.INTERPRETERS or INTERPRETER_NAME.fullmatch(name):
                if not self.is_ah_kill(name, args, cmd, depth) and not self.is_harness_cli(name, args, cmd, depth):
                    self.check_interpreter(name, texts, cmd)
            self.check_spawn(name, args, texts, depth, pl, idx)
            self.check_text_runners(name, args, texts, cmd, depth)

        def check_text_runners(self, name, args, texts, cmd, depth):
            """Commands that run a text argument or here-string as shell code, which the base does not follow."""
            runs_stdin = name in cg.SHELLS or name in ('at', 'batch') or (
                (name in WRAPPER_NAMES or name in REMOTE_WRAPPERS or name in REMOTE_EXEC) and any(
                    cg.norm_name(a.text) in cg.SHELLS or cg.norm_name(a.text) in ('at', 'batch') for a in args))
            if name in ('ssh', 'mosh'):
                runs_stdin = True
            if runs_stdin:
                remote = name in REMOTE_EXEC or name in REMOTE_WRAPPERS
                self.remote += 1 if remote else 0
                try:
                    for redir in getattr(cmd, 'redirs', []):
                        if redir.op == '<<<' and redir.target is not None:
                            self.script(redir.target.text, depth + 1)
                        elif redir.op == '<' and redir.target is not None:
                            self.script_file(redir.target, depth)
                        elif redir.body and redir.op.startswith('<<'):
                            self.script(redir.body, depth + 1)
                finally:
                    self.remote -= 1 if remote else 0
            if (name in WRAPPER_NAMES) and any(INTERPRETER_NAME.fullmatch(cg.norm_name(a.text)) for a in args):
                self.check_interpreter(name, texts, cmd)  # uv run python - <<EOF
            if name in ('at', 'batch'):
                for i, t in enumerate(texts):
                    if t == '-f' and i + 1 < len(args):
                        self.script_file(args[i + 1], depth)
            elif name == 'watch':
                i = 0
                while i < len(texts) and texts[i].startswith('-'):
                    i += 2 if texts[i] in ('-n', '-d', '--interval') else 1
                if i < len(texts):
                    self.script(' '.join(texts[i:]), depth + 1)
            elif name in ('cmd', 'cmd.exe'):
                for i, t in enumerate(texts):
                    if t.casefold() in ('/c', '/k') and i + 1 < len(texts):
                        self.script(' '.join(texts[i + 1:]), depth + 1)

        def check_spawn(self, name, args, texts, depth, pl, idx):
            """`kill_guard.py spawn [--log F] -- CMD` runs CMD: judge CMD as if it were typed directly."""
            if name in ('kill_guard.py', 'kill_guard'):
                rest = list(args)
            elif name in cg.INTERPRETERS and any(cg.norm_name(t) == 'kill_guard.py' for t in texts):
                rest = list(args)[[cg.norm_name(t) for t in texts].index('kill_guard.py') + 1:]
            else:
                return
            if not rest or rest[0].text != 'spawn':
                return
            rest = rest[1:]
            if rest[:1] and rest[0].text == '--log':
                rest = rest[2:]
            if rest[:1] and rest[0].text == '--':
                rest = rest[1:]
            if rest:
                self.inner_words(rest, depth, pl, idx)

        def check_indirect(self, name, args, texts):
            verbs = self.broad | self.windows | {'kill'}
            hit = False
            if name == 'find':
                for i, t in enumerate(texts):
                    if t in ('-exec', '-execdir', '-ok', '-okdir') and i + 1 < len(texts) \
                            and cg.norm_name(texts[i + 1]) in verbs:
                        hit = True
            else:
                first = next((t for t in texts if not t.startswith('-') and t != ':::'), '')
                hit = cg.norm_name(first) in verbs
            if hit:
                self.block('indirect-kill', '`%s` runs a kill verb on targets the guard cannot list' % name)

        def is_harness_cli(self, name, args, cmd, depth):
            """`python3 [-I|-B|-u] ~/.claude/hooks/{ah,wal_note,provenance}.py ...`: the words after the script are
            data for that script, so a note or search text that mentions kill is not signalling. `ah.py kill` is
            excluded (is_ah_kill decides it), and so is any assignment prefix, quoted head or other script."""
            if not name.startswith('python') or not INTERPRETER_NAME.fullmatch(name) or self.remote or depth:
                return False
            words = getattr(cmd, 'words', None) or []
            if not words or words[0].raw is None or words[0].raw != name:
                return False
            i = 0
            while i < len(args) and args[i].text in ('-I', '-B', '-u'):
                i += 1
            if i >= len(args) or not hook_script_ok(args[i].raw, ('ah', 'wal_note', 'provenance')):
                return False
            if args[i].text.endswith('/ah.py'):
                # only a known non-kill subcommand (optionally after the top-level --text) makes the rest data
                rest = [a.text for a in args[i + 1:]]
                if rest[:1] == ['--text']:
                    rest = rest[1:]
                if not rest or rest[0] not in AH_SUBCOMMANDS:
                    return False
            return True

        def is_ah_kill(self, name, args, cmd, depth):
            """True only for the literal form `python3 [-I|-B|-u] ~/.claude/hooks/ah.py kill --pid N[,N] --reason R
            [--tree] [--grace S] [--host H] [--agent A] [--session S]`. ah kill audits every pid and refuses
            system, other-user, GUI and ancestor processes itself, so the guard only has to prove the form is
            literal: no variable, substitution, glob, heredoc, `-c`, eval or second script. Anything else
            returns False and is judged by the ordinary interpreter rules."""
            if not INTERPRETER_NAME.fullmatch(name) or not name.startswith('python') or self.remote or depth:
                return False
            if any(getattr(r, 'body', None) or getattr(r, 'op', '').startswith('<') for r in getattr(cmd, 'redirs', [])):
                return False
            if any(a.dynamic or a.subs or a.glob for a in args):
                return False
            words = getattr(cmd, 'words', None) or []
            if not words or words[0].raw is None or words[0].raw != name:
                return False  # an assignment prefix (PYTHONPATH=x python3 ...) or a quoted head
            texts = [a.text for a in args]
            if not texts or texts[0] != '-I':
                return False  # isolated mode ignores PYTHONPATH and user site, so a planted module cannot run first
            i = 1
            while i < len(texts) and texts[i] in ('-B', '-u'):
                i += 1
            # the raw word is matched: a quoted '~' is a literal directory, and .text has HOME expanded
            if i + 1 >= len(texts) or not hook_script_ok(args[i].raw, ('ah',)) or texts[i + 1] != 'kill':
                return False
            rest, i, seen = texts[i + 2:], 0, set()
            while i < len(rest):
                t = rest[i]
                key, eq, val = t.partition('=') if t.startswith('--') else (t, '', '')
                if key in ('--tree', '--foreign') and not eq:
                    seen.add(key)
                    i += 1
                    continue
                if key not in ('--pid', '--reason', '--grace', '--host', '--agent', '--session'):
                    return False
                if not eq:
                    if i + 1 >= len(rest):
                        return False
                    val, i = rest[i + 1], i + 1
                i += 1
                if key in seen:
                    return False
                seen.add(key)
                if key == '--pid':
                    if not PID_OPT_VALUE.fullmatch(val) or any(int(p) <= 1 for p in val.split(',')):
                        return False
                elif key == '--reason':
                    if not val.strip():
                        return False
                elif key == '--grace':
                    if not re.fullmatch(r'[0-9]{1,3}(?:\.[0-9]{1,2})?', val):
                        return False
                elif key == '--host':
                    if val not in ('dev2', 't2-dev', 'ah-mac-mini'):
                        return False
                elif not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', val):
                    return False
            return '--pid' in seen and '--reason' in seen

        def check_interpreter(self, name, texts, cmd):
            body = ' '.join(texts)
            for redir in getattr(cmd, 'redirs', []):
                if redir.body:
                    body += '\n' + redir.body
                elif redir.op == '<<<' and redir.target is not None:
                    body += '\n' + redir.target.text
            body = body.replace('kill_guard', '').replace('kill-guard', '')  # the guard's own name
            if name.startswith('python') and '-c' in texts and texts.index('-c') + 1 < len(texts):
                code = texts[texts.index('-c') + 1]
                if pure_data_python(code):  # a program that only formats data: prose in literals is not signalling
                    body = body.replace(code, PY_LITERAL.sub("''", code), 1)
            body = re.sub(r'\b(?:os|process)\.kill\(\s*[\w.]+(?:\(\))?\s*,\s*0\s*\)', '', body)  # liveness probe
            if self.script_kill is not None and self.script_kill.search(body):
                self.block('script-kill', 'interpreter code signals processes the guard cannot check')

        def check_netwatch(self, args):
            texts = [a.text for a in args]
            if 'orphans' not in texts:
                return
            before = texts[:texts.index('orphans')]
            rest = texts[texts.index('orphans') + 1:]
            low = [t.lower() for t in rest]
            if not any(t in ('-kill', '--kill') or t.startswith(('-kill=', '--kill=')) for t in low + [b.lower() for b in before]):
                return  # listing only
            bad, has_pid, i = None, False, 0
            if any(a.dynamic or a.subs for a in args):
                bad = 'a dynamic argument'
            elif any(t.startswith('-') for t in before):
                bad = 'a flag before orphans'
            while i < len(rest) and bad is None:
                t = low[i]
                if t in ('-kill', '--kill', '-json', '--json'):
                    i += 1
                elif t in ('-pid', '--pid'):
                    value = rest[i + 1] if i + 1 < len(rest) else ''
                    if not PID_OPT_VALUE.fullmatch(value):
                        bad = '--pid needs digits'
                    has_pid = True
                    i += 2
                elif t.startswith(('-pid=', '--pid=')):
                    if not PID_OPT_VALUE.fullmatch(rest[i].split('=', 1)[1]):
                        bad = '--pid needs digits'
                    has_pid = True
                    i += 1
                else:
                    bad = 'option %s is not allowed' % one_line(rest[i].split('=', 1)[0], 20)
            if bad is None and not has_pid:
                bad = '--kill without --pid signals every orphan'
            if bad is None and any(int(p) <= 1 for t in rest for p in re.findall(r'\d+', t if t.replace(',', '').isdigit() else '')):
                bad = 'pid 0 or 1'
            if bad:
                self.block('netwatch-broad', 'netwatch orphans --kill is allowed only as --pid N[,N...] (%s); '
                           '--all, --force and --match need the user' % bad)

        def check_kill(self, args, pl, idx):
            error, signal, targets = parse_kill_words(args, self.remote)
            if error:
                self.block('unprovable-target', error)
                return
            if targets is None:
                return  # kill -l and friends only print
            if self.xargs:
                self.block('pidfeed', 'kill through xargs takes its targets from another command, so none can be '
                           'proven yours')
                return
            if not targets:
                return
            probe = signal == '0'
            if probe and len(targets) == 1 and QUOTED_VARIABLE.fullmatch(targets[0].raw or ''):
                return  # exactly one word in both shells, and one word cannot hold both a signal and a target
            pids, problems = [], []
            for w in targets:
                text = word_text(w, quoted_ok=True)
                if text is not None and JOB_SPEC.fullmatch(text):
                    continue
                if text is not None and INTEGER.fullmatch(text) and (probe or 0 < int(text) <= MAX_PID):
                    pids.append(int(text))
                elif w.dynamic or w.subs or w.glob:
                    finder = self.finder_before(pl, idx, w.subs) or any(
                        re.search(r'pgrep|pidof|lsof|ps\b', h) for h in self.ctx.var_hints.values())
                    problems.append(('pidfeed' if finder else 'unprovable-target',
                                     'a kill target comes from %s, so it cannot be proven yours' % (
                                         'a pid finder' if finder else 'a variable, substitution or glob')))
                else:
                    problems.append(('unprovable-target', 'a kill target is not a literal PID or job spec (%N, %%, %+, '
                                     '%-, %name) typed in this command'))
            for rule, reason in problems[:1]:
                self.block(rule, reason)
            if probe and not problems:
                return
            if self.remote:
                self.block('remote-kill', 'kill on a remote host or container cannot be checked for ownership',
                           pids)
                return
            for pid in dict.fromkeys(pids):
                ok, code, detail = self.own.check(pid)
                if not ok:
                    self.block('not-yours', detail, [pid])
                    break

    return KillAnalyzer



def leading_lookup(args):
    """`command -v kill` looks a name up; `command kill 4004 -v` runs kill. Only a bundled -p/-v/-V option before the
    first operand (or before `--`) can make it a lookup."""
    for a in args:
        t = a.text
        if a.dynamic or a.subs or a.glob or not re.fullmatch(r'-[pvV]+', t):
            return False
        if 'v' in t or 'V' in t:
            return True
    return False


def word_text(word, quoted_ok=False, remote=False):
    """The word's text when its source proves it is that one literal word in bash and zsh, else None. Whole-word quotes
    are accepted only where asked; a remote command line is rebuilt with every word single-quoted, so they say nothing
    there. Anything else (escapes, $'..', concatenation, expansions, braces) is not proof, even if it would be literal."""
    if word.dynamic or word.subs or word.glob or len(word.alts) != 1:
        return None
    text = word.text
    forms = {text}
    if quoted_ok or remote:
        forms.add("'%s'" % text)
    if quoted_ok:
        forms.add('"%s"' % text)
    return text if word.raw in forms else None


def parse_kill_words(args, remote=False):
    """Read `kill [SIGNAL] [--] TARGET...` or `kill LIST_FLAG [VALUE...]`. Returns (error, signal, targets); targets is
    None for the printing form. Only the first word can be an option: bash stops there, zsh reads later dash words as
    targets and procps reorders, so a later dash word is left in targets for the target grammar to refuse."""
    if not args:
        return None, None, []
    first = args[0]
    text = first.text
    if not text.startswith('-'):
        return None, None, list(args)
    if word_text(first, remote=remote) is None:
        return 'a kill option is quoted, expanded, braced or a glob, so the shell may read it as something else', None, None
    rest = 1
    signal = None
    if text in LIST_FLAGS:
        for w in args[1:]:
            value = word_text(w, remote=remote)
            if value is None or not SIGNAL_VALUE.fullmatch(value):
                return 'kill -l takes only plain signal names or numbers', None, None
        return None, None, None
    if text in ('-s', '-n', '--signal'):
        if len(args) > 1:
            signal = word_text(args[1], remote=remote)
            if signal is None or not SIGNAL_VALUE.fullmatch(signal):
                return 'the signal value is not one plain name or number, and the shell may split it into more kill ' \
                       'options or targets', None, None
        rest = 2
    elif text.startswith('--signal='):
        signal = text.split('=', 1)[1]
        if not SIGNAL_VALUE.fullmatch(signal):
            return 'the signal value is not one plain signal name or number', None, None
    elif text != '--':
        match = SIGNAL_OPTION.fullmatch(text)
        if match is None:
            return 'kill option %s is outside the literal grammar the guard proves (-SIG, -s SIG, -n SIG, --signal SIG, ' \
                   '--)' % one_line(text.split('=', 1)[0], 20), None, None
        signal = match.group(1)
    if text == '--':
        return None, None, list(args[1:])
    if rest < len(args) and args[rest].text == '--' and word_text(args[rest], remote=remote) == '--':
        rest += 1
    return None, signal, list(args[rest:])


def decide(command, cwd=None, ps=False, ownership=None, policy=None, compiled=None, home=None):
    """Return (verdict, rule, message, pids): verdict is 'allow', 'warn' or 'block'. Never raises."""
    policy = policy or load_policy()
    if policy['mode'] == 'off':
        return 'allow', '', '', ()
    raw = ' '.join(map(str, command)) if isinstance(command, (list, tuple)) else str(command)
    analyzer = None
    try:
        cg = _import_base()
        compiled = compiled or cg.Compiled(cg.load_policy(), cwd=cwd)
        if isinstance(command, (list, tuple)):
            command = ' '.join(cg._quote_for_rebuild(str(c)) for c in command)
        if len(command.encode('utf-8', 'replace')) > int(compiled.limits['max_command_bytes']):
            raise cg.Blocked('command is larger than the analysis limit')
        effective = cwd or compiled.cwd
        own = ownership or Ownership(effective, home=home, policy=policy)
        analyzer = make_analyzer_class(cg)(compiled, effective, ps, own, policy, raw)
        findings = analyzer.run_kill_scan(command)
        if not findings:
            for base in analyzer.ctx.findings:
                if str(getattr(base, 'rule', '')).startswith('obfuscated'):
                    findings = [('obfuscated-input', 'the input feeds decoded text to a shell, so the guard cannot see '
                                 'what runs', ())]
                    break
        if not findings and ps and analyzer.script_kill is not None and analyzer.script_kill.search(command):
            findings = [('script-kill', 'PowerShell code signals processes the guard cannot check', ())]
        if analyzer.ctx.unterminated and not findings and fallback_blocks(raw):
            findings = [('unterminated', 'the command has an unterminated quote or substitution and mentions a kill '
                         'verb or indirection', ())]
        if analyzer.ctx.readings_capped and not findings:  # the kill may be in the reading it dropped, spelled any way
            findings = [('readings-capped', '`>!` could not be judged under both shell readings, so what runs is unknown',
                         ())]
    except Exception as error:  # noqa: BLE001 - Blocked, RecursionError and bugs alike: fail closed on kill-looking text
        # With `>!` in the text the stop can come before a reading main would have judged (a script judged on disk
        # first, GoodQA #14657), so a kill spelled without the word is refused too.
        findings = list(getattr(analyzer, 'kf', None) or ())  # a kill already found stays found when the analysis stops
        if not findings:
            if not (fallback_blocks(raw) or CLOBBER_TEXT.search(LINE_JOIN.sub('', raw))):
                return 'allow', '', '', ()
            rule = 'unanalysable'
            reason = 'the command could not be analysed safely (%s) and it mentions a kill verb or indirection' % \
                     type(error).__name__
            audit(rule, raw, (), home)
            return ('block' if policy['mode'] == 'enforce' else 'warn'), rule, block_message(rule, reason), ()
    if not findings:
        return 'allow', '', '', ()
    rule, reason, pids = findings[0]
    message = block_message(rule, reason)
    if len(findings) > 1:  # name every finding, so the blocked command can be fixed in one pass
        also = '; '.join('[%s] %s' % (r, one_line(t, 160)) for r, t, _p in findings[1:9])
        more = ' (+%d more)' % (len(findings) - 9) if len(findings) > 9 else ''
        message = one_line(message + ' Also found: ' + also + more, 1600)
    if policy['mode'] == 'warn':
        return 'warn', rule, message.replace('BLOCKED', 'WARNING'), pids
    audit(rule, raw, pids, home)
    return 'block', rule, message, pids


# --------------------------------------------------------------------------- hook entry points

def guarded_text(raw):
    """(is_shell_tool, command text) for a PreToolUse payload; unparsable input counts as guarded."""
    try:
        payload = json.loads(raw)
    except ValueError:
        return True, raw
    if not isinstance(payload, dict):
        return True, raw
    tool = str(payload.get('tool_name') or payload.get('toolName') or '').casefold()
    tool_input = payload.get('tool_input') or payload.get('toolInput') or {}
    has_command = isinstance(tool_input, dict) and any(k in tool_input for k in COMMAND_KEYS[:3])
    if tool and tool not in GUARDED_TOOLS and not tool.startswith(('bash', 'shell', 'exec')) and not has_command:
        return False, ''
    if isinstance(tool_input, dict):
        parts = []
        for key in COMMAND_KEYS:
            value = tool_input.get(key)
            if isinstance(value, list):
                parts.append(' '.join(str(v) for v in value))
            elif isinstance(value, str):
                parts.append(value)
        return True, '\n'.join(parts) or raw
    return True, raw if not isinstance(tool_input, str) else tool_input


def emit(verdict, message):
    if verdict == 'block':
        sys.stderr.write(message + '\n')
        return 2
    if verdict == 'warn':
        print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'additionalContext': message}}))
    return 0


def analyze_main(data=None):
    """Child process: judge one payload. Exit 0 allow/warn, 2 block."""
    policy = load_policy()
    limit = int(policy['child_timeout_seconds'])
    if hasattr(signal, 'SIGALRM'):
        def _timeout(_s, _f):
            raise TimeoutError('kill_guard wall-clock limit')
        signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(max(2, limit - 2))
    raw = ''
    try:
        data = data if data is not None else sys.stdin.buffer.read(MAX_STDIN + 1)
        raw = data.decode('utf-8', 'replace')
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = None
        if payload is None:
            if fallback_blocks(raw):
                return emit('block', block_message('unparsable-payload', 'the hook payload is not valid JSON and '
                                                   'mentions a kill verb or indirection'))
            return 0
        cg = _import_base()
        command, ps = cg.extract_command(payload)
        if command is None:
            guarded, text = guarded_text(raw)
            if not guarded:
                return 0
            command = text  # a tool the launcher treats as a shell tool (a command/cmd/script key): judge its text
        cwd = cg.payload_cwd(payload)
        verdict, _rule, message, _pids = decide(command, cwd=cwd, ps=ps, policy=policy)
        return emit(verdict, message)
    except TimeoutError:
        if fallback_blocks(raw):
            return emit('block', block_message('timeout', 'analysis exceeded its time limit and the input mentions a '
                                               'kill verb or indirection'))
        return 0
    except Exception as error:  # noqa: BLE001
        if fallback_blocks(raw):
            return emit('block', block_message('guard-error', 'the guard failed (%s) on input that mentions a kill '
                                               'verb or indirection' % type(error).__name__))
        sys.stderr.write('kill_guard: internal error (%s); the command looked harmless and was allowed\n' %
                         type(error).__name__)
        return 0
    finally:
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)


def hook_main():
    """PreToolUse launcher: runs analyze in a child so a crash, hang or garbage answer cannot become a silent allow
    (Codex treats a crashing hook as allow)."""
    try:
        data = sys.stdin.buffer.read(MAX_STDIN + 1)
    except Exception:  # noqa: BLE001
        return 0
    oversized = len(data) > MAX_STDIN
    raw = data[:MAX_STDIN].decode('utf-8', 'replace')
    guarded, text = guarded_text(raw)
    if not guarded:
        return 0
    if oversized:
        return emit('block', block_message('oversized-input', 'the tool input is larger than the guard analyses; '
                                           'put the commands in a script file'))
    policy = load_policy()
    if policy['mode'] == 'off':
        return 0
    try:
        child = subprocess.run([sys.executable, '-I', os.path.abspath(__file__), 'analyze'], input=data,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=float(policy['child_timeout_seconds']), check=False)
    except subprocess.TimeoutExpired:
        return _fallback(raw, text, 'timed out')
    except Exception as error:  # noqa: BLE001
        return _fallback(raw, text, 'could not start (%s)' % type(error).__name__)
    if child.returncode in (0, 2):
        out = child.stdout.decode('utf-8', 'replace')
        if out.strip():
            try:
                json.loads(out)
            except ValueError:
                return _fallback(raw, text, 'printed invalid output')
            sys.stdout.write(out)
        err = child.stderr.decode('utf-8', 'replace')[:2000]
        if child.returncode == 2 and ALTERNATIVE.split('<')[0] not in err:
            return _fallback(raw, text, 'blocked without the standard message')
        sys.stderr.write(err)
        return child.returncode
    return _fallback(raw, text, 'crashed (exit %d)' % child.returncode)


def _fallback(raw, text, why):
    if fallback_blocks(raw) or fallback_blocks(text):
        return emit('block', block_message('guard-failure', 'the analyser %s and the input mentions a kill verb or '
                                           'indirection' % why))
    sys.stderr.write('kill_guard: analyser %s; the command looked harmless and was allowed\n' % why)
    return 0


# --------------------------------------------------------------------------- spawn and explain

def spawn_main(argv):
    """`kill_guard.py spawn [--log FILE] -- CMD ARGS...`: start CMD detached and record it in this worktree's ledger.

    The guard only believes the ledger for PIDs it started itself: spawn takes a command, never a PID."""
    log = None
    args = list(argv)
    if args[:1] == ['--log'] and len(args) >= 2:
        log, args = args[1], args[2:]
    if args[:1] == ['--']:
        args = args[1:]
    if not args:
        sys.stderr.write('usage: kill_guard.py spawn [--log FILE] -- CMD [ARGS...]\n')
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
    """`kill_guard.py explain FILE [--cwd DIR]`: FILE holds a command (text) or a hook payload (JSON)."""
    if not argv:
        sys.stderr.write('usage: kill_guard.py explain FILE [--cwd DIR]\n')
        return 2
    cwd = argv[argv.index('--cwd') + 1] if '--cwd' in argv and argv.index('--cwd') + 1 < len(argv) else os.getcwd()
    with open(argv[0], 'rb') as handle:
        text = handle.read(MAX_STDIN).decode('utf-8', 'replace')
    verdict, rule, message, pids = decide(text, cwd=cwd)
    print(json.dumps({'verdict': verdict, 'rule': rule, 'message': message, 'pids': list(pids)}))
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ('-h', '--help'):
        sys.stdout.write(__doc__.split('Entry points')[0] + 'Commands: hook | analyze | spawn | explain\n')
        return 0
    command, rest = argv[0], argv[1:]
    if command == 'hook':
        return hook_main()
    if command == 'analyze':
        return analyze_main()
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
    except BaseException:  # noqa: BLE001 - never let a launcher bug become a silent allow
        sys.stderr.write(block_message('guard-failure', 'the launcher failed') + '\n')
        sys.exit(2)
