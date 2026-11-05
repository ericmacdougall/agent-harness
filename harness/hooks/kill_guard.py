#!/usr/bin/env python3
"""PreToolUse guard against broad process kills and kills of processes the caller does not own (GoodQA #14506).

Why: on 2026-11-04 an owner piped pgrep -f into xargs kill and an earlier owner ran pkill -f; both stopped other
owners' test runs on a shared dev host.

What it blocks, before the command runs, on Claude Code (Bash, PowerShell) and Codex (every shell tool):
  * pkill, killall, killall5, skill, slay, fuser -k, taskkill, Stop-Process, systemctl/launchctl kill, interpreter
    code that signals processes (os.kill, process.kill, psutil ...), find -exec / parallel running those verbs;
  * kill whose targets come from a pid finder (xargs, $(...), backticks, read or for loops with a variable);
  * a plain `kill PID` unless every target is a literal PID that is provably the caller's own: its cwd, or argv[0]
    or argv[1], is inside the caller's own git worktree (the toplevel of the tool call's cwd), or it is in the
    per-worktree spawn ledger written by `kill_guard.py spawn -- CMD...`;
  * every kill inside ssh, mosh, docker exec and kubectl exec (ownership cannot be checked locally) except
    `netwatch orphans --kill --pid N[,N...]`.
Allowed: kill -0, kill -l, kill %N and kill $! after a background job in the same input, process listing, and text
that merely contains the word.

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
PROTECTED_COMM = {'claude', 'codex', 'sshd', 'launchd', 'systemd', 'init', 'tmux', 'screen', 'netwatch', 'login'}
INTERPRETER_COMM = {'python', 'python3', 'node', 'nodejs', 'ruby', 'perl', 'php', 'deno', 'bun', 'bash', 'sh', 'zsh',
                    'dash', 'ksh', 'lua', 'pypy', 'pypy3', 'uv', 'java'}
OVERRIDDEN = ('apply', 'inner_words', 'script', 'ssh', 'container', 'pipeline', 'bind_loop_var')

DEFAULT_POLICY = {
    'mode': 'enforce',
    'broad_verbs': ['pkill', 'killall', 'killall5', 'skill', 'slay', 'pkill-all'],
    'windows_verbs': ['taskkill', 'stop-process', 'spps', 'wmic'],
    'service_kill': {'systemctl': ['kill'], 'launchctl': ['kill'], 'loginctl': ['kill-session', 'kill-user']},
    'script_kill_pattern': r'os\.kill|os\.killpg|pthread_kill|process\.kill\(|Process\.kill|psutil|\bpkill\b|\bkillall\b|\btaskkill\b',
    'pid_finders': ['pgrep', 'pidof', 'ps', 'lsof', 'fuser', 'pstree', 'cat', 'awk', 'grep'],
    'ledger_max_lines': 2000,
    'child_timeout_seconds': 10,
}

KILLISH = re.compile(r'kill|fuser|stop-process|spps|slay|wmic')
INDIRECT = re.compile(r"\$'|\\x[0-9a-fA-F]{2}|\\[0-7]{3}|\beval\b|base64|\bxxd\b", re.I)
JOB_SPEC = re.compile(r'%(?:[0-9]+|[%+\-]|\?\S+|[A-Za-z_]\S*)?')
LIST_FLAGS = {'-l', '-L', '--list', '-t', '--table', '-Ll', '-lL'}
SIGNAL_NAME = re.compile(r'-(?:sig)?([A-Za-z0-9+]+)', re.I)
PID_OPT_VALUE = re.compile(r'[0-9]+(?:,[0-9]+)*')


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


def norm_raw(text):
    """Raw text with quoting, backslashes, braces and $ removed, NFKC and case-folded: the loose probe used where
    the parser is unavailable. `pk""ill`, `p\\kill` and `$'\\x70kill'` all still contain `kill`."""
    text = unicodedata.normalize('NFKC', text)
    text = ''.join(ch for ch in text if ch not in '\'"\\${}`' and unicodedata.category(ch) != 'Cf')
    return text.casefold()


def fallback_blocks(raw):
    """Used when the analyser cannot run: block kill-looking or indirect input, allow the rest."""
    text = raw[:4_000_000]
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


def _read_secure_file(path, limit):
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
    data = _read_secure_file(ledger_path(root, home), 1 << 20)
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
        """argv[0:2] as a list. On macOS only the whitespace-split `ps` command is available, so paths with spaces
        are not recognised there (unprovable, which is the safe side)."""
        if self.proc:
            try:
                with open('/proc/%d/cmdline' % pid, 'rb') as handle:
                    raw = handle.read(65536)
            except OSError:
                return None
            parts = [p.decode('utf-8', 'replace') for p in raw.split(b'\0') if p]
            return parts[:2] or None
        out = _run(['ps', '-ww', '-o', 'command=', '-p', str(pid)])
        parts = out.split() if out else []
        return parts[:2] or None


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
    if root == '/' or under(home_path, root) or root.count('/') < 2:
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
        if comm in PROTECTED_COMM:
            return False, 'protected', 'pid %d is a protected process (%s)' % (pid, one_line(comm, 20))
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
        if len(argv) > 1 and os.path.basename(argv[0]).casefold().rstrip('0123456789.-') in INTERPRETER_COMM \
                and '/' in argv[1] and self._inside(argv[1], root, nested):
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
            self.bg_seen = False
            self.broad = set(policy['broad_verbs'])
            self.windows = set(policy['windows_verbs'])
            self.script_kill = re.compile(policy['script_kill_pattern'])
            self.finders = set(policy['pid_finders'])

        # ---- findings
        def block(self, rule, reason, pids=()):
            self.kf.append((rule, reason, tuple(pids)))

        def run_kill_scan(self, text):
            self.script(text, depth=0)
            return self.kf

        # ---- overridden traversal hooks (OVERRIDDEN lists them; a test pins the base signatures)
        def script(self, text, depth, tail_visible=None, ps=None):
            saved, self.xargs = self.xargs, 0
            try:
                return super().script(text, depth, tail_visible=tail_visible, ps=ps)
            finally:
                self.xargs = saved

        def pipeline(self, pl, depth):
            super().pipeline(pl, depth)
            if getattr(pl, 'bg', False):
                self.bg_seen = True

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
            value_opts = set('bcDEeFIiJLlmOopQRSWw')
            i = 0
            while i < len(texts):
                t = texts[i]
                if t.startswith('-') and len(t) > 1:
                    i += 2 if len(t) == 2 and t[1] in value_opts else 1
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
                return super().ssh(args, depth)
            finally:
                self.remote -= 1

        def container(self, name, args, words, depth, pl, idx):
            self.remote += 1
            try:
                return super().container(name, args, words, depth, pl, idx)
            finally:
                self.remote -= 1

        def apply(self, name, words, cmd, pl, idx, depth):
            self.inspect(name, words, cmd, pl, idx, depth)
            return super().apply(name, words, cmd, pl, idx, depth)

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
            if head.dynamic and not head.subs:
                hints = ' '.join(self.ctx.var_hints.values())
                if KILLISH.search(norm_raw(head.text + ' ' + hints)):
                    self.block('dynamic-head', 'the command name is built at run time and the input mentions kill')
            if name in self.broad:
                self.block('broad-kill', '`%s` signals processes by name or pattern and can hit other owners' % name)
            elif name in self.windows:
                if name != 'wmic' or any(t.casefold() in ('delete', 'terminate') for t in texts):
                    self.block('windows-kill', '`%s` cannot be checked for ownership' % name)
            elif name == 'kill':
                if self.ctx.ps:
                    self.block('windows-kill', 'PowerShell kill is Stop-Process and cannot be checked for ownership')
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
            elif name in ('find', 'parallel'):
                self.check_indirect(name, args, texts)
            elif name in ('busybox', 'toybox', 'systemd-run') and args:
                rest = [a for a in args if not a.text.startswith('-')][:1]
                if rest:
                    self.inner_words(args[args.index(rest[0]):], depth, pl, idx)
            elif name in cg.INTERPRETERS:
                self.check_interpreter(name, texts, cmd)
            self.check_spawn(name, args, texts, depth, pl, idx)

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
                for t in texts:
                    if t == ':::':
                        break
                    if cg.norm_name(t) in verbs:
                        hit = True
            if hit:
                self.block('indirect-kill', '`%s` runs a kill verb on targets the guard cannot list' % name)

        def check_interpreter(self, name, texts, cmd):
            body = ' '.join(texts)
            for redir in getattr(cmd, 'redirs', []):
                if redir.body:
                    body += '\n' + redir.body
                elif redir.op == '<<<' and redir.target is not None:
                    body += '\n' + redir.target.text
            if self.script_kill.search(body):
                self.block('script-kill', 'interpreter code signals processes the guard cannot check')

        def check_netwatch(self, args):
            texts = [a.text for a in args]
            if 'orphans' not in texts:
                return
            rest = texts[texts.index('orphans') + 1:]
            low = [t.lower() for t in rest]
            if not any(t in ('-kill', '--kill') or t.startswith(('-kill=', '--kill=')) for t in low):
                return  # listing only
            bad, has_pid, i = None, False, 0
            if any(a.dynamic or a.subs for a in args):
                bad = 'a dynamic argument'
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
                    bad = '%s is not allowed' % one_line(rest[i], 30)
            if bad is None and not has_pid:
                bad = '--kill without --pid signals every orphan'
            if bad:
                self.block('netwatch-broad', 'netwatch orphans --kill is allowed only as --pid N[,N...] (%s); '
                           '--all, --force and --match need the user' % bad)

        def check_kill(self, args, pl, idx):
            texts = [a.text for a in args]
            targets, i, n, signal_seen = [], 0, len(args), False
            while i < n:
                t, w = texts[i], args[i]
                if not targets and not w.dynamic:
                    if t == '--':
                        i += 1
                        while i < n:
                            targets.append(args[i])
                            i += 1
                        break
                    if t in LIST_FLAGS:
                        return
                    if t in ('-s', '-n', '--signal'):
                        if i + 1 < n and texts[i + 1] == '0':
                            return
                        signal_seen = True
                        i += 2
                        continue
                    if t.startswith('--signal='):
                        if t.split('=', 1)[1] == '0':
                            return
                        signal_seen = True
                        i += 1
                        continue
                    if t.startswith('--'):
                        i += 1
                        continue
                    match = SIGNAL_NAME.fullmatch(t) if not signal_seen else None
                    if match:
                        if match.group(1) == '0':
                            return
                        signal_seen = True
                        i += 1
                        continue
                targets.append(w)
                i += 1
            if self.xargs:
                self.block('pidfeed', 'kill through xargs takes its targets from another command, so none can be '
                           'proven yours')
                return
            if not targets:
                return
            pids, problems = [], []
            for w in targets:
                if w.dynamic or w.subs or w.glob:
                    finder = self.finder_before(pl, idx, w.subs) or any(
                        re.search(r'pgrep|pidof|lsof|ps\b', h) for h in self.ctx.var_hints.values())
                    problems.append(('pidfeed' if finder else 'unprovable-target',
                                     'a kill target comes from %s, so it cannot be proven yours' % (
                                         'a pid finder' if finder else 'a variable, substitution or glob')))
                    continue
                for alt in w.alts[:32]:
                    if alt == '$!':
                        if not self.bg_seen:
                            problems.append(('unprovable-target', '$! has no background job in this input'))
                    elif JOB_SPEC.fullmatch(alt):
                        continue
                    elif re.fullmatch(r'[0-9]{1,10}', alt, re.ASCII) and 0 < int(alt) <= MAX_PID:
                        pids.append(int(alt))
                    else:
                        problems.append(('unprovable-target', 'kill target %s is not a plain positive PID' % one_line(alt, 20)))
            for rule, reason in problems[:1]:
                self.block(rule, reason)
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


def decide(command, cwd=None, ps=False, ownership=None, policy=None, compiled=None, home=None):
    """Return (verdict, rule, message, pids): verdict is 'allow', 'warn' or 'block'. Never raises."""
    policy = policy or load_policy()
    if policy['mode'] == 'off':
        return 'allow', '', '', ()
    raw = ' '.join(map(str, command)) if isinstance(command, (list, tuple)) else str(command)
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
    except Exception as error:  # noqa: BLE001 - Blocked, RecursionError and bugs alike: fail closed on kill-looking text
        if fallback_blocks(raw):
            rule = 'unanalysable'
            reason = 'the command could not be analysed safely (%s) and it mentions a kill verb or indirection' % \
                     type(error).__name__
            audit(rule, raw, (), home)
            return ('block' if policy['mode'] == 'enforce' else 'warn'), rule, block_message(rule, reason), ()
        return 'allow', '', '', ()
    if not findings:
        return 'allow', '', '', ()
    rule, reason, pids = findings[0]
    message = block_message(rule, reason)
    if len(findings) > 1:
        message = one_line(message + ' (%d more)' % (len(findings) - 1), 520)
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
            return 0
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
                                           'put the commands in a script file')) if fallback_blocks(raw) or True else 0
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
    out = open(log, 'ab') if log else subprocess.DEVNULL
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
    text = Path(argv[0]).read_text(encoding='utf-8', errors='replace')
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
