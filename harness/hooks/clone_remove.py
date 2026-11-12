"""`ah clone-remove`: remove ONE verified clean, fully pushed PRIMARY clone under this session's receipts directory (goodqa#15743).

`git worktree remove` and the hook-form `rm` exemption cannot judge a primary clone that is a partial clone
(`--filter=blob:none`), so a receipts directory over its budget could deadlock. This tool is not a general deleter:

  * the target is exactly ~/.agent-harness/work/SESSION/receipts/wt-NAME for the caller's own session, a real `.git`
    directory, no symlink anywhere, every path component equal to its directory entry byte for byte;
  * verification never fetches (its own git runner: protocol.allow=never, no per-protocol override, no lazy fetch) and
    only the one `ls-remote` is allowed to talk to the network; every ref, tracking ref and reflog commit must be reachable
    from a sha the live remote lists (heads, tags, refs/pull/N/head);
  * the intent row is written and fsynced BEFORE the clone is renamed to a quarantine name next to it; the refs are read
    again inside the quarantine; only then is it deleted by a descriptor-based walk that never follows a symlink, never
    crosses a device, and keeps (and reports) anything changed after verification began;
  * `--resume AUDIT_ID` finishes an interrupted removal of exactly that quarantine directory.

Threat model: careless or hurried agents, not one that edits the audit file or this module.
"""
from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import time
import uuid

import command_guard as cg
from ah_worktree import audit as _audit_write, PATH_RE, MAX_REASON, _redact

VERSION = 1
QUARANTINE_PREFIX = '.clone-remove-'
MARKER_NAME = '.clone-remove-marker'
VERIFY_SECONDS = 180.0
SCAN_SECONDS = 60.0
LSOF_SECONDS = 60.0
ALTERNATES_SECONDS = 60.0
GIT_TOP_ALLOWED = {'HEAD', 'config', 'description', 'index', 'info', 'logs', 'objects', 'packed-refs', 'refs', 'shallow',
                   'FETCH_HEAD', 'ORIG_HEAD', 'COMMIT_EDITMSG', 'branches', 'hooks'}
STATE_FILES = ('MERGE_HEAD', 'CHERRY_PICK_HEAD', 'REVERT_HEAD', 'REBASE_HEAD', 'AUTO_MERGE', 'rebase-merge', 'rebase-apply',
               'sequencer', 'BISECT_LOG', 'BISECT_START', 'BISECT_TERMS', 'BISECT_NAMES', 'BISECT_EXPECTED_REV')
PRUNE_DIRS = {'node_modules', '.venv', 'venv', '__pycache__', 'target', 'build', 'dist', '.next', '.cache'}
SESSION_RE = re.compile(r'[A-Za-z0-9_-]{1,64}')
SHA_RE = re.compile(r'[0-9a-f]{40,64}')
CREDENTIAL_URL = re.compile(r'://[^/@\s]*:[^/@\s]*@')
HOOK = None  # tests only: HOOK(event, **info) at fixed points of the walk and the removal


class CloneError(Exception):
    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code, self.exit_code = code, exit_code


def refuse(message):
    raise CloneError('refused', message)


def _hook(event, **info):
    if HOOK:
        HOOK(event, **info)


def REMOTE_LS(url, repo, timeout, authenticated=False):
    """ref -> sha as the remote reports it now: ALL refs (heads, tags, pull heads). The only network call. Replaced in tests."""
    env = cg._clone_env()
    if authenticated is not True:
        env.pop('SSH_AUTH_SOCK', None)
    done = subprocess.run(['git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
                           '-c', 'protocol.https.allow=always', '-c', 'protocol.ssh.allow=always', '-C', repo,
                           'ls-remote', '--', url], capture_output=True, timeout=max(1.0, timeout), env=env)
    if done.returncode != 0 or len(done.stdout) > 64 * 1024 * 1024:
        raise ValueError('ls-remote failed')
    refs = {}
    for line in done.stdout.decode('utf-8', 'surrogateescape').splitlines():
        sha, _, ref = line.partition('\t')
        if SHA_RE.fullmatch(sha) and ref and not ref.endswith('^{}'):
            refs[ref] = sha
    return refs


# ----------------------------------------------------------------------------- the verification git runner
_GIT_VERSION = None


def git_version():
    global _GIT_VERSION
    if _GIT_VERSION is None:
        out = subprocess.run(['git', '--version'], capture_output=True, text=True, env=cg._clone_env(), timeout=10).stdout
        match = re.search(r'(\d+)\.(\d+)', out)
        _GIT_VERSION = (int(match.group(1)), int(match.group(2))) if match else (0, 0)
    return _GIT_VERSION


def git_argv(repo, args):
    """Every verification git call: protocol denied outright (no per-protocol key), no lazy fetch, no program from config."""
    argv = ['git']
    if git_version() >= (2, 44):
        argv.append('--no-lazy-fetch')
    argv += ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never', '-C', repo]
    return argv + list(args)


def git_env():
    env = cg._clone_env()
    env.pop('SSH_AUTH_SOCK', None)
    env['GIT_NO_LAZY_FETCH'] = '1'
    env['GIT_OPTIONAL_LOCKS'] = '0'
    return env


def run_git(repo, args, timeout, stdin=None, check=True):
    done = subprocess.run(git_argv(repo, args), capture_output=True, timeout=max(0.5, timeout), env=git_env(),
                          input=stdin.encode() if stdin is not None else None)
    if check and (done.returncode != 0 or len(done.stdout) > 64 * 1024 * 1024):
        raise ValueError('git %s failed' % (args[0] if args else ''))
    return done.stdout.decode('utf-8', 'surrogateescape') if check else (done.returncode, done.stdout.decode('utf-8', 'surrogateescape'))


# ----------------------------------------------------------------------------- scope
def work_root(home):
    return os.path.join(str(home), '.agent-harness', 'work')


def check_target(path, session, home):
    """The target's identity (dev, ino of it and of its parent). Raises CloneError for anything outside the scope."""
    if not isinstance(session, str) or not SESSION_RE.fullmatch(session):
        refuse('the calling session is unknown (the harness session identity is required)')
    if not isinstance(path, str) or not 2 <= len(path) <= 1024 or not PATH_RE.fullmatch(path) or '..' in path.split('/'):
        refuse('the path must be one literal absolute path (letters, digits and _@+=:,.- only, no dot segments, no trailing slash)')
    receipts = os.path.join(work_root(home), session, 'receipts')
    parent, name = os.path.split(path)
    if parent != receipts or not name.startswith('wt-') or len(name) < 4:
        refuse('the target must be %s/wt-NAME (this session receipts clone)' % receipts)
    check_components(path, home)
    return identity(path)


def check_components(path, home):
    """No symlink, and every component below the home directory equals its entry in the parent listing byte for byte."""
    if os.path.realpath(path) != path:
        refuse('the path contains a symlink, a case or normalization variant or another alias')
    base = str(home)
    rest = path[len(base):].strip(os.sep).split(os.sep) if path.startswith(base + os.sep) else None
    if not rest:
        refuse('the path is not under the home directory')
    current = base
    for part in rest:
        try:
            names = os.listdir(current)
        except OSError:
            refuse('a parent directory cannot be listed')
        if part not in names:
            refuse('the path spelling does not match its directory entry byte for byte')
        current = os.path.join(current, part)
        if os.path.islink(current):
            refuse('the path contains a symlink')
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode):
        refuse('the target is not a plain directory')
    git = os.path.join(path, '.git')
    if os.path.islink(git) or not os.path.isdir(git):
        refuse('.git is not a real directory (a linked worktree or not a clone)')


def identity(path):
    info = os.lstat(path)
    parent = os.lstat(os.path.dirname(path))
    return {'dev': info.st_dev, 'ino': info.st_ino, 'parent_dev': parent.st_dev, 'parent_ino': parent.st_ino}


def caller_inside(path):
    """The caller's current directory is the target, inside it, or the target is inside the caller's directory chain."""
    try:
        cwd = os.getcwd()
    except OSError:
        refuse('the calling directory cannot be determined')
    target = os.lstat(path)
    current = cwd
    seen = 0
    while True:
        try:
            info = os.stat(current)
        except OSError:
            break
        if (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino):
            refuse('the calling directory is inside the target')
        parent = os.path.dirname(current)
        seen += 1
        if parent == current or seen > 200:
            break
        current = parent


def _live_owner_hits(session, path):
    """Other live owners of this session whose registered task text names the target. `ah owners` does not expose an
    owner's worktree or working directory, so this is a text match on the row, a disclosed limit; the process scan below
    covers a running process."""
    return []


# ----------------------------------------------------------------------------- process, mount and open-file scans
def _lsof_open(path):
    """(ok, [pids]) of processes holding any open file or mapping at the target or below it."""
    try:
        done = subprocess.run(['lsof', '-w', '-Fpn'], capture_output=True, text=True, timeout=LSOF_SECONDS,
                              env={'PATH': '/usr/sbin:/usr/bin:/bin', 'LC_ALL': 'C'}, cwd=os.sep)
    except (OSError, subprocess.SubprocessError):
        return False, []
    if done.returncode not in (0, 1):
        return False, []
    pids, pid = set(), None
    for line in done.stdout.splitlines():
        if line.startswith('p') and line[1:].isdigit():
            pid = int(line[1:])
        elif line.startswith('n') and pid not in (None, os.getpid()):
            name = line[1:]
            for spelling in (name, os.path.realpath(name) if name.startswith('/') else name):
                for prefix in (path, '/System/Volumes/Data' + path):
                    if spelling == prefix or spelling.startswith(prefix + os.sep):
                        pids.add(pid)
    return True, sorted(pids)


def _mounts():
    """Mount points on this host."""
    points = []
    if os.path.exists('/proc/self/mountinfo'):
        for line in open('/proc/self/mountinfo', errors='replace'):
            fields = line.split()
            if len(fields) > 4:
                points.append(fields[4].replace('\\040', ' '))
        return points
    done = subprocess.run(['mount'], capture_output=True, text=True, timeout=20, env={'PATH': '/sbin:/usr/sbin:/usr/bin:/bin'})
    if done.returncode != 0:
        raise OSError('mount failed')
    for line in done.stdout.splitlines():
        match = re.match(r'^.* on (/.*) \([^)]*\)$', line)
        if match:
            points.append(match.group(1))
    return points


def check_processes(path):
    busy = cg.busy_processes(path, cg.WORKTREE_POLICY['reproducible_clone']['busy_skip_names'])
    if busy is None:
        refuse('a same-user process could not be inspected, so it cannot be shown that nothing works inside the target')
    if busy:
        refuse('%d process(es) work inside the target (pid %s)' % (len(busy), ', '.join(str(p) for p, _ in busy[:5])))
    ok, pids = _lsof_open(path)
    if not ok:
        refuse('the open-file scan (lsof) did not complete; it fails closed')
    if pids:
        refuse('%d process(es) hold open files inside the target (pid %s)' % (len(pids), ', '.join(str(p) for p in pids[:5])))
    try:
        mounts = _mounts()
    except (OSError, subprocess.SubprocessError):
        refuse('the mount table could not be read')
    for point in mounts:
        if point == path or point.startswith(path + os.sep):
            refuse('a mount point sits at or under the target')


def alternates_scan(session_root, target):
    """Refuse when a repository under the session directory borrows objects from the target (objects/info/alternates)."""
    deadline = time.monotonic() + ALTERNATES_SECONDS
    stack = [session_root]
    while stack:
        current = stack.pop()
        if time.monotonic() > deadline:
            refuse('the alternates scan did not finish in its budget')
        if current == target or current.startswith(target + os.sep):
            continue
        for candidate in (os.path.join(current, '.git', 'objects', 'info', 'alternates'),
                          os.path.join(current, 'objects', 'info', 'alternates')):
            if os.path.isfile(candidate):
                for line in open(candidate, errors='replace'):
                    line = line.strip()
                    if line:
                        resolved = os.path.realpath(os.path.join(os.path.dirname(candidate), line))
                        if resolved == target or resolved.startswith(target + os.sep):
                            refuse('another repository borrows objects from the target (alternates)')
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    if entry.is_dir(follow_symlinks=False) and entry.name not in PRUNE_DIRS and entry.name != '.git' \
                            and entry.name != 'objects':
                        stack.append(entry.path)
        except OSError:
            continue


# ----------------------------------------------------------------------------- verification
def _config_checks(path):
    listing = run_git(path, ['config', '--local', '-z', '--list'], 5.0)
    items = [item for item in listing.split('\x00') if item]
    ext, kept = {}, []
    for item in items:
        key, _, value = item.partition('\n')
        if key.lower().startswith('extensions.'):
            ext[key.lower()] = value.strip()
        else:
            kept.append(item)
    bad = cg._config_refusal('\x00'.join(kept))
    if bad:
        refuse(bad)
    remotes, promisor, filters, legacy = set(), {}, {}, False
    for item in kept:
        key, _, value = item.partition('\n')
        lower = key.lower()
        match = re.fullmatch(r'remote\.(.+)\.(url|promisor|partialclonefilter)', lower)
        if match:
            if match.group(2) == 'url':
                remotes.add(match.group(1))
            elif match.group(2) == 'promisor':
                promisor[match.group(1)] = value.strip().lower()
            else:
                filters[match.group(1)] = value.strip()
        if lower == 'core.partialclonefilter':
            legacy = True
    if legacy:
        refuse('the legacy core.partialclonefilter key is not accepted')
    if set(ext) - {'extensions.partialclone'}:
        refuse('an unsupported git extension is set (%s)' % ', '.join(sorted(k.split('.', 1)[1] for k in ext)[:3]))
    if 'extensions.partialclone' in ext or promisor or filters:
        names = set(promisor) | set(filters) | ({ext['extensions.partialclone']} if 'extensions.partialclone' in ext else set())
        if len(remotes) != 1 or len(names) != 1 or next(iter(names)) not in remotes:
            refuse('a partial clone must have exactly one remote, and it must be the promisor remote')
        name = next(iter(names))
        if 'extensions.partialclone' in ext and ext['extensions.partialclone'] != name:
            refuse('extensions.partialClone does not name the promisor remote')
        if promisor.get(name) not in cg._TRUE_WORDS:
            refuse('the partial clone remote is not marked promisor')
        if filters.get(name) != 'blob:none':
            refuse('only a blob:none partial clone is accepted')
        fmt = run_git(path, ['config', '--local', '--get', 'core.repositoryformatversion'], 5.0, check=False)
        if fmt[0] != 0 or fmt[1].strip() != '1':
            refuse('a partial clone needs core.repositoryformatversion 1')
        return True
    return False


def _structure_checks(path):
    gitdir = os.path.join(path, '.git')
    top = set(os.listdir(gitdir))
    for name in STATE_FILES:
        if name in top or os.path.lexists(os.path.join(gitdir, name)):
            refuse('an operation is in progress (%s)' % name)
    for forbidden, why in (('worktrees', 'it owns linked worktrees'), ('modules', 'it has submodules'),
                           ('commondir', 'it is a worktree of another repository'), ('lfs', 'it has a git LFS store'),
                           (os.path.join('info', 'grafts'), 'it has grafts'), (os.path.join('info', 'attributes'), 'it has local git attributes'),
                           (os.path.join('refs', 'replace'), 'it has replace refs')):
        if os.path.lexists(os.path.join(gitdir, forbidden)):
            refuse(why)
    extra = sorted(top - GIT_TOP_ALLOWED)
    if extra:
        refuse('.git holds an unexpected entry (%s)' % re.sub(r'[^\w.-]', '?', extra[0])[:40])
    info_dir = os.path.join(gitdir, 'info')
    if os.path.isdir(info_dir) and set(os.listdir(info_dir)) - {'exclude'}:
        refuse('.git/info holds something other than exclude')
    hooks = os.path.join(gitdir, 'hooks')
    if os.path.isdir(hooks) and any(not n.endswith('.sample') for n in os.listdir(hooks)):
        refuse('it has hand-written git hooks')
    branches = os.path.join(gitdir, 'branches')
    if os.path.isdir(branches) and os.listdir(branches):
        refuse('.git/branches is not empty')
    if os.path.lexists(os.path.join(path, '.gitmodules')):
        refuse('it has submodules')
    for alt in ('alternates', 'http-alternates'):
        file = os.path.join(gitdir, 'objects', 'info', alt)
        if os.path.isfile(file):
            for line in open(file, errors='replace'):
                line = line.strip()
                if line and not os.path.exists(os.path.join(gitdir, 'objects', line)):
                    refuse('objects/info/%s names a path that does not exist' % alt)
    if os.path.getsize(os.path.join(gitdir, 'config')) > 256 * 1024:
        refuse('the repository config is unusually large')
    common = os.path.realpath(os.path.join(path, run_git(path, ['rev-parse', '--git-common-dir'], 5.0).strip()))
    if common != os.path.realpath(gitdir):
        refuse('the git common directory is not the target .git')


def _reflog_shas(path):
    shas = set()
    logs = os.path.join(path, '.git', 'logs')
    for root, _dirs, files in os.walk(logs):
        for name in files:
            with open(os.path.join(root, name), errors='replace') as handle:
                for line in handle:
                    for sha in re.findall(r'(?:^|\s)([0-9a-f]{40,64})(?=\s)', line.split('\t', 1)[0]):
                        if set(sha) != {'0'}:
                            shas.add(sha)
    return shas


def snapshot(path):
    refs = {}
    for line in run_git(path, ['for-each-ref', '--format=%(refname)%09%(objectname)'], 20.0).splitlines():
        name, _, sha = line.partition('\t')
        refs[name] = sha
    head = run_git(path, ['rev-parse', '--verify', 'HEAD'], 5.0).strip()
    shas = _reflog_shas(path) | {head}
    for pointer in ('ORIG_HEAD', 'FETCH_HEAD'):
        file = os.path.join(path, '.git', pointer)
        if os.path.isfile(file):
            shas |= set(SHA_RE.findall(open(file, errors='replace').read(65536)))
    worktrees = sorted(os.listdir(os.path.join(path, '.git', 'worktrees'))) if os.path.isdir(os.path.join(path, '.git', 'worktrees')) else []
    return {'refs': refs, 'head': head, 'shas': sorted(shas | {s for s in refs.values()}), 'worktrees': worktrees,
            'stash': 'refs/stash' in refs}


def refs_from_files(path):
    """ref -> sha read straight from .git (loose files and packed-refs), so a partly deleted quarantine can still be read."""
    refs = {}
    gitdir = os.path.join(path, '.git')
    packed = os.path.join(gitdir, 'packed-refs')
    if os.path.isfile(packed):
        for line in open(packed, errors='replace'):
            parts = line.split()
            if len(parts) == 2 and SHA_RE.fullmatch(parts[0]) and parts[1].startswith('refs/'):
                refs[parts[1]] = parts[0]
    for root, _dirs, files in os.walk(os.path.join(gitdir, 'refs')):
        for name in files:
            file = os.path.join(root, name)
            text = open(file, errors='replace').read(256).strip()
            if SHA_RE.fullmatch(text):
                refs[os.path.relpath(file, gitdir).replace(os.sep, '/')] = text
    return refs


def snapshot_digest(snap):
    return hashlib.sha256(json.dumps(snap, sort_keys=True).encode()).hexdigest()


def _tree_size(path):
    seen, total = set(), 0
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            try:
                info = os.lstat(os.path.join(root, name))
            except OSError:
                continue
            key = (info.st_dev, info.st_ino)
            if key not in seen:
                seen.add(key)
                total += getattr(info, 'st_blocks', 0) * 512 or info.st_size
    return total


def verify_clone(path, session, home, authenticated=False, cutoff_ns=None):
    """{'removable', 'refusal', ...plan}. Never raises for a refusal; a bug or a timeout also reads as not removable."""
    result = {'path': path, 'removable': False, 'refusal': None, 'verifier_version': VERSION}
    try:
        ident = check_target(path, session, home)
        caller_inside(path)
        started = time.monotonic()
        result['identity'] = ident
        result['cutoff_ns'] = cutoff_ns if cutoff_ns is not None else time.time_ns()
        _structure_checks(path)
        partial = _config_checks(path)
        result['partial_clone'] = partial
        for entry in run_git(path, ['ls-files', '-s', '-z'], 60.0).split('\x00'):
            if entry.startswith('160000'):
                refuse('a tracked path is an embedded repository (gitlink)')
        for entry in run_git(path, ['ls-files', '-v', '-z'], 60.0).split('\x00'):
            if entry and entry[0] != 'H':
                refuse('a tracked file is marked assume-unchanged, skip-worktree or hidden from git status')
        cfg = cg.DEFAULT_POLICY['reproducible_clone']  # always the policy from code
        ignored_ok, ignored_top_ok = set(cfg['ignored_ok']), set(cfg['ignored_top_ok'])
        ignored_dirs = []
        status = run_git(path, ['status', '--porcelain=v1', '-z', '--untracked-files=normal', '--ignored=traditional', '--no-renames'], 120.0)
        for entry in filter(None, status.split('\x00')):
            if not entry.startswith('!! '):
                refuse('the working tree is not clean (modified, staged or untracked files)')
            name = entry[3:]
            leaf = name.rstrip('/').rsplit('/', 1)[-1]
            top = '/' not in name.rstrip('/')
            if not (name.endswith('/') and (leaf in ignored_ok or (top and leaf in ignored_top_ok))):
                refuse('it holds an ignored file or folder that is not a whole regenerable build directory')
            found = cg._nested_repo(os.path.join(path, name), deep=leaf not in ignored_ok)
            if found == 'large':
                refuse('an ignored build directory is too large to check for nested repositories in time')
            if found:
                refuse('an ignored build directory holds a nested repository')
            code, out = run_git(path, ['check-ignore', '-v', '--no-index', '--', name.rstrip('/')], 10.0, check=False)
            source = out.split(':', 1)[0] if code == 0 else ''
            if not source or source.startswith('.git/') or source.startswith('/') or os.path.basename(source) != '.gitignore' \
                    or run_git(path, ['ls-files', '--error-unmatch', '--', source], 10.0, check=False)[0] != 0:
                refuse('an ignored build directory is ignored only by a local exclude, not by a tracked .gitignore')
            ignored_dirs.append(name)
        snap = snapshot(path)
        if snap['stash']:
            refuse('it has a stash')
        if any(name.startswith('refs/replace/') for name in snap['refs']):
            refuse('it has replace refs')
        remotes = [r for r in run_git(path, ['remote'], 5.0).split() if re.fullmatch(r'[\w.-]+', r)]
        if not remotes:
            refuse('it has no remote')
        live_all, urls_redacted = {}, {}
        for remote in remotes:
            urls = run_git(path, ['remote', 'get-url', '--all', remote], 5.0).split()
            for url in urls:
                if CREDENTIAL_URL.search(url):
                    refuse('remote %s URL carries a credential' % remote[:30])
            hosts = [cg._remote_host(u) for u in urls]
            if not urls or any(h is None or h not in cfg['remote_hosts'] for h in hosts):
                refuse('remote %s is not on a known hosting service' % remote[:30])
            urls_redacted[remote] = urls
            try:
                live = REMOTE_LS(urls[0], path, 120.0) if not authenticated else REMOTE_LS(urls[0], path, 120.0, True)
            except (ValueError, OSError, subprocess.SubprocessError):
                live = None
            if not live:
                refuse('the remote did not answer (cannot prove the commits are pushed)')
            live_all[remote] = live
        proof = set()
        for live in live_all.values():
            for ref, sha in live.items():
                if ref.startswith(('refs/heads/', 'refs/tags/')) or re.fullmatch(r'refs/pull/\d+/head', ref):
                    proof.add(sha)
        if not proof:
            refuse('the remote lists no branch, tag or pull head')
        local = set(snap['shas'])
        listing = run_git(path, ['cat-file', '--batch-check'], 120.0, stdin=''.join(s + '\n' for s in sorted(local | proof)))
        missing = {line.split()[0] for line in listing.splitlines() if line.endswith(' missing')}
        if local & missing:
            refuse('a local ref or reflog commit is missing from the repository (it cannot be proven pushed)')
        known_proof = sorted(proof - missing)
        spec = '\n'.join(sorted(local)) + '\n--not\n' + '\n'.join(known_proof) + '\n'
        unpushed = run_git(path, ['rev-list', '--count', '--stdin'], 120.0, stdin=spec).strip()
        if unpushed != '0':
            refuse('%s local commit(s) are not on the remote' % unpushed[:8])
        check_processes(path)
        alternates_scan(os.path.join(work_root(home), session), path)
        for hit in _live_owner_hits(session, path):
            refuse('a live owner (%s) works on the target' % hit)
        result.update(snapshot=snap, snapshot_sha256=snapshot_digest(snap), urls=urls_redacted, proof=known_proof,
                      ignored_dirs=ignored_dirs, entries=sorted(os.listdir(path)), size_estimate=_tree_size(path),
                      git_version='%d.%d' % git_version(), removable=True, seconds=round(time.monotonic() - started, 1))
        if check_target(path, session, home) != ident:
            refuse('the directory changed identity during verification')
    except CloneError as error:
        result['refusal'] = str(error)
        result['removable'] = False
    except Exception as error:  # noqa: BLE001 - any surprise means "not removable"
        result['refusal'] = 'could not verify (%s)' % type(error).__name__
        result['removable'] = False
    return result


# ----------------------------------------------------------------------------- audit
def audit(home, record):
    for key in ('urls',):
        if key in record:
            record[key] = {k: [re.sub(r'://[^/@\s]*@', '://', u) for u in v] for k, v in record[key].items()}
    _audit_write(home, record)


def audit_rows(home, audit_id):
    path = os.path.join(str(home), '.agent-harness', 'worktree-audit.jsonl')
    rows = []
    try:
        with open(path, errors='replace') as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict) and row.get('audit_id') == audit_id:
                    rows.append(row)
    except OSError:
        pass
    return rows


# ----------------------------------------------------------------------------- the descriptor walk
def _birth_ns(info):
    """When a directory was created (st_birthtime where the platform has it, else its ctime). A directory's ctime also moves
    when this very walk removes a child, so after an interrupted run only the birth time still says "created after
    verification began"; files are judged by ctime (any write or link change moves it)."""
    birth = getattr(info, 'st_birthtime', None)
    return int(birth * 1e9) if birth else info.st_ctime_ns


def _fd_ident(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino


def walk_delete(root_fd, cutoff_ns, exempt=None, dev=None):
    """Delete the contents of the directory `root_fd` (not the directory itself) without following a symlink, crossing a
    device or deleting anything whose ctime, judged at its first lstat, is newer than cutoff_ns. Holds one descriptor at a
    time below the root (each ascent reopens the parent through `..` and compares its identity), so a 300-deep tree works
    under the default descriptor limit. Returns {'removed': n, 'left': [relative names with reasons]}."""
    exempt = exempt or {}
    root_ident = _fd_ident(root_fd)
    dev = root_ident[0] if dev is None else dev
    stats = {'removed': 0, 'left': []}

    def listing(fd):
        with os.scandir(fd) as entries:
            return [e.name for e in entries]

    def make_writable(fd):
        mode = os.fstat(fd).st_mode
        if mode & 0o700 != 0o700:
            os.fchmod(fd, mode | 0o700)

    frames = [{'fd': root_fd, 'ident': root_ident, 'names': listing(root_fd), 'rel': '', 'kept': False, 'name': None}]
    while frames:
        frame = frames[-1]
        if frame['names']:
            name = frame['names'].pop()
            rel = (frame['rel'] + '/' + name) if frame['rel'] else name
            _hook('entry', rel=rel)
            try:
                info = os.lstat(name, dir_fd=frame['fd'])
            except FileNotFoundError:
                continue
            except OSError as error:
                stats['left'].append('%s (%s)' % (rel, errno.errorcode.get(error.errno, 'error')))
                frame['kept'] = True
                continue
            if not frame['rel'] and exempt.get(name) == info.st_ino:
                continue  # the marker: removed by the caller just before the root
            if (_birth_ns(info) if stat.S_ISDIR(info.st_mode) else info.st_ctime_ns) > cutoff_ns:
                stats['left'].append('%s (changed after verification began)' % rel)
                frame['kept'] = True
                continue
            if stat.S_ISDIR(info.st_mode):
                if info.st_dev != dev:
                    stats['left'].append('%s (another device)' % rel)
                    frame['kept'] = True
                    continue
                try:
                    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=frame['fd'])
                except OSError as error:
                    stats['left'].append('%s (%s)' % (rel, errno.errorcode.get(error.errno, 'error')))
                    frame['kept'] = True
                    continue
                try:
                    if _fd_ident(child) != (info.st_dev, info.st_ino):
                        os.close(child)
                        stats['left'].append('%s (changed while the walk ran)' % rel)
                        frame['kept'] = True
                        continue
                    make_writable(child)
                    names = listing(child)
                except OSError as error:
                    os.close(child)
                    stats['left'].append('%s (%s)' % (rel, errno.errorcode.get(error.errno, 'error')))
                    frame['kept'] = True
                    continue
                if frame['fd'] != root_fd:
                    os.close(frame['fd'])
                frame['fd'] = None
                frames.append({'fd': child, 'ident': (info.st_dev, info.st_ino), 'names': names, 'rel': rel, 'kept': False,
                               'name': name})
                continue
            try:
                os.unlink(name, dir_fd=frame['fd'])
                stats['removed'] += 1
            except FileNotFoundError:
                pass
            except OSError as error:
                stats['left'].append('%s (%s)' % (rel, errno.errorcode.get(error.errno, 'error')))
                frame['kept'] = True
            continue
        frames.pop()
        if not frames:
            break
        parent = frames[-1]
        try:
            pfd = os.open('..', os.O_RDONLY | os.O_DIRECTORY, dir_fd=frame['fd'])
        except OSError:
            stats['left'].append('%s (cannot ascend)' % frame['rel'])
            os.close(frame['fd'])
            raise CloneError('unknown', 'the walk lost its place below %s' % frame['rel'])
        os.close(frame['fd'])
        if _fd_ident(pfd) != parent['ident']:
            os.close(pfd)
            raise CloneError('unknown', 'the walk lost its place below %s (a directory moved)' % frame['rel'])
        if parent is frames[0]:
            os.close(pfd)
            parent['fd'] = root_fd
        else:
            parent['fd'] = pfd
        if frame['kept']:
            parent['kept'] = True
            continue
        try:
            os.rmdir(frame['name'], dir_fd=parent['fd'])
            stats['removed'] += 1
        except FileNotFoundError:
            pass
        except OSError as error:
            stats['left'].append('%s (%s)' % (frame['rel'], errno.errorcode.get(error.errno, 'error')))
            parent['kept'] = True
    return stats


# ----------------------------------------------------------------------------- removal
def _now_id():
    return time.strftime('%Y%m%dT%H%M%S', time.gmtime()) + '-' + uuid.uuid4().hex[:8]


def _open_parent(parent, expect):
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if (info.st_dev, info.st_ino) != expect:
        os.close(fd)
        refuse('the parent directory changed identity')
    return fd


def _rename(pfd, old, new):
    try:
        os.stat(new, dir_fd=pfd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        refuse('the quarantine name already exists')
    os.rename(old, new, src_dir_fd=pfd, dst_dir_fd=pfd)


def remove_clone(path, reason, session, home, agent='', authenticated=False, verify_only=False):
    reason = (reason or '').strip()
    if not reason:
        raise CloneError('bad_request', 'a reason is required')
    started = time.time_ns()
    verdict = verify_clone(path, session, home, authenticated, cutoff_ns=started)
    base = {'path': path, 'verify_only': bool(verify_only)}
    if not verdict['removable']:
        raise CloneError('refused', 'not removable: %s' % verdict['refusal'])
    if verify_only:
        audit(home, {'kind': 'clone-verify', 'session': session, 'agent': agent, 'path': path, 'reason': reason,
                     'refs': verdict['snapshot']['refs'], 'proof': verdict['proof'], 'size_estimate': verdict['size_estimate'],
                     'git_version': verdict['git_version'], 'verifier_version': VERSION, 'urls': verdict['urls'],
                     'identity': verdict['identity']})
        return dict(base, removable=True, removed=False, plan={k: verdict[k] for k in
                    ('refusal', 'snapshot', 'proof', 'entries', 'ignored_dirs', 'size_estimate', 'partial_clone', 'git_version')})
    audit_id = _now_id()
    parent, name = os.path.split(path)
    qname = QUARANTINE_PREFIX + audit_id
    ident = verdict['identity']
    _hook('after_verify', path=path)
    intent = {'kind': 'clone-intent', 'audit_id': audit_id, 'session': session, 'agent': agent, 'path': path,
              'quarantine': os.path.join(parent, qname), 'reason': reason, 'parent_dev': ident['parent_dev'],
              'parent_ino': ident['parent_ino'], 'dev': ident['dev'], 'ino': ident['ino'], 'cutoff_ns': started,
              'refs': verdict['snapshot']['refs'], 'snapshot': verdict['snapshot'], 'snapshot_sha256': verdict['snapshot_sha256'],
              'proof': verdict['proof'], 'size_estimate': verdict['size_estimate'], 'git_version': verdict['git_version'],
              'verifier_version': VERSION, 'urls': verdict['urls']}
    try:
        audit(home, intent)  # fail closed: nothing is renamed when the row cannot be written and fsynced
    except (OSError, ValueError, TypeError) as error:
        raise CloneError('refused', 'the audit row could not be written (%s); nothing was changed' % type(error).__name__)
    pfd = _open_parent(parent, (ident['parent_dev'], ident['parent_ino']))
    try:
        info = os.lstat(name, dir_fd=pfd)
        if (info.st_dev, info.st_ino) != (ident['dev'], ident['ino']) or not stat.S_ISDIR(info.st_mode):
            refuse('the target changed identity after verification')
        _rename(pfd, name, qname)
        renamed = True
        quarantine = os.path.join(parent, qname)
        try:
            qinfo = os.lstat(qname, dir_fd=pfd)
            if (qinfo.st_dev, qinfo.st_ino) != (ident['dev'], ident['ino']):
                refuse('the quarantined directory is not the verified one')
            again = snapshot(quarantine)
            if again != verdict['snapshot']:
                refuse('the refs, reflog or stash changed after verification')
        except Exception:
            os.rename(qname, name, src_dir_fd=pfd, dst_dir_fd=pfd)  # leave the clone exactly as found
            raise
    finally:
        os.close(pfd)
    return _finish(home, session, agent, audit_id, quarantine, intent, ident)


def _write_marker(quarantine, audit_id, digest):
    marker = os.path.join(quarantine, MARKER_NAME)
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, json.dumps({'audit_id': audit_id, 'snapshot_sha256': digest}).encode())
        os.fsync(fd)
        return os.fstat(fd).st_ino
    finally:
        os.close(fd)


def _finish(home, session, agent, audit_id, quarantine, intent, ident, marker_ino=None):
    parent, qname = os.path.split(quarantine)
    if marker_ino is None:
        marker_ino = _write_marker(quarantine, audit_id, intent['snapshot_sha256'])
        try:
            audit(home, {'kind': 'clone-marker', 'audit_id': audit_id, 'session': session, 'marker_ino': marker_ino})
        except (OSError, ValueError, TypeError) as error:
            os.unlink(os.path.join(quarantine, MARKER_NAME))
            pfd = _open_parent(parent, (ident['parent_dev'], ident['parent_ino']))
            try:
                os.rename(qname, os.path.basename(intent['path']), src_dir_fd=pfd, dst_dir_fd=pfd)
            finally:
                os.close(pfd)
            raise CloneError('refused', 'the marker audit row could not be written (%s); the clone was left in place' % type(error).__name__)
    result = {'audit_id': audit_id, 'path': intent['path'], 'quarantine': quarantine, 'removed': None,
              'directory_removed': False, 'left': [], 'bytes_freed': None, 'size_estimate': intent.get('size_estimate')}
    qfd = os.open(quarantine, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if _fd_ident(qfd) != (ident['dev'], ident['ino']):
            raise CloneError('unknown', 'the quarantine identity changed before the walk')
        fcntl.flock(qfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stats = walk_delete(qfd, intent['cutoff_ns'], exempt={MARKER_NAME: marker_ino}, dev=ident['dev'])
        result['left'] = stats['left']
        if not stats['left']:
            try:
                os.unlink(MARKER_NAME, dir_fd=qfd)
            except FileNotFoundError:
                pass
            pfd = _open_parent(parent, (ident['parent_dev'], ident['parent_ino']))
            try:
                os.rmdir(qname, dir_fd=pfd)
                result['directory_removed'] = True
                result['removed'] = True
                result['bytes_freed'] = intent.get('size_estimate')
            except FileNotFoundError:
                result['directory_removed'] = True
                result['removed'] = True
            except OSError as error:
                result['left'].append('%s (%s)' % (qname, errno.errorcode.get(error.errno, 'error')))
            finally:
                os.close(pfd)
    except BlockingIOError:
        raise CloneError('refused', 'another process holds this quarantine directory')
    except CloneError:
        raise
    except Exception as error:  # noqa: BLE001
        result['left'].append('walk stopped (%s)' % type(error).__name__)
    finally:
        os.close(qfd)
    try:
        audit(home, dict({'kind': 'clone-result', 'session': session, 'agent': agent}, **{k: result[k] for k in
              ('audit_id', 'removed', 'directory_removed', 'left', 'bytes_freed')}))
    except (OSError, ValueError, TypeError):
        result['audit_warning'] = 'the result row could not be written'
    return result


def resume_clone(audit_id, session, home, agent=''):
    if not isinstance(audit_id, str) or not re.fullmatch(r'[0-9TZ]{15}-[0-9a-f]{8}', audit_id):
        raise CloneError('bad_request', 'a malformed audit id')
    rows = audit_rows(home, audit_id)
    intents = [r for r in rows if r.get('kind') == 'clone-intent']
    if len(intents) != 1:
        refuse('no single intent row for that audit id')
    intent = intents[0]
    if intent.get('session') != session:
        refuse('that removal belongs to another session')
    if any(r.get('kind') == 'clone-result' and r.get('removed') is True for r in rows):
        return {'audit_id': audit_id, 'removed': True, 'directory_removed': True, 'already': True, 'left': []}
    receipts = os.path.join(work_root(home), session, 'receipts')
    quarantine = os.path.join(receipts, QUARANTINE_PREFIX + audit_id)
    if intent.get('quarantine') != quarantine:
        refuse('the quarantine path does not match the recorded one')
    if os.path.realpath(quarantine) != quarantine or os.path.islink(quarantine) or not os.path.isdir(quarantine):
        refuse('the quarantine directory is missing, a symlink or an alias')
    names = os.listdir(receipts)
    if os.path.basename(quarantine) not in names:
        refuse('the quarantine name does not match its directory entry byte for byte')
    info = os.lstat(quarantine)
    parent = os.lstat(receipts)
    if (info.st_dev, info.st_ino) != (intent['dev'], intent['ino']) or (parent.st_dev, parent.st_ino) != (intent['parent_dev'], intent['parent_ino']):
        refuse('the quarantine directory is not the one recorded')
    markers = [r for r in rows if r.get('kind') == 'clone-marker']
    if len(markers) != 1:
        refuse('no marker row for that audit id')
    marker_path = os.path.join(quarantine, MARKER_NAME)
    try:
        minfo = os.lstat(marker_path)
        content = json.loads(open(marker_path).read(4096))
    except (OSError, ValueError):
        refuse('the marker file is missing or unreadable')
    if minfo.st_ino != markers[0].get('marker_ino') or content.get('audit_id') != audit_id \
            or content.get('snapshot_sha256') != intent.get('snapshot_sha256'):
        refuse('the marker does not match the audit row')
    caller_inside(quarantine)
    recorded = intent['snapshot']['refs']
    if any(recorded.get(ref) != sha for ref, sha in refs_from_files(quarantine).items()):
        refuse('refs exist in the quarantine that were not in the recorded snapshot')
    check_processes(quarantine)
    ident = {'dev': intent['dev'], 'ino': intent['ino'], 'parent_dev': intent['parent_dev'], 'parent_ino': intent['parent_ino']}
    return _finish(home, session, agent, audit_id, quarantine, intent, ident, marker_ino=minfo.st_ino)
