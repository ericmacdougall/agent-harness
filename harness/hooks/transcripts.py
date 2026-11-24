#!/usr/bin/env python3
"""Private agent-transcripts archive (GoodQA #16650, phase 1).

Copies every Claude Code / Codex transcript and harness WAL on this host, redacts each record through the
two-pass gate in transcript_redact.py, splits it on record boundaries into chunks of at most 48 MiB raw,
compresses them with zstd and pushes them to private per-host monthly shard repos. A catalog repo maps
sessions, projects, hosts, tickets and PRs to chunks (manifests, per-host index JSONL, shard ledger).

Recovery truth:
  * Recovery from git is byte-identical to the REDACTED archive, never to the source.
  * Exact-source recovery comes from the local source file or the Dropbox log backup.

Sources are only ever opened read-only ('rb' via O_RDONLY|O_NOFOLLOW); symlinks and non-regular files are
skipped. The tool never force-pushes and never rewrites a published ref.

Stdlib only, Python 3.9 compatible. Docs: docs/transcripts-archive.md. Index contract:
docs/transcripts-index.schema.json (schema 1).
"""
from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import re
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

SCHEMA = 1
CHUNKER_VERSION = 1
CHECKPOINTS = ('start', 'recovery', 'takeover', 'pr', 'deploy', 'manual')
FORCE_SEAL = frozenset(('pr', 'deploy', 'takeover'))
MiB = 1 << 20
OWNER = 'ericmacdougall'
CATALOG = 'agent-transcripts'
DEFAULT_SOURCES = {
    'claude-projects': '~/.claude/projects',
    'claude-wals': '~/.claude/wals',
    'codex-sessions': '~/.codex/sessions',
    'codex-archived': '~/.codex/archived_sessions',
    'codex-wals': '~/.agent-harness/codex-wals',
}
TOOL_OF = {'claude-projects': 'claude', 'claude-wals': 'claude', 'codex-sessions': 'codex',
           'codex-archived': 'codex', 'codex-wals': 'codex'}
RECOVERY_TRUTH = ('Recovery from git is byte-identical to the REDACTED archive, never to the source. '
                  'Exact-source recovery comes from the local source file or the Dropbox log backup.')
HERE = os.path.dirname(os.path.abspath(__file__))
README_SRC = os.path.join(HERE, 'transcripts_catalog_README.md')  # shipped beside the hooks by install.py

_UUID = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
_SAFE = re.compile(r'[^A-Za-z0-9._-]')
_TS = re.compile(r'^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d{1,12})?(Z|[+-]\d{2}:?\d{2})?$')
_TICKET = re.compile(rb'(?i)\bgoodqa\s{0,3}#\s{0,3}(\d{1,7})\b')
_PR = re.compile(rb'https://github\.com/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}/pull/\d{1,7}')
_COMMIT = re.compile(rb'(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])')
MENTION_CAP = 200


class Refused(Exception):
    """A visible refusal: message is ours (never holds a source value)."""


# ----------------------------------------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------------------------------------

def _env_int(name, default, allowed):
    raw = os.environ.get(name)
    if raw and allowed:
        return int(raw)
    return default


class Cfg:
    def __init__(self):
        env = os.environ
        self.home = os.path.abspath(os.path.expanduser(env.get('TRANSCRIPTS_HOME') or '~/.agent-harness/transcripts'))
        raw = env.get('TRANSCRIPTS_SOURCES')
        srcs = json.loads(raw) if raw else DEFAULT_SOURCES
        self.sources = {str(k): os.path.abspath(os.path.expanduser(v)) for k, v in srcs.items()}
        for label in self.sources:
            if _SAFE.search(label) or label in ('.', '..'):
                raise Refused('invalid source label')
        base = env.get('TRANSCRIPTS_REMOTE_BASE')
        self.local = bool(base)
        if self.local and env.get('TRANSCRIPTS_ALLOW_LOCAL_REMOTE') != '1':
            raise Refused('TRANSCRIPTS_REMOTE_BASE needs TRANSCRIPTS_ALLOW_LOCAL_REMOTE=1')
        self.remote_base = os.path.abspath(base) if base else None
        host = env.get('TRANSCRIPTS_HOST')
        pinned = None
        if not host:
            try:
                with open(os.path.join(self.home, 'host'), 'r') as f:
                    pinned = f.read().strip() or None
            except OSError:
                pinned = None
            host = pinned or socket.gethostname().split('.')[0].lower()
        self.host = _SAFE.sub('_', host)[:40] or 'host'
        self.host_pinned = bool(pinned) or bool(env.get('TRANSCRIPTS_HOST'))
        t = self.local  # size overrides are honoured only against a local test remote
        self.chunk_max = _env_int('TRANSCRIPTS_CHUNK_MAX_BYTES', 48 * MiB, t)
        self.shard_cap = _env_int('TRANSCRIPTS_SHARD_CAP_BYTES', 1500 * 1000 * 1000, t)
        self.seal_min = _env_int('TRANSCRIPTS_SEAL_MIN_BYTES', 1 * MiB, t)
        self.hold_backoff = _env_int('TRANSCRIPTS_HOLD_BACKOFF_SECONDS', 900, t)  # first retry of a held file
        self.idle_s = 1800
        self.file_delta_cap = _env_int('TRANSCRIPTS_FILE_DELTA_CAP', 256 * MiB, t)
        self.push_max = 400 * 1000 * 1000
        self.file_max_z = 50 * 1000 * 1000
        self.outbox_cap = 1500 * 1000 * 1000
        self.push_timeout = _env_int('TRANSCRIPTS_PUSH_TIMEOUT', 300, t)
        self.min_free_gb = float(env.get('TRANSCRIPTS_MIN_FREE_GB') or 12)
        self.crash_at = env.get('TRANSCRIPTS_CRASH_AT') if t else None
        self.ignore_load = t and env.get('TRANSCRIPTS_IGNORE_LOAD') == '1'
        self.style = (env.get('TRANSCRIPTS_GIT_URL_STYLE') or 'auto').lower()
        if self.style not in ('auto', 'https', 'ssh'):
            raise Refused('TRANSCRIPTS_GIT_URL_STYLE must be auto, https or ssh')
        self.test_no_gh = t and env.get('TRANSCRIPTS_TEST_NO_GH') == '1'
        self._gh_ok = None

    @property
    def has_gh(self):
        """An authenticated gh: repo creation and the full privacy checks. Local test remotes stub it."""
        if self.local:
            return not self.test_no_gh
        if self._gh_ok is None:
            try:
                r = subprocess.run(['gh', 'auth', 'status'], capture_output=True, timeout=bounded(15))
                self._gh_ok = r.returncode == 0
            except (OSError, subprocess.SubprocessError):
                self._gh_ok = False
        return self._gh_ok

    @property
    def url_style(self):
        if self.local:
            return 'local'
        if self.style != 'auto':
            return self.style
        return 'https' if self.has_gh else 'ssh'

    def p(self, *parts):
        return os.path.join(self.home, *parts)

    def url(self, repo):
        if self.local:
            return os.path.join(self.remote_base, repo + '.git')
        if self.url_style == 'ssh':
            return 'git@github.com:%s/%s.git' % (OWNER, repo)
        return 'https://github.com/%s/%s.git' % (OWNER, repo)


def ensure_home(cfg):
    for sub in ('', 'receipts', 'requests', 'logs', 'outbox', 'tmp', 'meta'):
        d = cfg.p(sub) if sub else cfg.home
        os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(cfg.home, 0o700)
    if not cfg.host_pinned and not os.path.exists(cfg.p('host')):
        atomic_write(cfg.p('host'), (cfg.host + '\n').encode())  # macOS hostnames drift; the label must not
        cfg.host_pinned = True


def now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_iso(s):
    try:
        return datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def sha12(text):
    return hashlib.sha256(text.encode('utf-8', 'surrogateescape')).hexdigest()[:12]


def atomic_write(path, data, mode=0o600):
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.tmp-')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        dfd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def jdump(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def read_json(path, default=None):
    try:
        with open(path, 'rb') as f:
            return json.loads(f.read().decode('utf-8'))
    except (OSError, ValueError):
        return default


def alert(cfg, kind, detail):
    """Alerts carry our own words, kinds, counts and path sha12 only."""
    row = {'ts': now_iso(), 'host': cfg.host, 'kind': kind, 'detail': detail}
    try:
        with open(cfg.p('alerts.jsonl'), 'ab') as f:
            f.write(jdump(row) + b'\n')
    except OSError:
        pass
    sys.stderr.write('ALERT transcripts %s: %s\n' % (kind, detail))


def crash_point(cfg, name):
    if cfg.crash_at == name:
        sys.stderr.flush()
        os._exit(97)


def sanitize_err(text):
    text = re.sub(r'https?://[^\s/@]*@', 'https://', text or '')
    return ' '.join(text.split())[:240]


# ----------------------------------------------------------------------------------------------------------
# Lock and request files
# ----------------------------------------------------------------------------------------------------------

class Lock:
    def __init__(self, cfg):
        self.path = cfg.p('lock')
        self.fd = None

    def try_acquire(self):
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            os.close(fd)
            if e.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                return False
            raise
        self.fd = fd
        return True

    def release(self):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None


def drop_request(cfg, checkpoint):
    if checkpoint not in CHECKPOINTS:
        raise Refused('invalid checkpoint')
    name = '%s-%d-%d' % (checkpoint, time.time_ns(), os.getpid())
    fd = os.open(os.path.join(cfg.p('requests'), name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    return name


def take_requests(cfg, reap_only=False):
    served = set()
    d = cfg.p('requests')
    try:
        names = os.listdir(d)
    except OSError:
        return served
    now = time.time()
    for name in names:
        path = os.path.join(d, name)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        parts = name.split('-')
        valid = stat.S_ISREG(st.st_mode) and len(parts) == 3 and parts[0] in CHECKPOINTS
        old = now - st.st_mtime > 86400
        if valid and not old and reap_only:
            continue
        if valid and not old:
            served.add(parts[0])
        try:
            os.unlink(path)
        except OSError:
            pass
    return served


# ----------------------------------------------------------------------------------------------------------
# Git and remote checks
# ----------------------------------------------------------------------------------------------------------

def git_env():
    e = dict(os.environ)
    e.update({'GIT_TERMINAL_PROMPT': '0', 'GIT_AUTHOR_NAME': 'agent-transcripts',
              'GIT_AUTHOR_EMAIL': 'agent-transcripts@noreply.invalid', 'GIT_COMMITTER_NAME': 'agent-transcripts',
              'GIT_COMMITTER_EMAIL': 'agent-transcripts@noreply.invalid'})
    e.pop('GIT_INDEX_FILE', None)
    e.pop('GIT_DIR', None)
    return e


class GitError(Exception):
    pass


_DEADLINE = [None]  # monotonic hard stop of the current run (budget + 10 s); every child timeout honours it


def bounded(timeout):
    """A child timeout that never runs past the run's hard stop (AC-11, NEG-10)."""
    if _DEADLINE[0] is None:
        return timeout
    left = _DEADLINE[0] - time.monotonic()
    if left <= 0.5:
        raise subprocess.TimeoutExpired('budget', 0)
    return min(timeout, left)


def run_child(args, **kw):
    kw['timeout'] = bounded(kw.get('timeout', 120))
    return subprocess.run(args, **kw)


def git(cfg, args, cwd=None, inp=None, timeout=120, env_extra=None, check=True):
    base = ['git']
    if not cfg.local and cfg.url_style == 'https':
        base += ['-c', 'credential.helper=', '-c', 'credential.helper=!gh auth git-credential']
    env = git_env()
    if env_extra:
        env.update(env_extra)
    r = run_child(base + list(args), cwd=cwd, input=inp, capture_output=True, timeout=timeout, env=env)
    if check and r.returncode != 0:
        raise GitError('git %s failed: %s' % (args[0], sanitize_err(r.stderr.decode('utf-8', 'replace'))))
    return r


def blob_of(v):
    if isinstance(v, bytes):
        return git_blob_sha(v)
    h = hashlib.sha1()
    h.update(b'blob %d\0' % os.path.getsize(v))
    with open(v, 'rb') as f:
        for b in iter(lambda: f.read(MiB), b''):
            h.update(b)
    return h.hexdigest()


def git_blob_sha(data):
    h = hashlib.sha1()
    h.update(b'blob %d\0' % len(data))
    h.update(data)
    return h.hexdigest()


ATTEST_MAX_AGE = 86400     # a gh-less host trusts an attestation for 24 h
ATTEST_REFRESH = 6 * 3600  # a gh host refreshes attestations older than 6 h on its push runs


class Remote:
    """Repo existence, creation and the privacy checks.

    A host with an authenticated gh checks each repo itself (visibility, fork, owner, collaborators) and writes
    `repo-checks/<repo>.json` attestations into the catalog. A gh-less host (SSH push only) checks visibility
    with an unauthenticated API read (200 = public = refuse; 404 plus a working SSH ls-remote = private) and
    requires a fresh attestation for the rest. Local test remotes stub both paths."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.checked = {}  # per-run cache only
        self._snapshot = None

    def _stub(self):
        return read_json(os.path.join(self.cfg.remote_base, 'repo-checks.json'), {}) or {}

    def ls_remote_ok(self, repo):
        try:
            r = git(self.cfg, ['ls-remote', self.cfg.url(repo)], timeout=60, check=False)
        except subprocess.TimeoutExpired:
            raise Refused('repo lookup timed out for %s' % repo)
        return r

    def exists(self, repo):
        if self.cfg.local:
            return os.path.isdir(self.cfg.url(repo))
        if self.cfg.has_gh:
            r = run_child(['gh', 'api', 'repos/%s/%s' % (OWNER, repo), '--jq', '.name'],
                          capture_output=True, timeout=60)
            if r.returncode == 0:
                return True
            if b'Not Found' in r.stderr or b'404' in r.stderr:
                return False
            raise Refused('repo lookup failed for %s' % repo)
        r = self.ls_remote_ok(repo)
        if r.returncode == 0:
            return True
        err = r.stderr.decode('utf-8', 'replace').lower()
        if 'not found' in err or 'does not exist' in err:
            return False
        raise Refused('repo lookup failed for %s (ssh)' % repo)

    def ensure(self, repo):
        if self.exists(repo):
            return
        if not self.cfg.has_gh:
            what = 'catalog-repo-missing' if repo == CATALOG else 'shard-repo-missing'
            raise Refused('%s: %s; create with gh on an authenticated host (transcripts.py ensure-repos)'
                          % (what, repo))
        if self.cfg.local:
            url = self.cfg.url(repo)
            os.makedirs(url, exist_ok=True)
            git(self.cfg, ['init', '-q', '--bare', url])
            git(self.cfg, ['config', 'uploadpack.allowFilter', 'true'], cwd=url)
            git(self.cfg, ['config', 'uploadpack.allowAnySHA1InWant', 'true'], cwd=url)
            return
        r = run_child(['gh', 'repo', 'create', '%s/%s' % (OWNER, repo), '--private',
                       '--description', 'Private redacted agent transcripts archive (agent-harness)'],
                      capture_output=True, timeout=120)
        if r.returncode != 0:
            raise Refused('gh repo create failed for %s' % repo)

    def _facts(self, repo):
        if self.cfg.local:
            stub = self._stub()
            f = {'visibility': 'PRIVATE', 'fork': False, 'owner': OWNER, 'collaborators': [OWNER]}
            f.update(stub.get('*', {}))
            f.update(stub.get(repo, {}))
            if f.get('error'):
                raise Refused('repo check error for %s' % repo)
            return f
        r = run_child(['gh', 'api', 'repos/%s/%s' % (OWNER, repo)], capture_output=True, timeout=60)
        if r.returncode != 0:
            raise Refused('visibility unknown for %s (gh api failed)' % repo)
        meta = json.loads(r.stdout.decode('utf-8'))
        r2 = run_child(['gh', 'api', '--paginate', 'repos/%s/%s/collaborators' % (OWNER, repo), '--jq',
                        '.[].login'], capture_output=True, timeout=60)
        if r2.returncode != 0:
            raise Refused('collaborators unknown for %s (gh api failed)' % repo)
        return {'visibility': str(meta.get('visibility', '')).upper(), 'fork': bool(meta.get('fork')),
                'owner': (meta.get('owner') or {}).get('login'),
                'collaborators': [x for x in r2.stdout.decode('utf-8').split() if x]}

    def _unauth_status(self, repo):
        """HTTP status of an unauthenticated GET of the repo; None on any error."""
        if self.cfg.local:
            stub = self._stub()
            st = (stub.get(repo) or {}).get('unauth_status', (stub.get('*') or {}).get('unauth_status', 404))
            return int(st) if st is not None else None
        import urllib.error
        import urllib.request
        req = urllib.request.Request('https://api.github.com/repos/%s/%s' % (OWNER, repo),
                                     headers={'User-Agent': 'agent-transcripts-archiver',
                                              'Accept': 'application/vnd.github+json'})
        try:
            with urllib.request.urlopen(req, timeout=bounded(10)) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:  # noqa: BLE001 - unknown means refuse
            return None

    def snapshot(self):
        """Catalog incident files, attestations and ledgers, fetched once per run."""
        if self._snapshot is None:
            self._snapshot = catalog_snapshot(self.cfg)
        return self._snapshot

    def attestation(self, repo):
        raw = self.snapshot().get('repo-checks/%s.json' % repo)
        try:
            return json.loads(raw) if raw else None
        except ValueError:
            return None

    @staticmethod
    def attestation_ok(rec):
        if not rec:
            return False
        t = parse_iso(rec.get('checked_at'))
        return (t is not None and time.time() - t <= ATTEST_MAX_AGE and rec.get('private') is True
                and rec.get('fork') is False and rec.get('owner') == OWNER and rec.get('collaborators_count') == 0)

    def attest_record(self, repo):
        f = self._facts(repo)
        return {'schema': SCHEMA, 'repo': repo, 'checked_at': now_iso(), 'checked_by': self.cfg.host,
                'private': str(f.get('visibility')).upper() == 'PRIVATE', 'fork': bool(f.get('fork')),
                'owner': f.get('owner'),
                'collaborators_count': len(set(f.get('collaborators') or []) - {OWNER})}

    def _check_gh(self, repo):
        f = self._facts(repo)
        problems = []
        if str(f.get('visibility')).upper() != 'PRIVATE':
            problems.append('visibility=%s' % f.get('visibility'))
        if f.get('fork'):
            problems.append('fork')
        if f.get('owner') != OWNER:
            problems.append('owner')
        if set(f.get('collaborators') or []) - {OWNER}:
            problems.append('collaborators')
        if problems:
            raise Refused('repo check failed for %s: %s' % (repo, ','.join(problems)))

    def _check_ghless(self, repo):
        status = self._unauth_status(repo)
        if status == 200:
            raise Refused('repo check failed for %s: visibility=PUBLIC (unauthenticated read succeeded)' % repo)
        if status != 404:
            raise Refused('repo check failed for %s: visibility unknown (unauthenticated status %s)' % (repo, status))
        if self.ls_remote_ok(repo).returncode != 0:
            raise Refused('repo check failed for %s: ssh ls-remote failed, visibility unproven' % repo)
        if not self.attestation_ok(self.attestation(repo)):
            raise Refused('repo-attestation-stale: %s needs a fresh attestation (<24 h) from a gh host' % repo)

    def check(self, repo):
        if repo in self.checked:
            if self.checked[repo] is not True:
                raise Refused(self.checked[repo])
            return
        try:
            if self.cfg.has_gh:
                self._check_gh(repo)
            else:
                self._check_ghless(repo)
        except Refused as e:
            self.checked[repo] = str(e)
            raise
        except Exception:  # noqa: BLE001 - unknown is a refusal (NEG-8)
            self.checked[repo] = 'repo check failed for %s: unknown' % repo
            raise Refused(self.checked[repo])
        self.checked[repo] = True

    def attestation_files(self, repos):
        """gh host only: fresh repo-checks/<repo>.json for repos whose attestation is missing or over 6 h old."""
        out = {}
        if not self.cfg.has_gh:
            return out
        for repo in sorted(set(repos)):
            rec = self.attestation(repo)
            t = parse_iso(rec.get('checked_at')) if rec else None
            if t is not None and time.time() - t < ATTEST_REFRESH:
                continue
            try:
                if not self.exists(repo):
                    continue
                out['repo-checks/%s.json' % repo] = jdump(self.attest_record(repo)) + b'\n'
            except Refused:
                continue
        return out


def catalog_snapshot(cfg):
    tr = TmpRepo(cfg, CATALOG)
    try:
        if not tr.fetch_tip():
            return {}
        return {p: tr.blob(oid) for p, oid in sorted(tr.entries.items())
                if p.startswith(('incident/', 'repo-checks/', 'shards/'))}
    finally:
        tr.close()


def ledger_repos(snapshot):
    repos = []
    for p, b in snapshot.items():
        if p.startswith('shards/'):
            try:
                repos += [x['repo'] for x in json.loads(b).get('shards', [])]
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
    return repos


class TmpRepo:
    """A temporary bare repo with a promisor remote: blobless shallow fetches, lazy blob reads."""

    def __init__(self, cfg, repo):
        self.cfg = cfg
        self.repo = repo
        self.dir = tempfile.mkdtemp(prefix='%s-' % repo[:60], dir=cfg.p('tmp'))
        git(cfg, ['init', '-q', '--bare', self.dir])
        git(cfg, ['remote', 'add', 'origin', cfg.url(repo)], cwd=self.dir)
        git(cfg, ['config', 'remote.origin.promisor', 'true'], cwd=self.dir)
        git(cfg, ['config', 'remote.origin.partialclonefilter', 'blob:none'], cwd=self.dir)
        self.index = os.path.join(self.dir, 'tmp-index')
        self.tip = None
        self.entries = {}

    def ls_remote(self, timeout=60):
        r = git(self.cfg, ['ls-remote', 'origin', 'refs/heads/main'], cwd=self.dir, timeout=timeout)
        out = r.stdout.decode().split()
        return out[0] if out else None

    def fetch_tip(self, timeout=300):
        self.tip = self.ls_remote()
        self.entries = {}
        if self.tip:
            git(self.cfg, ['fetch', '-q', '--depth=1', '--filter=blob:none', 'origin', 'refs/heads/main'],
                cwd=self.dir, timeout=timeout)
            self.entries = self.ls_tree(self.tip)
        return self.tip

    def ls_tree(self, rev):
        r = git(self.cfg, ['ls-tree', '-r', '-z', rev], cwd=self.dir)
        entries = {}
        for item in r.stdout.split(b'\0'):
            if not item:
                continue
            head, path = item.split(b'\t', 1)
            entries[path.decode('utf-8', 'surrogateescape')] = head.split()[2].decode()
        return entries

    def blob(self, oid, timeout=300):
        return git(self.cfg, ['cat-file', 'blob', oid], cwd=self.dir, timeout=timeout).stdout

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def publish_tree(cfg, repo, files, message, journal=None, deadline=None, overwrite=False):
    """Add files {path: bytes} to repo main. Returns (commit or None if nothing to do, collisions [paths]).

    Chunk paths are never overwritten: an existing path with a different blob is a collision (NEG-17).
    Catalog files (overwrite=True) are replaced. Never --force; a non-fast-forward refetches (5 tries).

    The egress gate runs first, over the repo name, the ref, the message, every path and every blob; any hit
    refuses the whole commit before a tree is built (C11). This is the only function that runs commit-tree or
    push (a guard test lists every plumbing call site)."""
    failures = egress_check(cfg, repo, 'refs/heads/main', files, message)
    if failures:
        alert(cfg, 'egress-refused', '%d item(s) refused at the egress gate for %s' % (len(failures), sha12(repo)))
        raise egress_refusal(failures)
    collisions = []
    for attempt in range(5):
        tr = TmpRepo(cfg, repo)
        try:
            tip = tr.fetch_tip()
            write = {}
            for path, data in files.items():
                blob = blob_of(data)
                have = tr.entries.get(path)
                if have == blob:
                    continue
                if have is not None and not overwrite:
                    if path not in collisions:
                        collisions.append(path)
                    continue
                write[path] = (blob, data)
            if not overwrite:
                # a chunk and its sidecar are one unit: if either collides, neither is written
                for c in list(collisions):
                    base = c[:-len('.meta.json')] if c.endswith('.meta.json') else c
                    write.pop(base, None)
                    write.pop(base + '.meta.json', None)
            if not write:
                return (tip if files else None), collisions, False
            env = {'GIT_INDEX_FILE': tr.index}
            if tip:
                git(cfg, ['read-tree', tip], cwd=tr.dir, env_extra=env)
            info = []
            for path, (blob, data) in sorted(write.items()):
                if isinstance(data, bytes):
                    got = git(cfg, ['hash-object', '-w', '--stdin'], cwd=tr.dir, inp=data).stdout.decode().strip()
                else:
                    got = git(cfg, ['hash-object', '-w', '--', data], cwd=tr.dir).stdout.decode().strip()
                if got != blob:
                    raise GitError('hash mismatch')
                info.append('100644 %s\t%s' % (blob, path))
            git(cfg, ['update-index', '--add', '--index-info'], cwd=tr.dir, env_extra=env,
                inp=('\n'.join(info) + '\n').encode('utf-8', 'surrogateescape'))
            tree = git(cfg, ['write-tree', '--missing-ok'], cwd=tr.dir, env_extra=env).stdout.decode().strip()
            if tip:
                tip_tree = git(cfg, ['rev-parse', tip + '^{tree}'], cwd=tr.dir).stdout.decode().strip()
                if tip_tree == tree:
                    return tip, collisions, False
            args = ['commit-tree', '--no-gpg-sign', tree, '-m', message]
            if tip:
                args[3:3] = ['-p', tip]
            commit = git(cfg, args, cwd=tr.dir).stdout.decode().strip()
            if journal is not None:
                journal.pending(repo, [(p, b) for p, (b, _) in write.items() if p.endswith('.zst')])
            crash_point(cfg, 'before_push')
            timeout = cfg.push_timeout
            landed = False
            try:
                r = git(cfg, ['push', '-q', 'origin', '%s:refs/heads/main' % commit], cwd=tr.dir, timeout=timeout,
                        check=False)
                if cfg.crash_at == 'push_timeout_landed' and r.returncode == 0 and not getattr(cfg, '_tl_done', 0):
                    cfg._tl_done = 1
                    raise subprocess.TimeoutExpired('git push', timeout)
                if r.returncode == 0:
                    landed = True
                else:
                    err = r.stderr.decode('utf-8', 'replace')
                    if 'non-fast-forward' in err or 'fetch first' in err or 'rejected' in err:
                        continue
                    raise GitError('git push failed: %s' % sanitize_err(err))
            except subprocess.TimeoutExpired:
                # decide whether the push landed before retrying
                new_tip = tr.ls_remote()
                if new_tip == commit:
                    landed = True
                elif new_tip:
                    git(cfg, ['fetch', '-q', '--depth=1', '--filter=blob:none', 'origin', 'refs/heads/main'],
                        cwd=tr.dir, timeout=300)
                    ents = tr.ls_tree(new_tip)
                    if all(ents.get(p) == b for p, (b, _) in write.items()):
                        commit = new_tip
                        landed = True
                if not landed:
                    continue
            crash_point(cfg, 'after_push')
            if landed:
                return commit, collisions, True
        finally:
            tr.close()
    raise GitError('push to %s did not land after 5 tries' % repo)


# ----------------------------------------------------------------------------------------------------------
# Journal
# ----------------------------------------------------------------------------------------------------------

class Journal:
    def __init__(self, cfg):
        self.path = cfg.p('journal.jsonl')

    def _append(self, rows):
        with open(self.path, 'ab') as f:
            for row in rows:
                f.write(jdump(row) + b'\n')
            f.flush()
            os.fsync(f.fileno())

    def pending(self, repo, items):
        self._append([{'ts': now_iso(), 'state': 'pending', 'repo': repo, 'path': p, 'blob': b} for p, b in items])

    def pushed(self, repo, items, commit):
        self._append([{'ts': now_iso(), 'state': 'pushed', 'repo': repo, 'path': p, 'blob': b, 'commit': commit}
                      for p, b in items])

    def unresolved(self):
        rows = {}
        try:
            with open(self.path, 'rb') as f:
                for line in f:
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    k = (row['repo'], row['path'], row['blob'])
                    if row['state'] == 'pending':
                        rows[k] = row
                    else:
                        rows.pop(k, None)
        except OSError:
            pass
        return list(rows.values())

    def compact(self, keep):
        atomic_write(self.path, b''.join(jdump(r) + b'\n' for r in keep))


# ----------------------------------------------------------------------------------------------------------
# State
# ----------------------------------------------------------------------------------------------------------

def load_state(cfg):
    st = read_json(cfg.p('state.json'))
    if not st:
        st = {'schema': SCHEMA, 'host': cfg.host, 'files': {}, 'shards': [], 'catalog_dirty': False,
              'catalog_commit': None, 'last_progress_at': None, 'manifest_dirty': [], 'created_at': now_iso()}
    st.setdefault('manifest_dirty', [])
    st.setdefault('created_at', now_iso())
    st.setdefault('unvisited', {'files': 0, 'bytes': 0})
    return st


def save_state(cfg, st):
    atomic_write(cfg.p('state.json'), jdump(st))


def cur_gen(entry):
    if not entry['gens']:
        entry['gens'].append(new_gen(1, None))
    return entry['gens'][-1]


def new_gen(n, run_id):
    return {'gen': n, 'offset': 0, 'lines': 0, 'seq': 0, 'chain': '', 'prev': None, 'chunks': [],
            'whole_sha256': None, 'whole_sha256_pending': True, 'started_run': run_id}


# ----------------------------------------------------------------------------------------------------------
# Discovery and source reading
# ----------------------------------------------------------------------------------------------------------

def session_of(label, relpath):
    parts = relpath.split('/')
    stem = parts[-1][:-6] if parts[-1].endswith('.jsonl') else parts[-1]
    found = _UUID.findall(stem)
    if found:
        return found[-1], None
    if label == 'claude-projects' and len(parts) >= 3 and parts[-2] == 'subagents':
        return stem, parts[-3]
    for d in reversed(parts[:-1]):
        m = _UUID.findall(d)
        if m:
            return m[-1], None
    return stem, None


def discover(cfg):
    """Yield (key, label, relpath, abspath, lstat) for regular non-empty .jsonl files; never follows links."""
    out = []
    for label, root in cfg.sources.items():
        try:
            rst = os.lstat(root)
        except OSError:
            continue
        if not stat.S_ISDIR(rst.st_mode):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if not os.path.islink(os.path.join(dirpath, d)))
            for name in filenames:
                if not name.endswith('.jsonl'):
                    continue
                path = os.path.join(dirpath, name)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode) or st.st_size == 0:
                    continue  # symlinks, FIFOs, sockets, devices and empty files are skipped (NEG-4)
                rel = os.path.relpath(path, root).replace(os.sep, '/')
                if rel.startswith('../'):
                    continue
                out.append(('%s/%s' % (label, rel), label, rel, path, st))
    return out


def open_source(path):
    """Read-only, no symlink follow, never blocks on a FIFO; refuses anything but a regular file."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise OSError('not a regular file')
    return os.fdopen(fd, 'rb'), st


def fingerprint(f, offset):
    h = hashlib.sha256()
    if offset <= 0:
        return h.hexdigest()

    def rd(pos, n):
        f.seek(pos)
        return f.read(n)
    h.update(rd(0, min(65536, offset)))
    h.update(rd(max(0, offset - 65536), min(65536, offset)))
    for i in range(16):
        pos = (offset * i) // 16
        h.update(rd(pos, min(4096, offset - pos)))
    return h.hexdigest()


def hash_range(f, start, end):
    h = hashlib.sha256()
    f.seek(start)
    left = end - start
    while left > 0:
        b = f.read(min(left, MiB))
        if not b:
            break
        h.update(b)
        left -= len(b)
    return h.hexdigest(), left == 0


# ----------------------------------------------------------------------------------------------------------
# Chunk naming and metadata
# ----------------------------------------------------------------------------------------------------------

def norm_ts(value):
    if not isinstance(value, str):
        return None
    m = _TS.match(value.strip())
    if not m:
        return None
    y, mo, d, hh, mi, ss, tz = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(hh), int(mi), int(ss), tzinfo=timezone.utc)
    except ValueError:
        return None
    if tz and tz != 'Z':
        sign = 1 if tz[0] == '+' else -1
        tzd = tz[1:].replace(':', '')
        from datetime import timedelta
        dt = dt - sign * timedelta(hours=int(tzd[:2]), minutes=int(tzd[2:]))
    return dt.strftime('%Y-%m-%dT%H-%M-%SZ')


def safe_comp(c):
    c = _SAFE.sub('_', c)
    return '_' if c in ('', '.', '..') else c


def chunk_path(cfg, label, relpath, gen, seq, first, last):
    parts = [safe_comp(p) for p in relpath.split('/')]
    stem = parts[-1][:-6] if parts[-1].endswith('.jsonl') else parts[-1]
    reldir = '/'.join(parts[:-1])
    tail = '.%s_%s.g%d.p%05d.jsonl.zst' % (first, last, gen, seq)
    prefix = '%s/%s/%s' % (cfg.host, label, (reldir + '/') if reldir else '')
    if len(prefix) > 120:
        reldir = 'h_' + hashlib.sha256(reldir.encode()).hexdigest()[:16]
        prefix = '%s/%s/%s/' % (cfg.host, label, reldir)
    # the .meta.json sidecar must also stay under 200 characters
    room = 200 - len(prefix) - len(tail) - len('.meta.json')
    if len(stem) > room:
        stem = stem[:max(1, room - 9)] + '-' + hashlib.sha256(stem.encode()).hexdigest()[:8]
    name = stem + tail
    return prefix + name, name


def record_meta(out_line, acc):
    """Mapping fields from the REDACTED record only."""
    try:
        rec = json.loads(out_line)
    except ValueError:
        return
    if not isinstance(rec, dict):
        return
    ts = norm_ts(rec.get('timestamp'))
    if ts:
        acc['ts'].append(ts)
    payload = rec.get('payload') if isinstance(rec.get('payload'), dict) else {}
    msg = rec.get('message') if isinstance(rec.get('message'), dict) else {}
    cwd = rec.get('cwd') or payload.get('cwd')
    if isinstance(cwd, str) and not acc.get('project') and len(cwd) < 400:
        acc['project'] = cwd
    for m in (rec.get('model'), msg.get('model'), payload.get('model')):
        if isinstance(m, str) and len(m) < 100 and m not in acc['models'] and len(acc['models']) < 20:
            acc['models'].append(m)
    if rec.get('type') == 'session_meta' and not acc.get('parent'):
        for k in ('forked_from_id', 'forked_from', 'parent', 'parent_id'):
            v = payload.get(k)
            if isinstance(v, str) and _UUID.fullmatch(v):
                acc['parent'] = v
                break


def mentions_of(data):
    def uniq(it):
        seen = []
        for x in it:
            x = x.decode('ascii', 'replace')
            if x not in seen:
                seen.append(x)
                if len(seen) >= MENTION_CAP:
                    break
        return seen
    return {'tickets': uniq(m.group(1) for m in _TICKET.finditer(data)),
            'prs': uniq(m.group(0) for m in _PR.finditer(data)),
            'commits': uniq(m.group(0) for m in _COMMIT.finditer(data))}


def redact_mod():
    import transcript_redact  # lazy: keeps check and the --background parent fast
    return transcript_redact


def zstd_bin():
    z = shutil.which('zstd')
    if not z:
        raise Refused('zstd is not installed; refusing to archive (install zstd)')
    return z


def compress(data):
    z = zstd_bin()
    r = run_child([z, '-12', '-T1', '-q', '-c'], input=data, capture_output=True, timeout=600)
    if r.returncode != 0:
        raise Refused('zstd compress failed')
    return r.stdout


def decompress(zdata):
    z = zstd_bin()
    r = run_child([z, '-d', '-q', '-c'], input=zdata, capture_output=True, timeout=600)
    if r.returncode != 0:
        raise ValueError('zstd decompress failed')
    return r.stdout


# ----------------------------------------------------------------------------------------------------------
# Egress gate (click-test F1 / failure class C11): the one choke point every byte that leaves the host passes.
#
# publish_tree() is the only caller of commit-tree and push, and it calls egress_check() first over the repo name,
# the ref, the commit message, every tree path and every blob. A blob given as bytes is scanned line by line with
# pass 2 (transcript_redact.verify_bytes) and with gitleaks, the independent third gate. A blob given as an outbox
# path (a zstd chunk) must have been registered by Run.reverify(), which scanned its decompressed bytes and its
# sidecar with both scanners, and its sha256 must still match. Any hit refuses the whole commit (the last line);
# producers filter first (egress_filter) so one dirty catalog entry does not stall the catalog.
# Findings carry only rule names and counts, never a value.
# ----------------------------------------------------------------------------------------------------------

GITLEAKS_VERSION = '8.30.1'  # the pinned, checksum-verified scanner version (goodqa#17119)


def gitleaks_bin(cfg):
    """The gitleaks binary, or None when the local test remote turned it off. Missing in real use refuses."""
    want = os.environ.get('TRANSCRIPTS_GITLEAKS')
    if want == 'off':
        if cfg.local:
            return None
        raise Refused('TRANSCRIPTS_GITLEAKS=off is honoured only against a local test remote')
    cands = [want] if want and want != 'off' else [shutil.which('gitleaks'), os.path.expanduser('~/.local/bin/gitleaks'),
                                                   '/opt/homebrew/bin/gitleaks']
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    raise Refused('secret scanner gitleaks %s is not installed; refusing to push' % GITLEAKS_VERSION)


def gitleaks_scan(cfg, data):
    """gitleaks over bytes -> [(rule_id, 1-based line)]. Values are redacted by gitleaks and dropped here."""
    g = gitleaks_bin(cfg)
    if g is None or not data:
        return []
    r = run_child([g, 'stdin', '--no-banner', '--redact=100', '--report-format', 'json', '--report-path', '-',
                   '--exit-code', '0', '--log-level', 'error'], input=data, capture_output=True,
                  timeout=bounded(600))
    if r.returncode != 0:
        raise Refused('gitleaks failed (exit %d)' % r.returncode)
    try:
        found = json.loads(r.stdout or b'[]')
    except ValueError:
        raise Refused('gitleaks output unreadable')
    out = []
    for f in found or []:
        rule = _SAFE.sub('_', str(f.get('RuleID') or 'unknown'))[:60]
        out.append(('gitleaks:' + rule, int(f.get('StartLine') or 0)))
    return out


def scan_bytes(cfg, data):
    """Both scanners over one byte string -> [(kind, 1-based line)], kinds only."""
    tr = redact_mod()
    return list(tr.verify_bytes(data)) + gitleaks_scan(cfg, data)


class EgressRefused(Refused):
    pass


def _egress_items(repo, ref, files, message):
    yield 'repo', repo.encode('utf-8', 'surrogateescape')
    yield 'ref', ref.encode('utf-8', 'surrogateescape')
    yield 'message', message.encode('utf-8', 'surrogateescape')
    for path in files:
        yield 'path', path.encode('utf-8', 'surrogateescape')


def egress_check(cfg, repo, ref, files, message):
    """Scan everything a commit would publish. Returns [(where, kinds)] for each failing item; [] means clean.

    `where` is 'repo', 'ref', 'message', 'path:<sha12>' or 'blob:<sha12 of path>'. Bytes blobs and the names are
    scanned in one batch per scanner, so a catalog of thousands of small files costs one gitleaks process."""
    lines, owner = [], []  # one scanned line each; owner[i] = where it came from
    for where, b in _egress_items(repo, ref, files, message):
        b = b.replace(b'\n', b' ')
        lines.append(b)
        owner.append(where if where != 'path' else 'path:' + sha12(b.decode('utf-8', 'surrogateescape')))
    bad = {}
    registered = getattr(cfg, 'egress_registered', {})
    for path, data in files.items():
        where = 'blob:' + sha12(path)
        if isinstance(data, bytes):
            parts = data.split(b'\n')
            if parts and parts[-1] == b'':
                parts.pop()
            lines.extend(parts)
            owner.extend([where] * len(parts))
            continue
        # an outbox file: only a chunk reverify() scanned, unchanged since, may leave
        want = registered.get(os.path.abspath(data))
        try:
            with open(data, 'rb') as fh:
                got = hashlib.sha256(fh.read()).hexdigest()
        except OSError:
            got = None
        if want is None or got != want:
            bad.setdefault(where, set()).add('unverified-blob')
    # pass 2 per item (it is a per-record verifier), gitleaks once over the batch (one process per commit)
    tr = redact_mod()
    start = 0
    for where, group in _runs(owner):
        for kind, _ in tr.verify_bytes(b''.join(x + b'\n' for x in lines[start:start + group])):
            bad.setdefault(where, set()).add(kind)
        start += group
    for kind, line in gitleaks_scan(cfg, b''.join(x + b'\n' for x in lines)):
        if 1 <= line <= len(owner):
            bad.setdefault(owner[line - 1], set()).add(kind)
        else:
            bad.setdefault('batch', set()).add(kind)
    return sorted((w, sorted(k)) for w, k in bad.items())


def _runs(owner):
    """Consecutive runs of the same owner -> [(owner, length)]."""
    out = []
    for w in owner:
        if out and out[-1][0] == w:
            out[-1][1] += 1
        else:
            out.append([w, 1])
    return [tuple(x) for x in out]


def egress_refusal(failures):
    kinds = {}
    for _, ks in failures:
        for k in ks:
            kinds[k] = kinds.get(k, 0) + 1
    return EgressRefused('egress gate refused %d item(s): %s' % (
        len(failures), ','.join('%s=%d' % kv for kv in sorted(kinds.items()))))


def egress_filter(cfg, repo, files, message):
    """Drop what cannot leave before the commit is built, so one dirty entry does not stall a catalog.

    A JSONL blob loses only its failing lines; any other failing blob or path is dropped whole. Returns
    (clean files, dropped [(where, kinds)]). A failing repo, ref or message refuses: nothing can be dropped."""
    failures = egress_check(cfg, repo, 'refs/heads/main', files, message)
    if not failures:
        return files, []
    fatal = [f for f in failures if f[0] in ('repo', 'ref', 'message', 'batch')]
    if fatal:
        raise egress_refusal(fatal)
    by_sha = {sha12(p): p for p in files}
    out = dict(files)
    dropped = []
    for where, kinds in failures:
        p = by_sha.get(where.split(':', 1)[1])
        if p is None or p not in out:
            continue
        data = out[p]
        if where.startswith('blob:') and p.endswith('.jsonl') and isinstance(data, bytes):
            parts = data.split(b'\n')
            if parts and parts[-1] == b'':
                parts.pop()
            dirty = {line for _, line in scan_bytes(cfg, b''.join(x + b'\n' for x in parts))}
            out[p] = b''.join(x + b'\n' for n, x in enumerate(parts, 1) if n not in dirty)
            dropped.append((where + ':lines', kinds))
        else:
            out.pop(p)
            dropped.append((where, kinds))
    return out, dropped


def gate_metadata(sidecar):
    """Sidecars are pushed too: drop optional fields that trip the verifier; refuse if still dirty."""
    tr = redact_mod()
    if not tr.verify_bytes(jdump(sidecar)):
        return sidecar
    for k in ('project', 'models', 'mentions', 'parent'):
        sidecar[k] = None if k != 'models' else []
    sidecar['metadata_dropped'] = True
    if tr.verify_bytes(jdump(sidecar)):
        raise Refused('metadata')
    return sidecar


# ----------------------------------------------------------------------------------------------------------
# A record over the chunk maximum (TRANSCRIPTS_CHUNK_MAX_BYTES) can never be archived whole, so it is a
# record-level omission with this kind, counted as an incident in the receipt, check and status. It is never a
# hold: no retry can make it fit (triage of PR #316 at 79d55675).
OVERSIZE = 'oversize'


def oversize_record(line_no, src_len):
    """The omitted-record line, in transcript_redact's own format ({"_archive":"omitted",...})."""
    return json.dumps({'_archive': 'omitted', 'reason': OVERSIZE, 'line': int(line_no), 'src_len': int(src_len)},
                      separators=(',', ':')).encode('ascii')


def line_end(f, read, room):
    """Bytes in the record that starts `read` bytes before f's position, newline included, or None when it has no
    newline within `room` bytes (still being written). Reads in 1 MiB steps and keeps none of it."""
    size = read
    while size < room:
        block = f.readline(min(1 << 20, room - size))
        if not block:
            return None
        size += len(block)
        if block.endswith(b'\n'):
            return size
    return None


def feed_range(f, pos, size, h):
    f.seek(pos)
    left = size
    while left:
        block = f.read(min(1 << 20, left))
        if not block:
            raise OSError('source shrank while hashing an oversize record')
        h.update(block)
        left -= len(block)


# Hold state: the one owner (gate F1, PR #316). Only hold(), begin_retry() and release() write e['held'];
# tests.test_transcripts.HoldOwnerTests guards that. Every hold carries a retry rule (exponential backoff,
# and at once after a ruleset change), and any held file keeps the run status off "ok".
# ----------------------------------------------------------------------------------------------------------

HOLD_BACKOFF_MAX = 86400  # a held file is retried at least daily


def iso_of(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def hold_delay(cfg, attempts):
    """Seconds before held attempt `attempts` (1-based) is retried: doubling from cfg.hold_backoff, capped daily."""
    if cfg.hold_backoff <= 0:
        return 0
    return min(cfg.hold_backoff * (2 ** min(max(attempts - 1, 0), 32)), HOLD_BACKOFF_MAX)


def hold(cfg, e, reason, line=None):
    """Hold file entry `e` for `reason`. A repeat of the same reason (the previous hold, or the one this visit is
    retrying) counts as another attempt and backs off further; `since` keeps the first hold time."""
    prev = e.get('held') or e.get('retry_of') or {}
    attempts = (int(prev.get('attempts') or 0) + 1) if prev.get('reason') == reason else 1
    e['held'] = {'reason': reason, 'line': line, 'ruleset': redact_mod().RULESET_VERSION,
                 'since': prev.get('since') or now_iso(), 'attempts': attempts,
                 'retry_at': iso_of(time.time() + hold_delay(cfg, attempts))}


def hold_due(held):
    """True when a hold may be retried now: its retry time has come, the ruleset changed, or it predates retries."""
    if not held:
        return True
    if held.get('ruleset') != redact_mod().RULESET_VERSION:
        return True
    t = parse_iso(held.get('retry_at'))
    return t is None or time.time() >= t


def begin_retry(e):
    """Lift a due hold for this visit; hold() counts a repeat as another attempt, release() ends it."""
    e['retry_of'] = e.get('held')
    e['held'] = None


def release(e):
    e['held'] = None
    e.pop('retry_of', None)


def held_summary(st):
    """{'count', 'by_reason'} over every held file: the one view check, status, the receipt and deliver use."""
    by_reason = {}
    for e in st['files'].values():
        if e.get('held'):
            reason = str(e['held'].get('reason') or 'unknown')
            by_reason[reason] = by_reason.get(reason, 0) + 1
    return {'count': sum(by_reason.values()), 'by_reason': by_reason}


# ----------------------------------------------------------------------------------------------------------
# The sync run
# ----------------------------------------------------------------------------------------------------------

class Run:
    def __init__(self, cfg, checkpoint, budget, background=False):
        self.cfg = cfg
        self.checkpoint = checkpoint
        self.id = '%d-%d' % (time.time_ns(), os.getpid())
        self.started = time.monotonic()
        self.started_at = now_iso()
        self.budget = budget
        reserve = min(30.0, budget * 0.3)
        self.work_deadline = self.started + budget - reserve
        self.deadline = self.started + budget
        _DEADLINE[0] = self.deadline + 10
        self.served = set()
        self.force = checkpoint in FORCE_SEAL
        self.st = load_state(cfg)
        self.journal = Journal(cfg)
        self.remote = Remote(cfg)
        self.files_scanned = 0
        self.files_changed = 0
        self.chunks_staged = 0
        self.chunks_pushed = 0
        self.bytes_pushed = 0
        self.records = 0
        self.omitted = []  # (key, kind)
        self.file_counts = {}  # key -> [records, omitted]
        self.whole = {}  # (key, gen) -> hasher for generations begun in this run
        self.errors = []
        self.notes = []
        self.status = 'ok'
        self.shard_commits = {}
        self.catalog_commit = None
        self.collisions = 0
        self.refused = None
        self.last_save = time.monotonic()
        self.disk_low = None
        self.egress_held = 0  # files held because a chunk path or sidecar failed the egress gate
        self.scanner_held = 0  # files held because the pre-push rescan of a staged chunk still found a hit
        self.catalog_withheld = 0  # catalog entries (manifests, index lines) withheld at the egress gate
        cfg.egress_registered = {}  # outbox chunk abspath -> sha256, set only by reverify()

    # -- persistence
    def save(self, force=False):
        if force or time.monotonic() - self.last_save > 15:
            save_state(self.cfg, self.st)
            self.last_save = time.monotonic()

    def mark_manifest(self, key):
        if key not in self.st['manifest_dirty']:
            self.st['manifest_dirty'].append(key)
        self.st['catalog_dirty'] = True

    # -- outbox
    def outbox_paths(self, rec):
        base = os.path.join(self.cfg.p('outbox'), rec['path'])
        return base, base + '.meta.json', base + '.rec.json'

    def outbox_bytes(self):
        total = 0
        for dp, _, fns in os.walk(self.cfg.p('outbox')):
            for fn in fns:
                try:
                    total += os.lstat(os.path.join(dp, fn)).st_size
                except OSError:
                    pass
        return total

    def drop_outbox(self, rec):
        for p in self.outbox_paths(rec):
            try:
                os.unlink(p)
            except OSError:
                pass

    # -- startup reconciliation (NEG-6, NEG-19)
    def adopt_outbox(self):
        """Adopt staged chunks the state file missed (crash after staging), delete true orphans."""
        metas = []
        for dp, _, fns in os.walk(self.cfg.p('outbox')):
            for fn in fns:
                if fn.endswith('.rec.json'):
                    metas.append(os.path.join(dp, fn))
        recs = []
        for p in metas:
            r = read_json(p)
            if r:
                recs.append(r)
        recs.sort(key=lambda r: (r['key'], r['gen'], r['seq']))
        known = set()
        for e in self.st['files'].values():
            for g in e['gens']:
                for c in g['chunks']:
                    known.add(c['path'])
        for r in recs:
            if r['path'] in known:
                hit = self.chunk_index().get(r['path'])
                if hit and hit[2]['status'] == 'pushed':
                    self.drop_outbox(r['chunk'])
                continue
            e = self.st['files'].get(r['key'])
            if e is None and r['gen'] == 1 and r['seq'] == 1:
                e = self.new_entry(r['key'], r['label'], r['relpath'])
                self.st['files'][r['key']] = e
            g = cur_gen(e) if e else None
            if g and r['gen'] > g['gen'] and r['seq'] == 1 and r['src'][0] == 0:
                e['gens'].append(new_gen(r['gen'], None))
                g = cur_gen(e)
            if g and g['gen'] == r['gen'] and g['seq'] + 1 == r['seq'] and g['offset'] == r['src'][0]:
                self.apply_chunk(e, g, r['chunk'])
                e['stat'] = None  # force a rescan; fingerprint is refreshed on the next visit
                known.add(r['path'])
            else:
                self.drop_outbox(r['chunk'])
        # chunk files without a .rec.json are orphans from an interrupted write
        for dp, _, fns in os.walk(self.cfg.p('outbox')):
            for fn in fns:
                full = os.path.join(dp, fn)
                if fn.endswith('.zst') and not os.path.exists(full + '.rec.json'):
                    for q in (full, full + '.meta.json'):
                        try:
                            os.unlink(q)
                        except OSError:
                            pass

    def reconcile_journal(self):
        pend = self.journal.unresolved()
        if not pend:
            return
        by_repo = {}
        for row in pend:
            by_repo.setdefault(row['repo'], []).append(row)
        index = self.chunk_index()
        for repo, rows in by_repo.items():
            tr = TmpRepo(self.cfg, repo)
            try:
                tip = tr.fetch_tip()
            finally:
                tr.close()
            done = []
            for row in rows:
                if tr.entries.get(row['path']) == row['blob']:
                    hit = index.get(row['path'])
                    if hit:
                        e, g, c = hit
                        c['status'] = 'pushed'
                        c['shard'] = repo
                        c['commit'] = c.get('commit') or tip
                        self.finish_pushed(e, c)
                    done.append((row['path'], row['blob']))
            if done:
                self.journal.pushed(repo, done, tip)
        self.journal.compact([])
        self.save(force=True)
        for e in self.st['files'].values():
            for g in e['gens']:
                for c in g['chunks']:
                    if c['status'] == 'pushed':
                        self.drop_outbox(c)

    def chunk_index(self):
        idx = {}
        for e in self.st['files'].values():
            for g in e['gens']:
                for c in g['chunks']:
                    idx[c['path']] = (e, g, c)
        return idx

    # -- entries
    def new_entry(self, key, label, relpath):
        session, parent = session_of(label, relpath)
        return {'label': label, 'relpath': relpath, 'session': session, 'parent': parent,
                'tool': TOOL_OF.get(label, label.split('-')[0]), 'gens': [], 'stat': None, 'fp': None,
                'held': None, 'missing': False, 'pending_since': None, 'moved_from': None,
                'force_new_gen': False, 'project': None}

    def apply_chunk(self, e, g, c):
        g['chunks'].append(c)
        g['seq'] = c['seq']
        g['offset'] = c['src'][1]
        g['lines'] = c['line_start'] - 1 + c['records']
        g['chain'] = c['chain_sha256']
        g['prev'] = {'name': c['name'], 'sha256': c['sha256']}

    def rollback(self, e, g, from_idx, reason):
        """Discard staged chunks g.chunks[from_idx:] (never pushed ones) and rewind the generation."""
        drop = g['chunks'][from_idx:]
        if any(c['status'] == 'pushed' for c in drop):
            raise Refused('internal: rollback of a pushed chunk')
        for c in drop:
            self.drop_outbox(c)
            self.chunks_staged -= 1 if c.get('run') == self.id else 0
            for sh in self.st['shards']:
                if c.get('shard') and sh['repo'] == c['shard']:
                    sh['bytes'] -= c['zbytes']
                    sh['chunks'] -= 1
        first = drop[0]
        g['chunks'] = g['chunks'][:from_idx]
        g['seq'] = first['seq'] - 1
        g['offset'] = first['src'][0]
        g['lines'] = first['line_start'] - 1
        g['chain'] = first['prev_chain']
        g['prev'] = first['prev']
        e['stat'] = None
        e['fp'] = None
        self.whole.pop((self.key_of(e), g['gen']), None)

    def key_of(self, e):
        return '%s/%s' % (e['label'], e['relpath'])

    # -- scanning
    def needs_visit(self, e, st):
        if e is None:
            return True
        if e.get('force_new_gen'):
            return True
        if e.get('held'):
            return hold_due(e['held'])  # a held file waits for its retry, then is visited even if unchanged
        s = e.get('stat')
        sig = [st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino]
        if s != sig:
            return True
        return bool(e.get('pending_since'))  # an unsealed delta waits for the small-chunk rule

    def find_move(self, key, label, relpath, f, size, seen_keys):
        session, _ = session_of(label, relpath)
        if getattr(self, '_by_session', None) is None:
            self._by_session = {}
            for k, v in self.st['files'].items():
                self._by_session.setdefault(v['session'], []).append(k)
        for okey in list(self._by_session.get(session, [])):
            oe = self.st['files'].get(okey)
            if oe is None or okey in seen_keys or okey == key or oe['session'] != session or oe['tool'] != TOOL_OF.get(label):
                continue
            if os.path.lexists(os.path.join(self.cfg.sources.get(oe['label'], '/nonexistent'), oe['relpath'])):
                continue
            g = cur_gen(oe)
            if g['offset'] == 0 or size < g['offset']:
                continue
            ok = True
            for c in g['chunks']:
                h, full = hash_range(f, c['src'][0], c['src'][1])
                if not full or h != c['src_sha256']:
                    ok = False
                    break
            if ok:
                return okey
        return None

    def process_file(self, key, label, relpath, path, seen_keys):
        cfg = self.cfg
        try:
            f, fst = open_source(path)
        except OSError:
            return
        with f:
            e = self.st['files'].get(key)
            if e is None:
                mkey = self.find_move(key, label, relpath, f, fst.st_size, seen_keys)
                if mkey:
                    e = self.st['files'].pop(mkey)
                    e['moved_from'] = mkey
                    e['label'], e['relpath'] = label, relpath
                    e['tool'] = TOOL_OF.get(label, e['tool'])
                    e['fp'] = None
                    e['ino_moved'] = True
                    self.mark_manifest(mkey)
                else:
                    e = self.new_entry(key, label, relpath)
                self.st['files'][key] = e
            e['missing'] = False
            g = cur_gen(e)
            rewritten = False
            if g['offset'] > 0:
                s = e.get('stat')
                if e.pop('force_new_gen', False):
                    rewritten = True
                elif fst.st_size < g['offset']:
                    rewritten = True
                elif s and s[3] != fst.st_ino and not e.pop('ino_moved', False):
                    rewritten = True
                elif e.get('fp') and fingerprint(f, g['offset']) != e['fp']:
                    rewritten = True
                elif not e.get('fp'):
                    # no fingerprint (move or adoption): confirm the archived prefix chunk by chunk
                    for c in g['chunks']:
                        h, full = hash_range(f, c['src'][0], c['src'][1])
                        if not full or h != c['src_sha256']:
                            rewritten = True
                            break
            else:
                e.pop('force_new_gen', None)
            if rewritten:
                e['gens'].append(new_gen(g['gen'] + 1, self.id))
                g = cur_gen(e)
                release(e)  # a new generation starts clean
                self.mark_manifest(key)
            if g['offset'] == 0 and g['seq'] == 0:
                g['started_run'] = self.id
            self.files_changed += 1
            held = e.get('held')
            if held:
                if not hold_due(held):
                    return
                if held.get('reason') == 'collision':
                    # a shard path holds different bytes: only a person (or verify) can resolve it, so the retry
                    # re-checks and re-alerts; the file stays held and the run stays not ok
                    hold(cfg, e, 'collision', held.get('line'))
                    alert(cfg, 'collision', 'file %s is still held on a shard path collision' % sha12(key))
                    self.mark_manifest(key)
                    return
                begin_retry(e)
            try:
                complete = self.chunk_delta(e, g, key, f, fst)
            except (Refused, ValueError, OSError, subprocess.SubprocessError) as ex:
                if isinstance(ex, subprocess.TimeoutExpired) and ex.cmd == 'budget':
                    raise
                why = ('refused:' + str(ex)[:60]) if isinstance(ex, Refused) else 'error:' + type(ex).__name__
                hold(cfg, e, why)
                alert(self.cfg, 'file-held', 'file %s held (%s); the run continues' % (sha12(key), why))
                self.mark_manifest(key)
                complete = True
            # an early stop (budget, per-visit cap) leaves stat unset so the next run resumes the file
            e['stat'] = [fst.st_size, fst.st_mtime_ns, fst.st_ctime_ns, fst.st_ino] if complete else None
            e['fp'] = fingerprint(f, g['offset'])

    def chunk_delta(self, e, g, key, f, fst):
        cfg = self.cfg
        tr = redact_mod()
        snap = fst.st_size
        pos = g['offset']
        line_no = g['lines']
        f.seek(pos)
        limit = pos + cfg.file_delta_cap
        buf = []
        buf_bytes = 0
        src_h = hashlib.sha256()
        start = pos
        acc = {'ts': [], 'models': [], 'project': None, 'parent': None}
        redactions = {}
        omitted = []
        counts = self.file_counts.setdefault(key, [0, 0])
        stopped = None
        while True:
            if pos >= snap:
                break
            if pos >= limit:
                stopped = 'cap'
                break
            if time.monotonic() > self.work_deadline:
                stopped = 'budget'
                break
            line = f.readline(cfg.chunk_max + 1)
            if not line:
                break
            if not line.endswith(b'\n'):
                if len(line) <= cfg.chunk_max:
                    break  # partial last line waits for the next run (NEG-7)
                # A record over the maximum can never fit a chunk, so it is omitted, never held (holds are only for
                # causes a retry can clear). Find its end without holding it in memory; an unterminated one waits.
                size = line_end(f, len(line), snap - pos)
                if size is None:
                    break
                line_no += 1
                out, cnt, kind = oversize_record(line_no, size - 1), {}, OVERSIZE
            else:
                if pos + len(line) > snap:
                    break
                size = len(line)
                line_no += 1
                out, cnt, kind = tr.redact_line(line[:-1], line_no)
                if len(out) + 1 > cfg.chunk_max:
                    out, cnt, kind = oversize_record(line_no, size - 1), {}, OVERSIZE
            rec = out + b'\n'
            if buf and buf_bytes + len(rec) > cfg.chunk_max:
                self.seal(e, g, key, buf, start, pos, src_h, acc, redactions, omitted, fst)
                buf, buf_bytes, start = [], 0, pos
                src_h = hashlib.sha256()
                acc = {'ts': [], 'models': [], 'project': None, 'parent': acc.get('parent')}
                redactions, omitted = {}, []
            buf.append(rec)
            buf_bytes += len(rec)
            if size == len(line):
                src_h.update(line)
            else:
                feed_range(f, pos, size, src_h)  # the chunk's source hash still covers every byte of the record
            pos += size  # hash_range leaves f at pos + size as readline does
            counts[0] += 1
            self.records += 1
            for k, v in cnt.items():
                redactions[k] = redactions.get(k, 0) + v
            if kind:
                omitted.append({'line': line_no, 'kind': kind})
                self.omitted.append((key, kind))
                if kind != OVERSIZE:
                    counts[1] += 1  # an oversize record is an incident, not a redaction failure: no cap counts it
            record_meta(out, acc)
        if buf:
            src_bytes = pos - start
            idle = time.time() - fst.st_mtime >= cfg.idle_s
            if src_bytes >= cfg.seal_min or idle or self.force or self.served & FORCE_SEAL:
                self.seal(e, g, key, buf, start, pos, src_h, acc, redactions, omitted, fst)
                e['pending_since'] = None
            else:
                # the unsealed delta waits; its records were not archived
                counts[0] -= len(buf)
                self.records -= len(buf)
                counts[1] -= sum(1 for o in omitted if o['kind'] != OVERSIZE)
                for o in omitted:
                    self.omitted.remove((key, o['kind']))
                if not e.get('pending_since'):
                    e['pending_since'] = now_iso()
        elif stopped is None and not e.get('held'):
            e['pending_since'] = None
        if e.get('held'):
            self.mark_manifest(key)
        return stopped is None

    def seal(self, e, g, key, buf, start, end, src_h, acc, redactions, omitted, fst):
        cfg = self.cfg
        data = b''.join(buf)
        sha = hashlib.sha256(data).hexdigest()
        zdata = compress(data)
        if hashlib.sha256(decompress(zdata)).hexdigest() != sha:
            raise Refused('zstd round trip mismatch')
        if len(zdata) >= cfg.file_max_z:
            raise Refused('compressed chunk over 50 MB')
        if acc['ts']:
            first, last, ts_source = min(acc['ts']), max(acc['ts']), 'records'
        else:
            first = last = datetime.fromtimestamp(fst.st_mtime, timezone.utc).strftime('%Y-%m-%dT%H-%M-%SZ')
            ts_source = 'mtime'
        seq = g['seq'] + 1
        path, name = chunk_path(cfg, e['label'], e['relpath'], g['gen'], seq, first, last)
        chain = hashlib.sha256((g['chain'] + sha).encode('ascii')).hexdigest()
        if acc.get('parent') and not e.get('parent'):
            e['parent'] = acc['parent']
        if acc.get('project') and not e.get('project'):
            e['project'] = acc['project']
        line_start = g['lines'] + 1
        sidecar = {
            'schema': SCHEMA, 'chunker_version': CHUNKER_VERSION, 'host': cfg.host, 'tool': e['tool'],
            'source': e['label'], 'relpath': e['relpath'], 'session': e['session'], 'parent': e.get('parent'),
            'project': acc.get('project') or e.get('project'), 'models': acc['models'], 'gen': g['gen'],
            'seq': seq, 'name': name, 'path': path,
            'prev': dict(g['prev']) if g['prev'] else None,
            'src_range': [start, end], 'src_sha256': src_h.hexdigest(), 'sha256': sha,
            'zsha256': hashlib.sha256(zdata).hexdigest(), 'bytes': len(data), 'zbytes': len(zdata),
            'records': len(buf), 'line_start': line_start, 'first_ts': first,
            'last_ts': last, 'ts_source': ts_source, 'chain_sha256': chain, 'mentions': mentions_of(data),
            'redactions': redactions, 'omitted': omitted, 'ruleset_version': redact_mod().RULESET_VERSION,
        }
        sidecar = gate_metadata(sidecar)
        meta_bytes = jdump(sidecar)
        c = {'name': name, 'path': path, 'seq': seq, 'gen': g['gen'], 'status': 'staged', 'shard': None,
             'commit': None, 'blob': git_blob_sha(zdata), 'meta_blob': git_blob_sha(meta_bytes), 'sha256': sha,
             'zsha256': sidecar['zsha256'], 'src_sha256': sidecar['src_sha256'], 'src': [start, end],
             'line_start': line_start, 'records': len(buf), 'bytes': len(data), 'zbytes': len(zdata),
             'chain_sha256': chain, 'prev_chain': g['chain'], 'prev': sidecar['prev'],
             'omitted': len(omitted), 'oversize': sum(1 for o in omitted if o['kind'] == OVERSIZE),
             'month': datetime.now(timezone.utc).strftime('%Y-%m'), 'run': self.id}
        zp, mp, rp = self.outbox_paths(c)
        atomic_write(zp, zdata)
        atomic_write(mp, meta_bytes)
        atomic_write(rp, jdump({'key': key, 'label': e['label'], 'relpath': e['relpath'], 'gen': g['gen'],
                                'seq': seq, 'src': [start, end], 'path': path, 'chunk': c}))
        crash_point(cfg, 'after_stage')
        wk = (key, g['gen'])
        if g['started_run'] == self.id:
            self.whole.setdefault(wk, hashlib.sha256()).update(data)
        if g['started_run'] != self.id:
            g['whole_sha256'] = None  # appended in a later run: whole hash waits for verify --rehash
            g['whole_sha256_pending'] = True
        self.apply_chunk(e, g, c)
        self.chunks_staged += 1
        self.mark_manifest(key)
        self.save()

    # -- omission cap (AC-16)
    def enforce_omission_cap(self):
        """AC-16 and gate F1. Files over the per-file rule (5 %, at 100+ records) are held. If the rest still trips
        the run rule (0.5 %, at 1000+ records), the fewest top contributors are held, highest omission rate first,
        until the rest is under it. A file at or under the run rate is never held for the run rule, so one hostile
        file cannot hold its neighbours. Every hold retries (hold())."""
        counts = self.file_counts
        bad = {k for k, (r, o) in counts.items() if r >= 100 and o * 100 > r * 5}
        rest_r = sum(r for k, (r, o) in counts.items() if k not in bad)
        rest_o = sum(o for k, (r, o) in counts.items() if k not in bad)

        def over(r, o):
            return r >= 1000 and o * 1000 > r * 5  # the run rule needs a 1000-record denominator

        if over(rest_r, rest_o):
            ranked = sorted(((k, r, o) for k, (r, o) in counts.items() if k not in bad and o),
                            key=lambda x: (-(x[2] / max(x[1], 1)), -x[2], x[0]))
            for k, r, o in ranked:
                if o * 1000 <= r * 5:
                    break  # at or under the run rate: never collateral
                bad.add(k)
                rest_r, rest_o = rest_r - r, rest_o - o
                if not over(rest_r, rest_o):
                    break
        if not bad:
            return
        self.status = 'omission-cap'
        for key in bad:
            e = self.st['files'].get(key)
            if not e:
                continue
            g = cur_gen(e)
            idx = next((i for i, c in enumerate(g['chunks']) if c.get('run') == self.id and c['status'] == 'staged'),
                       None)
            if idx is not None:
                self.rollback(e, g, idx, 'omission-cap')
            hold(self.cfg, e, 'omission-cap')
            self.mark_manifest(key)
        alert(self.cfg, 'omission-cap', 'omitted %d of %d records; %d file(s) held'
              % (len(self.omitted), self.records, len(bad)))

    # -- publishing
    def staged(self):
        out = []
        for key, e in self.st['files'].items():
            for g in e['gens']:
                for i, c in enumerate(g['chunks']):
                    if c['status'] == 'staged':
                        out.append((key, e, g, i, c))
        return out

    def reverify(self, key, e, g, i, c):
        """Last-moment check of a staged chunk (NEG-16). Returns (zdata, meta) or None after a rollback."""
        tr = redact_mod()
        zp, mp, _ = self.outbox_paths(c)
        why = None
        try:
            with open(zp, 'rb') as fh:
                zdata = fh.read()
            with open(mp, 'rb') as fh:
                meta_b = fh.read()
            meta = json.loads(meta_b)
            if hashlib.sha256(zdata).hexdigest() != c['zsha256'] or meta.get('zsha256') != c['zsha256']:
                why = 'zsha256'
            else:
                data = decompress(zdata)
                if hashlib.sha256(data).hexdigest() != c['sha256']:
                    why = 'sha256'
                elif meta.get('ruleset_version') != tr.RULESET_VERSION:
                    why = 'ruleset'
                else:
                    # the pre-push rescan: pass 2 and gitleaks over the decompressed chunk and its sidecar
                    data_hits = scan_bytes(self.cfg, data)
                    hits = data_hits + scan_bytes(self.cfg, meta_b)
                    if hits:
                        why = 'scanner'
        except (OSError, ValueError):
            why = 'unreadable'
        if why is None:
            self.cfg.egress_registered[os.path.abspath(zp)] = c['zsha256']
            return zp, meta_b  # pushed from the outbox file: one chunk in memory at a time
        if why == 'scanner':
            # a hit that survived redaction: the whole file is held back and listed, never pushed (goodqa#17119)
            rules = sorted({k for k, _ in hits})
            first = min((h[1] for h in data_hits), default=None)  # a sidecar-only hit has no source line
            line = c.get('line_start', 1) + first - 1 if first and first <= c.get('records', 0) else None
            self.rollback(e, g, i, why)
            hold(self.cfg, e, 'scanner:' + ','.join(rules)[:80], line)
            alert(self.cfg, 'scanner-hit', 'file %s held: %d pre-push scanner hit(s) (%s)' % (
                sha12(key), len(hits), ','.join(rules)[:200]))
            self.scanner_held += 1
            self.mark_manifest(key)
            return None
        alert(self.cfg, 'reverify-failed', 'chunk %s held back (%s); re-chunking from source' % (sha12(c['path']), why))
        e['reverify_failures'] = e.get('reverify_failures', 0) + 1
        self.rollback(e, g, i, why)
        if e['reverify_failures'] >= 3:
            hold(self.cfg, e, 'reverify-' + why)
        self.mark_manifest(key)
        return None

    def shard_for(self, month, zbytes):
        shards = self.st['shards']
        mine = [s for s in shards if s['month'] == month]
        cur = mine[-1] if mine else None
        if cur is None or (cur['bytes'] > 0 and cur['bytes'] + zbytes > self.cfg.shard_cap):
            part = (cur['part'] + 1) if cur else 1
            cur = {'repo': 'agent-transcripts-%s-%s-p%d' % (self.cfg.host, month, part), 'month': month,
                   'part': part, 'bytes': 0, 'chunks': 0}
            shards.append(cur)
        cur['bytes'] += zbytes  # counted at assignment: an assigned chunk is pushed (or retried) to this shard
        cur['chunks'] += 1
        return cur

    def finish_pushed(self, e, c):
        meta_src = self.outbox_paths(c)[1]
        dst = os.path.join(self.cfg.p('meta'), c['path'] + '.meta.json')
        if os.path.exists(meta_src):
            os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
            os.replace(meta_src, dst)
        self.mark_manifest(self.key_of(e))
        self.st['last_progress_at'] = now_iso()

    def publish(self):
        cfg = self.cfg
        if os.path.exists(cfg.p('killswitch.json')):
            self.status = 'killswitch'
            return
        todo = [(key, e, g, c) for key, e, g, i, c in self.staged()]
        for key, e, g, c in todo:
            if not c.get('shard'):
                c['shard'] = self.shard_for(c['month'], c['zbytes'])['repo']
        self.save(force=True)
        repos = []
        for _, _, _, c in todo:
            if c['shard'] not in repos:
                repos.append(c['shard'])
        need_catalog = bool(todo) or bool(self.st.get('catalog_dirty')) or (
            self.st.get('catalog_commit') is None and any(c['status'] == 'pushed' for *_, c in self.all_chunks()))
        if not todo and not need_catalog:
            return
        try:
            for repo in [CATALOG] + repos:  # the catalog first: gh-less checks read attestations from it
                self.remote.ensure(repo)
                self.remote.check(repo)
        except Refused as ex:
            self.refused = str(ex)
            self.status = 'refused'
            alert(cfg, 'repo-check', str(ex))
            return
        kinds = open_incidents(cfg, self.remote)
        if kinds:
            self.status = 'killswitch'
            self.refused = 'catalog incident open kind=%s; pushes stop on every host' % ','.join(kinds)
            alert(cfg, 'incident-open', self.refused)
            return
        ready = self.rescan_staged(todo)
        for repo in repos:
            pending = [it for it in todo if it[3]['shard'] == repo and id(it[3]) in ready]
            while pending:
                group, size = [], 0
                while pending and (not group or size + pending[0][3]['zbytes'] <= cfg.push_max):
                    if time.monotonic() > self.deadline:
                        self.notes.append('budget reached; remaining staged chunks wait for the next run')
                        pending = []
                        break
                    key, e, g, c = pending.pop(0)
                    if c['status'] != 'staged' or c not in g['chunks']:
                        continue  # rolled back with an earlier chunk of the same file
                    group.append((key, e, g, c, ready[id(c)]))
                    size += c['zbytes']
                if group:
                    self.push_group(repo, group)
        if (need_catalog or self.st.get('catalog_dirty')) and time.monotonic() < self.deadline:
            self.push_catalog()

    def rescan_staged(self, todo):
        """File-atomic pre-push rescan. Every staged chunk of a file is rescanned before any chunk of that file is
        pushed. A scanner hit holds the whole file and none of its staged chunks leave; a file the budget cut off
        part way waits whole. Returns {id(chunk): (zpath, sidecar bytes)} for the chunks that may be pushed."""
        ready, failed, cut = {}, set(), set()
        for key, e, g, c in todo:
            if key in failed or key in cut or c['status'] != 'staged' or c not in g['chunks']:
                continue
            if time.monotonic() > self.deadline:
                cut.add(key)
                continue
            ok = self.reverify(key, e, g, g['chunks'].index(c), c)
            if ok is None:
                failed.add(key)
                if e.get('held'):
                    # held: the chunks of this file already rescanned clean are withdrawn too
                    for x in g['chunks']:
                        ready.pop(id(x), None)
                    staged = [i for i, x in enumerate(g['chunks']) if x['status'] == 'staged']
                    if staged:
                        self.rollback(e, g, staged[0], 'held')
                continue
            ready[id(c)] = ok
        for key, e, g, c in todo:
            if key in cut:
                ready.pop(id(c), None)
        if cut:
            self.notes.append('budget reached during the pre-push rescan; %d file(s) wait whole' % len(cut))
        return ready

    def all_chunks(self):
        for key, e in self.st['files'].items():
            for g in e['gens']:
                for i, c in enumerate(g['chunks']):
                    yield key, e, g, i, c

    def push_group(self, repo, group):
        files = {}
        for key, e, g, c, (zdata, meta_b) in group:
            files[c['path']] = zdata
            files[c['path'] + '.meta.json'] = meta_b
        message = 'archive %d chunk(s) from %s' % (len(group), self.cfg.host)
        files, dropped = egress_filter(self.cfg, repo, files, message)
        if dropped:
            # a chunk whose path or sidecar cannot leave: hold its file locally, push the rest of the group
            gone = {w.split(':')[1] for w, _ in dropped}
            bad = {}  # key -> (e, g, first index in this group)
            for key, e, g, c, _ in group:
                if sha12(c['path']) in gone or sha12(c['path'] + '.meta.json') in gone:
                    if key not in bad or g['chunks'].index(c) < bad[key][2]:
                        bad[key] = (e, g, g['chunks'].index(c))
            for key, (e, g, idx) in bad.items():
                # the whole file is held back: every chunk of it in this group stays local
                first = min([idx] + [g['chunks'].index(c) for k, _, gg, c, _ in group if k == key and gg is g])
                self.rollback(e, g, first, 'egress')
                hold(self.cfg, e, 'refused:egress')
                alert(self.cfg, 'egress-held', 'file %s held: a chunk path or sidecar failed the egress gate'
                      % sha12(key))
                self.mark_manifest(key)
                self.egress_held += 1
            group = [it for it in group if it[0] not in bad]
            files = {p: d for p, d in files.items()
                     if any(p in (it[3]['path'], it[3]['path'] + '.meta.json') for it in group)}
            if not group:
                self.save(force=True)
                return
        commit, collisions, _ = publish_tree(self.cfg, repo, files, message, journal=self.journal,
                                             deadline=self.deadline)
        bad = set()
        for p in collisions:
            bad.add(p[:-len('.meta.json')] if p.endswith('.meta.json') else p)
        done = []
        for key, e, g, c, _ in group:
            if c['path'] in bad:
                self.collisions += 1
                c['status'] = 'collision'
                hold(self.cfg, e, 'collision')
                alert(self.cfg, 'collision', 'shard path %s exists with different bytes; refusing to overwrite'
                      % sha12(c['path']))
                self.mark_manifest(key)
                continue
            done.append((c['path'], c['blob']))
        if commit:
            self.journal.pushed(repo, done, commit)
        for key, e, g, c, _ in group:
            if c['status'] != 'staged':
                continue
            c['status'] = 'pushed'
            c['commit'] = commit
            self.finish_pushed(e, c)
            self.chunks_pushed += 1
            self.bytes_pushed += c['zbytes']
        if commit:
            self.shard_commits[repo] = commit
        self.save(force=True)
        crash_point(self.cfg, 'after_state_pushed')
        for key, e, g, c, _ in group:
            if c['status'] == 'pushed':
                self.drop_outbox(c)

    def push_catalog(self):
        cfg = self.cfg
        files = catalog_files(cfg, self.st, self.whole_final())
        snap = self.remote.snapshot()
        files.update(self.remote.attestation_files(
            [CATALOG] + [x['repo'] for x in self.st['shards']] + ledger_repos(snap)
            + [p[len('repo-checks/'):-5] for p in snap if p.startswith('repo-checks/')]))
        if self.st.get('catalog_commit') is None:
            self.guard_lost_state(files)
        message = 'catalog update from %s' % cfg.host
        files, dropped = egress_filter(cfg, CATALOG, files, message)
        if dropped:
            # the entry stays local; its file is listed by path sha12 only, and nothing secret-shaped leaves
            self.catalog_withheld += len(dropped)
            alert(cfg, 'catalog-withheld', '%d catalog item(s) withheld at the egress gate' % len(dropped))
            self.notes.append('catalog items withheld at the egress gate: %d' % len(dropped))
        commit, _, _ = publish_tree(cfg, CATALOG, files, message, deadline=self.deadline, overwrite=True)
        crash_point(cfg, 'after_catalog_push')
        self.st['catalog_dirty'] = False
        self.st['manifest_dirty'] = []
        if commit:
            self.st['catalog_commit'] = commit
            self.catalog_commit = commit
        self.save(force=True)

    def guard_lost_state(self, files):
        """Refuse to overwrite a host's catalog index with a smaller view (state.json lost or replaced)."""
        tr = TmpRepo(self.cfg, CATALOG)
        try:
            tr.fetch_tip()
            oid = tr.entries.get('index/%s.jsonl' % self.cfg.host)
            if not oid:
                return
            remote = {json.loads(x).get('path') for x in tr.blob(oid).splitlines() if x.strip()}
        finally:
            tr.close()
        mine = {json.loads(x).get('path') for x in files['index/%s.jsonl' % self.cfg.host].splitlines() if x.strip()}
        if remote - mine:
            raise Refused('catalog lists %d chunk(s) for host %s that local state does not know; local state looks '
                          'lost: restore state.json or rebuild with reindex before syncing' % (len(remote - mine),
                                                                                            self.cfg.host))

    def whole_final(self):
        for (key, gen), h in self.whole.items():
            e = self.st['files'].get(key)
            if not e:
                continue
            for g in e['gens']:
                if g['gen'] == gen and all(c['status'] == 'pushed' for c in g['chunks']):
                    g['whole_sha256'] = h.hexdigest()
                    g['whole_sha256_pending'] = False
        return None


def catalog_files(cfg, st, _unused=None):
    files = {}
    try:
        with open(README_SRC, 'rb') as f:
            files['README.md'] = f.read()
    except OSError:
        raise Refused('catalog README source missing (install harness/hooks/transcripts_catalog_README.md beside transcripts.py)')
    files['shards/%s.json' % cfg.host] = jdump({'schema': SCHEMA, 'host': cfg.host, 'shards': st['shards']}) + b'\n'
    files['index/%s.jsonl' % cfg.host] = b''.join(jdump(r) + b'\n' for r in index_rows(cfg, st))
    for key in st['manifest_dirty'] if st.get('catalog_commit') else list(st['files'].keys()):
        e = st['files'].get(key)
        label, _, rel = key.partition('/')
        mpath = 'manifests/%s/%s/%s.json' % (cfg.host, safe_comp(label), '/'.join(safe_comp(p) for p in rel.split('/')))
        if e is None:
            continue
        if e.get('held') and not any(c['status'] == 'pushed' for g in e['gens'] for c in g['chunks']):
            continue  # C11: a held file with nothing archived gets no manifest; its hold shows locally only
        files[mpath] = jdump(manifest_of(cfg, key, e)) + b'\n'
    for key in st['manifest_dirty']:
        e = st['files'].get(key)
        if e is None:  # moved away: leave a pointer manifest
            label, _, rel = key.partition('/')
            mpath = 'manifests/%s/%s/%s.json' % (cfg.host, safe_comp(label), '/'.join(safe_comp(p) for p in rel.split('/')))
            dest = next((k for k, v in st['files'].items() if v.get('moved_from') == key), None)
            files[mpath] = jdump({'schema': SCHEMA, 'host': cfg.host, 'source': label, 'relpath': rel,
                                  'moved_to': dest}) + b'\n'
    return files


def manifest_of(cfg, key, e):
    gens = []
    for g in e['gens']:
        pushed = [c for c in g['chunks'] if c['status'] == 'pushed']
        gens.append({'gen': g['gen'], 'archived_offset': pushed[-1]['src'][1] if pushed else 0,
                     'chunks': [{'shard': c['shard'], 'path': c['path'], 'commit': c['commit'], 'sha256': c['sha256'],
                                 'zsha256': c['zsha256'], 'src_sha256': c['src_sha256'], 'blob': c['blob'],
                                 'seq': c['seq'], 'src_range': c['src']} for c in pushed],
                     'chain_sha256': pushed[-1]['chain_sha256'] if pushed else None,
                     'whole_sha256': g.get('whole_sha256'),
                     'whole_sha256_pending': bool(g.get('whole_sha256_pending', True))})
    s = e.get('stat') or [0, 0, 0, 0]
    g = e['gens'][-1] if e['gens'] else None
    archived = gens[-1]['archived_offset'] if gens else 0
    omitted = []
    for gg in e['gens']:
        for c in gg['chunks']:
            if c['status'] == 'pushed' and c.get('omitted'):
                omitted.append({'gen': gg['gen'], 'chunk': c['name'], 'count': c['omitted']})
    return {'schema': SCHEMA, 'host': cfg.host, 'source': e['label'], 'relpath': e['relpath'],
            'source_path': os.path.join(cfg.sources.get(e['label'], ''), e['relpath']), 'session': e['session'],
            'parent': e.get('parent'), 'tool': e['tool'], 'size': s[0], 'mtime_ns': s[1], 'inode': s[3],
            'current_gen': g['gen'] if g else None, 'generations': gens,
            'chain_sha256': gens[-1]['chain_sha256'] if gens else None,
            'whole_sha256': gens[-1]['whole_sha256'] if gens else None,
            'whole_sha256_pending': gens[-1]['whole_sha256_pending'] if gens else True,
            'fully_archived': bool(gens) and archived == s[0] and not e.get('pending_since') and not e.get('held'),
            'held': e.get('held'), 'missing': bool(e.get('missing')), 'moved_from': e.get('moved_from'),
            'omitted_chunks': omitted}


INDEX_FIELDS = ('host', 'tool', 'source', 'relpath', 'session', 'parent', 'project', 'models', 'gen', 'seq', 'name',
                'sha256', 'zsha256', 'bytes', 'zbytes', 'records', 'first_ts', 'last_ts', 'ts_source', 'mentions',
                'chain_sha256', 'line_start', 'src_range')


def row_from_sidecar(meta, shard, commit):
    row = {'schema': SCHEMA}
    for k in INDEX_FIELDS:
        row[k] = meta.get(k)
    row['omitted'] = len(meta.get('omitted') or [])
    row['shard'] = shard
    row['path'] = meta.get('path')
    row['commit'] = commit
    return row


def index_rows(cfg, st):
    rows = []
    for key, e in st['files'].items():
        for g in e['gens']:
            for c in g['chunks']:
                if c['status'] != 'pushed':
                    continue
                meta = read_json(os.path.join(cfg.p('meta'), c['path'] + '.meta.json'))
                if meta is None:
                    raise Refused('sidecar copy missing for chunk %s; run reindex --from-sidecars' % sha12(c['path']))
                rows.append(row_from_sidecar(meta, c['shard'], c['commit']))
    rows.sort(key=lambda r: (r['source'], r['relpath'], r['gen'], r['seq']))
    return rows


# ----------------------------------------------------------------------------------------------------------
# Receipts and check
# ----------------------------------------------------------------------------------------------------------

def backlog_of(cfg, st):
    """Work left: visits cut short (stat unset), unsealed deltas (pending_since) and files not yet visited.
    A file whose only unarchived bytes are a partial last line is not backlog."""
    files = 0
    nbytes = 0
    old = 0
    now = time.time()
    for e in st['files'].values():
        if e.get('missing') or e.get('held'):
            continue
        g = e['gens'][-1] if e['gens'] else None
        off = g['offset'] if g else 0
        ps = parse_iso(e.get('pending_since'))
        if e.get('stat') is None or ps:
            try:
                size = os.lstat(os.path.join(cfg.sources.get(e['label'], '/nonexistent'), e['relpath'])).st_size
            except OSError:
                continue
            if size > off:
                files += 1
                nbytes += size - off
        if ps and now - ps > 7200:
            old += 1
    un = st.get('unvisited') or {}
    files += un.get('files', 0)
    nbytes += un.get('bytes', 0)
    return {'files': files, 'bytes': nbytes, 'pending_over_2h': old}


def held_of(st):
    out = []
    for key, e in st['files'].items():
        if e.get('held'):
            h = e['held']
            out.append({'source': e['label'], 'path_sha12': sha12(key), 'reason': h.get('reason'),
                        'line': h.get('line'), 'since': h.get('since'), 'attempts': h.get('attempts'),
                        'retry_at': h.get('retry_at')})
    return out


def incidents_of(st):
    """Never-retriable causes recorded as record-level omissions instead of holds, over every archived chunk."""
    oversize = 0
    for e in st['files'].values():
        for g in e['gens']:
            for c in g['chunks']:
                oversize += c.get('oversize') or 0
    return {'oversize_records': oversize}


def write_receipt(cfg, run=None, status=None, error=None, checkpoint=None):
    st = run.st if run else load_state(cfg)
    by_kind = {}
    if run:
        for _, k in run.omitted:
            by_kind[k] = by_kind.get(k, 0) + 1
    status = status or (run.status if run else 'failed')
    ok = status == 'ok'
    rec = {
        'schema': SCHEMA, 'host': cfg.host, 'checkpoint': checkpoint or (run.checkpoint if run else None),
        'served_checkpoints': sorted(run.served) if run else [], 'started_at': run.started_at if run else now_iso(),
        'finished_at': now_iso(), 'ok': ok, 'status': status,
        'files_scanned': run.files_scanned if run else 0, 'files_changed': run.files_changed if run else 0,
        'chunks_staged': run.chunks_staged if run else 0, 'chunks_pushed': run.chunks_pushed if run else 0,
        'bytes_pushed': run.bytes_pushed if run else 0, 'held': held_of(st), 'backlog': backlog_of(cfg, st),
        'shard_commits': run.shard_commits if run else {}, 'catalog_commit': run.catalog_commit if run else None,
        'omitted': {'total': len(run.omitted) if run else 0, 'by_kind': by_kind,
                    'records_processed': run.records if run else 0},
        'incidents': incidents_of(st),
        'collisions': run.collisions if run else 0,
        'egress': {'egress_held_files': run.egress_held if run else 0,
                   'scanner_held_files': run.scanner_held if run else 0,
                   'catalog_withheld': run.catalog_withheld if run else 0,
                   'scanner': 'gitleaks %s + pass 2' % GITLEAKS_VERSION},
        'last_progress_at': st.get('last_progress_at') or st.get('created_at'),
        'killswitch': os.path.exists(cfg.p('killswitch.json')), 'notes': run.notes if run else [],
        'error': error or (run.refused if run else None) or ((run.disk_low or '; '.join(run.errors)) if run else None)
        or None,
    }
    atomic_write(cfg.p('receipts', 'last.json'), jdump(rec) + b'\n')
    if ok:
        atomic_write(cfg.p('receipts', 'last-ok.json'), jdump(rec) + b'\n')
    return rec


def check(cfg, max_age_min=60):
    last = read_json(cfg.p('receipts', 'last.json'))
    lastok = read_json(cfg.p('receipts', 'last-ok.json'))
    reasons = []
    code = 0
    held = {'count': 0, 'by_reason': {}}
    ks = read_json(cfg.p('killswitch.json'))
    if ks:
        reasons.append('killswitch kind=%s' % ks.get('kind'))
        code = 2
    if last:
        if last.get('status') in ('failed', 'omission-cap', 'disk-low', 'refused', 'killswitch'):
            reasons.append(last['status'] + ((': ' + last['error']) if last.get('error') else ''))
            code = 2
        for h in last.get('held') or []:
            reason = str(h.get('reason') or 'unknown')
            held['by_reason'][reason] = held['by_reason'].get(reason, 0) + 1
        held['count'] = sum(held['by_reason'].values())
        if held['count'] or last.get('status') == 'held':
            # gate F1: any held file is a failed check, with the counts by reason
            reasons.append('held=%d (%s)' % (held['count'], ', '.join(
                '%s=%d' % kv for kv in sorted(held['by_reason'].items()))))
            code = 2
        bl = last.get('backlog') or {}
        if bl.get('files'):
            reasons.append('backlog files=%d bytes=%d' % (bl['files'], bl.get('bytes', 0)))
            lp = parse_iso(last.get('last_progress_at'))
            if lp is None or time.time() - lp > 86400:
                reasons.append('no-progress-24h')
                code = 2
    age = None
    if lastok:
        t = parse_iso(lastok.get('finished_at'))
        age = (time.time() - t) / 60.0 if t else None
    if last and last.get('status') == 'unconfigured':
        reasons.insert(0, 'unconfigured' + ((': ' + last['error']) if last.get('error') else ''))
        code = 3
    elif not lastok or age is None:
        reasons.insert(0, 'never-ok')
        code = 3
    elif age > max_age_min and code < 2:
        reasons.insert(0, 'stale age_min=%d' % int(age))
        code = 1
    elif age > max_age_min:
        reasons.insert(0, 'stale age_min=%d' % int(age))
    status = {0: 'ok', 1: 'stale', 2: 'failed', 3: 'never-ok'}[code]
    if code == 3 and last and last.get('status') == 'unconfigured':
        status = 'unconfigured'
    return code, {'status': status, 'last_ok_at': lastok.get('finished_at') if lastok else None,
                  'age_min': round(age, 1) if age is not None else None, 'reasons': reasons, 'exit': code,
                  'held': held, 'incidents': (last or {}).get('incidents') or {'oversize_records': 0}}


# ----------------------------------------------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------------------------------------------

def max_load(cfg):
    """Backfill defers above this 1-minute load: --max-load, else the core count."""
    return getattr(cfg, 'max_load', None) or float(os.cpu_count() or 1)


def do_sync(cfg, checkpoint, budget, dry_run=False, backfill=False):
    ensure_home(cfg)
    if dry_run:
        return dry(cfg)
    lock = Lock(cfg)
    if not lock.try_acquire():
        if checkpoint in CHECKPOINTS:
            drop_request(cfg, checkpoint)
        print('skipped: locked (request queued)' if checkpoint in CHECKPOINTS else 'skipped: locked')
        return 0
    try:
        take_requests(cfg, reap_only=True)
        if backfill and not cfg.ignore_load:
            load = os.getloadavg()[0]
            if load > max_load(cfg):
                write_receipt(cfg, None, status='deferred', error='deferred: load %.1f' % load, checkpoint='backfill')
                print('deferred: load')
                return 0
        run = Run(cfg, checkpoint, budget)
        try:
            zstd_bin()
            sync_body(run, backfill)
        except Refused as ex:
            run.status = 'failed'
            run.errors.append(str(ex))
        except GitError as ex:
            run.status = 'failed'
            run.errors.append(str(ex))
        except subprocess.TimeoutExpired as ex:
            run.status = 'failed'
            run.errors.append('budget exhausted' if ex.cmd == 'budget' else 'child process timeout')
        except Exception as ex:  # noqa: BLE001 - always leave a receipt; the class name never holds a value
            run.status = 'failed'
            run.errors.append('internal error: %s' % type(ex).__name__)
        finally:
            _DEADLINE[0] = None
            try:
                save_state(cfg, run.st)
            except OSError:
                pass
        served = take_requests(cfg)
        run.served |= served
        rec = write_receipt(cfg, run)
        refresh_sqlite(cfg, run.st)
        print(json.dumps({'status': rec['status'], 'ok': rec['ok'], 'chunks_pushed': rec['chunks_pushed'],
                          'held': len(rec['held']), 'backlog_files': rec['backlog']['files'],
                          'error': rec['error']}))
        return 0 if rec['ok'] else 2
    finally:
        lock.release()


def sync_body(run, backfill):
    cfg = run.cfg
    run.adopt_outbox()
    run.reconcile_journal()
    free_gb = shutil.disk_usage(cfg.home).free / 1e9
    if free_gb < cfg.min_free_gb:
        run.disk_low = 'disk-low free=%.1fGB floor=%.1fGB' % (free_gb, cfg.min_free_gb)
    roots = [r for r in cfg.sources.values() if os.path.isdir(r) and not os.path.islink(r)]
    if not roots:
        run.status = 'unconfigured'
        run.errors.append('unconfigured: no source root exists on this host')
        return
    if run.disk_low is None:
        process_queue(run, backfill)
        run.enforce_omission_cap()
        if run.files_scanned == 0 and not run.st['files']:
            run.status = 'unconfigured'
            run.errors.append('unconfigured: no transcript files found under any source root')
            return
    run.publish()
    if run.disk_low and run.status == 'ok':
        run.status = 'disk-low'
    if run.collisions and run.status == 'ok':
        run.status = 'failed'
        run.errors.append('collision on %d chunk(s)' % run.collisions)
    if run.errors and run.status == 'ok':
        run.status = 'failed'
    for e in run.st['files'].values():
        e.pop('retry_of', None)  # a retry that ended without a new hold released the file
    if run.catalog_withheld and run.status == 'ok':
        run.status = 'held'
    held = held_summary(run.st)
    if held['count'] and run.status == 'ok':
        # gate F1: a held file is never reported ok. The run still archived every other file; the receipt is
        # not ok, so last-ok stays stale, `check` exits 2 with the counts and deliver prepare refuses.
        run.status = 'held'
        run.notes.append('held files=%d %s' % (held['count'], ','.join(
            '%s=%d' % kv for kv in sorted(held['by_reason'].items()))))


def process_queue(run, backfill):
    cfg = run.cfg
    while True:
        found = discover(cfg)
        seen = {k for k, *_ in found}
        run.files_scanned = len(found)
        for key, e in run.st['files'].items():
            if key not in seen and not e.get('missing'):
                e['missing'] = True
                run.mark_manifest(key)
        todo = [x for x in found if run.needs_visit(run.st['files'].get(x[0]), x[4])]
        # a checkpoint sync takes the newest first; backfill takes the oldest first, so the transcripts closest to
        # Claude Code's retention cleanup (30 days after last activity) are archived first (goodqa#17119)
        todo.sort(key=(lambda x: x[4].st_mtime_ns) if backfill else (lambda x: -x[4].st_mtime_ns))
        rescan = False
        for n, (key, label, rel, path, st) in enumerate(todo):
            rest = [x for x in todo[n:] if x[0] not in run.st['files']]
            run.st['unvisited'] = {'files': len(rest), 'bytes': sum(x[4].st_size for x in rest)}
            if time.monotonic() > run.work_deadline:
                return
            if run.outbox_bytes() > cfg.outbox_cap:
                run.publish()
                if run.outbox_bytes() > cfg.outbox_cap:
                    run.errors.append('outbox over its cap; staging stopped until pushes resume')
                    return
            run.process_file(key, label, rel, path, seen)
            run.save()
            got = take_requests(cfg)
            if got:
                run.served |= got
                rescan = True  # serve the requesting checkpoint: changed files first
                break
            if backfill and not cfg.ignore_load:
                load = os.getloadavg()[0]
                if load > max_load(cfg) * 0.8:
                    time.sleep(min(2.0, max(0.0, run.work_deadline - time.monotonic())))
        if not rescan:
            run.st['unvisited'] = {'files': 0, 'bytes': 0}
            return


def dry(cfg):
    st = load_state(cfg)
    run = type('R', (), {})()
    n = 0
    for key, label, rel, path, s in discover(cfg):
        e = st['files'].get(key)
        if e is not None and not Run.needs_visit(run, e, s):
            continue
        off = e['gens'][-1]['offset'] if e and e['gens'] else 0
        print(json.dumps({'would_archive': key, 'delta_bytes': max(0, s.st_size - off)}))
        n += 1
    print(json.dumps({'dry_run': True, 'files': n}))
    return 0


def background(cfg, argv):
    ensure_home(cfg)
    lock = Lock(cfg)
    cp = None
    if '--checkpoint' in argv:
        cp = argv[argv.index('--checkpoint') + 1]
    if not lock.try_acquire():
        if cp in CHECKPOINTS:
            drop_request(cfg, cp)
        print('skipped: locked (request queued)')
        return 0
    lock.release()
    child = [a for a in argv if a != '--background']
    if '--budget-seconds' not in child:
        child += ['--budget-seconds', '600']
    pid = os.fork()
    if pid > 0:
        os.waitpid(pid, 0)
        print('started: background sync')
        return 0
    try:
        os.setsid()
        if os.fork() > 0:
            os._exit(0)
        logp = cfg.p('logs', 'sync.log')
        fd = os.open(logp, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        nul = os.open(os.devnull, os.O_RDONLY)
        os.dup2(nul, 0)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        os.execv(sys.executable, [sys.executable, os.path.abspath(__file__)] + child)
    finally:
        os._exit(1)


# -- SQLite index

def open_db(cfg):
    db = sqlite3.connect(cfg.p('index.sqlite'))
    db.execute('CREATE TABLE IF NOT EXISTS chunks (host TEXT, path TEXT, shard TEXT, commit_sha TEXT, session TEXT, '
               'parent TEXT, source TEXT, relpath TEXT, project TEXT, gen INT, seq INT, first_ts TEXT, last_ts TEXT, '
               'row TEXT, PRIMARY KEY (host, path))')
    db.execute('CREATE TABLE IF NOT EXISTS mentions (host TEXT, path TEXT, kind TEXT, value TEXT)')
    db.execute('CREATE INDEX IF NOT EXISTS m_kv ON mentions(kind, value)')
    db.execute('CREATE TABLE IF NOT EXISTS files (host TEXT, source TEXT, relpath TEXT, manifest TEXT, '
               'PRIMARY KEY (host, source, relpath))')
    return db


def db_load(db, rows, hosts=None, manifests=None):
    hosts = set(hosts or {r['host'] for r in rows})
    for h in hosts:
        db.execute('DELETE FROM chunks WHERE host=?', (h,))
        db.execute('DELETE FROM mentions WHERE host=?', (h,))
        if manifests is not None:
            db.execute('DELETE FROM files WHERE host=?', (h,))
    for r in rows:
        db.execute('INSERT OR REPLACE INTO chunks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (r['host'], r['path'], r['shard'], r['commit'], r['session'], r.get('parent'), r['source'],
                    r['relpath'], r.get('project'), r['gen'], r['seq'], r.get('first_ts'), r.get('last_ts'),
                    json.dumps(r, sort_keys=True)))
        for kind, key in (('ticket', 'tickets'), ('pr', 'prs'), ('commit', 'commits')):
            for v in ((r.get('mentions') or {}).get(key) or []):
                db.execute('INSERT INTO mentions VALUES (?,?,?,?)', (r['host'], r['path'], kind, v))
    for m in manifests or []:
        if m.get('relpath') and m.get('generations') is not None:
            db.execute('INSERT OR REPLACE INTO files VALUES (?,?,?,?)',
                       (m['host'], m['source'], m['relpath'], json.dumps(m, sort_keys=True)))
    db.commit()


def refresh_sqlite(cfg, st):
    try:
        db = open_db(cfg)
        rows = index_rows(cfg, st)
        mans = [manifest_of(cfg, k, e) for k, e in st['files'].items()]
        db_load(db, rows, hosts=[cfg.host], manifests=mans)
        db.close()
    except sqlite3.Error:
        pass


def db_rows(cfg, where='1=1', args=()):
    db = open_db(cfg)
    try:
        return [json.loads(r[0]) for r in db.execute('SELECT row FROM chunks WHERE ' + where, args)]
    finally:
        db.close()


def cmd_find(cfg, a):
    conds, args = [], []
    if a.session:
        conds.append('(session=? OR parent=?)')
        args += [a.session, a.session]
    if a.project:
        conds.append('project LIKE ?')
        args.append('%' + a.project + '%')
    if a.host:
        conds.append('host=?')
        args.append(a.host)
    if a.since:
        conds.append('last_ts >= ?')
        args.append(norm_ts(a.since) or a.since)
    if a.ticket:
        conds.append("path IN (SELECT path FROM mentions WHERE kind='ticket' AND value=?)")
        args.append(str(a.ticket).lstrip('#'))
    rows = db_rows(cfg, ' AND '.join(conds) or '1=1', args)
    groups = {}
    for r in rows:
        k = (r['host'], r['source'], r['relpath'])
        g = groups.setdefault(k, {'host': r['host'], 'source': r['source'], 'relpath': r['relpath'],
                                  'session': r['session'], 'parent': r.get('parent'), 'project': r.get('project'),
                                  'chunks': 0, 'first_ts': r.get('first_ts'), 'last_ts': r.get('last_ts'),
                                  'gens': []})
        g['chunks'] += 1
        g['first_ts'] = min(filter(None, [g['first_ts'], r.get('first_ts')]), default=None)
        g['last_ts'] = max(filter(None, [g['last_ts'], r.get('last_ts')]), default=None)
        if r['gen'] not in g['gens']:
            g['gens'].append(r['gen'])
    for g in sorted(groups.values(), key=lambda x: (x['host'], x['source'], x['relpath'])):
        print(json.dumps(g, sort_keys=True))
    if not groups:
        sys.stderr.write('no matches (run `transcripts reindex` if the local index is empty)\n')
    return 0 if groups else 1


def session_files(cfg, session):
    """{(host, source, relpath): [rows of the latest gen sorted by seq]} for one session."""
    rows = db_rows(cfg, 'session=?', (session,))
    files = {}
    for r in rows:
        files.setdefault((r['host'], r['source'], r['relpath']), []).append(r)
    out = {}
    for k, rs in files.items():
        gen = max(r['gen'] for r in rs)
        out[k] = sorted((r for r in rs if r['gen'] == gen), key=lambda r: r['seq'])
    return out


def manifest_from_db(cfg, host, source, relpath):
    db = open_db(cfg)
    try:
        r = db.execute('SELECT manifest FROM files WHERE host=? AND source=? AND relpath=?',
                       (host, source, relpath)).fetchone()
        return json.loads(r[0]) if r else None
    finally:
        db.close()


class VerifyError(Exception):
    pass


def fetch_verified(cfg, rows, readers):
    """Yield verified raw bytes per chunk, in order; raises VerifyError naming the chunk."""
    chain = ''
    prev = None
    for i, r in enumerate(rows):
        if r['seq'] != i + 1:
            raise VerifyError('chunk %s: sequence gap (expected p%05d)' % (r['name'], i + 1))
        tr = readers.get(r['shard'])
        if tr is None:
            tr = TmpRepo(cfg, r['shard'])
            tr.fetch_tip()
            readers[r['shard']] = tr
        oid = tr.entries.get(r['path'])
        if oid is None:
            raise VerifyError('chunk %s: missing from shard %s' % (r['name'], r['shard']))
        zdata = tr.blob(oid)
        if hashlib.sha256(zdata).hexdigest() != r['zsha256']:
            raise VerifyError('chunk %s: zsha256 mismatch' % r['name'])
        try:
            data = decompress(zdata)
        except ValueError:
            raise VerifyError('chunk %s: zstd decode failed' % r['name'])
        sha = hashlib.sha256(data).hexdigest()
        if sha != r['sha256']:
            raise VerifyError('chunk %s: sha256 mismatch' % r['name'])
        expect_prev = {'name': prev['name'], 'sha256': prev['sha256']} if prev else None
        meta_oid = tr.entries.get(r['path'] + '.meta.json')
        if meta_oid:
            meta = json.loads(tr.blob(meta_oid))
            if meta.get('prev') != expect_prev or meta.get('sha256') != sha:
                raise VerifyError('chunk %s: sidecar prev/sha mismatch' % r['name'])
        chain = hashlib.sha256((chain + sha).encode('ascii')).hexdigest()
        if r.get('chain_sha256') and chain != r['chain_sha256']:
            raise VerifyError('chunk %s: chain mismatch' % r['name'])
        prev = r
        yield r, data, chain


def cmd_cat(cfg, a):
    files = session_files(cfg, a.session) if not a.local else None
    if a.local:
        st = load_state(cfg)
        hits = [e for e in st['files'].values() if e['session'] == a.session]
        if not hits:
            sys.stderr.write('no local source for that session\n')
            return 1
        for e in sorted(hits, key=lambda e: (e['label'], e['relpath'])):
            path = os.path.join(cfg.sources.get(e['label'], '/nonexistent'), e['relpath'])
            try:
                f, _ = open_source(path)
            except OSError:
                sys.stderr.write('source missing: %s\n' % sha12(e['label'] + '/' + e['relpath']))
                return 1
            with f:
                shutil.copyfileobj(f, sys.stdout.buffer)
        return 0
    if not files:
        sys.stderr.write('session not in the index (run `transcripts reindex`)\n')
        return 1
    readers = {}
    try:
        for k in sorted(files):
            for r, data, _ in fetch_verified(cfg, files[k], readers):
                sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    except VerifyError as ex:
        sys.stderr.write('verify failed: %s\n' % ex)
        return 1
    finally:
        for tr in readers.values():
            tr.close()
    return 0


def cmd_recover(cfg, a):
    target = os.path.abspath(a.to)
    staging = tempfile.mkdtemp(prefix='recover-', dir=cfg.p('tmp'))
    written = []
    try:
        if a.source == 'local':
            st = load_state(cfg)
            hits = [e for e in st['files'].values() if e['session'] == a.session]
            if not hits:
                raise VerifyError('no local source for that session')
            for e in hits:
                rel = os.path.join(cfg.host, e['label'], e['relpath'])
                out = os.path.join(staging, rel)
                os.makedirs(os.path.dirname(out), exist_ok=True)
                f, _ = open_source(os.path.join(cfg.sources[e['label']], e['relpath']))
                with f, open(out, 'wb') as o:
                    shutil.copyfileobj(f, o)
                written.append(rel)
        else:
            files = session_files(cfg, a.session)
            if not files:
                raise VerifyError('session not in the index (run `transcripts reindex`)')
            readers = {}
            try:
                for (host, source, relpath), rows in sorted(files.items()):
                    rel = os.path.join(host, source, relpath)
                    out = os.path.join(staging, rel)
                    os.makedirs(os.path.dirname(out), exist_ok=True)
                    whole = hashlib.sha256()
                    last_chain = None
                    with open(out, 'wb') as o:
                        for r, data, chain in fetch_verified(cfg, rows, readers):
                            o.write(data)
                            whole.update(data)
                            last_chain = chain
                    man = manifest_from_db(cfg, host, source, relpath)
                    if man:
                        g = next((x for x in man['generations'] if x['gen'] == rows[0]['gen']), None)
                        if g:
                            if len(g['chunks']) != len(rows):
                                raise VerifyError('%s: manifest lists %d chunks, index %d' % (
                                    rows[0]['name'], len(g['chunks']), len(rows)))
                            if g.get('chain_sha256') and g['chain_sha256'] != last_chain:
                                raise VerifyError('%s: manifest chain mismatch' % rows[-1]['name'])
                            if g.get('whole_sha256') and g['whole_sha256'] != whole.hexdigest():
                                raise VerifyError('%s: whole_sha256 mismatch' % rows[-1]['name'])
                    written.append(rel)
            finally:
                for tr in readers.values():
                    tr.close()
        for rel in written:
            if os.path.exists(os.path.join(target, rel)):
                raise VerifyError('target file exists: %s' % rel)
        for rel in written:
            dst = os.path.join(target, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.move(os.path.join(staging, rel), dst)
        print(json.dumps({'recovered': written, 'to': target, 'from': a.source, 'truth': RECOVERY_TRUTH}))
        return 0
    except (VerifyError, OSError, GitError) as ex:
        sys.stderr.write('recover failed, nothing written: %s\n' % ex)
        return 1
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def fetch_catalog(cfg):
    """Full depth-1 fetch of the small catalog repo -> {path: bytes}."""
    tr = TmpRepo(cfg, CATALOG)
    try:
        if not tr.fetch_tip():
            return {}
        return {p: tr.blob(oid) for p, oid in tr.entries.items()}
    finally:
        tr.close()


def cmd_reindex(cfg, a):
    ensure_home(cfg)
    if a.from_sidecars:
        cat = fetch_catalog(cfg)
        repos = []
        for p, b in cat.items():
            if p.startswith('shards/'):
                repos += [s['repo'] for s in json.loads(b).get('shards', [])]
        if not repos:  # catalog unreachable or empty: fall back to the local shard ledger
            repos = [s['repo'] for s in load_state(cfg)['shards']]
        rows = rows_from_sidecars(cfg, repos)
        db = open_db(cfg)
        db_load(db, rows, hosts={r['host'] for r in rows})
        db.close()
        print(json.dumps({'reindexed_from': 'sidecars', 'rows': len(rows), 'repos': len(repos)}))
        return 0
    cat = fetch_catalog(cfg)
    rows, mans = [], []
    hosts = set()
    for p, b in sorted(cat.items()):
        if p.startswith('index/') and p.endswith('.jsonl'):
            hosts.add(p[len('index/'):-len('.jsonl')])
            rows += [json.loads(x) for x in b.splitlines() if x.strip()]
        elif p.startswith('manifests/'):
            mans.append(json.loads(b))
    db = open_db(cfg)
    db_load(db, rows, hosts=hosts, manifests=mans)
    db.close()
    print(json.dumps({'reindexed_from': 'catalog', 'rows': len(rows), 'hosts': sorted(hosts)}))
    return 0


def rows_from_sidecars(cfg, repos):
    rows = []
    for repo in repos:
        tr = TmpRepo(cfg, repo)
        try:
            if not tr.ls_remote():
                continue
            git(cfg, ['fetch', '-q', '--filter=blob:none', 'origin', 'refs/heads/main:refs/heads/main'], cwd=tr.dir,
                timeout=600)
            added = {}
            log = git(cfg, ['log', '--reverse', '--raw', '--no-renames', '--diff-filter=A', '--format=C %H',
                            'refs/heads/main'], cwd=tr.dir).stdout.decode('utf-8', 'surrogateescape')
            commit = None
            for line in log.splitlines():
                if line.startswith('C '):
                    commit = line[2:].strip()
                elif line.startswith(':') and '\t' in line:
                    path = line.split('\t', 1)[1]
                    added.setdefault(path, commit)
            ents = tr.ls_tree('refs/heads/main')
            for path, oid in ents.items():
                if not path.endswith('.meta.json'):
                    continue
                meta = json.loads(tr.blob(oid))
                rows.append(row_from_sidecar(meta, repo, added.get(meta.get('path'))))
        finally:
            tr.close()
    rows.sort(key=lambda r: (r['host'], r['source'], r['relpath'], r['gen'], r['seq']))
    return rows


def cmd_verify(cfg, a):
    ensure_home(cfg)
    if a.rescan:
        return verify_rescan(cfg, a.kind)
    lock = Lock(cfg)
    if (a.rehash or a.against_source) and not lock.try_acquire():
        print('skipped: locked')
        return 0
    try:
        st = load_state(cfg)
        problems = []
        if a.against_source:
            n = 0
            for key, e in st['files'].items():
                g = cur_gen(e)
                if not g['chunks']:
                    continue
                try:
                    f, _ = open_source(os.path.join(cfg.sources.get(e['label'], '/nonexistent'), e['relpath']))
                except OSError:
                    continue
                with f:
                    for c in g['chunks']:
                        h, full = hash_range(f, c['src'][0], c['src'][1])
                        if not full or h != c['src_sha256']:
                            e['force_new_gen'] = True
                            n += 1
                            break
            save_state(cfg, st)
            print(json.dumps({'against_source': True, 'new_generations_scheduled': n}))
            return 0
        by_repo = {}
        for key, e in st['files'].items():
            for g in e['gens']:
                for c in g['chunks']:
                    if c['status'] == 'pushed':
                        by_repo.setdefault(c['shard'], []).append((key, e, g, c))
        orphans = 0
        for repo, items in sorted(by_repo.items()):
            tr = TmpRepo(cfg, repo)
            try:
                tr.fetch_tip()
                known = set()
                for key, e, g, c in items:
                    known |= {c['path'], c['path'] + '.meta.json'}
                    have = tr.entries.get(c['path'])
                    if have is None:
                        problems.append('chunk %s: missing from %s' % (c['name'], repo))
                    elif have != c['blob']:
                        problems.append('chunk %s: blob mismatch in %s' % (c['name'], repo))
                    elif c.get('meta_blob') and tr.entries.get(c['path'] + '.meta.json') != c['meta_blob']:
                        problems.append('chunk %s: sidecar mismatch in %s' % (c['name'], repo))
                for p in tr.entries:
                    if p.startswith(cfg.host + '/') and p not in known:
                        orphans += 1
            finally:
                tr.close()
        if a.rehash:
            readers = {}
            try:
                for key, e in st['files'].items():
                    for g in e['gens']:
                        pushed = [c for c in g['chunks'] if c['status'] == 'pushed']
                        if not pushed or len(pushed) != len(g['chunks']) or not g.get('whole_sha256_pending', True):
                            continue
                        rows = [{'seq': c['seq'], 'name': c['name'], 'shard': c['shard'], 'path': c['path'],
                                 'zsha256': c['zsha256'], 'sha256': c['sha256'], 'chain_sha256': c['chain_sha256']}
                                for c in pushed]
                        h = hashlib.sha256()
                        try:
                            for _, data, _ in fetch_verified(cfg, rows, readers):
                                h.update(data)
                        except VerifyError as ex:
                            problems.append(str(ex))
                            continue
                        g['whole_sha256'] = h.hexdigest()
                        g['whole_sha256_pending'] = False
                        if key not in st['manifest_dirty']:
                            st['manifest_dirty'].append(key)
                        st['catalog_dirty'] = True
            finally:
                for tr in readers.values():
                    tr.close()
            save_state(cfg, st)
        print(json.dumps({'ok': not problems, 'problems': problems, 'orphans': orphans}))
        return 1 if problems else 0
    finally:
        lock.release()


def verify_rescan(cfg, kind):
    tr_mod = redact_mod()
    cat = fetch_catalog(cfg)
    repos = []
    for p, b in sorted(cat.items()):
        if p.startswith('shards/'):
            repos += [s['repo'] for s in json.loads(b).get('shards', [])]
    for s in load_state(cfg)['shards']:
        if s['repo'] not in repos:
            repos.append(s['repo'])
    findings = []
    scanned = 0
    for repo in repos:
        tr = TmpRepo(cfg, repo)
        try:
            if not tr.fetch_tip():
                continue
            for path, oid in sorted(tr.entries.items()):
                if path.endswith('.zst'):
                    try:
                        data = decompress(tr.blob(oid))
                    except ValueError:
                        findings.append({'repo': repo, 'path_sha12': sha12(path), 'path': path, 'line': None,
                                         'kind': 'undecodable'})
                        continue
                elif path.endswith('.meta.json'):
                    data = tr.blob(oid)
                else:
                    continue
                scanned += 1
                for k, line in tr_mod.verify_bytes(data):
                    if kind is None or k == kind:
                        findings.append({'repo': repo, 'path': path, 'line': line, 'kind': k})
        finally:
            tr.close()
    ks = read_json(cfg.p('killswitch.json'))
    cleared = False
    catalog_cleared = False
    if not findings and ks and (kind is None or ks.get('kind') == kind):
        os.unlink(cfg.p('killswitch.json'))
        cleared = True
    ipath = incident_path(kind) if kind else None
    if not findings and ipath and ipath in cat:
        try:
            rec = json.loads(cat[ipath])
        except ValueError:
            rec = {}
        if not rec.get('cleared'):
            rec.update({'cleared': True, 'cleared_at': now_iso(), 'cleared_by': cfg.host,
                        'repos_scanned': len(repos), 'files_scanned': scanned})
            remote = Remote(cfg)
            remote.ensure(CATALOG)
            remote.check(CATALOG)
            publish_tree(cfg, CATALOG, {ipath: jdump(rec) + b'\n'}, 'incident %s cleared by clean rescan from %s'
                         % (safe_comp(kind), cfg.host), overwrite=True)
            catalog_cleared = True
    print(json.dumps({'rescan': True, 'kind': kind, 'repos': len(repos), 'files_scanned': scanned,
                      'findings': findings, 'killswitch_cleared': cleared, 'catalog_incident_cleared': catalog_cleared}))
    return 1 if findings else 0


def cmd_incident(cfg, a):
    ensure_home(cfg)
    rec = {'kind': a.kind, 'shard': a.shard, 'at': now_iso(), 'host': cfg.host,
           'note': 'all pushes on this host are stopped; follow the runbook in docs/transcripts-archive.md'}
    atomic_write(cfg.p('killswitch.json'), jdump(rec) + b'\n')
    alert(cfg, 'incident', 'kill switch set kind=%s shard=%s; every push on this host is stopped' % (a.kind, a.shard))
    # every host's publisher reads incident/KIND.json from the catalog before pushing, so all hosts stop
    out = dict(rec, cleared=False, note='every host refuses pushes until a clean verify --rescan --kind clears this')
    try:
        remote = Remote(cfg)
        remote.ensure(CATALOG)
        remote.check(CATALOG)
        publish_tree(cfg, CATALOG, {incident_path(a.kind): jdump(out) + b'\n'},
                     'incident %s raised on %s' % (safe_comp(a.kind), cfg.host), overwrite=True)
        rec['catalog'] = 'pushed'
    except (Refused, GitError, OSError, subprocess.SubprocessError) as ex:
        rec['catalog'] = 'failed'
        alert(cfg, 'incident-catalog', 'incident file not pushed to the catalog (%s); the local kill switch is set'
              % (str(ex)[:120] if isinstance(ex, (Refused, GitError)) else type(ex).__name__))
    print(json.dumps(rec))
    return 0 if rec['catalog'] == 'pushed' else 2


def incident_path(kind):
    return 'incident/%s.json' % safe_comp(kind)[:80]


def open_incidents(cfg, remote=None):
    """Kinds with an uncleared incident file in the catalog (raised by any host)."""
    snap = remote.snapshot() if remote else catalog_snapshot(cfg)
    kinds = []
    for path, raw in sorted(snap.items()):
        if path.startswith('incident/') and path.endswith('.json'):
            try:
                rec = json.loads(raw)
            except ValueError:
                rec = {}
            if not rec.get('cleared'):
                kinds.append(str(rec.get('kind') or path[len('incident/'):-5]))
    return kinds


def cmd_ensure_repos(cfg, a):
    """gh host: pre-create another host's private shard repos (p1..pN per month) and attest them."""
    ensure_home(cfg)
    if not cfg.has_gh:
        raise Refused('ensure-repos needs an authenticated gh host')
    host = _SAFE.sub('_', a.host)[:40]
    months = [m.strip() for m in a.months.split(',') if m.strip()]
    for m in months:
        if not re.fullmatch(r'\d{4}-\d{2}', m):
            raise Refused('months must look like YYYY-MM[,YYYY-MM]')
    remote = Remote(cfg)
    repos = [CATALOG] + ['agent-transcripts-%s-%s-p%d' % (host, m, n) for m in months for n in range(1, a.parts + 1)]
    for repo in repos:
        remote.ensure(repo)
        remote.check(repo)
    files = {'repo-checks/%s.json' % r: jdump(remote.attest_record(r)) + b'\n' for r in repos}
    commit, _, _ = publish_tree(cfg, CATALOG, files, 'attest %d repo(s) for %s' % (len(repos), host), overwrite=True)
    print(json.dumps({'ensured': repos, 'attested': len(files), 'catalog_commit': commit}))
    return 0


def cmd_status(cfg, a):
    st = load_state(cfg)
    chunks = pushed = staged = 0
    omitted = 0
    for e in st['files'].values():
        for g in e['gens']:
            for c in g['chunks']:
                chunks += 1
                pushed += c['status'] == 'pushed'
                staged += c['status'] == 'staged'
                omitted += c.get('omitted') or 0
    waivers = 0
    try:
        with open(cfg.p('waivers.jsonl'), 'rb') as f:
            waivers = sum(1 for line in f if line.strip())
    except OSError:
        pass
    code, chk = check(cfg)
    out = {'host': cfg.host, 'files': len(st['files']), 'chunks': chunks, 'pushed': pushed, 'staged': staged,
           'omitted_records': omitted, 'incidents': incidents_of(st), 'backlog': backlog_of(cfg, st),
           'held': held_of(st),
           'shards': st['shards'], 'catalog_commit': st.get('catalog_commit'),
           'killswitch': read_json(cfg.p('killswitch.json')), 'waivers': waivers, 'check': chk,
           'recovery_truth': RECOVERY_TRUTH}
    print(json.dumps(out, indent=1, sort_keys=True))
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog='transcripts', description=__doc__.split('\n\n')[0] + '\n\n' + RECOVERY_TRUTH,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd')
    s = sub.add_parser('sync', help='archive changed transcripts now')
    s.add_argument('--checkpoint', required=True, choices=CHECKPOINTS)
    s.add_argument('--budget-seconds', type=int, default=None)
    s.add_argument('--background', action='store_true')
    s.add_argument('--dry-run', action='store_true')
    b = sub.add_parser('backfill', help='resumable full-history archive (scheduler)')
    b.add_argument('--budget-seconds', type=int, default=1800)
    b.add_argument('--max-load', type=float, default=None,
                   help='defer while the 1-minute load is over this (default: the core count)')
    c = sub.add_parser('check', help='exit 0 ok, 1 stale, 2 failed/cap/held/disk-low/killswitch, 3 never-ok')
    c.add_argument('--max-age-min', type=int, default=60)
    c.add_argument('--json', action='store_true')
    sub.add_parser('status')
    f = sub.add_parser('find')
    f.add_argument('--session')
    f.add_argument('--ticket')
    f.add_argument('--project')
    f.add_argument('--since')
    f.add_argument('--host')
    ca = sub.add_parser('cat', help='stream a session (redacted archive; --local reads the source)')
    ca.add_argument('session')
    ca.add_argument('--local', action='store_true')
    r = sub.add_parser('recover', help=RECOVERY_TRUTH)
    r.add_argument('session')
    r.add_argument('--to', required=True)
    r.add_argument('--from', dest='source', choices=('git', 'local'), default='git')
    v = sub.add_parser('verify')
    v.add_argument('--rehash', action='store_true')
    v.add_argument('--against-source', action='store_true')
    v.add_argument('--rescan', action='store_true')
    v.add_argument('--kind')
    ri = sub.add_parser('reindex')
    ri.add_argument('--from-sidecars', action='store_true')
    er = sub.add_parser('ensure-repos', help='gh host: pre-create and attest private shard repos for a host')
    er.add_argument('--host', required=True)
    er.add_argument('--months', required=True)
    er.add_argument('--parts', type=int, default=1)
    i = sub.add_parser('incident', help='host-wide kill switch: stops every push on this host')
    i.add_argument('--kind', required=True)
    i.add_argument('--shard')
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    p = build_parser()
    a = p.parse_args(argv)
    if not a.cmd:
        p.print_help()
        return 2
    if sys.platform.startswith('win'):
        sys.stderr.write('transcripts: Windows is not supported yet (no verified lock or zstd path)\n')
        return 2
    try:
        cfg = Cfg()
    except Refused as ex:
        sys.stderr.write('transcripts: refused: %s\n' % ex)
        return 2
    try:
        if a.cmd == 'check':
            code, out = check(cfg, a.max_age_min)
            note = ''.join('; incident %s=%d' % kv for kv in sorted(out['incidents'].items()) if kv[1])
            print(json.dumps(out, sort_keys=True) if a.json else '%s: %s%s' % (out['status'], '; '.join(
                out['reasons']) or 'fresh ok receipt', note))
            return code
        if a.cmd == 'sync':
            if a.background and not a.dry_run:
                return background(cfg, argv)
            return do_sync(cfg, a.checkpoint, a.budget_seconds or 90, dry_run=a.dry_run)
        if a.cmd == 'backfill':
            if not cfg.ignore_load:
                try:
                    os.nice(10)
                except OSError:
                    pass
            if a.max_load is not None:
                if a.max_load <= 0:
                    raise Refused('--max-load must be positive')
                cfg.max_load = a.max_load
            return do_sync(cfg, 'backfill', a.budget_seconds, backfill=True)
        ensure_home(cfg)
        return {'status': cmd_status, 'find': cmd_find, 'cat': cmd_cat, 'recover': cmd_recover,
                'verify': cmd_verify, 'reindex': cmd_reindex, 'incident': cmd_incident,
                'ensure-repos': cmd_ensure_repos}[a.cmd](cfg, a)
    except Refused as ex:
        sys.stderr.write('transcripts: refused: %s\n' % ex)
        return 2


if __name__ == '__main__':
    sys.exit(main())
