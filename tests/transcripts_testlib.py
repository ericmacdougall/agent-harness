"""Shared fixtures for the transcripts archive tests (GoodQA #16650).

Every test runs against a temp HOME, temp source roots, a temp state dir and local bare remotes, with a
failing `gh` stub first on PATH, so a missed override can never reach real transcripts or GitHub.
Synthetic data only.
"""
import contextlib
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / 'harness' / 'hooks'
sys.path.insert(0, str(HOOKS))
import transcripts as T  # noqa: E402

SCRIPT = str(HOOKS / 'transcripts.py')
ZSTD_DIR = os.path.dirname(shutil.which('zstd') or '/opt/homebrew/bin/zstd')
GIT_DIR = os.path.dirname(shutil.which('git') or '/usr/bin/git')
LABELS = ('claude-projects', 'claude-wals', 'codex-sessions', 'codex-archived', 'codex-wals')
UUID1 = '11111111-2222-3333-4444-555555555555'
UUID2 = '66666666-7777-8888-9999-aaaaaaaaaaaa'
UUID3 = 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff'


class IdentityRedact:
    """Stand-in for transcript_redact: identity pass 1, clean pass 2 (test mode for AC-4)."""
    RULESET_VERSION = 'test-identity-1'
    omit_marker = None   # bytes: lines containing it are omitted
    flag_marker = None   # bytes: verify_bytes reports lines containing it
    flag_kind = 'canary'
    sleep = 0.0

    @classmethod
    def redact_line(cls, line, line_no):
        if cls.sleep:
            import time
            time.sleep(cls.sleep)
        if cls.omit_marker and cls.omit_marker in line:
            out = json.dumps({'_archive': 'omitted', 'reason': 'fakekind', 'line': line_no,
                              'src_len': len(line)}, separators=(',', ':')).encode()
            return out, {}, 'fakekind'
        return line, {}, None

    @classmethod
    def verify_bytes(cls, data):
        if not cls.flag_marker:
            return []
        return [(cls.flag_kind, n) for n, ln in enumerate(data.split(b'\n'), 1) if cls.flag_marker in ln]


def rec(i, ts=None, text=None, **extra):
    r = {'type': 'user', 'timestamp': ts or '2026-11-01T%02d:%02d:%02dZ' % ((i // 3600) % 24, (i // 60) % 60, i % 60),
         'sessionId': UUID1, 'cwd': '/work/proj', 'message': {'role': 'user', 'content': text or 'msg %d' % i}}
    r.update(extra)
    return (json.dumps(r, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


class Base(unittest.TestCase):
    identity = True

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='tx-test-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        t = Path(self.tmp)
        self.fakehome = t / 'home'
        self.home = t / 'state'
        self.remote = t / 'remote'
        self.src = t / 'src'
        self.stub = t / 'stubbin'
        for d in (self.fakehome, self.remote, self.stub):
            d.mkdir()
        self.roots = {lab: self.src / lab for lab in LABELS}
        for d in self.roots.values():
            d.mkdir(parents=True)
        gh = self.stub / 'gh'
        gh.write_text('#!/bin/sh\necho "gh stub: tests must never reach GitHub" >&2\nexit 1\n')
        gh.chmod(0o755)
        self.env = {
            'HOME': str(self.fakehome), 'TRANSCRIPTS_HOME': str(self.home),
            'TRANSCRIPTS_SOURCES': json.dumps({k: str(v) for k, v in self.roots.items()}),
            'TRANSCRIPTS_REMOTE_BASE': str(self.remote), 'TRANSCRIPTS_ALLOW_LOCAL_REMOTE': '1',
            'TRANSCRIPTS_HOST': 'testhost', 'TRANSCRIPTS_MIN_FREE_GB': '0', 'TRANSCRIPTS_IGNORE_LOAD': '1',
            'PATH': os.pathsep.join([str(self.stub), ZSTD_DIR, GIT_DIR, '/usr/bin', '/bin']),
            'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1',
        }
        # Every TRANSCRIPTS_* variable (ambient, or leaked by an earlier test) is cleared for the test and restored
        # after it, along with the keys this base sets, so no test sees another test's environment.
        saved = {k: os.environ.get(k) for k in set(self.env) | {k for k in os.environ if k.startswith('TRANSCRIPTS_')}}
        self._env_saved = saved

        def restore():
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.addCleanup(restore)
        for k in [k for k in os.environ if k.startswith('TRANSCRIPTS_')]:
            os.environ.pop(k, None)
        os.environ.update(self.env)
        orig = T.redact_mod
        self.addCleanup(setattr, T, 'redact_mod', orig)
        IdentityRedact.omit_marker = IdentityRedact.flag_marker = None
        IdentityRedact.sleep = 0.0
        IdentityRedact.RULESET_VERSION = 'test-identity-1'
        if self.identity:
            T.redact_mod = lambda: IdentityRedact

    # -- helpers
    def setenv(self, **kw):
        for k, v in kw.items():
            self._env_saved.setdefault(k, os.environ.get(k))  # restored by setUp's cleanup
            os.environ[k] = str(v)
            self.env[k] = str(v)

    def write(self, label, rel, data, mode='wb'):
        p = self.roots[label] / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, mode) as f:
            f.write(data)
        return p

    def cli(self, *args, env=None, timeout=120):
        e = dict(os.environ)
        e.update(self.env)
        if env:
            e.update(env)
        r = subprocess.run([sys.executable, SCRIPT] + list(args), capture_output=True, env=e, timeout=timeout)
        return r.returncode, r.stdout.decode(), r.stderr.decode()

    def main(self, *args):
        err = io.StringIO()
        buf = io.BytesIO()
        wrapper = io.TextIOWrapper(buf, encoding='utf-8', write_through=True)
        with contextlib.redirect_stdout(wrapper), contextlib.redirect_stderr(err):
            code = T.main(list(args))
            wrapper.flush()
        self.last_err = err.getvalue()
        return code, buf.getvalue().decode('utf-8', 'replace')

    def sync(self, cp='pr', *extra):
        code, out = self.main('sync', '--checkpoint', cp, *extra)
        return code, self.receipt()

    def receipt(self, name='last.json'):
        return T.read_json(str(self.home / 'receipts' / name))

    def state(self):
        return T.read_json(str(self.home / 'state.json'))

    def repos(self):
        return sorted(p.name[:-4] for p in self.remote.iterdir() if p.name.endswith('.git'))

    def git_remote(self, repo, *args, inp=None):
        r = subprocess.run(['git', '--git-dir', str(self.remote / (repo + '.git'))] + list(args),
                           capture_output=True, input=inp, env=dict(os.environ, **self.env))
        return r

    def tip(self, repo):
        r = self.git_remote(repo, 'rev-parse', '--verify', '-q', 'refs/heads/main')
        return r.stdout.decode().strip() or None

    def tree(self, repo):
        if not self.tip(repo):
            return {}
        out = self.git_remote(repo, 'ls-tree', '-r', 'main').stdout.decode()
        res = {}
        for line in out.splitlines():
            head, path = line.split('\t', 1)
            res[path] = head.split()[2]
        return res

    def blob(self, repo, oid):
        return self.git_remote(repo, 'cat-file', 'blob', oid).stdout

    def shard_repos(self):
        return [r for r in self.repos() if r != T.CATALOG]

    def chunks(self):
        """{path: (repo, oid)} for every chunk in every shard."""
        out = {}
        for repo in self.shard_repos():
            for p, oid in self.tree(repo).items():
                if p.endswith('.zst'):
                    out[p] = (repo, oid)
        return out

    def chunk_bytes(self, path):
        repo, oid = self.chunks()[path]
        return T.decompress(self.blob(repo, oid))

    def sidecar(self, path):
        repo, _ = self.chunks()[path]
        return json.loads(self.blob(repo, self.tree(repo)[path + '.meta.json']))

    def snapshot(self):
        snap = {}
        for dp, dns, fns in os.walk(self.src):
            snap[dp] = ('dir', sorted(dns), sorted(fns))
            for fn in fns:
                p = os.path.join(dp, fn)
                st = os.lstat(p)
                if stat.S_ISREG(st.st_mode):
                    with open(p, 'rb') as f:
                        h = hashlib.sha256(f.read()).hexdigest()
                else:
                    h = None
                snap[p] = (h, st.st_mtime_ns, st.st_size, st.st_mode)
        return snap
