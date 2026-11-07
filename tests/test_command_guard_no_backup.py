"""goodqa#14911: command_guard approve-delete --no-backup --user-source.

A user-approved deletion without a backup, for a clean pushed git working tree or a detached disk image only.
Every test builds its own temporary home, git remote and clones; nothing outside the temp tree is touched, and
commands are only judged by decide(), never run. CG_HOOKS_DIR points the suite at another implementation (for
example main before this change) to show it failing first.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('CG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))

import command_guard as cg  # noqa: E402

GIT_ENV = {'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.invalid', 'GIT_COMMITTER_NAME': 't',
           'GIT_COMMITTER_EMAIL': 't@example.invalid', 'GIT_CONFIG_NOSYSTEM': '1'}
SOURCE = 'answer:sess-1/a54d2164-40ad-4be7-bcb7-7c8125c0fc87'


def run(*args, cwd=None):
    env = dict(os.environ, **GIT_ENV)
    done = subprocess.run(list(args), cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if done.returncode != 0:
        raise AssertionError('%s failed: %s' % (args[:3], done.stderr.decode()[-300:]))
    return done.stdout.decode()


def ok_resolver_for(*paths, text='Delete, no backup (Recommended)', session='sess-1', predefined=True):
    """A resolver for an answer in `session`: one question naming `paths`, whose selected predefined option is
    `text`."""
    def resolver(source, now=None, max_age=None, home=None):
        return {'kind': 'answer', 'session': session, 'uid': source.rsplit('/', 1)[-1].lower(), 'at': time.time(),
                'text': text, 'predefined': predefined,
                'question': 'Delete %s without a backup?' % ' and '.join(str(p) for p in paths)}
    return resolver


def hook_wal(path, at):
    """A WAL with one hook-written (pretool) entry at epoch `at`, as the PreToolUse hook writes it."""
    import datetime
    stamp = datetime.datetime.fromtimestamp(at, datetime.timezone.utc).isoformat()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'a') as handle:
        handle.write(json.dumps({'at': stamp, 'event': 'pretool', 'agent_id': 'a1', 'tool': 'Bash',
                                 'tool_use_id': 'toolu_x', 'target_chars': 10}) + '\n')


ok_resolver = ok_resolver_for()


class NoBackupCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='cg-nb-')
        self.home = Path(os.path.realpath(self._tmp.name))
        self._old_home = os.environ.get('HOME')
        os.environ['HOME'] = str(self.home)
        for rel in ('.claude/projects/p/a.jsonl', '.claude/wals/s/main.jsonl', '.agent-harness/state/x.json'):
            (self.home / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.home / rel).write_text('x\n')
        self.task = self.home / '.agent-harness/work/S/T'
        self.task.mkdir(parents=True)
        self.policy = cg.load_policy(path=str(self.home / 'no-such-policy.json'))
        self.wal = str(self.home / '.claude/wals/sess-1/agent-nb.jsonl')
        hook_wal(self.wal, time.time() - 600)  # the session's hooks wrote before the user answered
        self.remote = self.home / 'remote.git'
        run('git', 'init', '-q', '--bare', str(self.remote))

    def tearDown(self):
        if self._old_home is None:
            os.environ.pop('HOME', None)
        else:
            os.environ['HOME'] = self._old_home
        self._tmp.cleanup()

    def clone(self, name='clone'):
        """A working tree under the task folder whose only commit is pushed to the bare remote."""
        path = self.task / name
        run('git', 'init', '-q', '-b', 'main', str(path))
        (path / 'README').write_text('hi\n')
        (path / 'tests').mkdir()
        (path / 'tests/fixture.jsonl').write_text('{}\n')  # tracked, committed data is not a log
        run('git', 'add', '-A', cwd=path)
        run('git', 'commit', '-q', '-m', 'one', cwd=path)
        run('git', 'remote', 'add', 'origin', str(self.remote), cwd=path)
        run('git', 'push', '-q', 'origin', 'main', cwd=path)
        run('git', 'fetch', '-q', 'origin', cwd=path)
        # "pushed" is proven only by an allowlisted network remote; ls_remote() stands in for the network
        run('git', 'remote', 'set-url', 'origin', 'https://github.com/example/nb-test.git', cwd=path)
        return path

    def ls_remote(self, url):
        """Every live head and tag sha of the bare remote (stands in for `git ls-remote <url>`)."""
        done = subprocess.run(['git', '--git-dir', str(self.remote), 'for-each-ref', '--format=%(objectname)',
                               'refs/heads', 'refs/tags'], stdout=subprocess.PIPE, check=False)
        return done.stdout.decode().split()

    def image(self, name='disk.sparseimage'):
        path = self.task / name
        path.write_bytes(b'\0' * 4096)
        return path

    def approve(self, path, **kw):
        kw.setdefault('resolver', ok_resolver_for(path))
        kw.setdefault('attached', lambda: set())
        kw.setdefault('ls_remote', self.ls_remote)
        return cg.approve_delete_no_backup(str(path), kw.pop('source', SOURCE), kw.pop('wal', self.wal),
                                           home=str(self.home), policy=self.policy, **kw)

    def approvals(self, now=None):
        return cg.Approvals(home=str(self.home), compiled=cg.Compiled(self.policy, home=str(self.home)), now=now)

    def refused(self, path, fragment=None, **kw):
        with self.assertRaises(ValueError) as caught:
            self.approve(path, **kw)
        if fragment:
            self.assertIn(fragment, str(caught.exception))


class GitTarget(NoBackupCase):
    def test_clean_pushed_tree_is_approved_once_and_only_for_that_path(self):
        path = self.clone()
        entry = self.approve(path)
        self.assertEqual((entry['kind'], entry['target']), ('no-backup', 'git'))
        a = self.approvals()
        self.assertTrue(a.covers(str(path)))
        self.assertFalse(a.covers(str(path / 'tests')))
        self.assertFalse(a.covers(str(self.task / 'other')))
        self.assertTrue(a.consume())
        self.assertFalse(self.approvals().covers(str(path)))

    def test_hook_allows_the_approved_rm_and_still_blocks_without_approval(self):
        path = self.clone()
        c = cg.Compiled(self.policy, home=str(self.home))
        cmd = 'rm -rf %s' % path
        self.assertEqual(cg.decide(cmd, c, marker=self.approvals())[0], 'block')
        self.approve(path)
        self.assertNotEqual(cg.decide(cmd, c, marker=self.approvals())[0], 'block')

    def test_changed_file_refused(self):
        path = self.clone()
        (path / 'README').write_text('changed\n')
        self.refused(path, 'untracked or ignored')

    def test_untracked_file_refused(self):
        path = self.clone()
        (path / 'notes.txt').write_text('unique work\n')
        self.refused(path, 'untracked or ignored')

    def test_ignored_file_refused(self):
        path = self.clone()
        (path / '.gitignore').write_text('*.log\n')
        run('git', 'add', '.gitignore', cwd=path)
        run('git', 'commit', '-q', '-m', 'ignore', cwd=path)
        run('git', 'push', '-q', str(self.remote), 'main', cwd=path)
        run('git', 'fetch', '-q', str(self.remote), 'main:refs/remotes/origin/main', cwd=path)
        (path / 'run.log').write_text('a log that exists nowhere else\n')
        self.refused(path, 'untracked or ignored')

    def test_unpushed_commit_refused(self):
        path = self.clone()
        (path / 'b').write_text('b\n')
        run('git', 'add', 'b', cwd=path)
        run('git', 'commit', '-q', '-m', 'local only', cwd=path)
        self.refused(path, 'unpushed')

    def test_unpushed_other_branch_refused(self):
        path = self.clone()
        run('git', 'checkout', '-q', '-b', 'side', cwd=path)
        (path / 'c').write_text('c\n')
        run('git', 'add', 'c', cwd=path)
        run('git', 'commit', '-q', '-m', 'side work', cwd=path)
        run('git', 'checkout', '-q', 'main', cwd=path)
        self.refused(path, 'unpushed')

    def test_stash_refused(self):
        path = self.clone()
        (path / 'README').write_text('stashed\n')
        run('git', 'stash', '-q', cwd=path)
        self.refused(path, 'stash')

    def test_remote_that_lacks_head_refused(self):
        path = self.clone()
        self.refused(path, 'allowlisted network remote', ls_remote=lambda url: ['0' * 40])

    def test_unreachable_remote_refused(self):
        path = self.clone()
        self.refused(path, 'allowlisted network remote', ls_remote=lambda url: None)

    def test_no_remote_refused(self):
        path = self.task / 'lonely'
        run('git', 'init', '-q', '-b', 'main', str(path))
        (path / 'a').write_text('a\n')
        run('git', 'add', 'a', cwd=path)
        run('git', 'commit', '-q', '-m', 'a', cwd=path)
        self.refused(path, 'unpushed')

    def test_subdirectory_of_a_tree_is_not_a_target(self):
        path = self.clone()
        self.refused(path / 'tests', 'only a git working tree root')

    def test_linked_worktree_refused(self):
        path = self.clone()
        run('git', 'worktree', 'add', '-q', str(self.task / 'linked'), '-b', 'lw', cwd=path)
        self.refused(path, 'linked worktrees')

    def test_change_after_approval_voids_it(self):
        path = self.clone()
        self.approve(path)
        (path / 'late.txt').write_text('new unique work\n')
        self.assertFalse(self.approvals().covers(str(path)))

    def test_new_commit_after_approval_voids_it(self):
        path = self.clone()
        self.approve(path)
        (path / 'd').write_text('d\n')
        run('git', 'add', 'd', cwd=path)
        run('git', 'commit', '-q', '-m', 'later', cwd=path)
        self.assertFalse(self.approvals().covers(str(path)))

    def test_repository_config_cannot_run_a_program(self):
        path = self.clone()
        pwned = self.home / 'PWNED'
        run('git', 'config', 'core.fsmonitor', 'touch %s; false' % pwned, cwd=path)
        try:
            self.approve(path)
        except ValueError:
            pass
        self.approvals().covers(str(path))
        self.assertFalse(pwned.exists())


class ImageTarget(NoBackupCase):
    def test_detached_image_is_approved(self):
        path = self.image()
        entry = self.approve(path)
        self.assertEqual(entry['target'], 'image')
        saved = cg._attached_images
        cg._attached_images = lambda: set()
        try:
            self.assertTrue(self.approvals().covers(str(path)))
        finally:
            cg._attached_images = saved

    def test_attached_image_refused(self):
        path = self.image()
        self.refused(path, 'attached', attached=lambda: {str(path)})

    def test_unverifiable_attach_state_refused(self):
        path = self.image()

        def broken():
            raise ValueError('cannot check whether the image is attached (hdiutil info failed)')
        self.refused(path, 'cannot check', attached=broken)

    def test_attached_after_approval_voids_it(self):
        path = self.image()
        self.approve(path)
        saved = cg._attached_images
        cg._attached_images = lambda: {str(path)}
        try:
            self.assertFalse(self.approvals().covers(str(path)))
        finally:
            cg._attached_images = saved

    def test_resized_image_voids_it(self):
        path = self.image()
        self.approve(path)
        with open(path, 'ab') as handle:
            handle.write(b'more')
        saved = cg._attached_images
        cg._attached_images = lambda: set()
        try:
            self.assertFalse(self.approvals().covers(str(path)))
        finally:
            cg._attached_images = saved

    def test_plain_file_or_folder_is_not_a_target(self):
        f = self.task / 'notes.md'
        f.write_text('x\n')
        self.refused(f, 'only a git working tree root')
        d = self.task / 'plain'
        d.mkdir()
        (d / 'x').write_text('x\n')
        self.refused(d, 'only a git working tree root')


class ProtectedAndLiteral(NoBackupCase):
    def test_logs_wals_transcripts_and_state_always_refused(self):
        for rel in ('.claude/projects/p', '.claude/projects/p/a.jsonl', '.claude/wals/s', '.claude/wals/s/main.jsonl',
                    '.agent-harness/state', '.agent-harness/state/x.json'):
            with self.subTest(rel=rel):
                self.refused(self.home / rel, 'never deleted without a verified backup')

    def test_wal_named_folder_in_the_work_tree_refused(self):
        wals = self.task / 'wals'
        wals.mkdir()
        (wals / 'main.jsonl').write_text('{}\n')
        self.refused(wals, 'never deleted without a verified backup')

    def test_harness_roots_and_ancestors_refused(self):
        for p in (self.home, self.home / '.agent-harness', self.home / '.agent-harness/work'):
            with self.subTest(p=str(p)):
                self.refused(p)

    def test_globs_variables_relative_and_symlinks_refused(self):
        path = self.clone()
        link = self.task / 'link'
        os.symlink(str(path), str(link))
        for bad in (str(self.task / 'clo*'), str(self.task) + '/$X', 'relative/clone', str(link),
                    str(self.task / 'T' / '..' / 'clone')):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    cg.approve_delete_no_backup(bad, SOURCE, self.wal, home=str(self.home), policy=self.policy,
                                                resolver=ok_resolver_for(bad), attached=lambda: set())

    def test_ttl_bounds_and_expiry(self):
        path = self.clone()
        self.refused(path, 'ttl', ttl=10 ** 6)
        entry = self.approve(path, ttl=60)
        self.assertFalse(self.approvals(now=entry['expires_at'] + 1).covers(str(path)))

    def test_wal_is_required_and_records_the_approval(self):
        path = self.clone()
        self.refused(path, '--wal is required', wal='')
        self.approve(path)
        lines = (self.home / '.agent-harness/state/log-delete-audit.jsonl').read_text().splitlines()
        approved = [json.loads(x) for x in lines if json.loads(x)['event'] == 'approved']
        self.assertEqual(approved[-1]['kind'], 'no-backup')
        self.assertEqual(approved[-1]['user_source'], SOURCE)
        self.assertIn('expires_at', approved[-1])
        self.assertTrue(Path(self.wal).exists())


class UserSource(NoBackupCase):
    def test_unresolved_source_refused(self):
        path = self.clone()

        def bad(source, now=None, max_age=None, home=None):
            raise ValueError('the user source does not resolve to a real answer turn')
        self.refused(path, 'does not resolve', resolver=bad)

    def test_real_resolver_refuses_made_up_and_malformed_sources(self):
        for source in ('answer:nosuch-session/a54d2164-40ad-4be7-bcb7-7c8125c0fc87', 'wal:/x#y', 'inferred: me',
                       'ticket:GoodQA goodqa#1', 'user:s', ''):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    cg.resolve_user_source(source, max_age=86400, home=str(self.home))

    def test_real_resolver_checks_age(self):
        path = self.image()
        uid = transcript(self.home / '.claude', 'sess-1', str(path))
        src = 'answer:sess-1/%s' % uid
        self.assertEqual(cg.resolve_user_source(src, max_age=86400, home=str(self.home))['kind'], 'answer')
        tfile = self.home / '.claude/projects/p/sess-1.jsonl'
        tfile.write_text(re.sub(r'"timestamp": "[^"]+"', '"timestamp": "2026-01-01T00:00:00.000Z"', tfile.read_text()))
        with self.assertRaises(ValueError) as caught:
            cg.resolve_user_source(src, max_age=86400, home=str(self.home))
        self.assertIn('older', str(caught.exception))

    def test_one_source_approves_a_bounded_number_of_paths(self):
        for i in range(4):
            self.approve(self.image('d%d.dmg' % i))
        self.refused(self.image('d9.dmg'), 'already approved')


class Cli(NoBackupCase):
    def cli(self, *args):
        return subprocess.run([sys.executable, str(HOOKS / 'command_guard.py'), 'approve-delete'] + list(args),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(os.environ),
                              check=False)

    def test_no_backup_flags_must_come_together(self):
        path = str(self.image())
        for args in (['--path', path, '--no-backup', '--wal', self.wal],
                     ['--path', path, '--user-source', SOURCE, '--wal', self.wal],
                     ['--path', path, '--no-backup', '--user-source', SOURCE, '--remote', 'dropbox:x', '--wal',
                      self.wal],
                     ['--path', path, '--wal', self.wal]):
            with self.subTest(args=args[2:4]):
                done = self.cli(*args)
                self.assertEqual(done.returncode, 2, done.stderr)
                self.assertIn(b'refused', done.stderr)


OPTIONS = ('Delete, no backup (Recommended)', 'Leave them')


def transcript(home, session, path_text, answer='Delete, no backup (Recommended)', uid=None, origin_ok=True,
               options=OPTIONS, questions=None, answers=None, folder_name='p', multi=False):
    """Write a real-shaped transcript with one AskUserQuestion naming `path_text` and its answer. Returns the uuid.
    `questions`/`answers` override the single question and its answer map (several-question calls)."""
    import uuid as _uuid
    uid = uid or str(_uuid.uuid4())
    use = 'toolu_%s' % _uuid.uuid4().hex[:20]
    stamp = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
    question = 'Delete %s without a backup?' % path_text
    asked = questions or [{'question': question, 'header': 'Cleanup', 'multiSelect': multi,
                           'options': [{'label': o, 'description': o} for o in options]}]
    ask = {'type': 'assistant', 'uuid': str(_uuid.uuid4()), 'timestamp': stamp, 'sessionId': session,
           'message': {'role': 'assistant', 'content': [{'type': 'tool_use', 'id': use, 'name': 'AskUserQuestion',
                                                         'input': {'questions': asked}}]}}
    reply = {'type': 'user', 'uuid': uid, 'timestamp': stamp, 'sessionId': session,
             'message': {'role': 'user', 'content': [{'type': 'tool_result', 'tool_use_id': use,
                                                      'content': 'User answered'}]},
             'toolUseResult': {'answers': answers or {question: answer}}}
    folder = Path(home) / 'projects' / folder_name
    folder.mkdir(parents=True, exist_ok=True)
    with open(folder / (session + '.jsonl'), 'a') as handle:
        handle.write(json.dumps(ask) + '\n' + json.dumps(reply) + '\n')
    return uid


class NativeReviewF1Environment(NoBackupCase):
    """F1: the source lookup cannot be pointed at a forged transcript through the caller's environment."""

    def forged(self, path):
        fake = self.home / 'fake-claude'
        uid = transcript(fake, 'sess-1', str(path))
        return fake, 'answer:sess-1/%s' % uid

    def live(self, path, source):
        saved = getattr(cg, '_pinned_home', None)
        cg._pinned_home = lambda: str(self.home)
        try:
            return cg.approve_delete_no_backup(str(path), source, self.wal, policy=self.policy,
                                               attached=lambda: set(), ls_remote=self.ls_remote)
        finally:
            if saved is None:
                del cg._pinned_home
            else:
                cg._pinned_home = saved

    def test_forged_claude_config_dir_refused(self):
        path = self.image()
        fake, source = self.forged(path)
        os.environ['CLAUDE_CONFIG_DIR'] = str(fake)
        try:
            with self.assertRaises(ValueError) as caught:
                self.live(path, source)
            self.assertIn('CLAUDE_CONFIG_DIR', str(caught.exception))
        finally:
            os.environ.pop('CLAUDE_CONFIG_DIR', None)

    def test_redirected_home_refused(self):
        path = self.image()
        fake_home = self.home / 'elsewhere'
        uid = transcript(fake_home / '.claude', 'sess-1', str(path))
        os.environ['HOME'] = str(fake_home)
        with self.assertRaises(ValueError) as caught:
            self.live(path, 'answer:sess-1/%s' % uid)
        self.assertIn('HOME', str(caught.exception))

    def test_explicit_home_lookup_ignores_claude_config_dir(self):
        path = self.image()
        fake, source = self.forged(path)
        os.environ['CLAUDE_CONFIG_DIR'] = str(fake)
        try:
            with self.assertRaises(ValueError):
                cg.resolve_user_source(source, max_age=86400, home=str(self.home))
        finally:
            os.environ.pop('CLAUDE_CONFIG_DIR', None)

    def test_hook_blocks_approve_delete_with_env_overrides(self):
        c = cg.Compiled(self.policy, home=str(self.home))
        tail = 'python3 ~/.claude/hooks/command_guard.py approve-delete --path /x --no-backup --user-source %s ' \
               '--wal /w.jsonl' % SOURCE
        for cmd in ('CLAUDE_CONFIG_DIR=/tmp/fake ' + tail, 'env CLAUDE_CONFIG_DIR=/tmp/fake ' + tail,
                    'HOME=/tmp/fake ' + tail, 'export HOME=/tmp/fake; ' + tail, 'env ' + tail,
                    'unset CLAUDE_CONFIG_DIR HOME; ' + tail, 'PATH=/tmp/shim:$PATH ' + tail,
                    'GIT_EXEC_PATH=/tmp/shim ' + tail, 'GIT_CONFIG_GLOBAL=/tmp/g ' + tail, '/usr/bin/env -i ' + tail,
                    'export PATH=/tmp/shim:$PATH; ' + tail, 'DYLD_INSERT_LIBRARIES=/tmp/x.dylib ' + tail,
                    'PYTHONPATH=/tmp/shim ' + tail):
            with self.subTest(cmd=cmd[:40]):
                self.assertEqual(cg.decide(cmd, c)[0], 'block')
        self.assertEqual(cg.decide(tail, c)[0], 'allow')


class NativeReviewF2Remote(NoBackupCase):
    """F2: "pushed" is proven only by a live allowlisted network remote, never by the repo itself or a local path."""

    def test_repo_that_is_its_own_remote_refused(self):
        path = self.task / 'self'
        run('git', 'init', '-q', '-b', 'main', str(path))
        (path / 'unique').write_text('only copy\n')
        run('git', 'add', '-A', cwd=path)
        run('git', 'commit', '-q', '-m', 'u', cwd=path)
        run('git', 'remote', 'add', 'origin', str(path), cwd=path)
        run('git', 'update-ref', 'refs/remotes/origin/main', 'HEAD', cwd=path)
        self.refused(path, 'allowlisted', ls_remote=None)

    def test_mutual_local_clones_refused(self):
        a, b = self.task / 'a', self.task / 'b'
        run('git', 'init', '-q', '-b', 'main', str(a))
        (a / 'unique').write_text('only copy\n')
        run('git', 'add', '-A', cwd=a)
        run('git', 'commit', '-q', '-m', 'u', cwd=a)
        run('git', 'clone', '-q', str(a), str(b))
        run('git', 'remote', 'add', 'origin', str(b), cwd=a)
        run('git', 'fetch', '-q', 'origin', cwd=a)
        self.refused(a, 'allowlisted', ls_remote=None)
        self.refused(b, 'allowlisted', ls_remote=None)

    def test_file_url_and_unlisted_host_refused(self):
        path = self.clone()
        for url in ('file://%s' % self.remote, str(self.remote), 'https://evil.example/x.git', 'ssh://evil.example/x',
                    '../remote.git'):
            with self.subTest(url=url):
                run('git', 'remote', 'set-url', 'origin', url, cwd=path)
                self.refused(path, 'allowlisted')

    def test_allowlisted_url_forms(self):
        self.assertEqual(cg._remote_host('https://github.com/o/r.git'), 'github.com')
        self.assertEqual(cg._remote_host('git@github.com:o/r.git'), 'github.com')
        self.assertEqual(cg._remote_host('ssh://t2-dev/home/someone/wt/qac-b-gate'), 't2-dev')
        self.assertEqual(cg._remote_host('ssh://git@GitHub.com:22/o/r'), 'github.com')
        for local in ('/srv/r.git', './r', '~/r', 'file:///srv/r.git', '', 'ext::sh -c x'):
            with self.subTest(local=local):
                self.assertEqual(cg._remote_host(local), '')
        path = self.clone()
        run('git', 'remote', 'set-url', 'origin', 'git@github.com:example/nb-test.git', cwd=path)
        pushed = self.approve(path)['pushed_to']
        self.assertEqual((pushed['url_host'], pushed['answered']), ('github.com', ['origin@github.com']))

    def test_ls_remote_runs_outside_the_repository(self):
        seen = []
        saved = cg._git
        cg._git = lambda repo, *args, **kw: (seen.append((repo, args[:1])), (1, ''))[1]
        try:
            cg._ls_remote('https://github.com/o/r.git')
        finally:
            cg._git = saved
        self.assertEqual(seen, [(None, ('ls-remote',))])


class NativeReviewF3HiddenWork(NoBackupCase):
    """F3: unique work that `git status` and branch tips do not show."""

    def test_skip_worktree_edit_refused(self):
        path = self.clone()
        (path / 'README').write_text('hidden edit\n')
        run('git', 'update-index', '--skip-worktree', 'README', cwd=path)
        self.refused(path, 'skip-worktree')

    def test_assume_unchanged_edit_refused(self):
        path = self.clone()
        (path / 'README').write_text('hidden edit\n')
        run('git', 'update-index', '--assume-unchanged', 'README', cwd=path)
        self.refused(path, 'assume-unchanged')

    def test_sparse_checkout_absent_files_are_fine(self):
        path = self.clone()
        run('git', 'sparse-checkout', 'set', '--no-cone', '/README', cwd=path)
        self.assertFalse((path / 'tests/fixture.jsonl').exists())
        self.assertEqual(self.approve(path)['target'], 'git')

    def test_shallow_clone_is_fine_but_hides_no_unpushed_tip(self):
        # the real qac-b mirror is a depth-1 clone; a shallow boundary cannot hide an unpushed tip
        path = self.clone()
        head = run('git', 'rev-parse', 'HEAD', cwd=path).strip()
        (path / '.git/shallow').write_text(head + '\n')
        self.assertEqual(self.approve(path)['target'], 'git')
        (path / 'u').write_text('u\n')
        run('git', 'add', 'u', cwd=path)
        run('git', 'commit', '-q', '-m', 'unpushed', cwd=path)
        (path / '.git/shallow').write_text(run('git', 'rev-parse', 'HEAD', cwd=path))
        self.refused(path, 'unpushed')

    def test_tag_only_commit_refused(self):
        path = self.clone()
        run('git', 'checkout', '-q', '-b', 'tmp', cwd=path)
        (path / 't').write_text('t\n')
        run('git', 'add', 't', cwd=path)
        run('git', 'commit', '-q', '-m', 'tagged only', cwd=path)
        run('git', 'tag', 'keep-me', cwd=path)
        run('git', 'checkout', '-q', 'main', cwd=path)
        run('git', 'branch', '-q', '-D', 'tmp', cwd=path)
        self.refused(path, 'unpushed')

    def test_custom_ref_commit_refused(self):
        path = self.clone()
        (path / 'n').write_text('n\n')
        run('git', 'add', 'n', cwd=path)
        run('git', 'commit', '-q', '-m', 'custom ref only', cwd=path)
        run('git', 'update-ref', 'refs/keep/x', 'HEAD', cwd=path)
        run('git', 'reset', '-q', '--hard', 'HEAD~1', cwd=path)
        self.refused(path, 'unpushed')

    def test_submodule_refused(self):
        path = self.clone()
        (path / '.gitmodules').write_text('[submodule "s"]\n\tpath = s\n\turl = https://github.com/o/s\n')
        run('git', 'add', '.gitmodules', cwd=path)
        run('git', 'commit', '-q', '-m', 'sub', cwd=path)
        run('git', 'push', '-q', str(self.remote), 'main', cwd=path)
        run('git', 'fetch', '-q', str(self.remote), 'main:refs/remotes/origin/main', cwd=path)
        self.refused(path, 'submodules')

    def test_gitlink_refused(self):
        path = self.clone()
        head = run('git', 'rev-parse', 'HEAD', cwd=path).strip()
        run('git', 'update-index', '--add', '--cacheinfo', '160000,%s,inner' % head, cwd=path)
        run('git', 'commit', '-q', '-m', 'gitlink', cwd=path)
        run('git', 'push', '-q', str(self.remote), 'main', cwd=path)
        run('git', 'fetch', '-q', str(self.remote), 'main:refs/remotes/origin/main', cwd=path)
        self.refused(path, 'submodules')

    def test_replace_refs_and_grafts_refused(self):
        path = self.clone()
        head = run('git', 'rev-parse', 'HEAD', cwd=path).strip()
        run('git', 'update-ref', 'refs/replace/%s' % head, head, cwd=path)
        self.refused(path, 'replace')
        run('git', 'update-ref', '-d', 'refs/replace/%s' % head, cwd=path)
        (path / '.git/info').mkdir(exist_ok=True)
        (path / '.git/info/grafts').write_text(head + '\n')
        self.refused(path, 'grafts')


class NativeReviewF4Recheck(NoBackupCase):
    """F4: the hook re-checks every local fact at delete time, not only HEAD and status."""

    def assertVoided(self, path, change):
        self.approve(path)
        change(path)
        self.assertFalse(self.approvals().covers(str(path)))

    def test_stash_after_approval_voids_it(self):
        def stash(path):
            (path / 'README').write_text('stashed\n')
            run('git', 'stash', '-q', cwd=path)
        self.assertVoided(self.clone(), stash)

    def test_local_branch_commit_after_approval_voids_it(self):
        def side(path):
            run('git', 'checkout', '-q', '-b', 'side', cwd=path)
            (path / 's').write_text('s\n')
            run('git', 'add', 's', cwd=path)
            run('git', 'commit', '-q', '-m', 'side', cwd=path)
            run('git', 'checkout', '-q', 'main', cwd=path)
        self.assertVoided(self.clone(), side)

    def test_linked_worktree_after_approval_voids_it(self):
        self.assertVoided(self.clone(), lambda path: run('git', 'worktree', 'add', '-q', str(self.task / 'lw'),
                                                         '-b', 'lw', cwd=path))

    def test_new_tag_after_approval_voids_it(self):
        self.assertVoided(self.clone(), lambda path: run('git', 'tag', 'late', cwd=path))

    def test_hidden_flag_after_approval_voids_it(self):
        self.assertVoided(self.clone(), lambda path: run('git', 'update-index', '--assume-unchanged', 'README',
                                                         cwd=path))


class NativeReviewF5Cap(NoBackupCase):
    """F5: the per-answer cap counts the canonical source, under the lock, and only from a written audit."""

    def test_excerpt_suffix_refused(self):
        self.refused(self.image(), 'exactly answer', source=SOURCE + ' "yes"')
        self.refused(self.image('b.dmg'), 'exactly answer', source=SOURCE + ' ')

    def test_case_variants_share_one_cap(self):
        for i in range(4):
            self.approve(self.image('d%d.dmg' % i))
        variant = SOURCE.rsplit('/', 1)[0] + '/' + SOURCE.rsplit('/', 1)[1].upper()
        self.refused(self.image('d8.dmg'), 'already approved', source=variant)

    def test_unwritable_audit_refuses(self):
        audit = self.home / '.agent-harness/state/log-delete-audit.jsonl'
        audit.parent.mkdir(parents=True, exist_ok=True)
        audit.write_text('')
        os.chmod(audit, 0o400)
        try:
            self.refused(self.image(), 'audit log could not be written')
            self.assertFalse(self.approvals().covers(str(self.task / 'disk.sparseimage')))
        finally:
            os.chmod(audit, 0o600)

    def test_concurrent_approvals_respect_the_cap(self):
        import threading
        images = [self.image('r%d.dmg' % i) for i in range(8)]
        go, results = threading.Barrier(len(images)), []

        def one(path):
            go.wait()
            try:
                self.approve(path)
                results.append(True)
            except ValueError:
                results.append(False)
        threads = [threading.Thread(target=one, args=(p,)) for p in images]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(True), 4, results)


class NativeReviewF6Binding(NoBackupCase):
    """F6: the answer must be an AskUserQuestion answer, in the WAL's session, naming this path, saying delete."""

    def test_user_turn_source_refused(self):
        self.refused(self.image(), 'exactly answer', source='user:sess-1/a54d2164-40ad-4be7-bcb7-7c8125c0fc87')

    def test_question_that_does_not_name_the_path_refused(self):
        path = self.image()
        self.refused(path, 'does not name the literal path', resolver=ok_resolver_for(self.task / 'other.dmg'))

    def test_declining_answer_refused(self):
        path = self.image()
        for text in ('Leave them', 'Back up to Dropbox first', 'Do not delete'):
            with self.subTest(text=text):
                self.refused(path, 'does not say delete', resolver=ok_resolver_for(path, text=text))

    def test_wal_of_another_session_refused(self):
        path = self.image()
        self.refused(path, 'not a WAL of that session', wal=str(self.home / '.claude/wals/other/main.jsonl'))


class NativeReviewF7RealTranscript(NoBackupCase):
    """F7: the real resolver reads <home>/.claude, end to end, with no injected resolver."""

    def test_real_answer_naming_the_path_is_approved(self):
        path = self.image()
        uid = transcript(self.home / '.claude', 'sess-1', str(path))
        entry = self.approve(path, source='answer:sess-1/%s' % uid, resolver=None)
        self.assertEqual(entry['user_source'], 'answer:sess-1/%s' % uid)

    def test_real_answer_not_naming_the_path_is_refused(self):
        path = self.image()
        uid = transcript(self.home / '.claude', 'sess-1', 'some other folder')
        self.refused(path, 'does not name the literal path', source='answer:sess-1/%s' % uid, resolver=None)

    def test_real_declining_answer_is_refused(self):
        path = self.image()
        uid = transcript(self.home / '.claude', 'sess-1', str(path), answer='Leave them')
        self.refused(path, 'does not say delete', source='answer:sess-1/%s' % uid, resolver=None)


class NativeReviewF8Images(NoBackupCase):
    """F8: images only under ~/.agent-harness/work, with the size recorded."""

    def test_image_outside_the_work_tree_refused(self):
        other = self.home / 'Downloads'
        other.mkdir()
        img = other / 'x.dmg'
        img.write_bytes(b'\0' * 10)
        self.refused(img, 'only under ~/.agent-harness/work')

    def test_size_is_recorded(self):
        entry = self.approve(self.image())
        self.assertEqual(entry['bytes'], 4096)
        lines = (self.home / '.agent-harness/state/log-delete-audit.jsonl').read_text().splitlines()
        self.assertEqual([json.loads(x).get('bytes') for x in lines if json.loads(x)['event'] == 'approved'], [4096])


class Round3N1LiveRefs(NoBackupCase):
    """N1: every local ref and HEAD must be reachable from one live ls-remote listing; tracking refs never count."""

    def side_commit(self, path, branch='work'):
        run('git', 'checkout', '-q', '-b', branch, cwd=path)
        (path / 'w').write_text('unique work\n')
        run('git', 'add', 'w', cwd=path)
        run('git', 'commit', '-q', '-m', 'work', cwd=path)
        return run('git', 'rev-parse', 'HEAD', cwd=path).strip()

    def test_unpushed_branch_with_forged_tracking_ref_refused(self):
        path = self.clone()
        self.side_commit(path)
        run('git', 'update-ref', 'refs/remotes/origin/work', 'HEAD', cwd=path)
        run('git', 'checkout', '-q', 'main', cwd=path)
        self.refused(path, 'no live ref of an allowlisted network remote')

    def test_pushed_side_branch_approved(self):
        path = self.clone()
        sha = self.side_commit(path, 'feat')
        run('git', 'push', '-q', str(self.remote), 'feat', cwd=path)
        run('git', 'update-ref', 'refs/remotes/origin/feat', sha, cwd=path)
        run('git', 'checkout', '-q', 'main', cwd=path)
        self.assertEqual(self.approve(path)['target'], 'git')

    def test_stale_tracking_ref_after_remote_branch_deleted_refused(self):
        path = self.clone()
        sha = self.side_commit(path, 'feat')
        run('git', 'push', '-q', str(self.remote), 'feat', cwd=path)
        run('git', 'update-ref', 'refs/remotes/origin/feat', sha, cwd=path)
        run('git', 'checkout', '-q', 'main', cwd=path)
        run('git', '--git-dir', str(self.remote), 'branch', '-q', '-D', 'feat')  # remote deleted it; clone never pruned
        self.refused(path, 'no live ref of an allowlisted network remote')

    def test_unpushed_detached_head_refused(self):
        path = self.clone()
        run('git', 'checkout', '-q', '--detach', cwd=path)
        (path / 'd').write_text('d\n')
        run('git', 'add', 'd', cwd=path)
        run('git', 'commit', '-q', '-m', 'detached', cwd=path)
        run('git', 'update-ref', 'refs/remotes/origin/main', 'HEAD', cwd=path)
        self.refused(path, 'no live ref of an allowlisted network remote')

    def test_unpushed_tag_refused_and_pushed_tag_approved(self):
        path = self.clone()
        self.side_commit(path, 'side')
        run('git', 'tag', '-a', '-m', 'v', 'v1', cwd=path)
        run('git', 'update-ref', 'refs/remotes/origin/side', 'HEAD', cwd=path)  # a hand-set tracking ref: no proof
        run('git', 'checkout', '-q', 'main', cwd=path)
        run('git', 'branch', '-q', '-D', 'side', cwd=path)
        self.refused(path, 'no live ref of an allowlisted network remote')
        run('git', 'push', '-q', str(self.remote), 'v1', cwd=path)
        self.assertEqual(self.approve(path)['target'], 'git')

    def test_remote_ahead_of_the_clone_needs_a_fetch(self):
        path = self.clone()
        other = self.task / 'other'
        run('git', 'clone', '-q', '-b', 'main', str(self.remote), str(other))
        (other / 'o').write_text('o\n')
        run('git', 'add', 'o', cwd=other)
        run('git', 'commit', '-q', '-m', 'o', cwd=other)
        run('git', 'push', '-q', 'origin', 'main', cwd=other)
        self.refused(path, 'fetch')

    def test_live_listing_is_taken_once_per_remote_with_heads_and_tags(self):
        seen = []
        saved = cg._git
        cg._git = lambda repo, *args, **kw: (seen.append((repo, args)), (0, 'a' * 40 + '\trefs/heads/main\n'))[1]
        try:
            self.assertEqual(cg._ls_remote('https://github.com/o/r.git'), ['a' * 40])
        finally:
            cg._git = saved
        self.assertEqual(len(seen), 1)
        self.assertIsNone(seen[0][0])
        self.assertIn('refs/heads/*', seen[0][1])
        self.assertIn('refs/tags/*', seen[0][1])


class Round3N2Answer(NoBackupCase):
    """N2: one question, one predefined option starting with Delete, naming exactly this path."""

    def real(self, path, **kw):
        uid = transcript(self.home / '.claude', 'sess-1', kw.pop('path_text', str(path)), **kw)
        return 'answer:sess-1/%s' % uid

    def test_never_delete_option_refused(self):
        path = self.image()
        src = self.real(path, answer='Never delete these', options=('Never delete these', 'Delete'))
        self.refused(path, 'does not say delete', source=src, resolver=None)

    def test_delete_nothing_yet_refused(self):
        path = self.image()
        src = self.real(path, answer='Delete nothing yet', options=('Delete nothing yet', 'Delete it'))
        self.refused(path, 'does not say delete', source=src, resolver=None)

    def test_free_text_other_answer_refused(self):
        path = self.image()
        src = self.real(path, answer='Delete it')  # not one of the offered options: typed into "Other"
        self.refused(path, 'predefined option', source=src, resolver=None)

    def test_two_question_call_refused(self):
        a, b = self.image('a.dmg'), self.image('b.dmg')
        qa, qb = 'Delete %s?' % a, 'What about %s?' % b
        opts = [{'label': 'Delete', 'description': 'd'}, {'label': 'Move it to Dropbox first', 'description': 'm'}]
        uid = transcript(self.home / '.claude', 'sess-1', '', questions=[
            {'question': qa, 'header': 'A', 'multiSelect': False, 'options': opts},
            {'question': qb, 'header': 'B', 'multiSelect': False, 'options': opts}],
            answers={qa: 'Delete', qb: 'Move it to Dropbox first'})
        self.refused(b, 'single question', source='answer:sess-1/%s' % uid, resolver=None)

    def test_two_questions_one_answer_refused(self):
        b = self.image('b.dmg')
        qb, qx = 'Delete %s without a backup?' % b, 'Anything else to clean?'
        opts = [{'label': 'Delete, no backup', 'description': 'd'}, {'label': 'Leave it', 'description': 'k'}]
        uid = transcript(self.home / '.claude', 'sess-1', '', questions=[
            {'question': qb, 'header': 'B', 'multiSelect': False, 'options': opts},
            {'question': qx, 'header': 'X', 'multiSelect': False, 'options': opts}],
            answers={qb: 'Delete, no backup'})
        self.refused(b, 'single question', source='answer:sess-1/%s' % uid, resolver=None)

    def test_delete_must_lead_the_selected_option(self):
        path = self.image()
        src = self.real(path, answer='Please delete it', options=('Please delete it', 'Leave it'))
        self.refused(path, 'does not say delete', source=src, resolver=None)

    def test_multi_select_refused(self):
        path = self.image()
        src = self.real(path, multi=True)
        self.refused(path, 'single question', source=src, resolver=None)

    def test_question_naming_two_paths_refused(self):
        a, b = self.image('a.dmg'), self.image('b.dmg')
        self.refused(b, 'names another path', resolver=ok_resolver_for(a, b))
        src = self.real(b, path_text='%s and %s' % (a, b))
        self.refused(b, 'names another path', source=src, resolver=None)

    def test_prefix_named_path_is_not_this_path(self):
        target = self.clone('mirror')
        src = self.real(target, path_text=str(target) + '-old')
        self.refused(target, 'does not name the literal path', source=src, resolver=None)
        self.refused(target, 'does not name the literal path', resolver=ok_resolver_for(str(target) + '-old'))
        self.refused(target, 'does not name the literal path', resolver=ok_resolver_for(str(target) + '/sub'))

    def test_question_with_ancestor_context_and_punctuation_is_approved(self):
        path = self.image()
        src = self.real(path, path_text='%s (under %s/)' % (path, self.task))
        self.assertEqual(self.approve(path, source=src, resolver=None)['target'], 'image')

    def test_injected_resolver_without_predefined_flag_refused(self):
        path = self.image()
        self.refused(path, 'predefined option', resolver=ok_resolver_for(path, predefined=False))


class Round3N3Environment(NoBackupCase):
    """N3: git runs by an absolute path with a constructed environment; PATH and GIT_* shims cannot answer."""

    def test_git_env_is_constructed(self):
        seen = {}
        real_run = subprocess.run

        def spy(argv, **kw):
            seen['argv'], seen['env'] = argv, kw.get('env')
            return real_run(['true'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        saved = dict(os.environ)
        os.environ.update(PATH='/tmp/shim:' + saved.get('PATH', ''), GIT_EXEC_PATH='/tmp/shim',
                          GIT_CONFIG_GLOBAL='/tmp/g', GIT_SSH_VARIANT='ssh', GIT_TEMPLATE_DIR='/tmp/t')
        cg.subprocess.run = spy
        try:
            cg._git(None, 'version')
        finally:
            cg.subprocess.run = real_run
            os.environ.clear()
            os.environ.update(saved)
        env = seen['env']
        self.assertTrue(os.path.isabs(seen['argv'][0]), seen['argv'][0])
        self.assertEqual(env['PATH'], '/usr/bin:/bin')
        self.assertEqual(env['GIT_CONFIG_GLOBAL'], '/dev/null')
        self.assertEqual(env['GIT_CONFIG_NOSYSTEM'], '1')
        allowed = {'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM', 'GIT_TERMINAL_PROMPT', 'GIT_OPTIONAL_LOCKS',
                   'GIT_PAGER', 'GIT_NO_REPLACE_OBJECTS', 'GIT_ATTR_NOSYSTEM'}
        self.assertEqual({k for k in env if k.startswith('GIT_')} - allowed, set())
        self.assertIn('core.sshCommand=/usr/bin/ssh', seen['argv'])

    def test_path_shim_git_never_runs(self):
        shim = self.home / 'shim'
        shim.mkdir()
        canary = self.home / 'canary'
        (shim / 'git').write_text('#!/bin/sh\ntouch %s\nexit 1\n' % canary)
        os.chmod(shim / 'git', 0o755)
        repo = str(self.clone())
        saved = os.environ.get('PATH', '')
        os.environ['PATH'] = '%s:%s' % (shim, saved)
        try:
            code, _ = cg._git(repo, 'rev-parse', 'HEAD')
        finally:
            os.environ['PATH'] = saved
        self.assertEqual(code, 0)
        self.assertFalse(canary.exists())


class Round3N4Filters(NoBackupCase):
    """N4: repository filter config, info/attributes and LFS are refused before git status can run a filter."""

    def hide(self, path, canary):
        (path / '.git/info').mkdir(exist_ok=True)
        (path / '.git/info/attributes').write_text('README filter=hide\n')
        run('git', 'config', 'filter.hide.clean', "sh -c 'touch %s; cat'" % canary, cwd=path)

    def test_clean_filter_refused_and_never_runs(self):
        path = self.clone()
        canary = self.home / 'filter-ran'
        self.hide(path, canary)
        (path / 'README').write_text('yo\n')
        self.refused(path, 'filter')
        self.assertFalse(canary.exists())

    def test_filter_config_alone_refused(self):
        path = self.clone()
        run('git', 'config', 'filter.lfs.process', 'git-lfs filter-process', cwd=path)
        self.refused(path, 'filter')

    def test_info_attributes_alone_refused(self):
        path = self.clone()
        (path / '.git/info').mkdir(exist_ok=True)
        (path / '.git/info/attributes').write_text('* -text\n')
        self.refused(path, 'attributes')

    def test_lfs_store_refused(self):
        path = self.clone()
        (path / '.git/lfs/objects').mkdir(parents=True)
        self.refused(path, 'LFS')

    def test_filter_added_after_approval_voids_it(self):
        path = self.clone()
        self.approve(path)
        canary = self.home / 'filter-ran-late'
        self.hide(path, canary)
        self.assertFalse(self.approvals().covers(str(path)))
        self.assertFalse(canary.exists())


class Round3N5SoleSegment(NoBackupCase):
    """N5: a no-backup approval is used only by a command whose only segment is the delete itself."""

    def test_compound_commands_blocked_and_plain_delete_allowed(self):
        path = self.clone()
        self.approve(path)
        c = cg.Compiled(self.policy, home=str(self.home))
        for cmd in ('echo unique > %s/new.txt && rm -rf %s' % (path, path),
                    'git -C %s commit --allow-empty -m wip && rm -rf %s' % (path, path),
                    'echo x >> %s/README; git -C %s stash; rm -rf %s' % (path, path, path),
                    'rm -rf %s; echo done' % path, 'rm -rf %s & sleep 1' % path,
                    'rm -rf %s\necho next' % path, 'rm -rf %s $(true)' % path,
                    'cd /tmp && rm -rf %s' % path):
            with self.subTest(cmd=cmd[:50]):
                self.assertEqual(cg.decide(cmd, c, marker=self.approvals())[0], 'block')
        for cmd in ('rm -rf %s' % path, '/bin/rm -rf -- %s' % path, "rm -r -f '%s'" % path):
            with self.subTest(cmd=cmd[:50]):
                self.assertEqual(cg.decide(cmd, c, marker=self.approvals())[0], 'allow')


class Round3N6Transcripts(NoBackupCase):
    """N6: the answer counts only from a real (not symlinked) transcript, and Bash cannot write transcripts."""

    def test_symlinked_project_dir_refused(self):
        path = self.image()
        forged = self.home / 'forged'
        uid = transcript(forged, 'sess-1', str(path))
        os.symlink(str(forged / 'projects' / 'p'), str(self.home / '.claude/projects/zz-link'))
        self.refused(path, 'symlink', source='answer:sess-1/%s' % uid, resolver=None)

    def test_symlinked_transcript_file_refused(self):
        path = self.image()
        forged = self.home / 'forged'
        uid = transcript(forged, 'sess-1', str(path))
        folder = self.home / '.claude/projects/q'
        folder.mkdir()
        os.symlink(str(forged / 'projects/p/sess-1.jsonl'), str(folder / 'sess-1.jsonl'))
        self.refused(path, 'symlink', source='answer:sess-1/%s' % uid, resolver=None)

    def test_bash_writes_into_projects_blocked(self):
        c = cg.Compiled(self.policy, home=str(self.home))
        p = '%s/.claude/projects' % self.home
        for cmd in ('mkdir -p %s/zz && printf x > %s/zz/s.jsonl' % (p, p), 'cp /tmp/f.jsonl %s/zz/' % p,
                    'ln -s /tmp/forged %s/zz-link' % p, 'echo x >> %s/p/a.jsonl' % p,
                    'tee -a %s/p/a.jsonl < /tmp/f' % p, 'cp -r /tmp/forged %s' % p,
                    "python3 -c \"open('%s/zz/s.jsonl','a').write('x')\"" % p):
            with self.subTest(cmd=cmd[:60]):
                self.assertEqual(cg.decide(cmd, c)[0], 'block')
        for cmd in ('cat %s/p/a.jsonl' % p, 'grep -c x %s/p/a.jsonl' % p,
                    'printf note > %s/-Users-x/memory/note.md' % p,
                    "python3 -c \"print(open('%s/p/a.jsonl').read())\"" % p):
            with self.subTest(cmd=cmd[:60]):
                self.assertNotEqual(cg.decide(cmd, c)[0], 'block')


class Round3N7SessionCase(NoBackupCase):
    """N7: the session id is canonical and must be the transcript's exact name."""

    def test_canonical_source_folds_the_session(self):
        self.assertEqual(cg._canonical_source('answer:SESS-1/ABCDEF01-0000'), 'answer:sess-1/abcdef01-0000')

    def test_session_case_variant_refused(self):
        path = self.image()
        uid = transcript(self.home / '.claude', 'sess-1', str(path))
        self.refused(path, None, source='answer:SESS-1/%s' % uid, resolver=None,
                     wal=str(self.home / '.claude/wals/SESS-1/agent-nb.jsonl'))

    def test_case_variants_of_the_session_share_one_cap(self):
        for i in range(4):
            self.approve(self.image('c%d.dmg' % i))
        self.refused(self.image('c9.dmg'), 'already approved', source=SOURCE.replace('sess-1', 'SESS-1'))


class Round3N8Wal(NoBackupCase):
    """N8: --wal must be an existing, real, hook-written WAL of the answer's session that predates the answer."""

    def test_missing_wal_refused(self):
        self.refused(self.image(), 'WAL', wal=str(self.home / '.claude/wals/sess-1/fresh.jsonl'))
        self.assertFalse((self.home / '.claude/wals/sess-1/fresh.jsonl').exists())

    def test_symlinked_wal_refused(self):
        link = self.home / '.claude/wals/sess-1/link.jsonl'
        os.symlink(self.wal, str(link))
        self.refused(self.image(), 'WAL', wal=str(link))

    def test_wal_written_only_after_the_answer_refused(self):
        late = str(self.home / '.claude/wals/sess-1/late.jsonl')
        hook_wal(late, time.time() + 120)
        self.refused(self.image(), 'predate', wal=late)

    def test_wal_without_hook_entries_refused(self):
        notes = self.home / '.claude/wals/sess-1/notes.jsonl'
        notes.write_text(json.dumps({'at': '2020-01-01T00:00:00+00:00', 'event': 'intent', 'note': 'x'}) + '\n')
        self.refused(self.image(), 'predate', wal=str(notes))


def case_insensitive_fs(path):
    """True when `path`'s file system folds case (macOS APFS by default)."""
    probe = Path(path) / 'CaseProbe'
    probe.write_text('x')
    try:
        return (Path(path) / 'caseprobe').exists()
    finally:
        probe.unlink()


class Round4(NoBackupCase):
    """Native re-review of a583e7d (nb-r3-a583e7d.md): R-A, R-B, R-C, R-D and the surviving reviewer mutants."""

    def real(self, path, **kw):
        uid = transcript(self.home / '.claude', kw.pop('session', 'sess-1'), kw.pop('path_text', str(path)), **kw)
        return uid

    def test_ra_commit_held_only_by_a_stale_tracking_ref_refused(self):
        path = self.clone()
        run('git', 'checkout', '-q', '-b', 'feat', cwd=path)
        (path / 'f').write_text('feature\n')
        run('git', 'add', 'f', cwd=path)
        run('git', 'commit', '-q', '-m', 'feat', cwd=path)
        sha = run('git', 'rev-parse', 'HEAD', cwd=path).strip()
        run('git', 'push', '-q', str(self.remote), 'feat', cwd=path)
        run('git', 'update-ref', 'refs/remotes/origin/feat', sha, cwd=path)
        run('git', 'checkout', '-q', 'main', cwd=path)
        run('git', 'branch', '-q', '-D', 'feat', cwd=path)  # the normal tidy-up after a push
        self.assertEqual(self.approve(path)['target'], 'git')  # still live on the remote: fine
        self.tearDown()
        self.setUp()
        path = self.clone()
        run('git', 'checkout', '-q', '-b', 'feat', cwd=path)
        (path / 'f').write_text('feature\n')
        run('git', 'add', 'f', cwd=path)
        run('git', 'commit', '-q', '-m', 'feat', cwd=path)
        sha = run('git', 'rev-parse', 'HEAD', cwd=path).strip()
        run('git', 'push', '-q', str(self.remote), 'feat', cwd=path)
        run('git', 'update-ref', 'refs/remotes/origin/feat', sha, cwd=path)
        run('git', 'checkout', '-q', 'main', cwd=path)
        run('git', 'branch', '-q', '-D', 'feat', cwd=path)
        run('git', '--git-dir', str(self.remote), 'branch', '-q', '-D', 'feat')  # gone remotely; never pruned here
        self.refused(path, 'fetch --prune')

    def test_rb_only_the_exact_no_backup_label_approves(self):
        for label in ('Delete after backing up to Dropbox', 'Delete once the Dropbox copy is verified',
                      'Delete only if a backup exists', 'Delete with a backup first', 'Delete (back up first)',
                      'Delete? No, back it up', 'Delete', 'Delete it, no backup please',
                      'Delete, no backups exist so archive first', 'Delete, no backup (Recommended) after archiving'):
            with self.subTest(label=label):
                path = self.image('rb-%d.dmg' % abs(hash(label)))
                uid = self.real(path, answer=label, options=(label, 'Leave them'))
                self.refused(path, 'Delete, no backup', source='answer:sess-1/%s' % uid, resolver=None)
        for label in ('Delete, no backup', 'Delete, no backup (Recommended)'):
            with self.subTest(label=label):
                path = self.image('ok-%d.dmg' % len(label))
                uid = self.real(path, answer=label, options=(label, 'Leave them'))
                self.assertEqual(self.approve(path, source='answer:sess-1/%s' % uid, resolver=None)['target'],
                                 'image')

    def test_rc_stat_config_cannot_hide_a_same_size_edit(self):
        path = self.clone()
        run('git', 'config', 'core.checkStat', 'minimal', cwd=path)
        run('git', 'config', 'core.trustctime', 'false', cwd=path)
        run('git', 'update-index', '--refresh', cwd=path)
        st = os.stat(path / 'README')
        (path / 'README').write_text('yo\n')  # same size as 'hi\n'
        os.utime(path / 'README', ns=(st.st_atime_ns, st.st_mtime_ns))
        self.refused(path, 'untracked or ignored')

    def test_rd_symlink_alias_of_projects_blocked(self):
        c = cg.Compiled(self.policy, home=str(self.home))
        p = '%s/.claude/projects' % self.home
        for cmd in ('ln -s %s /tmp/al' % p, 'ln -sf %s/p /tmp/al2' % p, 'ln --symbolic %s /tmp/al3' % p,
                    'cp -as %s /tmp/al4' % p, 'cp -s %s/p/x.jsonl /tmp/al5' % p):
            with self.subTest(cmd=cmd):
                self.assertEqual(cg.decide(cmd, c)[0], 'block')

    # R-F: each check alone
    def test_rf_transcript_case_check_alone(self):
        if not case_insensitive_fs(self.home):
            self.skipTest('case-sensitive file system: the variant cannot resolve at all')
        path = self.image()
        uid = self.real(path)
        with self.assertRaises(ValueError) as caught:
            cg.resolve_user_source('answer:SESS-1/%s' % uid, max_age=86400, home=str(self.home))
        self.assertIn('exact name', str(caught.exception))

    def test_rf_wal_session_exact_entry_alone(self):
        if not case_insensitive_fs(self.home):
            self.skipTest('case-sensitive file system: the variant path does not exist')
        path = self.image()
        uid = self.real(path, session='SESS-2')
        (self.home / '.claude/wals/sess-2').mkdir(parents=True)
        hook_wal(str(self.home / '.claude/wals/sess-2/main.jsonl'), time.time() - 600)
        self.refused(path, 'exact name', source='answer:SESS-2/%s' % uid, resolver=None,
                     wal=str(self.home / '.claude/wals/SESS-2/main.jsonl'))

    def test_rf_symlinked_projects_store_refused(self):
        path = self.image()
        projects = self.home / '.claude/projects'
        os.rename(str(projects), str(self.home / '.claude/projects-real'))
        os.symlink(str(self.home / '.claude/projects-real'), str(projects))
        uid = self.real(path)
        self.refused(path, 'transcript store', source='answer:sess-1/%s' % uid, resolver=None)

    def test_rf_wal_path_must_be_literal(self):
        path = self.image()
        detour = str(self.home / '.claude/wals/sess-1/../sess-1/agent-nb.jsonl')
        self.refused(path, 'existing, real WAL', wal=detour)

    def test_rf_answer_must_key_the_question(self):
        path = self.image()
        uid = transcript(self.home / '.claude', 'sess-1', str(path),
                         answers={'Some other question?': 'Delete, no backup (Recommended)'})
        self.refused(path, 'does not key', source='answer:sess-1/%s' % uid, resolver=None)

    def test_rf_two_operand_rm_blocked(self):
        path = self.clone()
        self.approve(path)
        c = cg.Compiled(self.policy, home=str(self.home))
        other = self.home / 'scratch.txt'
        other.write_text('x')
        self.assertEqual(cg.decide('rm -rf %s %s' % (path, other), c, marker=self.approvals())[0], 'block')
        self.assertEqual(cg.decide('rm -f %s' % other, c)[0], 'allow')  # the second operand alone is fine


if __name__ == '__main__':
    unittest.main()
