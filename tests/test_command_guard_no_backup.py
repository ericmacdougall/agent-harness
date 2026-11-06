"""goodqa#14911: command_guard approve-delete --no-backup --user-source.

A user-approved deletion without a backup, for a clean pushed git working tree or a detached disk image only.
Every test builds its own temporary home, git remote and clones; nothing outside the temp tree is touched, and
commands are only judged by decide(), never run. CG_HOOKS_DIR points the suite at another implementation (for
example main before this change) to show it failing first.
"""

import json
import os
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


def ok_resolver(source, now=None, max_age=None, home=None):
    return 'answer', time.time()


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
        self.wal = str(self.home / '.claude/wals/s/agent-nb.jsonl')
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
        return path

    def image(self, name='disk.sparseimage'):
        path = self.task / name
        path.write_bytes(b'\0' * 4096)
        return path

    def approve(self, path, **kw):
        kw.setdefault('resolver', ok_resolver)
        kw.setdefault('attached', lambda: set())
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
        run('git', 'push', '-q', 'origin', 'main', cwd=path)
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
        self.refused(path, 'no remote confirms', ls_remote=lambda real, url, branch: '0' * 40)

    def test_unreachable_remote_refused(self):
        path = self.clone()
        self.refused(path, 'no remote confirms', ls_remote=lambda real, url, branch: None)

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
                                                resolver=ok_resolver, attached=lambda: set())

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
        import provenance
        saved = provenance.answer_turn
        provenance.answer_turn = lambda session, uid, home=None: {'timestamp': '2026-01-01T00:00:00Z'}
        try:
            with self.assertRaises(ValueError) as caught:
                cg.resolve_user_source(SOURCE, max_age=86400, home=str(self.home))
            self.assertIn('older', str(caught.exception))
            stamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            provenance.answer_turn = lambda session, uid, home=None: {'timestamp': stamp}
            self.assertEqual(cg.resolve_user_source(SOURCE, max_age=86400, home=str(self.home))[0], 'answer')
        finally:
            provenance.answer_turn = saved

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


if __name__ == '__main__':
    unittest.main()
