"""The worktree verifier (`ah_worktree.py free-worktree`, moved from command_guard.py in release 1001) and `ah log-push`.

Real git repositories in a temporary HOME; nothing outside it is touched.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
os.environ["AH_LOCAL_CONFIG"] = str(Path(__file__).resolve().parent / "data" / "local_fixture.json")  # hermetic hosts
import ah_worktree as aw  # noqa: E402

SID = '11111111-2222-3333-4444-555555555555'
OTHER = '99999999-8888-7777-6666-555555555555'


def git(cwd, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@t',
               GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1')
    return subprocess.run(['git', '-C', str(cwd), *args], check=True, capture_output=True, text=True,
                          env=env).stdout.strip()


class FreeWorktree(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='aw-free-')
        self.addCleanup(tmp.cleanup)
        self.home = Path(os.path.realpath(tmp.name))
        patch = mock.patch.dict(os.environ, {'HOME': str(self.home)})
        patch.start()
        self.addCleanup(patch.stop)
        self.primary = self.home / 'code/proj'
        self.primary.mkdir(parents=True)
        git(self.primary, 'init', '-q', '-b', 'main')
        (self.primary / 'a.txt').write_text('one\n')
        git(self.primary, 'add', 'a.txt')
        git(self.primary, 'commit', '-q', '-m', 'one')
        self.linked = self.home / '.agent-harness/work' / SID / 'wt'
        self.linked.parent.mkdir(parents=True)
        git(self.primary, 'worktree', 'add', '-q', '-b', 'feature', str(self.linked))
        self.head = git(self.linked, 'rev-parse', 'HEAD')
        self.wal = self.home / '.claude/wals' / SID
        self.wal.mkdir(parents=True)  # the owning session is live (just written)

    def publish(self):
        git(self.primary, 'update-ref', 'refs/remotes/origin/feature', git(self.linked, 'rev-parse', 'HEAD'))

    def test_clean_and_published_is_removed_by_anyone(self):
        self.publish()
        report = aw.free_worktree(str(self.linked))
        self.assertTrue(report['removed'], report)
        self.assertFalse(self.linked.exists())

    def test_uncommitted_changes_need_rescue_and_rescue_saves_a_patch_and_the_commits(self):
        (self.linked / 'b.txt').write_text('new\n')
        git(self.linked, 'add', 'b.txt')
        git(self.linked, 'commit', '-q', '-m', 'local')
        (self.linked / 'dirty.txt').write_text('uncommitted\n')
        report = aw.free_worktree(str(self.linked))
        self.assertFalse(report['removable'])
        self.assertIn('--rescue', report['reason'])
        patches = self.home / '.agent-harness/work' / OTHER / 'rescue'
        report = aw.free_worktree(str(self.linked), rescue=True, patch_dir=str(patches))
        self.assertTrue(report['removed'], report)
        self.assertIn('dirty.txt', Path(report['patch']).read_text())
        self.assertEqual(git(self.primary, 'rev-parse', report['rescue_ref']), git(self.primary, 'rev-parse', 'feature'))

    def test_unpushed_commits_of_an_ended_session_are_kept_in_a_rescue_ref(self):
        git(self.linked, 'checkout', '-q', '--detach')
        (self.linked / 'c.txt').write_text('detached\n')
        git(self.linked, 'add', 'c.txt')
        git(self.linked, 'commit', '-q', '-m', 'detached only')
        detached = git(self.linked, 'rev-parse', 'HEAD')
        self.assertFalse(aw.free_worktree(str(self.linked))['removable'])  # session live, not published
        old = 1_000_000_000
        os.utime(self.wal, (old, old))
        report = aw.free_worktree(str(self.linked))
        self.assertTrue(report['removed'], report)
        self.assertEqual(git(self.primary, 'rev-parse', report['rescue_ref']), detached)

    def test_a_process_inside_still_stops_it_and_the_primary_is_never_removable(self):
        self.publish()
        self.assertFalse(aw.free_worktree(str(self.primary))['removable'])
        with mock.patch.object(aw, 'busy_scan', return_value={'busy': [(1, 'sh')], 'unreadable': [], 'skipped': [],
                                                               'failed': False}):
            self.assertIn('process', aw.free_worktree(str(self.linked))['reason'])

    def test_an_ignored_env_file_or_local_database_is_never_removed_with_or_without_rescue(self):
        # the release 1001 red team: HEAD on origin, an ignored .env and data/db.sqlite were deleted with removed:true
        (self.linked / '.gitignore').write_text('.env\ndata/\nnode_modules/\n')
        git(self.linked, 'add', '.gitignore')
        git(self.linked, 'commit', '-q', '-m', 'ignore')
        self.publish()
        (self.linked / '.env').write_text('KEY=1\n')
        (self.linked / 'data').mkdir()
        (self.linked / 'data/db.sqlite').write_bytes(b'db')
        for rescue in (False, True):
            report = aw.free_worktree(str(self.linked), rescue=rescue, patch_dir=str(self.home / 'patches'))
            self.assertFalse(report['removable'], report)
            self.assertFalse(report['removed'])
            self.assertIn('.env', report['reason'])
            self.assertIn('data/', report['reason'])
            self.assertTrue((self.linked / '.env').exists())
            self.assertTrue((self.linked / 'data/db.sqlite').exists())

    def test_the_ignored_file_refusal_lists_the_offending_paths(self):
        status = '\x00'.join(['!! f%d.env' % n for n in range(7)] + ['!! node_modules/', '?? new.txt']) + '\x00'
        text = aw.ignored_refusal(str(self.linked), status)
        for n in range(5):
            self.assertIn('f%d.env' % n, text)
        self.assertNotIn('f5.env', text)
        self.assertIn('(and 2 more)', text)
        self.assertNotIn('node_modules', text)

    def test_only_regenerable_build_directories_without_a_repository_may_go(self):
        (self.linked / '.gitignore').write_text('node_modules/\nbuild/\n__pycache__/\n')
        git(self.linked, 'add', '.gitignore')
        git(self.linked, 'commit', '-q', '-m', 'ignore')
        self.publish()
        (self.linked / 'node_modules/pkg').mkdir(parents=True)
        (self.linked / 'node_modules/pkg/index.js').write_text('x')
        (self.linked / 'build').mkdir()
        (self.linked / 'src/__pycache__').mkdir(parents=True)
        (self.linked / 'src/__pycache__/m.pyc').write_bytes(b'x')
        (self.linked / 'node_modules/dep/.git').mkdir(parents=True)  # a nested repository inside a build directory
        report = aw.free_worktree(str(self.linked))
        self.assertFalse(report['removable'], report)
        self.assertIn('nested repository', report['reason'])
        (self.linked / 'node_modules/dep/.git').rmdir()
        report = aw.free_worktree(str(self.linked))
        self.assertTrue(report['removed'], report)
        self.assertFalse(self.linked.exists())

    def test_a_build_directory_name_below_the_top_is_not_regenerable_unless_it_is_a_cache(self):
        offenders, build = aw.ignored_offenders('!! sub/build/\x00!! sub/node_modules/\x00!! dist/\x00!! dist\x00')
        self.assertEqual(offenders, ['sub/build/', 'dist'])
        self.assertEqual(build, ['sub/node_modules/', 'dist/'])


class LogPush(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='log-push-')
        self.addCleanup(tmp.cleanup)
        self.home = Path(os.path.realpath(tmp.name)) / 'home'
        self.remote = Path(os.path.realpath(tmp.name)) / 'logs.git'
        self.home.mkdir()
        git(self.home.parent, 'init', '-q', '--bare', str(self.remote))
        self.wals = self.home / '.claude/wals' / SID
        self.wals.mkdir(parents=True)
        (self.wals / 'main.jsonl').write_text('{"a":1}\n')
        (self.wals / 'sub').mkdir()
        (self.wals / 'sub/b.jsonl').write_bytes(b'\x00binary\xff\n')
        import ah_log_push
        self.lp = ah_log_push
        self.lp.setup(str(self.remote), home=self.home)

    def test_push_verifies_then_deletes_and_audits(self):
        report = self.lp.push([str(self.wals)], home=self.home)
        self.assertTrue(report['ok'], report)
        self.assertEqual(report['deleted'], 2)
        self.assertFalse(self.wals.exists())
        tree = git(self.remote, 'ls-tree', '-r', '--name-only', 'main')
        self.assertIn('.claude/wals/%s/sub/b.jsonl' % SID, tree)
        self.assertEqual(git(self.remote, 'cat-file', '-p', 'main:%s' % [t for t in tree.split('\n')
                                                                          if t.endswith('main.jsonl')][0]), '{"a":1}')
        row = json.loads((self.home / '.agent-harness/logs/log-push.jsonl').read_text().splitlines()[-1])
        self.assertEqual(row['deleted'], 2)
        # a second push lands on top of the first (no force)
        (self.home / '.claude/wals/x').mkdir(parents=True)
        (self.home / '.claude/wals/x/main.jsonl').write_text('2\n')
        self.assertTrue(self.lp.push([str(self.home / '.claude/wals/x/main.jsonl')], home=self.home)['ok'])
        self.assertEqual(git(self.remote, 'rev-list', '--count', 'main'), '2')

    def test_dry_run_changes_nothing(self):
        report = self.lp.push([str(self.wals)], dry_run=True, home=self.home)
        self.assertTrue(report['ok'])
        self.assertTrue((self.wals / 'main.jsonl').exists())
        self.assertNotIn('main', subprocess.run(['git', '--git-dir', str(self.remote), 'branch'], capture_output=True,
                                                text=True).stdout)

    def test_a_file_that_changes_during_the_push_is_kept(self):
        real = self.lp.build_commit

        def append_then_build(*args, **kw):
            commit = real(*args, **kw)
            with open(self.wals / 'main.jsonl', 'a') as handle:
                handle.write('{"late":true}\n')
            return commit
        with mock.patch.object(self.lp, 'build_commit', append_then_build):
            report = self.lp.push([str(self.wals)], home=self.home)
        self.assertFalse(report['ok'])
        self.assertTrue((self.wals / 'main.jsonl').exists())
        self.assertEqual(report['deleted'], 1)

    def test_size_limit_refuses_before_anything_is_pushed(self):
        (self.wals / 'big.jsonl').write_bytes(b'x' * 2_000_000)
        with self.assertRaises(self.lp.PushError) as caught:
            self.lp.push([str(self.wals)], max_mb=1, home=self.home)
        self.assertIn('limit', str(caught.exception))
        self.assertTrue((self.wals / 'main.jsonl').exists())

    def test_public_and_unknown_repositories_are_refused(self):
        def gh(answer, code=0):
            return lambda *a, **k: subprocess.CompletedProcess(a, code, stdout=answer, stderr='')
        url = 'https://github.com/someone/logs.git'
        self.assertIn('public', self.lp.visibility_refusal(url, gh('PUBLIC\n')))
        self.assertIn('unknown', self.lp.visibility_refusal(url, gh('', 1)))
        self.assertIsNone(self.lp.visibility_refusal(url, gh('PRIVATE\n')))
        self.assertIn('cannot be checked', self.lp.visibility_refusal('ssh://host.example/logs.git', gh('PRIVATE')))
        self.assertIn('public', self.lp.visibility_refusal('git@github.com:x/agent-harness.git', gh('PRIVATE')))
        with self.assertRaises(self.lp.PushError):
            self.lp.setup(url, home=self.home, gh_runner=gh('PUBLIC\n'))

    def test_paths_outside_the_harness_roots_are_refused(self):
        (self.home / 'code').mkdir()
        (self.home / 'code/a.txt').write_text('x')
        with self.assertRaises(self.lp.PushError):
            self.lp.push([str(self.home / 'code')], home=self.home)

if __name__ == '__main__':
    unittest.main()
