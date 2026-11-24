"""goodqa#17119: `ah clone-remove` and its verifier `command_guard.py verify-clone|remove-clone`.

Real git repositories in a temporary HOME. The network is the only fake (cg.REMOTE_LS answers from a local bare repository
standing in for the hosting service). The process scans are faked in most cases for speed. The Processes class runs
the real ones against real processes. Every refusal case leaves the clone where it was.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('CG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))
import ah_clone  # noqa: E402
import command_guard as cg  # noqa: E402

GIT_ENV = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
GIT_ENV.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@x',
               GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@x')
URL = 'https://github.com/acme/widgets.git'
QUIET_SCAN = {'busy': [], 'unreadable': [], 'skipped': [], 'failed': False}


def git(cwd, *args, check=True):
    done = subprocess.run(['git', *args], cwd=str(cwd), env=GIT_ENV, capture_output=True, text=True)
    if check and done.returncode:
        raise AssertionError('git %s: %s' % (' '.join(args), done.stderr))
    return done.stdout.strip()


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix='cg-clonerm-')
        cls.home = Path(os.path.realpath(cls._tmp.name))
        cls._old_home = os.environ.get('HOME')
        os.environ['HOME'] = str(cls.home)
        cls.policy = cg.load_policy(path=str(cls.home / 'no-such-policy.json'))

    @classmethod
    def tearDownClass(cls):
        if cls._old_home is not None:
            os.environ['HOME'] = cls._old_home
        cls._tmp.cleanup()

    def setUp(self):
        Base._n = getattr(Base, '_n', 0) + 1
        self.n = Base._n
        self.base = self.home / '.agent-harness' / 'work' / 'S2' / ('T%d' % self.n)
        self.base.mkdir(parents=True)
        self.origin = self.home / ('origin%d.git' % self.n)
        seed = self.home / ('seed%d' % self.n)
        seed.mkdir()
        git(seed, 'init', '-q', '-b', 'main')
        (seed / 'a.txt').write_text('one\n')
        git(seed, 'add', '.')
        git(seed, 'commit', '-q', '-m', 'one')
        git(self.home, 'clone', '-q', '--bare', str(seed), str(self.origin))
        self.seed = seed
        self.clone = self.make_clone(self.base / 'clone')
        self.refresh_live()
        for name, value in (('REMOTE_LS', lambda url, cwd, timeout: dict(self.live)),
                            ('busy_scan', lambda path, skip=(), created=None: dict(QUIET_SCAN)),
                            ('open_files_inside', lambda path, timeout=60: [])):
            patch = mock.patch.object(cg, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def make_clone(self, where):
        git(self.home, 'clone', '-q', str(self.origin), str(where))
        git(where, 'remote', 'set-url', 'origin', URL)  # what a GitHub clone looks like
        return where

    def refresh_live(self):
        out = git(self.origin, 'for-each-ref', '--format=%(refname) %(objectname)')
        self.live = dict(line.split(' ') for line in out.splitlines())

    def push_to_origin(self, branch='main'):
        """Publish the clone's branch to the stand-in origin and refresh the live answer."""
        git(self.origin, 'fetch', '-q', str(self.clone), '%s:%s' % (branch, branch))
        git(self.clone, 'update-ref', 'refs/remotes/origin/%s' % branch, branch)
        self.refresh_live()

    def verify(self, path=None, **kwargs):
        return cg.verify_clone(str(path or self.clone), policy=self.policy, **kwargs)

    def assertRefused(self, report, mention):
        self.assertFalse(report['removable'], report)
        self.assertIn(mention, report['reason'] or '')
        self.assertTrue(self.clone.is_dir())

    def audit_rows(self):
        path = self.home / '.agent-harness' / cg.CLONE_AUDIT
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


class Removable(Base):
    def test_clean_pushed_clone_is_verified_then_removed(self):
        report = self.verify()
        self.assertTrue(report['removable'], report)
        self.assertEqual(report['head'], git(self.clone, 'rev-parse', 'HEAD'))
        self.assertEqual(report['remotes'], {'origin': [URL]})
        self.assertEqual(report['local_refs'], 1)
        self.assertIn('refs/heads/main', report['local_ref_names'])
        self.assertGreater(report['bytes'], 0)
        self.assertEqual(report['process_check']['open_files_inside'], 0)
        self.assertEqual(report['clone_verifier'], cg.CLONE_VERIFIER_VERSION)
        result = cg.remove_clone(str(self.clone), policy=self.policy)
        self.assertTrue(result['removed'], result)
        self.assertFalse(os.path.lexists(self.clone))
        self.assertEqual(os.listdir(self.base), [])  # no quarantine left behind
        rows = self.audit_rows()
        self.assertEqual([r['event'] for r in rows], ['move-aside', 'result'])
        self.assertTrue(os.path.basename(rows[0]['quarantine']).startswith('.clone.clone-remove-'))
        self.assertEqual(rows[0]['head'], report['head'])
        self.assertTrue(rows[1]['removed'])

    def test_regenerable_ignored_dirs_do_not_matter(self):
        (self.clone / '.git' / 'info' / 'exclude').write_text('node_modules/\n__pycache__/\n')
        (self.clone / 'node_modules').mkdir()
        (self.clone / 'node_modules' / 'x.js').write_text('1')
        self.assertTrue(self.verify()['removable'])

    def test_token_in_the_remote_url_is_never_shown(self):
        git(self.clone, 'remote', 'set-url', 'origin', 'https://x-token:SECRETVALUE123@github.com/acme/widgets.git')
        report = self.verify()
        self.assertTrue(report['removable'], report)
        self.assertNotIn('SECRETVALUE123', json.dumps(report))
        cg.remove_clone(str(self.clone), policy=self.policy)
        self.assertNotIn('SECRETVALUE123', (self.home / '.agent-harness' / cg.CLONE_AUDIT).read_text())

    def test_stale_tracking_ref_whose_commits_are_merged_is_fine(self):
        git(self.origin, 'branch', 'old', 'main')
        git(self.clone, 'fetch', '-q', str(self.origin), '+refs/heads/old:refs/remotes/origin/old')
        git(self.origin, 'branch', '-D', 'old')
        self.refresh_live()
        report = self.verify()
        self.assertTrue(report['removable'], report)
        self.assertEqual(report['stale_tracking_refs'], 1)

    def test_private_repository_through_the_hosts_own_credentials(self):
        with mock.patch.object(cg, 'REMOTE_LS', side_effect=ValueError('anonymous ls-remote failed')), \
                mock.patch.object(cg, 'authenticated_remote_refs', lambda url, cwd, timeout: dict(self.live)):
            self.assertRefused(self.verify(), 'did not answer')
            self.assertTrue(self.verify(authenticated=True)['removable'])


class Refused(Base):
    def test_unpushed_commit(self):
        (self.clone / 'b.txt').write_text('two\n')
        git(self.clone, 'add', '.')
        git(self.clone, 'commit', '-q', '-m', 'local only')
        self.assertRefused(self.verify(), 'not on the remote')
        result = cg.remove_clone(str(self.clone), policy=self.policy)
        self.assertFalse(result['removed'])
        self.assertTrue((self.clone / 'b.txt').is_file())

    def test_unpushed_tag(self):
        (self.clone / 'b.txt').write_text('two\n')
        git(self.clone, 'add', '.')
        git(self.clone, 'commit', '-q', '-m', 'tagged only')
        git(self.clone, 'tag', 'keep')
        git(self.clone, 'reset', '-q', '--hard', 'origin/main')
        git(self.clone, 'reflog', 'expire', '--expire=now', '--all')
        self.assertRefused(self.verify(), 'not on the remote')

    def test_reflog_only_commit(self):
        (self.clone / 'b.txt').write_text('two\n')
        git(self.clone, 'add', '.')
        git(self.clone, 'commit', '-q', '-m', 'then reset away')
        git(self.clone, 'reset', '-q', '--hard', 'origin/main')
        self.assertRefused(self.verify(), 'not on the remote')

    def test_stash(self):
        (self.clone / 'a.txt').write_text('changed\n')
        git(self.clone, 'stash', '-q')
        self.assertRefused(self.verify(), 'stash')

    def test_modified_staged_and_untracked(self):
        (self.clone / 'a.txt').write_text('changed\n')
        self.assertRefused(self.verify(), 'not clean')
        git(self.clone, 'add', 'a.txt')
        self.assertRefused(self.verify(), 'not clean')
        git(self.clone, 'reset', '-q', '--hard')
        (self.clone / 'notes.txt').write_text('mine\n')
        self.assertRefused(self.verify(), 'not clean')

    def test_ignored_file_outside_the_regenerable_list(self):
        (self.clone / '.git' / 'info' / 'exclude').write_text('.env\n')
        (self.clone / '.env').write_text('TOKEN=x\n')
        self.assertRefused(self.verify(), 'ignored file')

    def test_stale_tracking_ref_with_commits_only_here(self):
        other = self.make_clone(self.home / ('other%d' % self.n))
        git(other, 'remote', 'set-url', 'origin', str(self.origin))
        git(other, 'checkout', '-q', '-b', 'gone')
        (other / 'g.txt').write_text('only on a deleted branch\n')
        git(other, 'add', '.')
        git(other, 'commit', '-q', '-m', 'gone')
        git(other, 'push', '-q', 'origin', 'gone')
        git(self.clone, 'fetch', '-q', str(self.origin), '+refs/heads/gone:refs/remotes/origin/gone')
        git(self.origin, 'branch', '-D', 'gone')
        self.refresh_live()
        self.assertRefused(self.verify(), "remote-tracking ref(s) the remote no longer shows")

    def test_tracking_ref_of_a_remote_that_is_no_longer_configured(self):
        (self.clone / 'b.txt').write_text('only under a dropped remote\n')
        git(self.clone, 'add', '.')
        git(self.clone, 'commit', '-q', '-m', 'dropped')
        git(self.clone, 'update-ref', 'refs/remotes/gone/work', 'HEAD')
        git(self.clone, 'reset', '-q', '--hard', 'origin/main')
        git(self.clone, 'reflog', 'expire', '--expire=now', '--all')
        self.assertRefused(self.verify(), "remote-tracking ref(s) the remote no longer shows")

    def test_remote_branch_moved_since_the_last_fetch(self):
        other = self.make_clone(self.home / ('mover%d' % self.n))
        git(other, 'remote', 'set-url', 'origin', str(self.origin))
        (other / 'm.txt').write_text('newer\n')
        git(other, 'add', '.')
        git(other, 'commit', '-q', '-m', 'newer')
        git(other, 'push', '-q', 'origin', 'main')
        self.refresh_live()
        self.assertRefused(self.verify(), 'moved since the last fetch')

    def test_any_linked_worktree_present_or_prunable(self):
        git(self.clone, 'worktree', 'add', '-q', str(self.base / 'wt'), '-b', 'side')
        self.assertRefused(self.verify(), 'linked worktree')
        shutil.rmtree(self.base / 'wt')  # its directory is gone, its admin entry is not
        self.assertRefused(self.verify(), 'linked worktree')

    def test_remote_that_does_not_answer(self):
        self.live = {}
        self.assertRefused(self.verify(), 'did not answer')


class Scope(Base):
    def test_outside_the_agent_work_dirs(self):
        elsewhere = self.make_clone(self.home / 'repos' / ('c%d' % self.n))
        report = self.verify(elsewhere)
        self.assertFalse(report['removable'])
        self.assertIn('only a clone inside an agent work dir', report['reason'])

    def test_the_session_work_dir_itself(self):
        report = self.verify(self.home / '.agent-harness' / 'work' / 'S2')
        self.assertIn('session work dir itself', report['reason'])

    def test_wal_log_transcript_and_state_locations(self):
        for segment in ('logs', 'wals', 'Transcripts', 'state', 'wal-archive', 'run.log'):
            target = self.make_clone(self.base / segment / 'c')
            report = self.verify(target)
            self.assertFalse(report['removable'], segment)
            self.assertRegex(report['reason'], 'WAL|log|transcript|state', segment)
            self.assertTrue(target.is_dir())

    def test_release_named_segments_are_an_assumption(self):
        for segment in ('pp-release-7', 'deploy', 'rollback_tmp'):
            report = self.verify(self.make_clone(self.base / segment / 'c'))
            self.assertIn('ASSUMPTION', report['reason'] or '', segment)

    def test_a_checkout_the_release_tooling_names(self):
        tooling = self.home / '.agent-harness' / 'bin' / 'pp-release'
        tooling.parent.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: tooling.unlink() if tooling.exists() or tooling.is_symlink() else None)
        tooling.write_text('RELEASE=~/pp-release\nSTAGE=$HOME/pp-staging\n')
        self.assertTrue(self.verify()['removable'])
        tooling.write_text('WORK="$HOME/.agent-harness/work/S2/T%d"\n' % self.n)  # names the clone's parent
        self.assertIn('release tooling names', self.verify()['reason'])
        tooling.write_text('cd ~/.agent-harness/work/S2/T%d/clone && ./deploy/release.sh\n' % self.n)
        self.assertIn('release tooling names', self.verify()['reason'])
        tooling.unlink()
        tooling.mkdir()
        self.addCleanup(lambda: tooling.rmdir() if tooling.is_dir() else None)
        self.assertIn('not a plain file', self.verify()['reason'])

    def test_symlinked_path(self):
        link = self.base / 'link'
        os.symlink(self.clone, link)
        self.assertIn('symlink', self.verify(link)['reason'])
        self.assertTrue(self.clone.is_dir())


class RemoveSafety(Base):
    def test_a_change_after_the_verification_moves_the_clone_back(self):
        def edit(quarantine):
            Path(quarantine, 'late.txt').write_text('written after the verification\n')
        result = cg.remove_clone(str(self.clone), policy=self.policy, _after_rename=edit)
        self.assertFalse(result['removed'])
        self.assertIn('changed after it was verified', result['reason'])
        self.assertTrue((self.clone / 'late.txt').is_file())
        self.assertEqual(sorted(os.listdir(self.base)), ['clone'])
        rows = self.audit_rows()
        self.assertEqual([r['event'] for r in rows], ['move-aside', 'result'])
        self.assertTrue(rows[1]['restored'])

    def test_a_commit_after_the_verification_moves_the_clone_back(self):
        def commit(quarantine):
            Path(quarantine, 'b.txt').write_text('two\n')
            git(quarantine, 'add', '.')
            git(quarantine, 'commit', '-q', '-m', 'late')
        result = cg.remove_clone(str(self.clone), policy=self.policy, _after_rename=commit)
        self.assertFalse(result['removed'])
        self.assertTrue(self.clone.is_dir())

    def test_a_process_after_the_move_moves_the_clone_back(self):
        def busy(quarantine):
            cg.open_files_inside = lambda path, timeout=60: [(4242, 'editor')]
        result = cg.remove_clone(str(self.clone), policy=self.policy, _after_rename=busy)
        self.assertFalse(result['removed'])
        self.assertIn('file open inside', result['reason'])
        self.assertTrue(self.clone.is_dir())

    def test_an_unwritable_audit_moves_nothing(self):
        audit = self.home / '.agent-harness' / cg.CLONE_AUDIT
        if audit.exists():
            audit.unlink()
        audit.mkdir(parents=True)
        self.addCleanup(audit.rmdir)
        result = cg.remove_clone(str(self.clone), policy=self.policy)
        self.assertFalse(result['removed'])
        self.assertIn('audit row', result['reason'])
        self.assertTrue(self.clone.is_dir())


class HookUnchanged(Base):
    """The guard's own rm exemption keeps its rules: the delegated additions are off unless asked for."""

    def test_an_empty_registry_still_refuses_in_the_hook(self):
        (self.clone / '.git' / 'worktrees').mkdir()
        self.assertEqual(cg.reproducible_clone_refusal(str(self.clone), self.policy), 'it owns linked worktrees')
        self.assertTrue(self.verify()['removable'])

    def test_the_hook_reason_text_is_unchanged(self):
        (self.clone / 'b.txt').write_text('two\n')
        git(self.clone, 'add', '.')
        git(self.clone, 'commit', '-q', '-m', 'local only')
        self.assertEqual(cg.reproducible_clone_refusal(str(self.clone), self.policy),
                         '1 local commit(s) are not on the remote')


class Processes(Base):
    """The real scans (lsof and, on Linux, /proc) against real processes."""

    def setUp(self):
        super().setUp()
        mock.patch.stopall()  # undo the fast fakes for the scans, keep a fake network
        patch = mock.patch.object(cg, 'REMOTE_LS', lambda url, cwd, timeout: dict(self.live))
        patch.start()
        self.addCleanup(patch.stop)

    def spawn(self, code, cwd):
        process = subprocess.Popen([sys.executable, '-c', code], cwd=str(cwd), stdout=subprocess.PIPE)
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        self.assertEqual(process.stdout.readline().strip(), b'ready')
        return process

    def test_no_process_inside_passes_the_real_scans(self):
        report = self.verify()
        self.assertTrue(report['removable'], report)
        self.assertEqual(report['process_check']['open_files_inside'], 0)

    def test_a_process_working_inside_refuses(self):
        self.spawn('import sys, time; print("ready", flush=True); time.sleep(60)', self.clone)
        report = self.verify()
        self.assertFalse(report['removable'])
        self.assertRegex(report['reason'], 'working directory|file open inside')

    def test_a_process_with_a_file_open_inside_refuses(self):
        target = self.clone / 'a.txt'
        self.spawn('import time; f = open(%r); print("ready", flush=True); time.sleep(60)' % str(target), self.home)
        report = self.verify()
        self.assertFalse(report['removable'])
        self.assertIn('file open inside', report['reason'])

    def test_no_lsof_refuses(self):
        with mock.patch.object(cg, '_lsof_exe', lambda: None):
            self.assertIsNone(cg.open_files_inside(str(self.clone)))
            with mock.patch.object(cg, 'busy_scan', lambda path, skip=(), created=None: dict(QUIET_SCAN)):
                self.assertIn('could not list the open files', self.verify()['reason'])


class FakeRunner:
    """Answers `ah owners` and the verifier the way the real programs print them, and records every call."""

    def __init__(self, owners=None, verifier=None):
        self.calls = []
        self.owners = owners if owners is not None else {'local': owners_answer([])}
        self.verifier = verifier if verifier is not None else {'removable': True, 'removed': True, 'head': 'a' * 40,
                                                                'clone_verifier': 1}

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        where = argv[argv.index('--') + 1] if argv[0] == 'ssh' else 'local'
        text = ' '.join(argv)
        if ' owners ' in text:
            answer = self.owners.get(where, {'ok': False, 'code': 'session_unknown'})
        else:
            answer = self.verifier
        out = answer if isinstance(answer, str) else json.dumps(answer)
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr='')

    def verifier_calls(self):
        return [c for c in self.calls if ' owners ' not in ' '.join(c)]


def owners_answer(rows, read=None):
    return {'session': 'S2', 'owners': rows, 'read': read or {'state': 'ok', 'unread_total': 0, 'limited': False}}


OLD = '2026-11-01T00:00:00Z'


class CallerSide(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='ah-clonerm-')
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(os.path.realpath(self._tmp.name))
        self.path = '/home/eric/.agent-harness/work/S2/T1/clone'
        self.now = time.time()

    def run_remove(self, runner, **kwargs):
        args = dict(host='local', path=self.path, reason='finished, pushed clone', home=self.home, runner=runner,
                    now=self.now)
        args.update(kwargs)
        return ah_clone.remove(**args)

    def audit_rows(self):
        path = self.home / '.agent-harness' / ah_clone.AUDIT_NAME
        return [json.loads(line) for line in path.read_text().splitlines()]

    def test_not_live_session_reaches_the_fixed_verifier(self):
        runner = FakeRunner(owners={'local': owners_answer([{'agent_id': 'a1', 'state': 'done', 'last_activity': OLD}])})
        answer = self.run_remove(runner)
        self.assertTrue(answer['ok'], answer)
        self.assertTrue(answer['removed'])
        call = runner.verifier_calls()[0]
        self.assertEqual(call[-3:], ['remove-clone', '--path', self.path])
        self.assertEqual([r['event'] for r in self.audit_rows()], ['start', 'result'])
        self.assertEqual(answer['liveness']['hosts'], {'local': 'not live (1 owner rows)'})

    def test_check_runs_the_verify_only_form_and_remote_auth_only_when_asked(self):
        runner = FakeRunner(verifier={'removable': True, 'head': 'b' * 40, 'clone_verifier': 1})
        answer = self.run_remove(runner, check=True)
        self.assertTrue(answer['ok'])
        self.assertFalse(answer['removed'])
        self.assertEqual(runner.verifier_calls()[0][-3:], ['verify-clone', '--path', self.path])
        runner = FakeRunner()
        self.run_remove(runner, authenticated=True)
        self.assertEqual(runner.verifier_calls()[0][-1], '--remote-auth')

    def test_a_live_owner_refuses_before_the_verifier_runs(self):
        for state in ('live', 'quiet', 'working', 'waiting-on-w0123456789a'):
            runner = FakeRunner(owners={'local': owners_answer([{'agent_id': 'a1', 'state': state,
                                                                 'last_activity': OLD}])})
            answer = self.run_remove(runner)
            self.assertFalse(answer['ok'])
            self.assertIn('is live', answer['reason'], state)
            self.assertEqual(runner.verifier_calls(), [])

    def test_recent_owner_activity_refuses(self):
        recent = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(self.now - 3600))
        runner = FakeRunner(owners={'local': owners_answer([{'agent_id': 'a1', 'state': 'SILENT-HIGH',
                                                             'last_activity': recent}])})
        self.assertIn('active 60 min ago', self.run_remove(runner)['reason'])
        self.assertEqual(runner.verifier_calls(), [])

    def test_a_recently_written_main_wal_refuses(self):
        wal = self.home / '.claude' / 'wals' / 'S2' / 'main.jsonl'
        wal.parent.mkdir(parents=True)
        wal.write_text('{}\n')
        runner = FakeRunner()
        self.assertIn('main WAL here was written', self.run_remove(runner)['reason'])
        self.assertEqual(runner.calls, [])

    def test_liveness_that_cannot_be_read_refuses(self):
        for answer in ({'ok': False, 'code': 'session_unknown'}, owners_answer([], {'state': 'partial'}),
                       owners_answer([], {'state': 'ok', 'unread_total': 2}), 'not json',
                       {'ok': False, 'code': 'internal'}):
            runner = FakeRunner(owners={'local': answer})
            result = self.run_remove(runner)
            self.assertFalse(result['ok'], answer)
            self.assertRegex(result['reason'], 'cannot be read|could not read|could not be read', answer)
            self.assertEqual(runner.verifier_calls(), [])

    def test_a_remote_path_checks_both_hosts(self):
        runner = FakeRunner(owners={'t2-dev': owners_answer([{'agent_id': 'a1', 'state': 'done', 'last_activity': OLD}])})
        answer = self.run_remove(runner, host='t2-dev')
        self.assertTrue(answer['ok'], answer)
        self.assertEqual(answer['liveness']['hosts'], {'local': 'unknown', 't2-dev': 'not live (1 owner rows)'})
        self.assertEqual(runner.verifier_calls()[0][:2], ['ssh', '-o'])
        runner = FakeRunner(owners={'local': owners_answer([]),
                                    't2-dev': owners_answer([{'agent_id': 'a2', 'state': 'live'}])})
        self.assertIn('is live on t2-dev', self.run_remove(runner, host='t2-dev')['reason'])

    def test_answers_that_leave_the_outcome_unknown(self):
        for verifier, code in (({'removable': True, 'removed': True}, 'verifier_outdated'),
                               ({'removable': False, 'removed': True, 'clone_verifier': 1}, 'host_unreachable'),
                               ('garbled', 'host_unreachable')):
            with self.assertRaises(ah_clone.CloneError) as raised:
                self.run_remove(FakeRunner(verifier=verifier))
            self.assertEqual(raised.exception.code, code)
        answer = self.run_remove(FakeRunner(verifier={'removable': True, 'removed': False, 'clone_verifier': 1,
                                                      'reason': 'the deletion did not complete'}))
        self.assertIsNone(answer['removed'])
        self.assertIn('outcome is unknown', answer['reason'])

    def test_bad_requests_never_run_anything(self):
        runner = FakeRunner()
        for path in ('/home/eric/repos/x', '/home/eric/.agent-harness/work/S2', 'relative/path', '/a/../b'):
            with self.assertRaises(ah_clone.CloneError):
                self.run_remove(runner, path=path)
        with self.assertRaises(ah_clone.CloneError):
            self.run_remove(runner, reason='')
        self.assertEqual(runner.calls, [])

    def test_the_first_audit_row_fails_closed(self):
        (self.home / '.agent-harness').mkdir()
        (self.home / '.agent-harness' / ah_clone.AUDIT_NAME).mkdir()
        runner = FakeRunner()
        with self.assertRaises(ah_clone.CloneError) as raised:
            self.run_remove(runner)
        self.assertEqual(raised.exception.code, 'audit_failed')
        self.assertEqual(runner.calls, [])

    def test_the_cli_prints_one_json_line_and_never_a_traceback(self):
        out = subprocess.run([sys.executable, '-I', str(HOOKS / 'ah.py'), 'clone-remove', '--host', 'local',
                              '--path', '/nowhere/x', '--reason', 'r'], capture_output=True, text=True,
                             env=dict(os.environ, HOME=str(self.home)))
        data = json.loads(out.stdout)
        self.assertFalse(data['ok'])
        self.assertEqual(data['code'], 'bad_request')
        self.assertEqual(out.returncode, 2)
        self.assertNotIn('Traceback', out.stderr)
        with mock.patch.object(ah_clone, 'remove', side_effect=RuntimeError('boom')):
            with mock.patch('sys.stdout', new_callable=__import__('io').StringIO) as stdout:
                self.assertEqual(ah_clone.cli_main(['--host', 'local', '--path', self.path, '--reason', 'r']), 4)
            self.assertEqual(json.loads(stdout.getvalue())['code'], 'internal')

    def test_both_installers_ship_the_module(self):
        for installer in ('install.py', 'install_codex.py'):
            self.assertRegex((ROOT / installer).read_text(), r'''["']ah_clone\.py["']''', installer)


if __name__ == '__main__':
    unittest.main()
