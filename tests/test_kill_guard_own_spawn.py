"""goodqa#15565: an agent may stop the processes its own background Bash calls started, and nobody else may.

Before this fix the only ledger route was `kill_guard.py spawn -- CMD`, so `rclone copy /a dropbox:b` started with
run_in_background (cwd and program outside the worktree) could not be stopped by the agent that started it.

What is tested here:
  * authenticated "group" ledger rows: a recorded tool-call shell S (pid + start time) owns itself, every process whose
    parent chain reaches S, and every member of process group S; a recycled S (other start time) owns nothing;
  * `kill_guard.py record-bg` (PostToolUse on Bash): it records S only for a run_in_background call, and only when S is
    a live direct child of the hook's own ancestor (the session process), the leader of its own session and process
    group, owned by the caller, and has stdout or stderr open on tasks/<backgroundTaskId>.output;
  * bg_job.py launch records its wrapper (a new session) the same way, so `kill CHILD` works for the job;
  * the PostToolUse hook is registered by install.py.

Every process here is described by a fake probe, except the bg_job test, which starts and then stops its own `sleep`
job through bg_job's own process-group stop. No kill command is executed: kill_guard.decide() only analyses text.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('KG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))

import kill_guard as kg  # noqa: E402

ME = os.getuid()
CLAUDE, HOOK_SH = 9000, 9001          # the hook's ancestors: os.getpid() -> HOOK_SH -> CLAUDE -> 1
SHELL, RCLONE, ORPHAN = 7000, 7001, 7002
TASK = 'b7ioa0ay5'
TASKFILE = '/s/claude-501/proj/sess/tasks/%s.output' % TASK


def proc(ppid, start, comm='sleep', cwd='/elsewhere', argv=None, pgid=None, sid=None, uid=None, fds=()):
    return {'ppid': ppid, 'start': start, 'comm': comm, 'cwd': cwd, 'argv': argv or [comm, 'x'], 'pgid': pgid,
            'sid': sid, 'uid': ME if uid is None else uid, 'fds': list(fds)}


class FakeProbe:
    """Process facts from a dict. Never touches a real process."""

    def __init__(self, procs):
        # As measured live: a hook is a direct child of claude with fd 1 and fd 2 on two socketpairs claude holds;
        # every tool shell (HOOK_SH here stands for one) holds one more socketpair to claude.
        self.procs = {os.getpid(): proc(CLAUDE, 'self', comm='python3', argv=['python3', 'kill_guard.py']),
                      HOOK_SH: proc(CLAUDE, 'hs', comm='zsh', argv=['/bin/zsh', '-c', 'x'], fds=[TASKFILE + '.mine']),
                      CLAUDE: proc(1, 'cl', comm='claude', argv=['claude'])}
        self.procs.update(procs)
        self.start_reads = {}
        self.stdio = {os.getpid(): {1: ('0xa1', '0xb1'), 2: ('0xa2', '0xb2')}}
        self.sockets = {CLAUDE: {'0xb1': '0xa1', '0xb2': '0xa2', '0xd11': '0xc11'}, HOOK_SH: {'0xc11': '0xd11'}}

    def stdio_sockets(self, pid):
        return dict(self.stdio.get(pid, {}))

    def unix_sockets(self, pid):
        return dict(self.sockets.get(pid, {}))

    def _get(self, pid, key):
        entry = self.procs.get(pid)
        return None if entry is None else entry[key]

    def uid(self, pid):
        return self._get(pid, 'uid')

    def comm(self, pid):
        return self._get(pid, 'comm')

    def cwd(self, pid):
        return self._get(pid, 'cwd')

    def argv(self, pid):
        return self._get(pid, 'argv')

    def start(self, pid):
        self.start_reads[pid] = self.start_reads.get(pid, 0) + 1
        value = self._get(pid, 'start')
        return value(self.start_reads[pid]) if callable(value) else value

    def ppid(self, pid):
        return self._get(pid, 'ppid')

    def pgid(self, pid):
        entry = self.procs.get(pid)
        return None if entry is None else (entry['pgid'] if entry['pgid'] is not None else pid)

    def sid(self, pid):
        entry = self.procs.get(pid)
        return None if entry is None else (entry['sid'] if entry['sid'] is not None else pid)

    def table(self):
        return {pid: (p['ppid'], self.pgid(pid), p['uid']) for pid, p in self.procs.items()}

    def fd_paths(self, pids):
        return {pid: set(self.procs[pid]['fds']) for pid in pids if pid in self.procs}


def rclone_world(**shell_overrides):
    """The incident: a run_in_background call whose shell S started rclone, whose cwd and program are outside."""
    shell = proc(CLAUDE, 'S-start', comm='zsh', argv=['/bin/zsh', '-c', 'eval x'], fds=[TASKFILE])
    shell.update(shell_overrides)
    return {SHELL: shell,
            RCLONE: proc(SHELL, 'R-start', comm='rclone', cwd='/Users/x', argv=['/opt/bin/rclone', 'copy'], pgid=SHELL,
                         sid=SHELL, fds=[TASKFILE]),
            # nohup rclone & exit: reparented to launchd, still in group S
            ORPHAN: proc(1, 'O-start', comm='rclone', cwd='/Users/x', argv=['/opt/bin/rclone', 'copy'], pgid=SHELL,
                         sid=SHELL, fds=[TASKFILE])}


def payload(cwd, task=TASK, tool='Bash', response=None):
    return {'hook_event_name': 'PostToolUse', 'tool_name': tool, 'cwd': cwd, 'session_id': 's1',
            'tool_input': {'command': 'rclone copy /a dropbox:b', 'run_in_background': True},
            'tool_response': response if response is not None else {'stdout': '', 'stderr': '', 'interrupted': False,
                                                                     'backgroundTaskId': task}}


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = os.path.realpath(tmp.name)
        self.root = os.path.join(self.home, 'work', 'wt-a')
        self.other = os.path.join(self.home, 'work', 'wt-b')
        for path in (self.root, self.other):
            os.makedirs(path)
        env = mock.patch.dict(os.environ, {'HOME': self.home})
        env.start()
        self.addCleanup(env.stop)

    def runner(self, root):
        return lambda argv, *a, **k: (root + '\n') if 'rev-parse' in argv else ''

    def own(self, probe, root=None):
        root = root or self.root
        return kg.Ownership(root, home=self.home, probe=probe, runner=self.runner(root), policy=kg.load_policy())

    def record(self, probe, root=None, **kw):
        root = root or self.root
        return kg.record_bg(payload(root, **kw), home=self.home, probe=probe, runner=self.runner(root))


class GroupLedger(Base):
    def test_root_child_and_orphan_are_owned(self):
        probe = FakeProbe(rclone_world())
        kg.append_ledger(self.root, SHELL, 'S-start', home=self.home, kind='group')
        for pid in (SHELL, RCLONE, ORPHAN):
            with self.subTest(pid=pid):
                ok, code, _ = self.own(probe).check(pid)
                self.assertTrue(ok, code)
                self.assertEqual(code, 'ledger-group')

    def test_orphan_owned_after_root_shell_exited(self):
        world = rclone_world()
        del world[SHELL]
        del world[RCLONE]
        kg.append_ledger(self.root, SHELL, 'S-start', home=self.home, kind='group')
        self.assertEqual(self.own(FakeProbe(world)).check(ORPHAN)[:2], (True, 'ledger-group'))

    def test_live_root_with_unreadable_start_owns_nothing(self):
        # S still runs (its uid is readable) but its start time cannot be read: not proof that S is gone
        probe = FakeProbe(rclone_world(start=None))
        kg.append_ledger(self.root, SHELL, 'S-start', home=self.home, kind='group')
        self.assertFalse(self.own(probe).check(ORPHAN)[0])

    def test_other_worktree_is_refused(self):
        probe = FakeProbe(rclone_world())
        kg.append_ledger(self.root, SHELL, 'S-start', home=self.home, kind='group')
        for pid in (SHELL, RCLONE, ORPHAN):
            with self.subTest(pid=pid):
                ok, code, _ = self.own(probe, self.other).check(pid)
                self.assertFalse(ok)
                self.assertEqual(code, 'outside')

    def test_recycled_root_owns_nothing(self):
        # pid 7000 now belongs to a newer process: same pid, other start time
        probe = FakeProbe(rclone_world(start='newer'))
        kg.append_ledger(self.root, SHELL, 'S-start', home=self.home, kind='group')
        for pid in (SHELL, RCLONE, ORPHAN):
            with self.subTest(pid=pid):
                self.assertFalse(self.own(probe).check(pid)[0])

    def test_unrelated_process_is_refused(self):
        world = rclone_world()
        world[7100] = proc(1, 'u', comm='rclone', cwd='/Users/x', argv=['/opt/bin/rclone', 'sync'], pgid=7100)
        world[7101] = proc(CLAUDE, 'v', comm='rclone', cwd='/Users/x', argv=['/opt/bin/rclone', 'sync'], pgid=7101)
        kg.append_ledger(self.root, SHELL, 'S-start', home=self.home, kind='group')
        for pid in (7100, 7101):
            with self.subTest(pid=pid):
                self.assertFalse(self.own(FakeProbe(world)).check(pid)[0])

    def test_plain_row_is_not_a_group_row(self):
        # `kill_guard.py spawn` rows prove only their own pid, never its group
        probe = FakeProbe(rclone_world())
        kg.append_ledger(self.root, SHELL, 'S-start', home=self.home)
        self.assertEqual(self.own(probe).check(SHELL)[:2], (True, 'ledger'))
        self.assertFalse(self.own(probe).check(ORPHAN)[0])

    def test_tampered_rows_are_ignored(self):
        probe = FakeProbe(rclone_world())
        kg.append_ledger(self.root, SHELL, 'S-start', home=self.home)
        path = kg.ledger_path(self.root, self.home)
        row = json.loads(Path(path).read_text().splitlines()[0])
        promoted = dict(row, kind='group')               # a plain row relabelled as a group row
        other_pid = dict(row, pid=7100, kind='group')    # mac no longer matches
        weird = dict(row, kind='admin')
        lines = [json.dumps(r) for r in (promoted, other_pid, weird)]
        lines += ['not json', '{"pid": "x"}', json.dumps({'pid': 7000, 'start': ['S'], 'ts': 1, 'root': self.root,
                                                          'mac': 'f' * 64, 'kind': 'group'}), 'x' * 200000]
        Path(path).write_text('\n'.join(lines) + '\n')
        os.chmod(str(path), 0o600)
        self.assertFalse(self.own(probe).check(ORPHAN)[0])
        self.assertFalse(self.own(probe).check(SHELL)[0])
        self.assertEqual(kg.read_ledger_groups(self.root, self.home), [])

    def test_group_row_stripped_of_its_kind_is_not_a_plain_row(self):
        kg.append_ledger(self.root, SHELL, 'S-start', home=self.home, kind='group')
        path = kg.ledger_path(self.root, self.home)
        row = json.loads(Path(path).read_text().splitlines()[0])
        row.pop('kind')
        Path(path).write_text(json.dumps(row) + '\n')
        self.assertEqual(kg.read_ledger(self.root, self.home), [])
        self.assertEqual(kg.read_ledger_groups(self.root, self.home), [])

    def test_old_readers_ignore_group_rows(self):
        kg.append_ledger(self.root, SHELL, 'S-start', home=self.home, kind='group')
        self.assertEqual(kg.read_ledger(self.root, self.home), [])
        self.assertEqual(kg.read_ledger_groups(self.root, self.home), [(SHELL, 'S-start')])

    def test_ledger_stays_bounded(self):
        for n in range(6000):
            kg.append_ledger(self.root, 10000 + n, 'st%d' % n, home=self.home, kind='group')
        size = os.path.getsize(str(kg.ledger_path(self.root, self.home)))
        self.assertLess(size, kg.LEDGER_COMPACT_BYTES + 4096)
        self.assertIn((15999, 'st5999'), kg.read_ledger_groups(self.root, self.home))
        mode = os.stat(str(kg.ledger_path(self.root, self.home))).st_mode & 0o777
        self.assertEqual(mode, 0o600)


class RecordBg(Base):
    def test_records_the_background_shell_and_the_agent_may_stop_rclone(self):
        probe = FakeProbe(rclone_world())
        pid, why = self.record(probe)
        self.assertEqual((pid, why), (SHELL, 'recorded'))
        self.assertEqual(kg.read_ledger_groups(self.root, self.home), [(SHELL, 'S-start')])
        for target in (RCLONE, ORPHAN):
            verdict, rule, message, _ = kg.decide('kill %d' % target, cwd=self.root + '/sub',
                                                  ownership=self.own(probe), home=self.home)
            self.assertEqual(verdict, 'allow', message)
        # another agent, in another worktree, is still refused
        verdict, _, message, _ = kg.decide('kill %d' % RCLONE, cwd=self.other, ownership=self.own(probe, self.other),
                                           home=self.home)
        self.assertEqual(verdict, 'block', message)

    def test_before_recording_the_kill_is_refused(self):
        verdict, _, message, _ = kg.decide('kill %d' % RCLONE, cwd=self.root, ownership=self.own(FakeProbe(rclone_world())),
                                           home=self.home)
        self.assertEqual(verdict, 'block', message)

    def assertNothing(self, result, code=None):
        pid, why = result
        self.assertIsNone(pid, why)
        if code:
            self.assertEqual(why, code)
        self.assertEqual(kg.read_ledger_groups(self.root, self.home), [])
        self.assertEqual(kg.read_ledger_groups(self.other, self.home), [])

    def test_foreground_call_has_no_task_id(self):
        self.assertNothing(kg.record_bg(payload(self.root, response={'stdout': '', 'stderr': ''}), home=self.home,
                                        probe=FakeProbe(rclone_world()), runner=self.runner(self.root)), 'not-background')

    def test_hostile_task_ids(self):
        for task in ('../tasks/x', 'a/b', '', 'x' * 65, 'a b', 7, None, 'a\nb'):
            with self.subTest(task=task):
                self.assertNothing(self.record(FakeProbe(rclone_world()), task=task))

    def test_other_tools_and_garbage(self):
        self.assertNothing(self.record(FakeProbe(rclone_world()), tool='Write'))
        for bad in (None, [], 'x', {'tool_name': 'Bash'}, {'tool_name': 'Bash', 'tool_response': 'text'}):
            self.assertNothing(kg.record_bg(bad, home=self.home, probe=FakeProbe(rclone_world()),
                                            runner=self.runner(self.root)))

    def test_shell_must_hold_this_calls_task_file(self):
        for fds in ([], ['/s/claude-501/proj/sess/tasks/zzzz.output'], ['/tmp/%s.output' % TASK],
                    ['/s/tasks/%s.output.bak' % TASK]):
            with self.subTest(fds=fds):
                self.assertNothing(self.record(FakeProbe(rclone_world(fds=fds))), 'no-shell')

    def test_stderr_alone_is_enough(self):
        probe = FakeProbe(rclone_world())
        probe.procs[SHELL]['fds'] = [TASKFILE]  # fd_paths reports fd 1 and fd 2 together
        self.assertEqual(self.record(probe)[0], SHELL)

    def test_shell_must_be_a_child_of_the_hooks_session_process(self):
        world = rclone_world(ppid=4242)
        world[4242] = proc(1, 'other', comm='claude', argv=['claude'])
        self.assertNothing(self.record(FakeProbe(world)), 'no-shell')

    def test_shell_must_lead_its_own_group_and_session(self):
        self.assertNothing(self.record(FakeProbe(rclone_world(pgid=CLAUDE))), 'no-shell')
        self.assertNothing(self.record(FakeProbe(rclone_world(sid=CLAUDE))), 'unproven')

    def test_run_by_hand_from_a_tool_call_records_nothing(self):
        # red-team F1: an agent running record-bg itself, naming another agent's task id
        probe = FakeProbe(rclone_world())
        probe.procs[os.getpid()]['ppid'] = HOOK_SH          # plain: a child of its tool shell
        probe.stdio[os.getpid()] = {}
        self.assertNothing(self.record(probe), 'not-hook')

    def test_redirected_tool_shell_records_nothing(self):
        # `exec >/dev/null 2>&1; python3 kill_guard.py record-bg`: no fd on a tasks file any more, still a child of
        # the tool shell
        probe = FakeProbe(rclone_world())
        probe.procs[os.getpid()]['ppid'] = HOOK_SH
        probe.procs[HOOK_SH]['fds'] = ['/dev/null']
        self.assertNothing(self.record(probe), 'not-hook')

    def test_exec_in_place_of_the_tool_shell_records_nothing(self):
        # `exec python3 kill_guard.py record-bg >/dev/null 2>&1 <payload`: a direct child of claude, output on files
        probe = FakeProbe(rclone_world())
        probe.stdio[os.getpid()] = {}
        self.assertNothing(self.record(probe), 'not-hook')
        # `exec 1>&11 2>&11` first: both fds are the tool shell's one socketpair to claude
        probe.stdio[os.getpid()] = {1: ('0xc11', '0xd11'), 2: ('0xc11', '0xd11')}
        self.assertNothing(self.record(probe), 'not-hook')
        # one claude socket and one socket of its own making
        probe.stdio[os.getpid()] = {1: ('0xc11', '0xd11'), 2: ('0xe1', '0xe2')}
        self.assertNothing(self.record(probe), 'not-hook')

    def test_sockets_paired_with_another_process_record_nothing(self):
        probe = FakeProbe(rclone_world())
        probe.sockets[CLAUDE] = {'0xb1': '0xa1'}
        probe.sockets[4242] = {'0xb2': '0xa2'}
        self.assertNothing(self.record(probe), 'not-hook')
        probe = FakeProbe(rclone_world())
        probe.sockets[CLAUDE] = {'0xb1': '0xa1', '0xb2': '/tmp/listening.sock'}  # not the pair's other end
        self.assertNothing(self.record(probe), 'not-hook')

    def test_no_socket_data_records_nothing(self):
        probe = FakeProbe(rclone_world())
        probe.stdio, probe.sockets = {}, {}  # Linux today, or lsof unreadable
        self.assertNothing(self.record(probe), 'not-hook')

    def test_shell_of_another_user(self):
        self.assertNothing(self.record(FakeProbe(rclone_world(uid=ME + 1))), 'no-shell')

    def test_two_candidates_record_nothing(self):
        world = rclone_world()
        world[7050] = proc(CLAUDE, 'twin', comm='zsh', argv=['/bin/zsh', '-c', 'eval y'], fds=[TASKFILE])
        self.assertNothing(self.record(FakeProbe(world)), 'ambiguous')

    def test_start_time_must_hold_across_the_checks(self):
        world = rclone_world(start=lambda n: 'S-start' if n == 1 else 'recycled')
        self.assertNothing(self.record(FakeProbe(world)), 'unproven')

    def test_shell_already_gone(self):
        world = rclone_world()
        del world[SHELL]
        self.assertNothing(self.record(FakeProbe(world)), 'no-shell')

    def test_main_outside_a_worktree_records_nothing(self):
        probe = FakeProbe(rclone_world())
        out = kg.record_bg(payload(self.home), home=self.home, probe=probe, runner=lambda *a, **k: None)
        self.assertEqual(out, (None, 'no-worktree'))
        self.assertFalse(kg.state_dir(self.home).exists(), 'nothing may be written for a call outside a worktree')

    def test_hook_entry_fails_open_and_quietly(self):
        for data in (b'', b'not json', b'{"tool_name": "Bash"}', b'\xff' * 100):
            with self.subTest(data=data[:20]):
                done = subprocess.run([sys.executable, '-I', str(HOOKS / 'kill_guard.py'), 'record-bg'], input=data,
                                      capture_output=True, timeout=30, env=dict(os.environ, HOME=self.home))
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(done.stdout, b'')


class BgJobLedger(Base):
    """A real bg_job launch inside a real temporary git worktree; the job is stopped by bg_job's own group stop."""

    def test_launch_records_the_job_group(self):
        repo = os.path.join(self.home, 'repo')
        os.makedirs(repo)
        subprocess.run(['git', 'init', '-q', repo], check=True, timeout=30)
        jobs = os.path.join(self.home, 'jobs')
        log = os.path.join(repo, 'job.log')
        done = subprocess.run([sys.executable, str(HOOKS / 'bg_job.py'), 'launch', '--name', 'ownspawn', '--log', log,
                               '--deadline', '20', '--dir', jobs, '--', sys.executable, '-c',
                               'import time,sys; print("up", flush=True); time.sleep(60)'],
                              cwd=repo, capture_output=True, text=True, timeout=60, env=dict(os.environ, HOME=self.home))
        record = json.loads(Path(jobs, 'ownspawn.json').read_text())
        sys.path.insert(0, str(HOOKS))
        import bg_job  # noqa: PLC0415
        self.addCleanup(bg_job.stop_group, record['pid'], record['nonce'])
        self.assertIn('STARTED', done.stdout, done.stdout + done.stderr)
        root = kg.find_worktree(repo, self.home)[0]
        wrapper = record['pid']
        rows = kg.read_ledger_groups(root, self.home)
        self.assertEqual(rows, [(wrapper, kg.Probe().start(wrapper))])
        child = None
        for _ in range(100):
            out = subprocess.run(['ps', '-axo', 'pid=,ppid='], capture_output=True, text=True, timeout=10).stdout
            kids = [int(a) for a, b in (line.split() for line in out.splitlines() if line.strip()) if int(b) == wrapper]
            if kids:
                child = kids[0]
                break
            time.sleep(0.05)
        self.assertIsNotNone(child)
        own = kg.Ownership(repo, home=self.home, policy=kg.load_policy())
        self.assertEqual(own.check(child)[:2], (True, 'ledger-group'))
        elsewhere = os.path.join(self.home, 'repo2')
        os.makedirs(elsewhere)
        subprocess.run(['git', 'init', '-q', elsewhere], check=True, timeout=30)
        self.assertFalse(kg.Ownership(elsewhere, home=self.home, policy=kg.load_policy()).check(child)[0])


class InstallWiring(unittest.TestCase):
    def test_post_tool_use_hook_is_registered(self):
        sys.path.insert(0, str(ROOT))
        import install  # noqa: PLC0415
        claude = Path('/h/.claude')
        hooks = install.managed_hooks(claude)
        entries = [(g.get('matcher'), h) for g in hooks.get('PostToolUse', []) for h in g['hooks']]
        found = [(m, h) for m, h in entries if h.get('args', [])[:1] == [str(claude / 'hooks' / 'kill_guard.py')]]
        self.assertEqual(len(found), 1, entries)
        matcher, hook = found[0]
        self.assertEqual(matcher, 'Bash')
        self.assertEqual(hook['args'][1:], ['record-bg'])
        self.assertNotIn('onFailure', hook, 'a recorder must fail open')
        self.assertNotIn('PostToolUse', install.managed_hooks(claude, command_guard=False))


if __name__ == '__main__':
    unittest.main()
