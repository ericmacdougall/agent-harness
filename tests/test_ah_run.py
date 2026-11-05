"""ah-run launcher core (goodqa#14548): exit pass-through, ledger digests, signals, parent death, kill, mask."""

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import ah_run
import host_table
from tests import shell_sandbox

AH = str(HOOKS / 'ah_run.py')
REAL_SUDO = re.compile(r'''(?:^|[^A-Za-z0-9_.-])s['"\\]*u['"\\]*d['"\\]*o(?:$|[^A-Za-z0-9_.-])''')


def assert_no_real_sudo(command):
    """r6 S30: a shell string that names sudo, however it is quoted, never reaches a shell from a test, generator or fuzz.
    A verdict row may hold it as data; `Differential.printed` skips any row marked `live: false`."""
    if REAL_SUDO.search(command.replace('\\\n', '')):
        raise AssertionError('refusing to run a string that names sudo: %r' % command[:120])


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ahrun-'); self.addCleanup(self.temp.cleanup)
        self.reserve = Path(self.temp.name) / 'reserve'; self.reserve.mkdir(mode=0o700)
        self.env = {**os.environ, 'AGENT_HARNESS_RESERVE_DIR': str(self.reserve), 'LC_ALL': 'C'}
        self.env.pop('CLAUDE_CODE_SHELL_SNAPSHOT', None)

    def run_cmd(self, command, *flags, **kw):
        token = ah_run.mint_pending(self.reserve, command, 't1', 'a1')
        return subprocess.run([sys.executable, AH, 'run', '--task', 't1', '--agent', 'a1', '--token', token, '--no-unit', *flags, '--', command],
                              env=self.env, capture_output=True, text=True, timeout=30, **kw)

    def rows(self):
        return list(ah_run.Ledger(self.reserve).rows())

    def wait_gone(self, pid, seconds=5):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if ah_run.pid_exists(pid) is False:
                return True
            time.sleep(0.05)
        return False


class Launcher(Fixture):
    def test_exit_status_stdout_cwd_and_env_pass_through(self):
        result = self.run_cmd('echo "$AGENT_HARNESS_TASK:$AGENT_ID:$AGENT_HARNESS_RUN_ID"; pwd; exit 3', cwd=self.temp.name)
        self.assertEqual(result.returncode, 3)
        head, cwd = result.stdout.splitlines()[:2]
        self.assertTrue(head.startswith('t1:a1:')); self.assertEqual(len(head.split(':')[2]), 32)
        self.assertEqual(Path(cwd).resolve(), Path(self.temp.name).resolve())

    def test_stdin_is_inherited(self):
        result = self.run_cmd('cat', input='piped in\n')
        self.assertEqual(result.stdout, 'piped in\n')

    def test_ledger_row_holds_digests_never_the_command(self):
        secret = 'ghp_' + 'x' * 30
        self.run_cmd('echo %s >/dev/null' % secret)
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row['task'], row['agent'], row['attribution'], row['exit_code']), ('t1', 'a1', 'verified', 0))
        serialized = json.dumps(row)
        self.assertNotIn(secret, serialized); self.assertNotIn('echo', serialized)
        self.assertEqual(len(row['command_sha256']), 64); self.assertIsNotNone(row['end'])
        self.assertIn('rusage', row)

    def test_missing_task_gets_a_generated_key_and_no_token_is_unverified(self):
        result = subprocess.run([sys.executable, AH, 'run', '--no-unit', '--', 'true'], env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        row = self.rows()[0]
        self.assertTrue(row['task'].startswith('auto-')); self.assertEqual(row['attribution'], 'unverified')
        refused = subprocess.run([sys.executable, AH, 'run', '--readonly', '--no-unit', '--', 'true'], env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(refused.returncode, 126)

    def test_base64_transport(self):
        import base64
        encoded = base64.b64encode(b"printf '%s\\n' \"it's $HOME-free\"").decode()
        result = subprocess.run([sys.executable, AH, 'run', '--task', 't1', '--token', 'via-hook-ssh', '--no-unit', '--cmd-b64', encoded],
                                env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0); self.assertIn("it's", result.stdout)
        self.assertEqual(self.rows()[0]['attribution'], 'hook-ssh')


class Signals(Fixture):
    def start_sleeper(self):
        marker = Path(self.temp.name) / 'pids.txt'
        script = ('sh -c \'echo $$ > %s; sleep 60\' & child=$!; echo $child >> %s; wait' % (marker, marker))
        proc = subprocess.Popen([sys.executable, AH, 'run', '--task', 't1', '--token', 'tok', '--no-unit', '--', script],
                                env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and (not marker.exists() or len(marker.read_text().split()) < 2):
            time.sleep(0.05)
        pids = [int(p) for p in marker.read_text().split()]
        return proc, pids

    def test_sigterm_to_the_launcher_kills_the_whole_group(self):
        proc, pids = self.start_sleeper()
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
        for pid in pids:
            self.assertTrue(self.wait_gone(pid), 'pid %d survived' % pid)
        self.assertEqual(proc.returncode, 128 + signal.SIGTERM)
        self.assertEqual(self.rows()[0]['signal'], int(signal.SIGTERM))

    def test_parent_death_kills_the_group(self):
        marker = Path(self.temp.name) / 'pids2.txt'
        wrapper = ('%s %s run --task t1 --token tok --no-unit -- "sh -c \'echo \\$\\$ > %s; sleep 60\' & echo \\$! >> %s; wait"'
                   % (sys.executable, AH, marker, marker))
        # "; :" keeps sh from exec-ing straight into ah-run, so killing sh is a true parent death.
        parent = subprocess.Popen(['/bin/sh', '-c', wrapper + '; :'], env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and (not marker.exists() or len(marker.read_text().split()) < 2):
            time.sleep(0.05)
        pids = [int(p) for p in marker.read_text().split()]
        os.kill(parent.pid, signal.SIGKILL); parent.wait(timeout=5)
        for pid in pids:
            self.assertTrue(self.wait_gone(pid, 6), 'pid %d survived the parent death' % pid)

    def test_sigkill_on_the_launcher_itself_still_ends_the_group(self):
        proc, pids = self.start_sleeper()
        os.kill(proc.pid, signal.SIGKILL); proc.wait(timeout=5)
        for pid in pids:
            self.assertTrue(self.wait_gone(pid, 8), 'pid %d survived the launcher SIGKILL' % pid)


class SignalEscalation(Fixture):
    """B8: the supervisor owns TERM then KILL, the watchdog survives the forwarded signal and does the same if it dies."""
    BUDGET = ah_run.KILL_GRACE + 1

    def start_term_ignoring(self):
        marker = Path(self.temp.name) / 'pgid.txt'
        command = "trap '' TERM; echo $$ > %s; sleep 60" % marker
        proc = subprocess.Popen([sys.executable, AH, 'run', '--task', 't1', '--no-unit', '--', command], env=self.env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.finish, proc)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not (marker.exists() and marker.read_text().strip()):
            time.sleep(0.02)
        pgid = int(marker.read_text())
        self.groups.append(pgid)
        return proc, pgid

    def setUp(self):
        super().setUp()
        self.env['CLAUDE_CODE_SHELL'] = '/bin/bash'
        self.groups = []
        self.addCleanup(self.kill_groups)

    def kill_groups(self):
        for pgid in self.groups:
            ah_run.kill_group(pgid, signal.SIGKILL)

    @staticmethod
    def finish(proc):
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=10)

    def group_gone_within(self, pgid, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if not ah_run.group_alive(pgid):
                return True
            time.sleep(0.02)
        return False

    def test_sigterm_to_the_launcher_ends_a_term_ignoring_command(self):
        proc, pgid = self.start_term_ignoring()
        proc.send_signal(signal.SIGTERM)
        self.assertFalse(self.group_gone_within(pgid, 0.5), 'the command ignores SIGTERM, so it must outlive the first signal')
        self.assertTrue(self.group_gone_within(pgid, self.BUDGET - 0.5), 'group %d survived SIGTERM plus the grace' % pgid)
        proc.wait(timeout=10)
        self.assertEqual(self.rows()[0]['signal'], int(signal.SIGTERM))

    def test_sigkill_of_the_supervisor_ends_a_term_ignoring_command(self):
        proc, pgid = self.start_term_ignoring()
        proc.kill(); proc.wait(timeout=5)
        self.assertTrue(self.group_gone_within(pgid, self.BUDGET), 'group %d survived the supervisor' % pgid)

    def test_term_then_kill_of_the_supervisor_still_ends_the_group(self):
        proc, pgid = self.start_term_ignoring()
        proc.send_signal(signal.SIGTERM)
        time.sleep(0.2)  # the forward has reached the group, the watchdog included
        proc.kill(); proc.wait(timeout=5)
        self.assertTrue(self.group_gone_within(pgid, self.BUDGET), 'group %d survived TERM then KILL' % pgid)

    def test_a_term_ignoring_leftover_of_a_finished_command_is_ended(self):
        marker = Path(self.temp.name) / 'left.txt'
        result = self.run_cmd("trap '' TERM; echo $$ > %s; sleep 60 & exit 4" % marker)
        self.assertEqual(result.returncode, 4)
        self.assertFalse(ah_run.group_alive(int(marker.read_text())))

    def test_a_clean_exit_returns_at_once_and_leaves_no_group(self):
        marker = Path(self.temp.name) / 'clean.txt'
        started = time.monotonic()
        result = self.run_cmd('echo $$ > %s' % marker)
        self.assertEqual(result.returncode, 0)
        self.assertLess(time.monotonic() - started, ah_run.KILL_GRACE, 'a clean exit must not wait out the grace')
        self.assertTrue(self.group_gone_within(int(marker.read_text()), 1))


class PausedGroup(SignalEscalation):
    """S19: a pause through `ah-run kill --pause` leaves the watchdog running, and it resumes the group before ending it.

    r5 S24: Darwin ends a stopped `sleep` on TERM without SIGCONT, so the two rows on a plain sleep can prove the SIGCONT-before-
    TERM path only on Linux, where TERM waits for CONT: they are Linux-authoritative. The two handler rows prove it on both,
    since a shell's TERM trap runs only once the process continues; without SIGCONT the group gets the SIGKILL and no marker."""
    test_sigterm_to_the_launcher_ends_a_term_ignoring_command = None
    test_sigkill_of_the_supervisor_ends_a_term_ignoring_command = None
    test_term_then_kill_of_the_supervisor_still_ends_the_group = None
    test_a_term_ignoring_leftover_of_a_finished_command_is_ended = None
    test_a_clean_exit_returns_at_once_and_leaves_no_group = None

    def pause(self, task):
        result = subprocess.run([sys.executable, AH, 'kill', '--task', task, '--pause'], env=self.env, capture_output=True, text=True, timeout=30)
        return json.loads(result.stdout)

    def start(self, task):
        marker = Path(self.temp.name) / ('%s.txt' % task)
        proc = subprocess.Popen([sys.executable, AH, 'run', '--task', task, '--token', 'tok', '--no-unit', '--', 'echo $$ > %s; sleep 60 & echo $! >> %s; wait' % (marker, marker)],
                                env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.finish, proc)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not (marker.exists() and len(marker.read_text().split()) == 2):
            time.sleep(0.02)
        pids = [int(pid) for pid in marker.read_text().split()]
        self.groups.append(pids[0])
        return proc, pids

    def test_a_paused_group_ends_when_the_supervisor_dies(self):
        proc, pids = self.start('ps1')
        report = self.pause('ps1')
        self.assertTrue(report['signalled'], report)
        self.assertTrue(any('watchdog' in entry['why'] for entry in report['skipped']), report)
        proc.kill(); proc.wait(timeout=5)
        # under the grace: the watchdog's SIGCONT let the TERM act at once, it did not wait for the SIGKILL. The watchdog
        # itself stays in the group until its SIGKILL, so the row checks the command's processes.
        for pid in pids:
            self.assertTrue(self.wait_gone(pid, ah_run.KILL_GRACE - 0.5), 'paused pid %d outlived the supervisor' % pid)

    def test_a_signal_to_the_launcher_reaches_a_paused_command_at_once(self):
        proc, pids = self.start('ps2')
        self.pause('ps2')
        proc.send_signal(signal.SIGTERM)
        self.assertTrue(self.group_gone_within(pids[0], ah_run.KILL_GRACE - 0.5), 'paused group %d waited for the SIGKILL' % pids[0])
        proc.wait(timeout=10)

    def start_with_a_handler(self, task):
        marker, handled = Path(self.temp.name) / ('%s.pid' % task), Path(self.temp.name) / ('%s.handled' % task)
        command = "trap 'echo term > %s; exit 0' TERM; echo $$ > %s; while :; do sleep 0.1; done" % (handled, marker)
        proc = subprocess.Popen([sys.executable, AH, 'run', '--task', task, '--token', 'tok', '--no-unit', '--', command],
                                env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.finish, proc)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not (marker.exists() and marker.read_text().strip()):
            time.sleep(0.02)
        self.groups.append(int(marker.read_text()))
        return proc, handled

    def handler_ran(self, handled):
        deadline = time.monotonic() + ah_run.KILL_GRACE - 0.5
        while time.monotonic() < deadline:
            if handled.exists():
                return True
            time.sleep(0.02)
        return False

    def test_the_watchdog_continues_a_paused_group_before_term(self):
        proc, handled = self.start_with_a_handler('ps3')
        self.assertTrue(self.pause('ps3')['signalled'])
        time.sleep(0.2)
        proc.kill(); proc.wait(timeout=5)
        self.assertTrue(self.handler_ran(handled), 'the TERM handler never ran: no SIGCONT before TERM')

    def test_the_forwarded_signal_continues_a_paused_group_before_term(self):
        proc, handled = self.start_with_a_handler('ps4')
        self.assertTrue(self.pause('ps4')['signalled'])
        time.sleep(0.2)
        proc.send_signal(signal.SIGTERM)
        self.assertTrue(self.handler_ran(handled), 'the TERM handler never ran: no SIGCONT before TERM')
        proc.wait(timeout=10)


class Kill(Fixture):
    def test_kill_by_task_reaches_env_attributed_orphans_and_spares_the_rest(self):
        marker = Path(self.temp.name) / 'orphan.txt'
        # A grandchild that leaves the group with its own session but keeps the attribution env.
        script = ('%s -c "import os,subprocess,sys,time; p=subprocess.Popen([\'sleep\',\'60\'], start_new_session=True); '
                  'open(%r,\'w\').write(str(p.pid)); time.sleep(60)"' % (sys.executable, str(marker)))
        proc = subprocess.Popen([sys.executable, AH, 'run', '--task', 'kt', '--token', 'tok', '--no-unit', '--', script], env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not marker.exists(): time.sleep(0.05)
        orphan = int(marker.read_text())
        bystander = subprocess.Popen(['sleep', '60'])
        self.addCleanup(lambda: bystander.poll() is None and bystander.kill())
        result = subprocess.run([sys.executable, AH, 'kill', '--task', 'kt'], env=self.env, capture_output=True, text=True, timeout=30)
        report = json.loads(result.stdout)
        self.assertTrue(any(e['pid'] == orphan for e in report['signalled']), report)
        self.assertTrue(self.wait_gone(orphan)); proc.wait(timeout=10)
        self.assertIsNone(bystander.poll())
        self.assertFalse(any(e['pid'] == os.getpid() for e in report['signalled']))
        none = json.loads(subprocess.run([sys.executable, AH, 'kill', '--task', 'nothing'], env=self.env, capture_output=True, text=True, timeout=30).stdout)
        self.assertEqual(none['signalled'], [])

    def test_pause_and_resume(self):
        proc = subprocess.Popen([sys.executable, AH, 'run', '--task', 'pt', '--token', 'tok', '--no-unit', '--', 'sleep 60'], env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: subprocess.run([sys.executable, AH, 'kill', '--task', 'pt'], env=self.env, capture_output=True, timeout=30))
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        time.sleep(1)
        paused = json.loads(subprocess.run([sys.executable, AH, 'kill', '--task', 'pt', '--pause'], env=self.env, capture_output=True, text=True, timeout=30).stdout)
        self.assertTrue(paused['signalled'])
        pid = paused['signalled'][0]['pid']
        state = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True).stdout.strip()
        self.assertTrue(state.startswith('T'), state)
        resumed = json.loads(subprocess.run([sys.executable, AH, 'kill', '--task', 'pt', '--resume'], env=self.env, capture_output=True, text=True, timeout=30).stdout)
        self.assertTrue(resumed['signalled'])
        state = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True).stdout.strip()
        self.assertFalse(state.startswith('T'), state)


class Mask(unittest.TestCase):
    def test_masks_bearer_flag_values_and_detector_patterns(self):
        text = 'curl -H "Authorization: Bearer abc123DEF" --token s3cr3t --api-key=K9K9 -token t2 --passwd pw ghp_' + 'q' * 20 + ' plain'
        masked = ah_run.mask_argv(text)
        for secret in ('abc123DEF', 's3cr3t', 'K9K9', 't2', 'pw', 'ghp_' + 'q' * 20):
            self.assertNotIn(secret, masked)
        self.assertIn('plain', masked)
        self.assertLessEqual(len(ah_run.mask_argv('x' * 2000)), 512)
        self.assertNotIn('\n', ah_run.mask_argv('a\nb'))




# ---------------------------------------------------------------------------------------------------------
# Slice 2: the PreToolUse rewrite hook (goodqa#14548 AC-1, AC-4, NEG-1, NEG-2, NEG-4)
# ---------------------------------------------------------------------------------------------------------

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'ah_run'


class HookFixture(Fixture):
    def setUp(self):
        super().setUp()
        self.home = Path(self.temp.name) / 'home'; (self.home / '.claude').mkdir(parents=True)
        self.project = Path(self.temp.name) / 'proj'; (self.project / '.claude').mkdir(parents=True)
        (self.project / 'sub').mkdir()
        patcher = mock.patch.dict(os.environ, {'AGENT_HARNESS_RESERVE_DIR': str(self.reserve)})
        patcher.start(); self.addCleanup(patcher.stop)
        for key in ('AGENT_HARNESS_TASK', 'AGENT_HARNESS_TICKET', 'AGENT_HARNESS_POLICY_FILE'):
            os.environ.pop(key, None)

    def settings(self, where, **lists):
        path = {'user': self.home / '.claude' / 'settings.json', 'project': self.project / '.claude' / 'settings.json',
                'local': self.project / '.claude' / 'settings.local.json'}[where]
        path.write_text(json.dumps({'permissions': lists}))
        return path

    def payload(self, command, **extra):
        return {'session_id': 's-1', 'tool_name': 'Bash', 'tool_input': {'command': command}, 'cwd': str(self.project),
                'permission_mode': 'default', **extra}

    def decide(self, command, ancestors=None, env=None, **extra):
        return ah_run.decide(self.payload(command, **extra), home=str(self.home), env=env if env is not None else {'AGENT_HARNESS_POLICY_FILE': os.environ.get('AGENT_HARNESS_POLICY_FILE', '')},
                             ancestors=ancestors or (lambda: []))['hookSpecificOutput']

    def raw(self, command, **extra):
        return ah_run.decide(self.payload(command, **extra), home=str(self.home), env={}, ancestors=lambda: [])

    def pending(self):
        return sorted((self.reserve / 'ledger' / 'pending').glob('*.json'))

    def run_wrapped(self, updated_command):
        return subprocess.run(['/bin/sh', '-c', updated_command], env={**self.env, 'AGENT_HARNESS_RESERVE_DIR': str(self.reserve)},
                              capture_output=True, text=True, timeout=30)

    def settings_policy(self, mode):
        path = Path(self.temp.name) / 'policy.json'
        path.write_text(json.dumps({'modes': {'escapes': mode}}))
        os.environ['AGENT_HARNESS_POLICY_FILE'] = str(path)


class RewriteHook(HookFixture):
    def test_matcher_matches_claude_code_word_boundary(self):
        # measured live (g10/slice2/matcher): `Bash(echo FORBIDDEN:*)` denies `echo FORBIDDEN 3`, not `echo FORBIDDEN-1`
        self.settings('project', deny=['Bash(echo FORBIDDEN:*)'])
        self.assertEqual(self.decide('echo FORBIDDEN 3')['permissionDecision'], 'deny')
        self.assertNotEqual(self.decide('echo FORBIDDEN-1').get('permissionDecision'), 'deny')

    def test_deny_wins(self):
        self.settings('project', deny=['Bash(echo FORBIDDEN*)'], allow=['Bash(echo:*)'])
        out = self.decide('echo FORBIDDEN-1')
        self.assertEqual(out['permissionDecision'], 'deny'); self.assertIn('Bash(echo FORBIDDEN*)', out['permissionDecisionReason'])
        self.assertNotIn('updatedInput', out); self.assertEqual(self.pending(), [])

    def test_deny_in_second_part_and_inside_substitution(self):
        self.settings('user', deny=['Bash(echo FORBIDDEN*)'], allow=['Bash(echo:*)', 'Bash(ls:*)'])
        self.assertEqual(self.decide('ls && echo FORBIDDEN-2')['permissionDecision'], 'deny')
        self.assertEqual(self.decide('ls; (echo FORBIDDEN-2)')['permissionDecision'], 'deny')
        self.assertEqual(self.decide('ls "$(echo FORBIDDEN-3)"')['permissionDecision'], 'deny')
        self.assertEqual(self.decide('timeout 5 echo FORBIDDEN-4')['permissionDecision'], 'deny')

    def test_deny_applies_to_a_stripped_ah_run_prefix(self):
        self.settings('user', deny=['Bash(echo FORBIDDEN*)'])
        self.assertEqual(self.decide('ah-run --task x -- echo FORBIDDEN-5')['permissionDecision'], 'deny')

    def test_allow_rewrites(self):
        self.settings('project', allow=['Bash(echo:*)'])
        out = self.decide('echo OK-2')
        self.assertEqual(out['permissionDecision'], 'allow')
        wrapped = out['updatedInput']['command']
        self.assertTrue(wrapped.startswith('python3 -I %s run --task auto-' % ah_run.Path(ah_run.__file__).resolve()), wrapped)
        self.assertIn('--agent main --session s-1 --token ', wrapped); self.assertTrue(wrapped.endswith("-- 'echo OK-2'"))
        result = self.run_wrapped(wrapped)
        self.assertEqual((result.returncode, result.stdout), (0, 'OK-2\n'))
        row = self.rows()[0]
        self.assertEqual((row['attribution'], row['agent'], row['session']), ('verified', 'main', 's-1'))

    def test_nomatch_asks(self):
        self.settings('project', allow=['Bash(ls:*)'])
        out = self.decide('echo hi')
        self.assertEqual(out['permissionDecision'], 'ask'); self.assertIn('updatedInput', out)

    def test_compound_partial_allow_asks(self):
        self.settings('project', allow=['Bash(ls:*)'])
        self.assertEqual(self.decide('ls && echo hi')['permissionDecision'], 'ask')
        self.assertEqual(self.decide('ls; ls | ls')['permissionDecision'], 'allow')

    def test_substitution_never_allows(self):
        self.settings('project', allow=['Bash(echo:*)'])
        for command in ('echo $(date)', 'echo `date`', 'echo "$(date)"', 'cat <(echo x)', 'echo a\necho b', 'eval echo x',
                        'echo x <<EOF\n$(date)\nEOF'):
            out = self.decide(command)
            self.assertEqual(out['permissionDecision'], 'ask', command); self.assertIn('updatedInput', out)
        # a quoted heredoc is data, not a newline or substitution
        self.assertEqual(self.decide("echo x <<'EOF'\n$(date)\nEOF")['permissionDecision'], 'allow')

    def test_matcher_forms(self):
        self.settings('project', allow=['Bash(git status)', 'Bash(npm run *)', 'Bash(make:*)', 'Bash(cat * | wc -l)'])
        verdict = lambda c: self.decide(c)['permissionDecision']
        self.assertEqual(verdict('git status'), 'allow'); self.assertEqual(verdict('git status -s'), 'ask')
        self.assertEqual(verdict('npm run test'), 'allow'); self.assertEqual(verdict('npm install'), 'ask')
        self.assertEqual(verdict('make'), 'allow'); self.assertEqual(verdict('make -j4 all'), 'allow'); self.assertEqual(verdict('makefile'), 'ask')
        self.settings('project', allow=['Bash'])
        self.assertEqual(verdict('anything at all'), 'allow')

    def test_ask_rule_beats_allow(self):
        self.settings('project', allow=['Bash(git:*)'], ask=['Bash(git push:*)'])
        self.assertEqual(self.decide('git status')['permissionDecision'], 'allow')
        self.assertEqual(self.decide('git push origin x')['permissionDecision'], 'ask')

    def test_permission_mode_table(self):
        self.settings('project', allow=['Bash(echo:*)'], deny=['Bash(echo FORBIDDEN*)'])
        out = self.decide('echo hi', permission_mode='bypassPermissions')
        self.assertNotIn('permissionDecision', out); self.assertIn('updatedInput', out)
        self.assertEqual(self.raw('echo hi', permission_mode='plan'), {})
        self.assertEqual(self.decide('echo hi', permission_mode='acceptEdits')['permissionDecision'], 'allow')
        self.assertEqual(self.decide('echo hi', permission_mode='auto')['permissionDecision'], 'allow')
        self.assertEqual(self.decide('ls', permission_mode='default')['permissionDecision'], 'ask')
        dont = self.decide('ls', permission_mode='dontAsk')
        self.assertEqual(dont['permissionDecision'], 'deny'); self.assertNotIn('updatedInput', dont)
        self.assertEqual(self.decide('echo hi', permission_mode='dontAsk')['permissionDecision'], 'allow')
        self.assertEqual(self.decide('echo FORBIDDEN-1', permission_mode='bypassPermissions')['permissionDecision'], 'deny')

    def test_dontask_denies(self):
        out = self.decide('echo unmatched', permission_mode='dontAsk')
        self.assertEqual(out['permissionDecision'], 'deny'); self.assertIn('dontAsk', out['permissionDecisionReason'])

    def test_bypass_rewrites_no_decision(self):
        out = self.decide('echo hi', permission_mode='bypassPermissions')
        self.assertEqual(set(out) - {'hookEventName'}, {'updatedInput'})

    def test_plan_untouched(self):
        self.assertEqual(self.raw('echo hi', permission_mode='plan'), {}); self.assertEqual(self.pending(), [])

    def test_missing_permission_mode_is_default(self):
        payload = self.payload('echo hi'); del payload['permission_mode']
        out = ah_run.decide(payload, home=str(self.home), env={}, ancestors=lambda: [])
        self.assertEqual(out['hookSpecificOutput']['permissionDecision'], 'ask')

    def test_settings_through_interposed_shell(self):
        extra = Path(self.temp.name) / 'helper-settings.json'
        extra.write_text(json.dumps({'permissions': {'allow': ['Bash(echo:*)']}}))
        chain = ['/bin/sh -c python3 hook', 'node /x/@anthropic-ai/claude-code/cli.js -p hi --settings %s --model m' % extra]
        self.assertEqual(self.decide('echo hi', ancestors=lambda: chain)['permissionDecision'], 'allow')
        self.assertEqual(self.decide('echo hi', ancestors=lambda: chain[:1])['permissionDecision'], 'ask')
        inline = ['claude -p x --settings=\'%s\'' % json.dumps({'permissions': {'allow': ['Bash(echo:*)']}})]
        self.assertEqual(self.decide('echo hi', ancestors=lambda: inline)['permissionDecision'], 'allow')

    def test_ancestor_walk_is_bounded(self):
        calls = []
        real = subprocess.run
        def fake(argv, **kw):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout='%d sh -c x\n' % (1000 + len(calls)), stderr='')
        # a fixed parent: in a container the test runner's parent can be pid 1, where the walk rightly stops at once
        with mock.patch.object(ah_run.subprocess, 'run', fake), mock.patch.object(ah_run.os, 'getppid', lambda: 4242):
            chain = ah_run.ancestor_commands()
        self.assertEqual(len(chain), 8); self.assertEqual(len(calls), 8)
        with mock.patch.object(ah_run.subprocess, 'run', fake), mock.patch.object(ah_run.os, 'getppid', lambda: 1):
            self.assertEqual(ah_run.ancestor_commands(), [])

    def test_project_deny_from_subdirectory(self):
        self.settings('project', deny=['Bash(echo FORBIDDEN*)'])
        self.assertEqual(self.decide('echo FORBIDDEN-1', cwd=str(self.project / 'sub'))['permissionDecision'], 'deny')

    def test_local_settings_are_read(self):
        self.settings('local', allow=['Bash(echo:*)'])
        self.assertEqual(self.decide('echo hi')['permissionDecision'], 'allow')

    def test_prefix_stripped(self):
        out = self.decide('ah-run --task other --agent main -- git checkout --detach SHA')
        wrapped = out['updatedInput']['command']
        self.assertNotIn('other', wrapped); self.assertTrue(wrapped.endswith("-- 'git checkout --detach SHA'"), wrapped)
        self.assertEqual(wrapped.count('ah_run.py'), 1)
        out = self.decide('python3 /x/ah_run.py run --task other --token abc -- echo hi && echo there')
        self.assertTrue(out['updatedInput']['command'].endswith("-- 'echo hi && echo there'"))

    def test_ahrun_allow_rule_refused(self):
        # EXP4 (G10-EXP4): a hook ask beats a matching settings allow rule, so the refuse-to-rewrite self-check is
        # dropped per AC-1; the hook ignores ah-run allow rules and only reports them.
        for where in ('user', 'local'):
            self.settings(where, allow=['Bash(python3 /x/ah_run.py run:*)', 'Bash(ah-run:*)'])
            out = self.decide('ls')
            self.assertEqual(out['permissionDecision'], 'ask')
            self.assertIn('ignored an ah-run allow rule', out['additionalContext'])
            self.assertIn('install.py --apply --role ROLE', out['additionalContext'])
            self.assertEqual(self.decide('ah-run --task x -- ls')['permissionDecision'], 'ask')
            os.unlink({'user': self.home / '.claude' / 'settings.json', 'local': self.project / '.claude' / 'settings.local.json'}[where])

    def test_committed_rule_degrades(self):
        path = self.settings('project', allow=['Bash(ah-run:*)', 'Bash(echo:*)'])
        path.write_text(json.dumps({'permissions': {'allow': ['Bash(echo:*)',
                                                              'Bash(ah-run:*)']}}, indent=1))
        out = self.decide('ls')
        self.assertEqual(out['permissionDecision'], 'ask')
        self.assertIn('settings.json line 5', out['additionalContext'])
        self.assertEqual(self.decide('echo ok')['permissionDecision'], 'ask')  # a committed rule degrades every command to ask

    def test_token_missing(self):
        result = subprocess.run([sys.executable, AH, 'run', '--task', 't1', '--agent', 'a1', '--token', 'N' * 24, '--no-unit', '--', 'echo hi'],
                                env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertEqual((self.rows()[0]['attribution'], self.rows()[0]['attribution_reason']), ('unverified', 'token-missing-or-replayed'))

    def test_token_replayed_and_mismatched(self):
        self.settings('project', allow=['Bash(echo:*)'])
        wrapped = self.decide('echo once')['updatedInput']['command']
        self.assertEqual(len(self.pending()), 1)
        self.assertEqual(self.run_wrapped(wrapped).stdout, 'once\n')
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.run_wrapped(wrapped).stdout, 'once\n')
        first, second = sorted(self.rows(), key=lambda r: r['started_at'])
        self.assertEqual((first['attribution'], second['attribution']), ('verified', 'unverified'))
        self.assertEqual(second['attribution_reason'], 'token-missing-or-replayed')
        # a token bound to another command digest is unverified
        wrapped = self.decide('echo bound')['updatedInput']['command']
        self.run_wrapped(wrapped.replace("'echo bound'", "'echo swapped'"))
        self.assertEqual(sorted(self.rows(), key=lambda r: r['started_at'])[-1]['attribution_reason'], 'token-command-mismatch')

    def test_token_row_is_private_and_single_use_under_a_race(self):
        token = ah_run.mint_pending(self.reserve, 'echo x', 't', 'a')
        path = self.reserve / 'ledger' / 'pending' / (token + '.json')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        row = json.loads(path.read_text())
        self.assertEqual(row['command_sha256'], ah_run.digest('echo x')); self.assertNotIn('echo x', path.read_text())
        results = []
        threads = [threading.Thread(target=lambda: results.append(ah_run.consume_pending(self.reserve, token, 'echo x', 't', 'a')[0]))
                   for _ in range(8)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(sorted(results), ['unverified'] * 7 + ['verified'])

    def test_expired_token_is_unverified(self):
        token = ah_run.mint_pending(self.reserve, 'echo x', 't', 'a')
        future = time.time() + 10_000
        with mock.patch.object(ah_run.time, 'time', lambda: future):
            self.assertEqual(ah_run.consume_pending(self.reserve, token, 'echo x', 't', 'a'), ('unverified', 'token-expired'))

    def test_generated_key(self):
        wrapped = self.decide('echo hi', agent_id='ag-9')['updatedInput']['command']
        expected = 'auto-' + hashlib.sha256(b's-1ag-9').hexdigest()[:12]
        self.assertIn('--task %s --agent ag-9' % expected, wrapped)

    def test_task_key_sources_and_ticket(self):
        env = {'AGENT_HARNESS_TASK': 'envtask', 'AGENT_HARNESS_TICKET': 'GoodQA#7'}
        out = ah_run.decide(self.payload('echo hi'), home=str(self.home), env=env, ancestors=lambda: [])['hookSpecificOutput']
        self.assertIn('--task envtask', out['updatedInput']['command']); self.assertIn("--ticket 'GoodQA#7'", out['updatedInput']['command'])
        out = self.decide('echo hi', prompt='do it [task:from-spawn] now')
        self.assertIn('--task from-spawn', out['updatedInput']['command']); self.assertNotIn('--ticket', out['updatedInput']['command'])
        # a task token inside the command text is the model's choice, not attribution
        out = self.decide('echo "[task:chosen-by-model]"')
        self.assertNotIn('chosen-by-model --agent', out['updatedInput']['command'])

    def test_large_command_cmd_file(self):
        self.settings('project', allow=['Bash(echo:*)'])
        command = 'echo ' + 'x' * (70 * 1024)
        out = self.decide(command)
        self.assertEqual(out['permissionDecision'], 'ask')  # over the 64 KiB scan cap: never allowed, never scanned
        wrapped = out['updatedInput']['command']
        self.assertIn('--cmd-file', wrapped); self.assertNotIn('xxxxxxxx', wrapped)
        payload = next((self.reserve / 'ledger' / 'pending').glob('*.cmd'))
        self.assertEqual(payload.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.run_wrapped(wrapped).stdout.strip(), 'x' * (70 * 1024))
        self.assertFalse(payload.exists())  # unlinked once ah-run read it
        self.assertEqual(self.rows()[0]['attribution'], 'verified')

    def test_payload_over_cap(self):
        out = self.decide('echo ' + 'x' * (1 << 20))
        self.assertEqual(out['permissionDecision'], 'deny'); self.assertIn('1 MiB', out['permissionDecisionReason'])
        self.assertEqual(list((self.reserve / 'ledger' / 'pending').glob('*')), [])

    def test_payload_write_failure_denies_non_recovery(self):
        real = os.open
        def failing(path, flags, *a, **k):
            if str(path).endswith('.cmd'):
                raise OSError(28, 'no space')
            return real(path, flags, *a, **k)
        with mock.patch.object(ah_run.os, 'open', failing):
            out = self.decide('echo ' + 'x' * (70 * 1024))
        self.assertEqual(out['permissionDecision'], 'deny'); self.assertIn('payload file', out['permissionDecisionReason'])

    def test_internal_error_asks(self):
        for stdin in ('not json', '[1,2]', '{"tool_name": "Bash", "tool_input": {"command": 7}}x'):
            result = subprocess.run([sys.executable, AH, 'hook'], input=stdin, env=self.env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0)
            out = json.loads(result.stdout)['hookSpecificOutput']
            self.assertEqual(out['permissionDecision'], 'ask'); self.assertNotIn('updatedInput', out)
        with mock.patch.object(ah_run, 'load_rules', side_effect=RuntimeError('boom')):
            out = io.StringIO()
            self.assertEqual(ah_run.hook_main(io.StringIO(json.dumps(self.payload('echo hi'))), out), 0)
            body = json.loads(out.getvalue())['hookSpecificOutput']
        self.assertEqual(body['permissionDecision'], 'ask'); self.assertIn('boom', body['permissionDecisionReason'])

    def test_hook_cli_end_to_end(self):
        self.settings('project', allow=['Bash(echo:*)'], deny=['Bash(echo FORBIDDEN*)'])
        env = {**self.env, 'HOME': str(self.home)}
        def call(command):
            result = subprocess.run([sys.executable, AH, 'hook'], input=json.dumps(self.payload(command)), env=env,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0)
            return json.loads(result.stdout)['hookSpecificOutput']
        self.assertEqual(call('echo FORBIDDEN-1')['permissionDecision'], 'deny')
        self.assertEqual(call('echo OK-2')['permissionDecision'], 'allow')

    def test_escape_modes(self):
        self.settings('project', allow=['Bash(nohup:*)'])
        out = self.decide('nohup sleep 100')           # no policy file: warn
        self.assertIn('WARNING', out['additionalContext']); self.assertEqual(out['permissionDecision'], 'allow')
        self.settings_policy('enforce')
        out = self.decide('nohup sleep 100')
        self.assertEqual(out['permissionDecision'], 'deny'); self.assertIn('nohup', out['permissionDecisionReason'])
        Path(os.environ['AGENT_HARNESS_POLICY_FILE']).write_text('{corrupt')
        self.assertEqual(self.decide('nohup sleep 100')['permissionDecision'], 'deny')  # unreadable policy is enforce


def escape_rows():
    data = json.loads((FIXTURES / 'escapes.json').read_text())
    return data['refused'], data['allowed']


def check_rows(classify):
    """Failures of a classifier against the corpus: refused rows it allowed, allowed rows it refused."""
    refused, allowed = escape_rows()
    wrong = ['allowed:' + row['id'] for row in refused if not classify(row['cmd'])]
    wrong += ['refused:' + row['id'] for row in allowed if classify(row['cmd'])]
    return wrong


class Escapes(unittest.TestCase):
    def test_corpus_is_big_enough_and_data_only(self):
        refused, allowed = escape_rows()
        self.assertGreaterEqual(len(refused), 30); self.assertGreaterEqual(len(allowed), 10)
        self.assertEqual(len({row['id'] for row in refused + allowed}), len(refused) + len(allowed))

    def test_refused_rows(self):
        refused, _ = escape_rows()
        for row in refused:
            with self.subTest(row['id']):
                self.assertTrue(ah_run.classify_escapes(row['cmd']), row['cmd'])

    def test_allowed_rows(self):
        _, allowed = escape_rows()
        for row in allowed:
            with self.subTest(row['id']):
                self.assertEqual(ah_run.classify_escapes(row['cmd']), [], row['cmd'])

    def test_timeout_is_allowed_and_recorded_pgid_split(self):
        self.assertEqual(ah_run.analyze_escapes('timeout 30 sleep 1'), ([], ['pgid-split']))

    def test_spec_examples(self):
        for command in ('(sleep 5 &) ; wait', 'cmd1 & cmd2; wait', 'a && b || c'):
            self.assertEqual(ah_run.classify_escapes(command), [], command)
        for command in ('echo x | nohup cat', 'setsid ./x', 'env -u AGENT_HARNESS_TASK ./x', 'sleep 1 &'):
            self.assertTrue(ah_run.classify_escapes(command), command)

    def test_the_owners_own_test_file_heredoc_is_allowed(self):
        command = "cat > tests/test_ah_run.py <<'EOF'\n# nohup setsid tmux disown\nsubprocess.run(['nohup', 'x'])  # sleep 5 &\nEOF"
        self.assertEqual(ah_run.classify_escapes(command), [])

    # failing controls: the corpus must catch a classifier that is wrong in either direction or in one subtle way
    def test_control_allow_everything_fails_refused_rows(self):
        wrong = check_rows(lambda command: [])
        self.assertGreaterEqual(len([w for w in wrong if w.startswith('allowed:')]), 30)

    def test_control_refuse_everything_fails_allowed_rows(self):
        wrong = check_rows(lambda command: ['x'])
        self.assertGreaterEqual(len([w for w in wrong if w.startswith('refused:')]), 10)

    def test_control_real_classifier_passes_the_whole_corpus(self):
        self.assertEqual(check_rows(ah_run.classify_escapes), [])

    def test_control_mutant_ignoring_heredocs_fails_the_heredoc_row(self):
        """r6 S29: the old mutant lacked a parameter, so every row raised and the control proved nothing. This one reads every
        `<<` as a plain redirect, runs on every row (counted), and is wrong only on the row whose body is data."""
        calls = []
        def mutant(command):
            calls.append(command)
            return ah_run._Lexer(command, whole=True).run()
        with mock.patch.object(ah_run, 'lex', mutant):
            wrong = check_rows(ah_run.classify_escapes)
            self.assertEqual(ah_run.classify_escapes('echo plain'), [])
        refused, allowed = escape_rows()
        self.assertGreaterEqual(len(calls), len(refused) + len(allowed))
        self.assertEqual(wrong, ['refused:heredoc-body-has-nohup'])

    def test_control_mutant_treating_and_and_as_background_fails_the_chain_row(self):
        real = ah_run.lex
        def mutant(command):
            lexed = real(command)
            lexed.commands = [item._replace(operator='&') if item.operator == '&&' else item for item in lexed.commands]
            return lexed
        with mock.patch.object(ah_run, 'lex', mutant):
            wrong = check_rows(ah_run.classify_escapes)
        self.assertEqual(wrong, ['refused:and-or-chain'])


class Equivalence(Fixture):
    """Wrapped and unwrapped runs give the same stdout, exit status and cwd (fixture shell: /bin/bash)."""

    def both(self, script):
        shell = '/bin/bash'
        env = {**self.env, 'CLAUDE_CODE_SHELL': shell}
        plain = subprocess.run([shell, '-c', script], env=env, capture_output=True, text=True, timeout=30, cwd=self.temp.name)
        wrapped = subprocess.run([sys.executable, AH, 'run', '--task', 'eq', '--agent', 'main', '--no-unit', '--', script],
                                 env=env, capture_output=True, text=True, timeout=30, cwd=self.temp.name)
        self.assertEqual((wrapped.returncode, wrapped.stdout), (plain.returncode, plain.stdout), script)
        return plain

    def test_heredoc_with_quotes_dollar_backticks_and_non_ascii(self):
        out = self.both("cat <<'EOF'\nit's \"q\" $HOME `date` \\n café ☃\nEOF\nprintf '%s\\n' \"$(printf 'ü')\"")
        self.assertIn('café ☃', out.stdout)

    def test_cd_and_pwd(self):
        self.both('cd /tmp && pwd')

    def test_exit_status(self):
        self.assertEqual(self.both('exit 3').returncode, 3)

    def test_pipeline_status_with_and_without_pipefail(self):
        self.assertEqual(self.both('false | true; echo $?').stdout, '0\n')
        self.assertEqual(self.both('set -o pipefail; false | true; echo $?').stdout, '1\n')

    def test_exec(self):
        self.assertEqual(self.both('exec sleep 0').returncode, 0)

    def test_cwd_is_inherited(self):
        self.assertEqual(Path(self.both('pwd').stdout.strip()).resolve(), Path(self.temp.name).resolve())

    def test_sigpipe_is_default_in_the_command(self):
        self.assertEqual(self.both('yes | head -1 >/dev/null; echo "${PIPESTATUS[0]}"').stdout, '141\n')
        self.assertEqual(self.both('set -o pipefail; yes | head -1').returncode, 141)

    def test_a_builtin_loop_into_head_finishes(self):
        script = 'while :; do echo x; done | head -1'
        started = time.monotonic()
        result = subprocess.run([sys.executable, AH, 'run', '--task', 'eq', '--no-unit', '--', script], stdin=subprocess.DEVNULL,
                                env={**self.env, 'CLAUDE_CODE_SHELL': '/bin/bash'}, capture_output=True, text=True, timeout=8)
        self.assertEqual(result.stdout, 'x\n'); self.assertLess(time.monotonic() - started, 2)

    def test_sigxfsz_is_default_in_the_command(self):
        out = self.both('ulimit -f 1; head -c 8192 /dev/zero > big 2>/dev/null; echo $?')
        self.assertEqual(out.stdout, '153\n')

    def decoy_dir(self, name):
        decoy = Path(tempfile.mkdtemp(dir=self.temp.name))
        marker = decoy / 'MARKER'
        (decoy / (name + '.py')).write_text('open(%r, "w").write("ran")\n' % str(marker))
        return decoy, marker

    def test_a_module_in_the_cwd_is_not_imported_by_the_launcher(self):
        for name in ('signal', 'os', 'time', 'sys'):
            decoy, marker = self.decoy_dir(name)
            result = subprocess.run([sys.executable, AH, 'run', '--task', 'eq', '--no-unit', '--', 'echo hi'], cwd=str(decoy), env=self.env,
                                    capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
            self.assertEqual((result.returncode, result.stdout), (0, 'hi\n'), (name, result.stderr))
            self.assertFalse(marker.exists(), name)

    def test_pythonpath_is_ignored_by_the_launcher_and_kept_for_the_command(self):
        for name in ('signal', 'os'):
            decoy, marker = self.decoy_dir(name)
            env = {**self.env, 'PYTHONPATH': str(decoy), 'PYTHONSTARTUP': str(decoy / (name + '.py'))}
            # the form the hook and the ssh rewrite build
            result = subprocess.run([sys.executable, '-I', AH, 'run', '--task', 'eq', '--no-unit', '--', 'echo "$PYTHONPATH|$PYTHONSTARTUP"'],
                                    env=env, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
            self.assertEqual(result.returncode, 0, (name, result.stderr))
            self.assertEqual(result.stdout, '%s|%s\n' % (env['PYTHONPATH'], env['PYTHONSTARTUP']), name)
            self.assertFalse(marker.exists(), name)

    def test_closed_stdio_does_not_kill_the_command(self):
        for closed in ('<&-', '>&-', '2>&-', '<&- 2>&-', '>&- 2>&-', '<&- >&- 2>&-'):
            done = Path(tempfile.mkdtemp(dir=self.temp.name)) / 'done'
            command = 'sleep 0.3; echo end > %s' % done
            outer = '%s %s run --task eq --no-unit -- %s %s' % (sys.executable, AH, shlex.quote(command), closed)
            result = subprocess.run(['/bin/bash', '-c', outer], env=self.env, capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL)
            self.assertEqual(result.returncode, 0, closed); self.assertTrue(done.exists(), closed)

    def test_the_pipe_is_above_stdio_even_when_stdio_is_closed(self):
        code = ('import os, sys; sys.path.insert(0, %r); import ah_run; os.close(0); os.close(2); r, w = ah_run.pipe_above_stdio(); '
                'os.write(1, b"%%d %%d" %% (r, w))' % str(HOOKS))
        out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=20, env=self.env, stdin=subprocess.DEVNULL).stdout
        self.assertTrue(out and min(int(fd) for fd in out.split()) >= 3, out)

    def test_the_mask_is_clear_in_the_command(self):
        # a TERM blocked across the trampoline's forks must not stay blocked in the command
        marker = Path(self.temp.name) / 'mask.txt'
        proc = subprocess.Popen([sys.executable, AH, 'run', '--task', 'eq', '--no-unit', '--', 'echo $$ > %s; sleep 60' % marker],
                                env={**self.env, 'CLAUDE_CODE_SHELL': '/bin/bash'}, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not (marker.exists() and marker.read_text().strip()):
            time.sleep(0.02)
        started = time.monotonic()
        proc.send_signal(signal.SIGTERM); proc.wait(timeout=10)
        self.assertEqual(proc.returncode, 128 + signal.SIGTERM)
        self.assertLess(time.monotonic() - started, ah_run.KILL_GRACE - 0.5, 'ended by the TERM, not by the SIGKILL after the grace')


class JobTable(Fixture):
    """B3: the watchdog is not a job of the user's shell, so wait, jobs and $! behave as without ah-run."""
    SHELLS = [s for s in ('/bin/bash', '/bin/zsh') if os.access(s, os.X_OK)]

    def run_in(self, shell, command):
        started = time.monotonic()
        env = {**self.env, 'CLAUDE_CODE_SHELL': shell}
        token = ah_run.mint_pending(self.reserve, command, 't1', 'a1')
        result = subprocess.run([sys.executable, AH, 'run', '--task', 't1', '--agent', 'a1', '--token', token, '--no-unit', '--', command],
                                env=env, capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL)
        return result, time.monotonic() - started

    def test_bare_wait_returns_after_a_subshell_background_job(self):
        for shell in self.SHELLS:
            result, elapsed = self.run_in(shell, '(sleep 1 &); wait')
            self.assertEqual(result.returncode, 0, shell); self.assertLess(elapsed, 8, shell)

    def test_dollar_bang_is_one_pid_and_wait_returns(self):
        for shell in self.SHELLS:
            result, elapsed = self.run_in(shell, 'sleep 1 & echo $!; wait')
            self.assertEqual(result.returncode, 0, shell); self.assertLess(elapsed, 8, shell)
            lines = result.stdout.split()
            self.assertEqual(len(lines), 1, (shell, result.stdout)); self.assertTrue(lines[0].isdigit())

    def test_jobs_prints_nothing_extra(self):
        for shell in self.SHELLS:
            result, _ = self.run_in(shell, 'jobs')
            self.assertEqual((result.returncode, result.stdout), (0, ''), shell)

    def test_row_records_the_in_group_watchdog(self):
        self.run_in('/bin/bash', 'true')
        self.assertEqual(self.rows()[0]['watchdog'], 'in-group')

    def test_normal_end_leaves_no_watchdog_behind(self):
        marker = Path(self.temp.name) / 'pgid.txt'
        self.run_in('/bin/bash', 'ps -o pgid= -p $$ > %s' % marker)
        pgid = marker.read_text().strip()
        self.assertTrue(pgid, 'ps gave no group, so this row would prove nothing')
        time.sleep(0.5)
        left = subprocess.run(['ps', '-axo', 'pgid='], capture_output=True, text=True).stdout.split()
        self.assertNotIn(pgid, left)

    def test_the_shell_has_no_child_of_its_own(self):
        """S12: a sole command that waits for any child sees none (the watchdog is not its child)."""
        for shell in self.SHELLS:
            env = {**self.env, 'CLAUDE_CODE_SHELL': shell}
            result = subprocess.run([sys.executable, AH, 'run', '--task', 't1', '--no-unit', '--',
                                     '%s -c "import os; os.wait()"' % sys.executable],
                                    env=env, capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            self.assertIn('ChildProcessError', result.stderr, shell); self.assertEqual(result.returncode, 1, shell)

    def run_on_pty(self, command, typed, limit=20):
        """(output, exit status or None, seconds). Writes only after the command printed READY, so the read is really
        waiting; the read loop and the reap are both bounded by the same deadline, and a stopped command misses it."""
        import pty, select
        try:
            pid, master = pty.fork()
        except OSError as error:
            self.skipTest('no pty available: %s' % error)
        if pid == 0:
            os.execve(sys.executable, [sys.executable, AH, 'run', '--task', 't1', '--no-unit', '--', 'echo READY; ' + command],
                      {**self.env, 'CLAUDE_CODE_SHELL': '/bin/bash'})
        started, out, sent, status = time.monotonic(), b'', False, None
        deadline = started + limit
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    out += chunk
                if not sent and b'READY' in out:
                    os.write(master, typed); sent = True
            while time.monotonic() < deadline and status is None:
                done, code = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = code
                else:
                    time.sleep(0.02)
            return out.decode('utf-8', 'replace'), status, time.monotonic() - started
        finally:
            if status is None:
                try:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                except OSError:
                    pass
            os.close(master)

    def test_no_job_control_stop_with_a_controlling_terminal(self):
        """S8: under a pty, stdin reads work and a /dev/tty read ends at once (no SIGTTIN stop)."""
        out, status, seconds = self.run_on_pty('read x; echo got:$x', b'hi\n')
        self.assertTrue(status is not None and 'got:hi' in out, (out, status, seconds))
        out, status, seconds = self.run_on_pty('read x < /dev/tty; echo end', b'hi\n')
        self.assertTrue(status is not None and 'end' in out, (out, status, seconds))

    def test_without_a_tty_behaviour_is_unchanged(self):
        result, _ = self.run_in('/bin/bash', 'read x; echo got:$x')
        self.assertEqual(result.stdout, 'got:\n')


class Recovery(HookFixture):
    """B2: recovery commands skip the rewrite but still need an allow rule, and only in the plain form."""
    HOOKS_DIR = str(HOOKS)

    def rule(self, text):
        self.settings('user', allow=['Bash(%s:*)' % text])

    def test_plain_with_a_rule_is_allowed_unwrapped(self):
        self.rule('python3 %s/reserve.py' % self.HOOKS_DIR)
        out = self.decide('python3 %s/reserve.py status' % self.HOOKS_DIR)
        self.assertEqual(out['permissionDecision'], 'allow'); self.assertNotIn('updatedInput', out)
        self.assertEqual(self.pending(), [])

    def test_without_a_rule_it_asks_and_is_not_rewritten(self):
        out = self.decide('python3 %s/reserve.py status' % self.HOOKS_DIR)
        self.assertEqual(out['permissionDecision'], 'ask'); self.assertNotIn('updatedInput', out)
        self.assertEqual(self.decide('python3 %s/reclaim.py plan' % self.HOOKS_DIR, permission_mode='dontAsk')['permissionDecision'], 'deny')

    def test_installer_needs_apply_and_a_role(self):
        self.rule('python3 harness/install.py')
        out = self.decide('python3 harness/install.py --apply --role dev')
        self.assertEqual(out['permissionDecision'], 'allow'); self.assertNotIn('updatedInput', out)
        out = self.decide('python3 harness/install.py --apply')
        self.assertIn('updatedInput', out); self.assertEqual(out['permissionDecision'], 'allow')  # ordinary: the rule admits it, wrapped

    def test_sudo_redirection_pipeline_env_and_other_paths_are_ordinary(self):
        self.settings('user', allow=['Bash(sudo:*)', 'Bash(python3:*)', 'Bash(reserve.py:*)', 'Bash(BASH_ENV=/x/y.sh:*)'])
        base = 'python3 %s/reserve.py status' % self.HOOKS_DIR
        for command in ('sudo ' + base, base + ' > out.txt', base + ' | cat', base + ' &', 'python3 /tmp/evil/reserve.py',
                        'reserve.py', 'BASH_ENV=/x/y.sh ' + base, 'sudo harness doctor'):
            out = self.decide(command)
            self.assertIn('updatedInput', out, command)

    def test_the_isolated_form_is_still_a_recovery_command(self):
        command = 'python3 -I %s/ah_run.py kill --task t1' % self.HOOKS_DIR
        self.settings('user', allow=['Bash(%s:*)' % command.rsplit(' ', 2)[0]])
        out = self.decide(command)
        self.assertEqual(out['permissionDecision'], 'allow'); self.assertNotIn('updatedInput', out)
        self.assertIn('updatedInput', self.decide('python3 -S %s/ah_run.py kill --task t1' % self.HOOKS_DIR))

    def test_other_recovery_forms_with_rules(self):
        self.settings('user', allow=['Bash(ah-run kill:*)', 'Bash(harness doctor)', 'Bash(harness doctor:*)'])
        for command in ('ah-run kill --task t1', 'harness doctor'):
            out = self.decide(command)
            self.assertEqual(out['permissionDecision'], 'allow', command); self.assertNotIn('updatedInput', out, command)


class ParserSync(HookFixture):
    """B1: the hook splits commands the way the shell does, ANSI-C and locale quoting included."""
    HIDDEN = "echo $'\\'' ; rm -rf x ; echo ''"

    def test_ansi_c_quote_does_not_hide_a_command_from_deny(self):
        self.settings('user', allow=['Bash(echo:*)'], deny=['Bash(rm:*)'])
        self.assertEqual(self.decide(self.HIDDEN)['permissionDecision'], 'deny')

    def test_ansi_c_quote_hiding_a_command_is_never_allowed(self):
        self.settings('user', allow=['Bash(echo:*)'])
        out = self.decide(self.HIDDEN)
        self.assertEqual(out['permissionDecision'], 'ask')

    def test_hidden_command_in_a_substitution_and_double_quote_forms(self):
        self.settings('user', allow=['Bash(echo:*)'], deny=['Bash(rm:*)'])
        for command in ("echo $(echo $'\\'' ; rm -rf x ; echo '')", "echo $'a\\'b' ; rm x", 'echo $"a" ; rm x'):
            self.assertEqual(self.decide(command)['permissionDecision'], 'deny', command)

    def test_benign_ansi_c_strings_are_allowed(self):
        self.settings('user', allow=['Bash(echo:*)'])
        for command in ("echo $'\\n'", "echo $'tab\\there' done", 'echo $"x y"', "echo $'\\x41\\101\\u00e9'"):
            self.assertEqual(self.decide(command)['permissionDecision'], 'allow', command)

    def test_an_escaped_quote_in_an_ansi_c_string_is_uncertain(self):
        """A shell without $'...' (dash) ends the string at the \\', so the rest of the text is code to it."""
        self.settings('user', allow=['Bash(echo:*)'])
        self.assertEqual(self.decide("echo $'it\\'s'")['permissionDecision'], 'ask')

    def test_unterminated_quotes_are_never_allowed(self):
        self.settings('user', allow=['Bash(echo:*)'])
        for command in ("echo 'abc", 'echo "abc', "echo $'abc", "echo $'\\'", "echo $'a\\x00b'"):
            self.assertEqual(self.decide(command)['permissionDecision'], 'ask', command)

    FAKE_HEREDOC = "echo $'a\\' <<EOF'\ntouch PWNED\nEOF"

    def test_heredoc_opener_inside_an_ansi_c_string_hides_nothing(self):
        self.settings('user', allow=['Bash(echo:*)'], deny=['Bash(touch:*)'])
        self.assertEqual(self.decide(self.FAKE_HEREDOC)['permissionDecision'], 'deny')
        self.settings('user', allow=['Bash(echo:*)'])
        self.assertEqual(self.decide(self.FAKE_HEREDOC)['permissionDecision'], 'ask')
        self.assertTrue(ah_run.classify_escapes("echo $'a\\' <<EOF'\nnohup sleep 9 &\nEOF"))

    def test_heredoc_opener_inside_other_quotes_hides_nothing(self):
        self.settings('user', allow=['Bash(echo:*)'], deny=['Bash(touch:*)'])
        for command in ('echo "<<EOF"\ntouch PWNED\nEOF', "echo '<<EOF'\ntouch PWNED\nEOF"):
            self.assertEqual(self.decide(command)['permissionDecision'], 'deny', command)

    def test_a_benign_heredoc_still_works(self):
        self.settings('user', allow=['Bash(cat:*)'], deny=['Bash(touch:*)'])
        out = self.decide("cat <<'EOF'\nit's fine; touch x\nEOF")
        self.assertEqual(out['permissionDecision'], 'allow')
        out = self.decide("cat > f.txt <<'EOF'\nprice is $'5'\nEOF")
        self.assertNotEqual(out['permissionDecision'], 'deny')

    def test_control_the_old_order_lets_the_fake_heredoc_through(self):
        self.settings('user', allow=['Bash(echo:*)'], deny=['Bash(touch:*)'])
        def old_order(command):  # bodies cut before quotes are read (pre-r2), and none of the lexer's reasons kept
            import commit_policy
            text, _bodies = commit_policy._heredocs(command.strip())
            lexed = ah_run._Lexer(text).run()
            lexed.reasons = {}
            return lexed
        with mock.patch.object(ah_run, 'lex', old_order):
            self.assertEqual(self.decide(self.FAKE_HEREDOC)['permissionDecision'], 'allow')

    def test_escape_classifier_sees_through_ansi_c(self):
        self.assertTrue(ah_run.classify_escapes("echo $'\\'' ; nohup x ; echo ''"))
        self.assertEqual(ah_run.classify_escapes("echo $'nohup \\n' ; true"), [])


class HeredocScan(HookFixture):
    """B6: a body is removed only when the opener is certain; everything else keeps all its lines in the checks. No shell runs
    here; HeredocRule hands the same shapes, with an echo on the hidden line, to real shells inside the sandbox."""
    SHAPES = {
        'r2-shape': "echo $'a\\' <<EOF'\n%s\nEOF",
        'param-default': 'echo ${x:-<<EOF}\n%s\nEOF',
        'param-arith': 'echo ${x:0:1<<EOF}\n%s\nEOF',
        'delim-dot': 'echo <<E.F\nE.F\n%s\nE\n',
        'delim-quote-tail': "echo <<'E'OF\nEOF\n%s\nE\n",
        'delim-escape': 'echo <<E\\OF\nEOF\n%s\nE\n',
        'arith-cmd': '((x=1<<EOF))\n%s\nEOF',
        'undecodable-tail': "echo $'a\\' <<EOF'\n%s\nEOF\necho $'",
        'prior-heredoc-desync': "cat <<X\n'\nX\necho $'a\\' <<EOF'\n%s\nEOF\n#'",
        'old-arith': 'echo $[1<<EOF]\n%s\nEOF',
        'partial-quote-head': 'echo <<E"O"F\nEOF\n%s\nE\n',
        'backslash-terminator': 'echo <<EOF\nEOF\\\n\n%s\nEOF',
        'escaped-space-comment': "echo a\\ #'\ncat <<E\n'; %s\nE\n#'",
        'comment-after-paren': "(true)#'\n' cat <<E\n'; %s\nE",
        'case-in-substitution': 'echo "$(case x in x) echo " <<EOF\n"; %s\nEOF\n;; esac)" #"',
        'array-assignment': 'a=(1<<E)\n%s\nE',
        'unquoted-substitution': 'cat <<EOF\n$(%s)\nEOF',
        'unterminated': 'echo <<EOF\n%s',
    }
    BENIGN = {
        'plain': ('cat <<EOF\nhi there\nEOF', 'cat'),
        'python-stdin': ("python3 - <<'PY'\nimport os\nprint(os.getcwd())\nPY", 'python3'),
        'tab-strip': ('cat <<-TAB\n\tbody\n\tTAB', 'cat'),
        'double-quoted': ('cat <<"X"\nit\'s $(literal) `text`\nX', 'cat'),
        'backslash': ('cat <<\\X\n$(literal)\nX', 'cat'),
        'body-with-escape-words': ("cat <<'EOF'\nnohup x &\ntouch PWNED\nEOF", 'cat'),
    }
    TABLE = (
        (ah_run.HEREDOC_CERTAIN, ('cat <<EOF\nhi\nEOF', 'cat <<EOF\nhi\nEOF\n', "python3 - <<'PY'\nprint(1)\nPY", 'cat <<-TAB\n\tb\n\tTAB',
                                  'cat <<\\EOF\nb\nEOF', 'cat << EOF\nb\nEOF', 'cat <<A <<B\n1\nA\n2\nB', 'cat 3<<EOF\nb\nEOF',
                                  'cat <<EOF; echo next\nb\nEOF', 'cat <<EOF | wc -l\nb\nEOF', '(cat <<EOF\nb\nEOF\n)', 'cat <<EOF # note\nb\nEOF',
                                  'cat > "$HOME/f" <<EOF\nb\nEOF', 'cat > ${HOME}/f <<EOF\nb\nEOF', 'if true; then cat <<EOF\nb\nEOF\nfi')),
        (ah_run.HEREDOC_NONE, ('echo hi', 'cat <<<x', 'cat <<<"a b"', 'echo a\necho b', "echo 'no shift'", 'echo $((1+1))', 'echo <\\<x')),
        (ah_run.HEREDOC_UNCERTAIN, ("echo '<<EOF'", 'echo "<<EOF"', 'cat <<', 'cat <<EOF', 'cat <<EOF\nb', 'cat <<E.F\nE.F', "cat <<'E'OF\nEOF",
                                    'cat <<E\\OF\nEOF', 'cat <<"E"F\nEF', 'cat <<$X\n$X', "cat <<E'O'F\nEOF", 'cat <<EOF\nb\n EOF', 'cat <<EOF\nb\nEOF ',
                                    'cat <<EOF\r\nb\r\nEOF\r\n', 'echo $((1<<2))', 'echo $[1<<2]', '((x=1<<2))', 'echo ${x:-<<EOF}',
                                    "git commit -m \"$(cat <<'EOF'\nb\nEOF\n)\"", 'echo `cat <<EOF\nb\nEOF\n`', 'echo # <<EOF', 'echo \\<<EOF\nb\nEOF',
                                    'cat <<EOF\n$(date)\nEOF', 'cat <<EOF\n`date`\nEOF', 'cat <<EOF\nEOF\\\n\nEOF', "cat <<EOF\nb\nEOF\necho $'x'",
                                    'cat <<<<EOF', 'cat <(cat <<E\nb\nE\n)', 'cat <<EOF\nb\nEOF\necho "${x:-y}"', '[[ a << b ]]', 'cat <<EOF\0\nb\nEOF')),
    )

    def test_the_rule_table(self):
        for status, commands in self.TABLE:
            for command in commands:
                self.assertEqual(ah_run.heredoc_scan(command)[0], status, repr(command))

    def test_a_certain_scan_returns_the_bodies_and_markers(self):
        status, text, bodies = ah_run.heredoc_scan("cat <<A <<'B'\n1\nA\n2\nB\necho after")
        self.assertEqual(status, ah_run.HEREDOC_CERTAIN)
        self.assertEqual(text, 'cat <<__HD0__ <<__HD1__\necho after')
        self.assertEqual(bodies, [('1\n', False), ('2\n', True)])
        self.assertEqual(ah_run.heredoc_scan('cat <<-T\n\tb\n\tT')[2], [('b\n', False)])

    def test_an_uncertain_scan_keeps_the_text_whole(self):
        command = 'echo <<E.F\nE.F\nnext line\nE'
        self.assertEqual(ah_run.heredoc_scan(command), (ah_run.HEREDOC_UNCERTAIN, command, []))

    def test_every_hidden_line_is_denied_in_default_and_bypass(self):
        self.settings('user', allow=['Bash(echo:*)', 'Bash(cat:*)'], deny=['Bash(touch:*)'])
        for name, shape in self.SHAPES.items():
            command = shape % 'touch PWNED'
            for mode in ('default', 'acceptEdits', 'dontAsk', 'bypassPermissions'):
                self.assertEqual(self.decide(command, permission_mode=mode).get('permissionDecision'), 'deny', (name, mode))

    def test_without_the_deny_rule_a_hidden_line_is_never_allowed(self):
        self.settings('user', allow=['Bash(echo:*)', 'Bash(cat:*)'])
        for name, shape in self.SHAPES.items():
            command = shape % 'touch PWNED'
            for mode in ('default', 'acceptEdits'):
                self.assertEqual(self.decide(command, permission_mode=mode).get('permissionDecision'), 'ask', (name, mode))
            self.assertEqual(self.decide(command, permission_mode='dontAsk').get('permissionDecision'), 'deny', name)
            out = self.decide(command, permission_mode='bypassPermissions')
            self.assertNotIn('permissionDecision', out, name); self.assertIn('updatedInput', out, name)
            self.assertIn('heredoc: uncertain', out.get('additionalContext', ''), name)

    def test_a_wrapper_or_a_second_command_on_the_hidden_line_is_seen(self):
        self.settings('user', allow=['Bash(echo:*)'], deny=['Bash(touch:*)'])
        for line in ('sudo touch PWNED', 'true; touch PWNED', 'true && touch PWNED', "'touch' PWNED", "$'\\x74ouch' PWNED", 'X=1 touch PWNED'):
            command = "echo $'a\\' <<EOF'\n%s\nEOF\necho $'" % line
            self.assertEqual(self.decide(command, permission_mode='bypassPermissions').get('permissionDecision'), 'deny', line)

    def test_the_escape_classifier_sees_every_hidden_line(self):
        for name, shape in self.SHAPES.items():
            self.assertTrue(ah_run.classify_escapes(shape % 'nohup sleep 9 &'), name)
            self.assertTrue(ah_run.classify_escapes(shape % 'sleep 9 &'), name)

    def test_benign_heredocs_stay_allowed(self):
        self.settings('user', allow=['Bash(cat:*)', 'Bash(python3:*)'], deny=['Bash(touch:*)'])
        for name, (command, _program) in self.BENIGN.items():
            self.assertEqual(self.decide(command).get('permissionDecision'), 'allow', name)
            self.assertEqual(ah_run.classify_escapes(command), [], name)
            out = self.decide(command, permission_mode='bypassPermissions')
            self.assertNotIn('permissionDecision', out, name)
            self.assertNotIn('heredoc: uncertain', out.get('additionalContext') or '', name)

    def test_the_rule_is_not_reached_through_the_shared_commit_policy_parser(self):
        import commit_policy
        with mock.patch.object(commit_policy, '_heredocs', side_effect=AssertionError('commit_policy parser used')):
            self.assertEqual(ah_run.parse_command('cat <<EOF\nb\nEOF').segments, ['cat <<__HD0__'])


class HeredocRule(HookFixture):
    """B6 against real shells: with a harmless echo on the hidden line, a shape the scan calls certain must not print it.
    Shape strings reach real shells, so the class runs only inside the shell sandbox."""
    @classmethod
    def setUpClass(cls):
        shell_sandbox.require()  # shape strings reach real shells: only inside the sandbox container
        super().setUpClass()

    def test_a_certain_scan_agrees_with_the_real_shells(self):
        ran = 0
        cases = list(HeredocScan.SHAPES.values()) + ['cat <<EOF\n%s\nEOF', "cat <<'E'\n%s\nE", 'cat <<-E\n\t%s\n\tE', 'cat <<A <<B\n%s\nA\n%s\nB']
        for shell in ('/bin/bash', '/bin/zsh', '/bin/sh'):
            if not os.access(shell, os.X_OK):
                continue
            for shape in cases:
                command = shape.replace('%s', 'echo HIDDEN-LINE')
                assert_no_real_sudo(command)
                done = subprocess.run([shell, '-c', command], capture_output=True, timeout=10, stdin=subprocess.DEVNULL, cwd=self.temp.name)
                shown = 'HIDDEN-LINE' in done.stdout.decode('utf-8', 'replace').replace('echo HIDDEN-LINE', '')
                ran += shown
                if ah_run.heredoc_scan(command)[0] == ah_run.HEREDOC_CERTAIN:
                    self.assertFalse(shown, (shell, command))
        self.assertGreater(ran, 5, 'the corpus must include shapes the shell really runs, or the row proves nothing')


class Continuations(HookFixture):
    """B10 and S16: a continuation and a run of blanks read as the shell reads them."""
    COMMENT_SHAPES = {
        'natural': "echo a \\\n# don't do this\n%s\n# won't happen",
        'single': "echo a \\\n#'\n%s\n#'",
        'double': 'echo a \\\n#"\n%s\n#"',
        'first-word': "\\\n#'\n%s\n#'",
        'indented': "echo a \\\n  #'\n%s\n#'",
    }

    def test_join_table(self):
        for text, joined in (('a \\\nb', 'a b'), ('a\\\nb', 'ab'), ('"a\\\nb"', '"ab"'), ("'a\\\nb'", "'a\\\nb'"), ("$'a\\\nb' c\\\nd", "$'a\\\nb' cd"),
                             ('# c \\\nb', '# c \\\nb'), ('a # c \\\nb', 'a # c \\\nb'), ('a#c\\\nb', 'a#cb'), ('a\\\\\nb', 'a\\\\\nb'), ('plain', 'plain')):
            self.assertEqual(ah_run.join_continuations(text), joined, repr(text))

    def test_a_comment_after_a_continuation_hides_nothing(self):
        self.settings('user', allow=['Bash(echo:*)'], deny=['Bash(touch:*)'])
        for name, shape in self.COMMENT_SHAPES.items():
            command = shape % 'touch PWNED'
            for mode in ('default', 'acceptEdits', 'dontAsk', 'bypassPermissions'):
                self.assertEqual(self.decide(command, permission_mode=mode).get('permissionDecision'), 'deny', (name, mode))
        self.settings('user', allow=['Bash(echo:*)'])
        for name, shape in self.COMMENT_SHAPES.items():
            self.assertEqual(self.decide(shape % 'touch PWNED').get('permissionDecision'), 'ask', name)

    def test_a_word_split_over_a_continuation_reaches_deny_when_uncertain(self):
        """r5 S22: the physical check reads the text with continuations removed too, and # after ) is a comment."""
        self.settings('user', allow=['Bash(echo:*)'], deny=['Bash(echo HIDDEN-LINE:*)'])
        for command in ("echo $'a\\' <<EOF'\nec\\\nho HIDDEN-LINE\nEOF\necho $'", "(true)#'\nec\\\nho HIDDEN-LINE\n#'", "echo '<<'\necho \\\nHIDDEN-LINE"):
            self.assertTrue(ah_run.parse_command(command).uncertain, command)
            for mode in ('default', 'acceptEdits', 'dontAsk', 'bypassPermissions'):
                self.assertEqual(self.decide(command, permission_mode=mode).get('permissionDecision'), 'deny', (command, mode))
        self.assertIn('echo HIDDEN-LINE', ah_run.physical_parts("x '\nec\\\nho HIDDEN-LINE"))
        self.assertEqual(ah_run.join_continuations("(a)#'\\\nb"), "(a)#'\\\nb")
        self.assertEqual(ah_run.join_continuations('(a)\\\n#x\\\nb'), '(a)#x\\\nb')  # ) and ( end a word, so # opens a comment
        self.assertEqual(ah_run.join_continuations('(\\\n#x\\\nb)'), '(#x\\\nb)')

    def test_a_quote_in_a_joined_fragment_is_uncertain(self):
        for command in ("echo a \\\n'b'", 'echo "a\\\nb"', "echo 'a\\\nb'", "echo $'a\\\nb'", "echo a \\\n# it's", "echo a\\\nb; echo 'c'", "git log \\\n  --format='%H'"):
            self.assertTrue(ah_run.parse_command(command).uncertain, command)
        for command in ('echo a \\\n b', "echo a \\\n b\necho 'c'", 'git log \\\n  -1', "echo 'c'\necho a \\\n b", "cat <<'E'\nit's \\\nE"):
            self.assertFalse(ah_run.parse_command(command).uncertain, command)

    def test_a_continuation_at_the_end_leaves_no_lone_backslash(self):
        self.settings('user', deny=['Bash(echo HIDDEN-LINE:*)'])
        for command in ('echo HIDDEN-LINE\\\n', 'true\necho HIDDEN-LINE\\\n\n'):
            self.assertEqual(self.decide(command, permission_mode='bypassPermissions').get('permissionDecision'), 'deny', command)

    def test_blanks_and_continuations_do_not_defeat_a_deny_rule(self):
        self.settings('user', allow=['Bash(git:*)', 'Bash(touch:*)'], deny=['Bash(git push --force:*)'])
        for command in ('git push  --force origin m', 'git push \\\n  --force origin m', 'git \\\n push --force', 'git\tpush --force',
                        'git\t\tpush\t--force', 'gi\\\nt push --force', '  git   push   --force  ', 'sudo  git  push  --force'):
            for mode in ('default', 'bypassPermissions'):
                self.assertEqual(self.decide(command, permission_mode=mode).get('permissionDecision'), 'deny', (command, mode))

    def test_collapsing_never_widens_an_allow_rule(self):
        self.settings('user', allow=['Bash(echo a b)'])
        self.assertEqual(self.decide('echo a b')['permissionDecision'], 'allow')
        self.assertEqual(self.decide("echo a  b")['permissionDecision'], 'ask')

    def test_a_continued_ordinary_command_still_works(self):
        self.settings('user', allow=['Bash(git:*)'])
        self.assertEqual(self.decide('git log \\\n  -1')['permissionDecision'], 'allow')


class GroupWalk(HookFixture):
    """B11: a group ends where a shell ends it, or the parse is uncertain."""
    SHAPES = {
        'comment-paren': "echo $(echo # ) '\n); %s; echo \"'\" #\"",
        'comment-paren-dq': '$(# ) "\n); %s #"',
        'backtick-escape': "echo `echo \\` ' `; %s; echo \"'\" #\"",
        'procsub-comment': "cat <(echo # ) '\n); %s; echo \"'\" #\"",
        'assign-comment': "x=$(echo # ) '\n); %s; echo \"'\" #\"",
    }

    def test_the_walk_table(self):
        # a group as the program word makes the program dynamic (r6), so the group rows sit after echo
        for text, certain in (('echo hi', True), ('echo $(date)', True), ('echo "$(echo ")")"', False), ('echo $(echo a#b)', True), ("echo $(echo '#')", False),
                              ('echo ${#x} $#', True), ('echo # $(', True), ("# it's\necho", True), ('echo `echo a`', True), ('echo $(echo $(date))', True),
                              ('echo $(echo # c\n)', False), ('echo `echo \\``', False), ('echo `# c`', False), ("echo `echo 'a'`", False), ('echo `echo "a"`', False),
                              ('echo "$[1]"', False), ('echo "$[ \'a\' ]"', False), ('echo $(case x in x) echo;; esac)', False),
                              ('echo "${x:-\'}"', False), ('echo $(echo', False), ('echo `echo', False), ("echo 'a", False), ('$(echo a)', False), ('`echo a`', False)):
            self.assertEqual(not ah_run.parse_command(text).uncertain, certain, repr(text))

    def test_a_group_end_is_a_best_effort_only_when_the_rule_says_uncertain(self):
        self.assertEqual(ah_run.inner_commands('a $(echo ")") b'), ['echo ")"'])
        self.assertEqual(ah_run.parse_command('a $(echo ")") b').segments, ['a X b'])
        self.assertEqual(ah_run.inner_commands("a `echo ')'` b"), ["echo ')'"])
        # shells close backticks at the next unescaped backtick, even inside what looks like a quote (r5 B12)
        self.assertEqual(ah_run.inner_commands("a `echo '` b `echo '` c"), ["echo '", "echo '"])
        self.assertEqual(ah_run.parse_command("a `echo '` b `echo '` c").segments, ['a X b X c'])
        self.assertEqual(ah_run.inner_commands('a $(echo ")"; touch x) b'), ['echo ")"; touch x'])
        self.assertEqual(ah_run.parse_command('a $(echo ")"; touch x) b').inner, ['echo ")"', 'touch x'])

    def test_every_line_after_an_uncertain_group_is_denied(self):
        self.settings('user', allow=['Bash(echo:*)'], deny=['Bash(touch:*)'])
        for name, shape in self.SHAPES.items():
            for mode in ('default', 'acceptEdits', 'dontAsk', 'bypassPermissions'):
                self.assertEqual(self.decide(shape % 'touch PWNED', permission_mode=mode).get('permissionDecision'), 'deny', (name, mode))
            self.assertTrue(ah_run.classify_escapes(shape % 'nohup sleep 9'), name)

    def test_a_quoted_close_does_not_end_a_group_early(self):
        self.settings('user', deny=['Bash(touch:*)'])
        command = 'echo $(echo ")"; touch PWNED; echo ")") #"'
        self.assertEqual(self.decide(command, permission_mode='bypassPermissions').get('permissionDecision'), 'deny')
        self.assertEqual(self.decide('echo $(case x in x) echo ")";; esac; touch PWNED)', permission_mode='bypassPermissions').get('permissionDecision'), 'deny')

    def test_a_comment_apostrophe_does_not_hide_a_later_substitution(self):
        self.settings('user', deny=['Bash(touch:*)'])
        command = "# it's\necho $(touch PWNED)\n# it's"
        self.assertEqual(self.decide(command, permission_mode='bypassPermissions').get('permissionDecision'), 'deny')

    def test_an_ordinary_substitution_is_not_uncertain(self):
        for command in ('echo $(date)', 'x=$(git rev-parse HEAD); echo "$x"', 'echo "$(date)"', "echo `date`", 'cat <(echo a)'):
            self.assertFalse(ah_run.parse_command(command).uncertain, command)
        for command in ('echo "$(echo "a b")"', "cat <(echo 'a # b')"):
            self.assertTrue(ah_run.parse_command(command).uncertain, command)


class CertaintyRule(HookFixture):
    """r5 B12, B14: a quote character in a group, or in a continuation-joined fragment, makes the command uncertain."""
    UNCERTAIN = ("echo `echo '`", 'echo `echo "`', "echo `echo 'a'`", 'echo `echo "a"`', "echo \"$[ 'a' ]\"", "echo `echo \\\\'`", "echo \"`echo '`\"", "echo $(echo 'a')", 'echo $(echo "a")', "echo $(echo $'a')", 'echo "$(echo "a")"',
                 "echo $(echo \\'a)", "cat <(echo 'a')", "cat >(echo 'a')", "((1 '))", '((1 "))', "((1 $'))", "true $((1 '))", 'true "$((1 "))"', "true $[1 ']", 'true "$[1 "]"', "true $[a['1']]",
                 "echo ${x:-'a'}", 'echo "${x:-"a"}"', "for ((i=0; i<1 '; i++)); do true; done", "(true)#'", "true >#'", "echo a\\ #'", "((1)", 'true $[1', "echo $'a\\'b'",
                 # r6: outside the grammar every shell shares (zsh and ksh read (( and $[ their own way; sh and dash do not have them)
                 'true $[1+2]', 'true $[a[1]]', '((x=1+2))', 'for ((i=0;i<1;i++)); do true; done', "for ((i=0;i<1;i++)); do echo 'a'; done", "((1)); echo 'a'")
    CERTAIN = ('echo `date`', 'echo $(date)', 'echo "$(date)"', 'echo "`date`"', 'true $((1+2))', 'true "$((1+2))"', 'echo $(echo $(date))', 'echo `echo $(date)`', "echo 'a' \"b\" $'c'", "echo 'a $(b) `c` ((d'", 'echo "it\'s"',
               'echo ${x} "${y}"', 'echo ${x:-a}', "(cd x && echo 'a')", "# it's\necho hi", "echo a # it's", "echo a#b'c'", "cat <<'E'\n$(it's) `\nE")

    def test_the_rule_table(self):
        for command in self.UNCERTAIN:
            self.assertTrue(ah_run.parse_command(command).uncertain, command)
        for command in self.CERTAIN:
            self.assertFalse(ah_run.parse_command(command).uncertain, command)

    def test_an_uncertain_command_is_never_allowed_and_carries_the_note(self):
        self.settings('user', allow=['Bash(*)'])
        for command in self.UNCERTAIN:
            self.assertEqual(self.decide(command).get('permissionDecision'), 'ask', command)
            self.assertEqual(self.decide(command, permission_mode='acceptEdits').get('permissionDecision'), 'ask', command)
            self.assertEqual(self.decide(command, permission_mode='dontAsk').get('permissionDecision'), 'deny', command)
            out = self.decide(command, permission_mode='bypassPermissions')
            self.assertNotIn('permissionDecision', out, command); self.assertIn('updatedInput', out, command)
            self.assertIn('uncertain', out.get('additionalContext', ''), command)

    def test_a_certain_command_keeps_its_allow_and_no_note(self):
        self.settings('user', allow=['Bash(*)'])
        for command in ("echo 'a' \"b\"", "(cd x && echo 'a')", "echo a#b'c'", 'echo ${x:-a} ${#y}'):
            self.assertEqual(self.decide(command).get('permissionDecision'), 'allow', command)
        self.assertNotIn('uncertain', self.decide("echo 'a'", permission_mode='bypassPermissions').get('additionalContext') or '')

    def test_the_r5_b12_and_b14_shapes_reach_deny_and_the_classifier(self):
        self.settings('user', allow=['Bash(echo:*)'], deny=['Bash(touch:*)'])
        for shape in ("echo `echo '`; %s; echo `echo '`", "echo `echo '`\n%s\necho `echo '`", "echo \"`echo '`\"; %s; echo \"`echo '`\"", "echo `echo a'`\n%s\necho `echo a'`",
                      "((1 '))\n%s\n((1 '))", '((1 "))\n%s\n((1 "))', "true $((1 '))\n%s\ntrue $((1 '))", "true $[1 ']\n%s\ntrue $[1 ']", "echo ${x:-'}\n%s\necho ${x:-'}"):
            for mode in ('default', 'acceptEdits', 'dontAsk', 'bypassPermissions'):
                self.assertEqual(self.decide(shape % 'touch PWNED', permission_mode=mode).get('permissionDecision'), 'deny', (shape, mode))
            self.assertTrue(ah_run.classify_escapes(shape % 'nohup sleep 9 &'), shape)
            self.assertTrue(ah_run.classify_escapes(shape % 'setsid sleep 9'), shape)

    def test_read_through_widens_deny_and_never_allow(self):
        self.settings('user', allow=['Bash(echo:*)', 'Bash(touch a)'], deny=['Bash(touch:*)'])
        for command in ('>x touch y', '2>/dev/null touch y', '</dev/null touch y', 'touch>x y', 'touch<<<x', '$x touch y', '${x} touch y', '${x}touch y', 'touch$x y', '$(true) touch y',
                        '`true` touch y', '=touch y', 'touch${IFS}y', '{touch,y}', '$""touch y'):
            self.assertEqual(self.decide(command, permission_mode='bypassPermissions').get('permissionDecision'), 'deny', command)
        self.settings('user', allow=['Bash(touch a)'])
        for command in ('>x touch a', '$x touch a', 'touch$x a'):
            self.assertEqual(self.decide(command).get('permissionDecision'), 'ask', command)
        for command in ('>f setsid x', '> f setsid x', '2>&1 setsid x', '</dev/null setsid x', '$x setsid y', '${x} setsid y', 'setsid>f x', '$(true) setsid y', '`true` setsid y', '=setsid y',
                        '{setsid,y}', 'setsid${IFS}y'):
            self.assertTrue(ah_run.classify_escapes(command), command)
        for command in ('echo ">f setsid x"', 'git commit -m "$x > setsid y"', 'echo a > f', '$x true', 'grep -c setsid f', '$x', '>f',
                        'ssh dev2 \'cat > "a b"\'', 'ssh dev2 "cat > \'a b\'"'):
            self.assertEqual(ah_run.classify_escapes(command), [], command)


class HeredocScripts(HookFixture):
    """S15: a heredoc a shell reads is a script, so its lines reach both checks; any other reader keeps it as data."""
    SCRIPT_SHAPES = ("bash <<'E'\n%s\nE", 'sh -s <<E\n%s\nE', "zsh <<-'E'\n\t%s\n\tE", "cat <<'E' | bash\n%s\nE", ". /dev/stdin <<'E'\n%s\nE", "source /dev/stdin <<'E'\n%s\nE",
                     "sudo bash <<'E'\n%s\nE", "timeout 5 bash <<'E'\n%s\nE", "/bin/bash <<'E'\n%s\nE", "ssh dev2 bash <<'E'\n%s\nE", "ssh dev2 <<'E'\n%s\nE", "ssh dev2 'cd /x && sh' <<'E'\n%s\nE",
                     # r5 S23: compound and variable hosts, a function, and a body kept for later
                     "{ /bin/bash; } <<'E'\n%s\nE", "(/bin/bash) <<'E'\n%s\nE", "if true; then /bin/bash; fi <<'E'\n%s\nE", "while true; do /bin/bash; break; done <<'E'\n%s\nE",
                     "for i in 1; do /bin/bash; done <<'E'\n%s\nE", "case x in x) /bin/bash;; esac <<'E'\n%s\nE", "f () { /bin/bash; }\nf <<'E'\n%s\nE", "function f { /bin/bash; }\nf <<'E'\n%s\nE",
                     "x=/bin/bash; $x <<'E'\n%s\nE", "x=/bin/bash; ${x} <<'E'\n%s\nE", "$BASH <<'E'\n%s\nE", "exec 3<<'E'\n%s\nE\n. /dev/fd/3", "exec <<'E'\n%s\nE\n/bin/bash", "read -r x <<'E'\n%s\nE\neval \"$x\"",
                     "cat <<'E' | xargs -I{} /bin/bash -c '{}'\n%s\nE")
    DATA_SHAPES = ("cat <<'E'\n%s\nE", "python3 - <<'E'\n%s\nE", "cat > f.sh <<'E'\n%s\nE", "ssh dev2 'cat > f' <<'E'\n%s\nE", "ssh dev2 python3 - <<'E'\n%s\nE",
                   "ssh dev2 'cd /x && cat > f' <<'E'\n%s\nE", "python3 -c 'a;b(c)' <<'E'\n%s\nE", "cat 3<<'E'\n%s\nE", "source venv/bin/activate && python3 - <<'E'\n%s\nE")

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(host_table, 'resolve', lambda target, ssh_args=(), run=None: host_table.Resolved('elsewhere.example.test', 22))
        patcher.start(); self.addCleanup(patcher.stop)

    def test_script_lines_reach_deny_and_the_classifier(self):
        self.settings('user', deny=['Bash(touch:*)'])
        for shape in self.SCRIPT_SHAPES:
            for mode in ('default', 'bypassPermissions'):
                self.assertEqual(self.decide(shape % 'touch PWNED', permission_mode=mode).get('permissionDecision'), 'deny', (shape, mode))
            self.assertTrue(ah_run.classify_escapes(shape % 'nohup sleep 9 &'), shape)
            self.assertTrue(ah_run.classify_escapes(shape % 'setsid sleep 9'), shape)

    def test_a_script_is_never_auto_allowed(self):
        self.settings('user', allow=['Bash(bash:*)', 'Bash(cat:*)'])
        self.assertEqual(self.decide("bash <<'E'\necho hi\nE")['permissionDecision'], 'ask')
        self.assertEqual(self.decide("cat <<'E'\necho hi\nE")['permissionDecision'], 'allow')

    def test_any_other_reader_keeps_the_body_as_data(self):
        self.settings('user', deny=['Bash(touch:*)'])
        for shape in self.DATA_SHAPES:
            self.assertNotEqual(self.decide(shape % 'touch PWNED', permission_mode='bypassPermissions').get('permissionDecision'), 'deny', shape)
            self.assertEqual(ah_run.classify_escapes(shape % 'nohup sleep 9 &'), [], shape)

    def test_the_script_table(self):
        def bodies(command):
            return ah_run.script_bodies(ah_run.lex(command))
        self.assertEqual(bodies("bash <<'A'\none\nA\ncat <<'B'\ntwo\nB"), ['one\n'])
        self.assertEqual(bodies("cat <<'A' <<'B'\none\nA\ntwo\nB"), [])
        self.assertEqual(bodies("{ bash; } <<'A'\none\nA"), ['one\n'])
        self.assertEqual(bodies("(bash) <<'A'\none\nA"), ['one\n'])
        self.assertEqual(bodies("ssh dev2 <<'A'\none\nA"), ['one\n'])
        self.assertEqual(bodies('bash'), [])
        # a pipeline into a shell, xargs and the other hidden readers are outside the grammar: the whole text is checked
        for command in ("cat <<'A' | sh\none\nA", "cat <<'A' | xargs echo\none\nA", "exec 3<<'A'\none\nA\n. /dev/fd/3"):
            self.assertTrue(ah_run.parse_command(command).uncertain, command)

    def test_a_quoted_code_host_is_uncertain_and_its_text_reaches_deny(self):
        self.settings('user', deny=['Bash(touch:*)'])
        for shape in ("cat <<'E' | xargs echo\n%s\nE", "cat <<'E' | xargs -I{} sh -c '{}'\n%s\nE"):
            self.assertTrue(ah_run.parse_command(shape % 'touch PWNED').uncertain, shape)
            self.assertEqual(self.decide(shape % 'touch PWNED', permission_mode='bypassPermissions').get('permissionDecision'), 'deny', shape)


class EndState(HookFixture):
    """The property behind rounds 1-4: if a real shell runs the hidden line, the hook's bypass decision is deny, for every
    scan status; and a certain scan means no shell ran it. The hidden line is an echo, the only command any row runs."""
    @classmethod
    def setUpClass(cls):
        shell_sandbox.require()  # table strings reach real shells: only inside the sandbox container
        super().setUpClass()

    LINE = 'echo HIDDEN-LINE'
    SHELLS = [s for s in ('/bin/bash', '/bin/zsh', '/bin/sh') if os.access(s, os.X_OK)]
    # name: (shape, scan status, whether /bin/bash runs the line)
    TABLE = {
        'r1-ansi-quote': ("echo $'\\'' ; %s ; echo ''", 'none', True),
        'r2-ansi-opener': ("echo $'a\\' <<EOF'\n%s\nEOF", 'uncertain', True),
        'r3-param-default': ('echo ${x:-<<EOF}\n%s\nEOF', 'uncertain', True),
        'r3-param-arith': ('echo ${x:0:1<<EOF}\n%s\nEOF', 'uncertain', True),
        'r3-delim-dot': ('echo <<E.F\nE.F\n%s\nE\n', 'uncertain', True),
        'r3-delim-quote-tail': ("echo <<'E'OF\nEOF\n%s\nE\n", 'uncertain', True),
        'r3-delim-escape': ('echo <<E\\OF\nEOF\n%s\nE\n', 'uncertain', True),
        'r3-arith': ('((x=1<<EOF))\n%s\nEOF', 'uncertain', True),
        'r3-undecodable': ("echo $'a\\' <<EOF'\n%s\nEOF\necho $'", 'uncertain', True),
        'r3-prior-desync': ("cat <<X\n'\nX\necho $'a\\' <<EOF'\n%s\nEOF\n#'", 'uncertain', True),
        'r3-backslash-terminator': ('echo <<EOF\nEOF\\\n\n%s\nEOF', 'uncertain', True),
        'r3-escaped-space-comment': ("echo a\\ #'\ncat <<E\n'; %s\nE\n#'", 'uncertain', True),
        'r3-comment-after-paren': ("(true)#'\n' cat <<E\n'; %s\nE", 'uncertain', True),
        'r4-dbracket': ('[[ a << b ]]\n%s\nb', 'uncertain', False),
        'r4-cont-natural': ("echo a \\\n# don't do this\n%s\n# won't happen", 'none', True),
        'r4-cont-single': ("echo a \\\n#'\n%s\n#'", 'none', True),
        'r4-cont-double': ('echo a \\\n#"\n%s\n#"', 'none', True),
        'r4-cont-first-word': ("\\\n#'\n%s\n#'", 'none', True),
        'r4-comment-paren': ("echo $(echo # ) '\n); %s; echo \"'\" #\"", 'none', True),
        'r4-comment-paren-dq': ('$(# ) "\n); %s #"', 'none', True),
        'r4-backtick-escape': ("echo `echo \\` ' `; %s; echo \"'\" #\"", 'none', True),
        'r4-shell-heredoc': ("bash <<'E'\n%s\nE", 'certain', True),
        'r4-sh-heredoc': ("sh -s <<E\n%s\nE", 'certain', True),
        'r4-attached-opener': ("true `true <<'E'`\n%s<<-E\nE", 'uncertain', True),
        'r4-attached-redirect': ("echo $'a\\' <<EOF'\n%s>/dev/null\nEOF", 'uncertain', False),
        'plain-line': ('echo a\n%s', 'none', True),
        'second-command': ('echo a; %s', 'none', True),
        'comment-apostrophe-substitution': ("# it's\necho $(%s)\n# it's", 'none', True),
    }
    QUIET = {  # the line is text here: the hook must neither run it nor refuse it, or the table would pass by denying everything
        'none-single-quoted': ("echo 'a\n%s\nb'", 'none'),
        'none-double-quoted': ('echo "a\n%s\nb"', 'none'),
        'none-comment': ('echo a # %s', 'none'),
        'certain-cat': ("cat <<'E'\n%s\nE", 'certain'),
        'certain-unquoted': ('cat <<E\n%s\nE', 'certain'),
        'certain-tab': ('cat <<-E\n\t%s\n\tE', 'certain'),
    }

    def setUp(self):
        super().setUp()
        self.settings('user', deny=['Bash(echo HIDDEN-LINE:*)'])

    def runs(self, shell, command):
        assert_no_real_sudo(command)
        done = subprocess.run([shell, '-c', command], capture_output=True, timeout=5, stdin=subprocess.DEVNULL, cwd=self.temp.name)
        return 'HIDDEN-LINE' in done.stdout.decode('utf-8', 'replace').split('\n')  # bytes: a printed CR is not a line end

    def bypass(self, command):
        return self.decide(command, permission_mode='bypassPermissions').get('permissionDecision')

    def test_the_table_agrees_with_the_shells(self):
        for name, (shape, status, bash_runs) in self.TABLE.items():
            command = shape % self.LINE
            self.assertEqual(ah_run.heredoc_scan(command)[0], status, name)
            self.assertEqual(self.runs('/bin/bash', command), bash_runs, name)
            self.assertEqual(self.bypass(command), 'deny', name)
            for shell in self.SHELLS:
                if self.runs(shell, command):
                    self.assertNotEqual(self.bypass(command), None, (name, shell))

    def test_the_quiet_rows_are_neither_run_nor_refused(self):
        for name, (shape, status) in self.QUIET.items():
            command = shape % self.LINE
            self.assertEqual(ah_run.heredoc_scan(command)[0], status, name)
            for shell in self.SHELLS:
                self.assertFalse(self.runs(shell, command), (name, shell))
            self.assertIsNone(self.bypass(command), name)

    def test_seeded_soup_holds_the_end_state(self):
        import random
        seed = 14548
        rng = random.Random(seed)
        tokens = ['echo', 'cat', 'true', ' ', ' ', '\n', '\n', '<<E', "<<'E'", '<<-E', '<<<x', 'E', "'", "'", '"', '"', '#', ' #', '\\', '\\\n', '$x', '${x}', '${',
                  '}', "$'", '`', '$(', '(', ')', '((', '))', ';', ';;', '&&', '|', 'case x in x)', 'esac', '[[', ']]', '$[', ']',
                  "echo $(echo # ) '", '\\\n#\'', '<<E.F', "<<'E'F", '${x:-<<E}', '`echo \\` \' `']
        checked = ran = 0
        for _ in range(250):
            head = ''.join(rng.choice(tokens) for _ in range(rng.randint(1, 8)))
            tail = ''.join(rng.choice(tokens) for _ in range(rng.randint(0, 4)))
            command = '%s\n%s\nE\n%s' % (head, self.LINE, tail)
            decision, status = self.bypass(command), ah_run.heredoc_scan(command)[0]
            checked += 1
            for shell in self.SHELLS:
                if self.runs(shell, command):
                    ran += 1
                    self.assertEqual(decision, 'deny', (seed, shell, status, command))
                    self.assertNotEqual(status, ah_run.HEREDOC_CERTAIN, (seed, shell, command))
        self.assertEqual(checked, 250); self.assertGreater(ran, 50, 'seed %d: too few shell runs to prove anything' % seed)

    def test_control_the_old_parse_fails_the_table(self):
        """The pre-r4 reading: a # inside a group is a plain word character and no reason is recorded."""
        real = ah_run._Lexer._comment
        def old_comment(lexer, i, st):
            if st.group:
                st.cur.append('#')
                return i + 1
            return real(lexer, i, st)
        command = self.TABLE['r4-comment-paren'][0] % self.LINE
        with mock.patch.object(ah_run._Lexer, '_comment', old_comment):
            self.assertIsNone(self.bypass(command), 'without the group comment check this shape must slip through')
        self.assertTrue(self.runs('/bin/bash', command))


class Differential(HookFixture):
    """End state of every shape from reviews r1-r5, through real shells, pinned in tests/fixtures/ah_run/differential.json.

    Each row holds the hook's verdict (certain or uncertain), whether the deny rule matched the marker line in bypass, and which
    shells printed the marker. The row's pins apply only to the exact shell versions the table was made on; the invariants apply
    everywhere: certain and no deny means no shell printed the marker, uncertain is never allowed, a printed marker was denied and
    seen by the escape classifier, and a rewritten command ends as the typed one does. `limit` rows are programs handed the text
    at run time (eval, sh -c, <<<, a pipe into a shell, python, a file written then run); no text model sees those, and the table
    says so instead of hiding them. Live rows print only the echo marker; besides echo, true, read and cat they use shell builtins
    (alias, shopt, setopt, trap, ...), a shell or python3 handed that echo, and a stub ssh that copies stdin. A stub sudo sits first
    on PATH and fails, and a row that names sudo is data only (`live: false`, r6 S30): `stdout` refuses to run it."""
    @classmethod
    def setUpClass(cls):
        shell_sandbox.require()  # table rows reach real shells: only inside the sandbox container
        super().setUpClass()

    TABLE = json.loads((Path(__file__).resolve().parent / 'fixtures' / 'ah_run' / 'differential.json').read_text())
    RULE = 'Bash(echo HIDDEN-LINE:*)'
    MARKER = 'HIDDEN-LINE'
    STUB = '#!/bin/sh\ncat\n'
    SUDO_STUB = '#!/bin/sh\nexit 126\n'
    observed = {}

    @classmethod
    def shells(cls):
        if not hasattr(cls, '_shells'):
            found = {}
            for name, path in (('bash', '/bin/bash'), ('bash', '/opt/homebrew/bin/bash'), ('bash', '/usr/local/bin/bash'), ('bash', '/usr/bin/bash'), ('zsh', '/bin/zsh'), ('zsh', '/usr/bin/zsh'),
                               ('sh', '/bin/sh'), ('dash', '/bin/dash'), ('dash', '/usr/bin/dash'), ('ksh', '/bin/ksh'), ('ksh', '/usr/bin/ksh')):
                if os.access(path, os.X_OK):
                    version = subprocess.run([path, '-c', 'echo ${BASH_VERSION:-}${ZSH_VERSION:-}${KSH_VERSION:-}'], capture_output=True, text=True, timeout=10).stdout.strip()
                    key = name if name != 'bash' else 'bash' + version[:1]
                    found.setdefault(key, (path, version))
            cls._shells = found
        return cls._shells

    def setUp(self):
        super().setUp()
        self.bin = Path(self.temp.name) / 'bin'; self.bin.mkdir()
        (self.bin / 'ssh').write_text(self.STUB); (self.bin / 'ssh').chmod(0o755)
        (self.bin / 'sudo').write_text(self.SUDO_STUB); (self.bin / 'sudo').chmod(0o755)
        self.policy = Path(self.temp.name) / 'policy.json'
        self.policy.write_text(json.dumps({'hosts': {'dev2.example.test': {'role': 'worker', 'ah_run': '/opt/ah/ah_run.py'}}, 'self': []}))
        patcher = mock.patch.object(host_table, 'resolve', lambda target, ssh_args=(), run=None: host_table.Resolved({'dev2': 'dev2.example.test'}.get(target, 'elsewhere.example.test'), 22))
        patcher.start(); self.addCleanup(patcher.stop)

    def hook(self, command, mode):
        return self.decide(command, env={'AGENT_HARNESS_RESOURCE_POLICY': str(self.policy)}, permission_mode=mode)

    def stdout(self, shell, command):
        assert_no_real_sudo(command)
        with tempfile.TemporaryDirectory(dir=self.temp.name) as cwd:
            try:
                return subprocess.run([shell, '-c', command], env={**self.env, 'PATH': '%s:%s' % (self.bin, os.environ['PATH'])}, capture_output=True, timeout=5,
                                      stdin=subprocess.DEVNULL, cwd=cwd).stdout.decode('utf-8', 'replace')  # bytes: text mode turns a printed CR into a line end
            except subprocess.TimeoutExpired:
                return None

    def printed(self, row):
        """{shell key: stdout} for the typed text, kept across rows of the class: the runs are the slow part."""
        key = row['group'] + ':' + row['name']
        if not row.get('live', True):
            return {}  # data only: its verdict and deny columns are checked, and no shell is given it
        if key not in self.observed:
            command = row['shape'].replace('%s', self.TABLE['line'])
            self.observed[key] = {name: self.stdout(path, command) for name, (path, _version) in self.shells().items()}
        return self.observed[key]

    def marker_in(self, text):
        return text is not None and self.MARKER in text.split('\n')

    def test_no_live_row_reaches_a_real_sudo(self):
        """r6 S30. Runs no row: every row naming sudo is data only, and the guard in `stdout` refuses the string if one is not."""
        named = [row for row in self.TABLE['rows'] if REAL_SUDO.search(row['shape'].replace('\\\n', ''))]
        self.assertGreaterEqual(len(named), 1, 'the verdict row stays in the table as data')
        for row in named:
            self.assertIs(row.get('live'), False, row['name'])
            self.assertEqual(self.printed(row), {}, row['name'])
            with self.assertRaises(AssertionError):
                self.stdout('/bin/sh', row['shape'].replace('%s', self.TABLE['line']))
        for command in ('sudo bash', 'true; sudo -n true', '"sudo" x', "s'u'do x", 's\\udo x', '/usr/bin/sudo x', 'su\\\ndo x', 'env sudo x'):
            with self.assertRaises(AssertionError, msg=command):
                assert_no_real_sudo(command)
        for command in ('echo pseudo', 'echo sudoku', 'cat sudo.txt', 'echo HIDDEN-LINE'):
            assert_no_real_sudo(command)
        self.assertEqual(os.stat(self.bin / 'sudo').st_mode & 0o111, 0o111)
        self.assertEqual(subprocess.run(['/bin/sh', '-c', 'command -v sudo'], env={**self.env, 'PATH': '%s:%s' % (self.bin, os.environ['PATH'])}, capture_output=True, text=True, timeout=5).stdout.strip(), str(self.bin / 'sudo'))

    def test_the_table_has_two_shells_to_compare(self):
        self.assertGreaterEqual(len(self.shells()), 2, 'the table needs at least two shells to compare')

    def test_what_the_shells_print_agrees_with_the_invariants(self):
        pinned = self.TABLE['pinned_on']
        pinned_shells = {name for name, (_path, version) in self.shells().items() if sys.platform == pinned['platform'] and pinned['shells'].get(name) == version}
        for row in self.TABLE['rows']:
            ran = {name for name, text in self.printed(row).items() if self.marker_in(text)}
            settled = pinned_shells - set(row['unstable'])  # a pipeline into a shell can race in some shells; generation recorded those
            self.assertEqual(ran & settled, set(row['ran']) & settled, row['name'])
            if row['kind'] == 'limit':
                continue
            if row['verdict'] == 'certain' and not row['deny']:
                self.assertEqual(ran, set(), 'certain and no deny, but the marker ran: %s' % row['name'])
            if ran:
                self.assertTrue(row['deny'], 'the marker ran and deny did not match: %s' % row['name'])
                if '%s' in row['shape']:  # setsid names no background, so only the classifier's reading of the line can flag it
                    self.assertTrue(ah_run.classify_escapes(row['shape'].replace('%s', 'setsid sleep 9')), row['name'])

    def test_the_rewritten_text_ends_as_the_typed_text_does(self):
        self.settings('user', deny=[self.RULE])
        changed = 0
        for row in self.TABLE['rows']:
            command = row['shape'].replace('%s', self.TABLE['line'])
            out = self.hook(command, 'bypassPermissions')
            if 'updatedInput' not in out:
                self.assertEqual(row['rewritten'], 'none', row['name'])
                continue
            payload = shlex.split(out['updatedInput']['command'])[-1]
            self.assertEqual('same' if payload == command else 'changed', row['rewritten'], row['name'])
            if payload == command:
                continue
            changed += 1
            for name, (path, _version) in self.shells().items():
                self.assertEqual(self.stdout(path, payload), self.printed(row)[name], (row['name'], name))
        self.assertGreater(changed, 5)

    def holes(self, *groups):
        """{group} of rows the hook lets through in bypass (no deny) while a shell here prints the marker."""
        self.settings('user', deny=[self.RULE])
        found = set()
        for row in self.TABLE['rows']:
            if row['group'] in groups and row.get('live', True):
                command = row['shape'].replace('%s', self.TABLE['line'])
                if self.hook(command, 'bypassPermissions').get('permissionDecision') != 'deny':
                    if any(self.marker_in(text) for text in self.printed(row).values()):
                        found.add(row['group'])
        return found

    def test_control_the_lexer_without_its_reasons_fails_the_invariant(self):
        """r6: drop every reason (everything reads as certain) and the table must find holes: no deny, and a shell printing the
        marker. trap and function bodies run in every shell, so those groups are required on any host."""
        groups = ('r6-B19', 'r6-B20', 'r6-B21', 'r6-host')
        self.assertEqual(self.holes(*groups), set())
        with mock.patch.object(ah_run._Lexer, 'reason', lambda lexer, name: None):
            found = self.holes(*groups)
        self.assertIn('r6-host', found)
        self.assertIn('r6-B19', found)

    def test_control_the_hook_without_the_literal_rule_fails_the_invariant(self):
        """r6 B22: an uncertain row is refused in bypass only through the literal rule; without it the marker runs."""
        self.assertEqual(self.holes('r6-B22'), set())
        with mock.patch.object(ah_run, 'denied_as_literal', lambda command, rules, lexed=None: None):
            self.assertIn('r6-B22', self.holes('r6-B22'))

    def test_control_a_rewrite_that_joins_body_lines_fails_the_end_state(self):
        command = next(row['shape'] for row in self.TABLE['rows'] if row['name'] == 'b13-terminator-appears-table').replace('%s', self.TABLE['line'])
        joined = command.replace('\\\n', '')  # what a rewrite that joined continuations inside bodies would run
        self.assertEqual(joined.split('\n', 1)[1], 'E\n' + self.TABLE['line'] + '\nE')
        self.assertTrue(any(self.marker_in(self.stdout(path, joined)) for path, _version in self.shells().values()))
        self.assertFalse(any(self.marker_in(self.stdout(path, command)) for path, _version in self.shells().values()))


class HookIsolation(Fixture):
    """r5 S26: the hook's own subcommands run isolated, so a module on PYTHONPATH or in the cwd neither runs nor breaks them."""
    DECOYS = ('signal', 'os', 'site', 'encodings', 'time', 'fcntl', 'subprocess', 'json', 'threading', 'usage_guard', 'host_table', 'pathlib', 'argparse', 'hashlib')
    FORMS = (('hook',), ('ledger', '--limit', '1'), ('kill', '--task', 'nope'), ('mask', 'x'))
    INPUT = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': 'echo hi'}, 'session_id': 's', 'permission_mode': 'bypassPermissions'})

    def setUp(self):
        super().setUp()
        self.dirty = Path(self.temp.name) / 'dirty'; self.dirty.mkdir()
        for name in self.DECOYS:
            (self.dirty / (name + '.py')).write_text('import sys\nsys.stderr.write("MARKER-%s\\n")\n' % name)

    def run_form(self, form, *flags, cwd=None, **env):
        return subprocess.run([sys.executable, *flags, AH, *form], env={**self.env, 'HOME': self.temp.name, **env}, cwd=cwd or self.temp.name, input=self.INPUT, capture_output=True, text=True, timeout=30)

    def test_every_subcommand_survives_a_dirty_pythonpath_and_cwd(self):
        for form in self.FORMS:
            for label, kwargs in (('PYTHONPATH', {'PYTHONPATH': str(self.dirty)}), ('cwd', {'cwd': str(self.dirty)}), ('PYTHONHOME', {'PYTHONHOME': '/nonexistent'})):
                result = self.run_form(form, '-I', **kwargs)
                self.assertEqual(result.returncode, 0, (form, label, result.stderr))
                self.assertNotIn('MARKER', result.stderr, (form, label))
        wrapped = json.loads(self.run_form(('hook',), '-I', PYTHONPATH=str(self.dirty)).stdout)
        self.assertIn('updatedInput', wrapped['hookSpecificOutput'])

    def test_control_without_isolation_the_decoy_runs(self):
        self.assertIn('MARKER', self.run_form(('mask', 'x'), PYTHONPATH=str(self.dirty)).stderr)

    def test_the_hook_builds_only_isolated_lines(self):
        source = Path(AH).read_text()
        self.assertEqual(re.findall(r"""['"]python3['"],(?!\s*['"]-I['"])""", source), [])
        self.assertEqual(re.findall(r"""sys\.executable,(?!\s*['"]-I['"])""", source), [])

    def test_anything_that_wires_the_script_uses_the_isolated_form(self):
        """Nothing wires the hook at this commit (the installer slice comes last); this row holds that slice to -I."""
        root = HOOKS.parents[1]
        invoke = re.compile(r'python[\d.]*((?:\s+-[A-Za-z]+)*)\s+\S*ah_run\.py')
        files = [root / 'install.py', root / 'install_codex.py', *(path for pattern in ('*.py', '*.json', '*.sh', '*.toml') for path in (root / 'harness').rglob(pattern))]
        self.assertGreater(len(files), 10)
        bad = []
        for path in files:
            for found in invoke.finditer(path.read_text(errors='replace') if path.is_file() else ''):
                if '-I' not in found.group(1):
                    bad.append((str(path), found.group()))
        self.assertEqual(bad, [])
        self.assertTrue(invoke.search('python3 -S /x/ah_run.py hook'), 'the row must be able to see an unisolated line')


PRIVILEGE_TOOLS = re.compile(r'(?:^|[^A-Za-z0-9_.-])(sudo|doas|su|pkexec|runuser|run0|chroot|nsenter|setpriv|unshare|capsh|setcap|sg|newgrp|login)'
                             r'(?:$|[^A-Za-z0-9_.-])')


def names_a_privilege_tool(command):
    return bool(PRIVILEGE_TOOLS.search(re.sub(r'''['"\\]''', '', command.replace('\\\n', ''))))


class DifferentialVerdicts(HookFixture):
    """The table's hook columns (the verdict, deny in bypass, never allowed when uncertain), checked on every host without
    running a shell. The shell columns are Differential's and run only inside the sandbox."""
    TABLE = Differential.TABLE
    RULE = Differential.RULE
    GROUPS = ('r1-B1', 'r2-B4', 'r3-B6', 'r4-B10', 'r4-B11', 'r4-S15', 'r5-B12', 'r5-B13', 'r5-B14', 'r5-S22', 'r5-S23',
              'r6-B15', 'r6-B16', 'r6-B17', 'r6-B18', 'r6-B19', 'r6-B20', 'r6-B21', 'r6-B22', 'r6-host', 'r6-wrapper', 'r6-path',
              'r6-state', 'r6-limit', 'r6-N22', 'r7-H1', 'r7-M1', 'r7-M2', 'r7-L1')

    def setUp(self):
        super().setUp()
        self.policy = Path(self.temp.name) / 'policy.json'
        self.policy.write_text(json.dumps({'hosts': {'dev2.example.test': {'role': 'worker', 'ah_run': '/opt/ah/ah_run.py'}}, 'self': []}))
        patcher = mock.patch.object(host_table, 'resolve', lambda target, ssh_args=(), run=None: host_table.Resolved({'dev2': 'dev2.example.test'}.get(target, 'elsewhere.example.test'), 22))
        patcher.start(); self.addCleanup(patcher.stop)

    def hook(self, command, mode):
        return self.decide(command, env={'AGENT_HARNESS_RESOURCE_POLICY': str(self.policy)}, permission_mode=mode)

    def commands(self):
        for row in self.TABLE['rows']:
            yield row, row['shape'].replace('%s', self.TABLE['line'])

    def test_the_table_covers_every_round_and_can_fail(self):
        rows = self.TABLE['rows']
        self.assertGreaterEqual(len(rows), 390)
        groups = {row['group'] for row in rows}
        for group in self.GROUPS:
            self.assertIn(group, groups)
        self.assertGreater(sum(row['verdict'] == 'certain' for row in rows), 50)
        self.assertGreater(sum(row['verdict'] == 'uncertain' for row in rows), 150)
        self.assertGreater(sum(bool(row['ran']) for row in rows), 100)
        self.assertEqual(len({(row['group'], row['name']) for row in rows}), len(rows))

    def test_verdict_and_deny_match(self):
        self.settings('user', deny=[self.RULE])
        for row, command in self.commands():
            self.assertEqual('uncertain' if ah_run.parse_command(command).uncertain else 'certain', row['verdict'], row['name'])
            self.assertEqual(self.hook(command, 'bypassPermissions').get('permissionDecision') == 'deny', row['deny'], row['name'])

    def test_uncertain_is_never_allowed(self):
        self.settings('user', allow=['Bash(*)'])
        for row, command in self.commands():
            if row['verdict'] == 'uncertain':
                self.assertNotEqual(self.hook(command, 'default').get('permissionDecision'), 'allow', row['name'])
                self.assertEqual(self.hook(command, 'dontAsk').get('permissionDecision'), 'deny', row['name'])

    def test_quiet_rows_are_data_and_stay_allowed(self):
        rows = [row for row in self.TABLE['rows'] if row['group'] == 'quiet-data']
        self.assertGreater(len(rows), 8)
        for row in rows:
            self.assertEqual((row['verdict'], row['deny'], row['ran']), ('certain', False, []), row['name'])

    def test_every_row_naming_a_privilege_tool_is_data_only(self):
        """Coordinator rule after r6 S30: such a row is never executed, on any host, sandbox included."""
        named = [row for row in self.TABLE['rows'] if names_a_privilege_tool(row['shape'])]
        self.assertGreaterEqual(len(named), 1)
        for row in named:
            self.assertIs(row.get('live'), False, row['name'])
        for command in ('sudo x', 'doas x', "s'u' -c x", 'pkexec x', 'x | runuser -u y z', 'chroot / x', 'nsenter -t 1 x'):
            self.assertTrue(names_a_privilege_tool(command), command)
        for command in ('echo pseudo', 'echo HIDDEN-LINE', 'cat sudo.txt', 'git log --summary', 'echo result'):
            self.assertFalse(names_a_privilege_tool(command), command)

    def test_limit_rows_name_what_the_hook_does_not_claim(self):
        limits = [row for row in self.TABLE['rows'] if row['kind'] == 'limit']
        self.assertGreaterEqual(len(limits), 8)
        names = {row['name'] for row in limits}
        for name in ('python-c', 'python-stdin', 'built-program-name', 'hash-renames-a-program', 'file-written-then-run'):
            self.assertIn(name, names)


class LexerReasons(HookFixture):
    """r6: `certain` is a closed claim the lexer earns. Each row is a command and a reason it must record; a reason named in the
    source without a row here fails the coverage test, so a new reason cannot land untested."""
    ROWS = {
        'nul': 'echo a\0b', 'character': 'echo caf\u00e9', 'hash-glued': '(true)#x', 'comment-in-group': 'echo $(echo # c\n)',
        'hash-after-continuation': 'echo a \\\n#x', 'heredoc-lookalike': "echo '<<E'", 'hash-after-escaped-blank': 'echo a\\ #b',
        'split-word': 'ec\\\nho a', 'split-operator': 'echo a &\\\n& echo b', 'continuation-after-opener': 'cat <<E \\\nx\nb\nE',
        'trailing-backslash': 'echo a\\', 'quoted-continuation': "echo 'a' \\\nb", 'quote-in-group': "echo $(echo 'a')",
        'heredoc-quoted-newline': "cat <<E 'a\nb'\nx\nE", 'unterminated': "echo 'a", 'backslash-in-backtick': 'echo `echo \\$x`',
        'arith': 'echo $((a)(b))', 'param-expansion': 'echo ${ x; }', 'old-arith': 'echo $[1]', 'dollar-special-quote': "echo $#'a'",
        'dbracket': '[[ -f x ]]', 'bracket-in-word': 'echo a[1]', 'lone-brace': 'echo }', 'attached-paren': 'echo a(b)',
        'arith-command': '((x=1))', 'stray-paren': 'echo a )', 'word-after-close': '(true) x', 'for-header': 'for 1 in a; do true; done',
        'keyword-order': 'then true', 'unclosed-keyword': 'if true; then true', 'case-operator': 'true ;; true', 'empty-command': '; true',
        'dangling-operator': 'true &&', 'zsh-disown': 'true &| true', 'pipe-amp': 'true |& cat', 'redirect-target': 'echo >',
        'escaped-redirect': 'echo \\> f', 'attached-procsub': 'cat a<(true)', 'heredoc-in-group': 'echo $(cat <<E\nb\nE\n)',
        'heredoc-opener': 'cat <<E.F\nE.F', 'heredoc-body': 'cat <<E\n$(date)\nE', 'heredoc-unterminated': 'cat <<E\nb',
        'heredoc-with-group': 'echo $(date); cat <<E\nb\nE', 'nesting': 'echo ' + '$(' * 20 + 'true' + ')' * 20,
        'subscript-code': "x='a[$(true)]'", 'state-variable': 'PS4=x true', 'dynamic-program-word': '$x a', 'set-option': 'set -o vi',
        'find-exec': 'find . -exec true {} +', 'git-alias': 'git -c alias.x=y x', 'source-dev': '. /dev/stdin', 'exec-redirect': 'exec 3>f', 'shell-dev': 'bash /dev/fd/3',
        'wrapper-option': 'nice --adj=5 true', 'dynamic-name': 'printf -v "$v" x', 'arith-variable': 'echo $((t))',
        'amp-redirect-words': 'true &>f x', 'ansi-c': "echo $'\\c'", 'pipe-into-shell': 'echo x | bash', 'shell-dynamic-arg': 'bash $x',
        'quoted-code:shell-c': "bash -c 'true'", 'quoted-code:shell-here-string': 'bash <<<x', 'quoted-code:env-S': "env -S 'true'",
        'wrapper-depth': 'nice ' * 13 + 'true',
        'quoted-code:ssh-option': "ssh -o 'ProxyCommand=true' dev2 ls",
    }
    CERTAIN = ('git status', 'ls -la | head -5', 'cd sub && make test', "git commit -m 'fix: a thing'", 'for f in *.py; do echo "$f"; done',
               'if [ -f x ]; then cat x; fi', 'echo $(date)', 'x=1; echo $x', 'echo ${HOME}/a ${x:-b} ${#x} ${x%.py}', "python3 - <<'PY'\nprint(1)\nPY",
               'set -euo pipefail', 'set -e; echo a', 'export A=1', 'cat <<EOF\n$HOME and ${HOME}\nEOF', 'echo a > f 2>&1', 'cmd 2>/dev/null || true',
               'echo "it\'s"', "echo $'a\\tb'", 'while read -r l; do echo "$l"; done < f', '[ -d x ] || mkdir x', 'echo {a,b}', 'echo ~/x',
               "echo 'caf\u00e9'", 'echo "\u2603"', "cat <<'E'\ncaf\u00e9 \u2603\nE", 'echo a # caf\u00e9', 'git log --format=%h -3',
               'gh pr view 12 --json title', 'grep -n "a b" f | wc -l', 'timeout 30 make', 'env A=1 B=2 make', 'make -j4 2>&1 | tail -5',
               '(cd x && make)', 'a=$(git rev-parse HEAD) && echo "$a"', 'echo $((1+2))', 'until false; do break; done', '! true',
               '{ echo a; echo b; } > f', 'test -n "$x" && echo y', 'sleep 1 & wait', 'echo a; echo b\necho c', 'ssh dev2 ls')

    def test_every_row_records_its_reason(self):
        for name, command in self.ROWS.items():
            self.assertIn(name, ah_run.parse_command(command).reasons, repr(command))

    PINNED = {  # the lists as reviewed in r6 (B19-B21, the quoted-code hosts); a name dropped from the source fails here
        'parse-word:': 'function alias unalias shopt setopt unsetopt emulate enable disable hash bindkey bind zmodload autoload repeat noglob '
                       'nocorrect foreach select coproc case esac declare typeset readonly sched',
        'quoted-code:': 'trap eval let mapfile readarray compgen complete compctl fc print',
        'wrapper:': 'busybox stdbuf flock script watch xargs parallel nsenter chroot unshare setpriv su doas pkexec runuser fakeroot strace',
    }

    def test_the_named_lists_keep_every_reviewed_name(self):
        for prefix, names in (('parse-word:', ah_run.PARSE_CHANGING), ('quoted-code:', ah_run.QUOTED_CODE), ('wrapper:', ah_run.UNPEELED_WRAPPERS)):
            self.assertEqual(set(self.PINNED[prefix].split(' ')) - names, set(), prefix)
            for name in self.PINNED[prefix].split(' '):
                self.assertIn(prefix + name, ah_run.parse_command('%s x' % name).reasons, name)

    def test_every_named_list_member_records_its_reason(self):
        for prefix, names in (('parse-word:', ah_run.PARSE_CHANGING), ('quoted-code:', ah_run.QUOTED_CODE), ('wrapper:', ah_run.UNPEELED_WRAPPERS)):
            for name in names:
                self.assertIn(prefix + name, ah_run.parse_command('%s x' % name).reasons, name)
                self.assertIn(prefix + name, ah_run.parse_command('true && /usr/bin/%s x' % name).reasons, name)
                self.assertIn(prefix + name, ah_run.parse_command('env A=1 %s x' % name).reasons, name)

    def test_every_reason_in_the_source_has_a_row(self):
        source = Path(ah_run.__file__).read_text()
        named = set(re.findall(r"""\.reason\('([a-z:-]+)'\)""", source))
        self.assertGreater(len(named), 50)
        self.assertEqual(named - set(self.ROWS), set())

    def test_common_commands_stay_certain(self):
        for command in self.CERTAIN:
            self.assertEqual(ah_run.parse_command(command).reasons, [], repr(command))

    def test_a_reason_never_raises_and_nesting_bails_early(self):
        started = time.monotonic()
        for command in ('$(' * 5000, '`' * 5001, '${' * 5000, '((' * 5000, '"$(' * 3000, "$'\\" * 4000, '<<E\n' * 3000, 'if ' * 4000):
            self.assertTrue(ah_run.parse_command(command).uncertain, command[:12])
        self.assertLess(time.monotonic() - started, 8)

    def test_unterminated_bodies_are_read_once(self):
        """Openers that never close: the first body reads to the end, later ones are not read again (the work counted, not
        timed, so load cannot hide a quadratic). 2000 openers rescanned would be about two million body lines."""
        real, seen = ah_run._body_line_runs_code, []

        def counted(line):
            seen.append(line)
            return real(line)
        with mock.patch.object(ah_run, '_body_line_runs_code', counted):
            parsed = ah_run.parse_command('<<E\n' * 2000)
            for opener in ('<<A\n', '<<-B\n', "<<'C'\n", '<<D\n'):
                ah_run.parse_command('cat ' + opener + 'x\n' * 500 + '<<E\n' * 1000)
        self.assertIn('heredoc-unterminated', parsed.reasons)
        self.assertGreater(len(seen), 1999, 'vacuous: no body line was read')
        self.assertLess(len(seen), 20000)
        self.assertLessEqual({'heredoc-body', 'heredoc-unterminated'}, set(ah_run.parse_command('cat <<A\n$(x)\nA\n<<B\nrm y').reasons))

    def test_quoted_unterminated_bodies_are_read_once(self):
        """r8 L3: the counter above sees only unquoted bodies. This one counts every line the body reader reads, so quoted
        openers are bounded too: 3000 of them rescanned would be about 4.5 million lines."""
        for opener in ("<<'E'\n", '<<"E"\n', '<<\\E\n', "<<-'E'\n", '<<E\n'):
            lexer = ah_run._Lexer(opener * 3000).run()
            self.assertIn('heredoc-unterminated', lexer.reasons, opener)
            self.assertGreater(lexer.body_lines, 2998, 'vacuous: %r read no body' % opener)
            self.assertLess(lexer.body_lines, 20000, opener)


class R6Shapes(HookFixture):
    """r6 B15-B21 and the quoted-code hosts, decision only (no shell): the hidden line is denied in every mode, never allowed
    without the rule, and the escape classifier sees it. The real-shell end state is the Differential table's."""
    SHAPES = {
        'B15-param-blank-hash': 'git status ${x:- #}; %s', 'B15-param-tab-hash': 'git status ${x:-\t#}; %s', 'B15-extglob': 'echo @(a #b); %s',
        'B15-subscript': 'a[1 #]=b|%s', 'B15-array': ': a=(b #c) & %s', 'B16-ansi-c': "git status $'\\c' ; %s #'",
        'B16-ansi-c-line': "echo $'\\c'\n%s\n#'", 'B17-funsub': 'git status "${ %s; }"', 'B17-funsub-heredoc': 'cat <<E\n${ %s; }\nE',
        'B18-formfeed': '\f# ; %s', 'B18-vtab': '\v#x\n%s', 'B18-nbsp': '\u00a0#x\n%s', 'B18-nel': '\u0085#x\n%s', 'B18-ideographic': '\u3000#x\n%s',
        'B18-cr': '\r#x\n%s', 'B19-function': 'function f { %s; }; f', 'B19-name-paren': 'f () { %s; }; f',
        'B20-alias-heredoc': 'alias t="echo \'"\nt <<E #\'\n%s\nE', 'B20-alias': "alias e='%s'\ne", 'B20-shopt': "shopt -s expand_aliases\nalias e='%s'\ne",
        'B21-repeat': 'repeat 1 %s', 'B21-noglob': 'noglob %s', 'B21-nocorrect': 'nocorrect %s', 'B21-short-if': 'if [[ 1 = 1 ]] %s',
        'B21-always': '{ true } always { %s }', 'B21-brace-for': 'for i in 1 { %s }', 'B21-paren-for': 'for i (1) %s',
        'host-trap': "trap '%s' EXIT", 'host-eval': "eval '%s'", 'host-bash-c': "bash -c '%s'", 'host-find': 'find . -exec %s \\;',
        'host-xargs': 'echo | xargs %s', 'host-git-alias': "git -c alias.z='!%s' z", 'host-env-S': "env -S '%s'", 'host-emulate': "emulate sh -c '%s'",
        'host-ps4': "PS4='$(%s)'; set -x; true", 'host-zsh-e': "x='$(%s)'; echo ${(e)x}",
    }

    def test_the_hidden_line_is_denied_in_every_mode(self):
        self.settings('user', allow=['Bash(git status:*)', 'Bash(echo:*)', 'Bash(true:*)', 'Bash(cat:*)'], deny=['Bash(touch:*)'])
        for name, shape in self.SHAPES.items():
            command = shape % 'touch PWNED'
            self.assertTrue(ah_run.parse_command(command).uncertain, name)
            for mode in ('default', 'acceptEdits', 'dontAsk', 'bypassPermissions'):
                self.assertEqual(self.decide(command, permission_mode=mode).get('permissionDecision'), 'deny', (name, mode))

    def test_without_the_rule_it_is_never_allowed(self):
        self.settings('user', allow=['Bash(*)'])
        for name, shape in self.SHAPES.items():
            command = shape % 'touch PWNED'
            self.assertEqual(self.decide(command).get('permissionDecision'), 'ask', name)
            self.assertEqual(self.decide(command, permission_mode='dontAsk').get('permissionDecision'), 'deny', name)
            self.assertIn('uncertain', self.decide(command, permission_mode='bypassPermissions').get('additionalContext', ''), name)

    def test_the_escape_classifier_sees_the_hidden_line(self):
        for name, shape in self.SHAPES.items():
            self.assertTrue(ah_run.classify_escapes(shape % 'setsid sleep 9'), name)
            self.assertTrue(ah_run.classify_escapes(shape % 'nohup sleep 9'), name)

    def test_control_the_lexer_without_its_reasons_lets_shapes_through(self):
        self.settings('user', allow=['Bash(*)'], deny=['Bash(touch:*)'])
        with mock.patch.object(ah_run._Lexer, 'reason', lambda lexer, name: None):
            passed = [name for name, shape in self.SHAPES.items()
                      if self.decide(shape % 'touch PWNED', permission_mode='bypassPermissions').get('permissionDecision') != 'deny']
        for name in ('B19-function', 'B21-repeat', 'B21-noglob', 'host-trap', 'host-eval', 'host-bash-c', 'B20-alias'):
            self.assertIn(name, passed)


class LiteralRule(HookFixture):
    """r6 B22: on uncertain text a deny rule refuses when its literal text appears at a word start anywhere, quotes and
    backslash-newlines removed; the escape names the same way. Bypass makes no decision of its own, so this is what stops an
    uncertain command there."""
    FIRST = 'echo "$(echo \'x\')"\n'  # an unrelated first line that makes the whole text uncertain (r6 hand3 A)
    B22 = ('echo "${ %s; }"', 'function f { %s; }; f', "alias e='%s'\ne", 'repeat 1 %s', 'noglob %s', 'if [[ 1 = 1 ]] %s',
           '{ true } always { %s }', "trap '%s' EXIT", "eval '%s'", 'bash -c "%s"')
    MATCH = (  # (spec, text, matches)
        ('touch:*', 'touch x', True), ('touch:*', 'a; touch x', True), ('touch:*', 'x=$(touch y)', True), ('touch:*', "e='touch y'", True),
        ('touch:*', '"tou"ch x', True), ("touch:*", "t'o'uch x", True), ('touch:*', 'tou\\ch x', True), ('touch:*', 'tou\\\nch x', True),
        ('touch:*', '{ touch x; }', True), ('touch:*', '`touch x`', True), ('touch:*', '/usr/bin/touch x', True), ('touch:*', '=touch x', True),
        ('touch:*', 'touch', True), ('touch:*', 'echo touched', False), ('touch:*', 'retouch x', False), ('touch:*', 'touch-up x', False),
        ('touch:*', 'git commit -m touch-ups', False), ('git push --force:*', 'x; git  push   --force origin', True),
        ('git push --force:*', 'git push --force-with-lease', False), ('rm -rf *', 'a && rm -rf /tmp/x', True), ('rm -rf *', 'rm -r x', False),
        ('npm publish', 'x; npm publish', True), ('npm publish', 'npm publish --dry-run', True), ('npm publish', 'npm publisher', False),
        ('touch:*', 'x=touch y', True), ('touch:*', '--exec=touch y', True), ('touch:*', "ssh -o 'ProxyCommand=touch y' h", True),
        ('touch:*', 'x=touched', False),
    )

    def test_the_match_table(self):
        for spec, text, expected in self.MATCH:
            self.assertEqual(ah_run.literal_match(spec, ah_run.literal_views(text)), expected, (spec, text))

    def test_the_b22_shapes_are_refused_in_every_mode(self):
        self.settings('user', allow=['Bash(echo:*)'], deny=['Bash(echo HIDDEN-LINE:*)'])
        for shape in self.B22:
            command = self.FIRST + shape % 'echo HIDDEN-LINE'
            self.assertTrue(ah_run.parse_command(command).uncertain, shape)
            for mode in ('bypassPermissions', 'default', 'acceptEdits', 'dontAsk'):
                out = self.decide(command, permission_mode=mode)
                self.assertEqual(out.get('permissionDecision'), 'deny', (shape, mode))
            self.assertIn('word start', self.decide(command, permission_mode='bypassPermissions')['permissionDecisionReason'])

    def test_control_without_the_rule_the_b22_shapes_pass_bypass(self):
        self.settings('user', deny=['Bash(echo HIDDEN-LINE:*)'])
        with mock.patch.object(ah_run, 'denied_as_literal', lambda command, rules, lexed=None: None):
            passed = [shape for shape in self.B22 if self.decide(self.FIRST + shape % 'echo HIDDEN-LINE', permission_mode='bypassPermissions').get('permissionDecision') != 'deny']
        self.assertGreaterEqual(len(passed), 8, passed)

    def test_a_certain_command_never_reaches_the_rule(self):
        self.settings('user', allow=['Bash(echo:*)'], deny=['Bash(touch:*)'])
        self.assertEqual(self.decide("echo 'touch x'").get('permissionDecision'), 'allow')
        with mock.patch.object(ah_run, 'denied_as_literal', side_effect=AssertionError('the literal rule ran on certain text')):
            self.decide("echo 'touch x'"); self.decide("cat <<'E'\ntouch x\nE")

    def test_a_glob_program_word_is_matched_against_the_rule(self):
        self.settings('user', deny=['Bash(touch:*)'])
        for command in ('/bin/tou?h x', '/usr/bin/t*h x', '/bin/tou[c]h x', 'x=1; /usr/bin/to?ch y'):
            self.assertEqual(self.decide(command, permission_mode='bypassPermissions').get('permissionDecision'), 'deny', command)
        self.assertNotEqual(self.decide('/bin/l? x', permission_mode='bypassPermissions').get('permissionDecision'), 'deny')
        # fuzz seed 1: a glob with the range N-L. fnmatch raised on Python 3.9 and dropped the range on 3.12 (sandbox r7mod), so
        # the hook reads brackets itself: any one character, the same on every Python, and never an exception.
        self.assertIsNone(self.decide('${<$[echo HIDDEN-LINE)" << E<<-E<&<<<esac]$"<<<((', permission_mode='bypassPermissions').get('permissionDecision'))
        for name, glob, matches in (('touch', 'tou?h', True), ('touch', 't*h', True), ('touch', 'tou[c]h', True), ('touch', 'tou[!x]h', True),
                                    ('touch', 'tou[]]h', True), ('touch', '[z-a]ouch', True), ('touch', 'tou[x-a]h', True), ('touch', 'l?', False),
                                    ('touch', 'tou[ch', False), ('xtouch', 't*', False), ('axb', 'a.b', False)):
            self.assertEqual(ah_run._glob_matches(name, glob), matches, (name, glob))

    def test_what_it_wrongly_catches(self):
        """Pinned false refusals, the price of the rule: a denied word at a word start in prose inside uncertain text."""
        self.settings('user', deny=['Bash(rm:*)'])
        prose = "git commit -m \"$(cat <<'EOF'\nfix: rm stale files from the cache\nEOF\n)\""
        self.assertEqual(self.decide(prose, permission_mode='bypassPermissions').get('permissionDecision'), 'deny')
        self.assertEqual(self.decide(self.FIRST + 'echo note: rm later', permission_mode='bypassPermissions').get('permissionDecision'), 'deny')
        # the certain form of the same message is not refused; the refusal names it
        certain = "git commit -F - <<'EOF'\nfix: rm stale files from the cache\nEOF"
        self.assertNotEqual(self.decide(certain, permission_mode='bypassPermissions').get('permissionDecision'), 'deny')
        self.assertIn("-F - <<'EOF'", self.decide(prose, permission_mode='bypassPermissions')['permissionDecisionReason'])

    def test_escape_names_at_a_word_start_in_uncertain_text(self):
        self.assertTrue(ah_run.classify_escapes(self.FIRST + "x='nohup'"))
        self.assertTrue(ah_run.classify_escapes(self.FIRST + "alias b='setsid sleep 9'"))
        self.assertEqual([r for r in ah_run.classify_escapes(self.FIRST + 'echo look at this batch on screen') if 'detaches' in r], [])
        self.assertEqual(ah_run.classify_escapes("echo 'nohup is a word here'"), [])  # certain text: quoted words are data


class ScanCap(HookFixture):
    """S27 and the coordinator's cap: a command over 64 KiB by byte length is not scanned at all. bypassPermissions and dontAsk
    refuse it, with or without a denied line, naming how to split it; default and acceptEdits ask. At and under the cap the
    command is scanned as before."""
    LINE = 'touch PWNED'

    def command(self, size, denied=False, char='y'):
        head = (self.LINE + '\n') if denied else ''
        filler = size - len((head + 'echo ').encode('utf-8'))
        return head + 'echo ' + char * (filler // len(char.encode('utf-8')))

    def files(self):
        return sorted(p.name for p in (self.reserve / 'ledger' / 'pending').glob('*'))

    def test_over_the_cap_no_ask_modes_refuse_and_others_ask(self):
        self.settings('user', allow=['Bash(*)'], deny=['Bash(touch:*)'])
        for denied in (False, True):
            command = self.command(ah_run.SCAN_CAP + 1, denied)
            self.assertEqual(len(command.encode('utf-8')), ah_run.SCAN_CAP + 1)
            with mock.patch.object(ah_run, 'parse_command', side_effect=AssertionError('scanned over the cap')):
                before = self.files()
                for mode in ('bypassPermissions', 'dontAsk'):
                    out = self.decide(command, permission_mode=mode)
                    self.assertEqual(out['permissionDecision'], 'deny', (mode, denied))
                    for text in ('64 KiB', 'script file', 'scp'):
                        self.assertIn(text, out['permissionDecisionReason'])
                self.assertEqual(self.files(), before)  # a refusal writes no pending row or payload
                for mode in ('default', 'acceptEdits'):
                    out = self.decide(command, permission_mode=mode)
                    self.assertEqual(out['permissionDecision'], 'ask', (mode, denied))
                    self.assertIn('--cmd-file', out['updatedInput']['command'])
                    self.assertIn('not scanned', out['additionalContext'])

    def test_at_and_just_under_the_cap_the_command_is_scanned(self):
        self.settings('user', allow=['Bash(echo:*)'], deny=['Bash(touch:*)'])
        for size in (ah_run.SCAN_CAP, ah_run.SCAN_CAP - 1, 60000):
            denied = self.command(size, True)
            self.assertEqual(len(denied.encode('utf-8')), size)
            for mode in ('default', 'acceptEdits', 'dontAsk', 'bypassPermissions'):
                self.assertEqual(self.decide(denied, permission_mode=mode)['permissionDecision'], 'deny', (size, mode))
            clean = self.command(size)
            self.assertEqual(self.decide(clean)['permissionDecision'], 'allow', size)
            out = self.decide(clean, permission_mode='bypassPermissions')
            self.assertNotIn('permissionDecision', out); self.assertIn('updatedInput', out)

    def test_bytes_not_characters_are_counted(self):
        command = self.command(ah_run.SCAN_CAP + 2, char='\u00e9')
        self.assertLess(len(command), ah_run.SCAN_CAP)
        self.assertGreater(len(command.encode('utf-8')), ah_run.SCAN_CAP)
        self.assertEqual(self.decide(command, permission_mode='bypassPermissions')['permissionDecision'], 'deny')

    def test_over_one_mib_keeps_its_own_refusal_in_every_mode(self):
        command = 'echo ' + 'x' * ah_run.PAYLOAD_CAP
        for mode in ('default', 'bypassPermissions'):
            out = self.decide(command, permission_mode=mode)
            self.assertEqual(out['permissionDecision'], 'deny'); self.assertIn('1 MiB', out['permissionDecisionReason'])

    def test_control_a_cap_that_counts_characters_lets_the_multibyte_command_be_scanned(self):
        command = self.command(ah_run.SCAN_CAP + 2, char='\u00e9')
        real = ah_run.parse_command
        seen = []
        with mock.patch.object(ah_run, 'command_bytes', len), mock.patch.object(ah_run, 'parse_command', lambda text, depth=0: seen.append(1) or real(text, depth)):
            self.decide(command, permission_mode='bypassPermissions')
        self.assertTrue(seen)


class HookDeadline(HookFixture):
    """S27: the hook's own time limit. Passing it refuses in bypassPermissions and dontAsk and asks in the other modes."""

    def run_hook(self, mode, delay, limit=0.2):
        def slow(payload, **kwargs):
            time.sleep(delay)
            return {'marker': 'decided'}
        out = io.StringIO()
        with mock.patch.object(ah_run, 'HOOK_DEADLINE', limit), mock.patch.object(ah_run, 'decide', slow):
            started = time.monotonic()
            ah_run.hook_main(io.StringIO(json.dumps(self.payload('echo hi', permission_mode=mode))), out)
        return json.loads(out.getvalue()), time.monotonic() - started

    def test_passing_the_limit_refuses_or_asks(self):
        for mode, decision in (('bypassPermissions', 'deny'), ('dontAsk', 'deny'), ('default', 'ask'), ('acceptEdits', 'ask')):
            result, took = self.run_hook(mode, 3)
            self.assertEqual(result['hookSpecificOutput']['permissionDecision'], decision, mode)
            self.assertIn('limit', result['hookSpecificOutput']['permissionDecisionReason'])
            self.assertLess(took, 2, mode)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0)

    def test_a_fast_decision_is_kept_and_the_timer_is_disarmed(self):
        result, _took = self.run_hook('bypassPermissions', 0)
        self.assertEqual(result, {'marker': 'decided'})
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0)
        self.assertNotIsInstance(getattr(signal.getsignal(signal.SIGALRM), '__self__', None), ah_run._Deadline)

    def test_control_without_the_timer_the_slow_analysis_decides(self):
        with mock.patch.object(ah_run._Deadline, 'arm', lambda deadline, seconds: False):
            result, took = self.run_hook('bypassPermissions', 0.5)
        self.assertEqual(result, {'marker': 'decided'}); self.assertGreaterEqual(took, 0.5)


    def test_cpu_bound_work_is_cut_off(self):
        """r8 L3: the limit stops work that spins the CPU through many regex calls, not only a sleep. One C-level regex call
        cannot be interrupted, which is why decide avoids regexes that backtrack over the text (LinearCost)."""
        pattern = re.compile(r'(a|b)*c')

        def busy(payload, **kwargs):
            subject, stop = 'ab' * 2000, time.monotonic() + 5
            while time.monotonic() < stop:
                pattern.search(subject)
            return {'marker': 'decided'}
        out = io.StringIO()
        with mock.patch.object(ah_run, 'HOOK_DEADLINE', 0.3), mock.patch.object(ah_run, 'decide', busy):
            started = time.monotonic()
            ah_run.hook_main(io.StringIO(json.dumps(self.payload('echo hi', permission_mode='bypassPermissions'))), out)
        took = time.monotonic() - started
        self.assertEqual(json.loads(out.getvalue())['hookSpecificOutput']['permissionDecision'], 'deny')
        self.assertLess(took, 3)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0)


class WrapperGrammar(HookFixture):
    """r8 H1: which word a wrapper runs is read by one strict grammar (WRAPPER_GRAMMAR) in the lexer, the deny forms and the
    escape classifier. A spelling outside it is uncertain (`wrapper-option`); a spelling inside it is certain and the program
    behind it is the one checked."""
    REVIEWED = ('nice -n5 %s', 'nice --adjustment 5 %s', 'nice --adjustment=5 %s', 'nice --10 %s', 'nice -10 %s',
                'timeout --signal KILL 5 %s', 'timeout --kill-after 1 5 %s', 'timeout -sKILL 5 %s', 'timeout -k1 -s9 5 %s',
                "env -vS '%s'", 'env -P /bin %s', 'exec -la x %s', 'time -o f %s', 'command -pv %s', 'nice -n 5 nohup %s',
                'nice 5 %s', 'nice --adj=5 %s', 'timeout 5x %s', 'nice -n $N %s', 'env -i A=1 -u B %s', 'env -a x %s', 'sudo -Eu root %s',
                'nice -n5 timeout --signal KILL 5 env -u X %s', 'builtin -x %s', 'nohup -x %s', 'exec -x %s')
    UNCERTAIN = ("env -vS '%s'", 'env -P /bin %s', 'nice 5 %s', 'nice --adj=5 %s', 'timeout 5x %s', 'nice -n $N %s', 'env -i A=1 -u B %s',
                 'env -a x %s', 'builtin -x %s', 'nohup -x %s', 'exec -x %s')
    SCAN = (  # (words, index of the program, unknown)
        ('nice -n5 rm', 2, False), ('nice -n 5 rm', 3, False), ('nice --adjustment=5 rm', 2, False), ('nice --adjustment 5 rm', 3, False),
        ('nice --10 rm', 2, False), ('nice -+5 rm', 2, False), ('nice -n x rm', 3, True), ('nice -n', 3, True),
        ('timeout 5 rm', 2, False), ('timeout -s KILL -k 1s 2.5m rm', 6, False), ('timeout --foreground --kill-after=1 5 rm', 4, False),
        ('timeout -fvsKILL 5 rm', 3, False), ('timeout --sig=KILL 5 rm', 3, True), ('env -iu X -C/tmp A=1 B=2 rm', 6, False),
        ('env -- A=1 rm', 3, False), ('env - rm', 2, False), ('exec -cl -a n rm', 4, False), ('exec -lan rm', 2, False),
        ('command -pVv rm', 2, False), ('command -x rm', 2, True), ('time -p rm', 2, False), ('time -f %e -o f rm', 5, False),
        ('time --format=%e rm', 2, False), ('sudo -Eu root -g wheel rm', 5, False), ('sudo -h rm', 2, True), ('sudo --user=root rm', 2, False),
        ('sudo --preserve-env=PATH rm', 2, False), ('sudo -- rm', 2, False), ('nohup -- rm', 2, False), ('builtin rm', 1, False),
    )

    ALLOWS = ['Bash(nice:*)', 'Bash(timeout:*)', 'Bash(env:*)', 'Bash(exec:*)', 'Bash(time:*)', 'Bash(command:*)', 'Bash(sudo:*)', 'Bash(*)']

    def test_each_reviewed_spelling_is_denied_and_never_allowed(self):
        for shape in self.REVIEWED:
            command = shape % 'rm -rf /tmp/zz'
            self.settings('user', deny=['Bash(rm:*)'], allow=self.ALLOWS)  # the review's case: an allow on the wrapper too
            for mode in ('bypassPermissions', 'default', 'dontAsk', 'acceptEdits'):
                self.assertEqual(self.decide(command, permission_mode=mode).get('permissionDecision'), 'deny', (shape, mode))
            self.settings('user', allow=self.ALLOWS)
            self.assertNotEqual(self.decide(command.replace('rm -rf /tmp/zz', 'true')).get('permissionDecision') if shape in self.UNCERTAIN else None, 'allow', shape)

    def test_outside_the_grammar_is_uncertain_inside_is_certain(self):
        for shape in self.REVIEWED:
            command = shape % 'echo hi'
            reasons = ah_run.parse_command(command).reasons
            if shape in self.UNCERTAIN:
                self.assertTrue(set(reasons) & {'wrapper-option', 'quoted-code:env-S'}, (shape, reasons))
            elif 'sudo' not in shape:
                self.assertEqual(reasons, [], shape)
        for command, reasons in (('exec "$@"', ['dynamic-program-word']), ('command "$c" x', ['dynamic-program-word']),
                                 ('nice -n "$N" make', ['wrapper-option']), ('nice -x "$c"', ['dynamic-program-word', 'wrapper-option'])):
            self.assertEqual(ah_run.parse_command(command).reasons, reasons, command)  # an expanded program is named as such

    def test_the_scan_table(self):
        for words, index, unknown in self.SCAN:
            values = words.split(' ')
            self.assertEqual(ah_run._wrapper_scan(values[0], values, values, 1), (index, unknown), words)
        self.assertEqual(ah_run._wrapper_scan('env', ['env', '-vS', 'x'], ['env', '-vS', 'x'], 1)[0], -2)
        self.assertEqual(ah_run._wrapper_scan('env', ['env', '-uS', 'x'], ['env', '-uS', 'x'], 1), (2, False))  # unsets S
        self.assertEqual(ah_run._wrapper_scan('ls', ['ls'], ['ls'], 1), (None, False))

    def test_escapes_and_code_hosts_behind_any_spelling(self):
        for shape in ('nice -n5 %s', 'sudo -Eu root %s', 'timeout --signal KILL 5 %s', 'exec -la x %s', 'command -p %s', 'time -o f %s'):
            self.assertTrue(any('nohup' in reason for reason in ah_run.classify_escapes(shape % 'nohup sleep 1')), shape)
            self.assertTrue(any('setsid' in reason for reason in ah_run.classify_escapes(shape % 'setsid sleep 1')), shape)
        self.settings('user', deny=['Bash(rm:*)'])
        for command in ("nice -n5 bash <<'E'\nrm x\nE", 'timeout --kill-after 1 5 bash -c "rm x"', "nice --10 sh -c 'rm x'"):
            self.assertEqual(self.decide(command, permission_mode='bypassPermissions').get('permissionDecision'), 'deny', command)

    def test_control_the_old_peel_reads_the_option_as_the_program(self):
        """66f21b8's exec reading: every word starting with - is one option, except -a with its name. `-la x` then leaves x as
        the program, which is certain and matches no rule."""
        def old_scan(base, values, raws, k, dynamic=None):
            if base != 'exec':
                return None, False
            while k < len(values) and values[k].startswith('-'):
                k += 2 if values[k] == '-a' else 1
            return k, False
        self.settings('user', deny=['Bash(rm:*)'])
        ah_run.match_candidates.cache_clear(); self.addCleanup(ah_run.match_candidates.cache_clear)  # forms read under the old scan
        with mock.patch.object(ah_run, '_wrapper_scan', old_scan):
            self.assertIsNone(self.decide('exec -la x rm -rf /tmp/zz', permission_mode='bypassPermissions').get('permissionDecision'))
        ah_run.match_candidates.cache_clear()
        self.assertEqual(self.decide('exec -la x rm -rf /tmp/zz', permission_mode='bypassPermissions').get('permissionDecision'), 'deny')


class SourceInput(HookFixture):
    """r8 M1: source and . read their script the way a shell does, so they get the shell's checks: a here-string, stdin from a
    pipe, a word built at run time (`<(cmd)`), and descriptor paths (/dev/fd/N, /dev/stdin, /proc/self/fd/N)."""
    SHAPES = ("source <(echo '%s')", ". <(echo '%s')", "source /proc/self/fd/0 <<< '%s'", "echo '%s' | . /proc/self/fd/0",
              "echo '%s' | . /dev/stdin", "source /dev/fd/0 <<< '%s'", "echo '%s' | source /dev/stdin", 'source "$f"',
              ". /proc/self/fd/3 3<<'E'\n%s\nE", "bash /proc/self/fd/3 3<<'E'\n%s\nE", "zsh /dev/fd/3 3<<'E'\n%s\nE",
              "bash /dev/fd/3 3< <(echo '%s')", "bash /proc/self/fd/0 <<< '%s'")

    def test_each_is_uncertain_and_the_deny_holds(self):
        self.settings('user', deny=['Bash(rm:*)'])
        for shape in self.SHAPES:
            command = shape.replace('%s', 'rm -rf /tmp/zz')
            self.assertTrue(ah_run.parse_command(command).uncertain, shape)
            if 'rm' in command:
                self.assertEqual(self.decide(command, permission_mode='bypassPermissions').get('permissionDecision'), 'deny', shape)

    def test_a_plain_file_stays_certain(self):
        for command in ('source .venv/bin/activate', 'source ~/.zshrc', '. ./env.sh', 'bash script.sh'):
            self.assertEqual(ah_run.parse_command(command).reasons, [], command)


class TildeProgram(HookFixture):
    """r8 M2: a program named through ~ is checked by its basename too, as /bin/rm is."""

    def test_tilde_paths_are_denied(self):
        self.settings('user', deny=['Bash(rm:*)'])
        for command in ('~/../../../bin/rm -rf /tmp/zz', '~root/../bin/rm x', '~/bin/rm x', '/bin/rm x'):
            for mode in ('bypassPermissions', 'default'):
                self.assertEqual(self.decide(command, permission_mode=mode).get('permissionDecision'), 'deny', (command, mode))
        self.assertIn('rm -rf x', ah_run.match_candidates('~/../bin/rm -rf x'))


class VariableCode(HookFixture):
    """r8 L1: text the shell evaluates as code through a variable is uncertain: arithmetic that names a variable, and a builtin
    given a variable name built at run time (bash evaluates a subscript in either)."""

    def test_uncertain(self):
        for command in ('p=\'$(\'; t="a[${p}echo M >&2)]"; echo $((t))', 'echo $((n+1))', 'echo "$(( x * 2 ))"', 'printf -v "$v" x',
                        'printf -v"$v" x', 'read "$v"', 'read -a "$v"', 'unset -v "$v"', '[ -v "$v" ]', 'test -v "$v"', 'export "$v"=1',
                        'local "$v"', 'wait -p "$v"', 'getopts ab "$v"'):
            self.assertTrue(ah_run.parse_command(command).uncertain, command)

    def test_certain(self):
        for command in ('echo $((1+2))', 'printf "%s\\n" "$x"', 'printf -v name x', 'read -rp "P $x" var', '[ -n "$x" ]', 'export FOO="$x"',
                        'local -r x="$1"', 'unset FOO', 'getopts "ab:" opt'):
            self.assertEqual(ah_run.parse_command(command).reasons, [], command)


class LinearCost(HookFixture):
    """r8 L2: the literal rule and the glob reader never backtrack over the text. A regex that backtracks cannot be
    stopped by the hook's limit in the middle of one call, so these are bounded by construction."""
    GLOBS = (('touch', 'tou?h', True), ('touch', '*', True), ('touch', 't*h', True), ('touch', '*z*', False), ('touch', '[a-z]ouch', True),
             ('touch', '[!x]ouch', True), ('touch', '[]ouch', False), ('touch', '[]]ouch', True), ('t]ouch', '[]]]ouch', True), ('t]ouch', 'x[]]]ouch', False),
             ('touch', 'tou[', False), ('tou[', 'tou[', True), ('touch', '[z-a]ouch', True), ('touch', 'touch?', False), ('', '*', True),
             ('', '', True), ('a', '', False), ('touch', '**t***o*u*c*h**', True))

    def test_the_glob_reader_agrees_with_its_table(self):
        for name, glob, matches in self.GLOBS:
            self.assertEqual(ah_run._glob_matches(name, glob), matches, (name, glob))

    def test_reviewed_inputs_decide_quickly(self):
        self.settings('user', deny=['Bash(touch:*)'])
        for command in ('=' * 65000, '*' * 121 + 'Z x', '*a' * 60 + 'b x', '[' * 64000 + ' x', 'x ' + '=' * 64000 + 'touch'):
            started = time.monotonic()
            with mock.patch.object(ah_run, 'HOOK_DEADLINE', 60):
                self.decide(command, permission_mode='bypassPermissions')
            self.assertLess(time.monotonic() - started, 2.5, command[:12])
        self.assertTrue(ah_run.literal_match('touch:*', ah_run.literal_views('x ' + '=' * 64000 + 'touch')))


class LauncherShell(unittest.TestCase):
    """r6 S31: the launcher runs bash or zsh by basename and falls back to bash, so the wrapped and unwrapped runs use a shell
    the hook's claim covers."""

    def shell(self, **env):
        with mock.patch.dict(os.environ, env, clear=False):
            for key in ('CLAUDE_CODE_SHELL', 'SHELL'):
                if key not in env:
                    os.environ.pop(key, None)
            return ah_run.shell_for_command()[0]

    def test_bash_and_zsh_are_kept(self):
        for path in ('/bin/bash', '/bin/zsh'):
            if os.access(path, os.X_OK):
                self.assertEqual(self.shell(CLAUDE_CODE_SHELL=path), path)
                self.assertEqual(self.shell(SHELL=path), path)

    def test_any_other_shell_falls_back_to_bash(self):
        bash = next(path for path in ah_run.BASH_PATHS if os.access(path, os.X_OK))
        for path in ('/bin/ksh', '/bin/dash', '/bin/sh', '/bin/csh', '/usr/bin/fish', '/opt/homebrew/bin/fish', 'bash', '../bin/bash', '/nonexistent/bash'):
            self.assertEqual(self.shell(SHELL=path), bash, path)
            self.assertEqual(self.shell(CLAUDE_CODE_SHELL=path), bash, path)
        self.assertEqual(self.shell(CLAUDE_CODE_SHELL='/bin/ksh', SHELL='/bin/zsh'), '/bin/zsh' if os.access('/bin/zsh', os.X_OK) else bash)

    def test_control_the_old_selection_kept_ksh(self):
        def old():
            shell = os.environ.get('CLAUDE_CODE_SHELL') or os.environ.get('SHELL') or '/bin/bash'
            return shell if os.path.isabs(shell) and os.access(shell, os.X_OK) else '/bin/bash'
        with mock.patch.dict(os.environ, {'SHELL': '/bin/sh'}):
            os.environ.pop('CLAUDE_CODE_SHELL', None)
            self.assertEqual(old(), '/bin/sh')
            self.assertNotEqual(ah_run.shell_for_command()[0], '/bin/sh')


class ShellBlanks(HookFixture):
    """r6 B18: only space, tab and newline are blanks, as in every shell. Python's str.split, str.strip and \\s also treat form
    feed, vertical tab, \\x1c-\\x1f, \\x85, NBSP, U+3000 and others as blanks, so they decide nothing in the lexer and its readers."""
    BLANKS = ('\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\x1f', '\x85', '\xa0', '\u1680', '\u2000', '\u2007', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000', '\r')

    def test_a_python_blank_never_opens_a_comment(self):
        self.settings('user', allow=['Bash(echo:*)'], deny=['Bash(touch:*)'])
        for blank in self.BLANKS:
            for shape in ('%s# ; touch PWNED', '%s#x\ntouch PWNED', 'echo a%s# ; touch PWNED', 'echo a;%s#x\ntouch PWNED'):
                command = shape % blank
                self.assertTrue(ah_run.parse_command(command).uncertain, repr(command))
                self.assertEqual(self.decide(command, permission_mode='bypassPermissions').get('permissionDecision'), 'deny', repr(command))

    def test_the_lexer_and_its_readers_use_no_python_blank(self):
        source = Path(ah_run.__file__).read_text()
        start, end = source.index('# -- the one lexer'), source.index('def normalize_segment(')
        offenders = []
        for number, line in enumerate(source[start:end].split('\n')):
            if 'LITERAL_START' in line or 'LITERAL_STOP' in line or line.lstrip().startswith('#'):
                continue  # the literal rule keeps Python's wider \s on purpose: it only widens a refusal
            if re.search(r'\.strip\(\)|\.split\(\)|\.lstrip\(\)|\.rstrip\(\)|\\s|\.isspace\(\)', line):
                offenders.append(line.strip(' '))
        self.assertEqual(offenders, [])

    def test_control_a_lexer_that_reads_form_feed_as_a_blank_hides_the_line(self):
        self.settings('user', deny=['Bash(touch:*)'])
        real = ah_run.lex
        with mock.patch.object(ah_run, 'lex', lambda command: real(command.replace('\f', ' '))):
            self.assertIsNone(self.decide('\f# ; touch PWNED', permission_mode='bypassPermissions').get('permissionDecision'))


class HookCost(HookFixture):
    """S21: the refused case costs nothing and the two scans are linear."""

    def test_the_payload_cap_runs_before_any_analysis(self):
        with mock.patch.object(ah_run, 'parse_command', side_effect=AssertionError('analysis ran')):
            out = self.decide('echo ' + 'x' * ah_run.PAYLOAD_CAP)
        self.assertEqual(out['permissionDecision'], 'deny'); self.assertIn('1 MiB', out['permissionDecisionReason'])

    def test_deep_nesting_is_uncertain_not_an_internal_error(self):
        self.settings('user', deny=['Bash(touch:*)'])
        command = 'echo ' + '$(' * 6000 + 'true' + ')' * 6000 + '\ntouch PWNED'
        started = time.monotonic()
        self.assertTrue(ah_run.parse_command(command).uncertain)
        self.assertEqual(self.decide(command, permission_mode='bypassPermissions').get('permissionDecision'), 'deny')
        self.assertLess(time.monotonic() - started, 8)

    def test_many_heredocs_and_backgrounds_stay_fast(self):
        many = ''.join('cat <<E\nb\nE\n' for _ in range(3000))
        started = time.monotonic()
        self.assertEqual(len(ah_run.heredoc_scan(many)[2]), 3000)
        backgrounds = 'a & ' * 3000 + 'wait'
        self.assertEqual(ah_run.classify_escapes(backgrounds), [])
        self.assertLess(time.monotonic() - started, 5)


class RefusalText(HookFixture):
    """S18: the refusal for an uncertain heredoc names the forms the hook reads with certainty."""
    FORM = "cat <<'EOF'"

    def test_the_refusal_names_the_certain_commit_form(self):
        self.settings('user', deny=['Bash(touch:*)'])
        command = "git commit -m \"$(cat <<'EOF'\ntouch up the docs\nEOF\n)\""
        reason = self.decide(command, permission_mode='bypassPermissions')['permissionDecisionReason']
        self.assertIn("git commit -F - <<'EOF'", reason); self.assertIn("--body-file - <<'EOF'", reason)
        self.settings_policy('enforce')
        reason = self.decide("git commit -m \"$(cat <<'EOF'\nat least one row\nEOF\n)\"", permission_mode='bypassPermissions')['permissionDecisionReason']
        self.assertIn("git commit -F - <<'EOF'", reason)

    def test_the_named_form_is_not_refused(self):
        self.settings('user', allow=['Bash(git commit:*)'], deny=['Bash(touch:*)'])
        self.settings_policy('enforce')
        out = self.decide("git commit -F - <<'EOF'\ntouch up the docs\nat least one row & more\nEOF")
        self.assertEqual(out['permissionDecision'], 'allow')


class PermissionRules(HookFixture):
    def test_ask_rules_see_through_wrappers_and_env_prefixes(self):
        self.settings('user', allow=['Bash'], ask=['Bash(git push:*)'])
        for command in ('git push origin main', 'FOO=1 git push origin main', 'timeout 60 git push', 'command git push',
                        'env git push', 'sudo git push', 'exec git push'):
            out = self.decide(command)
            self.assertEqual(out['permissionDecision'], 'ask', command); self.assertIn('updatedInput', out, command)
        self.assertEqual(self.decide('git status')['permissionDecision'], 'allow')

    def test_deny_sees_through_wrappers_and_quoting(self):
        self.settings('user', allow=['Bash'], deny=['Bash(rm:*)'])
        for command in ('timeout -s KILL 5 rm -rf x', 'timeout --kill-after=2 5 rm x', 'sudo rm -rf x', 'sudo -u root rm x', 'exec rm x',
                        '"rm" -rf x', "'rm' x", '\\rm x', 'env FOO=1 rm x', 'env -i rm x', 'nohup rm x', 'command -p rm x',
                        'time rm x', 'nice -n 5 rm x', 'sudo -n timeout 5 rm x', 'FOO=1 sudo rm x'):
            self.assertEqual(self.decide(command)['permissionDecision'], 'deny', command)
        for command in ('echo rm', 'ls', 'sudo ls', 'timeout 5 sleep 1', '"echo" rm'):
            self.assertNotEqual(self.decide(command).get('permissionDecision'), 'deny', command)


class PendingHygiene(HookFixture):
    """S2: pending rows and payloads exist only for a command that will run, and expire."""
    BIG = 'echo ' + 'A' * (70 * 1024) + ' --password hunter2'

    def files(self):
        return sorted(p.name for p in (self.reserve / 'ledger' / 'pending').glob('*'))

    def test_deny_leaves_nothing_behind(self):
        self.settings('user', deny=['Bash(rm:*)'])
        self.assertEqual(self.decide('echo ' + 'A' * (60 * 1024) + ' --password hunter2; rm x')['permissionDecision'], 'deny')
        self.assertEqual(self.files(), [])
        for mode in ('bypassPermissions', 'dontAsk'):  # over the cap a no-ask mode refuses, and writes nothing either
            self.assertEqual(self.decide(self.BIG + '; rm x', permission_mode=mode)['permissionDecision'], 'deny', mode)
        self.assertEqual(self.files(), [])

    def test_dont_ask_refusal_leaves_nothing_behind(self):
        out = self.decide(self.BIG, permission_mode='dontAsk')
        self.assertEqual(out['permissionDecision'], 'deny'); self.assertEqual(self.files(), [])

    def test_ask_writes_a_row_and_a_payload(self):
        out = self.decide(self.BIG)
        self.assertEqual(out['permissionDecision'], 'ask'); self.assertEqual(len(self.files()), 2)

    def age(self, path, seconds):
        old = time.time() - seconds
        os.utime(path, (old, old))

    def test_prune_removes_expired_rows_and_payloads_only(self):
        fresh = ah_run.mint_pending(self.reserve, 'echo a', 't', 'a')
        stale = ah_run.mint_pending(self.reserve, 'echo b', 't', 'a')
        pend = self.reserve / 'ledger' / 'pending'
        (pend / (stale + '.cmd')).write_text('secret'); self.age(pend / (stale + '.cmd'), 2 * ah_run.PENDING_TTL)
        self.age(pend / (stale + '.json'), 2 * ah_run.PENDING_TTL)
        self.assertEqual(ah_run.prune_pending(self.reserve), 2)
        self.assertEqual(self.files(), [fresh + '.json'])

    def test_ledger_prune_command_and_run_start_prune(self):
        pend = self.reserve / 'ledger' / 'pending'; pend.mkdir(parents=True, exist_ok=True)
        for name in ('old1.cmd', 'old2.json'):
            (pend / name).write_text('x'); self.age(pend / name, 2 * ah_run.PENDING_TTL)
        result = subprocess.run([sys.executable, AH, 'ledger', '--prune'], env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(json.loads(result.stdout), {'pruned': 2})
        (pend / 'old3.cmd').write_text('x'); self.age(pend / 'old3.cmd', 2 * ah_run.PENDING_TTL)
        subprocess.run([sys.executable, AH, 'run', '--no-unit', '--', 'true'], env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(self.files(), [])


class LedgerFailure(Fixture):
    """S5: a reserve that cannot be written never stops the command or changes its exit code."""

    def run_plain(self, command, env=None):
        return subprocess.run([sys.executable, AH, 'run', '--task', 't1', '--no-unit', '--', command], env=env or self.env,
                              capture_output=True, text=True, timeout=30)

    def test_read_only_ledger_dir_passes_the_exit_code_through(self):
        (self.reserve / 'ledger' / 'pending').mkdir(parents=True)
        os.chmod(self.reserve / 'ledger', 0o500); self.addCleanup(os.chmod, self.reserve / 'ledger', 0o700)
        result = self.run_plain('echo ran; exit 3')
        self.assertEqual((result.returncode, result.stdout), (3, 'ran\n')); self.assertNotIn('Traceback', result.stderr)

    def test_symlinked_reserve_still_runs_the_command(self):
        link = Path(self.temp.name) / 'link'; link.symlink_to(self.reserve)
        result = self.run_plain('echo ran; exit 4', env={**self.env, 'AGENT_HARNESS_RESERVE_DIR': str(link)})
        self.assertEqual((result.returncode, result.stdout), (4, 'ran\n')); self.assertNotIn('Traceback', result.stderr)

    def test_a_row_that_lands_late_is_retried_at_the_end(self):
        real = ah_run.Ledger.write
        calls = []
        def flaky(self_, run_id, row):
            calls.append(row.get('end'))
            if len(calls) == 1:
                raise OSError(28, 'no space')
            return real(self_, run_id, row)
        with mock.patch.object(ah_run.Ledger, 'write', flaky):
            with mock.patch.dict(os.environ, {'AGENT_HARNESS_RESERVE_DIR': str(self.reserve)}):
                args = ah_run.argparse.Namespace(task='t1', agent=None, ticket=None, session=None, token=None, cmd_file=None, cmd_b64=None,
                                                 command_class=None, remote_host_sha256=None, task_source=None, readonly=False,
                                                 no_unit=True, command=['exit 5'])
                self.assertEqual(ah_run.launch(args), 5)
        self.assertEqual(len(calls), 2); self.assertEqual(self.rows()[0]['exit_code'], 5)


class TaskSource(HookFixture):
    """S6: the model cannot pick its own task key per call."""

    def with_description(self, text, env=None, **extra):
        payload = self.payload('echo hi', **extra)
        payload['tool_input']['description'] = text
        return ah_run.decide(payload, home=str(self.home), env=env or {}, ancestors=lambda: [])['hookSpecificOutput']

    def test_environment_task_wins_over_the_description(self):
        out = self.with_description('x [task:evil]', env={'AGENT_HARNESS_TASK': 'envtask'})
        self.assertIn('--task envtask', out['updatedInput']['command']); self.assertNotIn('task-source', out['updatedInput']['command'])

    def test_subagent_record_wins_and_a_recordless_subagent_gets_a_generated_key(self):
        record = self.reserve / 'subagents'; record.mkdir()
        (record / 'ag-1.json').write_text(json.dumps({'task': 'rec-task'}))
        out = self.with_description('x [task:evil]', agent_id='ag-1')
        self.assertIn('--task rec-task', out['updatedInput']['command'])
        out = self.with_description('x [task:evil]', agent_id='ag-2')
        self.assertNotIn('evil', out['updatedInput']['command']); self.assertIn('--task auto-', out['updatedInput']['command'])

    def test_a_cwd_named_like_a_task_token_is_never_a_source(self):
        for extra in ({}, {'agent_id': 'ag-3'}):
            payload = self.payload('echo hi', **extra); payload['cwd'] = '/tmp/[task:victim]'
            out = ah_run.decide(payload, home=str(self.home), env={}, ancestors=lambda: [])['hookSpecificOutput']
            self.assertNotIn('victim', out['updatedInput']['command']); self.assertIn('--task auto-', out['updatedInput']['command'])
        out = self.decide('echo hi', prompt='x [task:from-spawn]', cwd='/tmp/[task:victim]')
        self.assertIn('--task from-spawn', out['updatedInput']['command'])
        out = self.decide('echo hi', other_field='[task:victim]')
        self.assertNotIn('victim', out['updatedInput']['command'])

    def test_main_session_input_token_is_used_and_marked(self):
        out = self.with_description('x [task:from-input]')
        wrapped = out['updatedInput']['command']
        self.assertIn('--task from-input', wrapped); self.assertIn('--task-source input', wrapped)
        subprocess.run(['/bin/sh', '-c', wrapped], env={**self.env, 'AGENT_HARNESS_RESERVE_DIR': str(self.reserve)}, capture_output=True, timeout=30)
        self.assertEqual(self.rows()[0]['task_source'], 'input')


class HookSshToken(Fixture):
    """S10: `via-hook-ssh` is the hook-built remote form (--cmd-b64) only."""

    def go(self, *flags):
        return subprocess.run([sys.executable, AH, 'run', '--task', 'victim', '--agent', 'x', '--token', 'via-hook-ssh', '--no-unit', *flags],
                              env=self.env, capture_output=True, text=True, timeout=30)

    def test_local_form_is_refused_for_a_read_only_agent(self):
        self.assertEqual(self.go('--readonly', '--', 'true').returncode, 126)
        self.assertEqual(self.go('--readonly', '--cmd-b64', base64.b64encode(b'true').decode(), '--', 'true').returncode, 126)
        self.assertEqual(self.rows(), [])

    def test_local_form_is_recorded_unverified(self):
        self.assertEqual(self.go('--', 'true').returncode, 0)
        row = self.rows()[0]
        self.assertEqual((row['attribution'], row['attribution_reason']), ('unverified', 'via-hook-ssh-needs-cmd-b64'))

    def test_cmd_b64_form_still_records_hook_ssh_and_passes_read_only(self):
        result = self.go('--readonly', '--cmd-b64', base64.b64encode(b'echo ok').decode())
        self.assertEqual((result.returncode, result.stdout), (0, 'ok\n')); self.assertEqual(self.rows()[0]['attribution'], 'hook-ssh')


class PayloadFile(Fixture):
    """S7: --cmd-file is only <reserve>/ledger/pending/<token>.cmd, opened without following links."""

    def setUp(self):
        super().setUp()
        self.token = ah_run.mint_pending(self.reserve, 'echo from-file', 't1', 'a1')
        self.payload = self.reserve / 'ledger' / 'pending' / (self.token + '.cmd')

    def run_file(self, path, token=None):
        return subprocess.run([sys.executable, AH, 'run', '--task', 't1', '--agent', 'a1', '--token', token or self.token, '--no-unit',
                               '--cmd-file', str(path)], env=self.env, capture_output=True, text=True, timeout=30)

    def write(self, text='echo from-file'):
        self.payload.write_text(text); self.payload.chmod(0o600)

    def test_verified_payload_runs_and_is_unlinked(self):
        self.write()
        result = self.run_file(self.payload)
        self.assertEqual((result.returncode, result.stdout), (0, 'from-file\n')); self.assertFalse(self.payload.exists())
        self.assertEqual(self.rows()[0]['attribution'], 'verified')

    def test_digest_mismatch_runs_unverified_and_keeps_the_file_for_pruning(self):
        self.write('echo swapped')
        result = self.run_file(self.payload)
        self.assertEqual(self.rows()[0]['attribution_reason'], 'token-command-mismatch'); self.assertTrue(self.payload.exists())

    def test_a_path_outside_pending_is_refused_and_survives(self):
        other = Path(self.temp.name) / 'victim.txt'; other.write_text('echo owned')
        result = self.run_file(other)
        self.assertEqual(result.returncode, 126); self.assertTrue(other.exists()); self.assertNotIn('owned', result.stdout)
        elsewhere = self.reserve / 'ledger' / 'pending' / 'other.cmd'; elsewhere.write_text('echo x')
        self.assertEqual(self.run_file(elsewhere).returncode, 126); self.assertTrue(elsewhere.exists())

    def test_a_symlink_payload_is_refused(self):
        target = Path(self.temp.name) / 'target.txt'; target.write_text('echo from-file')
        self.payload.symlink_to(target)
        result = self.run_file(self.payload)
        self.assertEqual(result.returncode, 126); self.assertTrue(target.exists()); self.assertEqual(result.stdout, '')

    def test_a_hard_linked_payload_is_refused(self):
        self.write(); os.link(self.payload, Path(self.temp.name) / 'second-name')
        self.assertEqual(self.run_file(self.payload).returncode, 126)

    def test_a_token_that_is_not_a_token_is_refused(self):
        self.write()
        self.assertEqual(self.run_file(self.payload, token='tok').returncode, 126)


# ---------------------------------------------------------------------------------------------------------
# Slice 2b: ssh through the host table (goodqa#14548 AC-4 ssh rows, AC-19 --readonly travel)
# ---------------------------------------------------------------------------------------------------------

RIG_SSH = '''#!/bin/sh
# `ssh -G` answers from $FAKE_SSH_DIR/<target>.txt; any other call behaves like ssh: skip options and the
# host, then hand the remaining arguments, joined with spaces, to a shell (what a remote login shell does)
[ -n "$FAKE_SSH_LOG" ] && echo "$@" >> "$FAKE_SSH_LOG"
if [ "$1" = "-G" ]; then
  for last; do :; done
  [ -n "$FAKE_SSH_SLEEP" ] && sleep "$FAKE_SSH_SLEEP"
  [ -f "$FAKE_SSH_DIR/$last.txt" ] || exit 255
  cat "$FAKE_SSH_DIR/$last.txt"; exit 0
fi
while [ $# -gt 0 ]; do case "$1" in -p|-o|-J|-l|-i|-F) shift 2;; -*) shift;; *) break;; esac; done
shift
exec sh -c "$*"
'''


def _ssh_g(hostname, port=22):
    return 'user eric\nhostname %s\nport %d\n' % (hostname, port)


class SshRewrite(HookFixture):
    REMOTE_PATH = '/opt/ah/ah_run.py'

    def setUp(self):
        super().setUp()
        root = Path(self.temp.name)
        self.bin = root / 'bin'; self.bin.mkdir()
        (self.bin / 'ssh').write_text(RIG_SSH); (self.bin / 'ssh').chmod(0o755)
        self.stubs = root / 'stubs'; self.stubs.mkdir()
        self.remote_reserve = root / 'remote-reserve'; self.remote_reserve.mkdir(mode=0o700)
        self.ssh_log = root / 'ssh.log'
        self.policy = root / 'resource_policy.json'
        self.write_policy()
        patcher = mock.patch.dict(os.environ, {'PATH': '%s:%s' % (self.bin, os.environ['PATH']), 'FAKE_SSH_DIR': str(self.stubs),
                                               'FAKE_SSH_LOG': str(self.ssh_log)})
        patcher.start(); self.addCleanup(patcher.stop)
        os.environ.pop('FAKE_SSH_SLEEP', None)
        for alias, host in (('dev2', 'dev2.example.test'), ('rig', 'rig.example.test'), ('pve', 'pve.example.test'),
                            ('mac2', 'mac2.example.test'), ('localhost', 'localhost'), ('unwrapped', 'unwrapped.example.test'),
                            ('badpath', 'badpath.example.test')):
            (self.stubs / (alias + '.txt')).write_text(_ssh_g(host))

    def write_policy(self, **hosts):
        table = {'dev2.example.test': {'role': 'worker', 'ah_run': self.REMOTE_PATH},
                 # the rig host runs the real launcher, with its own reserve directory standing in for the remote one
                 'rig.example.test': {'role': 'worker', 'ah_run': str(Path(ah_run.__file__).resolve()),
                                      'remote_env': {'AGENT_HARNESS_RESERVE_DIR': str(self.remote_reserve), 'PATH': '/evil'}},
                 'mac2.example.test': {'role': 'interactive', 'ah_run': False},
                 'unwrapped.example.test': {'role': 'worker', 'ah_run': False},
                 'badpath.example.test': {'role': 'worker', 'ah_run': '/opt/a b/ah_run.py;x'},
                 'pve.example.test': {'role': 'external'}}
        table.update(hosts)
        self.policy.write_text(json.dumps({'modes': {'escapes': 'enforce'}, 'hosts': table, 'self': ['this-mac']}))

    def ssh(self, command, **extra):
        return ah_run.decide(self.payload(command, **extra), home=str(self.home),
                             env={'AGENT_HARNESS_RESOURCE_POLICY': str(self.policy)}, ancestors=lambda: [])['hookSpecificOutput']

    @staticmethod
    def inner(out):
        words = shlex.split(out['updatedInput']['command'])
        return words[words.index('--') + 1]

    @staticmethod
    def b64_of(line):
        return base64.b64decode(re.search(r'--cmd-b64 (\S+)', line).group(1)).decode('utf-8')

    def contacted(self):
        return self.ssh_log.exists() and bool(self.ssh_log.read_text().strip())

    def exec_wrapped(self, out, **env):
        env = {**self.env, 'PATH': os.environ['PATH'], 'AGENT_HARNESS_RESERVE_DIR': str(self.reserve), **env}
        return subprocess.run(['/bin/sh', '-c', out['updatedInput']['command']], env=env, capture_output=True, text=True, timeout=30)

    def remote_rows(self):
        return list(ah_run.Ledger(self.remote_reserve).rows())

    # -- the rewrite --------------------------------------------------------------------------------------

    def test_plain_rewrite(self):
        line = self.inner(self.ssh("ssh dev2 'git log'"))
        self.assertTrue(line.startswith('ssh dev2 python3 -I %s run --task auto-' % self.REMOTE_PATH), line)
        self.assertIn('--agent main --session s-1 --token via-hook-ssh --cmd-b64 ', line)
        self.assertNotIn('--readonly', line)
        self.assertEqual(self.b64_of(line), 'git log')

    def test_readonly_travels_for_the_review_set_only(self):
        for kind in ('red-team', 'click-tester', 'reviewer', 'Explore', 'Plan'):
            line = self.inner(self.ssh("ssh dev2 'git log'", agent_type=kind, agent_id='ag1'))
            self.assertIn(' --agent ag1 ', line); self.assertIn('--token via-hook-ssh --readonly --cmd-b64 ', line, kind)
        for kind in ('task-owner', 'general-purpose', None):
            extra = {'agent_type': kind} if kind else {}
            self.assertNotIn('--readonly', self.inner(self.ssh("ssh dev2 'git log'", **extra)), kind)

    def test_ticket_travels_and_unsafe_ticket_does_not(self):
        out = ah_run.decide(self.payload("ssh dev2 'ls'"), home=str(self.home), ancestors=lambda: [],
                            env={'AGENT_HARNESS_RESOURCE_POLICY': str(self.policy), 'AGENT_HARNESS_TICKET': 'goodqa#14548'})
        self.assertIn('--ticket goodqa#14548 --session', self.inner(out['hookSpecificOutput']))
        out = ah_run.decide(self.payload("ssh dev2 'ls'"), home=str(self.home), ancestors=lambda: [],
                            env={'AGENT_HARNESS_RESOURCE_POLICY': str(self.policy), 'AGENT_HARNESS_TICKET': 'a; reboot'})
        self.assertNotIn('--ticket', self.inner(out['hookSpecificOutput']))

    def test_prefix_stripped_inside_the_ssh_argument(self):
        for command in ("ssh dev2 'ah-run run --task x --agent y -- git log'", 'ssh dev2 "ah-run --task x -- git log"',
                        "ssh dev2 'python3 /x/ah_run.py run --task x -- git log'"):
            self.assertEqual(self.b64_of(self.inner(self.ssh(command))), 'git log', command)

    def test_prefix_in_remote_does_not_hide_an_escape(self):
        self.assertEqual(self.ssh("ssh dev2 'ah-run run --task x -- nohup sleep 9'")['permissionDecision'], 'deny')

    def test_config_bearing_options_never_reach_ssh_g_and_leave_the_line_unwrapped(self):
        for command in ("ssh -F ./x.conf dev2 'git log'", "ssh -o ProxyCommand=true dev2 'git log'", "ssh -oProxyJump=j dev2 ls",
                        "ssh -J jump dev2 'git log'", "ssh -p 22 -F./x.conf dev2 ls", 'ssh -o NoSuchKey=1 dev2 ls',
                        'ssh -o RemoteCommand=x dev2 ls', 'ssh -o LocalCommand=x dev2 ls', 'ssh -o PermitLocalCommand=yes dev2 ls',
                        'ssh -o Include=x dev2 ls', 'ssh -o "Match all" dev2 ls', 'ssh -o ConnectTimeout=$X dev2 ls',
                        'ssh -o ConnectTimeout=5 -o ProxyCommand=x dev2 ls', 'ssh dev2 -F evil.conf ls', 'ssh dev2 -o ProxyCommand=x ls'):
            if self.ssh_log.exists():
                self.ssh_log.unlink()
            out = self.ssh(command)
            self.assertFalse(self.contacted(), command)  # ssh -G never ran, so a `Match exec` in -F could not execute
            self.assertNotIn('via-hook-ssh', out['updatedInput']['command'], command)
            self.assertIn('ah_run.py', out['updatedInput']['command'])  # still wrapped locally, attributed to the supervisor

    def test_options_with_values_are_parsed(self):
        line = self.inner(self.ssh("ssh -p 2222 dev2 'git log'"))
        self.assertTrue(line.startswith('ssh -p 2222 dev2 python3 -I %s run' % self.REMOTE_PATH), line)
        self.assertEqual(self.b64_of(line), 'git log')
        self.assertIn('-G -p 2222 -- dev2', self.ssh_log.read_text())
        line = self.inner(self.ssh("ssh -p2222 -l eric dev2 git -C /x log -1"))
        self.assertEqual(self.b64_of(line), 'git -C /x log -1')

    def test_safe_o_keys_keep_the_rewrite_and_never_reach_ssh_g(self):
        for option in ('-o ConnectTimeout=5', '-oBatchMode=yes', '-o StrictHostKeyChecking=no', '-o UserKnownHostsFile=/dev/null',
                       '-o ServerAliveInterval=5', '-o ServerAliveCountMax=3', '-o LogLevel=ERROR', '-o IdentitiesOnly=yes',
                       '-o "ConnectTimeout 5"', '-o connecttimeout=5'):
            self.ssh_log.write_text('')
            line = self.inner(self.ssh("ssh %s dev2 'git log'" % option, agent_type='red-team'))
            self.assertIn('via-hook-ssh', line, option); self.assertIn('--readonly', line, option)
            self.assertTrue(line.startswith('ssh %s dev2 python3 ' % option), line)
            self.assertEqual(self.b64_of(line), 'git log', option)
            contacted = self.ssh_log.read_text()
            self.assertIn('-G -- dev2', contacted, option); self.assertNotIn('-o', contacted.split(), option)

    def test_options_after_the_host_are_options_not_the_remote_command(self):
        line = self.inner(self.ssh('ssh dev2 -p 2222 ls -l'))
        self.assertTrue(line.startswith('ssh dev2 -p 2222 python3 -I %s run' % self.REMOTE_PATH), line)
        self.assertEqual(self.b64_of(line), 'ls -l')
        self.assertIn('-G -p 2222 -- dev2', self.ssh_log.read_text())
        line = self.inner(self.ssh('ssh dev2 ls -p 2222'))  # the first other word ends the options
        self.assertEqual(self.b64_of(line), 'ls -p 2222')
        line = self.inner(self.ssh('ssh dev2 -t -- -x'))
        self.assertEqual(self.b64_of(line), '-x')

    def test_ssh_f_after_the_host_is_still_the_escape(self):
        for command in ('ssh dev2 -f', 'ssh dev2 -f sleep 99', 'ssh dev2 -p 22 -f ls', 'ssh dev2 -fN'):
            self.assertEqual(self.ssh(command)['permissionDecision'], 'deny', command)
        self.assertEqual(self.ssh('ssh dev2 ls -f').get('permissionDecision'), 'ask')  # -f of the remote ls

    def test_a_remote_escape_after_host_options_is_still_found(self):
        self.assertEqual(self.ssh("ssh dev2 -p 22 'nohup sleep 9'")['permissionDecision'], 'deny')

    def test_a_heredoc_script_keeps_the_rewrite_and_readonly(self):
        line = self.inner(self.ssh("ssh dev2 bash <<'E'\necho hi\nE", agent_type='red-team', agent_id='rt1'))
        self.assertIn('--token via-hook-ssh --readonly --cmd-b64 ', line)
        self.assertEqual(self.b64_of(line.split('\n')[0]), 'bash')
        self.assertTrue(line.endswith("<<'E'\necho hi\nE"), line)

    def test_a_heredoc_script_reaches_the_remote_shell(self):
        out = self.ssh("ssh rig bash <<'E'\necho from-the-body\nE")
        result = self.exec_wrapped(out)
        self.assertEqual((result.returncode, result.stdout), (0, 'from-the-body\n'), result.stderr)

    def test_a_continued_ssh_line_is_still_wrapped(self):
        line = self.inner(self.ssh("ssh dev2 \\\n  git log", agent_type='red-team', agent_id='rt1'))
        self.assertIn('via-hook-ssh --readonly', line); self.assertEqual(self.b64_of(line), 'git log')

    def test_a_continued_ssh_line_with_a_quote_is_uncertain_and_left_unwrapped(self):
        typed = "ssh dev2 \\\n  'git log'"
        out = self.ssh(typed, agent_type='red-team', agent_id='rt1')
        self.assertEqual(self.inner(out), typed)
        head = out['updatedInput']['command'].split(' -- ', 1)[0]
        self.assertIn('--command-class remote-unwrapped', head); self.assertIn('--readonly', head)
        self.assertIn('uncertain', out['additionalContext'])

    # -- r5 B13: what runs is what was checked, and a body travels byte for byte ------------------------------

    BODY_ROWS = ("'cat > f' <<'EOF'\nfoo \\\nbar\nEOF", "cat <<'E'\nE\\\n\necho HIDDEN-LINE\nE", "cat <<'E'\nb\\\nE\necho AFTER\nE", 'cat <<"E"\na\\\nb\nE',
                 "cat <<'E'\n\ttabs and  spaces \n\n$(not run) `not run` 'q' \"q\" \\\\\n\u00e9\nE\n", "cat <<-'E'\n\tb\\\n\tE", "cat <<\\E\nb\\\nE")

    def test_the_rewrite_never_changes_a_body(self):
        for host in ('dev2', 'pve', 'unknown-host', 'unwrapped'):
            for row in self.BODY_ROWS:
                typed = 'ssh %s %s' % (host, row)
                new = self.inner(self.ssh(typed))
                self.assertEqual(new.split('\n', 1)[1], typed.split('\n', 1)[1], (host, row))
                self.assertEqual(new.split('\n', 1)[0].rsplit('<<', 1)[1], typed.split('\n', 1)[0].rsplit('<<', 1)[1], (host, row))

    def test_a_line_that_is_not_wrapped_comes_back_exactly_as_typed(self):
        for typed in ("ssh pve cat <<'E'\nE\\\n\necho HIDDEN-LINE\nE", "ssh pve ls\ncat <<'E'\nx\\\ny\nE", 'ssh pve \\\n  ls\necho a \\\n b'):
            self.assertEqual(self.inner(self.ssh(typed)), typed)

    def test_a_body_elsewhere_in_the_command_keeps_its_bytes(self):
        typed = "ssh dev2 ls\ncat <<'E'\nx\\\ny\nE\necho a \\\n b"
        new = self.inner(self.ssh(typed))
        self.assertIn('--token via-hook-ssh', new.split('\n')[0])
        self.assertEqual(new.split('\n', 1)[1], "cat <<'E'\nx\\\ny\nE\necho a  b")

    def test_a_body_line_that_equals_the_ssh_line_is_not_replaced(self):
        new = self.inner(self.ssh("ssh dev2 ls\ncat <<'E'\nssh dev2 ls\nE"))
        self.assertIn('--token via-hook-ssh', new.split('\n')[0])
        self.assertEqual(new.split('\n', 1)[1], "cat <<'E'\nssh dev2 ls\nE")

    def test_typed_and_rewritten_end_the_same(self):
        """The rig runs the real launcher for the rewritten form and a plain sh for the typed one; stdout and status must match."""
        scratch = Path(self.temp.name) / 'cwd'; scratch.mkdir()
        rows = ("ssh rig cat <<'E'\nE\\\n\necho HIDDEN-LINE\nE", "ssh rig cat <<'E'\nb\\\nE\necho AFTER\nE", "ssh rig ls /dev/null\ncat <<'E'\nx\\\ny\nE",
                "ssh rig 'cat' <<'EOF'\nfoo \\\nbar\nEOF", "ssh rig cat <<'E'\n$(no) `no` \\\n'\nE\necho next", 'ssh rig \\\n  cat <<E\nplain\nE')
        for typed in rows:
            out = self.ssh(typed)
            new = self.inner(out)
            self.assertIn('--cmd-b64', new.split('\n')[0], typed)
            plain = subprocess.run(['/bin/sh', '-c', typed], env={**self.env, 'PATH': os.environ['PATH']}, capture_output=True, text=True, timeout=30, cwd=str(scratch))
            wrapped = subprocess.run(['/bin/sh', '-c', new], env={**self.env, 'PATH': os.environ['PATH']}, capture_output=True, text=True, timeout=30, cwd=str(scratch))
            self.assertEqual((wrapped.returncode, wrapped.stdout), (plain.returncode, plain.stdout), (typed, wrapped.stderr))
            self.assertNotIn('HIDDEN-LINE\n', wrapped.stdout.replace('echo HIDDEN-LINE\n', ''), typed)

    def test_a_file_sent_through_a_heredoc_has_the_typed_bytes(self):
        target = Path(self.temp.name) / 'sent.txt'
        body = "foo \\\nbar\n\ttab\n'quote' \"q\" $(x) \u00e9\n"
        out = self.ssh("ssh rig 'cat > %s' <<'EOF'\n%sEOF" % (target, body))
        self.assertEqual(self.b64_of(self.inner(out).split('\n')[0]), 'cat > %s' % target)
        result = self.exec_wrapped(out)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(target.read_bytes(), body.encode('utf-8'))

    def test_a_remote_heredoc_in_one_quoted_word_keeps_its_exact_bytes(self):
        payload = 'cat <<EOF\nfoo \\\nbar\nEOF'
        out = self.ssh("ssh dev2 '%s'" % payload)
        self.assertEqual(self.b64_of(self.inner(out)), payload)
        self.assertIn('uncertain', out['additionalContext'])

    def test_text_the_parse_cannot_place_is_never_replaced(self):
        for typed in ("ssh dev2 ls\necho $'a' <<E\nssh dev2 ls\nE", 'echo "a; ssh dev2 X; b"; ssh dev2 $(echo ls)', "echo \"ssh dev2 'ls'\"; ssh dev2 $'ls'",
                      'ssh dev2 ls; echo $(echo \'a\')', 'ssh dev2 echo $(echo \'a\')', 'ssh dev2 echo `echo "a"`', 'ssh dev2 echo "${y:-\'a\'}"'):
            out = self.ssh(typed)
            self.assertEqual(self.inner(out), typed)
            self.assertIn('--command-class remote-unwrapped', out['updatedInput']['command'], typed)

    def test_a_redirect_attached_to_a_word_stays_on_the_local_side(self):
        for typed in ('ssh dev2 cat>f', 'ssh dev2 cat<f', 'ssh dev2 a>f<g', 'ssh dev2 cat }', '{ ssh dev2 ls }'):  # zsh reads a bare } as a close, or a parse error
            out = self.ssh(typed)
            self.assertEqual(self.inner(out), typed)
            self.assertIn('--command-class remote-unwrapped', out['updatedInput']['command'], typed)

    def test_ssh_fork_and_persist_options_are_escapes(self):
        for command in ('ssh -o ForkAfterAuthentication=yes dev2 sleep 99', 'ssh -oForkAfterAuthentication=yes dev2 sleep 99',
                        'ssh dev2 -o ForkAfterAuthentication=yes sleep 99', 'ssh -o "ForkAfterAuthentication yes" dev2 ls',
                        'ssh -o forkafterauthentication=YES dev2 ls', 'ssh -o ControlPersist=yes dev2 ls', 'ssh -o ControlPersist=10m dev2 ls',
                        'ssh -o RemoteCommand="nohup x" dev2', 'ssh -o LocalCommand="nohup x" dev2 ls',
                        # r5 S25: ssh separates an option from its value with =, blanks or tabs
                        "ssh -o 'ForkAfterAuthentication\tyes' dev2 ls", "ssh -o 'ControlPersist\t5' dev2 ls", "ssh -o 'RemoteCommand\tnohup x' dev2",
                        "ssh -o 'ForkAfterAuthentication = yes' dev2 ls", "ssh -o 'ControlPersist  5' dev2 ls"):
            self.assertEqual(self.ssh(command)['permissionDecision'], 'deny', command)
        for command in ('ssh -o ForkAfterAuthentication=no dev2 ls', 'ssh -o ControlPersist=no dev2 ls', 'ssh -o ConnectTimeout=5 dev2 ls',
                        "ssh -o 'ForkAfterAuthentication\tno' dev2 ls"):
            self.assertNotEqual(self.ssh(command).get('permissionDecision'), 'deny', command)

    def test_an_unwrapped_line_of_a_readonly_agent_records_readonly(self):
        for command in ('ssh -o IdentityFile=x dev2 ls', 'ssh -J jump dev2 ls', 'ssh -F x dev2 ls', "ssh dev2 <<'E'\necho hi\nE"):
            out = self.ssh(command, agent_type='red-team', agent_id='rt1')
            wrapped = out['updatedInput']['command']
            head = wrapped.split(' -- ', 1)[0]
            self.assertIn('--readonly', head, command); self.assertIn('--command-class remote-', head, command)
            self.assertIn('read-only agent', out.get('additionalContext', ''), command)
            self.assertNotIn('--readonly', self.ssh(command)['updatedInput']['command'].split(' -- ', 1)[0], command)

    def test_prefix_and_pipeline_stages_are_kept(self):
        line = self.inner(self.ssh("printf data | ssh dev2 'cat' | wc -c"))
        self.assertTrue(line.startswith('printf data | ssh dev2 python3 '), line); self.assertTrue(line.endswith(' | wc -c'), line)
        line = self.inner(self.ssh("timeout 20 ssh dev2 'ls'"))
        self.assertTrue(line.startswith('timeout 20 ssh dev2 python3 '), line)
        line = self.inner(self.ssh("cd /tmp && ssh dev2 'ls' && echo done"))
        self.assertTrue(line.startswith('cd /tmp && ssh dev2 python3 ') and line.endswith(' && echo done'), line)

    def test_stdin_pipe_is_preserved_end_to_end(self):
        out = self.ssh("printf 'a b\\nc\\n' | ssh rig 'cat'")
        self.assertRegex(self.inner(out), r"^printf 'a b\\nc\\n' \| ssh rig ")
        done = self.exec_wrapped(out)
        self.assertEqual((done.returncode, done.stdout), (0, 'a b\nc\n'), done.stderr)
        rows = self.remote_rows()
        self.assertEqual(len(rows), 1); self.assertEqual((rows[0]['attribution'], rows[0]['exit_code']), ('hook-ssh', 0))

    def test_base64_round_trip_with_quotes_dollar_backticks_and_non_ascii(self):
        remote = 'printf %s \'$HOME `date` "q" it\'"\'"\'s é ü 日本 \\n\''
        line = self.inner(self.ssh('ssh dev2 ' + shlex.quote(remote)))
        self.assertEqual(self.b64_of(line), remote)
        out = self.ssh('ssh rig ' + shlex.quote(remote))
        done = self.exec_wrapped(out)
        self.assertEqual(done.stdout, '$HOME `date` "q" it\'s é ü 日本 \\n', done.stderr)

    def test_local_expansion_happens_before_ssh_like_the_unwrapped_command(self):
        out = self.ssh('ssh rig "echo $LOCALVAR"')
        self.assertIn('"$(set -- ', self.inner(out))
        self.assertEqual(self.exec_wrapped(out, LOCALVAR='seen-locally').stdout, 'seen-locally\n')
        plain = subprocess.run(['/bin/sh', '-c', 'ssh rig "echo $LOCALVAR"'], capture_output=True, text=True,
                               env={**os.environ, 'LOCALVAR': 'seen-locally'})
        self.assertEqual(plain.stdout, 'seen-locally\n')

    def test_redirections_stay_local(self):
        target = Path(self.temp.name) / 'out.txt'
        out = self.ssh("ssh rig 'echo hi' > %s 2>&1" % target)
        self.assertRegex(self.inner(out), r'--cmd-b64 \S+ > \S+out\.txt 2>&1$')
        self.assertEqual(self.exec_wrapped(out).returncode, 0)
        self.assertEqual(target.read_text(), 'hi\n')

    def test_remote_row_records_attribution_readonly_and_exit(self):
        out = self.ssh("ssh rig 'exit 7'", agent_type='red-team', agent_id='rt1')
        self.assertEqual(self.exec_wrapped(out).returncode, 7)
        row = self.remote_rows()[0]
        self.assertEqual((row['attribution'], row['readonly'], row['agent'], row['exit_code']), ('hook-ssh', True, 'rt1', 7))
        self.assertEqual(row['command_sha256'], hashlib.sha256(b'exit 7').hexdigest())

    def test_remote_env_is_limited_to_agent_harness_keys(self):
        line = self.inner(self.ssh("ssh rig 'ls'"))
        self.assertIn(' env AGENT_HARNESS_RESERVE_DIR=%s ' % self.remote_reserve, line); self.assertNotIn('/evil', line)

    # -- escapes, refusals and what stays untouched --------------------------------------------------------

    def test_escape_in_remote_command_is_refused_without_contacting_the_host(self):
        for command in ("ssh dev2 'sleep 30 &'", "ssh dev2 'nohup sleep 30'", "ssh pve 'make test &'", "ssh unknown 'make test &'",
                        "ssh dev2 'setsid sleep 9'", "ssh dev2 'cd /x && nohup make'", "ssh dev2 'tmux new -d make'"):
            out = self.ssh(command)
            self.assertEqual(out['permissionDecision'], 'deny', command)
            self.assertIn('escapes tracking', out['permissionDecisionReason'])
            self.assertNotIn('updatedInput', out)
        self.assertFalse(self.contacted())

    def test_foreground_parallelism_in_the_remote_command_is_not_an_escape(self):
        self.assertEqual(self.b64_of(self.inner(self.ssh("ssh dev2 'sleep 1 & wait'"))), 'sleep 1 & wait')

    def test_ssh_f_is_an_escape(self):
        for command in ("ssh -f dev2 'sleep 1'", "ssh -fN -L 8080:x:80 dev2", "ssh -o BatchMode=yes -f dev2 ls"):
            self.assertEqual(self.ssh(command)['permissionDecision'], 'deny', command)

    def test_no_command_is_untouched(self):
        for command in ('ssh dev2', 'ssh -t dev2', 'ssh -N -L 8080:x:80 dev2', 'ssh -W host:22 dev2'):
            self.assertEqual(self.inner(self.ssh(command)), command)
        self.assertFalse(self.contacted())

    def test_scp_sftp_rsync_are_untouched(self):
        for command in ('scp a.txt dev2:/tmp/', 'sftp dev2', 'rsync -a src/ dev2:/tmp/src/', 'rsync -e ssh -a src/ dev2:/tmp/src/',
                        "rsync -e 'ssh -p 2222' dev2:/x ."):
            self.assertEqual(self.inner(self.ssh(command)), command)
        self.assertFalse(self.contacted())

    def test_over_64kib_is_refused_naming_the_limit_and_the_alternative(self):
        command = "ssh dev2 'echo %s'" % ('x' * (64 * 1024 + 1))
        for mode in ('bypassPermissions', 'dontAsk'):
            out = self.ssh(command, permission_mode=mode)
            self.assertEqual(out['permissionDecision'], 'deny', mode)
            reason = out['permissionDecisionReason']
            self.assertIn('64 KiB', reason); self.assertIn('scp', reason); self.assertIn('rsync', reason); self.assertIn('script file', reason)
        for mode in ('default', 'acceptEdits'):  # a person sees it: asked, not scanned, not rewritten
            out = self.ssh(command, permission_mode=mode)
            self.assertEqual(out['permissionDecision'], 'ask', mode)
            self.assertIn('64 KiB', out['permissionDecisionReason']); self.assertIn('--cmd-file', out['updatedInput']['command'])
        self.assertFalse(self.contacted())
        self.assertNotEqual(self.ssh("ssh dev2 'echo %s'" % ('x' * 60000)).get('permissionDecision'), 'deny')

    def test_a_quoted_or_escaped_ssh_word_is_recorded_and_carries_readonly(self):
        """r6 S28: the line cannot be rewritten in place, so it runs unwrapped, recorded remote-unattributed, and a review agent's
        row carries --readonly."""
        for command in ('"ssh" dev2 ls', "'ssh' dev2 ls", 's\\sh dev2 ls', 'command "ssh" dev2 ls', '"/usr/bin/ssh" dev2 ls'):
            out = self.ssh(command, agent_type='red-team', agent_id='r1')
            wrapped = out['updatedInput']['command']
            self.assertIn('--command-class remote-unattributed', wrapped, command)
            self.assertIn('--readonly', wrapped, command)
            self.assertEqual(self.inner(out), command, command)
            plain = self.ssh(command)['updatedInput']['command']
            self.assertIn('--command-class remote-unattributed', plain, command); self.assertNotIn('--readonly', plain, command)
        self.assertFalse(self.contacted())

    def test_control_without_the_s28_check_a_quoted_ssh_word_is_not_recorded(self):
        with mock.patch.object(ah_run, '_quoted_ssh_target', lambda segment: None):
            wrapped = self.ssh('"ssh" dev2 ls', agent_type='red-team')['updatedInput']['command']
        self.assertNotIn('--command-class', wrapped); self.assertNotIn('--readonly', wrapped)

    def test_external_host_is_untouched_and_recorded_remote_unattributed(self):
        out = self.ssh("ssh pve 'qm list'")
        self.assertEqual(self.inner(out), "ssh pve 'qm list'")
        wrapped = out['updatedInput']['command']
        host_digest = hashlib.sha256(b'pve.example.test').hexdigest()
        self.assertIn('--command-class remote-unattributed --remote-host-sha256 ' + host_digest, wrapped)
        done = self.exec_wrapped(self.ssh("ssh pve 'echo listed'"))
        self.assertEqual(done.stdout, 'listed\n', done.stderr)
        row = self.rows()[0]
        self.assertEqual((row['command_class'], row['remote_host_sha256']), ('remote-unattributed', host_digest))
        self.assertNotIn('pve.example.test', json.dumps(row)); self.assertEqual(self.remote_rows(), [])

    def test_unknown_host_is_external(self):
        (self.stubs / 'mystery.txt').write_text(_ssh_g('mystery.example.test'))
        out = self.ssh("ssh mystery 'uptime'")
        self.assertEqual(self.inner(out), "ssh mystery 'uptime'"); self.assertIn('remote-unattributed', out['updatedInput']['command'])

    def test_worker_without_remote_ah_run_is_untouched_and_recorded_remote_unwrapped(self):
        for alias, name in (('mac2', 'mac2.example.test'), ('unwrapped', 'unwrapped.example.test')):
            out = self.ssh("ssh %s 'ls'" % alias)
            self.assertEqual(self.inner(out), "ssh %s 'ls'" % alias)
            self.assertIn('--command-class remote-unwrapped --remote-host-sha256 ' + hashlib.sha256(name.encode()).hexdigest(),
                          out['updatedInput']['command'])

    def test_an_unsafe_table_path_is_not_used(self):
        out = self.ssh("ssh badpath 'ls'")
        self.assertEqual(self.inner(out), "ssh badpath 'ls'"); self.assertIn('remote-unwrapped', out['updatedInput']['command'])
        self.assertIn('not a plain path', out['additionalContext'])

    def test_local_loopback_is_not_rewritten_or_classed_remote(self):
        out = self.ssh("ssh localhost 'ls'")
        self.assertEqual(self.inner(out), "ssh localhost 'ls'"); self.assertNotIn('remote-', out['updatedInput']['command'])

    def test_loopback_on_a_tunnel_port_is_external(self):
        (self.stubs / 'localhost.txt').write_text(_ssh_g('localhost', 2222))
        out = self.ssh("ssh -p 2222 localhost 'ls'")
        self.assertIn('--command-class remote-unattributed', out['updatedInput']['command'])

    def test_resolution_failure_is_external_and_logged_without_the_name(self):
        out = self.ssh("ssh nowhere.example.test 'ls'")
        self.assertEqual(self.inner(out), "ssh nowhere.example.test 'ls'"); self.assertIn('remote-unattributed', out['updatedInput']['command'])
        rows = [json.loads(line) for line in (self.reserve / 'warn.jsonl').read_text().splitlines()]
        self.assertEqual(rows[0]['guard'], 'ssh-resolve')
        self.assertNotIn('nowhere', json.dumps(rows))

    def test_a_missing_table_leaves_every_host_untouched(self):
        self.policy.unlink()
        out = self.ssh("ssh dev2 'ls'")
        self.assertEqual(self.inner(out), "ssh dev2 'ls'"); self.assertIn('remote-unattributed', out['updatedInput']['command'])

    def test_ssh_inside_a_substitution_or_other_form_that_cannot_be_rewritten_is_recorded_unwrapped(self):
        out = self.ssh('ssh dev2 "echo $(date)"')
        self.assertEqual(self.inner(out), 'ssh dev2 "echo $(date)"')
        self.assertIn('remote-unwrapped', out['updatedInput']['command'])

    def test_non_ssh_commands_never_resolve(self):
        self.ssh('git status && ls | wc -l')
        self.assertFalse(self.contacted())

    # -- failing-first controls ---------------------------------------------------------------------------

    def alias_row_rewrites(self):
        return 'python3 -I %s run' % self.REMOTE_PATH in self.inner(self.ssh("ssh dev2 'git log'"))

    def nohup_row_refused(self):
        return self.ssh("ssh dev2 'nohup sleep 30'").get('permissionDecision') == 'deny'

    def test_control_real_code_passes_both_rows(self):
        self.assertTrue(self.alias_row_rewrites()); self.assertTrue(self.nohup_row_refused())

    def test_control_mutant_keying_the_table_by_the_alias_fails_the_alias_row(self):
        # the alias `dev2` resolves to dev2.example.test; a table keyed by the alias would look up `dev2`
        real = host_table.resolve
        mutant = lambda target, args=(), run=None: host_table.Resolved(target, 22)
        with mock.patch.object(host_table, 'resolve', mutant):
            self.assertFalse(self.alias_row_rewrites())
        self.write_policy(**{'dev2': {'role': 'worker', 'ah_run': self.REMOTE_PATH}})
        with mock.patch.object(host_table, 'resolve', mutant):
            self.assertTrue(self.alias_row_rewrites())   # the mutant only passes with an alias-keyed table: the row discriminates
        self.assertIs(host_table.resolve, real)

    def test_control_mutant_skipping_the_remote_command_escape_check_fails_the_nohup_row(self):
        original = ah_run._classify_ssh

        def skip_remote(args, reasons, notes, depth):
            call = host_table.parse_ssh(args)
            original(call.opts + [call.target] if call else args, reasons, notes, depth)
        with mock.patch.object(ah_run, '_classify_ssh', skip_remote):
            self.assertFalse(self.nohup_row_refused())
            self.assertFalse(self.ssh("ssh dev2 'sleep 30 &'").get('permissionDecision') == 'deny')


if __name__ == '__main__':
    unittest.main()
