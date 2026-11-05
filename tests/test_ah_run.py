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

AH = str(HOOKS / 'ah_run.py')


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
        self.assertTrue(wrapped.startswith('python3 %s run --task auto-' % ah_run.Path(ah_run.__file__).resolve()), wrapped)
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
        with mock.patch.object(ah_run.subprocess, 'run', fake):
            chain = ah_run.ancestor_commands()
        self.assertEqual(len(chain), 8); self.assertEqual(len(calls), 8)

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
        with mock.patch.object(ah_run, 'heredoc_scan', lambda command: (ah_run.HEREDOC_NONE, command, [])):
            wrong = check_rows(ah_run.classify_escapes)
        self.assertIn('refused:heredoc-body-has-nohup', wrong)

    def test_control_mutant_treating_and_and_as_background_fails_the_chain_row(self):
        real = ah_run._tokens
        def mutant(text):
            return [('op', '&') if token == ('op', '&&') else token for token in real(text)]
        with mock.patch.object(ah_run, '_tokens', mutant):
            wrong = check_rows(ah_run.classify_escapes)
        self.assertIn('refused:and-or-chain', wrong)


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
        for command in ("echo $'\\n'", "echo $'tab\\there' done", "echo $'it\\'s'", 'echo $"x y"', "echo $'\\x41\\101\\u00e9'"):
            self.assertEqual(self.decide(command)['permissionDecision'], 'allow', command)

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
        def old_order(command):
            import commit_policy
            text, bodies = commit_policy._heredocs(command.strip())
            text, ok = ah_run.deansi(text)
            return text, bodies, not ok
        with mock.patch.object(ah_run, '_prepare_text', old_order):
            self.assertEqual(self.decide(self.FAKE_HEREDOC)['permissionDecision'], 'allow')

    def test_escape_classifier_sees_through_ansi_c(self):
        self.assertTrue(ah_run.classify_escapes("echo $'\\'' ; nohup x ; echo ''"))
        self.assertEqual(ah_run.classify_escapes("echo $'nohup \\n' ; true"), [])


class HeredocRule(HookFixture):
    """B6: a body is removed only when the opener is certain; everything else keeps all its lines in the checks."""
    # Data only for the touch rows. HIDDEN below is the only form that reaches a shell, and it is an echo.
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

    def test_a_certain_scan_agrees_with_the_real_shells(self):
        """Differential: with a harmless echo on the hidden line, a shape the scan calls certain must not print it."""
        ran = 0
        cases = list(self.SHAPES.values()) + ['cat <<EOF\n%s\nEOF', "cat <<'E'\n%s\nE", 'cat <<-E\n\t%s\n\tE', 'cat <<A <<B\n%s\nA\n%s\nB']
        for shell in ('/bin/bash', '/bin/zsh', '/bin/sh'):
            if not os.access(shell, os.X_OK):
                continue
            for shape in cases:
                command = shape.replace('%s', 'echo HIDDEN-LINE')
                done = subprocess.run([shell, '-c', command], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL, cwd=self.temp.name)
                shown = 'HIDDEN-LINE' in done.stdout.replace('echo HIDDEN-LINE', '')
                ran += shown
                if ah_run.heredoc_scan(command)[0] == ah_run.HEREDOC_CERTAIN:
                    self.assertFalse(shown, (shell, command))
        self.assertGreater(ran, 5, 'the corpus must include shapes the shell really runs, or the row proves nothing')

    def test_the_rule_is_not_reached_through_the_shared_commit_policy_parser(self):
        import commit_policy
        with mock.patch.object(commit_policy, '_heredocs', side_effect=AssertionError('commit_policy parser used')):
            self.assertEqual(ah_run.parse_command('cat <<EOF\nb\nEOF').segments, ['cat <<__HD0__'])


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
        self.assertEqual(self.decide(self.BIG + '; rm x')['permissionDecision'], 'deny')
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
        self.assertTrue(line.startswith('ssh dev2 python3 %s run --task auto-' % self.REMOTE_PATH), line)
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
        self.assertTrue(line.startswith('ssh -p 2222 dev2 python3 %s run' % self.REMOTE_PATH), line)
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
        self.assertTrue(line.startswith('ssh dev2 -p 2222 python3 %s run' % self.REMOTE_PATH), line)
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
        out = self.ssh("ssh dev2 'echo %s'" % ('x' * (64 * 1024 + 1)))
        self.assertEqual(out['permissionDecision'], 'deny')
        reason = out['permissionDecisionReason']
        self.assertIn('64 KiB', reason); self.assertIn('scp', reason); self.assertIn('rsync', reason)
        self.assertNotEqual(self.ssh("ssh dev2 'echo %s'" % ('x' * 60000)).get('permissionDecision'), 'deny')

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
        return 'python3 %s run' % self.REMOTE_PATH in self.inner(self.ssh("ssh dev2 'git log'"))

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
