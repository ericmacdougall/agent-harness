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

    def test_payload_file_is_read_once_and_unlinked(self):
        payload = self.reserve / 'ledger' / 'pending' / 'tok.cmd'
        payload.parent.mkdir(parents=True, exist_ok=True)
        payload.write_text('echo from-file'); payload.chmod(0o600)
        result = subprocess.run([sys.executable, AH, 'run', '--task', 't1', '--token', 'tok', '--no-unit', '--cmd-file', str(payload)],
                                env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, 'from-file'))
        self.assertFalse(payload.exists())

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

    def test_recovery_passthrough(self):
        for command in ('python3 harness/reserve.py status', 'python3 /x/reclaim.py plan', 'ah-run kill --task t1',
                        'python3 /x/ah_run.py kill --agent a', 'harness doctor', 'python3 harness/install.py --apply --role dev',
                        'harness doctor && python3 harness/reserve.py status'):
            out = self.decide(command)
            self.assertEqual(out['permissionDecision'], 'allow', command); self.assertNotIn('updatedInput', out, command)
        self.assertIn('updatedInput', self.decide('python3 harness/install.py --dry-run'))
        self.assertIn('updatedInput', self.decide('harness doctor; echo hi'))
        self.assertIn('updatedInput', self.decide('harness doctor $(echo x)'))

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
        with mock.patch.object(ah_run, '_strip_heredocs', lambda command: (command, [])):
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

    def test_options_with_values_are_parsed(self):
        line = self.inner(self.ssh("ssh -p 2222 -o StrictHostKeyChecking=no -J jump dev2 'git log'"))
        self.assertTrue(line.startswith('ssh -p 2222 -o StrictHostKeyChecking=no -J jump dev2 python3 %s run' % self.REMOTE_PATH), line)
        self.assertEqual(self.b64_of(line), 'git log')
        self.assertIn('-G -p 2222 -o StrictHostKeyChecking=no -J jump -- dev2', self.ssh_log.read_text())
        line = self.inner(self.ssh("ssh -p2222 -oBatchMode=yes -l eric dev2 git -C /x log -1"))
        self.assertEqual(self.b64_of(line), 'git -C /x log -1')

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
