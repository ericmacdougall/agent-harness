"""Self-serve lane L6 (GoodQA goodqa#16753; spec NEG-1 guard half, NEG-6 guard half).

The command guard protects the signed self-serve policy, its pinned public key, the signing key, the installed enabler
and the run journals from agent writes and deletes, and refuses enable/undo/disable/resume from any agent. An agent
may still create the kill-switch file (fail-safe revoke) but can never delete it. ACCIDENT PREVENTION: the guard sees
command text only; the enabler's own TTY and nonce check is the real control. Corpus rows are data only."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'harness/hooks'))
import command_guard as cg  # noqa: E402

AH = '~/.agent-harness'
PROTECTED_PATHS = (
    AH + '/policy/self-serve.json',
    AH + '/policy/self-serve-pubkeys.json',
    AH + '/private/self-serve/ed25519.key',
    AH + '/private/self-serve/ed25519.key.bak',
    AH + '/bin/ah_enable_self_serve.py',
    AH + '/bin/enable-agent-ops.py',
    AH + '/work/self-serve/run-1/journal.json',
)
WRITERS = (
    "echo '{}' > %s",
    "echo '{}' >> %s",
    "printf x | tee %s",
    "cp /tmp/x %s",
    "install -m 600 /tmp/x %s",
    "sed -i s/a/b/ %s",
    "dd if=/tmp/x of=%s",
    "python3 -c \"open('%s','w').write('x')\"",
)
DELETERS = ("rm %s", "rm -f %s", "mv %s /tmp/gone", "truncate -s 0 %s", "shred %s")
ENABLER = AH + '/bin/ah_enable_self_serve.py'
SCRIPT = 'scripts/enable-agent-ops.py'


class Guard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        for sub in ('policy', 'private/self-serve', 'bin', 'work/self-serve/run-1'):
            (self.home / '.agent-harness' / sub).mkdir(parents=True)
        for path in PROTECTED_PATHS:
            (Path(path.replace('~', str(self.home)))).write_text('x')
        patch = mock.patch.dict(os.environ, {'HOME': str(self.home)})
        patch.start()
        self.addCleanup(patch.stop)
        self.compiled = cg.Compiled(cg.load_policy(), cwd=str(self.home))

    def decide(self, command):
        return cg.decide(command.replace('~', str(self.home)), self.compiled, cwd=str(self.home))[0]

    def hook(self, command):
        payload = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': command.replace('~', str(self.home))}})
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = cg.hook_main('exit2', stdin_bytes=payload.encode(), compiled=self.compiled, marker=False)
        return code, err.getvalue()


class ProtectedPaths(Guard):
    def test_agent_writes_to_policy_key_enabler_and_journals_are_blocked(self):  # NEG-1
        for path in PROTECTED_PATHS:
            for template in WRITERS:
                command = template % path
                with self.subTest(command):
                    code, message = self.hook(command)
                    self.assertEqual(code, 2, command)
                    self.assertTrue('self-serve' in message or 'credential' in message, message)

    def test_agent_deletes_of_the_same_paths_are_blocked(self):
        for path in PROTECTED_PATHS + (AH + '/private/self-serve', AH + '/work/self-serve'):
            for template in DELETERS + ("rm -rf %s",):
                command = template % path
                with self.subTest(command):
                    self.assertEqual(self.hook(command)[0], 2, command)

    def test_the_refusal_names_the_sanctioned_route(self):
        code, message = self.hook("echo '{}' > %s/policy/self-serve.json" % AH)
        self.assertEqual(code, 2)
        self.assertIn('ah install-files', message)
        self.assertIn('ah ops', message)

    def test_reading_the_policy_and_listing_the_folders_stays_allowed(self):
        for command in ('cat %s/policy/self-serve.json' % AH, 'ls -la %s/policy %s/work/self-serve' % (AH, AH),
                        'python3 -c "import json;print(json.load(open(\'%s/policy/self-serve.json\')))"' % AH,
                        'wc -c %s/policy/self-serve-pubkeys.json' % AH, 'git status'):
            with self.subTest(command):
                self.assertNotEqual(self.hook(command)[0], 2, command)

    def test_the_private_key_cannot_be_read_by_an_agent(self):
        for command in ('cat %s/private/self-serve/ed25519.key' % AH, 'base64 %s/private/self-serve/ed25519.key' % AH):
            with self.subTest(command):
                self.assertEqual(self.hook(command)[0], 2, command)

    def test_unrelated_harness_files_are_not_newly_blocked(self):
        for command in ('echo x > %s/policy/other.json' % AH, 'echo x > %s/work/s1/notes.txt' % AH,
                        'echo x > %s/bin/other-tool' % AH):
            with self.subTest(command):
                self.assertEqual(self.decide(command), 'allow', command)


class KillSwitch(Guard):
    def test_an_agent_may_create_the_kill_switch_but_not_remove_or_replace_it(self):  # NEG-6
        flag = AH + '/policy/disabled'
        for command in ('touch %s' % flag, 'echo revoked > %s' % flag, 'printf x > %s' % flag):
            with self.subTest(command):
                self.assertNotEqual(self.hook(command)[0], 2, command)
        (self.home / '.agent-harness/policy/disabled').write_text('1')
        for command in ('rm %s' % flag, 'rm -f %s' % flag, 'mv %s /tmp/x' % flag, 'truncate -s 0 %s' % flag,
                        'rm -rf %s/policy' % AH, 'cp /tmp/x %s' % flag):
            with self.subTest(command):
                self.assertEqual(self.hook(command)[0], 2, command)


class Enabler(Guard):
    def test_enable_undo_disable_resume_are_refused_in_every_spelling(self):  # NEG-1, NEG-6
        mutating = (
            'python3 %s --apply' % ENABLER,
            'python3 -I %s --apply' % ENABLER,
            'python3 %s --undo' % ENABLER,
            'python3 %s --disable merge_reviewed_pr' % ENABLER,
            'python3 %s --resume run-1' % ENABLER,
            'python3 %s --apply' % SCRIPT,
            'python3 %s --undo' % SCRIPT,
            'python3 harness/scripts/enable-agent-ops.py --apply',
            '%s --apply' % ENABLER,
            'env FOO=1 python3 %s --apply' % ENABLER,
            'sudo python3 %s --undo' % ENABLER,
            'yes | python3 %s --apply' % ENABLER,
            'echo hi; python3 %s --apply' % ENABLER,
            'python3 %s --ap""ply' % ENABLER,
            "python3 %s '--undo'" % ENABLER,
            "bash -c 'python3 %s --apply'" % ENABLER,
            "sh -lc \"python3 %s --undo\"" % SCRIPT,
            'python3 %s apply' % ENABLER,
            'python3 %s --apply --yes' % ENABLER,
            'python3 -c "import ah_enable_self_serve as m; m.main([\'--apply\'])"',
            'python3 -m ah_enable_self_serve --apply',
            'python3 -c "import runpy; runpy.run_path(\'%s\')"' % SCRIPT,
        )
        for command in mutating:
            with self.subTest(command):
                code, message = self.hook(command)
                self.assertEqual(code, 2, command)
                self.assertIn('self-serve', message)

    def test_the_refusal_says_the_user_runs_it_and_how_to_revoke(self):
        code, message = self.hook('python3 %s --apply' % ENABLER)
        self.assertEqual(code, 2)
        self.assertIn('own terminal', message)
        self.assertIn('policy/disabled', message)
        self.assertIn('ah ops', message)

    def test_read_only_forms_and_mentions_stay_allowed(self):
        for command in ('python3 %s --status' % ENABLER, 'python3 %s' % ENABLER, 'python3 %s --dry-run' % SCRIPT,
                        'python3 %s --help' % SCRIPT, 'git log --oneline -- %s' % SCRIPT, 'git add %s' % SCRIPT,
                        'grep -n -- --apply %s' % SCRIPT, 'cat %s | head' % SCRIPT, 'ls %s' % ENABLER,
                        'python3 -m pytest tests/test_enable_agent_ops.py', 'echo --apply'):
            with self.subTest(command):
                self.assertNotEqual(self.hook(command)[0], 2, command)


class Launcher(unittest.TestCase):
    def test_the_fail_closed_launcher_also_blocks_a_mutating_enabler_call(self):
        sys.path.insert(0, str(ROOT / 'harness/hooks'))
        import command_guard_hook as launcher  # noqa: PLC0415
        self.assertTrue(launcher.sensitive('python3 scripts/enable-agent-ops.py --apply'))
        self.assertTrue(launcher.sensitive('python3 ah_enable_self_serve.py --undo'))
        self.assertFalse(launcher.sensitive('git status'))
        self.assertFalse(launcher.sensitive('python3 scripts/enable-agent-ops.py --status'))


if __name__ == '__main__':
    unittest.main()
