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
    def test_enable_undo_disable_resume_are_refused_in_the_basic_spellings(self):  # NEG-1, NEG-6
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


BIN = AH + '/bin'
# Spellings that slipped past the first allowlist of wrappers (review finding 1). The guard is accident prevention, not
# a boundary: it must refuse by shape (anything that is not a plain read or a plain read-only run), not by wrapper name.
BYPASSES = (
    '(python3 %s --apply)' % ENABLER,
    '{ python3 %s --apply; }' % ENABLER,
    'timeout 5 python3 %s --apply' % ENABLER,
    'script -q /dev/null python3 %s --apply' % ENABLER,
    'python3 -W ignore %s --apply' % ENABLER,
    'nice -n 5 python3 %s --undo' % ENABLER,
    'python3 %s/ah_enable_*.py --apply' % BIN,
    'python3 %s/ah_enable_self_ser?e.py --apply' % BIN,
    'python3 %s/*enable*.py --apply' % BIN,
    'python3 %s/[a]h_enable_self_serve.py --apply' % BIN,
    'cd %s && python3 ah_enable_*.py --apply' % BIN,
    'cp %s /tmp/x.py && python3 /tmp/x.py --apply' % ENABLER,
    'cp %s /tmp/x.py' % ENABLER,
    'install -m 700 %s /tmp/x.py' % ENABLER,
    'rsync %s /tmp/' % ENABLER,
    'dd if=%s of=/tmp/x.py' % ENABLER,
    'tar cf /tmp/x.tar %s' % ENABLER,
    'ln -s %s /tmp/x.py && python3 /tmp/x.py --apply' % ENABLER,
    'ln %s /tmp/x.py' % ENABLER,
    'cat %s > /tmp/x.py && python3 /tmp/x.py --apply' % ENABLER,
    'cat %s >> /tmp/x.py' % ENABLER,
    'cat %s | python3 - --apply' % ENABLER,
    'cat %s | sh' % ENABLER,
    'cat %s | tee /tmp/x.py' % ENABLER,
    'ls %s | xargs python3 --apply' % ENABLER,
    'python3 -c "exec(open(\'%s\').read())"' % ENABLER,
    'python3 -c "import shutil;shutil.copy(\'%s\',\'/tmp/x.py\')"' % ENABLER,
    'perl -e \'system("python3 %s --apply")\'' % ENABLER,
    'eval "$(cat %s)"' % ENABLER,
    'source <(cat %s)' % ENABLER,
    'python3 <(cat %s) --apply' % ENABLER,
    'echo $(python3 %s --apply)' % ENABLER,
    'echo `python3 %s --apply`' % ENABLER,
    'find %s -name ah_enable_self_serve.py -exec python3 {} --apply \\;' % BIN,
    'find %s -exec python3 {} --apply \\; -name ah_enable_self_serve.py' % BIN,
    'a=ah_enable; python3 %s/${a}_self_serve.py --apply' % BIN,
    'python3 %s/$(echo ah_enable)_self_serve.py --apply' % BIN,
    'env -i python3 %s --apply' % ENABLER,
    'python3 %s --apply 2>/dev/null' % ENABLER,
    'python3 ./%s --apply' % os.path.basename(ENABLER),
    'cd %s && ./ah_enable_self_serve.py --apply' % BIN,
    'sudo -u root python3 %s --undo' % ENABLER,
    'echo "$(python3 %s --apply)"' % ENABLER,
    "python3 - <<'EOF'\nimport ah_enable_self_serve\nah_enable_self_serve.main(['--apply'])\nEOF",
    "cat <<'EOF' > /tmp/x.py\nimport runpy\nrunpy.run_path('%s')\nEOF" % ENABLER,
    "python3 - <<'EOF'\nimport os\nos.execv('/usr/bin/python3', ['python3', '%s', '--apply'])\nEOF" % ENABLER,
    # a command line inside a word, behind any wrapper (second review round)
    "timeout 5 bash -c 'python3 %s --apply'" % ENABLER,
    "nohup sh -c 'python3 %s --undo'" % ENABLER,
    "sudo bash -lc 'python3 %s --apply'" % ENABLER,
    "script -q /dev/null sh -c 'python3 %s --apply'" % ENABLER,
    "env -S 'python3 %s --apply'" % ENABLER,
    "watch 'python3 %s --apply'" % ENABLER,
    "ssh host 'python3 %s --apply'" % ENABLER,
    'eval $(cat %s)' % ENABLER,
    # pipelines that carry the enabler further than one hop
    'cat %s | head -999 | python3 - --apply' % ENABLER,
    'cat %s | cat > /tmp/x.py' % ENABLER,
    'cat %s | sort -o /tmp/x.py' % ENABLER,
    'python3 -c "print(open(E).read())" %s | sh' % ENABLER,
)
# Everyday work on the repo copy of the enabler and on prose that names it must keep working.
EVERYDAY = (
    './configure --enable-shared && cp build/* out/',
    'git add scripts/enable-agent-ops.py && python3 -m py_compile harness/hooks/*.py',
    'chmod +x scripts/enable-agent-ops.py', 'chmod +x ' + AH + '/work/s1/self-serve/l5/run.sh',
    'sed -n 1,40p scripts/enable-agent-ops.py', 'python3 -m py_compile scripts/enable-agent-ops.py',
    'ruff check scripts/enable-agent-ops.py', 'python3 -m pytest -q scripts/enable-agent-ops.py',
    'gh pr create --title "x" --body "uses `enable-agent-ops` as the guard"',
    'python3 ~/.claude/hooks/wal_note.py --event result --note "reviewed the ah_enable_self_serve guard"',
    'ah ticket comment goodqa#1 --body "the enable-agent-ops script is user-only"',
    'cat %s | head -5' % ENABLER, 'cat %s | grep -n main | sort | uniq -c' % ENABLER,
)
PERM_BYPASSES = (
    'chmod 000 %s/policy/disabled' % AH,
    'chmod -R 777 %s/policy' % AH,
    'chmod 755 %s/policy' % AH,
    'chmod -R go+rwx %s/private' % AH,
    'chmod 644 %s/private/self-serve/ed25519.key' % AH,
    'chmod 666 %s/policy/self-serve.json' % AH,
    'chmod a+rwx %s' % ENABLER,
    'chmod -R 777 %s' % AH,
    'chmod --recursive 777 %s' % AH,
    'chown nobody %s/policy/disabled' % AH,
    'chown -R nobody %s/policy' % AH,
    'chgrp staff %s/policy/self-serve.json' % AH,
    'chattr +i %s/policy/disabled' % AH,
    'chattr -R -i %s/policy' % AH,
    'setfacl -m u:nobody:rwx %s/policy' % AH,
    'setfacl -R -b %s/private' % AH,
    'chflags nouchg %s/policy/self-serve.json' % AH,
    'xattr -c %s/policy/disabled' % AH,
    'cd %s/policy && chmod 000 disabled' % AH,
    'cd %s/policy && chmod 700 .' % AH,
    'cd %s && chmod -R 777 policy' % AH,
    'find %s/policy -exec chmod 000 {} +' % AH,
    'find %s/private -type f -exec chown nobody {} \\;' % AH,
    'python3 -c "import os;os.chmod(\'%s/policy/disabled\',0)"' % AH,
    'python3 -c "import pathlib;pathlib.Path(\'%s/policy\').chmod(0o777)"' % AH,
)


class EnablerChokePoint(Guard):
    """One shape-based decision for every way of running, copying or feeding the enabler (class fix, review round 1)."""

    def test_bypass_spellings_from_the_review_are_refused(self):  # NEG-1, NEG-6
        for command in BYPASSES:
            with self.subTest(command):
                code, message = self.hook(command)
                self.assertEqual(code, 2, command)
                self.assertIn('self-serve', message)

    def test_everyday_work_on_the_repo_copy_and_prose_stay_allowed(self):
        for command in EVERYDAY:
            with self.subTest(command):
                self.assertNotEqual(self.hook(command)[0], 2, command)
                self.assertIsNone(cg.enabler_refusal(command.replace('~', str(self.home))), command)
                self.assertIsNone(cg.self_serve_perm_refusal(command.replace('~', str(self.home))), command)

    def test_the_two_probes_refuse_none_of_the_guard_corpus_allow_rows(self):
        sys.path.insert(0, str(ROOT / 'tests'))
        import command_guard_corpus as corpus  # noqa: PLC0415
        rows = list(corpus.NEGATIVE) + [r['cmd'] if isinstance(r, dict) else r for r in corpus.NEG15_WORK_ALLOW] \
            + list(corpus.HEREDOC_PLAIN_ALLOW)
        self.assertGreater(len(rows), 100)
        for command in rows:
            with self.subTest(command[:80]):
                self.assertIsNone(cg.enabler_refusal(command), command)
                self.assertIsNone(cg.self_serve_perm_refusal(command), command)

    def test_a_third_party_wrapper_name_does_not_matter(self):
        for wrapper in ('timeout 5', 'nohup', 'doas', 'chronic', 'unknown-wrapper --flag value', 'caffeinate -i', 'ionice -c3'):
            command = '%s python3 %s --apply' % (wrapper, ENABLER)
            with self.subTest(command):
                self.assertEqual(self.hook(command)[0], 2, command)

    def test_plain_mentions_and_read_only_runs_stay_allowed(self):
        for command in (
                'python3 %s --status' % ENABLER, 'python3 -I %s --dry-run' % ENABLER, 'timeout 5 python3 %s --status' % ENABLER,
                'env FOO=1 python3 %s --help' % ENABLER,
                'git commit -m "fix the enable-agent-ops guard"', 'git diff -- %s' % SCRIPT, 'git add %s' % SCRIPT,
                'git log --oneline -- %s' % SCRIPT, 'grep -n enable-agent-ops docs/ops.md', 'grep -n apply %s | head' % SCRIPT,
                'cat %s | head -20' % SCRIPT, 'cat %s | grep -n main' % ENABLER, 'ls -l %s/ah_enable_*' % BIN,
                'wc -l %s' % ENABLER, 'shellcheck %s' % SCRIPT, 'python3 -m pytest tests/test_enable_agent_ops.py',
                'python3 -m pytest -q tests/test_ah_enable_self_serve.py', 'find %s -name "ah_enable_*"' % BIN,
                'cat %s 2>/dev/null' % SCRIPT, 'diff %s %s' % (SCRIPT, ENABLER),
                'echo "see enable-agent-ops notes" >> /tmp/notes.md',
                "git commit -F - <<'EOF'\nfix(guard): enable-agent-ops handling\n\nWhy: x\nEOF",
                "git commit -m \"$(cat <<'EOF'\nfix: ah_enable_self_serve guard\nEOF\n)\"",
                'python3 -c "print(open(\'%s\').read()[:10])"' % ENABLER):
            with self.subTest(command):
                self.assertNotEqual(self.hook(command)[0], 2, command)


class PermissionChanges(Guard):
    """chmod and its relatives are writes to a protected location (review finding 2): a mode change can disable the
    revoke flag or widen the signed policy and key directories."""

    def setUp(self):
        super().setUp()
        (self.home / '.agent-harness/policy/disabled').write_text('1')

    def test_mode_owner_and_attribute_changes_are_refused(self):  # NEG-6
        for command in PERM_BYPASSES:
            with self.subTest(command):
                code, message = self.hook(command)
                self.assertEqual(code, 2, command)
                self.assertIn('self-serve', message)

    def test_the_decider_alone_refuses_a_resolved_permission_change(self):
        # the analyser path (decide), not only the text probe in hook_main
        for command in ('chmod 000 %s/policy/disabled' % AH, 'cd %s/policy && chmod 000 disabled' % AH,
                        'chmod -R 777 %s' % AH):
            with self.subTest(command):
                self.assertNotEqual(self.decide(command), 'allow', command)

    def test_unrelated_permission_changes_and_reads_stay_allowed(self):
        for command in ('chmod +x %s/bin/other-tool' % AH, 'chmod 600 %s/work/s1/notes.txt' % AH,
                        'chmod -R u+rwX %s/work/s1' % AH, 'chmod 644 /tmp/x', 'ls -l %s/policy' % AH,
                        'stat %s/policy/disabled' % AH, 'touch %s/policy/disabled' % AH, 'chmod --help'):
            with self.subTest(command):
                self.assertNotEqual(self.hook(command)[0], 2, command)


class RevokeFlagContract(unittest.TestCase):
    """Cross-lane: L1's revoke-flag test must fail safe when the file or its directory is unreadable. Runs when L1's
    self_serve.py is importable (this branch's base does not have it yet; set SELF_SERVE_L1_HOOKS to the L1 checkout's
    harness/hooks to run it before L1 merges)."""

    @classmethod
    def setUpClass(cls):
        extra = os.environ.get('SELF_SERVE_L1_HOOKS')
        if extra:
            sys.path.insert(0, extra)
        try:
            import self_serve  # noqa: PLC0415
        except ImportError:
            raise unittest.SkipTest('self_serve.py (lane L1) is not on this branch yet')
        cls.mod = self_serve

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = self.tmp.name
        self.policy = Path(self.home) / '.agent-harness/policy'
        self.policy.mkdir(parents=True)

    def _restore(self):
        os.chmod(self.policy, 0o700)
        flag = self.policy / 'disabled'
        if flag.exists():
            os.chmod(flag, 0o600)

    def test_no_file_means_not_disabled(self):
        self.assertFalse(self.mod.kill_switch_active(self.home))

    def test_chmod_000_on_the_flag_still_means_disabled(self):
        flag = self.policy / 'disabled'
        flag.write_text('1')
        self.addCleanup(self._restore)
        os.chmod(flag, 0)
        self.assertTrue(self.mod.kill_switch_active(self.home))

    @unittest.skipIf(os.geteuid() == 0, 'root ignores directory modes')
    def test_chmod_000_on_the_policy_directory_still_means_disabled(self):
        (self.policy / 'disabled').write_text('1')
        self.addCleanup(self._restore)
        os.chmod(self.policy, 0)
        self.assertTrue(self.mod.kill_switch_active(self.home))


class Launcher(unittest.TestCase):
    def test_the_fail_closed_launcher_also_blocks_a_mutating_enabler_call(self):
        sys.path.insert(0, str(ROOT / 'harness/hooks'))
        import command_guard_hook as launcher  # noqa: PLC0415
        self.assertTrue(launcher.sensitive('python3 scripts/enable-agent-ops.py --apply'))
        self.assertTrue(launcher.sensitive('python3 ah_enable_self_serve.py --undo'))
        # path-free spellings, so the older protected-text rule cannot be what blocks them
        for command in ('cp ah_enable_self_serve.py /tmp/y.py', 'timeout 5 python3 ah_enable_self_serve.py --apply',
                        'cat enable-agent-ops.py | sh', 'chmod 000 policy/disabled', 'chmod -R 777 policy/self-serve.json',
                        'find private/self-serve -exec chown nobody {} \\;', 'python3 -c "import os;os.chmod(\'policy/disabled\',0)"'):
            with self.subTest(command):
                self.assertTrue(launcher.sensitive(command), command)
        self.assertFalse(launcher.sensitive('git status'))
        self.assertFalse(launcher.sensitive('python3 scripts/enable-agent-ops.py --status'))


if __name__ == '__main__':
    unittest.main()
