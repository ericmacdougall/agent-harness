"""The Mac guard allows `ah install-files` only in its exact literal form and only for main (goodqa#15742, AC-9).
ACCIDENT PREVENTION, not an access control: the guard sees command text only."""
import contextlib
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import caller_identity  # noqa: E402
import command_guard as cg  # noqa: E402

HOME = os.path.expanduser("~")
GOOD = ('python3 -I ~/.claude/hooks/ah.py install-files --host t2-dev --from-ref %s --file ah.py --file doctor.py '
        '--ticket "GoodQA goodqa#15742"' % ("a" * 40))


def hook(command, main):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}).encode()
    err = io.StringIO()
    with mock.patch.object(caller_identity, "is_main", return_value=main), contextlib.redirect_stderr(err), \
            contextlib.redirect_stdout(io.StringIO()):
        code = cg.hook_main("exit2", stdin_bytes=payload, marker=False)
    return code, err.getvalue()


class Forms(unittest.TestCase):
    def test_the_installed_literal_form_passes_for_main_and_every_other_form_is_refused(self):  # AC-9, NEG-11
        for text in (GOOD, GOOD.replace("~", "$HOME"), GOOD.replace("~", HOME), GOOD.replace("python3 -I", "python3 -B -I"),
                     'python3 -I ~/.claude/hooks/ah.py install-files --host t2-dev --rollback ins-0123456789ab --force-file ah.py --ticket "GoodQA a#1"',
                     'python3 -I ~/.claude/hooks/ah.py install-files --host t2-dev --resume ins-0123456789ab --ticket "GoodQA a#1"',
                     'python3 -I ~/.claude/hooks/ah.py install-files --host t2-dev --from-ref %s --file ah.py --dry-run' % ("a" * 40)):
            with self.subTest(text[:70]):
                self.assertIsNone(cg.install_files_refusal(text, True))
                self.assertEqual(hook(text, True)[0], 0)
        bad = {
            "worktree copy": 'python3 harness/hooks/ah.py install-files --host t2-dev --file ah.py',
            "absolute other path": 'python3 /tmp/x/ah.py install-files --host t2-dev --file ah.py',
            "relative dot": 'python3 ./ah.py install-files --host t2-dev --file ah.py',
            "-c import": 'python3 -c "import ah_install; ah_install.install_files()"',
            "-c from import": 'python3 -c "from ah_install import install_files"',
            "-m module": 'python3 -m ah_install',
            "direct module": 'python3 harness/hooks/ah_install.py install-files',
            "repo flag": GOOD + " --repo /tmp/x",
            "unknown flag": GOOD + " --verbose",
            "flag missing value": 'python3 -I ~/.claude/hooks/ah.py install-files --host',
            "env prefix other script": 'FOO=1 python3 harness/hooks/ah.py install-files --host t2-dev',
            "chained after another command": 'echo hi; python3 harness/hooks/ah.py install-files --host t2-dev',
            "piped": 'true | python3 harness/hooks/ah.py install-files --host t2-dev',
        }
        for label, text in bad.items():
            with self.subTest(label):
                self.assertIsNotNone(cg.install_files_refusal(text, True), text)
                code, message = hook(text, True)
                self.assertEqual(code, 2, message)
                self.assertIn("install-files", message)

    def test_everyday_evasions_are_refused_for_a_sub_agent_and_the_real_form_with_redirects_passes_for_main(self):  # review M1, L1
        sub = {
            "quote-split name": GOOD.replace("install-files", 'install-file""s'),
            "bash -c wrapper": "bash -c '" + GOOD.replace('"', "") .replace("GoodQA goodqa#15742", "GoodQA-goodqa#15742") + "'",
            "sh -c wrapper": 'sh -c "' + GOOD.replace('"GoodQA goodqa#15742"', "'GoodQA goodqa#15742'") + '"',
            "env wrapper": "env FOO=1 " + GOOD,
            "heredoc import": "python3 - <<'EOF'\nimport ah_install\nEOF",
            "concatenated import": "python3 -c \"import importlib; importlib.import_module('ah_'+'install')\"",
        }
        for label, text in sub.items():
            with self.subTest(label):
                self.assertIsNotNone(cg.install_files_refusal(text, False), text)
                self.assertEqual(hook(text, False)[0], 2, text)
        worktree_in_bash = "bash -c 'python3 harness/hooks/ah.py install-files --host t2-dev'"
        self.assertIsNotNone(cg.install_files_refusal(worktree_in_bash, True))  # not even main, from a worktree copy
        for text in (GOOD + " > out.json", GOOD + " > out.json 2>&1", GOOD + " 2>&1 | tee out.txt", GOOD + " --allow-older"):
            with self.subTest(text[-30:]):
                self.assertIsNone(cg.install_files_refusal(text, True), text)
        for viewer in ("grep -rn install-files harness/", "rg install-files", "git log -S install-files", "sed -n 1,5p harness/hooks/ah_install.py",
                       'git commit -m "fix install-files guard; done"', 'git commit -m "install-files & more | x"',
                       "git commit -F - <<'E'\nfeat(install-files): add it; and more\nE"):
            with self.subTest(viewer):
                self.assertIsNone(cg.install_files_refusal(viewer, False), viewer)

    def test_a_sub_agent_is_refused_even_in_the_literal_form(self):  # AC-9, NEG-11
        self.assertIn("only the main agent", cg.install_files_refusal(GOOD, False))
        code, message = hook(GOOD, False)
        self.assertEqual(code, 2)
        self.assertIn("main agent", message)

    def test_the_local_targets_pass_for_main_and_are_refused_for_a_sub_agent(self):  # goodqa#15913 AC-5, NEG-1
        forms = [GOOD.replace("--host t2-dev", "--host " + host) for host in ("local", "local-codex")]
        forms += ['python3 -I ~/.claude/hooks/ah.py install-files --host local --rollback ins-0123456789ab --ticket "GoodQA a#1"',
                  'python3 -I ~/.claude/hooks/ah.py install-files --host local-codex --resume ins-0123456789ab --ticket "GoodQA a#1"',
                  'python3 -I ~/.claude/hooks/ah.py install-files --host local --from-ref %s --file command_guard.py --dry-run' % ("a" * 40)]
        for text in forms:
            with self.subTest(text[:80]):
                self.assertIsNone(cg.install_files_refusal(text, True))
                self.assertEqual(hook(text, True)[0], 0)
                self.assertIn("only the main agent", cg.install_files_refusal(text, False))
                code, message = hook(text, False)
                self.assertEqual(code, 2)
                self.assertIn("main agent", message)
        for text in (forms[0].replace("~/.claude/hooks/ah.py", "harness/hooks/ah.py"), "bash -c '%s'" % forms[0].replace('"', "")):
            with self.subTest(text[:60]):
                self.assertIsNotNone(cg.install_files_refusal(text, False))
        self.assertIsNotNone(cg.install_files_refusal(forms[0].replace("~/.claude/hooks/ah.py", "harness/hooks/ah.py"), True))

    def test_a_direct_write_into_the_hooks_directory_stays_refused_even_for_main(self):  # goodqa#15913 NEG-6
        for text in ("cp /tmp/x/command_guard.py ~/.claude/hooks/command_guard.py",
                     "cp /tmp/x/command_guard.py $HOME/.claude/hooks/command_guard.py",
                     "mv /tmp/x/command_guard_hook.py ~/.claude/hooks/command_guard_hook.py",
                     "cat /tmp/x/ah.py > ~/.claude/hooks/ah.py",
                     "tee ~/.claude/hooks/command_guard.py < /tmp/x/command_guard.py",
                     "cp /tmp/x/command_guard.py ~/.codex/agent-harness/command_guard.py"):
            for main in (True, False):
                with self.subTest(text, main=main):
                    self.assertEqual(hook(text, main)[0], 2, text)

    def test_a_script_named_ah_earlier_on_path_does_not_pass(self):  # AC-9, NEG-11
        text = 'ah install-files --host t2-dev --from-ref %s --file ah.py --ticket "GoodQA a#1"' % ("a" * 40)
        with mock.patch.object(cg.shutil, "which", return_value="/tmp/evil/ah"):
            self.assertIn("bare `ah`", cg.install_files_refusal(text, True))
        installed = os.path.join(HOME, ".claude", "hooks", "ah.py")
        with mock.patch.object(cg.shutil, "which", return_value=installed):
            self.assertIsNone(cg.install_files_refusal(text, True))

    def test_everyday_commands_that_only_mention_the_names_are_not_refused(self):  # AC-9
        for text in ("git add harness/hooks/ah_install.py", "git commit -m 'feat(install-files): add it'", "cat harness/hooks/ah_install.py",
                     "python3 -B -m unittest tests.test_ah_install", "python3 ~/.claude/hooks/spec_flow.py lint notes/goodqa-15742/spec.md",
                     'python3 ~/.claude/hooks/ah.py ticket comment "GoodQA goodqa#15742" --body "ah install-files plan"'):
            with self.subTest(text):
                self.assertIsNone(cg.install_files_refusal(text, False), text)
                self.assertEqual(hook(text, False)[0], 0)

    def test_the_guard_is_accident_prevention_and_says_so(self):
        self.assertIn("ACCIDENT PREVENTION", cg.install_files_refusal.__doc__)
        self.assertIn("NOT AN ACCESS CONTROL", cg.install_files_refusal.__doc__)

    def test_main_is_decided_from_the_hook_payload_not_an_environment_variable(self):  # AC-9
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": GOOD}}).encode()
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_SESSION_ID": "x", "AH_MAIN": "1", "AH_IS_MAIN": "1"}), \
                contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            code = cg.hook_main("exit2", stdin_bytes=payload, marker=False)  # the real caller_identity: the payload proves nothing
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
