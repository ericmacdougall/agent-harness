"""The Mac guard allows `ah install-files` only in its exact literal form and only for main (goodqa#15742, AC-9), and fails
closed on every other text that may run it (goodqa#15913 final round: an allowlist, not a search for the command).
ACCIDENT PREVENTION, not an access control: the guard sees command text only."""
import contextlib
import io
import json
import os
import shlex
import sys
import time
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
LOCAL = GOOD.replace("--host t2-dev", "--host local")
SCRIPT = "~/.claude/hooks/ah.py"
NAMED = "names install-files or ah_install"  # step 2: the name is visible, the whole text is not an allowed shape
HIDDEN = "not a literal word"  # step 3: an ah entry that may run with a built subcommand (or from a variable or alias)
SPLICED = "spelled with quotes, escapes, braces or expansions"  # step 3: the script name itself is spliced
INLINE = "inline code of a second program"  # step 3: ah.py inside code another program runs
REASONS = (NAMED, HIDDEN, SPLICED, INLINE)


def hook(command, main):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}).encode()
    err = io.StringIO()
    with mock.patch.object(caller_identity, "is_main", return_value=main), contextlib.redirect_stderr(err), \
            contextlib.redirect_stdout(io.StringIO()):
        code = cg.hook_main("exit2", stdin_bytes=payload, marker=False)
    return code, err.getvalue()


class Forms(unittest.TestCase):
    def assertRefusedForBoth(self, text, reasons=REASONS):
        for main in (True, False):
            with self.subTest(text[:90], main=main):
                reason = cg.install_files_refusal(text, main)
                self.assertIsNotNone(reason, text)
                self.assertTrue(any(r in reason for r in reasons), reason)  # refused for this, not only for being a sub-agent
                code, message = hook(text, main)
                self.assertEqual(code, 2, message)
                self.assertIn("log_delete/install-files", message)

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
            "worktree copy with -I": 'python3 -I harness/hooks/ah.py install-files --host t2-dev --file ah.py',  # not caught by -I alone
            "Codex copy with -I": 'python3 -I ~/.codex/agent-harness/ah.py install-files --host local --file ah.py',
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
            "an interpreter outside PATH": GOOD.replace("python3 -I", "/tmp/evil/python3 -I"),
            "a host outside the closed set": GOOD.replace("--host t2-dev", "--host mac"),
            "a short sha": GOOD.replace("a" * 40, "a" * 12),
            "a file path, not a name": GOOD.replace("--file ah.py", "--file harness/hooks/ah.py"),
            "an unquoted ticket": GOOD.replace('"GoodQA goodqa#15742"', "GoodQA-goodqa#15742"),
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
        for text in (GOOD + " > out.json", GOOD + " > out.json 2>&1", GOOD + " 2>/tmp/err.txt", GOOD + " --allow-older"):
            with self.subTest(text[-30:]):
                self.assertIsNone(cg.install_files_refusal(text, True), text)
        for viewer in ("grep -rn install-files harness/", "git log -S install-files", "sed -n 1,5p harness/hooks/ah_install.py",
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

    def test_a_script_named_ah_earlier_on_path_does_not_pass(self):  # AC-9, NEG-11; goodqa#15913 NEG-17: a bare ah never passes
        text = 'ah install-files --host t2-dev --from-ref %s --file ah.py --ticket "GoodQA a#1"' % ("a" * 40)
        installed = os.path.join(HOME, ".claude", "hooks", "ah.py")
        for found in ("/tmp/evil/ah", installed):  # even one that resolves to the installed copy: its flags are not pinned
            with self.subTest(found), mock.patch.object(cg.shutil, "which", return_value=found):
                self.assertIn(NAMED, cg.install_files_refusal(text, True))
                self.assertIn(NAMED, cg.install_files_refusal("/usr/local/bin/" + text, True))
                self.assertEqual(hook(text, True)[0], 2)

    def test_environment_wrappers_shells_and_a_missing_dash_i_are_refused_for_main_too(self):  # goodqa#15913 AC-5, NEG-17
        bad = {
            "PYTHONPATH prefix": "PYTHONPATH=/tmp/evil " + LOCAL,
            "HOME prefix": "HOME=/tmp/x " + LOCAL,
            "env -i HOME": "env -i HOME=/tmp/x " + LOCAL,
            "env wrapper": "env " + LOCAL,
            "sudo": "sudo " + LOCAL,
            "nohup": "nohup " + LOCAL,
            "time": "time " + LOCAL,
            "xargs": "echo | xargs " + LOCAL,
            "missing -I": LOCAL.replace("python3 -I", "python3"),
            "missing -I with -B": LOCAL.replace("python3 -I", "python3 -B"),
            "-I after the script": LOCAL.replace("python3 -I ~/.claude/hooks/ah.py", "python3 ~/.claude/hooks/ah.py -I"),
            "bare ah": LOCAL.replace("python3 -I ~/.claude/hooks/ah.py", "ah"),
            "bash -c": "bash -c '%s'" % LOCAL.replace('"', ""),
            "sh -c": 'sh -c "%s"' % LOCAL.replace('"GoodQA goodqa#15742"', "'GoodQA goodqa#15742'"),
            "zsh -lc": "zsh -lc '%s'" % LOCAL.replace('"', ""),
            "export HOME first": "export HOME=/tmp/x; " + LOCAL,
            "assignment segment first": "HOME=/tmp/x; " + LOCAL,
            "PATH assignment first": "PATH=/tmp/evil:$PATH && " + LOCAL,
            "unset first": "unset HOME; " + LOCAL,
            "source first": "source /tmp/x/env.sh && " + LOCAL,
            "dot first": ". /tmp/x/env.sh && " + LOCAL,
            "function named python3": "python3() { /tmp/evil/python3 \"$@\"; }; " + LOCAL,
            "hash -p": "hash -p /tmp/evil/python3 python3; " + LOCAL,
            "cd first": "cd ~ && " + LOCAL,
            "assignment segment after it": LOCAL + "; HOME=/tmp/x",
        }
        for label, text in bad.items():
            with self.subTest(label):
                self.assertIsNotNone(cg.install_files_refusal(text, True), text)
                code, message = hook(text, True)
                self.assertEqual(code, 2, message)
                self.assertIn("install-files", message)
        for text in (LOCAL, LOCAL.replace("python3 -I", "python3 -B -I"), LOCAL.replace("python3 -I", "python3 -I -B"),
                     LOCAL + " > /tmp/out.json 2>&1"):  # the plain form stays allowed for main
            with self.subTest(text[:50]):
                self.assertIsNone(cg.install_files_refusal(text, True), text)
                self.assertEqual(hook(text, True)[0], 0)
        # goodqa#15913 final round: a viewer that names install-files must itself be a plain line; behind a prefix,
        # wrapper or an earlier command it is refused too (fail closed: the rule does not judge what an earlier part does)
        for viewer in ("FOO=1 git commit -m 'install-files: plain form only'", "env grep -rn install-files harness/",
                       "export X=1; grep install-files notes/x.md", "time git log -S install-files"):
            with self.subTest(viewer):
                self.assertIn(NAMED, cg.install_files_refusal(viewer, False))
        for viewer in ("git commit -m 'install-files: plain form only'", "grep -rn install-files harness/",
                       "grep install-files notes/x.md", "git log -S install-files"):
            with self.subTest(viewer):
                self.assertIsNone(cg.install_files_refusal(viewer, False), viewer)

    def test_wrapped_or_prefixed_environment_changers_and_anything_before_it_are_refused_for_main_and_sub_agents(self):  # NEG-27
        bad = {
            "builtin export": "builtin export HOME=/tmp/x; " + LOCAL,
            "command export": "command export HOME=/tmp/x; " + LOCAL,
            "noglob export": "noglob export HOME=/tmp/x; " + LOCAL,
            "nested builtin command": "builtin command export HOME=/tmp/x; " + LOCAL,
            "nested command builtin": "command builtin export HOME=/tmp/x && " + LOCAL,
            "builtin source": "builtin source /tmp/x/env.sh && " + LOCAL,
            "command dot": "command . /tmp/x/env.sh && " + LOCAL,
            "assignment then export": "FOO=1 export HOME=/tmp/x; " + LOCAL,
            "assignment then builtin source": "FOO=1 builtin source /tmp/x/env.sh; " + LOCAL,
            "builtin typeset -x": "builtin typeset -x HOME=/tmp/x; " + LOCAL,
            "command declare -x": "command declare -x HOME=/tmp/x; " + LOCAL,
            "builtin cd": "builtin cd /tmp/x && " + LOCAL,
            "pushd": "pushd /tmp/x && " + LOCAL,
            "setopt": "setopt no_rcs; " + LOCAL,
            "builtin eval": "builtin eval 'export HOME=/tmp/x'; " + LOCAL,
            "builtin alias": "builtin alias python3=/tmp/evil/python3; " + LOCAL,
            "grouped builtin export": "{ builtin export HOME=/tmp/x; }; " + LOCAL,
            "if then builtin export": "if true; then builtin export HOME=/tmp/x; fi; " + LOCAL,
            "an assigning expansion in an inert command first": "echo ${HOME::=/tmp/x}; " + LOCAL,
            "true first": "true && " + LOCAL,
            "an assigning expansion in a flag": LOCAL.replace('"GoodQA goodqa#15742"', '"${HOME::=/tmp/x}GoodQA a#1"'),
            "a backquote in a flag": LOCAL.replace('"GoodQA goodqa#15742"', '"`touch /tmp/x`GoodQA a#1"'),
            "builtin export after it": LOCAL + "; builtin export HOME=/tmp/x",
            "assignment and command export after it": LOCAL + "; FOO=1 command export X=1",
            "grouped export after it": LOCAL + "; { export X=1; }",
            "printf -v after it": LOCAL + "; printf -v HOME %s /tmp/x",
            "subshell export on a later line": LOCAL + "\n(export HOME=/tmp/x)",
        }
        for label, text in bad.items():
            self.assertRefusedForBoth(text, (NAMED,))
        for text in (LOCAL, GOOD.replace("~", "$HOME")):  # still allowed for main
            with self.subTest(text[-40:]):
                self.assertIsNone(cg.install_files_refusal(text, True), text)
                self.assertEqual(hook(text, True)[0], 0)
        for viewer in ("cd /tmp && grep -rn install-files .", "grep -c install-files notes/x.md | head -3"):  # plain viewers pass
            with self.subTest(viewer):
                self.assertIsNone(cg.install_files_refusal(viewer, False), viewer)

    def test_an_expansion_in_a_redirect_and_any_pipe_after_the_install_line_are_refused(self):  # AC-5, NEG-27
        for text in (LOCAL + " > $HOME/x", LOCAL + " > ${HOME::=/tmp/x}", LOCAL + " 2> `echo /tmp/x`",
                     LOCAL + " | tee /tmp/out.txt", LOCAL + " 2>&1 | tee /tmp/out.txt", LOCAL + " | tee $HOME/x",
                     LOCAL + " 2>&1 | head -5"):
            self.assertRefusedForBoth(text, (NAMED,))

    def test_everyday_commands_that_only_mention_the_names_are_not_refused(self):  # AC-9
        for text in ("git add harness/hooks/ah_install.py", "git commit -m 'feat(install-files): add it'", "cat harness/hooks/ah_install.py",
                     "python3 -B -m unittest tests.test_ah_install", "python3 ~/.claude/hooks/spec_flow.py lint notes/goodqa-15742/spec.md",
                     'python3 ~/.claude/hooks/ah.py ticket comment "GoodQA goodqa#15742" --body "ah install-files plan"',
                     "python3 -B -m unittest tests.test_ah_install tests.test_command_guard_install_files 2>&1 | tail -3",
                     "git push origin afef-install-files-local", "gh pr view 233 --json headRefName -q .headRefName"):
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


class FailClosed(unittest.TestCase):
    """goodqa#15913 final round (NEG-29): every bypass family the PR reviews found (r6 F1 wrapped builtins, r7 F1 line
    continuations, the round-8 owner's $'..' splices) and the shapes around them are refused for main and for a
    sub-agent, through install_files_refusal and the full hook, for a reason of the rule itself."""

    assertRefusedForBoth = Forms.assertRefusedForBoth

    def test_line_continuations_and_multiline_input_are_refused(self):  # r7-pr233 F1
        for text in (LOCAL.replace("install-files", "install-\\\nfiles"),
                     "HOME=/tmp/x " + LOCAL.replace("install-files", "install-\\\nfiles"),
                     LOCAL.replace("install-files", "install-\\\nfiles").replace("python3 -I", "python3"),
                     LOCAL.replace("install-files", "ins\\\ntall-files"),
                     LOCAL.replace(" --host", " \\\n--host"),
                     LOCAL.replace("python3 -I ~/.claude/hooks/ah.py", "python3 -I ~/.claude/hooks/ah.p\\\ny"),
                     LOCAL + "\n", "\n" + LOCAL, "true\n" + LOCAL, LOCAL + "\nexport X=1", LOCAL + "\r\ntrue",
                     # a commit heredoc whose body closes early and runs more lines
                     "git commit -F - <<'E'\nfix install-files\nE\nHOME=/tmp/x " + LOCAL + "\nE"):
            self.assertRefusedForBoth(text)

    def test_long_or_crowded_texts_are_refused_and_the_rule_stays_fast(self):
        # a hook timeout is only a warning (fail open), so the rule's work must stay far inside the hook's time limit
        long_text = "grep install-files " + "a " * cg.INSTALL_TEXT_MAX
        self.assertIn("at most %d characters" % cg.INSTALL_TEXT_MAX, cg.install_files_refusal(long_text, True))
        self.assertIn("more than %d times" % cg.INSTALL_ENTRY_MAX,
                      cg.install_files_refusal("cat" + " ah.py" * (cg.INSTALL_ENTRY_MAX + 1), True))
        self.assertIsNone(cg.install_files_refusal("cat" + " ah.py" * cg.INSTALL_ENTRY_MAX, True))
        entry = SCRIPT + ' "$S"; '
        slow = {"interpreter words": entry + "sh " * 3000, "slash run": entry + "/" * 9000, "path words": entry + "x/" * 5000,
                "pipe slash runs": entry + "|/" * 5000, "punctuation run": entry + "%" * 9000, "eval words": entry + "eval x " * 2000,
                "heredoc markers": entry + "\n" + "python3 <<x\n" * 1000, "entries in one segment": "cat " + "ah.py " * 2000,
                "entries after a long word": "cat " + "a" * 7000 + " ah.py" * cg.INSTALL_ENTRY_MAX}
        for name, text in slow.items():
            with self.subTest(name):
                start = time.monotonic()
                cg.install_files_refusal(text[:cg.INSTALL_TEXT_MAX], True)
                self.assertLess(time.monotonic() - start, 1.0)  # quadratic regexes took 2 to 16 s here

    def test_separators_before_or_after_the_install_line_are_refused(self):
        for sep in ("; ", " && ", " || ", " & ", " | ", ";", "&&", " |& "):
            self.assertRefusedForBoth("true" + sep + LOCAL, (NAMED,))
            self.assertRefusedForBoth(LOCAL + sep + "true", (NAMED,))

    def test_dollar_quote_and_other_quote_splices_of_the_subcommand_are_refused(self):  # round-8 owner probe
        for word in ("install-file$''s", "$'install-files'", '$"install-files"', "ins$'\\x74'all-files", "install-$'\\146'iles",
                     "$'\\x69nstall-files'", "'install-files'", '"install-files"', "install\\-files", "i\\nstall-files",
                     "install-{files}", "{install-files,}", "install-{x,files}", "ins{x,t}all-files", "install-fil?s",
                     "install-fil[e]s", "install-fil*", "inst''all-files", "install-file\"\"s"):
            self.assertRefusedForBoth(LOCAL.replace("install-files", word))

    def test_a_spliced_install_name_is_refused_without_any_ah_py_in_the_text(self):
        # a bare ah on PATH or a link to ah.py: only the spliced subcommand shows, so the trigger must see the splice itself
        for text in ("ah install-file$''s --host local --dry-run", "/tmp/link.py install-$'f'iles --host local",
                     "python3 -I /tmp/x.py ins$'t'all-files --host local", "ah $\"install-files\" --host local"):
            self.assertRefusedForBoth(text, (NAMED,))

    def test_substitutions_that_build_the_subcommand_are_refused(self):
        for word in ("$(echo install-files)", "`echo install-files`", '"$(printf install-files)"', "${X:-install-files}",
                     "$(printf 'install-%s' files)", '"$S"', "$S", "${S}", "$1", '"$@"', "$(cat /tmp/sub)", "<(echo x)",
                     "$((0))install-files"):
            self.assertRefusedForBoth(LOCAL.replace("install-files", word))
        for text in ("S=install-files; " + LOCAL.replace("install-files", '"$S"'),
                     "python3 -I %s \"$S\" --host local --dry-run" % SCRIPT,
                     "python3 -I %s $'\\x69nstall-files' --host local" % SCRIPT,
                     "python3 -I %s --text \"$S\" --host local" % SCRIPT,
                     "python3 -I %s -- install-files --host local" % SCRIPT,
                     "python3 -I %s @/tmp/args" % SCRIPT,
                     "python3 -I %s < /tmp/args" % SCRIPT,
                     "cat /tmp/args | xargs python3 -I %s" % SCRIPT,
                     "xargs -a /tmp/args python3 -I %s" % SCRIPT,
                     "find /tmp -name x -exec python3 -I %s {} +" % SCRIPT,
                     "timeout -s KILL 60 python3 -I %s \"$S\"" % SCRIPT,
                     "python3 -W ignore %s \"$S\"" % SCRIPT,
                     "python3 -m cProfile %s \"$S\"" % SCRIPT,
                     "A=%s; python3 -I $A \"$S\"" % SCRIPT,
                     "A=%s\npython3 -I $A ticket get 1" % SCRIPT,
                     "git -c alias.x='!python3 -I %s' x" % SCRIPT,
                     'git commit -m "fix install-files $(touch /tmp/x)"', 'grep -n "install-files `touch /tmp/x`" notes/x.md'):
            self.assertRefusedForBoth(text)

    def test_a_spliced_or_case_changed_script_name_is_refused(self):
        for script in ('~/.claude/hooks/a""h.py', "~/.claude/hooks/a''h.py", "~/.claude/hooks/ah.p\\y", "~/.claude/hooks/a{h,}.py",
                       "~/.claude/hooks/{ah.py,}", "~/.claude/hooks/a$'h'.py", "~/.claude/hooks/AH.PY", "~/.claude/HOOKS/Ah.py"):
            self.assertRefusedForBoth('python3 -I %s "$S" --host local' % script)
            self.assertRefusedForBoth(LOCAL.replace(SCRIPT, script))

    def test_environment_prefixes_and_wrappers_are_refused(self):
        for prefix in ("HOME=/tmp/x ", "PYTHONPATH=/tmp/evil ", "PATH=/tmp/evil ", "env ", "env -i ", "env -u HOME ", "exec ",
                       "command ", "builtin ", "nohup ", "nice -n 5 ", "caffeinate -i ", "sudo -E ", "stdbuf -o0 ", "noglob ",
                       "- ", "! ", "{ ", "( ", "time ", "timeout 60 "):
            self.assertRefusedForBoth(prefix + LOCAL, (NAMED,))
            self.assertRefusedForBoth(prefix + 'python3 -I %s "$S" --host local' % SCRIPT, (HIDDEN, NAMED))

    def test_a_second_interpreter_that_runs_ah_is_refused(self):
        for text in ("python3 -c \"import subprocess; subprocess.run(['python3', '-I', '%s/.claude/hooks/ah.py', 'install-' + "
                     "'files', '--host', 'local'])\"" % HOME,
                     "python3 -c \"import os; os.execvp('python3', ['python3', '%s/.claude/hooks/ah.py', 'install' + '-files'])\"" % HOME,
                     "python3 -c 'import runpy, sys; sys.argv = sys.argv[1:]; runpy.run_path(sys.argv[0], run_name=\"__main__\")' %s \"$S\"" % SCRIPT,
                     "python3 - <<'EOF'\nimport subprocess\nsubprocess.run(['python3', '%s/.claude/hooks/ah.py', 'install-' + 'files'])\nEOF" % HOME,
                     "python3 <<< \"import os; os.system('python3 ~/.claude/hooks/ah.py ' + 'install' + '-files')\"",
                     "echo \"import os; os.system('python3 ~/.claude/hooks/ah.py ' + 'install' + '-files')\" | python3",
                     "echo 'python3 ~/.claude/hooks/ah.py \"$1\"' | sh -s x",
                     "perl -e 'exec \"python3\", \"%s/.claude/hooks/ah.py\", \"install-\" . \"files\"'" % HOME,
                     "ruby -e 'exec(\"python3\", \"%s/.claude/hooks/ah.py\", ARGV[0])' x" % HOME,
                     "node -e 'require(\"child_process\").execFileSync(\"python3\", [\"%s/.claude/hooks/ah.py\", process.argv[1]])' x" % HOME,
                     "osascript -e 'do shell script \"python3 ~/.claude/hooks/ah.py \" & \"x\"'",
                     "awk 'BEGIN { system(\"python3 ~/.claude/hooks/ah.py \" v) }' v=x",
                     "bash -c 'python3 -I ~/.claude/hooks/ah.py \"$0\"' \"$S\"",
                     "zsh -c 'python3 -I ~/.claude/hooks/ah.py \"$1\"' _ \"$S\"",
                     "eval \"python3 -I ~/.claude/hooks/ah.py $S\"",
                     "eval 'python3 -I ~/.claude/hooks/a''h.py' \"$S\""):
            self.assertRefusedForBoth(text)

    def test_every_one_character_insertion_into_the_line_is_refused_unless_it_cannot_run_install_files(self):
        """Insert each printable ASCII character, tab and newline at every position of the sanctioned line: a result the
        guard allows must still be the sanctioned line (its own grammar), or an expansion-free text (no `$`, backquote,
        backslash, brace, glob or line break) in which no shell word is install-files (shlex with the shell's operator
        characters, independently of the guard's views)."""
        meta = set("$`\\*?[]{}\n\r")
        allowed_odd = []
        for pos in range(len(LOCAL) + 1):
            for code in list(range(32, 127)) + [9, 10]:
                text = LOCAL[:pos] + chr(code) + LOCAL[pos:]
                if cg.install_files_refusal(text, True) is not None:
                    continue
                line = cg._install_files_line(HOME).fullmatch(text)
                if line and "I" in line.group(1):
                    self.assertIsNotNone(cg.install_files_refusal(text, False))  # still main only
                    continue
                try:
                    lex = shlex.shlex(text, posix=True, punctuation_chars=True)
                    lex.whitespace_split = True
                    words = list(lex)
                except ValueError:
                    words = None
                if words is None or "install-files" in words or (set(text) - set(LOCAL)) & meta:
                    allowed_odd.append(text)
        self.assertEqual(allowed_odd, [])

    def test_a_list_command_and_a_second_command_field_are_judged_whole(self):
        for tool_input in ({"command": ["python3", "-I", HOME + "/.claude/hooks/ah.py", "install-\nfiles", "--host", "local"]},
                           {"command": "true", "cmd": LOCAL}, {"command": LOCAL, "cmd": "export HOME=/tmp/x"}):
            for main in (True, False):
                with self.subTest(str(tool_input)[:60], main=main):
                    payload = json.dumps({"tool_name": "Bash", "tool_input": tool_input}).encode()
                    with mock.patch.object(caller_identity, "is_main", return_value=main), \
                            contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(cg.hook_main("exit2", stdin_bytes=payload, marker=False), 2)

    def test_everyday_ah_calls_and_viewers_still_pass(self):  # AC-9: measured against this session's real commands
        for text in ("python3 ~/.claude/hooks/ah.py status --since 2h",
                     "python3 -I ~/.claude/hooks/ah.py user-msg --recent 3 2>&1 | tail -6",
                     "python3 ~/.claude/hooks/ah.py --text owners 2>/dev/null | grep -E 'DROPPED|SILENT' | head -14",
                     "cd ~ && timeout 60 python3 ~/.claude/hooks/ah.py ticket get \"GoodQA goodqa#15914\" 2>&1 | head -40",
                     "python3 ~/.claude/hooks/ah.py ticket get 14669 2>&1 | python3 -c \"import json,sys; print(json.load(sys.stdin))\"",
                     "python3 ~/.claude/hooks/ah.py ticket comment 'GoodQA goodqa#15913' --body \"$(cat /tmp/body.md)\"",
                     "cd ~/.claude/hooks && python3 ah.py task dispose --agent a1 --kind waiting --ref \"GoodQA goodqa#1\" --until 2026-11-14T00:00:00Z",
                     "python3 ~/.claude/hooks/ah.py kill --help 2>&1 | head -40", "python3 ~/.claude/hooks/ah.py --help",
                     "sed -n 625,690p harness/hooks/ah.py", "grep -n 'def main' harness/hooks/ah.py | head",
                     "git diff -- harness/hooks/ah.py", "wc -l harness/hooks/ah.py harness/hooks/command_guard.py",
                     "shasum -a 256 ~/.claude/hooks/ah.py", "python3 -m py_compile x.py && cat ah.py | head -1",
                     "python3 ~/.claude/hooks/wal_note.py --wal /tmp/w.jsonl --event check --note 'ah.py status showed 3 owners'"):
            with self.subTest(text):
                self.assertIsNone(cg.install_files_refusal(text, False), text)
                self.assertEqual(hook(text, False)[0], 0)


if __name__ == "__main__":
    unittest.main()
