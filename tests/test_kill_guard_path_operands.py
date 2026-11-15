"""kill_guard [script-kill]: a kill word that appears only inside a path-shaped operand of an interpreter is a file
name, not signalling (GoodQA goodqa#16124). Owners must run apps/api/test/qac-kill-switch-ceiling.test.ts through
`python3 lanes/pgpool.py run ... -- dbtest-any.sh`, which the rule refused because "-kill-" matched inside the path.
Interpreter code that signals, a script whose own name is a kill word, and commands a runner executes stay refused.
Nothing here executes a command; every row is only analysed by kill_guard.decide."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import kill_guard as kg  # noqa: E402

TEST_TS = "test/qac-kill-switch-ceiling.test.ts"
PGPOOL = "python3 lanes/pgpool.py run --mode server -- "

# The defect as reported, with the elided values filled in from real owner runs (pgpool --mode server).
REPORTED = ("ssh t2-dev 'cd ~/repos/harness && " + PGPOOL
            + "dbtest-any.sh ~/wt/qac-16124 ~/wt/qac-16124.log " + TEST_TS + "'")

ALLOW = [
    REPORTED,
    PGPOOL + "dbtest-any.sh /srv/wt /srv/wt.log " + TEST_TS,
    PGPOOL + "dbtest-any.sh /srv/wt /srv/wt.log tests/test-kill-switch-ceiling.py",  # the same in a .py path
    "ssh t2-dev 'cd ~/repos/harness && " + PGPOOL + "dbtest-any.sh /srv/wt /srv/wt.log tests/qac-kill-switch.py'",
    PGPOOL + "npx vitest run " + TEST_TS + " test/oauth.test.ts",
    PGPOOL + "pnpm --filter @bugtracker/api exec vitest run " + TEST_TS,
    "python3 -m pytest tests/test_kill_switch.py",
    "python3 -I lanes/pgpool.py run -- dbtest-any.sh /srv/wt /srv/wt.log apps/api/" + TEST_TS,
    "node scripts/run.mjs apps/api/" + TEST_TS,
    "python3 tools/lint.py src/kill-switch.go src/kill_switch.rs web/kill-switch.tsx web/kill-switch.js",
    "python3 tools/report.py kill-switch-notes/README",  # the word only in a directory name
]

BLOCK = [
    # interpreter code that really signals, with and without path operands beside it
    "python3 -c \"import os; os.kill(4242, 9)\"",
    "python3 -c \"import os; os.kill(4242, 9)\" tests/x.py",
    "python3 -c \"import os; os.system('pkill -f x')\" a/b.py",
    "node -e \"process.kill(4242)\"",
    "node -e \"process.kill(4242)\" " + TEST_TS,
    "perl -e 'kill 9, 4242'",
    "perl -le 'kill 9, 4242' a/b.py",
    "ruby -e 'Process.kill(9, 4242)' a/b.rb",
    # a script whose own name is the kill word: the program operand is never exempt
    "python3 kill-all.sh",
    "python3 scripts/kill-all.sh",
    "python3 scripts/kill_all.py",
    "python3 -u tools/kill-all.py",
    "python3 -X dev tools/kill-all.py",
    "python3 -W ignore tools/kill-all.py",
    "node ./kill-all.mjs",
    "node -r ./preload.js ./kill-all.mjs",
    # pkill hidden in a shell
    "bash -c 'pkill -f vite'",
    PGPOOL + "bash -c 'pkill -f vite'",
    # commands a runner executes after `--`, or a nested interpreter's script
    "python3 runner.py -- kill 4242",
    "python3 runner.py -- pkill -f vite",
    "python3 runner.py -- tools/kill-all.py",
    "python3 runner.py -- python3 tools/kill-all.py",
    "python3 runner.py -- node kill-all.mjs",
    "python3 runner.py -- env python3 -u tools/kill-all.py",
    # review of 8f4788a: a wrapper's command word is what runs, and a subcommand is not the program
    "python3 runner.py -- env tools/kill-all.py",
    "python3 runner.py -- env X=1 tools/kill-all.py",
    "python3 runner.py -- timeout 5 ./kill-all.py",
    "python3 runner.py -- uv run tools/kill-all.py",
    "python3 runner.py -- sudo -u bob tools/kill-all.py",
    PGPOOL + "pnpm exec tools/kill-all.ts",
    "python3 runner.py env tools/kill-all.py",
    "deno run kill-all.ts",
    "deno run tools/kill-all.ts",
    "bun run kill-all.ts",
    "bun x tools/kill-all.ts",
    "node inspect kill-all.js",
    # an argument that is a kill tool or kill text, not a file name
    "python3 x.py --then pkill",
    "python3 run.py kill",
    "python3 runner.py /usr/bin/pkill -f vite",
    "python3 runner.py bin/kill 4242",
    "python3 runner.py scripts/kill-all.sh",
    "python3 runner.py 'kill 4242'",
    "python3 runner.py 'tests/kill-switch.py; pkill -f x'",
    "python3 runner.py --script=tests/kill-all.py",
    "python3 runner.py --script tests/kill-all.py",
    # quoting, substitution and globs are not plain path words
    "python3 runner.py $K/kill-all.py",
    "python3 runner.py tests/kill-*.py",
    "python3 runner.py 'tests/kill-all.py'",
    # a here-document body is code, whatever the operands are
    "python3 - " + TEST_TS + " <<'EOF'\nimport os\nos.kill(4242, 9)\nEOF",
]

# Refusals that reach the path predicate itself (the structural rules let them through), so widening the predicate
# to "any token" must flip them. Kept separate so the mutation check below cannot pass vacuously.
PREDICATE_REFUSALS = [
    "python3 run.py kill",
    "python3 runner.py /usr/bin/pkill -f vite",
    "python3 runner.py scripts/kill-all.sh",
    "python3 runner.py 'kill 4242'",
]


def verdict(cmd):
    with tempfile.TemporaryDirectory() as tmp:
        return kg.decide(cmd, cwd=tmp, policy=kg.load_policy(), home=tmp)[:2]


def refusals_that_pass(rows=BLOCK):
    """The refusal rows the guard currently lets through; the refusal test requires none."""
    return [cmd for cmd in rows if verdict(cmd)[0] != "block"]


class PathOperands(unittest.TestCase):
    def test_control_policy_pattern_still_matches_the_test_path(self):
        """Control: the policy pattern itself still matches the path (the fix is in where it is applied, not a
        narrowed pattern), so ALLOW below passes because of the operand rule. On f26cf1b every ALLOW row was
        refused as [script-kill]."""
        self.assertIsNotNone(kg.re.search(kg.load_policy()['script_kill_pattern'], TEST_TS))

    def test_kill_word_inside_a_path_operand_is_allowed(self):
        for cmd in ALLOW:
            with self.subTest(cmd=cmd):
                self.assertEqual(verdict(cmd), ("allow", ""))

    def test_real_signalling_and_kill_scripts_stay_refused(self):
        self.assertEqual(refusals_that_pass(), [])

    def test_interpreter_refusals_keep_the_script_kill_rule(self):
        for cmd in ("python3 -c \"import os; os.kill(4242, 9)\" tests/x.py", "python3 scripts/kill-all.sh",
                    "python3 runner.py -- tools/kill-all.py", "python3 runner.py /usr/bin/pkill -f vite"):
            with self.subTest(cmd=cmd):
                self.assertEqual(verdict(cmd), ("block", "script-kill"))

    def test_predicate_refusals_are_in_the_refusal_set(self):
        self.assertTrue(set(PREDICATE_REFUSALS) <= set(BLOCK))

    def test_mutation_widening_the_exemption_to_any_token_breaks_a_refusal(self):
        """Mutation check: if the path predicate accepted every operand, refusals must start passing. This proves the
        predicate (not some other rule) is what keeps them refused, so the refusal tests are not vacuous."""
        self.assertEqual(refusals_that_pass(PREDICATE_REFUSALS), [])  # unmutated: all refused
        with mock.patch.object(kg, "path_operand", lambda word, kill_re: True):
            self.assertEqual(refusals_that_pass(PREDICATE_REFUSALS), PREDICATE_REFUSALS)
            self.assertNotEqual(refusals_that_pass(), [])  # the refusal test above would now fail
        self.assertEqual(refusals_that_pass(PREDICATE_REFUSALS), [])  # the patch is undone

    def test_predicate_shape(self):
        kill_re = kg.re.compile(kg.load_policy()['script_kill_pattern'])
        cg = kg._import_base()

        def word(text):
            w = cg.Word()
            w.alts, w.raw = [text], text
            return w

        self.assertTrue(kg.path_operand(word(TEST_TS), kill_re))
        self.assertTrue(kg.path_operand(word("qac-kill-switch-ceiling.test.ts"), kill_re))
        self.assertTrue(kg.path_operand(word("tests/kill_switch.PY"), kill_re))
        self.assertTrue(kg.path_operand(word("kill-dir/run"), kill_re))
        for text in ("kill", "pkill", "/usr/bin/pkill", "bin/kill", "scripts/kill-all.sh", "kill-all.sh",
                     "kill 4242", "-kill-x.ts", "--script=tests/kill-all.py", "a;kill.py", "a/kill$x.py", ""):
            with self.subTest(text=text):
                self.assertFalse(kg.path_operand(word(text), kill_re))


if __name__ == "__main__":
    unittest.main()
