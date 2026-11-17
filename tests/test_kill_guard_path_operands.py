"""kill_guard [script-kill]: a kill word that appears only inside a test path of an exact test-runner line is a file
name, not signalling (GoodQA goodqa#16124). Owners must run apps/api/test/qac-kill-switch-ceiling.test.ts through
`python3 lanes/pgpool.py run ... -- dbtest-any.sh`, which the rule refused because "-kill-" matched inside the path.
PR 265 rescue: the exemption is an allowlist (kill_guard.test_runner_exemptions). Only the whole-command grammars
G1 (pgpool), G2 (python -m pytest) and G3 (node --test) exempt anything; every other command, including any wrapper,
runner, option or subcommand the grammars do not name, is scanned in full.
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

# The QAC owner's real run-kit line (given by main): pgpool run options, then the dbtest-any.sh that lives outside
# the repo on t2-dev, a worktree, a log name, one test path and an optional `-t NAME`.
QAC_PGPOOL = "python3 lanes/pgpool.py run --job 7 --lane qac-b1 --ttl 1500 --mode server -- "
QAC_DBTEST = QAC_PGPOOL + "~/qacp-work/fable-b1/dbtest-any.sh /home/eric/repos/bt-qac-gates-main qac-7.log "
QAC_LINE = QAC_DBTEST + TEST_TS
QAC_LINE_T = QAC_LINE + ' -t "caps the ceiling"'

ALLOW = [
    QAC_LINE,
    QAC_LINE_T,
    "ssh t2-dev '" + QAC_LINE + "'",  # the ssh remote command is re-lexed into the same scan
    "ssh t2-dev 'cd ~/repos/harness && " + QAC_LINE_T + "'",
    REPORTED,
    PGPOOL + "dbtest-any.sh /srv/wt /srv/wt.log " + TEST_TS,
    PGPOOL + "dbtest-any.sh /srv/wt /srv/wt.log tests/test-kill-switch-ceiling.py",  # the same in a .py path
    "ssh t2-dev 'cd ~/repos/harness && " + PGPOOL + "dbtest-any.sh /srv/wt /srv/wt.log tests/test-kill-switch.py'",
    PGPOOL + "npx vitest run " + TEST_TS + " test/oauth.test.ts",
    PGPOOL + "npx -y vitest run " + TEST_TS,
    PGPOOL + "pnpm --filter @bugtracker/api exec vitest run " + TEST_TS,
    "python3 -m pytest tests/test_kill_switch.py",
    "python3 -I lanes/pgpool.py run -- dbtest-any.sh /srv/wt /srv/wt.log apps/api/" + TEST_TS,
    "node --test " + TEST_TS,
]

# Legitimate commands that were allowed at bdc78e1c or a0eaf357 and lose the exemption under the allowlist (main
# approved the strict reading). They are not one of the exact test-runner lines, so they are scanned in full again,
# as they were before PR 265. Pinned so the packet's list of lost commands is the tested list.
LOST_EXEMPTION = [
    "node scripts/run.mjs apps/api/" + TEST_TS,  # a generic script with path operands
    "python3 tools/lint.py src/kill-switch.go src/kill_switch.rs web/kill-switch.tsx web/kill-switch.js",
    "python3 tools/report.py kill-switch-notes/README",
    PGPOOL + "env CI=1 npx vitest run " + TEST_TS,  # a wrapper inside the pgpool line
    PGPOOL + "timeout 600 dbtest-any.sh /srv/wt /srv/wt.log " + TEST_TS,
    PGPOOL + "env -u NODE_OPTIONS sudo -u ci -- npx -y vitest run " + TEST_TS,
    # review v3: a test path needs a test-shaped file name, not only a tests/ directory (main approved losing it)
    "ssh t2-dev 'cd ~/repos/harness && " + PGPOOL + "dbtest-any.sh /srv/wt /srv/wt.log tests/qac-kill-switch.py'",
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

RUNNER = "python3 runner.py -- "
KILL_PY = "tools/kill-all.py"
KILL_TS = "tools/kill-all.ts"

# PR 265 review round 1 (receipts/harness-pr265-v1.md): a wrapper's option values and operands must not be read as
# the command it runs. Every row was allowed at bdc78e1c.
WRAPPER_VALUE_ESCAPES = [
    RUNNER + "env -C /srv " + KILL_PY,  # round 1 F1 as reported
    RUNNER + "sudo -u bob -g staff " + KILL_PY,  # round 1 F1 as reported
    RUNNER + "env -u A -u B " + KILL_PY,
    RUNNER + "env -u NAME -C /srv " + KILL_PY,
    RUNNER + "env -C /srv -u NAME VAR=1 " + KILL_PY,
    RUNNER + "env --chdir /srv " + KILL_PY,
    RUNNER + "sudo -Eu bob -g staff " + KILL_PY,
    RUNNER + "sudo -E -u bob -g staff " + KILL_PY,
    RUNNER + "sudo -D /srv " + KILL_PY,
    RUNNER + "env sudo -u bob -g staff " + KILL_PY,
    RUNNER + "sudo -- env -C /srv " + KILL_PY,
    RUNNER + "xargs -a /tmp/list " + KILL_PY,
    RUNNER + "conda run -n myenv " + KILL_PY,
    RUNNER + "flock /tmp/l " + KILL_PY,
    RUNNER + "chroot /mnt " + KILL_PY,
    RUNNER + "script /dev/null " + KILL_PY,
    RUNNER + "gtimeout 5 ./kill-all.py",
    RUNNER + "python3 -X dev " + KILL_PY,
    RUNNER + "python3 -W ignore " + KILL_PY,
    RUNNER + "node -r ./preload.js ./kill-all.mjs",
    RUNNER + "bash -o pipefail " + KILL_PY,
]

# Round-1 variants bdc78e1c already refused; pinned.
WRAPPER_VALUE_PINNED = [
    RUNNER + "env -u NAME " + KILL_PY,
    RUNNER + "env VAR=1 " + KILL_PY,
    RUNNER + "env -iu NAME " + KILL_PY,
    RUNNER + "env --chdir=/srv " + KILL_PY,
    RUNNER + "timeout -s KILL 5 " + KILL_PY,
    RUNNER + "timeout -s KILL -k 3 5 " + KILL_PY,
    RUNNER + "timeout --signal=KILL 5 " + KILL_PY,
    RUNNER + "nice -n 5 " + KILL_PY,
    RUNNER + "nice -n 5 -- " + KILL_PY,
    RUNNER + "sudo -E " + KILL_PY,
    RUNNER + "sudo -Eu bob " + KILL_PY,
    RUNNER + "stdbuf -o L " + KILL_PY,
    RUNNER + "taskset 0x3 " + KILL_PY,
    RUNNER + "X=1 " + KILL_PY,
    RUNNER + "-v " + KILL_PY,
]

# A bare tool or subcommand a wrapper runs (a0eaf357's rows).
WRAPPER_SUBCOMMANDS = [
    RUNNER + "npx tsx " + KILL_TS,
    RUNNER + "env tsx " + KILL_TS,
    RUNNER + "timeout 5 tsx " + KILL_TS,
    RUNNER + "npx vitest " + KILL_TS,
    "python3 runner.py docker exec web " + KILL_PY,
    RUNNER + "deno run " + KILL_TS,
    RUNNER + "bun x " + KILL_TS,
    RUNNER + "node inspect kill-all.js",
    RUNNER + "bash run " + KILL_PY,
]

# PR 265 review round 2 (receipts/harness-pr265-v2.md): bare runners with options or subcommands, the two reported
# examples and the variants main asked for, after a generic runner's `--`, inside a pgpool line and on their own.
RUNNER_SCRIPT_ESCAPES = [
    RUNNER + "npx tsx --tsconfig tsconfig.json " + KILL_TS,  # round 2 F1 as reported
    RUNNER + "env npm exec tsx " + KILL_TS,  # round 2 F1 as reported
    RUNNER + "bunx " + KILL_TS,
    RUNNER + "bunx tsx " + KILL_TS,
    RUNNER + "pnpm exec tsx " + KILL_TS,
    RUNNER + "pnpm --filter api exec tsx " + KILL_TS,
    RUNNER + "yarn dlx tsx " + KILL_TS,
    RUNNER + "npm exec -- tsx " + KILL_TS,
    RUNNER + "node --import x " + KILL_TS,
    RUNNER + "node --import tsx " + KILL_TS,
    RUNNER + "deno run -A " + KILL_TS,
    RUNNER + "deno run --allow-all " + KILL_TS,
    PGPOOL + "npx tsx --tsconfig tsconfig.json " + KILL_TS,
    PGPOOL + "env npm exec tsx " + KILL_TS,
    PGPOOL + "bunx " + KILL_TS,
    PGPOOL + "pnpm exec tsx " + KILL_TS,
    PGPOOL + "yarn dlx tsx " + KILL_TS,
    PGPOOL + "node --import x " + KILL_TS,
    PGPOOL + "deno run -A " + KILL_TS,
    "node --import x " + KILL_TS,
    "node --import x --test " + KILL_TS,
    "deno run -A " + KILL_TS,
]

# Commands one word away from an allowed grammar: an extra, missing or changed word anywhere means the full scan.
GRAMMAR_EDGES = [
    QAC_DBTEST + KILL_TS,  # the test slot holds a non-test file
    QAC_DBTEST + "scripts/kill-all.sh",
    QAC_LINE + " " + KILL_TS,  # an extra word after the test path
    QAC_LINE + " -x " + KILL_TS,  # only `-t NAME` may follow the test path
    QAC_LINE + " -t " + KILL_TS,  # the -t value is scanned, never exempt
    QAC_LINE_T + " " + KILL_TS,
    QAC_PGPOOL + "~/qacp-work/fable-b1/dbtest-any.sh " + KILL_PY + " qac-7.log " + TEST_TS,  # WT slot is scanned
    QAC_PGPOOL + "tools/dbtest-any.sh /srv/wt qac.log " + TEST_TS + " " + KILL_TS,  # relative dbtest path
    QAC_PGPOOL + "~/qacp-work/fable-b1/kill-all.sh /srv/wt qac.log " + TEST_TS,
    "python3 lanes/pgpool.py run --job $N -- dbtest-any.sh /srv/wt qac.log " + TEST_TS,  # a dynamic word
    "python3 lanes/pgpool.py run --foo x -- dbtest-any.sh /srv/wt qac.log " + TEST_TS,  # an unknown option
    "python3 lanes/pgpool.py run --mode -- dbtest-any.sh /srv/wt qac.log " + TEST_TS,  # option without a value
    "python3 lanes/pgpool.py lease -- dbtest-any.sh /srv/wt qac.log " + TEST_TS,  # another subcommand
    "python3 lanes/pgpool.py run " + TEST_TS,  # no `--`
    "python3 -X dev lanes/pgpool.py run -- dbtest-any.sh /srv/wt qac.log " + TEST_TS,  # an unlisted python flag
    "python3 tools/pgpool.py run -- dbtest-any.sh /srv/wt qac.log " + TEST_TS,  # not lanes/pgpool.py
    PGPOOL + "npx vitest run " + KILL_TS,  # vitest given a non-test file
    PGPOOL + "npx vitest run " + TEST_TS + " " + KILL_TS,
    PGPOOL + "npx vitest run --config vite.config.ts " + TEST_TS,
    PGPOOL + "npx vitest " + TEST_TS,  # no `run`
    PGPOOL + "pnpm --filter api exec vitest run " + KILL_TS,
    "python3 -m pytest " + KILL_PY,
    "python3 -m pytest -p plugin tests/test_kill_switch.py",
    "python3 -m pytest tests/test_kill_switch.py " + KILL_PY,
    "node --test " + KILL_TS,
    "node --test --import x " + TEST_TS,
]

# The real QAC line with a test name that holds a kill word. The -t value is free text handed to a script the guard
# cannot see, so it is scanned, as it was at a0eaf357. Disclosed in the packet.
SCANNED_TEST_NAME = [QAC_LINE + ' -t "kill switch ceiling"']

# PR 265 review v3 (receipts/harness-pr265-v3.md): a TEST operand that resolves outside a test directory, or that
# only looks like a test, is not exempt. `..`, `.`, empty components, absolute paths and `~` fail closed.
PGPOOL_DB = "python3 lanes/pgpool.py run -- dbtest-any.sh /srv/wt qac.log "
TRAVERSAL_ESCAPES = [
    "node --test tests/../tools/kill-all.js",  # v3 F1 as reported (G3)
    "python3 -m pytest tests/../tools/kill-all.py",  # v3 F1 as reported (G2)
    PGPOOL_DB + "tests/../tools/kill-all.ts",  # v3 F1 as reported (G1)
    QAC_DBTEST + "test/../tools/kill-all.ts",
    QAC_DBTEST + "test/../tools/kill-all.test.ts",  # a test-shaped name reached through `..`
    QAC_DBTEST + "test/x/../../tools/kill-all.test.ts",
    QAC_DBTEST + "./test/../tools/kill-all.test.ts",
    QAC_DBTEST + "test/./kill-all.ts",
    QAC_DBTEST + "test//kill-all.ts",
    QAC_DBTEST + "/srv/test/kill-all.test.ts",  # an absolute path
    QAC_DBTEST + "~/test/kill-all.test.ts",  # a tilde path
    PGPOOL + "npx vitest run test/../tools/kill-all.ts",
    PGPOOL + "npx vitest run " + TEST_TS + " test/../tools/kill-all.test.ts",
    PGPOOL + "pnpm --filter api exec vitest run tests/../tools/kill-all.ts",
    "python3 -m pytest tests/kill-all.py",  # inside tests/, but not a test-shaped name
    "python3 -m pytest tools/kill-all.test.py",  # a test-shaped name outside a test directory
    "node --test tests/kill-all.js",
    "node --test tools/kill-all.test.js",
    "node --test /srv/test/kill-all.test.js",
    QAC_PGPOOL + "~/qacp-work/fable-b1/dbtest-any.sh /srv/wt{,2} qac.log " + TEST_TS,  # brace alternatives
    "ssh t2-dev '" + QAC_DBTEST + "test/../tools/kill-all.ts'",  # the ssh forms of the same escapes
    "ssh t2-dev 'cd ~/repos/harness && " + PGPOOL_DB + "tests/../tools/kill-all.ts'",
    "ssh t2-dev 'python3 -m pytest tests/../tools/kill-all.py'",
    "ssh t2-dev 'node --test tests/../tools/kill-all.js'",
]

# Refusals that match a grammar and fail only in path_operand (a test-shaped word that is quoted or holds non-path
# characters). Widening path_operand to "any token" must flip each one, so the mutation check is not vacuous.
PREDICATE_REFUSALS = [
    QAC_DBTEST + "'test/kill-switch.test.ts; pkill -f vite'",
    PGPOOL + "npx vitest run 'test/kill 4242.test.ts'",
    "python3 -m pytest 'tests/test_kill 4242.py'",
    "node --test 'test/kill-all.test.js'",
]

# Refusals that match a grammar and fail only in the test-shape rule (a plain path that is not a test file).
# Treating every path_operand as a test path must flip each one.
TEST_SHAPE_REFUSALS = [
    QAC_DBTEST + KILL_TS,
    PGPOOL + "npx vitest run " + KILL_TS,
    "python3 -m pytest " + KILL_PY,
    "node --test " + KILL_TS,
]

BLOCK += (WRAPPER_VALUE_ESCAPES + WRAPPER_VALUE_PINNED + WRAPPER_SUBCOMMANDS + RUNNER_SCRIPT_ESCAPES
          + GRAMMAR_EDGES + LOST_EXEMPTION + SCANNED_TEST_NAME + PREDICATE_REFUSALS + TRAVERSAL_ESCAPES)

# Rows that must be refused by the script-kill rule itself (not by some other rule).
SCRIPT_KILL_ROWS = (WRAPPER_VALUE_ESCAPES + WRAPPER_VALUE_PINNED + WRAPPER_SUBCOMMANDS + RUNNER_SCRIPT_ESCAPES
                    + GRAMMAR_EDGES + LOST_EXEMPTION + SCANNED_TEST_NAME + PREDICATE_REFUSALS
                    + TRAVERSAL_ESCAPES)


def verdict(cmd):
    with tempfile.TemporaryDirectory() as tmp:
        return kg.decide(cmd, cwd=tmp, policy=kg.load_policy(), home=tmp)[:2]


def refusals_that_pass(rows=BLOCK):
    """The refusal rows the guard currently lets through; the refusal test requires none."""
    return [cmd for cmd in rows if verdict(cmd)[0] != "block"]


def word(text, cg=None):
    cg = cg or kg._import_base()
    w = cg.Word()
    w.alts, w.raw = [text], text
    return w


class PathOperands(unittest.TestCase):
    def test_control_policy_pattern_still_matches_the_test_path(self):
        """Control: the policy pattern itself still matches the path (the fix is in where it is applied, not a
        narrowed pattern), so ALLOW below passes because of the grammar. On f26cf1b every ALLOW row was refused as
        [script-kill]."""
        self.assertIsNotNone(kg.re.search(kg.load_policy()['script_kill_pattern'], TEST_TS))

    def test_kill_word_inside_a_test_path_of_an_exact_runner_line_is_allowed(self):
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

    def test_anything_outside_the_grammar_keeps_the_script_kill_refusal(self):
        """Rounds 1 and 2 of the PR 265 review, the grammar edges, and the legitimate commands that lose the
        exemption: every one is refused by [script-kill]."""
        for cmd in SCRIPT_KILL_ROWS:
            with self.subTest(cmd=cmd):
                self.assertEqual(verdict(cmd), ("block", "script-kill"))

    def test_only_the_test_path_is_exempt(self):
        """The exemption covers exactly the test-path slot of the QAC line; pgpool's values, the dbtest script, the
        worktree, the log and the -t value stay in the scan."""
        kill_re = kg.re.compile(kg.load_policy()['script_kill_pattern'])
        cg = kg._import_base()
        words = QAC_LINE.split()[1:]
        self.assertEqual(kg.test_runner_exemptions("python3", [word(t, cg) for t in words], kill_re),
                         {words.index(TEST_TS)})
        words_t = words + ["-t", "caps the ceiling"]
        self.assertEqual(kg.test_runner_exemptions("python3", [word(t, cg) for t in words_t], kill_re),
                         {words.index(TEST_TS)})
        self.assertEqual(kg.test_runner_exemptions("python3", [word(t, cg) for t in words], None), set())
        self.assertEqual(kg.test_runner_exemptions("python3", [word(t, cg) for t in words + ["x"]], kill_re), set())
        self.assertEqual(kg.test_runner_exemptions("ruby", [word(t, cg) for t in words], kill_re), set())

    def test_mutation_widening_the_path_predicate_breaks_a_refusal(self):
        """Mutation check: if path_operand accepted every token, refusals must start passing. This proves the
        predicate (not some other rule) keeps them refused, so the refusal tests are not vacuous."""
        self.assertEqual(refusals_that_pass(PREDICATE_REFUSALS), [])  # unmutated: all refused
        with mock.patch.object(kg, "path_operand", lambda word, kill_re: True):
            self.assertEqual(refusals_that_pass(PREDICATE_REFUSALS), PREDICATE_REFUSALS)
            self.assertNotEqual(refusals_that_pass(), [])  # the refusal test above would now fail
        self.assertEqual(refusals_that_pass(PREDICATE_REFUSALS), [])  # the patch is undone

    def test_mutation_dropping_the_test_shape_rule_breaks_a_refusal(self):
        """Mutation check: if every path_operand counted as a test path, a runner line given a kill-named
        non-test file would be allowed."""
        self.assertEqual(refusals_that_pass(TEST_SHAPE_REFUSALS), [])
        with mock.patch.object(kg, "is_test_path", lambda w, kill_re: kg.path_operand(w, kill_re)):
            self.assertEqual(refusals_that_pass(TEST_SHAPE_REFUSALS), TEST_SHAPE_REFUSALS)
        self.assertEqual(refusals_that_pass(TEST_SHAPE_REFUSALS), [])

    def test_mutation_sets_are_refusal_rows(self):
        self.assertTrue(set(PREDICATE_REFUSALS) <= set(BLOCK))
        self.assertTrue(set(TEST_SHAPE_REFUSALS) <= set(BLOCK))

    def test_predicate_shape(self):
        kill_re = kg.re.compile(kg.load_policy()['script_kill_pattern'])
        cg = kg._import_base()
        self.assertTrue(kg.path_operand(word(TEST_TS, cg), kill_re))
        self.assertTrue(kg.path_operand(word("qac-kill-switch-ceiling.test.ts", cg), kill_re))
        self.assertTrue(kg.path_operand(word("tests/kill_switch.PY", cg), kill_re))
        self.assertTrue(kg.path_operand(word("kill-dir/run", cg), kill_re))
        for text in ("kill", "pkill", "/usr/bin/pkill", "bin/kill", "scripts/kill-all.sh", "kill-all.sh",
                     "kill 4242", "-kill-x.ts", "--script=tests/kill-all.py", "a;kill.py", "a/kill$x.py", ""):
            with self.subTest(text=text):
                self.assertFalse(kg.path_operand(word(text, cg), kill_re))

    def test_test_path_shape(self):
        kill_re = kg.re.compile(kg.load_policy()['script_kill_pattern'])
        cg = kg._import_base()
        for text in (TEST_TS, "apps/api/" + TEST_TS, "tests/test_kill_switch.py", "tests/test-kill-switch.py",
                     "src/__tests__/kill.spec.tsx", "test/unit/kill-switch.test.ts"):
            with self.subTest(text=text):
                self.assertTrue(kg.is_test_path(word(text, cg), kill_re))
        for text in (KILL_TS, KILL_PY, "scripts/kill-all.sh", "kill-all.ts", "testing/kill-all.ts",
                     "src/kill-switch.go", "kill-switch-notes/README", "test_kill.py", "tests/qac-kill-switch.py",
                     "tools/kill-all.test.ts", "tests/../tools/kill-all.js", "test/../tools/kill-all.test.ts",
                     "./test/kill.test.ts", "test/./kill.test.ts", "test//kill.test.ts", "/srv/test/kill.test.ts",
                     "~/test/kill.test.ts", "test/kill.test.ts/"):
            with self.subTest(text=text):
                self.assertFalse(kg.is_test_path(word(text, cg), kill_re))


if __name__ == "__main__":
    unittest.main()
