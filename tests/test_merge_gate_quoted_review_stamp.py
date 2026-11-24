"""goodqa#16811: the review-auth stamp reads shell punctuation only outside quotes, binds from the validated argv, and
says why when it mints nothing.

The commands below are genericized from refused real runs (a quoted --repeat-reason holding `;`, an output redirect):
no host, project, path or session from those runs appears here.
"""
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
HOOKS = HERE.parent / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(HERE))
import merge_gate as mg  # noqa: E402
import test_merge_gate as fixture  # noqa: E402

SID = "11111111-2222-4333-8444-555555555555"
HEAD = "a" * 40
PREFIX = "python3 ~/.claude/hooks/peer_review.py pr --repo /w --packet /p --expected-head " + HEAD
BOUND = PREFIX + " --github-repo o/r --pr 5"


class MainHome(unittest.TestCase):
    """A temporary HOME with a real main transcript, so caller_identity.is_main proves main without mocks."""

    def setUp(self):
        import caller_identity
        self.ci = caller_identity
        self.home = tempfile.mkdtemp(prefix="mg-quoted-")
        self.addCleanup(__import__("shutil").rmtree, self.home, True)
        transcript = Path(self.home) / ".claude" / "projects" / "-x" / (SID + ".jsonl")
        transcript.parent.mkdir(parents=True)
        transcript.write_text("{}\n")
        self.transcript = str(transcript)
        patcher = mock.patch.dict(os.environ, {"HOME": self.home})
        patcher.start()
        self.addCleanup(patcher.stop)

    def payload(self, command, **extra):
        return dict(fixture.bash(command), **{"session_id": SID, "transcript_path": self.transcript, **extra})

    def decide(self, command, notes=None, **extra):
        # `notes` is passed only when a test reads them, so the stamp assertions fail on their own merits on a base
        # without the notes parameter.
        return mg.decide(self.payload(command, **extra), fixture.FakeGh(fixture.SCENARIOS["green"]),
                         Path(self.home) / "s", **({} if notes is None else {"notes": notes}))

    def taken(self, repo="o/r", pr=5):
        return self.ci.take_stamp("review-auth", [repo, pr], home=self.home)

    def hook(self, command, **extra):
        out, err = io.StringIO(), io.StringIO()
        raw = json.dumps(self.payload(command, **extra)).encode()
        code = mg.hook_main(Path(self.home) / "s", fixture.FakeGh(fixture.SCENARIOS["green"]), io.BytesIO(raw),
                            out, err)
        return code, out.getvalue(), err.getvalue()


class QuotedPunctuationMints(MainHome):
    def test_separators_inside_a_quoted_reason_mint_in_both_quote_styles(self):
        reasons = ["first attempt died on a provider limit; rerun", "lint & tests fixed", "a | b", "x < y",
                   "x > y", "fixed && retested", "a || b", "2>&1 was the old form", "a;b;c"]
        for reason in reasons:
            for quoted in ("'" + reason + "'", '"' + reason + '"'):
                for command in (BOUND + " --repeat-reason " + quoted,
                                PREFIX + " --repeat-reason " + quoted + " --github-repo o/r --pr 5"):
                    with self.subTest(command=command):
                        self.assertEqual(self.decide(command)[0], 0)
                        self.assertIsNotNone(self.taken(), command)

    def test_equals_forms_and_isolated_python_still_mint(self):
        for command in ("python3 -I ~/.claude/hooks/peer_review.py pr --github-repo=o/r --pr=5 "
                        "--repeat-reason='a; b'",
                        "python3 /x/.claude/hooks/peer_review.py --pr 5 --github-repo o/r pr --repeat-reason 'q|r'"):
            with self.subTest(command=command):
                self.decide(command)
                self.assertIsNotNone(self.taken())

    def test_the_reason_cannot_rebind_the_stamp(self):
        for reason in ("'see --pr 999 --github-repo other/repo; old run'", '"was --pr=999 --github-repo=other/repo"',
                       "'--pr 999'"):
            with self.subTest(reason=reason):
                self.decide(BOUND + " --repeat-reason " + reason)
                self.assertIsNone(self.taken("other/repo", 999))
                self.assertIsNone(self.taken("o/r", 999))
                self.assertIsNotNone(self.taken())

    def test_a_word_argparse_reads_as_the_flag_mints_nothing(self):
        # argparse reads a word starting `--pr=` as the option (and then refuses the run); the stamp never guesses.
        for reason in ('"--pr=999 --github-repo=other/repo"', "--pr=999"):
            with self.subTest(reason=reason):
                self.decide(BOUND + " --repeat-reason " + reason)
                for repo, pr in (("other/repo", 999), ("o/r", 999), ("o/r", 5)):
                    self.assertIsNone(self.taken(repo, pr))

    def test_a_reason_before_the_flags_is_still_a_bound_review_for_subagents(self):
        # PEER_REVIEW_AUTH stops at `;`, so this shape used to pass the subagent rule (no stamp, but a paid run).
        command = PREFIX + " --repeat-reason 'one; two' --github-repo o/r --pr 5"
        code, text = mg.decide(dict(fixture.bash(command), agent_id="sub1"),
                               fixture.FakeGh(fixture.SCENARIOS["green"]), Path(self.home) / "s")
        self.assertEqual(code, 2)
        self.assertIn("subagent cannot run the PR review", text)


class UnsafeFormsMintNothing(MainHome):
    BACKTICK = "`"
    CASES = [
        ("a compound command (`;`", BOUND + "; true"),
        ("a compound command (`&&`", BOUND + " && echo done"),
        ("a compound command (`||`", BOUND + " || true"),
        ("a pipe (`|`", BOUND + " | tee out.txt"),
        ("a redirect (`>`", BOUND + " > out.txt"),
        ("a redirect (`>>`", BOUND + " >> out.txt"),
        ("a redirect (`<`", BOUND + " < /dev/null"),
        ("a compound or background command (`&`", BOUND + " &"),
        ("a command substitution (`$(`", BOUND + " --repeat-reason $(cat r)"),
        ("a command substitution (`" + BACKTICK + "`", BOUND + " --repeat-reason `cat r`"),
        ("a newline", BOUND + "\ntrue"),
        ("ANSI-C quoting", BOUND + " --repeat-reason $'a\\nb'"),
        ("a backslash escape", BOUND + " --repeat-reason a\\;b"),
        ("unbalanced quotes", BOUND + " --repeat-reason 'a"),
        ("an unquoted shell expansion", BOUND + " --repeat-reason $REASON"),
        ("a shell expansion inside double quotes ('$'", BOUND + ' --repeat-reason "home $HOME"'),
        ("a shell expansion inside double quotes ('$'", BOUND + ' --repeat-reason "$(id)"'),
        ("a shell expansion inside double quotes ('`'", BOUND + ' --repeat-reason "`id`"'),
        ("a shell expansion inside double quotes ('$'", BOUND + ' --repeat-reason "${a[@]}"'),
        ("a control character '\\r'", BOUND + " --repeat-reason 'a\rb'"),
        ("a control character '\\t'", BOUND + "\t--repeat-reason x"),
        ("an unquoted comment, glob", BOUND + " # trailing comment"),
        ("given more than once", BOUND + " --pr 6"),
        ("does not name --github-repo OWNER/REPO", PREFIX + " --github-repo o/r --pr 5x"),
    ]

    def test_every_unsafe_form_mints_nothing(self):
        # Must-fail controls: each form below mints no stamp. The separator forms minted none before goodqa#16811
        # either; the expansion, ANSI-C, control-character, comment and repeated-flag forms used to mint.
        for _, command in self.CASES:
            with self.subTest(command=command):
                self.decide(command)
                self.assertIsNone(self.taken(), command)
                self.assertIsNone(self.taken("o/r", 6), command)

    def test_every_unsafe_form_names_its_cause(self):
        for cause, command in self.CASES:
            with self.subTest(command=command):
                notes = []
                self.decide(command, notes)
                self.assertEqual(len(notes), 1, (command, notes))
                self.assertIn(cause, notes[0])
                self.assertIn("no review-auth stamp was minted", notes[0])

    def test_quoted_punctuation_in_a_waive_command_still_mints_no_waive_stamp(self):
        # Only the review stamp changed: the waive rule refuses separators even inside quotes.
        command = ("python3 ~/.claude/hooks/merge_gate.py waive --repo o/r --pr 5 --head " + HEAD
                   + " --ticket 'GoodQA #1' --reason 'flaky; rerun is fine'")
        self.assertFalse(mg._plain_waive(command))


class NoStampNote(MainHome):
    """H2: the hook names the real reason on stdout (additionalContext), never blocks, and is silent otherwise."""

    def context(self, stdout):
        return json.loads(stdout)["hookSpecificOutput"]["additionalContext"]

    def test_each_cause_reaches_the_agent_without_blocking(self):
        cases = {"redirect": BOUND + " > review.out", "pipe": BOUND + " | tail -5",
                 "compound": "cd /w && " + BOUND,
                 "shell expansion inside double quotes": BOUND + ' --repeat-reason "retry $N"'}
        for word, command in cases.items():
            with self.subTest(word=word):
                code, out, err = self.hook(command)
                self.assertEqual(code, 0, err)
                self.assertIn(word, self.context(out))
                self.assertIsNone(self.taken())

    def test_a_caller_that_is_not_main_is_told_so(self):
        code, out, _ = self.hook(BOUND, transcript_path=str(Path(self.home) / "missing.jsonl"))
        self.assertEqual(code, 0)
        self.assertIn("not the proven main agent", self.context(out))
        self.assertIsNone(self.taken())

    def test_a_minted_stamp_and_text_that_only_mentions_the_flags_print_nothing(self):
        for command in (BOUND + " --repeat-reason 'a; b'",
                        "grep -n 'python3 ~/.claude/hooks/peer_review.py pr --github-repo o/r --pr 5' notes.md",
                        "echo peer_review.py --github-repo o/r --pr 5",
                        "git commit -m 'run python3 peer_review.py --pr 5 later'"):
            with self.subTest(command=command):
                code, out, _ = self.hook(command)
                self.assertEqual(code, 0)
                self.assertEqual(out, "")


if __name__ == "__main__":
    unittest.main()
