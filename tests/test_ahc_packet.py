"""ahc_packet: the deterministic packet fixer only MOVES evidence lines into the command's own fenced block; it never
invents an exit status, a count or a SHA, and the conservation check rejects any rewrite (deterministic or LLM) that
adds, drops or alters an evidence line. Stdlib only, no network. GoodQA goodqa#16034 AC-4 / NEG-4."""
import sys
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.append(str(Path.home() / ".claude" / "hooks"))  # review_diagnostics when run from a staging tree
import ahc_packet  # noqa: E402
import review_diagnostics  # noqa: E402

HEAD = "ad60fa6d9" + "0" * 31
CMD = "cd platform && node --test test/a.test.js"

# The real failure shape of packet-pr783 v1 (GoodQA run 2026-11-14): command above a label line, output in a fence,
# the count and exit status on a Result line AFTER the fence. Every evidence line exists; none is in one block.
BROKEN = f"""# PR 783 packet
Reviewed head: {HEAD}

## Test run at head
Command:
`{CMD}`
Output (tail of the tap file):
```
1..137
# tests 137
# pass 131
# fail 0
```
Result: 131 passed, 0 failed, 6 skipped, exit 0

## Notes
nothing else
"""

# Evidence genuinely missing: no exit status anywhere. The fixer must refuse rather than add one.
NO_EXIT = BROKEN.replace(", exit 0", "")


class LintFixTests(unittest.TestCase):
    def lint(self, text):
        return review_diagnostics.lint_packet("pr", text, HEAD)

    def test_broken_fixture_fails_lint_before_fix(self):
        self.assertTrue(self.lint(BROKEN), "fixture must reproduce the real lint failure")

    def test_fix_moves_lines_and_passes_lint(self):
        fixed = ahc_packet.fix_layout(BROKEN)
        self.assertIsNotNone(fixed)
        self.assertEqual(self.lint(fixed), [])
        self.assertTrue(ahc_packet.conserved(BROKEN, fixed))
        self.assertIn("$ " + CMD, fixed)

    def test_fix_never_invents_an_exit_status(self):
        fixed = ahc_packet.fix_layout(NO_EXIT)
        if fixed is not None:
            self.assertNotIn("exit 0", fixed)
            self.assertTrue(self.lint(fixed), "a packet with no exit status must still fail lint")

    def test_already_clean_packet_is_returned_unchanged(self):
        clean = ahc_packet.fix_layout(BROKEN)
        self.assertEqual(ahc_packet.fix_layout(clean), clean)

    def test_conservation_rejects_changed_count(self):
        fixed = ahc_packet.fix_layout(BROKEN)
        self.assertFalse(ahc_packet.conserved(BROKEN, fixed.replace("# pass 131", "# pass 137")))

    def test_conservation_rejects_added_exit_line(self):
        fixed = ahc_packet.fix_layout(BROKEN)
        self.assertFalse(ahc_packet.conserved(BROKEN, fixed + "\nexit 0\n"))

    def test_conservation_rejects_dropped_line(self):
        fixed = ahc_packet.fix_layout(BROKEN)
        self.assertFalse(ahc_packet.conserved(BROKEN, fixed.replace("# fail 0\n", "")))

    def test_conservation_rejects_changed_sha(self):
        fixed = ahc_packet.fix_layout(BROKEN)
        self.assertFalse(ahc_packet.conserved(BROKEN, fixed.replace(HEAD, "f" * 40)))

    def test_conservation_rejects_changed_command(self):
        fixed = ahc_packet.fix_layout(BROKEN)
        self.assertFalse(ahc_packet.conserved(BROKEN, fixed.replace("a.test.js", "b.test.js")))

    def test_conservation_ignores_blank_lines_and_fences_only(self):
        self.assertTrue(ahc_packet.conserved("a\n\n```\nb\n```\n", "a\n```\n\nb\n```"))


FULL_HEAD = "ad60fa6d9a6e97059326697aa99470afd8866576"
LONG_CMD = "cd platform && node --test --test-reporter=tap test/one.test.js test/two.test.js"

# Sanitized shape of the real packet-pr783 v1 (two runs; the second is the expected failing-first run with exit 1
# and an inline-backtick Setup line above it).
PR783_V1 = f"""Head: {FULL_HEAD}
Base: 84892554c36ad3d374608fdca548eff9850abd87

## Test run at head
Command:
`{LONG_CMD}`
Output (tail of focused.tap, sha256 {'8' * 64}):
```
1..137
# tests 137
# pass 131
# fail 0
# skipped 6
```
Result: 131 passed, 0 failed, 6 skipped (no PG in this run), exit 0

## Failing-first
Setup: detached at head, then `git checkout 84892554c36ad3d374608fdca548eff9850abd87 -- platform/src` (tests from head).
Command:
`{LONG_CMD}`
Output (tail of failing-first.tap):
```
1..137
# tests 137
# pass 114
# fail 17
```
Result: 114 passed, 17 failed on base, exit 1 (expected).
"""

# The hand "fix" (v2) that ADDED "131 passed..." and "exit 0" lines that were not in v1. Conservation must reject it.
PR783_V2_HAND = PR783_V1.replace(
    f"Command:\n`{LONG_CMD}`\nOutput (tail of focused.tap, sha256 {'8' * 64}):\n```\n",
    "Command and output:\n```\n$ " + LONG_CMD + "\n", 1).replace(
    "# skipped 6\n```\n", "# skipped 6\n131 passed, 0 failed, 6 skipped\nexit 0\n```\n", 1)

NOISE = "".join(
    f"/usr/lib/python3/unittest/case.py:{n}: ResourceWarning: unclosed file <_io.TextIOWrapper name='x{n}'>\n"
    f"  method()\n" for n in range(1, 7)) + "ResourceWarning: Enable tracemalloc to get the object allocation traceback\n"

NOISY = f"""# Noisy packet
Head: {FULL_HEAD}

$ python3 -m unittest tests.test_x
```
{NOISE}..........
Ran 10 tests in 0.1s
OK
exit 0
```
"""


class RealShapeTests(unittest.TestCase):
    def test_pr783_v1_shape_fails_lint_then_fixes_with_real_head(self):
        self.assertTrue(review_diagnostics.lint_packet("pr", PR783_V1, FULL_HEAD))
        result = ahc_packet.fix_packet(PR783_V1, FULL_HEAD)
        self.assertEqual(result["status"], "fixed", result)
        self.assertEqual(review_diagnostics.lint_packet("pr", result["text"], FULL_HEAD), [])
        self.assertTrue(ahc_packet.conserved(PR783_V1, result["text"]))
        # The failing-first run keeps its own exit 1; nothing turned it into a pass.
        self.assertIn("Result: 114 passed, 17 failed on base, exit 1 (expected).\n```", result["text"])
        self.assertEqual(result["text"].count("exit 0"), PR783_V1.count("exit 0"))

    def test_hand_fix_that_added_evidence_is_rejected(self):
        self.assertIn("\nexit 0\n", PR783_V2_HAND)
        self.assertFalse(ahc_packet.conserved(PR783_V1, PR783_V2_HAND))

    def test_reordered_evidence_is_rejected(self):
        fixed = ahc_packet.fix_layout(PR783_V1)
        swapped = fixed.replace("# pass 131\n# fail 0", "# fail 0\n# pass 131")
        self.assertNotEqual(swapped, fixed)
        self.assertFalse(ahc_packet.conserved(PR783_V1, swapped))

    def test_missing_head_is_never_repaired(self):
        result = ahc_packet.fix_packet(PR783_V1.replace(FULL_HEAD, FULL_HEAD[:9]), FULL_HEAD)
        self.assertEqual(result["status"], "unfixable")
        self.assertIsNone(result["text"])
        self.assertTrue(any("full expected HEAD" in p for p in result["problems"]))

    def test_result_line_far_below_fence_is_not_pulled_in(self):
        far = PR783_V1.replace("```\nResult: 131", "```\nnote one\nnote two\nnote three\nResult: 131", 1)
        far = far.replace("Result: 114 passed, 17 failed on base, exit 1 (expected).", "Result: see above")
        self.assertIsNone(ahc_packet.fix_layout(far))

    def test_head_problem_filter_matches_lint_wording(self):
        problems = review_diagnostics.lint_packet("pr", "no head here", FULL_HEAD)
        self.assertTrue(any(p.startswith(ahc_packet._HEAD_PROBLEM) for p in problems))


class NoiseTests(unittest.TestCase):
    def test_noise_pushes_exit_out_of_window_and_strip_is_disclosed(self):
        self.assertTrue(review_diagnostics.lint_packet("pr", NOISY, FULL_HEAD))
        result = ahc_packet.fix_packet(NOISY, FULL_HEAD)
        self.assertEqual(result["status"], "fixed", result)
        text = result["text"]
        self.assertNotIn("ResourceWarning: unclosed", text)
        self.assertEqual(text.splitlines()[1], ahc_packet.NOTE_TEMPLATE.format(n=13, sha=ahc_packet.sha256_text(NOISY)))
        self.assertTrue(ahc_packet.conserved(NOISY, text))
        self.assertEqual(review_diagnostics.lint_packet("pr", text, FULL_HEAD), [])

    def test_undisclosed_noise_removal_is_rejected(self):
        text = ahc_packet.fix_layout(NOISY)
        undisclosed = "\n".join(line for line in text.split("\n") if not line.startswith("> ahc-fixer:"))
        self.assertFalse(ahc_packet.conserved(NOISY, undisclosed))

    def test_note_with_wrong_count_or_sha_is_rejected(self):
        text = ahc_packet.fix_layout(NOISY)
        self.assertFalse(ahc_packet.conserved(NOISY, text.replace("removed 13 ", "removed 12 ")))
        self.assertFalse(ahc_packet.conserved(NOISY, text.replace(ahc_packet.sha256_text(NOISY), "a" * 64)))

    def test_note_cannot_launder_a_dropped_evidence_line(self):
        text = ahc_packet.fix_layout(NOISY)
        self.assertFalse(ahc_packet.conserved(NOISY, text.replace("Ran 10 tests in 0.1s\n", "")))

    def test_noise_outside_a_fence_is_not_removed(self):
        outside = NOISY.replace("```\n" + NOISE, NOISE + "```\n")
        self.assertEqual(ahc_packet.noise_lines(outside), [])


class CliTests(unittest.TestCase):
    def test_cli_never_overwrites_the_input_packet(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp) / "packet.md"
            packet.write_text(PR783_V1, encoding="utf-8")
            code = ahc_packet.main([str(packet), "--expected-head", FULL_HEAD, "--output", str(packet)])
            self.assertEqual(code, 2)
            self.assertEqual(packet.read_text(encoding="utf-8"), PR783_V1)
            out = Path(tmp) / "fixed.md"
            self.assertEqual(ahc_packet.main([str(packet), "--expected-head", FULL_HEAD, "--output", str(out)]), 0)
            self.assertEqual(packet.read_text(encoding="utf-8"), PR783_V1)
            self.assertEqual(review_diagnostics.lint_packet("pr", out.read_text(encoding="utf-8"), FULL_HEAD), [])


if __name__ == "__main__":
    unittest.main()
