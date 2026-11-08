"""goodqa#15317: 'the command word is built at run time and the command mentions gh or a merge' fired on a compound command
whose first word was an environment variable (a relay path) and whose other segments only read (gh pr view, ticket
comments). A variable this command never binds cannot carry text from elsewhere in the command, so the hint must be in
its own segment. Variables bound in the command, and every merge spelling, stay unverifiable. Corpus rows are data."""

import os
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
HOOKS = Path(os.environ.get("MERGE_GATE_HOOKS_DIR") or HERE.parent / "harness" / "hooks")
sys.path.insert(0, str(HOOKS))
import merge_gate as mg  # noqa: E402

FALSE_POSITIVES = (
    "$RELAY run; gh pr view 5",
    "$RELAY run --all; n=$(gh api repos/o/r/issues/5/comments --jq length); echo $n",
    "${RELAY} run; ah ticket comments 5 | wc -l; gh pr checks 5",
    "$RELAY run; python3 ~/.claude/hooks/ah.py ticket create --title 'merge gate noise' --body-file b.md",
)

STILL_UNVERIFIABLE = (
    "$X pr merge 5",
    "X=$(echo gh); $X pr merge 5",
    "read C <<<'gh pr merge 5'; $C",
    "export C='gh pr merge 5'; $C",
    "for C in 'gh pr merge 5'; do $C; done",
    "$RELAY run; gh pr merge 5",
    "eval \"$RELAY\" pr merge 5",
    # red-team C2: text for the shell arrives by pipe or file, not in the variable's own segment
    'echo "gh pr merge 1" | $SHELL',
    'printf "gh pr merge 1" | $X',
    'echo "gh pr merge 1" > s.sh; $X s.sh',
    "$RELAY gh pr merge 5",
)


class DynamicWord(unittest.TestCase):
    def test_unbound_variable_with_unrelated_gh_segment_is_not_a_merge(self):
        flagged = [c for c in FALSE_POSITIVES if mg.find_merges(c)]
        self.assertEqual(flagged, [], 'false positive on %d of %d rows' % (len(flagged), len(FALSE_POSITIVES)))

    def test_control_merges_stay_flagged(self):
        passed = [c for c in STILL_UNVERIFIABLE if not mg.find_merges(c)]
        self.assertEqual(passed, [], 'a merge spelling stopped being flagged')


if __name__ == "__main__":
    unittest.main()
