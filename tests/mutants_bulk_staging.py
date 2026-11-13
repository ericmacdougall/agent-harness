"""goodqa#15787 failing-first evidence: tests.test_command_guard_bulk_staging must fail against command_guard.py WITHOUT the rule
(origin/main) and against each controlled broken variant.

Run: python3 -B tests/mutants_bulk_staging.py   (copies the hooks and the test into a temporary tree; changes nothing here)."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = "tests.test_command_guard_bulk_staging"
GUARD = "command_guard.py"

MUTANTS = {
    "the rule is not called": ("        self.bulk_staging(sub, rest, cwd_words, locations, alias_values)\n", "        pass\n"),
    "a linked worktree is judged": ("            if os.path.exists(marker):\n                return None\n            parent = os.path.dirname(current)",
                                    "            if os.path.exists(marker):\n                return current\n            parent = os.path.dirname(current)"),
    "a clean tree is judged": ("            if code != 0 or not out:", "            if code != 0:"),
    "commit -a is not detected": ("                    if letter == 'a':\n                        return True", "                    if letter == 'a':\n                        pass"),
    "message text is read as flags": ("                    if letter in self.COMMIT_VALUE_SHORT:", "                    if False:"),
    "--all and --update abbreviations are not read": ("len(key) >= 3 and ('--all'.startswith(key) or '--update'.startswith(key))",
                                                      "key in ('--all', '--update')"),
    "-u is not detected": ("                if set(word[1:]) & set('Au'):", "                if set(word[1:]) & set('A'):"),
    "an interactive add is bulk": ("                if set(word[1:]) & set('pie'):\n                    return False", "                if set(word[1:]) & set('pie'):\n                    pass"),
    "magic and glob pathspecs are explicit": ("or t in (':/', ':/:', ':/.', '*', '**', ':/*'):", "or t in ():"),
    "a path outside the top is bulk": ("        return absolute == top or (top + '/').startswith(absolute.rstrip('/') + '/')", "        return True"),
    "work-tree and git-dir locations are ignored": ("            if not place or '$' in place or not os.path.isdir(place):\n                continue\n            top = self._original_checkout_top(place)",
                                                    "            if not place or '$' in place or place != where or not os.path.isdir(place):\n                continue\n            top = self._original_checkout_top(place)"),
    "aliases are not judged": ("            elif alias_values:", "            elif False:"),
    "the default mode is enforce": ("'broad_kill': 'warn', 'bulk_staging': 'warn'}", "'broad_kill': 'warn', 'bulk_staging': 'enforce'}"),
    "a failed status call is judged": ("            if code != 0 or not out:\n                continue  # a clean tree", "            if False:\n                continue  # a clean tree"),
}


def run(tmp, label):
    done = subprocess.run([sys.executable, "-B", "-m", "unittest", TEST], cwd=str(tmp), capture_output=True, text=True)
    killed = done.returncode != 0
    print("%-48s %s" % (label, "FAILS (good)" if killed else "PASSES (test is vacuous)"))
    return killed


def tree():
    tmp = Path(tempfile.mkdtemp(prefix="mutant-"))
    shutil.copytree(ROOT / "harness" / "hooks", tmp / "harness" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
    (tmp / "tests").mkdir()
    shutil.copy(ROOT / "tests" / "test_command_guard_bulk_staging.py", tmp / "tests")
    return tmp


def main():
    bad = 0
    tmp = tree()
    try:
        base = subprocess.run(["git", "-C", str(ROOT), "show", "origin/main:harness/hooks/" + GUARD], capture_output=True, check=True).stdout
        (tmp / "harness" / "hooks" / GUARD).write_bytes(base)
        bad += 0 if run(tmp, "origin/main (no rule)") else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for name, (old, new) in MUTANTS.items():
        tmp = tree()
        try:
            path = tmp / "harness" / "hooks" / GUARD
            text = path.read_text()
            if old not in text:
                print("MUTANT NOT APPLIED:", name)
                bad += 1
                continue
            path.write_text(text.replace(old, new, 1))
            bad += 0 if run(tmp, name) else 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
