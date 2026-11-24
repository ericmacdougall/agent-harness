"""goodqa#17112, #17099, #17106 failing-first evidence: tests/test_copy_hygiene_records.py must fail against the code
without the fix (8539e978) and against each broken variant below.

A variant counts as killed only when the unmutated control passes, the variant runs the same number of tests, and the
run prints a FAIL or ERROR line; an import error or a crash before the tests run kills nothing.

Run: python3 -B tests/mutants_copy_floor_records.py   (copies the hooks and the test into a temporary tree; changes
nothing here). The shell ground-truth class is left out: it runs real shells and does not read the mask's code.
"""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOK = "copy_hygiene.py"
BASE = "8539e978"
CLASSES = ["tests.test_copy_hygiene_records.%s" % c
           for c in ("RecordWrites", "NearMisses", "RemoteDestinations", "ScpCopies")]

MUTANTS = {
    "data piped into any program": (
        "ok = j < len(segments) and self.sink(segments[j])", "ok = j < len(segments)"),
    "an unquoted heredoc holding code is blanked": (
        'if quoted or not re.search(r"\\$\\(|`", self.s[a:b]):', "if True:"),
    "a substitution in double quotes is blanked": (
        'elif piece[0] == "sub":\n                                self.masks(piece[3], spans)',
        'elif piece[0] == "sub":\n                                spans.append((piece[1], piece[2]))'),
    "an unquoted substitution is blanked": (
        'elif kind == "sub":\n                        self.masks(nested, spans)',
        'elif kind == "sub":\n                        spans.append((a, b))'),
    "a written file named later is not checked": (
        "if not ok or not all(self.target_ok(t) for t in targets):", "if not ok:"),
    "no whole-line check": ("        lexer.check(segments)\n", ""),
    "reserved words do not stop the mask": (
        "MASK_BAIL_COMMANDS = REDEFINES | shell_words.RESERVED | frozenset((\"exec\", \"coproc\"))",
        "MASK_BAIL_COMMANDS = REDEFINES | frozenset((\"coproc\",))"),
    "exec does not stop the mask": (
        "MASK_BAIL_COMMANDS = REDEFINES | shell_words.RESERVED | frozenset((\"exec\", \"coproc\"))",
        "MASK_BAIL_COMMANDS = REDEFINES | shell_words.RESERVED | frozenset((\"coproc\",))"),
    "a precommand hides eval": (
        "if v in PRECOMMANDS or (v.startswith(\"-\") and p and self.value(segment.words[p - 1]) == \"command\"):",
        "if False:"),
    "a lookup variable assignment is not refused": (
        "if m and m.group(1) in LOOKUP_VARIABLES:", "if False:"),
    "printf -v is data": ('if name == "printf" and any(', 'if False and any('),
    "a dup to an fd above 2 is data": (
        'if raw not in ("0", "1", "2", "-"):\n                cur.bad = True', "if False:\n                cur.bad = True"),
    "the mask fails open": (
        '            alert("data-mask-error", {"error": type(e).__name__})\n        except Exception:  # noqa: BLE001\n'
        "            pass\n        return strict",
        '            alert("data-mask-error", {"error": type(e).__name__})\n        except Exception:  # noqa: BLE001\n'
        "            pass\n        return []"),
    "any script after python3 is wal_note": (
        "if name in PYTHONS and p + 1 < len(words) and self.raw(words[p + 1]) in trusted:",
        "if name in PYTHONS and p + 1 < len(words):"),
    "two heredocs on one line are read": (
        'if len(pending) > 1:\n                    self.fail("two heredocs wait on one line")',
        "if False:\n                    pass"),
    "a backslash-joined unquoted heredoc is read": ('if not quoted and line.endswith("\\\\"):', "if False:"),
    "a newline in a substitution while a heredoc waits is read": (
        'if waiting:\n                    self.fail("a newline in a substitution while a heredoc waits")',
        "if False:\n                    pass"),
    "redirect words read as operands": (
        "def is_copy_command(words: list) -> bool:\n    words = _strip_redirects(words)",
        "def is_copy_command(words: list) -> bool:\n    words = list(words)"),
    "a glued redirect also drops the next word": ("i += 1 if m.group(1) else 2", "i += 2"),
    "long option values read as operands": (
        'i += 2 if "=" not in w and w in long_values else 1', "i += 1"),
    "short option values read as operands": ("i += 2 if letter == len(w) - 1 else 1", "i += 1"),
    "any remote last operand is remote": (
        "remote = bool(operands) and _remote(operands[-1]) and not any(_remote(p) for p in operands[:-1])",
        "remote = bool(operands) and _remote(operands[-1])"),
    "the volume is picked from a redirect": ("d = _copy_destination(w)", "d = _dest(w)"),
    "scp is not a copy": ('    if name == "scp":\n        # goodqa#17106', '    if False:\n        # goodqa#17106'),
    "an scp to a host is charged": (
        'return "r" in flags and len(operands) >= 2 and not _remote(operands[-1])',
        'return "r" in flags and len(operands) >= 2'),
    "scp option values read as operands": (
        'operands = _operands(words, SCP_VALUE_SHORT, frozenset())\n        return "r"',
        'operands = _operands(words, frozenset(), frozenset())\n        return "r"'),
    "the scp volume is read from its last word": (
        "        return _operands(words, SCP_VALUE_SHORT, frozenset())[-1:]\n", "        return _dest(words)\n"),
    "the refusal does not name the copy": (
        "low_disk_message(target, gb, fl, copy=_copy_verb(copying[0]))", "low_disk_message(target, gb, fl)"),
}


def run(tmp):
    done = subprocess.run([sys.executable, "-B", "-m", "unittest"] + CLASSES, cwd=str(tmp), capture_output=True,
                          text=True)
    out = done.stdout + done.stderr
    ran = re.search(r"^Ran (\d+) tests?", out, re.M)
    return done.returncode, int(ran.group(1)) if ran else -1, bool(re.search(r"^(FAIL|ERROR):", out, re.M))


def tree():
    tmp = Path(tempfile.mkdtemp(prefix="mutant-"))
    shutil.copytree(ROOT / "harness" / "hooks", tmp / "harness" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
    (tmp / "tests").mkdir()
    shutil.copy(ROOT / "tests" / "test_copy_hygiene_records.py", tmp / "tests")
    return tmp


def main():
    bad = 0
    tmp = tree()
    try:
        rc, control_count, _ = run(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("%-52s rc=%d tests=%d %s" % ("control (this tree)", rc, control_count, "passes" if rc == 0 else "FAILS"))
    if rc != 0 or control_count <= 0:
        return 1
    variants = [("%s (no fix)" % BASE, None)] + list(MUTANTS.items())
    for name, change in variants:
        tmp = tree()
        try:
            path = tmp / "harness" / "hooks" / HOOK
            if change is None:
                path.write_bytes(subprocess.run(["git", "-C", str(ROOT), "show", "%s:harness/hooks/%s" % (BASE, HOOK)],
                                                capture_output=True, check=True).stdout)
            else:
                text = path.read_text()
                if text.count(change[0]) != 1:
                    print("%-52s NOT APPLIED (found %d times)" % (name, text.count(change[0])))
                    bad += 1
                    continue
                path.write_text(text.replace(change[0], change[1], 1))
            rc, count, failed = run(tmp)
            killed = rc != 0 and failed and (count == control_count or change is None)
            print("%-52s rc=%d tests=%d %s" % (name, rc, count, "killed" if killed else "SURVIVED"))
            bad += 0 if killed else 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print("survivors or not applied: %d" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
