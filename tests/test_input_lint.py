"""Fails the suite on new unbounded reads in harness/hooks (devices, FIFOs and huge files must never be read whole).

Flagged calls: `.read()` or `.readline()` with no size, `.readlines()`, `.read_text()`, `.read_bytes()`,
`json.load(f)` and `sys.stdin.read()` with no size. Use harness/hooks/safe_input.py instead, or add
`# input-ok: <why this input is bounded or trusted>` on the call line or the line above.

Existing hooks that predate safe_input are held to a ratchet: BASELINE may only go down. Migrating a hook
means deleting its entry (GoodQA ticket: migrate hooks to safe_input).
"""

import ast
import re
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parent.parent / "harness" / "hooks"
ALLOW = re.compile(r"#\s*input-ok:\s*\S")
# file -> number of unannotated unbounded reads that existed before safe_input. Only ever decrease these.
BASELINE = {"commit_policy.py": 7, "deliver.py": 2, "peer_review.py": 2, "spec_flow.py": 13, "wal.py": 1, "workdir.py": 4}


def violations(path: Path) -> list:
    source = path.read_text(encoding="utf-8")  # input-ok: repository source file under test
    lines = source.split("\n")
    found = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        name = node.func.attr
        first = node.args[0] if node.args else (node.keywords[0].value if node.keywords else None)
        unbounded_arg = (isinstance(first, ast.Constant) and first.value in (None, -1)) \
            or (isinstance(first, ast.UnaryOp) and isinstance(first.operand, ast.Constant) and first.operand.value == 1)
        sized = first is not None and not unbounded_arg
        owner = node.func.value
        bad = ((name in ("read", "readline") and not sized)
               or name in ("readlines", "read_text", "read_bytes")
               or (name == "load" and isinstance(owner, ast.Name) and owner.id in ("json", "j")))
        if not bad:
            continue
        here = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
        above = lines[node.lineno - 2] if node.lineno >= 2 else ""
        if ALLOW.search(here) or ALLOW.search(above):
            continue
        found.append((node.lineno, f"{name}()", here.strip()[:90]))
    return found


class UnboundedReads(unittest.TestCase):
    def test_no_new_unbounded_reads_in_hooks(self):
        problems = []
        for path in sorted(HOOKS.glob("*.py")):
            found = violations(path)
            allowed = BASELINE.get(path.name, 0)
            if len(found) > allowed:
                problems.extend(f"{path.name}:{line}: unbounded {call}: {text}" for line, call, text in found)
        self.assertEqual(problems, [], "use safe_input (read_bounded, read_tail, read_stdin_bounded, safe_json_loads, "
                                      "iter_jsonl_lines) or annotate with `# input-ok: <reason>`")

    def test_baseline_only_shrinks(self):
        stale = [name for name, count in BASELINE.items() if len(violations(HOOKS / name)) < count]
        self.assertEqual(stale, [], "lower BASELINE for these files (they were migrated)")

    def test_the_lint_itself_catches_the_patterns(self):  # failing control: not vacuous
        import tempfile
        sample = ("import json, sys\nf = open('x')\nf.read()\nf.readlines()\njson.load(f)\nsys.stdin.read()\n"
                  "f.read(10)\nP.read_text()\nf.readline()\n# input-ok: tiny config\nf.read()\n")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.py"
            path.write_text(sample)
            self.assertEqual([call for _, call, _ in violations(path)],
                             ["read()", "readlines()", "load()", "read()", "read_text()", "readline()"])


if __name__ == "__main__":
    unittest.main()
