"""Fails the suite on new unbounded reads in harness/hooks (devices, FIFOs and huge files must never be read whole).

Flagged calls: `.read()` or `.readline()` with no size, `.readlines()`, `.read_text()`, `.read_bytes()`,
`json.load(f)` and `sys.stdin.read()` with no size. Use harness/hooks/safe_input.py instead, or add
`# input-ok: <why this input is bounded or trusted>` on the call line or the line above.

Existing hooks that predate safe_input are held to a ratchet: BASELINE may only go down. Migrating a hook
means deleting its entry (GoodQA ticket: migrate hooks to safe_input).
"""

import ast
import collections
import re
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parent.parent / "harness" / "hooks"
ALLOW = re.compile(r"#\s*input-ok:\s*\S")
# file -> number of unannotated unbounded reads that existed before safe_input. Only ever decrease these.
BASELINE = {"commit_policy.py": 7, "deliver.py": 2, "peer_review.py": 2, "spec_flow.py": 13, "wal.py": 1, "workdir.py": 4}
# Counts are the ratchet; this also pins each baselined call by its source line so swapping an old violation for a
# new one fails. Delete a line from here when you migrate it (fill with `python3 tests/test_input_lint.py --pins`).
PINS = {'commit_policy.py': ['_HOOK_STATE["raw"] = sys.stdin.buffer.read().decode("utf-8", errors="replace")',
                      'message = Path(args.file).read_text(encoding="utf-8") if args.file else '
                      'sys.stdin.read()',
                      'message = Path(args.file).read_text(encoding="utf-8") if args.file else '
                      'sys.stdin.read()',
                      'message = normalize(Path(path).read_text(encoding="utf-8", errors="replace"), '
                      'strip_commen',
                      'parts.append(path.read_text(encoding="utf-8", errors="replace"))',
                      'policy = json.load(handle)',
                      'previous = Path(args.previous_file).read_text(encoding="utf-8") if args.previous_file '
                      'else'],
 'deliver.py': ['and (hooks / name).read_bytes() == data for name, data in observed.items())',
                'observed = {name: (hooks / name).read_bytes() for name in names}'],
 'peer_review.py': ["last_message = last.read_text(errors='replace') if last.exists() else ''",
                    'listed = set(boundary.read_text().split() if boundary.exists() else ())'],
 'spec_flow.py': ['"spec_file_sha": sha256_bytes(spec_path.read_bytes()),',
                  '("reviews", reviews_path(spec_path).name, "text/plain", '
                  'reviews_path(spec_path).read_bytes',
                  'code, text = plan_ticket_gate(Path(args.repo), '
                  'Path(args.packet).read_text(encoding="utf-8',
                  'data = json.loads(path.read_text(encoding="utf-8"))',
                  'files = [("spec", spec_path.name, "text/markdown", spec_path.read_bytes()),',
                  'payload = json.load(sys.stdin)',
                  'policy = json.load(handle)',
                  'text = Path(args.spec).read_text(encoding="utf-8")',
                  'text = Path(args.spec).read_text(encoding="utf-8")',
                  'text = TEMPLATE_FILE.read_text(encoding="utf-8").format(',
                  'text = spec_path.read_text(encoding="utf-8")',
                  'text = spec_path.read_text(encoding="utf-8")',
                  'text = spec_path.read_text(encoding="utf-8")'],
 'wal.py': ['data = json.load(sys.stdin)'],
 'workdir.py': ['config = json.loads(path.read_text())',
                'lines = handle.read().splitlines()',
                'recorded = json.loads(marker.read_text()).get("session_id")',
                'state = json.loads((home() / ".agent-harness" / "install-state.json").read_text())']}


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
                continue
            pinned = collections.Counter(PINS.get(path.name, []))
            for line, call, text in found:  # same count but a different call: an old violation was swapped for a new one
                if pinned[text] > 0:
                    pinned[text] -= 1
                else:
                    problems.append(f"{path.name}:{line}: unbounded {call} is not in the baseline: {text}")
        self.assertEqual(problems, [], "use safe_input (read_bounded, read_tail, read_stdin_bounded, safe_json_loads, "
                                      "iter_jsonl_lines) or annotate with `# input-ok: <reason>`")

    def test_baseline_only_shrinks(self):
        stale = [name for name, count in BASELINE.items() if len(violations(HOOKS / name)) < count]
        self.assertEqual(stale, [], "lower BASELINE for these files (they were migrated)")

    def test_swapping_a_baselined_violation_for_a_new_one_fails(self):
        import shutil
        import tempfile
        global HOOKS
        original = HOOKS
        with tempfile.TemporaryDirectory() as tmp:
            for name in BASELINE:
                shutil.copy(original / name, Path(tmp) / name)
            target = Path(tmp) / "wal.py"
            text = target.read_text()
            self.assertIn("json.load(sys.stdin)", text)
            target.write_text(text.replace("json.load(sys.stdin)", "json.load(sys.stdin)  # old") .replace("def safe_id", "def _x(f):\n    return f.readlines()\n\n\ndef safe_id", 1))
            HOOKS = Path(tmp)
            try:
                found = violations(target)
                pinned = collections.Counter(PINS["wal.py"])
                new = [text for _, _, text in found if pinned[text] == 0 or not pinned.subtract([text])]
            finally:
                HOOKS = original
        self.assertTrue(any("readlines" in line for line in new))

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
