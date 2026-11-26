"""Release 1001 deleted these modules (docs/direction.md, "What we took, and what we left"). Nothing that ships may
import, launch or register one, and the README and the operator docs name none of them (CHANGELOG.md and
docs/direction.md keep the history).

"Launch" is the file name in a string the code uses (not a comment or docstring): `python3 ~/.claude/hooks/X.py`.
install.py and install_codex.py are not scanned for that: they must name every retired script so an upgrade strips
its old registrations (install.managed_scripts, install_codex.known_commands, install.RETIRED_ALLOW_RULES).
"""
import ast
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS_DIR = ROOT / "harness" / "hooks"
sys.path.insert(0, str(ROOT))

import install  # noqa: E402

DELETED = (
    "command_guard", "command_guard_hook", "guard_selftest", "kill_guard", "heavy_job_guard", "agent_gate", "run_probe",
    "run_capped", "copy_hygiene", "lifecycle_cleanup", "shell_words", "shellwords", "provenance_hooks", "tier_gate",
    "mission_coverage", "mission_gate", "goals_view", "status_truth", "stop_blocks", "ask_reminders", "ahd", "ahd_peek",
    "doctor", "wal_cadence", "worktree_hygiene", "ledger_reminder", "bg_lint", "idle_guard", "mc_inbox",
    "central_decisions", "review_map", "remote_delete", "remote_delete_agent", "ah_install",
    "ahc_clock", "ahc_clone", "ahc_contracts", "ahc_core", "ahc_crash", "ahc_fs", "ahc_guard", "ahc_install",
    "ahc_merge", "ahc_migrate", "ahc_observe", "ahc_packet", "ahc_review", "ahc_runner", "ahc_scan", "ahc_shadow",
    "ahc_w21", "merge_gate", "commit_policy", "escalation", "spec_flow", "resource_budget",
)
DELETED_DATA = ("kill_guard_policy.json", "ahd_policy.json", "rules.json", "hooks_manifest.json", "ahc_release.json",
                "commit_policy.json", "spec_policy.json", "spec_template.md", "resource_limits.json")
DELETED_TREES = ("cmd", "internal", "console", "plugins/harness-tui", "native/codex", "testdata", "go.mod",
                 "install_tui_plugin.py")
# Shipped files that still name a deleted file, each with the reason it is not a launch of it. Keep this short.
KNOWN = {
    "harness/hooks/mc_chat.py": "its docstring records that mc_inbox.py (kill list) was deleted and the Claude reply "
                                "route with it; no code launches it",
}
# Docs this branch owns; the others are listed for the integrator (they still describe the deleted parts).
OPERATOR_DOCS = ("README.md", "docs/off-switch.md", "docs/local-config.md", "docs/operations.md",
                 "docs/harness-reference.md", "docs/architecture.md")


def docstring_nodes(tree):
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                out.add(id(first.value))
    return out


def problems_in(path: Path) -> list:
    text = path.read_text(errors="replace")
    found = []
    if path.suffix == ".py":
        tree = ast.parse(text)
        skip = docstring_nodes(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found += [f"imports {a.name}" for a in node.names if a.name in DELETED]
            elif isinstance(node, ast.ImportFrom) and node.module in DELETED:
                found.append(f"imports from {node.module}")
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip:
                for name in DELETED:
                    if re.search(r"(?<![\w.])%s\.py\b" % re.escape(name), node.value):
                        found.append(f"names {name}.py in a string")
                    if node.value == name and isinstance(node, ast.Constant):
                        pass  # a bare word ("ahd" in a process-name list) is not a launch
    else:
        for name in DELETED:
            if re.search(r"(?<![\w.])%s\.py\b" % re.escape(name), text):
                found.append(f"names {name}.py")
    return found


class NoDeletedReferences(unittest.TestCase):
    def test_the_deleted_files_are_gone(self):
        for name in DELETED:
            self.assertFalse((HOOKS_DIR / f"{name}.py").exists(), name)
        for name in DELETED_DATA:
            self.assertFalse((HOOKS_DIR / name).exists(), name)
        for rel in DELETED_TREES:
            self.assertFalse((ROOT / rel).exists(), rel)

    def test_nothing_shipped_imports_or_launches_a_deleted_module(self):
        shipped = [HOOKS_DIR / n for n in install.HOOKS if n.endswith(".py")]
        shipped += sorted((ROOT / "codex" / "hooks").glob("*.py")) + sorted((ROOT / "harness" / "bin").iterdir())
        bad = {str(p.relative_to(ROOT)): problems_in(p) for p in shipped if p.is_file()}
        bad = {k: v for k, v in bad.items() if v}
        for name in KNOWN:
            self.assertIn(name, bad, f"{name} no longer names a deleted file: drop it from KNOWN")
            bad.pop(name)
        self.assertEqual(bad, {})

    def test_nothing_ships_or_registers_a_deleted_module(self):
        names = {n.rsplit(".", 1)[0] for n in install.HOOKS}
        self.assertEqual(names & set(DELETED), set())
        self.assertEqual(set(install.HOOKS) & set(DELETED_DATA), set())
        registered = {Path(install.hook_argv(h)[0]).stem for groups in install.managed_hooks(Path("/x/.claude")).values()
                      for g in groups for h in g["hooks"]}
        self.assertEqual(registered & set(DELETED), set())

    def test_the_operator_docs_name_no_deleted_module(self):
        bad = {doc: problems_in(ROOT / doc) for doc in OPERATOR_DOCS}
        self.assertEqual({k: v for k, v in bad.items() if v}, {})

    def test_the_checker_can_fail(self):
        import tempfile  # noqa: PLC0415
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "x.py"
            sample.write_text('"""mentions command_guard.py in a docstring: fine"""\nimport os\n'
                              'CMD = ["python3", "~/.claude/hooks/kill_guard.py"]\n# idle_guard.py in a comment: fine\n')
            self.assertEqual(problems_in(sample), ["names kill_guard.py in a string"])
            sample.write_text("import tier_gate\nfrom ahd import host\n")
            self.assertEqual(sorted(problems_in(sample)), ["imports from ahd", "imports tier_gate"])


if __name__ == "__main__":
    unittest.main()
