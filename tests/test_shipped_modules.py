"""Every module under harness/hooks ships, or is listed here as deliberately not shipped (harness redesign 2026-11-24).

A module a shipped hook imports but the installer does not copy fails only on an installed host (ImportError at the
first call). These tests read the import statements, so a new helper cannot be forgotten in install.HOOKS or in
install_codex.DELIVERY_HELPERS.
"""

import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS_DIR = ROOT / 'harness' / 'hooks'
sys.path.insert(0, str(ROOT))

import install  # noqa: E402
import install_codex  # noqa: E402

# Files under harness/hooks that no installer copies, each with its reason.
NOT_SHIPPED = {
    'loss_inventory.py': 'a one-off host decommission scan tool, run from the checkout',
}
# Codex copies its own wal.py (codex/hooks/wal.py) and ops_watch.py by name, outside DELIVERY_HELPERS.
CODEX_SHIPPED_ELSEWHERE = {'wal.py', 'ops_watch.py'}
SHIPPED_SUFFIXES = ('.py', '.json')


def sibling_imports(path, modules):
    text = path.read_text()
    found = set()
    for m in re.finditer(r'^\s*(?:from\s+(\w+)\s+import|import\s+([\w, ]+))', text, re.M):
        names = [m.group(1)] if m.group(1) else [x.strip().split(' ')[0] for x in m.group(2).split(',')]
        found.update(n for n in names if n in modules)
    found.update(n for n in re.findall(r"import_module\(['\"](\w+)['\"]\)", text) if n in modules)
    return {n + '.py' for n in found}


def closure(start, modules):
    seen = {n for n in start if n.endswith('.py')}
    todo = list(seen)
    while todo:
        path = HOOKS_DIR / todo.pop()
        if not path.is_file():
            continue
        for dep in sibling_imports(path, modules):
            if dep not in seen:
                seen.add(dep)
                todo.append(dep)
    return seen


class ShippedModules(unittest.TestCase):
    def setUp(self):
        self.files = {p.name for p in HOOKS_DIR.iterdir() if p.is_file() and p.suffix in SHIPPED_SUFFIXES}
        self.modules = {p.stem for p in HOOKS_DIR.iterdir() if p.suffix == '.py'}

    def test_every_hooks_file_is_shipped_or_listed_as_not_shipped(self):
        missing = self.files - set(install.HOOKS) - set(NOT_SHIPPED)
        self.assertEqual(missing, set(), 'add these to install.HOOKS or to NOT_SHIPPED with a reason')
        self.assertEqual(set(NOT_SHIPPED) & set(install.HOOKS), set(), 'shipped now: drop from NOT_SHIPPED')

    def test_the_redesign_modules_ship_to_both_hosts(self):
        for name in ('ah_hook.py', 'ah_roles.py', 'ah_switch.py', 'ah_approvals.py', 'ah_secret.py', 'ah_log_push.py'):
            self.assertIn(name, install.HOOKS)
            self.assertIn(name, install_codex.DELIVERY_HELPERS)
        self.assertIn('ahc_merge.py', install.HOOKS)

    def test_every_import_of_a_shipped_claude_module_ships(self):
        needed = closure(install.HOOKS, self.modules)
        self.assertEqual(needed - set(install.HOOKS), set())

    def test_every_import_of_a_shipped_codex_module_ships(self):
        start = set(install_codex.DELIVERY_HELPERS)
        for path in (ROOT / 'codex' / 'hooks').glob('*.py'):
            start |= sibling_imports(path, self.modules)
        needed = closure(start, self.modules)
        self.assertEqual(needed - set(install_codex.DELIVERY_HELPERS) - CODEX_SHIPPED_ELSEWHERE, set())

    def test_the_reader_sees_lazy_imports(self):
        # a broken variant of the walker (top-level imports only) would miss these, and the tests above would pass
        self.assertIn('ah_approvals.py', sibling_imports(HOOKS_DIR / 'merge_gate.py', self.modules))


if __name__ == '__main__':
    unittest.main()
