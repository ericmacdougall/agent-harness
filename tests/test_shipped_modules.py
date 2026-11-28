"""What ships beside the hooks is exactly the import closure of the entry points, plus the data files they read.

A module a shipped hook imports but the installer does not copy fails only on an installed host (ImportError at the
first call); a shipped module nothing reaches is dead weight that keeps a deleted part alive. These tests read the
import statements (lazy imports included), so install.HOOKS cannot drift either way, and they import every shipped
module under the macOS system python (3.9) with -I in a temporary HOME.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS_DIR = ROOT / 'harness' / 'hooks'
sys.path.insert(0, str(ROOT))

import install  # noqa: E402

try:
    import install_codex  # noqa: E402
except (ImportError, SyntaxError):  # Python < 3.11 has no tomllib
    install_codex = None

# Files under harness/hooks that no installer copies, each with its reason.
NOT_SHIPPED = {
    'loss_inventory.py': 'a one-off host decommission scan tool, run from the checkout',
}
# Codex copies its own wal.py (codex/hooks/wal.py) and ops_watch.py by name, outside DELIVERY_HELPERS.
CODEX_SHIPPED_ELSEWHERE = {'wal.py', 'ops_watch.py'}
SHIPPED_SUFFIXES = ('.py', '.json', '.md', '.mjs', '.conf')


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
        self.assertEqual(missing, set(), 'add these to install.HOOKS or to NOT_SHIPPED with a reason, or delete them')
        self.assertEqual(set(NOT_SHIPPED) & set(install.HOOKS), set(), 'shipped now: drop from NOT_SHIPPED')
        self.assertEqual(len(install.HOOKS), len(set(install.HOOKS)), 'a name is listed twice')

    def test_every_shipped_file_exists(self):
        self.assertEqual([n for n in install.HOOKS if not (HOOKS_DIR / n).is_file()], [])

    def test_every_import_of_a_shipped_claude_module_ships(self):
        needed = closure(install.HOOKS, self.modules)
        self.assertEqual(needed - set(install.HOOKS), set())

    def test_every_shipped_module_is_reachable_from_an_entry_point(self):
        reachable = closure(install.ENTRY_POINTS, self.modules)
        shipped = {n for n in install.HOOKS if n.endswith('.py')}
        self.assertEqual(shipped - reachable, set(), 'shipped but nothing reaches it: delete it or name its entry point')
        self.assertEqual(reachable - shipped, set())

    def test_every_shipped_data_file_is_read_by_a_shipped_module_or_script(self):
        texts = [(HOOKS_DIR / n).read_text() for n in install.HOOKS if n.endswith('.py')]
        texts += [p.read_text(errors='replace') for p in (ROOT / 'harness' / 'bin').iterdir() if p.is_file()]
        for name in install.HOOKS:
            if name.endswith('.py'):
                continue
            self.assertIn(name, install.DATA_FILES)
            self.assertTrue(any(name in text for text in texts), f'{name} ships but nothing names it')

    def test_the_registered_hooks_and_the_dispatched_modules_are_entry_points(self):
        claude = Path('/x/.claude')
        registered = {os.path.basename(install.hook_argv(h)[0]) for groups in install.managed_hooks(claude).values()
                      for g in groups for h in g['hooks']}
        self.assertLessEqual(registered | {'ah_hook.py', 'ah.py'}, set(install.ENTRY_POINTS))
        for name in ('ah_sandbox.py', 'ah_doctor.py', 'ah_repo.py', 'ah_switch.py', 'ah_reap.py', 'ah_secret.py',
                     'ah_log_push.py', 'ah_kill.py', 'ah_worktree.py', 'ah_approvals.py'):
            self.assertIn(name, install.ENTRY_POINTS)
        self.assertIn('sandbox_base.json', install.DATA_FILES)

    @unittest.skipUnless(install_codex is not None, 'install_codex needs Python 3.11')
    def test_the_redesign_modules_ship_to_both_hosts(self):
        for name in ('ah_hook.py', 'ah_roles.py', 'ah_switch.py', 'ah_approvals.py', 'ah_secret.py', 'ah_log_push.py',
                     'git_save.py', 'ah_reap.py', 'session_env.py', 'autosave.py', 'ah_sandbox.py', 'ah_doctor.py',
                     'ah_repo.py', 'sandbox_base.json'):
            self.assertIn(name, install.HOOKS)
            self.assertIn(name, install_codex.DELIVERY_HELPERS)

    @unittest.skipUnless(install_codex is not None, 'install_codex needs Python 3.11')
    def test_every_import_of_a_shipped_codex_module_ships(self):
        start = set(install_codex.DELIVERY_HELPERS)
        for path in (ROOT / 'codex' / 'hooks').glob('*.py'):
            start |= sibling_imports(path, self.modules)
        needed = closure(start, self.modules)
        self.assertEqual(needed - set(install_codex.DELIVERY_HELPERS) - CODEX_SHIPPED_ELSEWHERE, set())

    def test_the_reader_sees_lazy_imports(self):
        # a broken variant of the walker (top-level imports only) would miss these, and the tests above would pass
        self.assertIn('ah_approvals.py', sibling_imports(HOOKS_DIR / 'ah_kill.py', self.modules))

    @unittest.skipUnless(Path('/usr/bin/python3').exists(), 'no system python3')
    def test_every_shipped_module_imports_under_the_system_python_isolated(self):
        with tempfile.TemporaryDirectory(prefix='ah-shipped-') as tmp:
            hooks = Path(tmp) / 'hooks'
            hooks.mkdir()
            for name in install.HOOKS:
                shutil.copy(HOOKS_DIR / name, hooks / name)
            names = sorted(n[:-3] for n in install.HOOKS if n.endswith('.py'))
            code = ('import importlib, sys\nsys.path.insert(0, sys.argv[1])\nbad = []\n'
                    'for name in sys.argv[2:]:\n'
                    '    try:\n        importlib.import_module(name)\n'
                    '    except Exception as e:\n        bad.append("%s: %s: %s" % (name, type(e).__name__, e))\n'
                    'print("\\n".join(bad))\nsys.exit(1 if bad else 0)\n')
            env = {'HOME': str(Path(tmp) / 'home'), 'PATH': '/usr/bin:/bin'}
            (Path(tmp) / 'home').mkdir()
            done = subprocess.run(['/usr/bin/python3', '-I', '-c', code, str(hooks), *names], capture_output=True,
                                  text=True, env=env, timeout=300, cwd=tmp)
            self.assertEqual(done.returncode, 0, done.stdout[-3000:] + done.stderr[-2000:])


if __name__ == '__main__':
    unittest.main()
