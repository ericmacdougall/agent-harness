"""Focused reporter packaging and interrupted-upgrade controls for both installers."""
from pathlib import Path
import hashlib
import importlib.util
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'harness/hooks'))
import install
import install_codex
import integrate_local as il

WORK = Path.home()/'.agent-harness/work/focused-node-test-fixtures'
WORK.mkdir(mode=0o700,parents=True,exist_ok=True)

class NodeReporterInstall(unittest.TestCase):
    def fixture(self, module):
        temporary=tempfile.TemporaryDirectory(dir=WORK); self.addCleanup(temporary.cleanup)
        home=Path(temporary.name)
        directory=home/('.claude/hooks' if module is install else '.codex/agent-harness')
        return home,directory

    def snapshot(self,home):
        return {str(p.relative_to(home)):p.read_bytes() for p in home.rglob('*') if p.is_file()
                and 'backups' not in p.parts and 'agent-harness-backups' not in p.parts}

    def test_both_installed_payloads_verify_without_source_imports(self):
        for module in (install,install_codex):
            with self.subTest(installer=module.__name__):
                home,directory=self.fixture(module)
                module.install(home,True,hooks_only=True)
                reporter=directory/'node_check_reporter.mjs'
                self.assertEqual(hashlib.sha256(reporter.read_bytes()).hexdigest(),il.NODE_REPORTER_SHA256)
                # Load the actual installed guard without touching any production install.
                spec=importlib.util.spec_from_file_location('installed_node_guard',directory/'integrate_local.py')
                guard=importlib.util.module_from_spec(spec); spec.loader.exec_module(guard)
                self.assertEqual(guard.node_reporter(),reporter)
                reporter.write_text('// replaced\n')
                with self.assertRaises(guard.CheckInterpreterError): guard.node_reporter()
                reporter.unlink()
                with self.assertRaises(guard.CheckInterpreterError): guard.node_reporter()

    def test_missing_source_reporter_is_refused_before_writes(self):
        original=Path.read_bytes
        for module in (install,install_codex):
            with self.subTest(installer=module.__name__):
                home,directory=self.fixture(module)
                def missing(path):
                    if path == ROOT/'harness/hooks/node_check_reporter.mjs': raise FileNotFoundError('fixture missing reporter')
                    return original(path)
                before=self.snapshot(home)
                with patch.object(Path,'read_bytes',missing),self.assertRaises(FileNotFoundError):
                    module.install(home,True,hooks_only=True)
                self.assertEqual(self.snapshot(home),before)

    def test_interrupted_reporter_upgrade_restores_old_pair(self):
        for module in (install,install_codex):
            with self.subTest(installer=module.__name__):
                home,directory=self.fixture(module)
                module.install(home,True,hooks_only=True)
                (directory/'integrate_local.py').write_text('# previous reviewed guard\n')
                (directory/'node_check_reporter.mjs').write_text('// previous reviewed reporter\n')
                before=self.snapshot(home)
                write=module.atomic_write
                def interrupted(path,data,mode=0o600,**kwargs):
                    if path == directory/'node_check_reporter.mjs': raise OSError('fixture interrupted reporter upgrade')
                    return write(path,data,mode,**kwargs)
                with patch.object(module,'atomic_write',side_effect=interrupted),self.assertRaisesRegex(OSError,'interrupted reporter'):
                    module.install(home,True,hooks_only=True)
                self.assertEqual(self.snapshot(home),before)
