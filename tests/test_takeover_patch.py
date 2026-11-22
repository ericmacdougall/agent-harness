import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'takeover_patch.py'
spec = importlib.util.spec_from_file_location('takeover_patch', MODULE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class PatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.target = self.home / '.claude/hooks/native_main.py'
        self.target.parent.mkdir(parents=True, mode=0o700)
        self.old = b'value = 1\n'
        self.new = b'value = 2\n'
        self.target.write_bytes(self.old)
        self.target.chmod(0o600)
        self.manifest = {'version':1, 'id':'takeover-test-001', 'files':[
            {'target':'.claude/hooks/native_main.py', 'before':{'local':module.digest(self.old), 't2-dev':module.digest(self.old)}, 'after':module.digest(self.new), 'content':base64.b64encode(self.new).decode()}]}

    def run_action(self, action):
        return module.worker(self.manifest, 'local', action, self.home)

    def test_plan_apply_idempotence_rollback(self):
        self.assertEqual(self.run_action('plan')['status'], 'READY')
        self.assertFalse((self.home / '.agent-harness').exists())
        self.assertEqual(self.run_action('apply')['status'], 'APPLIED')
        self.assertEqual(self.target.read_bytes(), self.new)
        self.run_action('apply')
        self.run_action('rollback')
        self.assertEqual(self.target.read_bytes(), self.old)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)
        self.run_action('rollback')

    def test_unknown_installed_bytes_refused_without_mutation(self):
        self.target.write_bytes(b'value = 3\n')
        with self.assertRaises(ValueError):
            self.run_action('apply')
        self.assertFalse((self.home / '.agent-harness').exists())

    def test_symlink_target_and_parent_refused(self):
        self.target.rename(self.target.with_suffix('.save'))
        self.target.symlink_to(self.target.with_suffix('.save'))
        with self.assertRaises(ValueError):
            self.run_action('apply')
        self.target.unlink()
        self.target.parent.rename(self.home / 'saved-hooks')
        self.target.parent.symlink_to(self.home / 'saved-hooks')
        with self.assertRaises(ValueError):
            self.run_action('apply')

    def test_bad_digest_and_escape_refused(self):
        self.manifest['files'][0]['after'] = '0' * 64
        with self.assertRaises(ValueError):
            self.run_action('apply')
        self.manifest['files'][0]['target'] = '.claude/hooks/../../evil.py'
        with self.assertRaises(ValueError):
            self.run_action('apply')

    def test_concurrent_changes_preserved_on_rollback(self):
        self.run_action('apply')
        other = b'value = 99\n'
        self.target.write_bytes(other)
        with self.assertRaises(ValueError):
            self.run_action('rollback')
        self.assertEqual(self.target.read_bytes(), other)

    def test_identity_reuse_refused(self):
        self.run_action('apply')
        self.manifest['extra'] = True
        with self.assertRaises(ValueError):
            self.run_action('apply')

    def test_failed_second_write_restores_first(self):
        second = self.home / '.codex/agent-harness/native_main.py'
        second.parent.mkdir(parents=True, mode=0o700)
        second.write_bytes(self.old)
        second.chmod(0o600)
        self.manifest['files'].append(dict(self.manifest['files'][0], target='.codex/agent-harness/native_main.py'))
        real = module.atomic
        def fail(path, data, mode):
            if path == second and data == self.new:
                raise OSError('synthetic disk full')
            return real(path, data, mode)
        with patch.object(module, 'atomic', side_effect=fail):
            with self.assertRaises(OSError):
                self.run_action('apply')
        self.assertEqual(self.target.read_bytes(), self.old)
        self.assertEqual(second.read_bytes(), self.old)

    def test_postreplace_failure_restores_module(self):
        real = module.atomic
        fired = []
        def fail(path, data, mode):
            real(path, data, mode)
            if path == self.target and data == self.new and not fired:
                fired.append(True)
                raise OSError('synthetic fsync failure after replacement')
        with patch.object(module, 'atomic', side_effect=fail):
            with self.assertRaises(OSError):
                self.run_action('apply')
        self.assertEqual(self.target.read_bytes(), self.old)

    def test_resume_after_backup_before_mode(self):
        real = module.atomic
        def fail(path, data, mode):
            if path.name == '0.mode':
                raise OSError('synthetic stop before mode save')
            real(path, data, mode)
        with patch.object(module, 'atomic', side_effect=fail):
            with self.assertRaises(OSError):
                self.run_action('apply')
        self.run_action('apply')
        self.assertEqual(self.target.read_bytes(), self.new)
        self.run_action('rollback')
        self.assertEqual(self.target.read_bytes(), self.old)

    def test_stale_scratch_is_preserved_and_retry_succeeds(self):
        stale = self.target.with_name(self.target.name + '.takeover-pending')
        stale.write_bytes(b'earlier interrupted write')
        self.run_action('apply')
        self.assertEqual(self.target.read_bytes(), self.new)
        self.assertEqual(stale.read_bytes(), b'earlier interrupted write')

    def test_subprocess_worker_protocol(self):
        import subprocess,sys
        source = MODULE.read_text().split('\n# TAKEOVER_CLI_ENTRY\n')[0]
        source += '\nrequest=json.loads(sys.stdin.read())\nprint(json.dumps(worker(request["manifest"],"local","apply",request["home"])))\n'
        result = subprocess.run([sys.executable,'-B','-c',source],input=json.dumps({'manifest':self.manifest,'home':str(self.home)}).encode(),capture_output=True,check=True)
        self.assertEqual(json.loads(result.stdout)['status'],'APPLIED')
        self.assertEqual(self.target.read_bytes(),self.new)

if __name__ == '__main__':
    unittest.main()
