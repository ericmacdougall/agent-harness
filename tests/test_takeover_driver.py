import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('driver',ROOT/'install_goodqa_takeover.py')
driver=importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)

class DriverTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        records={}
        for name in driver.NAMES:
            p=self.root/name
            p.write_text('synthetic input')
            records[name]={'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
        self.manifest=self.root/'release.json'
        self.manifest.write_text(json.dumps(records))
        self.sha=hashlib.sha256(self.manifest.read_bytes()).hexdigest()

    def invoke(self,apply=False):
        args=['driver','--release',str(self.manifest),'--release-sha256',self.sha]
        if apply:
            args.append('--apply')
        with patch.object(sys,'argv',args):
            driver.main()

    def test_preview_and_apply_order(self):
        with patch.object(subprocess,'run') as run:
            self.invoke()
            self.assertEqual(run.call_count,2)
            self.assertNotIn('--apply',run.call_args_list[0].args[0])
            self.assertFalse(json.loads(run.call_args_list[1].kwargs['input'])['apply'])
        with patch.object(subprocess,'run') as run:
            self.invoke(True)
            self.assertEqual(run.call_count,4)
            self.assertIn('--apply',run.call_args_list[2].args[0])
            self.assertTrue(json.loads(run.call_args_list[3].kwargs['input'])['apply'])

    def test_bad_bundle_or_manifest_never_executes(self):
        (self.root/driver.NAMES[0]).write_text('changed')
        with patch.object(subprocess,'run') as run:
            with self.assertRaises(ValueError):
                self.invoke(True)
            run.assert_not_called()
        with self.assertRaises(ValueError):
            driver.release_files(self.manifest,'0'*64)

    def test_failed_preflight_stops_before_apply(self):
        with patch.object(subprocess,'run',side_effect=[None,subprocess.CalledProcessError(2,['ssh'])]) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                self.invoke(True)
            self.assertEqual(run.call_count,2)

    def test_failed_broker_phase_preserves_native_success_and_can_retry(self):
        with patch.object(subprocess,'run',side_effect=[None,None,None,subprocess.CalledProcessError(2,['ssh'])]) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                self.invoke(True)
            self.assertEqual(run.call_count,4)
        with patch.object(subprocess,'run') as run:
            self.invoke(True)
            self.assertEqual(run.call_count,4)

if __name__=='__main__':
    unittest.main()
