"""Cross-generation delivery recovery with real Git and explicit resolution."""

import json
from pathlib import Path
import shutil
import sys
import unittest

import test_delivery_workflow as workflow


class LocalGenerationRetry(unittest.TestCase):
    def setUp(self):
        self.fixture = workflow.DeliveryWorkflow()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.cleanup_preserved_history)

    def cleanup_preserved_history(self):
        root = self.fixture.original / '.git' / 'agent-harness' / 'delivery-scratch'
        for journal in root.glob('scopes/*/history/*/*/journal.json'):
            record = json.loads(journal.read_text())
            if record.get('schema') != 2 or 'container' not in record:
                continue
            container = Path(record['container'])
            if not container.exists():
                continue
            info = container.stat()
            self.assertTrue(container.name.startswith('agent-harness-delivery-scratch-'))
            self.assertEqual((info.st_dev, info.st_ino), (record['container_dev'], record['container_ino']))
            shutil.rmtree(container)

    def test_same_tuple_new_generation_retries_after_explicit_resolution(self):
        fixture = self.fixture
        prepared, first = fixture.invoke(*fixture.prepare_args(), '--local-only')
        self.assertEqual((prepared.returncode, first['status']), (0, 'LOCAL_READY'), prepared.stdout)
        fixture.env['FIXTURE_DEPENDENCY'] = 'unavailable'
        failed, outcome = fixture.invoke(*fixture.finish_args('local'))
        self.assertEqual((failed.returncode, outcome['status']), (3, 'RECOVERY_REQUIRED'), failed.stdout)
        self.assertEqual(workflow.command('git', 'rev-parse', 'HEAD', cwd=fixture.original,
                                          env=fixture.env).stdout.strip(), fixture.base)
        root = fixture.original / '.git' / 'agent-harness' / 'delivery-scratch'
        active = list(root.glob('scopes/*/active/*/journal.json'))
        self.assertEqual(len(active), 1)
        key = active[0].parent.name
        fixture.env.pop('FIXTURE_DEPENDENCY')
        resolved = workflow.command(sys.executable, str(workflow.DELIVER.with_name('integrate_local.py')),
                    '--repo', str(fixture.original), '--original-branch', 'main', '--expected-head', fixture.base,
                    '--resolve-journal', key, '--check', workflow.CHECK, env=fixture.env, check=False)
        self.assertEqual((resolved.returncode, json.loads(resolved.stdout)['status']), (0, 'RESOLVED'), resolved.stdout)
        baseline, accepted = fixture.invoke(*fixture.baseline_args(fixture.base))
        self.assertEqual((baseline.returncode, accepted['status']), (0, 'RESOLVED_BASELINE'), baseline.stdout)
        archived = list(root.glob('scopes/*/archive/' + key + '/journal.json'))
        self.assertEqual(len(archived), 1)
        old_record = archived[0].read_bytes()
        again, second = fixture.invoke(*fixture.prepare_args(), '--local-only', '--new-generation')
        self.assertEqual((again.returncode, second['status']), (0, 'LOCAL_READY'), again.stdout)
        self.assertNotEqual(second['generation'], first['generation'])
        delivered, final = fixture.invoke(*fixture.finish_args('local', second['generation']))
        self.assertEqual((delivered.returncode, final['status']), (0, 'LOCAL_DELIVERED'), delivered.stdout)
        self.assertEqual((fixture.original / 'app.txt').read_text(), 'feature\n')
        self.assertEqual(workflow.command('git', 'status', '--porcelain', cwd=fixture.original,
                                          env=fixture.env).stdout, '')
        retained = [path.read_bytes() for path in root.glob('scopes/*/history/' + key + '/*/journal.json')]
        self.assertIn(old_record, retained)


if __name__ == '__main__':
    unittest.main()
