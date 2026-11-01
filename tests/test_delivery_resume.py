"""Explicit interrupted-delivery resume in owned disposable repositories."""

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import test_delivery_workflow as workflow


class RemoteResume(unittest.TestCase):
    def setUp(self):
        self.fixture = workflow.DeliveryWorkflow()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.counter = self.fixture.root / 'checks-executed'
        self.fixture.env['FIXTURE_RESUME_COUNTER'] = str(self.counter)
        self.fixture.replace_feature_tests(
            'import os,unittest\nfrom pathlib import Path\n'
            'class ResumeCheck(unittest.TestCase):\n'
            '    def test_feature(self):\n'
            '        p=Path(os.environ["FIXTURE_RESUME_COUNTER"])\n'
            '        p.write_text(str(int(p.read_text())+1) if p.exists() else "1")\n'
            '        self.assertEqual(Path("app.txt").read_text(), "feature\\n")\n')
        self.fixture.configure_github()

    def pending(self, *, preparations=()):
        fixture = self.fixture
        prepared, data = fixture.invoke(*fixture.prepare_args())
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        self.generation = data['generation']
        self.target = fixture.merge_remote()
        arguments = fixture.finish_args('remote', self.generation)
        for command in preparations:
            arguments.extend(('--prepare', command))
        code, failed = fixture.direct_finish(
            lambda module: mock.patch.object(module, 'run_checks', side_effect=
                module.DeliveryError('DELIVERED_CHECK_FAILED', 'Fixture interrupted checks')),
            arguments=arguments)
        self.assertEqual((code, failed['status']), (3, 'RECOVERY_REQUIRED'), failed)
        self.state_path = Path(failed['state'])
        self.guard_path = Path(failed['recovery_journal'])
        self.assertEqual(json.loads(self.guard_path.read_text())['phase'], 'applying')
        self.assertFalse(self.counter.exists())

    def resume_args(self):
        return [*self.fixture.finish_args('remote', self.generation), '--resume',
                '--resume-reason', 'Fixture supervisor interruption',
                '--kit-file', str(self.fixture.kit)]

    def test_explicit_pending_resume_runs_one_fresh_check(self):
        self.pending()
        fixture = self.fixture
        old, refusal = fixture.invoke(*fixture.finish_args('remote', self.generation))
        self.assertEqual((old.returncode, refusal['status']), (3, 'RECOVERY_REQUIRED'))
        self.assertFalse(self.counter.exists())
        broken, blocked = fixture.direct_finish(
            lambda module: mock.patch.object(module, 'resume_remote_finish',
                side_effect=lambda flow, preparations, checks: module.remote_finish(flow, preparations, checks)),
            arguments=self.resume_args())
        self.assertEqual((broken, blocked['status']), (3, 'RECOVERY_REQUIRED'))
        self.assertFalse(self.counter.exists(), 'The old pending-refusal path cannot claim fresh verification')
        result = workflow.command(sys.executable, str(workflow.DELIVER), *self.resume_args(),
                                  env=fixture.env, check=False)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        outcome = json.loads(result.stdout)
        self.assertEqual((outcome['status'], outcome['head']), ('DELIVERED', self.target))
        self.assertEqual(self.counter.read_text(), '1')
        self.assertEqual(workflow.command('git', 'status', '--porcelain', cwd=fixture.original,
                                          env=fixture.env).stdout, '')
        self.assertEqual(json.loads(self.state_path.read_text())['source_head'], fixture.head)
        self.assertTrue(Path(outcome['resume_record']).is_file())
