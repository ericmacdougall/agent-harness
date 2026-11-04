"""deliver.py with the commit policy: ticket freshness at prepare, ticket comments at finish."""

import json
import shutil
import sys
import unittest
from datetime import datetime, timezone

import test_delivery_workflow as workflow
from commit_messages import message
from test_commit_policy import FakeGoodQA


class TicketDelivery(workflow.DeliveryWorkflow):
    """Reuses the delivery fixture with a hooks copy whose policy points at a fake GoodQA."""

    def setUp(self):
        super().setUp()
        self.fake = FakeGoodQA()
        self.addCleanup(self.fake.close)
        hooks = self.root / 'hooks'
        shutil.copytree(workflow.DELIVER.parent, hooks, ignore=shutil.ignore_patterns('__pycache__'))
        key = self.home / 'member.key'
        key.write_text('test-key\n')
        key.chmod(0o600)
        policy = json.loads((hooks / 'commit_policy.json').read_text())
        policy['ticket_systems']['goodqa'].update(endpoint=self.fake.url, key_file=str(key), org_id='org-1',
                                                  repos=['github\\.com[:/]fixture/'], timeout_seconds=5,
                                                  total_deadline_seconds=20)
        (hooks / 'commit_policy.json').write_text(json.dumps(policy))
        self.deliver = hooks / 'deliver.py'
        self.issue = self.fake.add_issue(7)
        workflow.command('git', 'remote', 'set-url', 'origin', 'https://github.com/fixture/project.git',
                         cwd=self.original, env=self.env)
        workflow.command('git', 'commit', '-q', '--amend', '-m',
                         message('add the fixture feature', kind='feat', scope='app', refs='GoodQA #7'),
                         cwd=self.source, env=self.env)
        self.head = workflow.command('git', 'rev-parse', 'HEAD', cwd=self.source, env=self.env).stdout.strip()

    def run_deliver(self, *args):
        result = workflow.command(sys.executable, str(self.deliver), *args, env=self.env, check=False)
        self.assertTrue(result.stdout, result.stderr)
        return result.returncode, json.loads(result.stdout)

    def test_prepare_requires_fresh_ticket_and_finish_comments_once(self):
        prepare = (*self.prepare_args(), '--local-only')
        code, report = self.run_deliver(*prepare)
        self.assertEqual((code, report['status']), (2, 'BLOCKED_COMMIT_POLICY'), report)
        self.assertIn('GoodQA', report['commit_policy'])
        self.assertIn('STALE', report['commit_policy'])
        self.assertNotIn('generation', report, 'a refused prepare must not create delivery state')

        self.fake.fail = 'reset'
        code, report = self.run_deliver(*prepare)
        self.assertEqual((code, report['status']), (6, 'TICKETS_UNVERIFIED'), report)
        self.assertNotIn('generation', report)

        self.fake.fail = None
        self.fake.comment(self.issue, f'Implemented in {self.head[:10]}', datetime.now(timezone.utc))
        code, report = self.run_deliver(*prepare)
        self.assertEqual((code, report['status']), (0, 'LOCAL_READY'), report)

        code, report = self.run_deliver(*self.finish_args(mode='local'))
        self.assertEqual((code, report['status']), (0, 'LOCAL_DELIVERED'), report)
        self.assertEqual(report['ticket_updates']['status'], 'UPDATED', report)
        self.assertEqual(len(self.fake.posted), 1)
        body = self.fake.posted[0]['body']
        self.assertTrue(body.startswith('**Delivered to the local checkout only'), body)
        self.assertIn(workflow.CHECK, body)

        code, report = self.run_deliver(*self.finish_args(mode='local'))
        self.assertEqual((code, report['status']), (0, 'ALREADY_DELIVERED'), report)
        self.assertEqual(len(self.fake.posted), 1, 'a repeat must not duplicate the ticket comment')

        self.fake.fail = 'reset'
        code, report = self.run_deliver(*self.finish_args(mode='local'))
        self.assertEqual((code, report['status'], report['ticket_updates']['status']),
                         (5, 'ALREADY_DELIVERED', 'PENDING'), report)
        self.assertIn('notify', report['ticket_updates']['retry'])

    def test_missing_ticket_blocks(self):
        self.fake.issues.clear()
        code, report = self.run_deliver(*self.prepare_args(), '--local-only')
        self.assertEqual((code, report['status']), (2, 'BLOCKED_COMMIT_POLICY'))
        self.assertIn('MISSING', report['commit_policy'])

    def test_noncompliant_pr_title_blocks_remote_prepare(self):
        self.configure_github()
        self.fake.comment(self.issue, f'Implemented in {self.head[:10]}', datetime.now(timezone.utc))
        args = list(self.prepare_args())
        args[args.index('--pr-title') + 1] = 'Feature fixture'
        code, report = self.run_deliver(*args)
        self.assertEqual((code, report['status']), (2, 'BLOCKED_COMMIT_POLICY'), report)
        self.assertIn('PR title/body', report['commit_policy'])


# Run only the tests defined here, not the inherited workflow suite.
for _name in dir(workflow.DeliveryWorkflow):
    if _name.startswith('test_') and _name not in vars(TicketDelivery):
        setattr(TicketDelivery, _name, None)


if __name__ == '__main__':
    unittest.main()
