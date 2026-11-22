"""Native click tester identity and report authorship, with owned SQLite fixtures."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import test_spec_flow_native_review as fixtures
REVIEWER, OTHER = fixtures.REVIEWER, fixtures.OTHER
import spec_flow as sf


class NativeClick(unittest.TestCase):
    setUp = fixtures.NativeSpecReview.setUp
    child = fixtures.NativeSpecReview.child

    def fixture(self):
        self.child(REVIEWER, 'harness_click_tester')
        self.db.execute('ALTER TABLE threads ADD COLUMN rollout_path TEXT')
        self.rollout = self.home / '.codex/sessions/2026/11/22/tester.jsonl'
        self.rollout.parent.mkdir(parents=True)
        for path in (self.home / '.codex/sessions', *list(self.rollout.parents)[:3]):
            path.chmod(0o700)
        self.sha = hashlib.sha256(self.report.read_bytes()).hexdigest()
        self.final = {'timestamp':'2026-11-22T19:00:00Z','type':'response_item',
                      'payload':{'type':'message','role':'assistant','channel':'final',
                                 'content':[{'type':'output_text','text':'REPORT_SHA256 '+self.sha}]}}
        self.write_final()
        self.db.execute('UPDATE threads SET rollout_path=? WHERE id=?', (str(self.rollout), REVIEWER))
        self.db.commit()

    def write_final(self):
        self.rollout.write_text(json.dumps({'type':'session_meta','payload':{'id':REVIEWER}})+'\n'+json.dumps(self.final)+'\n')
        self.rollout.chmod(0o600)

    def get(self, sha=None):
        return sf._native_click_tester(self.wal.parent, REVIEWER, sha or self.sha)

    def test_native_report_digest_bound_to_tester_final(self):
        self.fixture()
        tester = self.get()
        self.assertEqual(tester['agent_type'], 'harness_click_tester')
        self.assertEqual(tester['family'], 'codex')
        self.assertEqual(tester['identity'], REVIEWER)

    def test_click_command_records_native_tester_without_legacy_wal(self):
        self.report.write_text('CLICK_TEST_RESULT: PASS\nOwned sandbox observation.\n')
        self.fixture()
        session = SimpleNamespace(ticket=SimpleNamespace(label='GoodQA harness#1'), post=mock.Mock())
        args = SimpleNamespace(log=[],report=str(self.report),result='pass',screenshot=[],repo=str(self.root),
                               deployed_commit='a'*40,agent_id=REVIEWER,wal_dir=str(self.wal.parent),
                               human=None,actor='agent:main',url='http://owned.test',really_tested=None)
        with mock.patch.object(sf,'_actor_and_spec',return_value=(session,[],{}, {'spec_core_sha':'b'*64})), \
             mock.patch.object(sf,'git_commit',return_value={'sha':'a'*40}):
            self.assertEqual(sf.cmd_click_test(args,{}),0)
        record = session.post.call_args.args[2]
        self.assertEqual(record['tester']['family'],'codex')
        self.assertEqual(record['pass_source'],'report+codex-tester-final-sha256')

    def test_wrong_role_parent_and_digest_refuse(self):
        self.fixture()
        with self.assertRaises(sf.SpecError):
            self.get('a'*64)
        self.db.execute('UPDATE threads SET agent_role=? WHERE id=?', ('harness_owner', REVIEWER));self.db.commit()
        with self.assertRaises(sf.SpecError):
            self.get()
        self.db.execute('UPDATE threads SET agent_role=?,attached_thread_parent_id=? WHERE id=?',
                        ('harness_click_tester', OTHER, REVIEWER));self.db.commit()
        with self.assertRaises(sf.SpecError):
            self.get()

    def test_tool_user_and_nonfinal_text_cannot_bind_report(self):
        self.fixture()
        for role, channel in (('user','final'), ('tool','final'), ('assistant','commentary')):
            self.final['payload']['role'], self.final['payload']['channel'] = role,channel
            self.write_final()
            with self.assertRaises(sf.SpecError):
                self.get()

    def test_unowned_shape_symlink_and_foreign_path_refuse(self):
        self.fixture()
        original = self.rollout.read_bytes()
        self.rollout.chmod(0o666)
        with self.assertRaises(sf.SpecError):
            self.get()
        self.rollout.chmod(0o600)
        elsewhere = self.root / 'foreign.jsonl'
        elsewhere.write_bytes(original);elsewhere.chmod(0o600)
        self.rollout.unlink();self.rollout.symlink_to(elsewhere)
        with self.assertRaises(sf.SpecError):
            self.get()


if __name__ == '__main__':
    unittest.main()
