"""Explicit owner declarations preserve real independence without aliasing reporters."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

import test_spec_flow as base
import spec_flow as sf

A = '22222222-2222-4222-8222-222222222222'
B = '44444444-4444-4444-8444-444444444444'
PARENT = '11111111-1111-4111-8111-111111111111'
OWNERS = ['agent:' + A, 'agent:' + B]
TEXT = base.SPEC.replace('Author: agent:owner1 (claude-opus-5-5)',
                         'Author: agent:' + A + '\nOwners: ' + ', '.join(OWNERS))


def setUpModule():
    base.setUpModule()


def tearDownModule():
    base.tearDownModule()


def proof(owner):
    return {'owner': owner, 'parent': PARENT, 'family': 'codex', 'agent_type': 'harness_owner',
            'attestation_event': 'handoff', 'attestation_at': '2026-11-22T01:00:00+00:00',
            'wal_sha256': 'a' * 64, 'event_sha256': 'b' * 64, 'native_binding_sha256': 'c' * 64}


class ExplicitOwners(unittest.TestCase):
    def setUp(self):
        self.case = base.DoneGate()
        self.case.setUp()
        self.addCleanup(self.case.tearDown)

    def attach(self, text=TEXT, actor='agent:main1'):
        spec = self.case.reviewed_spec(text)
        with mock.patch.object(sf, '_native_owner_proof', side_effect=lambda wal, owner: proof(owner)):
            code, _, error = self.case.run_cli('attach', str(spec), '--actor', actor,
                                              '--owners-wal', str(self.case.main_wal))
        self.assertEqual(code, 0, error)
        return spec

    def sign(self, signer='main1'):
        return self.case.run_cli('signoff', '--ticket', 'GoodQA harness#168', '--actor', 'agent:main1',
                                 '--by', signer, '--kind', 'agent', '--source', 'independent main review')

    def record(self):
        records, _ = sf.ticket_records(self.case.fake.comments[base.ISSUE], 65536)
        return next(r for r in records if r['kind'] == 'spec')

    def test_coordinator_reporter_can_sign_actual_declared_owners_cannot(self):
        self.attach()
        self.assertEqual(self.sign()[0], 0)
        for owner in (A, B, 'acc1'):
            code, _, error = self.sign(owner)
            self.assertNotEqual(code, 0, error)
        self.assertEqual(self.record()['owners'], OWNERS)
        self.assertEqual(self.record()['owners_core_sha'], sf.core_sha(TEXT))
        result = self.case.evaluate()
        self.assertFalse(any(x.startswith('sign-off:') for x in result['missing']), result['missing'])

    def test_missing_native_provenance_refuses_attachment_before_post(self):
        spec = self.case.reviewed_spec(TEXT)
        for extra in ([], ['--owners-wal', str(self.case.main_wal)]):
            code, _, error = self.case.run_cli('attach', str(spec), '--actor', 'agent:main1', *extra)
            self.assertNotEqual(code, 0, error)
            self.assertEqual(self.case.fake.comments[base.ISSUE], [])

    def test_legacy_reporter_inference_is_unchanged(self):
        spec = self.case.reviewed_spec()
        self.assertEqual(self.case.run_cli('attach', str(spec), '--actor', 'agent:main1')[0], 0)
        self.assertNotEqual(self.sign()[0], 0)

    def test_empty_alias_duplicate_or_author_omitted_declaration_fails_lint(self):
        for declaration in ('', 'agent:' + B, OWNERS[0] + ', ' + OWNERS[0], 'agent:OWNER', 'model:root'):
            with self.subTest(owners=declaration):
                text = TEXT.replace(', '.join(OWNERS), declaration)
                self.assertTrue(sf.lint(text, self.case.config))
        self.assertTrue(sf.lint(TEXT.replace('Owners: ', 'Owners: ' + OWNERS[0] + '\nOwners: '), self.case.config))

    def test_proof_mutation_or_missing_binding_cannot_fall_back_to_legacy(self):
        self.attach()
        record = self.record()
        for key, value in [('owners', []), ('owners_core_sha', 'f' * 64), ('owner_proofs', []), ('owner_proof_sha256', 'f' * 64)]:
            changed = copy.deepcopy(record)
            changed[key] = value
            self.assertTrue(sf.kind_problems(changed), (key, changed))
        changed = copy.deepcopy(record)
        del changed['owners']
        self.assertTrue(sf.kind_problems(changed))

    def test_owner_cannot_review_spec_and_owner_change_stales_reviews(self):
        self.assertTrue(sf.review_problems([{'role': 'acceptance', 'verdict': 'ACCEPT', 'core_sha': 'x',
                                            'key': OWNERS[1]}], 'x', OWNERS[0], owners=OWNERS))
        before = sf.core_sha(TEXT)
        revised = TEXT.replace(', ' + OWNERS[1], '')
        self.assertNotEqual(before, sf.core_sha(revised))
        spec = self.case.reviewed_spec(TEXT)
        spec.write_text(revised)
        code, _, error = self.case.run_cli('attach', str(spec), '--actor', 'agent:main1',
                                          '--owners-wal', str(self.case.main_wal))
        self.assertNotEqual(code, 0)
        self.assertIn('current spec', error)
        self.assertEqual(self.case.fake.comments[base.ISSUE], [])


    def complete(self):
        with mock.patch.object(self.case, 'attached', side_effect=self.attach):
            self.case.complete(signer=None, text=TEXT)

    def test_reporter_uploading_evidence_and_test_does_not_become_owner(self):
        self.complete()
        for comment in self.case.fake.comments[base.ISSUE]:
            record = json.loads(sf.RECORD_BLOCK.search(comment['body']).group(1))
            record['actor'] = 'agent:main1'
            comment['body'] = sf.record_body('same genuine report, coordinator transports it', record)
        self.assertEqual(self.sign()[0], 0)
        self.assertTrue(self.case.evaluate()['ready'], self.case.evaluate())
        self.assertNotEqual(self.sign('ct1')[0], 0)

    def test_unverified_comment_does_not_invent_a_tester_role(self):
        self.complete()
        record = {'v': 1, 'kind': 'click_test', 'spec_core_sha': sf.core_sha(TEXT), 'actor': 'agent:unknown',
                  'tester': {'kind': 'agent', 'identity': 'main1'}, 'attachments': []}
        self.case.fake.comments[base.ISSUE].append({'id': 'unverified', 'createdAt': self.case.fake.now(),
            'body': sf.record_body('unverified data', record)})
        self.assertEqual(self.sign()[0], 0)
        self.assertTrue(self.case.evaluate()['ready'], self.case.evaluate())

    def test_historical_verified_tester_remains_excluded_from_signing(self):
        self.complete()
        for comment in self.case.fake.comments[base.ISSUE]:
            record = json.loads(sf.RECORD_BLOCK.search(comment['body']).group(1))
            if record['kind'] == 'click_test':
                record['spec_core_sha'] = 'f' * 64
                comment['body'] = sf.record_body('historical verified tester', record)
        self.assertNotEqual(self.sign('ct1')[0], 0)

    def test_actual_declared_owner_cannot_be_click_tester(self):
        self.complete()
        with self.assertRaisesRegex(AssertionError, 'declared owner'):
            self.case.click(A, 'https://app.goodqa.example')
        self.assertEqual(len([c for c in self.case.fake.comments[base.ISSUE]
            if json.loads(sf.RECORD_BLOCK.search(c['body']).group(1))['kind'] == 'click_test']), 1)

    def test_provenance_attachment_corruption_cannot_choose_older_spec(self):
        self.case.attached()
        self.attach()
        records, _ = sf.ticket_records(self.case.fake.comments[base.ISSUE], 65536)
        current = [r for r in records if r['kind'] == 'spec'][-1]
        attachment = next(a for a in current['attachments'] if a['role'] == 'owner-provenance')
        self.case.fake.attachments[attachment['id']]['sha256'] = 'f' * 64
        self.assertNotEqual(self.sign()[0], 0)
        self.assertFalse(self.case.evaluate()['ready'])
        self.assertTrue(any('provenance' in m for m in self.case.evaluate()['missing']))

    def test_torn_current_explicit_record_never_uses_older_legacy_spec(self):
        self.case.attached()
        self.attach()
        comment = self.case.fake.comments[base.ISSUE][-1]
        original = json.loads(sf.RECORD_BLOCK.search(comment['body']).group(1))
        for changed in (dict(original, owners=[]), dict(original, owners='malformed'),
                        {k: v for k, v in original.items() if k not in sf._OWNERSHIP_FIELDS}):
            comment['body'] = sf.record_body('torn current explicit record', changed)
            self.assertNotEqual(self.sign()[0], 0)
            self.assertFalse(self.case.evaluate()['ready'])
            self.assertTrue(any('owner' in m.lower() for m in self.case.evaluate()['missing']))


class NativeOwnerProvenance(unittest.TestCase):
    def setUp(self):
        import test_spec_flow_native_review as native
        self.native = native.NativeSpecReview()
        self.native.setUp()
        self.addCleanup(self.native.doCleanups)
        self.native.child(A, 'harness_owner')
        self.owner_wal = self.native.wal.parent / ('agent-' + A + '.jsonl')
        self.line = json.dumps({'at': '2026-11-22T02:00:00+00:00', 'event': 'handoff',
                                'note': 'private owner-recorded work handoff; never upload this note'}) + '\n'
        self.owner_wal.write_text(self.line)
        self.owner_wal.chmod(0o600)

    def get(self):
        return sf._native_owner_proof(self.native.wal, OWNERS[0])

    def test_real_native_assignment_and_recorded_handoff_are_distinct(self):
        before = self.native.db_path.read_bytes()
        found = self.get()
        self.assertEqual(found['owner'], OWNERS[0])
        self.assertEqual(found['agent_type'], 'harness_owner')
        self.assertEqual(found['attestation_event'], 'handoff')
        self.assertNotIn('completed', found)
        self.assertNotIn('private owner-recorded', json.dumps(found))
        self.assertEqual(found['wal_sha256'], hashlib.sha256(self.line.encode()).hexdigest())
        self.assertEqual(self.native.db_path.read_bytes(), before)

    def test_unverified_role_or_parent_cannot_claim_ownership(self):
        for role in ('harness_reviewer', 'harness_red_team', None, 'default'):
            with self.subTest(role=role):
                self.native.child(A, role)
                with self.assertRaises(sf.SpecError):
                    self.get()
        self.native.child(A, 'harness_owner', parent=B)
        with self.assertRaises(sf.SpecError):
            self.get()

    def test_torn_missing_or_ambiguous_handoff_never_supplies_proof(self):
        for data in (self.line.rstrip('\n'), '{}\n', self.line + '{torn\n',
                     '{"event":"handoff","event":"result","at":"2026-11-22T01:00:00+00:00","note":"x"}\n'):
            with self.subTest(data=data[:30]):
                self.owner_wal.write_text(data)
                with self.assertRaises(sf.SpecError):
                    self.get()

    def test_owner_wal_alias_or_changed_snapshot_refuses(self):
        target = self.owner_wal.with_suffix('.saved')
        self.owner_wal.rename(target)
        self.owner_wal.symlink_to(target)
        with self.assertRaises(sf.SpecError):
            self.get()
        self.owner_wal.unlink()
        target.rename(self.owner_wal)
        original = sf.read_regular
        def changed(path, *args, **kwargs):
            data = original(path, *args, **kwargs)
            if path == self.owner_wal:
                with path.open('a') as output:
                    output.write('{}\n')
            return data
        with mock.patch.object(sf, 'read_regular', side_effect=changed), self.assertRaises(sf.SpecError):
            self.get()


if __name__ == '__main__':
    unittest.main()
