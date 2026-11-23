"""GoodQA goodqa#16651: signed central top-rung decisions on a GoodQA ledger ticket.

The trust root stays the user's own words in the Mac transcript (approve-top evidence, re-verified at publish).
Other hosts accept only records signed by the pinned key, for the exact task and family, inside the 12 h window,
and not covered by any revocation. Every failure denies. These tests use a fake ledger, a temp store per "host"
and a temp transcript; nothing reaches GoodQA."""

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
HOOKS = HERE.parent / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(HERE))
import central_decisions as cd  # noqa: E402
import escalation as esc  # noqa: E402
import model_tiers as tiers  # noqa: E402
import tier_gate as gate  # noqa: E402
import top_assent_fixture as fx  # noqa: E402

from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

SESSION = fx.SESSION
UID = fx.UID
ISSUE = 'df6e5927-0772-414a-be9b-03ad45c3d608'
OTHER_ISSUE = 'aaaaaaaa-0772-414a-be9b-03ad45c3d608'
WORDS = 'codex is down, use fable'


def iso_ms(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.') + '%03dZ' % int((ts % 1) * 1000)


class FakeLedger:
    def __init__(self):
        self.items, self.closed, self.missing, self.down, self.truncated, self.fail_post = [], False, False, False, False, False
        self.issue_id = ISSUE

    def issue_state(self, project, number):
        if self.down:
            raise ConnectionError('down')
        return None if self.missing else {'id': self.issue_id, 'closed': self.closed}

    def comments(self, issue_id):
        if self.down:
            raise ConnectionError('down')
        if self.truncated:
            raise cd.Denied('ledger_truncated', 'page budget')
        return [dict(item) for item in self.items]

    def post(self, issue_id, body, operation_id):
        if self.fail_post or self.down:
            raise cd.Denied('ledger_write_failed', 'refused')
        self.add(body)
        return {'ok': True}

    def add(self, body, *, at=None, archived=False):
        self.items.append({'id': 'c%d' % len(self.items), 'body': body, 'createdAt': iso_ms(at if at is not None else time.time()),
                           'archived': archived})


class Host:
    """One host's decision store (the Mac or t2-dev) under a temp home."""

    def __init__(self, base, name):
        self.store = cd.Store(Path(base) / name)

    def configure(self, public_key, issue=ISSUE):
        cd.pin(public_key, store=self.store)
        cd.enable('goodqa', 16652, issue, store=self.store)


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='central-'); self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.home = base / 'home'; self.home.mkdir()
        self.claude = self.home / '.claude'
        self.root = base / 'esc'; self.root.mkdir(mode=0o700)
        self.policy = tiers.load_policy()
        self.ledger = esc.Ledger(self.root, self.policy)
        self.wals = self.claude / 'wals'
        (self.wals / SESSION).mkdir(parents=True)
        self.wal = self.wals / SESSION / 'main.jsonl'
        self.env = mock.patch.dict(os.environ, {'AGENT_HARNESS_WALS_DIR': str(self.wals), 'AGENT_HARNESS_ESCALATION_DIR': str(self.root),
                                                'HOME': str(self.home), 'CLAUDE_CODE_SESSION_ID': '', 'CLAUDE_CONFIG_DIR': str(self.claude)})
        self.env.start(); self.addCleanup(self.env.stop)
        self.mac, self.t2 = Host(base, 'mac'), Host(base, 't2')
        key = cd.keygen(store=self.mac.store)
        self.public = key['public_key']
        self.mac.configure(self.public)
        self.t2.configure(self.public)
        self.fake = FakeLedger()

    # -- evidence helpers
    def grant_local(self, task, words=WORDS, uid=UID, age=60):
        if not hasattr(self, '_turns'):
            self._turns = {}
        if uid not in self._turns:  # one human turn may back several tasks; write it once
            self._turns[uid] = fx.user_turn(self.claude, words, uid=uid, age_seconds=age)
        source = self._turns[uid]
        rows = [{'id': 'w%s1' % task[:4], 'event': 'ask', 'note': '[task:%s] fable' % task, 'source': source},
                {'id': 'w%s2' % task[:4], 'event': 'ask_resolved', 'ref': 'w%s1' % task[:4], 'decision': 'approved', 'source': source}]
        with open(self.wal, 'a') as handle:
            handle.write(''.join(json.dumps(r) + '\n' for r in rows))
        self.ledger.approve_top(task, 'w%s1' % task[:4], self.wal)
        return source

    def publish(self, task, **kw):
        return cd.publish(task, ledger=self.ledger, store=self.mac.store, client=self.fake, claude_home=self.claude,
                          test_mode=True, host='mac', **kw)

    def verify(self, task, family='fable', **kw):
        return cd.verify(task, family, store=self.t2.store, client=self.fake, **kw)

    # -- raw record helpers (to forge or tamper)
    def signing_key(self):
        _, serialization, _ = cd._crypto()
        return cd._private_key(self.mac.store, ed25519, serialization)

    def payload(self, **over):
        now = time.time()
        sentence = WORDS
        p = {'schema': cd.SCHEMA, 'decision_id': 'a' * 32, 'task': 'k1', 'families': ['fable'],
             'source': 'user:%s/%s "%s"' % (SESSION, UID, sentence), 'session': SESSION, 'turn_uuid': UID,
             'sentence': sentence, 'sentence_sha256': hashlib.sha256(sentence.encode()).hexdigest(),
             'assent_at': cd.iso(now - 60), 'issued_at': cd.iso(now - 30), 'expires_at': cd.iso(now - 60 + 12 * 3600),
             'key_id': cd.key_id_of(base64.urlsafe_b64decode(self.public + '=' * (-len(self.public) % 4))),
             'issuer_host': 'mac', 'ask_id': 'w1'}
        p.update(over)
        return p

    def body(self, payload, *, issue=ISSUE, key=None, raw=None):
        payload_raw = raw if raw is not None else cd.canonical(payload)
        sig = (key or self.signing_key()).sign(cd.signed_message(issue, payload_raw))
        return cd.DECISION_PREFIX + cd.b64url(payload_raw) + '.' + cd.b64url(sig)


class PublishAndVerify(Base):
    def test_published_decision_verifies_on_the_other_host_for_exactly_its_task(self):
        self.grant_local('t2scan-audit-5db5032d0c554f08e7e50c90f47ebc85')
        out = self.publish('t2scan-audit-5db5032d0c554f08e7e50c90f47ebc85')
        self.assertEqual(out['families'], ['fable'])
        self.assertEqual(len(self.fake.items), 1)
        self.assertTrue(self.fake.items[0]['body'].startswith(cd.DECISION_PREFIX))
        found = self.verify('t2scan-audit-5db5032d0c554f08e7e50c90f47ebc85')
        self.assertEqual(found['sentence'], WORDS)
        self.assertEqual(found['session'], SESSION)
        # the signing key never appears in the posted record
        pem = self.mac.store.signing_key.read_bytes()
        self.assertNotIn(pem.decode(), self.fake.items[0]['body'])

    def test_task_key_mismatch_variants_are_refused(self):  # NEG-4
        self.grant_local('k1'); self.publish('k1')
        for other in ('k2', 'k1x', 'K1', 'k', 'k1\n', 'k1\x00', 'к1'):
            with self.subTest(other=repr(other)):
                with self.assertRaises(cd.Denied):
                    self.verify(other)

    def test_wildcard_and_malformed_task_keys_never_publish(self):  # NEG-5
        for task in ('*', 't2scan-*', 'k?', '[a]', '', 'k1\n', 'a b'):
            with self.subTest(task=repr(task)):
                with self.assertRaises(cd.Denied) as caught:
                    self.publish(task)
                self.assertEqual(caught.exception.code, 'bad_task')
        self.assertEqual(self.fake.items, [])

    def test_family_must_be_named_in_the_sentence(self):  # NEG-12/NEG-17 family binding
        self.grant_local('k1'); self.publish('k1')
        with self.assertRaises(cd.Denied):
            self.verify('k1', 'astra')

    def test_no_local_permission_or_agent_text_source_refuses(self):  # NEG-2
        with self.assertRaises(cd.Denied) as caught:
            self.publish('k9')
        self.assertEqual(caught.exception.code, 'no_local_permission')
        # A hand-written permission whose WAL ask is not user-sourced is refused by the ask-pair check.
        self.ledger.approve_top  # noqa: B018  (the real path refuses inferred sources; write the state by hand)
        state = self.ledger.load('k8')
        state['permission'] = {'ask_id': 'wz1', 'wal': str(self.wal), 'source': 'inferred: from file:x -- guess', 'task': 'k8'}
        self.ledger._write('k8', state)
        with self.assertRaises(cd.Denied) as caught:
            self.publish('k8')
        self.assertEqual(caught.exception.code, 'not_user_turn')
        state['permission'] = {'ask_id': 'wz1', 'wal': str(self.wal), 'source': 'user:%s/%s "%s"' % (SESSION, UID, WORDS), 'task': 'k8'}
        self.ledger._write('k8', state)
        with self.assertRaises(cd.Denied):  # no ask pair in the WAL for wz1
            self.publish('k8')
        self.assertEqual(self.fake.items, [])

    def test_unwritable_index_refuses_before_posting(self):  # plan review 3 F3: auto-revocation needs the index
        self.grant_local('k1')
        with mock.patch.object(cd, '_append_private', side_effect=OSError('read-only')):
            with self.assertRaises(cd.Denied) as caught:
                self.publish('k1')
        self.assertEqual(caught.exception.code, 'index_unwritable')
        self.assertFalse(any(str(i['body']).startswith(cd.DECISION_PREFIX) for i in self.fake.items))

    def test_publish_refuses_when_the_mac_clock_disagrees_with_the_server(self):  # plan review 4 F2
        self.grant_local('k1')
        self.fake.server_time = lambda: time.time() + 600
        with self.assertRaises(cd.Denied) as caught:
            self.publish('k1')
        self.assertEqual(caught.exception.code, 'clock_skew')
        self.assertFalse(any(str(i['body']).startswith(cd.DECISION_PREFIX) for i in self.fake.items))

    def test_later_turn_naming_the_top_rung_blocks_publish(self):  # NEG-14
        self.grant_local('k1')
        fx.user_turn(self.claude, 'actually keep fable off', uid='00000000-0000-4000-8000-0000000000f2', age_seconds=30)
        with self.assertRaises(cd.Denied) as caught:
            self.publish('k1')
        self.assertEqual(caught.exception.code, 'later_turn')
        # refused before signing: nothing was posted (the post-publish rescan is a second net, not this one)
        self.assertFalse(any(str(i['body']).startswith(cd.DECISION_PREFIX) for i in self.fake.items))

    def test_turn_arriving_during_publish_withdraws_the_new_decision(self):  # NEG-14 publish window
        self.grant_local('k1')
        real_post = self.fake.post

        def post_then_user_speaks(issue_id, body, operation_id):
            out = real_post(issue_id, body, operation_id)
            if body.startswith(cd.DECISION_PREFIX):
                fx.user_turn(self.claude, 'wait, stop fable', uid='00000000-0000-4000-8000-0000000000f3', age_seconds=1)
            return out
        self.fake.post = post_then_user_speaks
        with self.assertRaises(cd.Denied) as caught:
            self.publish('k1')
        self.assertEqual(caught.exception.code, 'later_turn')
        self.assertTrue(self.fake.items[-1]['body'].startswith('agent-harness-revoke decision '))
        with self.assertRaises(cd.Denied):
            self.verify('k1')

    def test_later_unrelated_turn_does_not_block(self):
        self.grant_local('k1')
        fx.user_turn(self.claude, 'build native runtime', uid='00000000-0000-4000-8000-0000000000f2', age_seconds=30)
        self.publish('k1')
        self.verify('k1')

    def test_old_assent_refused_and_expiry_clamped(self):  # NEG-10
        self.grant_local('k1', age=60)
        out = self.publish('k1', now=time.time() + 11 * 3600)
        self.assertLessEqual(cd.parse_time(out['expires_at']) - (time.time() - 60), 12 * 3600 + 2)
        with self.assertRaises(cd.Denied):
            self.publish('k1', now=time.time() + 12 * 3600 + 5)

    def test_fourth_task_for_one_turn_is_refused(self):  # NEG-13
        for task in ('k1', 'k2', 'k3'):
            self.grant_local(task)
            self.publish(task)
        self.grant_local('k4')
        with self.assertRaises(cd.Denied) as caught:
            self.publish('k4')
        self.assertEqual(caught.exception.code, 'turn_cap')

    def test_cap_also_enforced_at_verify(self):  # spec review F5: a racing fourth publish denies the whole turn
        for task in ('k1', 'k2', 'k3', 'k4'):
            self.fake.add(self.body(self.payload(task=task, decision_id=hashlib.md5(task.encode()).hexdigest())))
        with self.assertRaises(cd.Denied):
            self.verify('k1')

    def test_publish_refused_after_a_revocation_that_follows_the_words(self):
        self.grant_local('k1')
        self.fake.add('agent-harness-revoke task k1')
        with self.assertRaises(cd.Denied) as caught:
            self.publish('k1')
        self.assertEqual(caught.exception.code, 'revoked')

    def test_installed_ledger_required_outside_tests(self):
        self.grant_local('k1')
        with self.assertRaises(cd.Denied) as caught:
            cd.publish('k1', ledger=self.ledger, store=self.mac.store, client=self.fake)
        self.assertEqual(caught.exception.code, 'non_default_root')


class Forgery(Base):
    def test_valid_handmade_record_verifies(self):  # control for the cases below
        self.fake.add(self.body(self.payload()))
        self.verify('k1')

    def test_forged_and_tampered_records_are_refused(self):  # NEG-1, NEG-7, NEG-16
        other = ed25519.Ed25519PrivateKey.generate()
        good = self.payload()
        raw = cd.canonical(good)
        sig_body = self.body(good)
        token = sig_body[len(cd.DECISION_PREFIX):]
        p64, s64 = token.split('.')
        flipped_payload = bytearray(raw); flipped_payload[40] ^= 1
        flipped_sig = bytearray(cd.b64url_decode(s64)); flipped_sig[0] ^= 1
        cases = {
            'other key': self.body(good, key=other),
            'no signature': cd.DECISION_PREFIX + p64,
            'flipped payload bit': cd.DECISION_PREFIX + cd.b64url(bytes(flipped_payload)) + '.' + s64,
            'flipped signature bit': cd.DECISION_PREFIX + p64 + '.' + cd.b64url(bytes(flipped_sig)),
            'extra key': self.body(dict(good, extra=1)),
            'duplicate key': self.body(None, raw=raw[:-1] + b',"task":"k1"}'),
            'non-canonical spacing': self.body(None, raw=json.dumps(good, sort_keys=True).encode()),
            'padded base64': cd.DECISION_PREFIX + base64.urlsafe_b64encode(raw).decode() + '.' + s64,
            'sentence hash mismatch': self.body(dict(good, sentence='codex is down, use fable now')),
            'families not from sentence': self.body(dict(good, families=['astra', 'fable'])),
            'another ledger issue': self.body(good, issue=OTHER_ISSUE),
            'future issued': self.body(dict(good, issued_at=cd.iso(time.time() + 600))),
            'assent after issue': self.body(dict(good, assent_at=cd.iso(time.time() - 10))),
            'expiry beyond 12h': self.body(dict(good, expires_at=cd.iso(time.time() + 13 * 3600))),
            'expired': self.body(dict(good, assent_at=cd.iso(time.time() - 13 * 3600), issued_at=cd.iso(time.time() - 13 * 3600 + 5),
                                      expires_at=cd.iso(time.time() - 3600))),
            'wrapped body': sig_body[:60] + '\n' + sig_body[60:],
            'truncated body': sig_body[:-5],
            'quoted in prose': 'see this record: ' + sig_body,
            'source session mismatch': self.body(dict(good, source='user:%s/%s "%s"' % (SESSION.replace('1', '2', 1), UID, WORDS))),
        }
        for name, body in cases.items():
            with self.subTest(name):
                self.fake.items = []
                self.fake.add(body)
                with self.assertRaises(cd.Denied):
                    self.verify('k1')

    def test_base64url_is_canonical_only(self):  # NEG-7 non-canonical base64
        for text in ('ab+c', 'ab/c', 'YQ==', 'YR', 'a', ''):
            with self.subTest(text=text):
                with self.assertRaises(cd.Denied):
                    cd.b64url_decode(text)
        self.assertEqual(cd.b64url_decode('YQ'), b'a')

    def test_unpinned_host_and_missing_crypto_deny(self):  # NEG-6
        self.fake.add(self.body(self.payload()))
        self.t2.store.keys.unlink()
        with self.assertRaises(cd.Denied) as caught:
            self.verify('k1')
        self.assertEqual(caught.exception.code, 'no_pinned_key')
        self.t2.configure(self.public)
        with mock.patch.object(cd, '_crypto', side_effect=cd.Denied('no_crypto', 'x')):
            with self.assertRaises(cd.Denied):
                self.verify('k1')

    def test_ledger_failures_deny(self):  # NEG-6
        self.fake.add(self.body(self.payload()))
        for attr in ('down', 'closed', 'missing', 'truncated'):
            with self.subTest(attr):
                setattr(self.fake, attr, True)
                with self.assertRaises(cd.Denied):
                    self.verify('k1')
                setattr(self.fake, attr, False)
        self.fake.issue_id = OTHER_ISSUE  # the pinned issue id must match what the tracker returns
        with self.assertRaises(cd.Denied):
            self.verify('k1')

    def test_clock_behind_the_server_denies(self):  # spec review F6
        self.fake.add(self.body(self.payload()))
        with self.assertRaises(cd.Denied) as caught:
            self.verify('k1', now=time.time() - 600)
        self.assertEqual(caught.exception.code, 'clock_behind')

    def test_slow_clock_on_a_quiet_ledger_denies_by_server_time(self):  # plan review 3 F1
        self.fake.add(self.body(self.payload()), at=time.time() - 7200)  # nothing posted for two hours
        self.fake.server_time = lambda: time.time()
        with self.assertRaises(cd.Denied) as caught:
            self.verify('k1', now=time.time() - 3600)  # this host is an hour slow
        self.assertEqual(caught.exception.code, 'clock_behind')
        self.assertEqual(self.verify('k1')['task'], 'k1')  # same ledger, correct clock: valid

    def test_real_ledger_client_requires_a_server_date(self):  # plan review 3 F1
        adapter = mock.Mock(spec=['last_server_date'])
        adapter.last_server_date = None
        with self.assertRaises(cd.Denied) as caught:
            cd.GoodQALedger(adapter=adapter).server_time()
        self.assertEqual(caught.exception.code, 'no_server_time')
        adapter.last_server_date = 'Mon, 23 Nov 2026 01:00:00 GMT'
        self.assertEqual(cd.GoodQALedger(adapter=adapter).server_time(), 1795395600.0)


class Revocation(Base):
    def setUp(self):
        super().setUp()
        self.fake.add(self.body(self.payload()), at=time.time() - 20)


    def test_revoke_without_a_server_time_still_denies(self):  # plan review 4 F1
        self.assertEqual(self.verify('k1')['task'], 'k1')
        self.fake.items.append({'id': 'undated', 'body': 'agent-harness-revoke task k1', 'createdAt': None, 'archived': False})
        with self.assertRaises(cd.Denied):
            self.verify('k1')

    def test_grant_without_a_server_time_is_not_valid(self):  # plan review 4 F1
        self.fake.items[:] = [dict(i, createdAt='not-a-time') for i in self.fake.items]
        with self.assertRaises(cd.Denied):
            self.verify('k1')
    def test_each_revoke_scope_denies(self):  # NEG-3
        for line in ('agent-harness-revoke all', 'agent-harness-revoke task k1',
                     'agent-harness-revoke session %s' % SESSION, 'agent-harness-revoke decision ' + 'a' * 32):
            with self.subTest(line):
                self.fake.items = self.fake.items[:1]
                self.fake.add(line)
                with self.assertRaises(cd.Denied):
                    self.verify('k1')
                self.t2.store.tombstones.unlink()

    def test_revoke_quoted_in_prose_does_not_deny_and_other_task_unaffected(self):  # NEG-15
        self.fake.add('to revoke, post: agent-harness-revoke task k1')
        self.fake.add('agent-harness-revoke task k2')
        self.verify('k1')

    def test_revoke_older_than_the_words_does_not_deny(self):  # NEG-15: a new decision after a revoke-all is new
        self.fake.items.insert(0, {'id': 'old', 'body': 'agent-harness-revoke all', 'createdAt': iso_ms(time.time() - 3600),
                                   'archived': False})
        self.verify('k1')

    def test_archived_revoke_still_denies_and_archived_grant_is_invalid(self):  # NEG-15
        self.fake.add('agent-harness-revoke task k1', archived=True)
        with self.assertRaises(cd.Denied):
            self.verify('k1')
        self.fake.items = self.fake.items[:1]
        self.t2.store.tombstones.unlink()
        self.fake.items[0]['archived'] = True
        with self.assertRaises(cd.Denied):
            self.verify('k1')

    def test_tombstone_keeps_denying_after_the_revoke_disappears(self):  # NEG-3 replay of a withdrawn decision
        self.fake.add('agent-harness-revoke task k1')
        with self.assertRaises(cd.Denied):
            self.verify('k1')
        self.fake.items = self.fake.items[:1]  # the revoke comment is gone from the tracker
        with self.assertRaises(cd.Denied):
            self.verify('k1')

    def test_no_cache_between_checks(self):  # NEG-9
        self.verify('k1')
        self.fake.add('agent-harness-revoke task k1')
        with self.assertRaises(cd.Denied):
            self.verify('k1')

    def test_republish_after_revoke_by_id_is_refused(self):
        self.fake.items = []
        self.grant_local('k1')
        out = self.publish('k1')
        self.fake.add('agent-harness-revoke decision ' + out['decision_id'])
        with self.assertRaises(cd.Denied) as caught:
            self.publish('k1')
        self.assertEqual(caught.exception.code, 'revoked')


class PromptHookRevokes(Base):
    def test_later_mention_revokes_published_decisions_and_failed_post_is_queued(self):  # AC-5, NEG-18
        self.grant_local('k1')
        out = self.publish('k1')
        self.verify('k1')
        self.fake.fail_post = True
        note = cd.on_user_prompt(SESSION, 'no more fable please', store=self.mac.store, client=self.fake)
        self.assertIn('NOT posted', note)
        # the Mac denies at once through its tombstone even though the ledger post failed
        with self.assertRaises(cd.Denied):
            cd.verify('k1', 'fable', store=self.mac.store, client=self.fake)
        self.verify('k1')  # t2-dev still accepts until the queued post lands (the documented gap)
        self.fake.fail_post = False
        note = cd.on_user_prompt(SESSION, 'thanks', store=self.mac.store, client=self.fake)
        self.assertIn('posted 1 queued', note)
        with self.assertRaises(cd.Denied):
            self.verify('k1')
        self.assertIn(out['decision_id'], self.fake.items[-1]['body'])

    def test_unrelated_prompt_and_other_session_do_nothing(self):
        self.grant_local('k1'); self.publish('k1')
        self.assertIsNone(cd.on_user_prompt(SESSION, 'looks good', store=self.mac.store, client=self.fake))
        self.assertIsNone(cd.on_user_prompt('99999999-2222-4333-8444-555555555555', 'use fable', store=self.mac.store,
                                            client=self.fake))
        self.verify('k1')

    def test_every_adapter_withdrawal_opener_revokes(self):  # PR 14 review F2: harness trigger is a superset
        for opener in ('no', 'stop', 'cancel', 'revoke', 'do not', "don't", 'withdraw'):
            with self.subTest(opener):
                self.fake.items.clear()
                for path in (self.mac.store.published, self.mac.store.tombstones):
                    if path.exists():
                        path.unlink()
                self.grant_local('k1')
                self.publish('k1')
                cd.on_user_prompt(SESSION, opener + ' run that review', store=self.mac.store, client=self.fake)
                with self.assertRaises(cd.Denied):
                    self.verify('k1')


class WithdrawalPredicate(unittest.TestCase):
    """withdrawal_signal is the one trigger for every revocation path; its truth table."""

    def test_truth_table(self):
        fires = ['no', 'No, stop', '  stop the run', 'cancel', 'revoke it', 'withdraw that', 'do not run it',
                 'do  not', "don't", 'dont', 'never mind', 'hold off for now', 'scratch that', 'forget it',
                 'use astra instead', 'the top rung is fine', 'keep fable off', 'STOP',
                 '<ide_selection>x</ide_selection> never mind']
        quiet = ['looks good', 'thanks', 'yes, go on', 'knob tweak', 'notable result', 'stopwatch', '', '   ', None, 7]
        for text in fires:
            with self.subTest(fires=text):
                self.assertTrue(cd.withdrawal_signal(text))
        for text in quiet:
            with self.subTest(quiet=text):
                self.assertFalse(cd.withdrawal_signal(text))


class EveryWithdrawalChannelRevokes(Base):
    """PR 14 round-2 class A: a worker host has no transcript, so it sees a withdrawal only as a ledger revocation.
    Every channel the T2Scan local path honours (a typed turn, a question answer, a queued mid-turn message) must
    therefore produce one from the Mac's hooks. The other host (t2) has no transcript and no tombstone here."""

    ASK_USE = 'toolu_01AskUserQuestionFixture'

    def setUp(self):
        super().setUp()
        self.grant_local('k1')
        self.decision = self.publish('k1')['decision_id']
        self.verify('k1')
        self.transcript = self.claude / 'projects' / '-proj' / (SESSION + '.jsonl')

    def append(self, *rows):
        with open(self.transcript, 'a') as handle:
            handle.write(''.join(json.dumps(row) + '\n' for row in rows))

    def answer_rows(self, answer):
        asked = {'type': 'assistant', 'uuid': '00000000-0000-4000-8000-00000000a5c1', 'message': {'role': 'assistant',
                 'content': [{'type': 'tool_use', 'id': self.ASK_USE, 'name': 'AskUserQuestion', 'input': {}}]}}
        answered = {'type': 'user', 'uuid': '00000000-0000-4000-8000-00000000a5c2', 'timestamp': fx.stamp(1),
                    'toolUseResult': {'questions': [{'question': 'Proceed with fable?'}],
                                      'answers': {'Proceed with fable?': answer}},
                    'message': {'role': 'user', 'content': [{'type': 'tool_result', 'tool_use_id': self.ASK_USE,
                                                             'content': 'User answered'}]}}
        return asked, answered

    def revoke_lines(self):
        return [item['body'] for item in self.fake.items if item['body'].startswith('agent-harness-revoke')]

    def assert_revoked_everywhere(self):
        with self.assertRaises(cd.Denied) as caught:
            self.verify('k1')
        self.assertIn('revoked', str(caught.exception))
        self.assertEqual(self.revoke_lines(), ['agent-harness-revoke decision ' + self.decision])

    def test_withdrawing_question_answer_revokes_from_the_hook_payload(self):
        response = {'questions': [{'question': 'Proceed with fable?'}], 'answers': {'Proceed with fable?': 'Yes, go on'}}
        self.assertIsNone(cd.on_ask_answer(SESSION, response, store=self.mac.store, client=self.fake))
        self.verify('k1')  # a non-withdrawing answer changes nothing
        response['answers'] = {'Proceed with fable?': 'No, stop'}
        note = cd.on_ask_answer(SESSION, response, store=self.mac.store, client=self.fake)
        self.assertIn('revoked central decision', note)
        self.assert_revoked_everywhere()

    def test_unreadable_question_answer_revokes(self):
        for response in ('User declined to answer', {'answers': {}}, {'answers': 'no'}, None):
            with self.subTest(response=response):
                self.fake.items[:] = [i for i in self.fake.items if not i['body'].startswith('agent-harness-revoke')]
                for store in (self.mac.store, self.t2.store):  # each subtest starts unrevoked on both hosts
                    if store.tombstones.exists():
                        store.tombstones.unlink()
                self.verify('k1')
                cd.on_ask_answer(SESSION, response, store=self.mac.store, client=self.fake)
                self.assert_revoked_everywhere()

    def test_stop_sweep_revokes_on_a_queued_mid_turn_message(self):
        self.assertIsNone(cd.on_stop(SESSION, store=self.mac.store, client=self.fake, claude_home=self.claude))
        self.verify('k1')  # nothing later in the transcript yet
        self.append({'type': 'queue-operation', 'operation': 'enqueue', 'sessionId': SESSION, 'timestamp': fx.stamp(1),
                     'content': 'stop, hold the review'})
        cd.on_stop(SESSION, store=self.mac.store, client=self.fake, claude_home=self.claude)
        self.assert_revoked_everywhere()

    def test_stop_sweep_revokes_on_an_answer_the_payload_path_missed(self):
        self.append(*self.answer_rows('No, stop'))
        cd.on_stop(SESSION, store=self.mac.store, client=self.fake, claude_home=self.claude)
        self.assert_revoked_everywhere()

    def test_prompt_hook_sweeps_too(self):
        self.append({'type': 'queue-operation', 'operation': 'enqueue', 'sessionId': SESSION, 'timestamp': fx.stamp(1),
                     'content': 'cancel that'})
        cd.on_user_prompt(SESSION, 'thanks', store=self.mac.store, client=self.fake, claude_home=self.claude)
        self.assert_revoked_everywhere()

    def test_unreadable_transcript_revokes_and_a_revoked_decision_is_not_withdrawn_again(self):
        self.transcript.rename(self.transcript.with_suffix('.gone'))
        cd.on_stop(SESSION, store=self.mac.store, client=self.fake, claude_home=self.claude)
        self.assert_revoked_everywhere()
        for _ in range(3):
            cd.on_stop(SESSION, store=self.mac.store, client=self.fake, claude_home=self.claude)
            cd.on_user_prompt(SESSION, 'no', store=self.mac.store, client=self.fake, claude_home=self.claude)
        self.assertEqual(len(self.revoke_lines()), 1)

    def test_failed_post_tombstones_first_and_any_verb_retries(self):
        self.fake.fail_post = True
        note = cd.on_ask_answer(SESSION, {'answers': {'q': 'no'}}, store=self.mac.store, client=self.fake)
        self.assertIn('NOT posted', note)
        with self.assertRaises(cd.Denied):
            cd.verify('k1', 'fable', store=self.mac.store, client=self.fake)  # the Mac tombstone denies at once
        self.verify('k1')  # the stated limit: other hosts accept until the queued post lands
        self.fake.fail_post = False
        self.assertIn('posted 1 queued', cd.on_stop(SESSION, store=self.mac.store, client=self.fake,
                                                    claude_home=self.claude))
        self.assert_revoked_everywhere()

    def test_a_client_error_that_is_not_denied_is_still_queued(self):
        class Unavailable(Exception):
            pass
        real_post = self.fake.post
        with mock.patch.object(self.fake, 'post', side_effect=Unavailable('ticket system down')):
            note = cd.on_ask_answer(SESSION, {'answers': {'q': 'no'}}, store=self.mac.store, client=self.fake)
        self.assertIn('NOT posted', note)
        self.assertEqual(self.revoke_lines(), [])
        self.assertIn('Unavailable', self.mac.store.pending.read_text())
        self.assertIs(self.fake.post.__func__, real_post.__func__)
        cd.on_stop(SESSION, store=self.mac.store, client=self.fake, claude_home=self.claude)
        self.assert_revoked_everywhere()

    def test_other_session_decisions_are_untouched(self):
        other = '99999999-2222-4333-8444-555555555555'
        cd.on_ask_answer(other, {'answers': {'q': 'no, stop'}}, store=self.mac.store, client=self.fake)
        cd.on_stop(other, store=self.mac.store, client=self.fake, claude_home=self.claude)
        self.verify('k1')
        self.assertEqual(self.revoke_lines(), [])


class AnswerHookIsWired(Base):
    """The `answer` verb through provenance_hooks.main (verb allow-list and handler table) and its registration."""

    def run_main(self, verb, payload):
        import io
        import provenance_hooks as ph
        out = io.StringIO()
        with mock.patch.object(ph, 'read_payload', return_value=payload), \
                mock.patch.object(ph, 'install_limits', return_value=None), \
                mock.patch.object(ph, 'central_enabled', return_value=True), \
                mock.patch.object(cd, 'Store', lambda home=None: self.mac.store), \
                mock.patch.object(cd, 'GoodQALedger', lambda adapter=None, deadline_seconds=None: self.fake), \
                mock.patch('sys.stdout', out):
            self.assertEqual(ph.main([verb]), 0)
        return out.getvalue()

    def test_answer_verb_revokes_and_reports(self):
        self.grant_local('k1')
        self.publish('k1')
        payload = {'session_id': SESSION, 'tool_name': 'AskUserQuestion', 'hook_event_name': 'PostToolUse',
                   'tool_input': {}, 'tool_response': {'answers': {'Go?': 'Yes'}}}
        self.assertEqual(self.run_main('answer', payload), '')
        self.verify('k1')
        self.assertEqual(self.run_main('answer', dict(payload, tool_name='Bash',
                                                      tool_response={'answers': {'Go?': 'no'}})), '')
        self.verify('k1')  # another tool's output never counts as an answer
        printed = json.loads(self.run_main('answer', dict(payload, tool_response={'answers': {'Go?': 'No, stop'}})))
        self.assertEqual(printed['hookSpecificOutput']['hookEventName'], 'PostToolUse')
        self.assertIn('revoked central decision', printed['hookSpecificOutput']['additionalContext'])
        with self.assertRaises(cd.Denied):
            self.verify('k1')

    def test_host_without_central_config_never_loads_the_module(self):
        import provenance_hooks as ph
        with mock.patch.object(ph, 'central_enabled', return_value=False), \
                mock.patch.object(cd, 'on_ask_answer', side_effect=AssertionError('loaded')):
            self.assertIsNone(ph.central_note(SESSION, {'tool_response': {'answers': {'q': 'no'}}}, 'answer'))

    def test_stop_lint_runs_the_sweep(self):
        self.grant_local('k1')
        self.publish('k1')
        stop = {'session_id': SESSION, 'hook_event_name': 'Stop', 'stop_hook_active': False}
        self.run_main('stop-lint', stop)
        self.verify('k1')  # the sweep found the transcript and nothing later in it (not a fail-safe revoke)
        fx.user_turn(self.claude, 'no, stop', uid='00000000-0000-4000-8000-0000000000f9', age_seconds=1)
        self.run_main('stop-lint', stop)
        with self.assertRaises(cd.Denied):
            self.verify('k1')

    def test_installer_registers_the_answer_hook(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('ah_install', HERE.parent / 'install.py')
        install = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(install)
        groups = install.provenance_hook_groups(Path('/x/.claude'))
        self.assertEqual(groups['PostToolUse'], [{'matcher': 'AskUserQuestion', 'hooks': [
            {'type': 'command', 'command': 'python3', 'args': ['/x/.claude/hooks/provenance_hooks.py', 'answer'],
             'timeout': 10}]}])


class CallerFreshnessLimit(Base):
    def test_verify_honours_the_caller_max_age(self):  # PR 14 review F1 (goodqa#16665)
        now = time.time()
        self.fake.add(self.body(self.payload(assent_at=cd.iso(now - 900), expires_at=cd.iso(now - 900 + 12 * 3600))))
        self.assertEqual(self.verify('k1')['task'], 'k1')  # within the 12 h record limit
        self.assertEqual(self.verify('k1', max_age_seconds=3600)['task'], 'k1')
        with self.assertRaises(cd.Denied) as caught:
            self.verify('k1', max_age_seconds=600)  # the operator's shorter freshness cap wins
        self.assertIn('older_than_caller_limit', str(caught.exception))
        for bad in (0, -1, 12 * 3600 + 1, 60.0, '600', True):
            with self.subTest(bad=bad), self.assertRaises(cd.Denied) as caught:
                self.verify('k1', max_age_seconds=bad)
            self.assertEqual(caught.exception.code, 'bad_max_age')


class TierGateAcceptsCentral(Base):
    def spawn(self, task, model='fable'):
        ledger = esc.Ledger(self.root, self.policy)
        tool_input = {'prompt': 'work', 'description': 'owner [task:%s]' % task, 'subagent_type': 'task-owner', 'model': model}
        return gate.decide_spawn({'tool_name': 'Agent', 'tool_input': tool_input, 'session_id': SESSION}, self.policy, ledger,
                                 session_id=SESSION)

    def run_gate(self, task, verify_side_effect=None):
        real = cd.verify

        def fake_verify(t, family, store=None, deadline_seconds=None, **kw):
            return real(t, family, store=self.t2.store, client=self.fake)
        with mock.patch.object(cd, 'Store', return_value=self.t2.store), mock.patch.object(cd, 'verify', side_effect=fake_verify):
            return self.spawn(task)

    def test_spawn_allowed_with_a_valid_central_decision_and_denied_without(self):  # AC-3
        denied = self.run_gate('k1')
        self.assertEqual(denied[0], 'deny')
        self.fake.add(self.body(self.payload()))
        allowed = self.run_gate('k1')
        self.assertEqual(allowed[0], 'allow', allowed[1])
        self.assertIsNone(self.ledger.status('k1')['permission'])  # nothing written into the escalation state

    def test_astra_only_decision_does_not_permit_a_fable_spawn(self):  # NEG-17
        sentence = 'use astra'
        self.fake.add(self.body(self.payload(sentence=sentence, families=['astra'],
                                             sentence_sha256=hashlib.sha256(sentence.encode()).hexdigest(),
                                             source='user:%s/%s "%s"' % (SESSION, UID, sentence))))
        self.assertEqual(self.run_gate('k1')[0], 'deny')

    def test_central_decision_does_not_lift_the_bash_rung_ceiling(self):  # NEG-19
        self.fake.add(self.body(self.payload()))
        real = cd.verify

        def fake_verify(t, family, store=None, deadline_seconds=None, **kw):
            return real(t, family, store=self.t2.store, client=self.fake)
        ledger = esc.Ledger(self.root, self.policy)
        with mock.patch.object(cd, 'Store', return_value=self.t2.store), mock.patch.object(cd, 'verify', side_effect=fake_verify):
            decision, reason, _, facts = gate.decide_bash(
                {'tool_name': 'Bash', 'tool_input': {'command': 'claude -p --model fable --task k1 x'}}, self.policy, ledger)
        self.assertEqual(facts.get('central'), 'a' * 32, facts)  # the permission site did accept it
        self.assertEqual(decision, 'deny')
        self.assertIn('above task k1', reason)  # ...and the unchanged ceiling still denied the launch

    def bash_with_central(self, command):
        real = cd.verify

        def fake_verify(t, family, store=None, deadline_seconds=None, **kw):
            return real(t, family, store=self.t2.store, client=self.fake)
        with mock.patch.object(cd, 'Store', return_value=self.t2.store), mock.patch.object(cd, 'verify', side_effect=fake_verify):
            return gate.decide_bash({'tool_name': 'Bash', 'tool_input': {'command': command}}, self.policy,
                                    esc.Ledger(self.root, self.policy))

    def test_bash_permission_site_uses_the_model_family(self):  # plan review 5 F1: Bash sites and family mismatch
        sentence = 'use astra'
        self.fake.add(self.body(self.payload(sentence=sentence, families=['astra'],
                                             sentence_sha256=hashlib.sha256(sentence.encode()).hexdigest(),
                                             source='user:%s/%s "%s"' % (SESSION, UID, sentence))))
        decision, reason, _, facts = self.bash_with_central('claude -p --model fable --task k1 x')
        self.assertEqual(decision, 'deny')
        self.assertIn('needs the user permission', reason)  # fable launch: an astra-only decision is no permission
        self.assertEqual(facts.get('central'), 'no_decision')
        decision, reason, _, facts = self.bash_with_central('codex exec --model gpt-6-astra --task k1 -')
        self.assertEqual(facts.get('central'), 'a' * 32)  # astra launch: the permission site accepts it
        self.assertIn('above task k1', reason)  # and the unchanged ceiling decides

    def test_reviewer_site_never_consults_central_decisions(self):  # plan review 5 F1 option (b)
        self.fake.add(self.body(self.payload()))
        decision, reason, _, facts = self.bash_with_central(
            'python3 ~/.claude/hooks/peer_review.py pr --repo r --packet p --output o --task k1 --author-rung R5')
        self.assertEqual(decision, 'deny')
        self.assertIn('needs recorded user permission', reason)
        self.assertNotIn('central', facts)

    def test_hook_consult_uses_the_short_deadline_and_fails_closed(self):  # NEG-20
        seen = {}

        def slow(t, family, store=None, deadline_seconds=None, **kw):
            seen['deadline'] = deadline_seconds
            raise cd.Denied('ledger_timeout', 'deadline exceeded')
        with mock.patch.object(cd, 'Store', return_value=self.t2.store), mock.patch.object(cd, 'verify', side_effect=slow):
            facts = {}
            self.assertIsNone(gate.central_permission('k1', 'fable', facts))
        self.assertTrue(0 < seen['deadline'] <= cd.HOOK_DEADLINE)
        self.assertLess(cd.HOOK_DEADLINE, 10)  # inside the tier_gate hook's 10 s timeout (onFailure block)
        self.assertEqual(facts['central'], 'ledger_timeout')

    def test_two_consults_in_one_hook_run_share_one_budget(self):  # plan review 3 F2
        calls = []

        def slow(t, family, store=None, deadline_seconds=None, **kw):
            calls.append(deadline_seconds)
            raise cd.Denied('ledger_timeout', 'slow')
        facts = {}
        with mock.patch.object(cd, 'Store', return_value=self.t2.store), mock.patch.object(cd, 'verify', side_effect=slow):
            gate.central_permission('k1', 'fable', facts)
            facts['central_budget_end'] -= cd.HOOK_DEADLINE  # the first consult used up the run's budget
            self.assertIsNone(gate.central_permission('k1', 'astra', facts))
        self.assertEqual(len(calls), 1)  # the second site denied without another ledger read
        self.assertEqual(facts['central'], 'ledger_timeout')


if __name__ == '__main__':
    unittest.main()
