"""GoodQA goodqa#16740: a provider pool holds several concurrent reviews (slots); one cooldown blocks the pool."""

import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_usage_guard as base  # noqa: E402

guard = base.guard


class PoolCapacityTests(base.OwnerLiveness):
    POOL = 'fixture-pool'

    def capacity_store(self, capacity, root=None):
        return guard.UsageStore(root or self.store.root, pool_capacity={'codex': {self.POOL: capacity}})

    def run_for(self, label, store=None, facts=None):
        identity = guard.invocation_identity(self.subject, purpose=label, argv=[label], cwd=self.repo)
        store = store or self.store
        patch = (mock.patch.object(guard, 'owner_process_facts', return_value=facts) if facts
                 else mock.patch.object(guard, 'owner_process_facts', wraps=guard.owner_process_facts))
        with patch:
            return store.begin(self.subject, identity, owner='fixture', label=label, timeout=10,
                               kind='focused', minimum_bytes=0, aggregate_timeout=30)

    def head(self, alias, provider='codex'):
        return self.store.root / 'pools' / guard.digest([provider, alias]) / 'head.json'

    def event_count(self):
        return len(list((self.store.root / 'pools').glob('*/events/*.json')))

    def test_two_acquires_fit_third_refused(self):
        store = self.capacity_store(2)
        first, second, third = (self.run_for(name, store) for name in 'abc')
        store.acquire_pool('codex', self.POOL, first.run_id)
        store.acquire_pool('codex', self.POOL, second.run_id)
        with self.assertRaises(guard.PoolUnavailable) as refused:
            store.acquire_pool('codex', self.POOL, third.run_id)
        self.assertEqual(refused.exception.kind, 'active')
        self.assertIn(refused.exception.holder, {first.run_id, second.run_id})
        # NEG-1: the same run cannot take a second slot
        with self.assertRaises(guard.PoolUnavailable):
            store.acquire_pool('codex', self.POOL, first.run_id)
        # releasing one frees exactly one slot, and release finds the caller's own slot
        store.release_pool('codex', self.POOL, second.run_id)
        store.acquire_pool('codex', self.POOL, third.run_id)
        store.release_pool('codex', self.POOL, first.run_id)
        store.release_pool('codex', self.POOL, third.run_id)

    def test_default_capacity_is_one_for_unlisted_pools(self):
        first, second = self.run_for('a'), self.run_for('b')
        self.store.acquire_pool('codex', self.POOL, first.run_id)
        with self.assertRaises(guard.PoolUnavailable):
            self.store.acquire_pool('codex', self.POOL, second.run_id)

    def test_cooldown_on_one_slot_blocks_all(self):
        store = self.capacity_store(3)
        a, b, c = (self.run_for(name, store) for name in 'abc')
        store.acquire_pool('codex', self.POOL, a.run_id)
        store.acquire_pool('codex', self.POOL, b.run_id)
        store.release_pool('codex', self.POOL, b.run_id, reason='QUOTA', account_cooldown=True)
        # slot 3 is free and slot 1 is merely busy, but the whole pool is cooling down
        with self.assertRaises(guard.PoolUnavailable) as refused:
            store.acquire_pool('codex', self.POOL, c.run_id)
        self.assertEqual((refused.exception.kind, refused.exception.reason), ('cooldown', 'QUOTA'))
        # still blocks when the cooled slot is above a later, lower capacity
        with self.assertRaises(guard.PoolUnavailable) as lowered:
            self.capacity_store(1).acquire_pool('codex', self.POOL, c.run_id)
        self.assertEqual(lowered.exception.kind, 'cooldown')
        # AC-6: ack clears the cooled slot even though slot 1 is still running, and history is kept
        before = self.event_count()
        store.ack_pool('codex', self.POOL, actor='fixture', reason='availability changed', evidence='owned check')
        self.assertGreater(self.event_count(), before)
        store.acquire_pool('codex', self.POOL, c.run_id)

    def test_expired_cooldown_does_not_block_but_unknown_reset_does(self):
        store = self.capacity_store(2)
        a, b, c = (self.run_for(name, store) for name in 'abc')
        store.acquire_pool('codex', self.POOL, a.run_id)
        store.release_pool('codex', self.POOL, a.run_id, reason='AUTH', account_cooldown=True,
                           reset_at=time.time() + 60)
        with self.assertRaises(guard.PoolUnavailable):
            store.acquire_pool('codex', self.POOL, b.run_id)
        with mock.patch.object(guard.time, 'time', return_value=time.time() + 120):
            store.acquire_pool('codex', self.POOL, b.run_id)
        store.release_pool('codex', self.POOL, b.run_id, reason='QUOTA', account_cooldown=True)  # reset unknown
        with mock.patch.object(guard.time, 'time', return_value=time.time() + 10 ** 6):
            with self.assertRaises(guard.PoolUnavailable):
                store.acquire_pool('codex', self.POOL, c.run_id)

    def test_dead_slot_reconciled_without_touching_live_slot(self):
        store = self.capacity_store(2)
        child = self.child()
        dead = self.run_for('dead', store, facts=self.facts_for(child))
        # The simulated reboot makes every same-host owner dead, so the live holder is an owner on another host
        # (never provably dead from here), the same stand-in the existing never-reconciled test uses.
        live = self.run_for('live', store, facts=self.facts_for(child, host='another-host.example'))
        newcomer = self.run_for('new', store)
        store.acquire_pool('codex', self.POOL, dead.run_id)
        store.acquire_pool('codex', self.POOL, live.run_id)
        live_head = self.head(self.POOL + ':slot2').read_bytes()
        dead_head = self.head(self.POOL).read_bytes()
        with self.assertRaises(guard.PoolUnavailable):
            store.acquire_pool('codex', self.POOL, newcomer.run_id)
        child.kill(); child.wait(timeout=5)
        with self.future(), self.reboot():
            store.acquire_pool('codex', self.POOL, newcomer.run_id)
        self.assertTrue(self.reconciled_path(dead).exists())
        self.assertFalse(self.reconciled_path(live).exists())
        self.assertEqual(self.head(self.POOL + ':slot2').read_bytes(), live_head)  # NEG-3
        self.assertNotEqual(self.head(self.POOL).read_bytes(), dead_head)
        store.release_pool('codex', self.POOL, live.run_id)
        store.release_pool('codex', self.POOL, newcomer.run_id)

    def test_legacy_single_active_state_reads(self):
        legacy = self.run_for('legacy')
        self.store.acquire_pool('codex', self.POOL, legacy.run_id)  # capacity 1: exactly the pre-slot layout
        ref = json.loads(self.head(self.POOL).read_text())
        event = json.loads((self.head(self.POOL).parent / 'events' / (ref['event'] + '.json')).read_text())
        self.assertEqual(event['state']['active'], legacy.run_id)
        self.assertEqual([path.name for path in (self.store.root / 'pools').iterdir()],
                         [guard.digest(['codex', self.POOL])])
        other, third = self.run_for('b'), self.run_for('c')
        with self.assertRaises(guard.PoolUnavailable):
            self.store.acquire_pool('codex', self.POOL, other.run_id)
        store = self.capacity_store(3)  # the legacy holder is slot 1 and is released by its own run
        store.acquire_pool('codex', self.POOL, other.run_id)
        store.release_pool('codex', self.POOL, legacy.run_id)
        store.acquire_pool('codex', self.POOL, third.run_id)

    def test_corrupt_slot_fails_closed(self):
        store = self.capacity_store(3)
        a, b, c = (self.run_for(name, store) for name in 'abc')
        store.acquire_pool('codex', self.POOL, a.run_id)
        store.acquire_pool('codex', self.POOL, b.run_id)
        self.head(self.POOL + ':slot2').write_text('{"event": "bad"}')
        with self.assertRaises(guard.GuardError) as refused:
            store.acquire_pool('codex', self.POOL, c.run_id)
        self.assertNotIsInstance(refused.exception, guard.PoolUnavailable)
        self.assertEqual(refused.exception.reason, 'UNKNOWN')

    def test_capacity_above_bound_rejected(self):
        for bad in (9, 0, -1, True, '3', 2.0, None):
            with self.subTest(capacity=bad), self.assertRaises(guard.GuardError):
                self.capacity_store(bad)
        self.assertEqual(self.capacity_store(8).pool_capacity('codex', self.POOL), 8)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'review_policy.json'
            path.write_text(json.dumps({'pool_capacity': {'claude': {'default': 9}}}))
            with self.assertRaises(guard.GuardError):
                guard.load_pool_capacity(path)

    def test_shipped_policy_capacity(self):
        shipped = guard.load_pool_capacity()
        self.assertEqual(shipped['claude']['default'], 3)
        self.assertEqual(shipped['codex']['default'], 3)
        self.assertEqual(self.store.pool_capacity('claude', 'default'), 3)
        self.assertEqual(self.store.pool_capacity('kimi', 'default'), 1)
        runs = [self.run_for(name) for name in 'abcd']
        for run in runs[:3]:
            self.store.acquire_pool('claude', 'default', run.run_id)
        with self.assertRaises(guard.PoolUnavailable):
            self.store.acquire_pool('claude', 'default', runs[3].run_id)

    def test_capacity_never_comes_from_the_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'p.json'
            path.write_text(json.dumps({'pool_capacity': {'codex': {self.POOL: 8}}}))
            path.chmod(0o600)
            env = {'AGENT_HARNESS_REVIEW_POLICY': str(path), 'AGENT_HARNESS_POOL_CAPACITY': '8'}
            with mock.patch.dict(os.environ, env):
                self.assertEqual(guard.UsageStore(self.root / 'envstore').pool_capacity('codex', self.POOL), 1)
                self.assertEqual(guard.load_pool_capacity()['claude']['default'], 3)

    def test_slot_aliases_cannot_be_addressed_directly(self):
        run = self.run_for('a')
        with self.assertRaises(guard.GuardError):
            self.store.acquire_pool('codex', self.POOL + ':slot2', run.run_id)
        with self.assertRaises(guard.GuardError):
            self.store.release_pool('codex', self.POOL + ':slot2', run.run_id)

    def test_release_by_a_run_without_a_slot_is_refused(self):
        store = self.capacity_store(2)
        a, stranger = self.run_for('a', store), self.run_for('b', store)
        store.acquire_pool('codex', self.POOL, a.run_id)
        with self.assertRaises(guard.GuardError) as refused:
            store.release_pool('codex', self.POOL, stranger.run_id)
        self.assertEqual(refused.exception.message, 'Provider pool ownership changed')

    def test_release_and_ack_per_slot(self):
        store = self.capacity_store(2)
        a, b = self.run_for('a', store), self.run_for('b', store)
        store.acquire_pool('codex', self.POOL, a.run_id)
        store.acquire_pool('codex', self.POOL, b.run_id)
        store.release_pool('codex', self.POOL, a.run_id, reason='QUOTA', account_cooldown=True)
        held = self.head(self.POOL + ':slot2').read_bytes()  # b still runs on slot 2
        store.ack_pool('codex', self.POOL, actor='fixture', reason='availability changed', evidence='owned check')
        self.assertEqual(self.head(self.POOL + ':slot2').read_bytes(), held)
        self.assertNotEqual(self.head(self.POOL).read_bytes(), b'')
        store.release_pool('codex', self.POOL, b.run_id)
        c = self.run_for('c', store)
        store.acquire_pool('codex', self.POOL, c.run_id)  # cooldown on slot 1 was cleared


if __name__ == '__main__':
    unittest.main()
