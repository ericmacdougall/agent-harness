"""Disposable DATA controls: real locks, inode changes, append-C and sealed restore."""
import fcntl
import json
import multiprocessing
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'harness/hooks'), str(ROOT / 'harness/mission_control')]
import collectors as col
import events as ev
import fabric_state as fs


def append(root, name):
    col._fabric_append(Path(root) / fs.DATA, (json.dumps(ev.make('owner', 'fixture', name, eid='fixture:' + name)) + '\n').encode())


def paused_restore(root, bundle, preimage, digest, reached, release):
    def barrier(stage):
        if stage == 'after_data_replace':
            reached.set()
            if not release.wait(8):
                raise RuntimeError('barrier deadline')
    fs.restore(root, bundle, preimage, operation_id='same-op', expected=digest, quiesced=True, fault=barrier)


class StateSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'sources'
        self.root.mkdir()
        append(self.root, 'A')
        self.bundle = self.base / 'snapshot'
        self.digest = fs.snapshot(self.root, self.bundle)

    def ids(self):
        return [json.loads(line)['id'] for line in (self.root / fs.DATA).read_bytes().splitlines()]

    def test_mixed_generation_rejected_before_live_mutation(self):
        append(self.root, 'B')
        newer = self.base / 'newer'
        fs.snapshot(self.root, newer)
        (self.bundle / 'accepted.ndjson').write_bytes((newer / 'accepted.ndjson').read_bytes())
        before = (self.root / fs.DATA).read_bytes()
        with self.assertRaises(fs.Hold):
            fs.restore(self.root, self.bundle, self.base / 'preimage', operation_id='op', expected=self.digest, quiesced=True)
        self.assertEqual((self.root / fs.DATA).read_bytes(), before)
        self.assertFalse((self.root / fs.FENCE).exists())
        append(self.root, 'C')
        self.assertEqual(self.ids(), ['fixture:A', 'fixture:B', 'fixture:C'])

    def test_tail_preserved_in_bundle_but_never_glued_to_restored_data(self):
        with (self.root / fs.DATA).open('ab') as handle:
            handle.write(b'{"torn')
        tail_bundle = self.base / 'with-tail'
        digest = fs.snapshot(self.root, tail_bundle)
        self.assertEqual((tail_bundle / 'unaccepted-tail.bin').read_bytes(), b'{"torn')
        fs.restore(self.root, tail_bundle, self.base / 'preimage', operation_id='op', expected=digest, quiesced=True)
        append(self.root, 'B')
        self.assertEqual(self.ids(), ['fixture:A', 'fixture:B'])
        self.assertEqual((tail_bundle / 'unaccepted-tail.bin').read_bytes(), b'{"torn')

    def test_same_op_helper_cannot_enter_after_inode_replacement(self):
        append(self.root, 'B')
        old_inode = (self.root / fs.DATA).stat().st_ino
        context = multiprocessing.get_context('spawn')
        reached, release = context.Event(), context.Event()
        child = context.Process(target=paused_restore, args=(str(self.root), str(self.bundle),
                                str(self.base / 'preimage'), self.digest, reached, release))
        child.start()
        try:
            self.assertTrue(reached.wait(5))
            self.assertNotEqual(old_inode, (self.root / fs.DATA).stat().st_ino)
            # Real baseline demonstration: the new DATA inode alone is lockable while P1 owns the old inode.
            fd = os.open(self.root / fs.DATA, os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
            before = {name: (self.root / name).read_bytes() for name in (fs.DATA, fs.CHECKPOINT, fs.JOURNAL, fs.FENCE)}
            for abort in (False, True):
                with self.assertRaises(fs.Busy):
                    fs.recover(self.root, operation_id='same-op', abort=abort, quiesced=True)
            self.assertEqual(before, {name: (self.root / name).read_bytes() for name in before})
        finally:
            release.set()
            child.join(10)
        self.assertEqual(child.exitcode, 0)

    def test_post_unfence_crash_then_append_c_survives_resume_and_abort(self):
        append(self.root, 'B')
        def crash(stage):
            if stage == 'after_unfence':
                raise OSError('synthetic crash before final receipt')
        with self.assertRaises(OSError):
            fs.restore(self.root, self.bundle, self.base / 'preimage', operation_id='op', expected=self.digest,
                       quiesced=True, fault=crash)
        self.assertFalse((self.root / fs.FENCE).exists())
        append(self.root, 'C')
        before = {name: (self.root / name).read_bytes() for name in (fs.DATA, fs.CHECKPOINT)}
        for _ in range(2):
            fs.recover(self.root, operation_id='op')
        with self.assertRaises(fs.Hold):
            fs.recover(self.root, operation_id='op', abort=True, quiesced=True)
        self.assertEqual(before, {name: (self.root / name).read_bytes() for name in before})
        self.assertEqual(self.ids(), ['fixture:A', 'fixture:C'])
        pre = fs.verify(self.base / 'preimage')[0]
        self.assertGreater(pre['accepted_offset'], (self.bundle / 'accepted.ndjson').stat().st_size)
        fs.restore(self.root, self.bundle, self.base / 'fresh-preimage', operation_id='new-op',
                   expected=self.digest, quiesced=True)
        self.assertIn(b'fixture:C', (self.base / 'fresh-preimage/accepted.ndjson').read_bytes())

    def test_precommit_failure_fenced_then_resume(self):
        def crash(stage):
            if stage == 'after_data_replace':
                raise OSError('synthetic crash between pair replacements')
        with self.assertRaises(OSError):
            fs.restore(self.root, self.bundle, self.base / 'preimage', operation_id='op', expected=self.digest,
                       quiesced=True, fault=crash)
        with self.assertRaises(fs.Hold):
            append(self.root, 'C')
        fs.recover(self.root, operation_id='op', quiesced=True)
        append(self.root, 'C')
        self.assertEqual(self.ids(), ['fixture:A', 'fixture:C'])

    def test_unknown_or_malformed_phase_holds_all_state_bytes(self):
        def crash(stage):
            if stage == 'after_data_replace':
                raise OSError('crash before pair publication')
        with self.assertRaises(OSError):
            fs.restore(self.root, self.bundle, self.base / 'preimage', operation_id='op', expected=self.digest,
                       quiesced=True, fault=crash)
        journal = json.loads((self.root / fs.JOURNAL).read_bytes())
        for phase in ('FUTURE_PHASE', 'FENCED', '', None, [], {'phase': 'PRECOMMIT'}):
            for abort in (False, True):
                with self.subTest(phase=phase, abort=abort):
                    bad = {**journal, 'phase': phase}
                    (self.root / fs.JOURNAL).write_text(json.dumps(bad))
                    before = {name: (self.root / name).read_bytes() for name in (fs.DATA, fs.CHECKPOINT, fs.JOURNAL, fs.FENCE)}
                    with self.assertRaises(fs.Hold):
                        fs.recover(self.root, operation_id='op', abort=abort, quiesced=True)
                    self.assertEqual(before, {name: (self.root / name).read_bytes() for name in before})
                    with self.assertRaises(fs.Hold):
                        fs._install(self.root, bad, self.bundle, self.digest, lambda stage: None)
                    self.assertEqual(before, {name: (self.root / name).read_bytes() for name in before})
