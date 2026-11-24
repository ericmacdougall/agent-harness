"""Egress gate, pre-push scanner hold-back and backfill order (goodqa#17119; click-test F1 of PR #316, class C11).

Synthetic data only. Markers are generated per test run; the leak scan reads every object of every remote repo,
tree entries (names) included, so a marker in a path, a blob or a commit message is found.
"""
import ast
import os
import secrets
import subprocess
import time
import unittest

from transcripts_testlib import Base, IdentityRedact, T, UUID1, UUID2, rec


def all_object_bytes(test):
    """Raw bytes of every object (blobs, trees with entry names, commits with messages) in every remote repo."""
    out = b''
    for p in test.remote.iterdir():
        if not p.name.endswith('.git'):
            continue
        r = subprocess.run(['git', '--git-dir', str(p), 'cat-file', '--batch-all-objects', '--batch'],
                           capture_output=True, env=dict(os.environ, **test.env))
        out += r.stdout
        refs = subprocess.run(['git', '--git-dir', str(p), 'for-each-ref', '--format=%(refname)'],
                              capture_output=True, env=dict(os.environ, **test.env))
        out += refs.stdout
    return out


class EgressPathTest(Base):
    def test_held_secret_shaped_path_reaches_no_remote_object(self):
        """Click-test F1 repro: a held file whose directory name trips pass 2 must not leak into the catalog."""
        marker = 'SECRETX' + secrets.token_hex(8)
        IdentityRedact.flag_marker = marker.encode()
        self.write('claude-projects', '-work-%s/%s.jsonl' % (marker, UUID1), rec(1) + rec(2) + rec(3))
        self.write('claude-projects', '-work-clean/%s.jsonl' % UUID2, rec(4) + rec(5))
        code, r = self.sync('takeover')
        self.assertEqual(code, 2)
        self.assertNotEqual(r['status'], 'ok')
        self.assertIn(T.CATALOG, self.repos(), 'the clean file must still archive')
        blob = all_object_bytes(self)
        self.assertGreater(len(blob), 0)
        self.assertFalse(marker.encode() in blob, "marker leaked into a remote object")
        self.assertIn(b'-work-clean', blob, 'positive control: the clean path is in the catalog')

    def test_gitleaks_only_path_hit_holds_file_and_leaks_nothing(self):
        """A path pass 2 misses but the third scanner flags: the chunk path cannot leave, so the file is held."""
        marker = 'GLFAKE-' + secrets.token_hex(8)
        self.write('claude-projects', '-work-%s/%s.jsonl' % (marker, UUID1), rec(1) + rec(2))
        self.write('claude-projects', '-work-clean/%s.jsonl' % UUID2, rec(3))
        code, r = self.sync('takeover')
        self.assertEqual(code, 2)
        self.assertFalse(marker.encode() in all_object_bytes(self), "marker leaked into a remote object")
        reasons = [h['reason'] for h in r['held']]
        self.assertEqual(len(reasons), 1, reasons)
        self.assertTrue(reasons[0] in ('refused:egress', 'refused:metadata') or reasons[0].startswith('scanner:'), reasons)
        self.assertEqual(len(self.chunks()), 1, 'the clean file archived')


class EgressGateUnitTest(Base):
    def setUp(self):
        super().setUp()
        self.cfg = T.Cfg()
        T.ensure_home(self.cfg)
        self.cfg.egress_registered = {}

    def test_dirty_blob_refuses_whole_commit(self):
        IdentityRedact.flag_marker = b'SECRETXBLOB'
        T.Remote(self.cfg).ensure('agent-transcripts-x')
        with self.assertRaises(T.EgressRefused) as cm:
            T.publish_tree(self.cfg, 'agent-transcripts-x', {'ok.json': b'{}\n', 'b.json': b'{"v":"SECRETXBLOB"}\n'},
                           'msg', overwrite=True)
        self.assertNotIn('SECRETXBLOB', str(cm.exception))
        self.assertIsNone(self.tip('agent-transcripts-x'))

    def test_dirty_message_and_gitleaks_path_refuse(self):
        T.Remote(self.cfg).ensure('agent-transcripts-x')
        IdentityRedact.flag_marker = b'SECRETXMSG'
        with self.assertRaises(T.EgressRefused):
            T.publish_tree(self.cfg, 'agent-transcripts-x', {'a.json': b'{}\n'}, 'update SECRETXMSG', overwrite=True)
        with self.assertRaises(T.EgressRefused):
            T.publish_tree(self.cfg, 'agent-transcripts-x', {'dir-GLFAKE-1234/a.json': b'{}\n'}, 'm', overwrite=True)
        self.assertIsNone(self.tip('agent-transcripts-x'))

    def test_unregistered_or_changed_outbox_file_refuses(self):
        T.Remote(self.cfg).ensure('agent-transcripts-x')
        p = os.path.join(self.cfg.home, 'tmpchunk.zst')
        with open(p, 'wb') as f:
            f.write(T.compress(b'{"a":1}\n'))
        with self.assertRaises(T.EgressRefused):
            T.publish_tree(self.cfg, 'agent-transcripts-x', {'c.zst': p}, 'm')
        import hashlib
        with open(p, 'rb') as f:
            self.cfg.egress_registered[os.path.abspath(p)] = hashlib.sha256(f.read()).hexdigest()
        with open(p, 'ab') as f:
            f.write(b'x')  # changed after the rescan
        with self.assertRaises(T.EgressRefused):
            T.publish_tree(self.cfg, 'agent-transcripts-x', {'c.zst': p}, 'm')
        self.assertIsNone(self.tip('agent-transcripts-x'))

    def test_filter_drops_only_dirty_jsonl_lines(self):
        IdentityRedact.flag_marker = b'SECRETXLINE'
        files = {'index/h.jsonl': b'{"a":1}\n{"b":"SECRETXLINE"}\n{"c":3}\n', 'manifests/x.json': b'{"v":"SECRETXLINE"}\n',
                 'manifests/y.json': b'{}\n'}
        out, dropped = T.egress_filter(self.cfg, 'agent-transcripts', files, 'm')
        self.assertEqual(out['index/h.jsonl'], b'{"a":1}\n{"c":3}\n')
        self.assertNotIn('manifests/x.json', out)
        self.assertIn('manifests/y.json', out)
        self.assertEqual(len(dropped), 2)

    def test_missing_gitleaks_refuses(self):
        self.setenv(TRANSCRIPTS_GITLEAKS='/nonexistent/gitleaks')
        with self.assertRaises(T.Refused):
            T.gitleaks_scan(self.cfg, b'x\n')

    def test_off_only_with_local_remote(self):
        self.setenv(TRANSCRIPTS_GITLEAKS='off')
        self.assertIsNone(T.gitleaks_bin(self.cfg))
        self.cfg.local = False
        with self.assertRaises(T.Refused):
            T.gitleaks_bin(self.cfg)


class ScannerHoldTest(Base):
    def test_rescan_hit_holds_whole_file_and_pushes_none_of_it(self):
        """A hit that survives redaction, in a LATER chunk, must keep EVERY chunk of that file local."""
        self.setenv(TRANSCRIPTS_CHUNK_MAX_BYTES=400, TRANSCRIPTS_SEAL_MIN_BYTES=1)
        marker = 'GLFAKE-' + secrets.token_hex(6)
        data = b''.join(rec(i) for i in range(1, 8)) + rec(8, text='key ' + marker)
        self.write('claude-projects', '-work-a/%s.jsonl' % UUID1, data)
        self.write('claude-projects', '-work-b/%s.jsonl' % UUID2, rec(20) + rec(21))
        code, r = self.sync('takeover')
        self.assertEqual(code, 2)
        self.assertFalse(marker.encode() in all_object_bytes(self), "marker leaked into a remote object")
        held = [h for h in r['held'] if h['reason'].startswith('scanner:')]
        self.assertEqual(len(held), 1, r['held'])
        self.assertIn('gitleaks:fake-leak', held[0]['reason'])
        self.assertEqual(held[0]['line'], 8)
        self.assertEqual(r['egress']['scanner_held_files'], 1)
        names = list(self.chunks())
        self.assertTrue(names, 'the clean file archived')
        self.assertFalse([n for n in names if '-work-a' in n], 'no chunk of the held file was pushed')
        st = self.state()
        e = st['files']['claude-projects/-work-a/%s.jsonl' % UUID1]
        self.assertFalse([c for g in e['gens'] for c in g['chunks']], 'held file rewound to nothing staged')


class BackfillOrderTest(Base):
    def test_backfill_is_oldest_first_sync_newest_first(self):
        now = time.time()
        for n, age in ((1, 10), (2, 30), (3, 20)):
            p = self.write('claude-projects', 'p/%s-%d.jsonl' % (UUID1[:-1], n), rec(n))
            os.utime(p, (now - age * 86400, now - age * 86400))
        seen = []
        orig = T.Run.process_file

        def spy(run, key, *a):
            seen.append(key.rsplit('-', 1)[1])
            return orig(run, key, *a)
        T.Run.process_file = spy
        self.addCleanup(setattr, T.Run, 'process_file', orig)
        self.main('backfill', '--budget-seconds', '60')
        self.assertEqual(seen, ['2.jsonl', '3.jsonl', '1.jsonl'])
        for n in (1, 2, 3):
            p = self.roots['claude-projects'] / ('p/%s-%d.jsonl' % (UUID1[:-1], n))
            with open(p, 'ab') as f:
                f.write(rec(10 + n))
            t = now - (40 - n) * 3600
            os.utime(p, (t, t))
        seen.clear()
        self.sync('pr')
        self.assertEqual(seen, ['3.jsonl', '2.jsonl', '1.jsonl'])

    def test_max_load_must_be_positive(self):
        code, _ = self.main('backfill', '--max-load', '0')
        self.assertNotEqual(code, 0)
        self.assertIsNone(self.receipt(), 'refused before any run')


class ChokePointGuardTest(unittest.TestCase):
    def test_only_publish_tree_runs_commit_tree_or_push(self):
        with open(T.__file__, encoding='utf-8') as f:
            src = f.read()
        tree = ast.parse(src)
        owners = []
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for node in ast.walk(fn):
                    if isinstance(node, ast.Constant) and node.value in ('commit-tree', 'push'):
                        owners.append(fn.name)
        # nested functions are walked by their parent too; every site must be inside publish_tree
        self.assertTrue(owners)
        self.assertEqual(set(owners), {'publish_tree'}, owners)


if __name__ == '__main__':
    unittest.main()
