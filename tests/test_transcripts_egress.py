"""Egress gate, pre-push scanner hold-back and backfill order (goodqa#17119; click-test F1 of PR #316, class C11).

Synthetic data only. Markers are generated per test run; the leak scan reads every object of every remote repo,
tree entries (names) included, so a marker in a path, a blob or a commit message is found.
"""
import ast
import os
import secrets
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from transcripts_testlib import Base, IdentityRedact, T, UUID1, UUID2, rec  # noqa: E402


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
        # gate F6: pinned. The chunk's sidecar carries the relpath, so the pre-push rescan (gitleaks over the sidecar)
        # is the layer that catches it, before any egress filter is reached.
        self.assertEqual(reasons, ['scanner:gitleaks:fake-leak'])
        self.assertIsNone(r['held'][0]['line'], 'a sidecar-only hit has no source line')
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


class HoldAcrossGenerationsTest(Base):
    def test_older_generation_staged_chunks_of_a_held_file_never_leave(self):
        """PR #316 gate F2: gen 1 staged clean (pushes stopped), the file is rewritten, gen 2 holds a hit. None of
        the file's bytes may leave, gen 1's already-rescanned chunks included."""
        gen1 = 'GENONE' + secrets.token_hex(6)
        marker = 'GLFAKE-' + secrets.token_hex(6)
        key = 'claude-projects/-work-a/%s.jsonl' % UUID1
        self.write('claude-projects', '-work-a/%s.jsonl' % UUID1,
                   b''.join(rec(i, text='%s %d' % (gen1, i)) for i in range(1, 9)))
        self.write('claude-projects', '-work-b/%s.jsonl' % UUID2, rec(20) + rec(21))
        T.ensure_home(T.Cfg())
        (self.home / 'killswitch.json').write_text('{"kind": "hold-for-test"}')  # stage, do not push
        self.sync('takeover')
        st = self.state()
        self.assertTrue([c for g in st['files'][key]['gens'] for c in g['chunks'] if c['status'] == 'staged'])
        os.unlink(self.home / 'killswitch.json')
        self.write('claude-projects', '-work-a/%s.jsonl' % UUID1, rec(30, text='key ' + marker))  # shorter: gen 2
        code, r = self.sync('takeover')
        self.assertEqual(code, 2)
        e = self.state()['files'][key]
        self.assertEqual(len(e['gens']), 2, 'the rewrite started generation 2')
        blob = all_object_bytes(self)
        self.assertFalse(marker.encode() in blob, 'gen 2 marker leaked')
        self.assertFalse(gen1.encode() in blob, 'a staged gen 1 chunk of the held file was pushed')
        self.assertFalse([n for n in self.chunks() if '-work-a' in n], 'no chunk of the held file was pushed')
        self.assertTrue([n for n in self.chunks() if '-work-b' in n], 'positive control: the clean file archived')
        self.assertEqual(e['held']['reason'], 'scanner:gitleaks:fake-leak')
        self.assertFalse([c for g in e['gens'] for c in g['chunks'] if c['status'] == 'staged'],
                         'every generation rolled back')

    def test_publish_refuses_a_group_with_a_held_file(self):
        """The invariant behind F2 is enforced in push_group, not only by the filters before it."""
        run = T.Run.__new__(T.Run)
        e = {'held': {'reason': 'scanner:x'}, 'gens': []}
        with self.assertRaises(T.Refused):
            T.Run.push_group(run, 'agent-transcripts-x', [('k', e, {'chunks': []}, {'path': 'p'}, (b'', b''))])

    def test_a_hold_from_an_earlier_run_withdraws_chunks_still_staged(self):
        """A held entry that still has staged chunks (any generation, any run) is withdrawn at publish."""
        key = 'claude-projects/-work-a/%s.jsonl' % UUID1
        self.write('claude-projects', '-work-a/%s.jsonl' % UUID1, rec(1) + rec(2))
        T.ensure_home(T.Cfg())
        (self.home / 'killswitch.json').write_text('{"kind": "hold-for-test"}')
        self.sync('takeover')
        os.unlink(self.home / 'killswitch.json')
        st = self.state()
        st['files'][key]['held'] = {'reason': 'refused:egress', 'line': None, 'ruleset': 'test-identity-1',
                                    'since': '2026-11-24T00:00:00Z', 'attempts': 1, 'retry_at': '2099-01-01T00:00:00Z'}
        T.atomic_write(str(self.home / 'state.json'), T.jdump(st) + b'\n')
        self.sync('takeover')
        self.assertFalse(self.chunks(), 'nothing of the held file was pushed')
        e = self.state()['files'][key]
        self.assertFalse([c for g in e['gens'] for c in g['chunks'] if c['status'] == 'staged'])


class WithheldManifestTest(Base):
    def test_a_withheld_manifest_keeps_the_status_off_ok_until_it_passes(self):
        """PR #316 gate F1: a manifest dropped at the egress gate is persisted and retried; the second run is still
        not ok, and once it passes it is published and the status returns to ok."""
        key = 'claude-projects/-work-a/%s.jsonl' % UUID1
        self.write('claude-projects', '-work-a/%s.jsonl' % UUID1, rec(1) + rec(2))
        orig = T.manifest_of
        marker = 'GLFAKE-' + secrets.token_hex(6)

        def dirty(cfg, k, e):
            m = orig(cfg, k, e)
            if k == key:
                m['source_path'] = '/srv/%s/x' % marker  # a manifest-only field that fails the scanner
            return m
        T.manifest_of = dirty
        self.addCleanup(setattr, T, 'manifest_of', orig)
        code, r = self.sync('takeover')
        self.assertEqual(r['status'], 'held')
        self.assertTrue(self.chunks(), 'the chunks themselves archived')
        code, r = self.sync('takeover')  # nothing changed: before the fix this run reported ok
        self.assertNotEqual(code, 0)
        self.assertEqual(r['status'], 'held')
        self.assertEqual(r['egress']['catalog_withheld_manifests'], 1)
        self.assertEqual(self.state()['catalog_withheld'], [key])
        self.assertFalse(marker.encode() in all_object_bytes(self))
        T.manifest_of = orig
        code, r = self.sync('takeover')
        self.assertEqual(r['status'], 'ok', r)
        self.assertEqual(self.state()['catalog_withheld'], [])
        mpath = T.manifest_path(T.Cfg(), key)
        self.assertIn(mpath, self.tree(T.CATALOG), 'the manifest is published once it passes')

    def test_a_dropped_index_line_keeps_the_status_off_ok_until_it_passes(self):
        """Gate F1, non-manifest side: an index line dropped at the gate is retried by the next unchanged run."""
        self.write('claude-projects', '-work-a/%s.jsonl' % UUID1, rec(1) + rec(2))
        orig = T.index_rows
        marker = 'GLFAKE-' + secrets.token_hex(6)

        def dirty(cfg, st):
            rows = orig(cfg, st)
            return rows + [dict(rows[0], name=marker)] if rows else rows
        T.index_rows = dirty
        self.addCleanup(setattr, T, 'index_rows', orig)
        code, r = self.sync('takeover')
        self.assertEqual(r['status'], 'held')
        code, r = self.sync('takeover')  # unchanged: the catalog is still incomplete
        self.assertNotEqual(code, 0)
        self.assertEqual(r['status'], 'held')
        self.assertEqual(r['egress']['catalog_withheld_other'], 1)
        self.assertFalse(marker.encode() in all_object_bytes(self))
        T.index_rows = orig
        code, r = self.sync('takeover')
        self.assertEqual(r['status'], 'ok', r)
        self.assertEqual(r['egress']['catalog_withheld_other'], 0)


class ReadOnceTest(Base):
    def test_outbox_file_swapped_after_the_gate_is_not_published(self):
        """PR #316 gate F4: the bytes written are the bytes the gate read."""
        cfg = T.Cfg()
        T.ensure_home(cfg)
        cfg.egress_registered = {}
        T.Remote(cfg).ensure('agent-transcripts-x')
        p = os.path.join(cfg.home, 'tmpchunk.zst')
        with open(p, 'wb') as f:
            f.write(T.compress(b'{"a":1}\n'))
        import hashlib
        with open(p, 'rb') as f:
            cfg.egress_registered[os.path.abspath(p)] = hashlib.sha256(f.read()).hexdigest()
        orig = T.egress_check

        def swap(*a, **kw):
            out = orig(*a, **kw)
            with open(p, 'wb') as f:
                f.write(T.compress(b'{"swapped":1}\n'))
            return out
        T.egress_check = swap
        self.addCleanup(setattr, T, 'egress_check', orig)
        with self.assertRaises(T.GitError) as cm:
            T.publish_tree(cfg, 'agent-transcripts-x', {'c.zst': p}, 'm')
        self.assertIn('hash mismatch', str(cm.exception))
        self.assertIsNone(self.tip('agent-transcripts-x'))


REAL_PATH = os.environ.get('PATH', '')  # read at import, before Base puts the stub scanner first on PATH
# read at import too: Base.setUp clears every TRANSCRIPTS_* variable before a test's own setUp runs
REQUIRE_GITLEAKS = os.environ.get('TRANSCRIPTS_REQUIRE_GITLEAKS') == '1'
REAL_HOME = os.path.expanduser('~')


def real_gitleaks():
    import shutil
    for c in (shutil.which('gitleaks', path=REAL_PATH), os.path.join(REAL_HOME, '.local/bin/gitleaks'),
              '/opt/homebrew/bin/gitleaks'):
        if c and os.path.isfile(c) and os.access(c, os.X_OK) and 'stubbin' not in c:
            return c
    return None


class RealGitleaksTest(Base):
    """PR #316 gate F3: the production command line against the installed, pinned binary. Skipped (and said so)
    when the binary is absent; TRANSCRIPTS_REQUIRE_GITLEAKS=1 turns the skip into a failure for the hosts that push."""

    def setUp(self):
        super().setUp()
        b = real_gitleaks()
        if not b:
            if REQUIRE_GITLEAKS:
                self.fail('gitleaks %s is required on this host but was not found' % T.GITLEAKS_VERSION)
            self.skipTest('real gitleaks not installed on this host')
        self.setenv(TRANSCRIPTS_GITLEAKS=b)
        self.bin = b
        self.cfg = T.Cfg()

    @staticmethod
    def token():
        # built at run time from a seeded hash, so no token-shaped literal sits in the source
        import hashlib
        body = hashlib.sha256(b'transcripts-real-gitleaks-seed-1').hexdigest()
        return ('ghp' + '_' + body[:36]).encode()

    def test_pinned_version(self):
        r = subprocess.run([self.bin, 'version'], capture_output=True, timeout=30)
        self.assertEqual(r.returncode, 0)
        self.assertIn(T.GITLEAKS_VERSION, r.stdout.decode())

    def test_flags_accepted_and_clean_input_gives_no_findings(self):
        self.assertEqual(T.gitleaks_scan(self.cfg, b'{"a":1}\n{"b":"hello world"}\n'), [])

    def test_line_mapping_first_and_last_line(self):
        t = self.token()
        first = T.gitleaks_scan(self.cfg, b'{"k":"' + t + b'"}\n{"a":1}\n{"b":2}\n')
        self.assertEqual([n for _, n in first], [1], first)
        self.assertTrue(all(k.startswith('gitleaks:') for k, _ in first))
        last = T.gitleaks_scan(self.cfg, b'{"a":1}\n{"b":2}\n{"c":3}\n{"d":4}\n{"k":"' + t + b'"}\n')
        self.assertEqual([n for _, n in last], [5], last)

    def test_value_never_returned(self):
        t = self.token()
        out = T.gitleaks_scan(self.cfg, b'x\n' + t + b'\n')
        self.assertTrue(out)
        self.assertNotIn(t.decode(), repr(out))

    def test_filter_drops_exactly_the_dirty_index_line(self):
        t = self.token()
        files = {'index/h.jsonl': b'{"a":1}\n{"b":2}\n{"k":"' + t + b'"}\n{"c":3}\n'}
        out, dropped = T.egress_filter(self.cfg, 'agent-transcripts', files, 'm')
        self.assertEqual(out['index/h.jsonl'], b'{"a":1}\n{"b":2}\n{"c":3}\n')
        self.assertEqual(len(dropped), 1)
        self.assertEqual(T.egress_check(self.cfg, 'agent-transcripts', 'refs/heads/main', out, 'm'), [])


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
    def test_only_publish_tree_runs_git_write_plumbing(self):
        with open(T.__file__, encoding='utf-8') as f:
            src = f.read()
        tree = ast.parse(src)
        owners = []
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for node in ast.walk(fn):
                    if isinstance(node, ast.Constant) and node.value in ('commit-tree', 'push', 'hash-object', 'update-index', 'write-tree', 'update-ref', 'mktree',
                                                                       'send-pack', 'fast-import'):
                        owners.append(fn.name)
        # nested functions are walked by their parent too; every site must be inside publish_tree
        self.assertTrue(owners)
        self.assertEqual(set(owners), {'publish_tree'}, owners)

    def test_gh_writers_are_only_repo_create_behind_the_gate(self):
        """Gate F5: every gh call is listed. The only one that writes is `gh repo create` in Remote.ensure, which
        passes the repo name through egress_check first; every `gh api` call is a read (no method or field flags)."""
        with open(T.__file__, encoding='utf-8') as f:
            tree = ast.parse(f.read())
        writers, calls = [], 0
        write_flags = {'-X', '--method', '-f', '-F', '--field', '--raw-field', '--input'}
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(fn):
                if not (isinstance(node, ast.List) and node.elts and isinstance(node.elts[0], ast.Constant)
                        and node.elts[0].value == 'gh'):
                    continue
                calls += 1
                words = [x.value for x in node.elts if isinstance(x, ast.Constant)]
                self.assertTrue(len(words) >= 2 and words[1] in ('api', 'repo', 'auth'), words)
                if words[1] == 'api':
                    self.assertFalse(write_flags & set(words), (fn.name, words))
                if words[1] == 'repo':
                    self.assertEqual(words[2], 'create', words)
                    writers.append(fn)
        self.assertGreaterEqual(calls, 4)
        self.assertEqual([w.name for w in writers], ['ensure'])
        body = writers[0]
        gate = [n.lineno for n in ast.walk(body) if isinstance(n, ast.Call) and getattr(n.func, 'id', None) == 'egress_check']
        create = [n.lineno for n in ast.walk(body) if isinstance(n, ast.List) and n.elts
                  and getattr(n.elts[0], 'value', None) == 'gh']
        self.assertTrue(gate and create and min(gate) < min(create), (gate, create))


class RepoNameGateTest(Base):
    def test_a_secret_shaped_repo_name_is_never_created(self):
        cfg = T.Cfg()
        T.ensure_home(cfg)
        cfg.egress_registered = {}
        with self.assertRaises(T.EgressRefused):
            T.Remote(cfg).ensure('agent-transcripts-GLFAKE-1234')
        self.assertFalse(os.path.exists(cfg.url('agent-transcripts-GLFAKE-1234')))


if __name__ == '__main__':
    unittest.main()
