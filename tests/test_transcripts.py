"""Transcript archive core tests (GoodQA #16650, spec "Design (phase 1)", ACs 1-12, 15, 16; NEGs 4-13, 16-19).

Synthetic data, local bare remotes, temp HOME and a failing gh stub (see transcripts_testlib).
Run: nice python3 -m unittest tests.test_transcripts -q
"""
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import transcripts_testlib as L  # noqa: E402
from transcripts_testlib import T, rec, UUID1, UUID2, UUID3  # noqa: E402


def lines(n, start=0, **kw):
    return b''.join(rec(i, **kw) for i in range(start, start + n))


class ContractTests(L.Base):
    """CLI contract the integration writer depends on: check codes, receipts, lock, requests, background."""

    def test_check_codes_and_json(self):
        code, out = self.main('check', '--json')
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)['status'], 'never-ok')
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(5))
        code, r = self.sync('pr')
        self.assertEqual(code, 0, r)
        self.assertTrue(r['ok'])
        self.assertEqual(r['checkpoint'], 'pr')
        self.assertTrue((self.home / 'receipts' / 'last-ok.json').exists())
        code, out = self.main('check', '--json')
        self.assertEqual(code, 0)
        j = json.loads(out)
        self.assertEqual(set(j), {'last_ok_at', 'age_min', 'status', 'reasons', 'exit', 'held'})
        self.assertEqual(j['held'], {'count': 0, 'by_reason': {}})
        # stale: age the ok receipt
        for name in ('last.json', 'last-ok.json'):
            p = self.home / 'receipts' / name
            d = json.loads(p.read_text())
            d['finished_at'] = '2020-01-01T00:00:00Z'
            p.write_text(json.dumps(d))
        code, out = self.main('check', '--max-age-min', '60')
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith('stale'))
        self.assertEqual((self.home.stat().st_mode & 0o777), 0o700)

    def test_lock_contention(self):
        """AC-11 / NEG-9: a second run exits fast with skipped: locked, leaves the receipt, queues a request."""
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        T.ensure_home(T.Cfg())
        fd = os.open(str(self.home / 'lock'), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            t0 = time.monotonic()
            code, out, err = self.cli('sync', '--checkpoint', 'deploy')
            self.assertLess(time.monotonic() - t0, 2.0)
            self.assertEqual(code, 0)
            self.assertIn('skipped: locked', out)
            self.assertFalse((self.home / 'receipts' / 'last.json').exists())
            reqs = os.listdir(self.home / 'requests')
            self.assertEqual(len(reqs), 1)
            self.assertTrue(reqs[0].startswith('deploy-'))
        finally:
            os.close(fd)  # the kernel releases the lock with the descriptor (dead holder case)
        code, r = self.sync('manual')
        self.assertIn('deploy', r['served_checkpoints'])
        self.assertEqual(os.listdir(self.home / 'requests'), [])

    def test_request_files_validated_and_reaped(self):
        cfg = T.Cfg()
        T.ensure_home(cfg)
        with self.assertRaises(T.Refused):
            T.drop_request(cfg, '../evil')
        T.drop_request(cfg, 'pr')
        old = self.home / 'requests' / 'deploy-1-1'
        old.write_text('')
        os.utime(old, (time.time() - 90000, time.time() - 90000))
        (self.home / 'requests' / 'bogus-1-1').write_text('')
        self.assertEqual(T.take_requests(cfg), {'pr'})
        self.assertEqual(os.listdir(self.home / 'requests'), [])

    def test_background_returns_fast(self):
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        t0 = time.monotonic()
        code, out, err = self.cli('sync', '--checkpoint', 'start', '--background')
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertEqual(code, 0)
        deadline = time.time() + 60
        while time.time() < deadline and not (self.home / 'receipts' / 'last.json').exists():
            time.sleep(0.2)
        r = self.receipt()
        self.assertIsNotNone(r)
        self.assertEqual(r['checkpoint'], 'start')
        self.assertTrue((self.home / 'logs' / 'sync.log').exists())

    def test_zstd_missing_refuses_visibly(self):
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        code, out, err = self.cli('sync', '--checkpoint', 'pr', env={'PATH': os.pathsep.join(
            [str(self.stub), L.GIT_DIR, '/usr/bin', '/bin']) if L.ZSTD_DIR not in (L.GIT_DIR, '/usr/bin', '/bin')
            else str(self.stub)})
        self.assertEqual(code, 2)
        self.assertIn('zstd', self.receipt()['error'])

    def test_local_remote_needs_explicit_allow(self):
        code, out, err = self.cli('status', env={'TRANSCRIPTS_ALLOW_LOCAL_REMOTE': '0'})
        self.assertEqual(code, 2)
        self.assertIn('ALLOW_LOCAL_REMOTE', err)


class ChunkTests(L.Base):

    def test_split_then_recover_byte_identical(self):
        """AC-4: identity redaction, ~120 MB, recovery from a fresh fetch equals the source bytes."""
        filler = hashlib.sha256(b'x').hexdigest() * 14
        rows = []
        size = 0
        i = 0
        while size < 120 * 1000 * 1000:
            line = rec(i, text='%d %s %s' % (i, hashlib.md5(str(i).encode()).hexdigest(), filler))
            rows.append(line)
            size += len(line)
            i += 1
        data = b''.join(rows)
        del rows
        self.write('claude-projects', '-work-proj/%s.jsonl' % UUID1, data)
        code, r = self.sync('pr', '--budget-seconds', '600')
        self.assertEqual(code, 0, r)
        chunks = sorted(self.chunks())
        self.assertEqual(len(chunks), 3)  # 120 MB / 48 MiB
        # fresh: wipe all local state, rebuild the index from the catalog, recover from git
        shutil.rmtree(self.home)
        code, out = self.main('reindex')
        self.assertEqual(code, 0)
        dest = Path(self.tmp) / 'out'
        code, out = self.main('recover', UUID1, '--to', str(dest), '--from', 'git')
        self.assertEqual(code, 0, self.last_err)
        got = dest / 'testhost' / 'claude-projects' / '-work-proj' / ('%s.jsonl' % UUID1)
        self.assertEqual(hashlib.sha256(got.read_bytes()).hexdigest(), hashlib.sha256(data).hexdigest())
        man = json.loads(self.blob(T.CATALOG, self.tree(T.CATALOG)[
            'manifests/testhost/claude-projects/-work-proj/%s.jsonl.json' % UUID1]))
        self.assertEqual(man['whole_sha256'], hashlib.sha256(data).hexdigest())
        self.assertTrue(man['fully_archived'])

    def test_chunker_never_splits_record(self):
        """AC-3 / NEG-7: chunks end on record boundaries, stay under the cap, concatenate back exactly."""
        self.setenv(TRANSCRIPTS_CHUNK_MAX_BYTES=4096)
        data = b''.join(rec(i, text='y' * ((i * 37) % 1500)) for i in range(60))
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, data)
        code, r = self.sync('pr')
        self.assertEqual(code, 0, r)
        paths = sorted(self.chunks(), key=lambda p: int(re.search(r'\.p(\d{5})\.', p).group(1)))
        self.assertGreater(len(paths), 5)
        joined = b''
        for p in paths:
            b = self.chunk_bytes(p)
            self.assertLessEqual(len(b), 4096)
            self.assertTrue(b.endswith(b'\n'))
            for ln in b.splitlines():
                json.loads(ln)  # every line is a whole record
            joined += b
        self.assertEqual(joined, data)

    def test_record_over_max_is_held(self):
        self.setenv(TRANSCRIPTS_CHUNK_MAX_BYTES=4096)
        data = lines(3) + rec(3, text='z' * 5000) + lines(3, start=4)
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, data)
        code, r = self.sync('pr')
        self.assertEqual(r['held'][0]['reason'], 'record-over-max')
        self.assertEqual(r['held'][0]['line'], 4)
        code, out = self.main('check', '--json')  # first run held a file, so no ok receipt yet: never-ok (3)
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)['held'], {'count': 1, 'by_reason': {'record-over-max': 1}})
        self.assertEqual(b''.join(self.chunk_bytes(p) for p in sorted(self.chunks())), lines(3))

    def test_chunk_names_carry_timestamps(self):
        data = (rec(0, ts='2026-11-01T10:00:00.123+02:00') + rec(1, ts='2026-11-03T23:59:59Z')
                + rec(2, ts='not a time'))
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, data)
        p2 = self.write('claude-wals', '%s/main.jsonl' % UUID2, b'{"event":"intent"}\n')
        os.utime(p2, (1762000000, 1762000000))  # 2025-11-01T12:26:40Z
        self.sync('pr')
        names = sorted(os.path.basename(p) for p in self.chunks())
        self.assertIn('%s.2026-11-01T08-00-00Z_2026-11-03T23-59-59Z.g1.p00001.jsonl.zst' % UUID1, names)
        self.assertIn('main.2025-11-01T12-26-40Z_2025-11-01T12-26-40Z.g1.p00001.jsonl.zst', names)
        wal = [p for p in self.chunks() if p.startswith('testhost/claude-wals/')][0]
        self.assertEqual(self.sidecar(wal)['ts_source'], 'mtime')
        self.assertEqual(self.sidecar(wal)['session'], UUID2)

    def test_partial_last_line_waits(self):
        p = self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3) + b'{"type":"user","partial')
        code, r = self.sync('pr')
        self.assertEqual(b''.join(self.chunk_bytes(x) for x in self.chunks()), lines(3))
        self.assertEqual(r['backlog']['files'], 0)  # a partial last line alone is not backlog
        self.assertEqual(self.main('check')[0], 0)
        with open(p, 'ab') as f:
            f.write(b'":1}\n')
        self.sync('pr')
        allb = b''.join(self.chunk_bytes(x) for x in sorted(self.chunks()))
        self.assertEqual(allb, p.read_bytes())

    def test_small_delta_waits_unless_forced(self):
        p = self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        code, r = self.sync('start')
        self.assertEqual(self.chunks(), {})
        self.assertEqual(r['backlog']['files'], 1)
        code, r = self.sync('pr')
        self.assertEqual(len(self.chunks()), 1)
        self.assertEqual(r['backlog']['files'], 0)


class IncrementalTests(L.Base):

    def test_second_run_noop(self):
        """AC-5: no source change -> no push, no commit."""
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(10))
        self.write('codex-wals', 'w.jsonl', lines(4))
        self.sync('pr')
        tips = {r: self.tip(r) for r in self.repos()}
        code, r = self.sync('pr')
        self.assertEqual(code, 0)
        self.assertEqual(r['chunks_pushed'], 0)
        self.assertEqual({x: self.tip(x) for x in self.repos()}, tips)

    def test_append_adds_new_chunks_only(self):
        p = self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(10))
        self.sync('pr')
        before = self.chunks()
        with open(p, 'ab') as f:
            f.write(lines(5, start=10))
        code, r = self.sync('pr')
        after = self.chunks()
        for path, (repo, oid) in before.items():
            self.assertEqual(after[path][1], oid)
        new = set(after) - set(before)
        self.assertEqual(len(new), 1)
        self.assertIn('.g1.p00002.', new.pop())
        self.assertEqual(b''.join(self.chunk_bytes(x) for x in sorted(after)), p.read_bytes())

    def test_generation_on_rewrite(self):
        """NEG-5: rewrite or truncation starts a new generation; old chunks stay."""
        p = self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(10))
        self.sync('pr')
        g1 = self.chunks()
        same_size = lines(10).replace(b'msg ', b'MSG ')
        p.write_bytes(same_size)
        os.utime(p, None)
        self.sync('pr')
        now = self.chunks()
        for k, v in g1.items():
            self.assertEqual(now[k], v)
        g2 = [k for k in now if '.g2.' in k]
        self.assertEqual(len(g2), 1)
        self.assertEqual(self.chunk_bytes(g2[0]), same_size)
        p.write_bytes(lines(2))
        self.sync('pr')
        self.assertEqual(len([k for k in self.chunks() if '.g3.' in k]), 1)

    def test_move_detection_archived_sessions(self):
        rel = '2026/11/01/rollout-2026-11-01T00-00-00-%s.jsonl' % UUID3
        p = self.write('codex-sessions', rel, lines(6))
        self.sync('pr')
        dst = self.roots['codex-archived'] / os.path.basename(rel)
        os.rename(p, dst)
        with open(dst, 'ab') as f:
            f.write(lines(3, start=6))
        code, r = self.sync('pr')
        self.assertEqual(code, 0, r)
        ch = sorted(self.chunks())
        self.assertEqual(len(ch), 2)
        self.assertFalse(any('.g2.' in c for c in ch))
        old = [c for c in ch if c.startswith('testhost/codex-sessions/')]
        new = [c for c in ch if c.startswith('testhost/codex-archived/')]
        self.assertEqual(len(old), 1)
        self.assertEqual(len(new), 1)
        self.assertIn('.p00002.', new[0])
        # range by range continuation: the moved file's first chunk range was matched, never re-pushed
        self.assertEqual(self.sidecar(new[0])['src_range'][0], self.sidecar(old[0])['src_range'][1])
        self.assertEqual(self.chunk_bytes(old[0]) + self.chunk_bytes(new[0]), dst.read_bytes())
        st = self.state()
        self.assertIn('codex-archived/' + os.path.basename(rel), st['files'])
        self.assertNotIn('codex-sessions/' + rel, st['files'])
        moved = json.loads(self.blob(T.CATALOG, self.tree(T.CATALOG)['manifests/testhost/codex-sessions/%s.json' % rel]))
        self.assertEqual(moved['moved_to'], 'codex-archived/' + os.path.basename(rel))

    def test_symlink_and_fifo_skipped(self):
        """NEG-4: a symlink to outside the root and a FIFO are skipped and never opened for writing."""
        outside = Path(self.tmp) / 'outside.jsonl'
        outside.write_bytes(lines(3))
        before = outside.stat().st_mtime_ns
        os.symlink(outside, self.roots['claude-projects'] / 'link.jsonl')
        os.mkfifo(self.roots['claude-projects'] / 'pipe.jsonl')
        os.symlink(Path(self.tmp), self.roots['claude-projects'] / 'dirlink')
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(2))
        code, r = self.sync('pr')
        self.assertEqual(code, 0, r)
        self.assertEqual(list(self.state()['files']), ['claude-projects/p/%s.jsonl' % UUID1])
        self.assertEqual(outside.stat().st_mtime_ns, before)

    def test_sources_untouched(self):
        """AC-7: bytes, mtimes and listings of every source are unchanged by sync, verify, cat, recover."""
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(20))
        self.write('claude-projects', 'p/%s/subagents/agent-a1.jsonl' % UUID1, lines(4))
        self.write('codex-sessions', '2026/11/01/rollout-x-%s.jsonl' % UUID3, lines(5))
        self.write('claude-wals', '%s/main.jsonl' % UUID2, lines(2) + b'{"partial')
        snap = self.snapshot()
        self.sync('pr')
        self.main('verify')
        self.main('cat', UUID1, '--local')
        self.main('cat', UUID1)
        self.main('recover', UUID1, '--to', str(Path(self.tmp) / 'rec'), '--from', 'local')
        self.main('verify', '--against-source')
        self.sync('pr')
        self.assertEqual(self.snapshot(), snap)


class RedactionGateTests(L.Base):

    def test_omit_record_not_file(self):
        """AC-6 / AC-16: an omitted record is replaced by its marker; the file keeps archiving."""
        IdentityRedact = L.IdentityRedact
        IdentityRedact.omit_marker = b'OMITME'
        data = lines(150) + rec(150, text='OMITME') + lines(149, start=151)
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, data)
        code, r = self.sync('pr')
        self.assertEqual(code, 0, r)
        self.assertEqual(r['omitted']['total'], 1)
        self.assertEqual(r['omitted']['by_kind'], {'fakekind': 1})
        (path,) = self.chunks()
        side = self.sidecar(path)
        self.assertEqual(side['omitted'], [{'line': 151, 'kind': 'fakekind'}])
        body = self.chunk_bytes(path).splitlines()
        self.assertEqual(len(body), 300)
        self.assertEqual(json.loads(body[150])['_archive'], 'omitted')
        self.assertNotIn(b'OMITME', self.chunk_bytes(path))
        self.assertEqual(body[151] + b'\n', rec(151))

    def test_omission_cap_run_level(self):
        L.IdentityRedact.omit_marker = b'OMITME'
        data = b''.join(rec(i, text='OMITME' if i % 100 == 0 else None) for i in range(1000))
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, data)
        code, r = self.sync('pr')
        self.assertEqual(r['status'], 'omission-cap')
        self.assertFalse(r['ok'])
        self.assertEqual(self.chunks(), {})
        code, out = self.main('check')
        self.assertEqual(code, 3)  # never-ok outranks failed
        self.assertIn('omission-cap', out)

    def test_omission_cap_run_rule_needs_1000_records(self):
        L.IdentityRedact.omit_marker = b'OMITME'
        data = b''.join(rec(i, text='OMITME' if i in (10, 200) else None) for i in range(300))  # 0.67 %, 300 records
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, data)
        code, r = self.sync('pr')
        self.assertTrue(r['ok'], r)
        self.assertEqual(r['omitted']['total'], 2)
        self.assertEqual(len(self.chunks()), 1)

    def test_omission_cap_per_file(self):
        L.IdentityRedact.omit_marker = b'OMITME'
        bad = b''.join(rec(i, text='OMITME' if i < 6 else None) for i in range(100))
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, bad)
        self.write('claude-projects', 'p/%s.jsonl' % UUID2, lines(2000))
        code, r = self.sync('pr')
        self.assertEqual(r['status'], 'omission-cap')
        names = list(self.chunks())
        self.assertTrue(any(UUID2 in n for n in names))
        self.assertFalse(any(UUID1 in n for n in names))
        self.assertEqual(r['held'][0]['reason'], 'omission-cap')
        code, r = self.sync('pr')  # same ruleset, hold not yet due: the file stays held and the run is not ok
        self.assertFalse(r['ok'], r)
        self.assertEqual(r['status'], 'held')
        self.assertEqual(r['held'][0]['reason'], 'omission-cap')
        self.assertFalse(any(UUID1 in n for n in self.chunks()))
        L.IdentityRedact.RULESET_VERSION = 'test-identity-2'  # rules tuned
        L.IdentityRedact.omit_marker = None
        code, r = self.sync('pr')
        self.assertEqual(r['held'], [])
        self.assertTrue(any(UUID1 in n for n in self.chunks()))

    def test_reverify_before_push(self):
        """NEG-16: a corrupted staged chunk and an older-ruleset chunk are kept out and re-chunked."""
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(5))
        self.write('claude-projects', 'p/%s.jsonl' % UUID2, lines(5, start=5))
        T.ensure_home(T.Cfg())
        (self.home / 'killswitch.json').write_text('{"kind": "hold-for-test"}')  # local switch only
        self.sync('pr')  # stages, kill switch blocks the push
        staged = [os.path.join(dp, f) for dp, _, fs in os.walk(self.home / 'outbox') for f in fs if f.endswith('.zst')]
        self.assertEqual(len(staged), 2)
        bad = [s for s in staged if UUID1 in s][0]
        with open(bad, 'r+b') as f:
            f.seek(10)
            f.write(b'\x00\x01\x02')
        os.unlink(self.home / 'killswitch.json')
        L.IdentityRedact.RULESET_VERSION = 'test-identity-2'  # UUID2's staged chunk is now an older ruleset
        code, r = self.sync('pr')
        self.assertEqual(code, 0, r)
        alerts = (self.home / 'alerts.jsonl').read_text()
        self.assertEqual(alerts.count('reverify-failed'), 2)
        self.assertEqual(self.chunks(), {})  # both held back, rewound to their source offsets
        code, r = self.sync('pr')  # re-chunked from source under the current ruleset
        self.assertEqual(code, 0, r)
        self.assertEqual(len(self.chunks()), 2)
        for p in self.chunks():
            side = self.sidecar(p)
            self.assertEqual(side['ruleset_version'], 'test-identity-2')
            self.assertEqual(hashlib.sha256(self.chunk_bytes(p)).hexdigest(), side['sha256'])

    def test_metadata_is_gated(self):
        """Sidecars are pushed: a field that trips the verifier is dropped, never pushed."""
        class Gate(L.IdentityRedact):
            @classmethod
            def verify_bytes(cls, data):
                return [('canary', 1)] if b'SECRETPROJ' in data and b'"project"' in data else []
        T.redact_mod = lambda: Gate
        self.write('claude-projects', 'p/%s.jsonl' % UUID1,
                   rec(0, cwd='/work/SECRETPROJ'))
        code, r = self.sync('pr')
        (p,) = self.chunks()
        side = self.sidecar(p)
        self.assertTrue(side.get('metadata_dropped'))
        self.assertIsNone(side['project'])


class RealRedactionTests(L.Base):
    identity = False

    def test_no_secret_value_reaches_receipt_state_or_archive(self):
        """NEG-3 with the real gate: a fake credential never appears in receipt, state, output or archive."""
        fake = 'Zq9X' + 'w2Lm8Rt4' + 'Vb7Np3Kc6'
        body = json.dumps({'type': 'user', 'timestamp': '2026-11-01T00:00:00Z', 'sessionId': UUID1,
                           'message': {'content': 'export GITHUB_TOKEN=ghp_' + fake + 'AAAAAAAAAAAAAAA'},
                           'env': {'password': fake}}, separators=(',', ':')) + '\n'
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, body.encode() + lines(3, start=1))
        code, out, err = self.cli('sync', '--checkpoint', 'pr')
        self.assertEqual(code, 0, err[-500:])
        blobs = b''
        for p in self.chunks():
            blobs += self.chunk_bytes(p)
            blobs += json.dumps(self.sidecar(p)).encode()
        for text in (out, err, (self.home / 'receipts' / 'last.json').read_text(),
                     (self.home / 'state.json').read_text(), blobs.decode('utf-8', 'replace')):
            self.assertFalse(fake in text)
        side = self.sidecar(next(iter(self.chunks())))
        self.assertEqual(side['session'], UUID1)  # index mapping comes from the path and survives redaction


class RealGateMappingTests(L.Base):
    identity = False

    def test_mapping_fields_survive_real_gate(self):
        r0 = json.dumps({'type': 'assistant', 'timestamp': '2026-11-02T03:04:05Z', 'cwd': '/work/proj',
                         'message': {'model': 'claude-opus-5-5', 'content': 'shipping GoodQA #16650 via '
                                     'https://github.com/o/r/pull/77 at ' + 'ab' * 20}},
                        separators=(',', ':')) + '\n'
        self.write('claude-projects', 'proj/%s.jsonl' % UUID1, r0.encode())
        code, r = self.sync('pr')
        self.assertEqual(code, 0, r)
        (p,) = self.chunks()
        side = self.sidecar(p)
        self.assertNotIn('metadata_dropped', side)
        self.assertEqual(side['project'], '/work/proj')
        self.assertEqual(side['models'], ['claude-opus-5-5'])
        self.assertEqual(side['mentions']['tickets'], ['16650'])
        self.assertEqual(side['mentions']['prs'], ['https://github.com/o/r/pull/77'])
        self.assertEqual(side['mentions']['commits'], ['ab' * 20])
        code, out = self.main('find', '--ticket', '16650')
        self.assertEqual(json.loads(out)['session'], UUID1)


class RealGateNewlineTests(L.Base):
    identity = False

    def test_chunker_strips_newline_before_the_gate(self):
        """redact_line gets each record WITHOUT its trailing newline: real JSONL never yields embedded-newline."""
        body = b''.join((json.dumps({'type': 'user', 'timestamp': '2026-11-01T00:00:%02dZ' % i, 'sessionId': UUID1,
                                     'message': {'content': 'line one\nline two %d' % i}},
                                    separators=(',', ':')) + '\n').encode() for i in range(20))
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, body)
        code, r = self.sync('pr')
        self.assertEqual(code, 0, r)
        self.assertEqual(r['omitted']['total'], 0)
        self.assertNotIn(b'embedded-newline', b''.join(self.chunk_bytes(p) for p in self.chunks()))
        self.assertIn(UUID1.encode(), self.chunk_bytes(next(iter(self.chunks()))))  # NEG-18 with 70060134


class PublisherTests(L.Base):

    def test_publisher_refuses_non_private(self):
        """AC-1 / NEG-8: public, unknown, fork or extra collaborators -> no push, visible failure."""
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        for stub in ({'*': {'visibility': 'PUBLIC'}}, {'*': {'error': 'api down'}}, {'*': {'fork': True}},
                     {'*': {'collaborators': ['ericmacdougall', 'someone']}},
                     {T.CATALOG: {'visibility': 'INTERNAL'}}):
            (self.remote / 'repo-checks.json').write_text(json.dumps(stub))
            code, r = self.sync('pr')
            self.assertEqual(code, 2)
            self.assertEqual(r['status'], 'refused')
            self.assertFalse(any(self.tip(x) for x in self.repos()), stub)
            self.assertEqual(self.main('check')[0], 3)
        os.unlink(self.remote / 'repo-checks.json')
        code, r = self.sync('pr')
        self.assertEqual(code, 0, r)
        self.assertEqual(r['chunks_pushed'], 1)

    def test_collision_refusal(self):
        """NEG-17: an existing shard path with different bytes is never overwritten."""
        data = lines(3)
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, data)
        cfg = T.Cfg()
        T.ensure_home(cfg)
        month = time.strftime('%Y-%m', time.gmtime())
        repo = 'agent-transcripts-testhost-%s-p1' % month
        path, _ = T.chunk_path(cfg, 'claude-projects', 'p/%s.jsonl' % UUID1, 1, 1,
                               '2026-11-01T00-00-00Z', '2026-11-01T00-00-02Z')
        T.Remote(cfg).ensure(repo)
        T.publish_tree(cfg, repo, {path: b'someone else\n'}, 'pre-existing')
        before = self.tree(repo)[path]
        code, r = self.sync('pr')
        self.assertEqual(code, 2)
        self.assertEqual(r['collisions'], 1)
        self.assertEqual(self.tree(repo)[path], before)
        self.assertNotIn(path + '.meta.json', self.tree(repo))  # chunk and sidecar are one unit
        self.assertEqual(r['held'][0]['reason'], 'collision')
        self.assertIn('collision', (self.home / 'alerts.jsonl').read_text())

    def test_shard_roll_at_cap(self):
        self.setenv(TRANSCRIPTS_SHARD_CAP_BYTES=300)
        for u in (UUID1, UUID2, UUID3):
            self.write('claude-projects', 'p/%s.jsonl' % u, lines(4, text='payload ' + u))
        code, r = self.sync('pr')
        self.assertEqual(code, 0, r)
        shards = self.shard_repos()
        self.assertGreaterEqual(len(shards), 2)
        self.assertTrue(all(re.fullmatch(r'agent-transcripts-testhost-\d{4}-\d{2}-p\d+', s) for s in shards))
        ledger = json.loads(self.blob(T.CATALOG, self.tree(T.CATALOG)['shards/testhost.json']))
        self.assertEqual(sorted(s['repo'] for s in ledger['shards']), shards)
        for s in ledger['shards']:
            got = sum(len(self.blob(s['repo'], oid)) for p, oid in self.tree(s['repo']).items() if p.endswith('.zst'))
            self.assertEqual(s['bytes'], got)

    def test_crash_injection_each_publisher_step(self):
        """NEG-6 / NEG-19: a hard crash at each step reconciles with no duplicate and no lost chunk."""
        import transcript_redact as real

        def expect(path):
            return b''.join(real.redact_line(ln, n)[0] + b'\n'
                            for n, ln in enumerate(path.read_bytes().splitlines(), 1))
        points = ['after_stage', 'before_push', 'after_push', 'push_timeout_landed', 'after_state_pushed',
                  'after_catalog_push']
        for point in points:
            with self.subTest(point=point):
                shutil.rmtree(self.home, ignore_errors=True)
                shutil.rmtree(self.remote)
                self.remote.mkdir()
                for d in self.roots.values():
                    shutil.rmtree(d)
                    d.mkdir()
                a = self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(6))
                b = self.write('codex-wals', 'w.jsonl', lines(4, start=50))
                snap = self.snapshot()
                code, out, err = self.cli('sync', '--checkpoint', 'pr', env={'TRANSCRIPTS_CRASH_AT': point})
                if point == 'push_timeout_landed':
                    self.assertEqual(code, 0, err[-400:])
                else:
                    self.assertEqual(code, 97, err[-400:])
                self.assertEqual(self.snapshot(), snap)  # copy-only holds through a hard crash
                code, out, err = self.cli('sync', '--checkpoint', 'pr')
                self.assertEqual(code, 0, err[-400:] + out)
                self.assertEqual(self.snapshot(), snap)  # and through the replay
                self.assert_one_path_per_source_range({a: 'claude-projects', b: 'codex-wals'})
                ch = self.chunks()
                self.assertEqual(len(ch), 2, sorted(ch))
                self.assertEqual(sorted(os.path.basename(p).split('.')[0] for p in ch), sorted([UUID1, 'w']))
                got = {p: self.chunk_bytes(p) for p in ch}
                self.assertIn(expect(a), got.values())
                self.assertIn(expect(b), got.values())
                idx = self.blob(T.CATALOG, self.tree(T.CATALOG)['index/testhost.jsonl']).splitlines()
                self.assertEqual(sorted(json.loads(x)['path'] for x in idx), sorted(ch))
                leftovers = [f for _, _, fs in os.walk(self.home / 'outbox') for f in fs]
                self.assertEqual(leftovers, [])
                tips = {r: self.tip(r) for r in self.repos()}
                code, out, err = self.cli('sync', '--checkpoint', 'pr')
                self.assertEqual({r: self.tip(r) for r in self.repos()}, tips)

    def assert_one_path_per_source_range(self, sources):
        """Every chunk blob in every shard (not one per path): per source, the sidecars' src_range values tile
        [0, size) exactly once, so a replay never published one byte range under two paths."""
        ranges = {}
        for repo in self.shard_repos():
            tree = self.tree(repo)
            for path in tree:
                if path.endswith('.zst'):
                    meta = json.loads(self.blob(repo, tree[path + '.meta.json']))
                    ranges.setdefault((meta['source'], meta['relpath'], meta['gen']), []).append(
                        (tuple(meta['src_range']), path))
        for src_path, label in sources.items():
            got = [k for k in ranges if k[0] == label]
            self.assertEqual(len(got), 1, (label, sorted(ranges)))
            spans = sorted(ranges[got[0]])
            self.assertEqual(len({p for _, p in spans}), len(spans))
            pos = 0
            for (start, end), _ in spans:
                self.assertEqual(start, pos, spans)
                pos = end
            self.assertEqual(pos, src_path.stat().st_size, spans)

    def test_catalog_race_retries_without_force(self):
        """NEG-11: the catalog tip moves under us (another host); the push refetches and keeps both."""
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        cfg = T.Cfg()
        T.ensure_home(cfg)
        T.Remote(cfg).ensure(T.CATALOG)
        orig = T.TmpRepo.fetch_tip
        state = {'n': 0}

        def racing(self_):
            tip = orig(self_)
            if self_.repo == T.CATALOG:
                state['n'] += 1
                # catalog fetches per run: incident/attestation snapshot, lost-state guard, publisher.
                # Land another host's commit right after the publisher read its tip.
                if state['n'] == 3:
                    T.publish_tree(cfg, T.CATALOG, {'index/otherhost.jsonl': b'{}\n'}, 'other host')
            return tip
        T.TmpRepo.fetch_tip = racing
        try:
            code, r = self.sync('pr')
        finally:
            T.TmpRepo.fetch_tip = orig
        self.assertEqual(code, 0, r)
        tree = self.tree(T.CATALOG)
        self.assertIn('index/otherhost.jsonl', tree)
        self.assertIn('index/testhost.jsonl', tree)


class GhlessHostTests(L.Base):
    """A host with no gh login pushes over SSH: unauthenticated visibility read plus a gh host's attestation."""

    def host_b(self):
        b_src = Path(self.tmp) / 'srcb'
        (b_src / 'p').mkdir(parents=True, exist_ok=True)
        f = b_src / 'p' / ('%s.jsonl' % UUID2)
        with open(f, 'ab') as fh:
            fh.write(lines(3, start=40 + (f.stat().st_size if f.exists() else 0) % 1000))
        return {'TRANSCRIPTS_HOME': str(Path(self.tmp) / 'stateb'), 'TRANSCRIPTS_HOST': 'hostb',
                'TRANSCRIPTS_TEST_NO_GH': '1', 'TRANSCRIPTS_SOURCES': json.dumps({'claude-projects': str(b_src)})}

    def receipt_b(self):
        return T.read_json(str(Path(self.tmp) / 'stateb' / 'receipts' / 'last.json'))

    def setUp(self):
        super().setUp()
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        code, r = self.sync('pr')  # the gh host creates the catalog and attests its repos
        self.assertEqual(code, 0, r)
        self.month = time.strftime('%Y-%m', time.gmtime())
        self.shard_b = 'agent-transcripts-hostb-%s-p1' % self.month

    def test_missing_shard_refuses_then_ensure_repos(self):
        code, out, err = self.cli('sync', '--checkpoint', 'pr', env=self.host_b())
        self.assertEqual(code, 2)
        self.assertIn('shard-repo-missing', self.receipt_b()['error'])
        self.assertNotIn(self.shard_b, self.repos())
        code, out = self.main('ensure-repos', '--host', 'hostb', '--months', self.month)
        self.assertEqual(code, 0, self.last_err)
        att = json.loads(self.blob(T.CATALOG, self.tree(T.CATALOG)['repo-checks/%s.json' % self.shard_b]))
        self.assertEqual((att['private'], att['fork'], att['owner'], att['collaborators_count']),
                         (True, False, T.OWNER, 0))
        code, out, err = self.cli('sync', '--checkpoint', 'pr', env=self.host_b())
        self.assertEqual(code, 0, err[-300:] + out)
        self.assertTrue(any(p.startswith('hostb/') for p in self.chunks()))

    def test_unauthenticated_200_refuses(self):
        self.main('ensure-repos', '--host', 'hostb', '--months', self.month)
        (self.remote / 'repo-checks.json').write_text(json.dumps({self.shard_b: {'unauth_status': 200}}))
        code, out, err = self.cli('sync', '--checkpoint', 'pr', env=self.host_b())
        self.assertEqual(code, 2)
        r = self.receipt_b()
        self.assertEqual(r['status'], 'refused')
        self.assertIn('visibility=PUBLIC', r['error'])
        self.assertFalse(self.tip(self.shard_b))
        (self.remote / 'repo-checks.json').write_text(json.dumps({self.shard_b: {'unauth_status': 500}}))
        code, out, err = self.cli('sync', '--checkpoint', 'pr', env=self.host_b())
        self.assertIn('visibility unknown', self.receipt_b()['error'])

    def test_stale_attestation_refuses_fresh_passes(self):
        self.main('ensure-repos', '--host', 'hostb', '--months', self.month)
        code, out, err = self.cli('sync', '--checkpoint', 'pr', env=self.host_b())
        self.assertEqual(code, 0, err[-300:] + out)
        path = 'repo-checks/%s.json' % self.shard_b
        att = json.loads(self.blob(T.CATALOG, self.tree(T.CATALOG)[path]))
        att['checked_at'] = '2020-01-01T00:00:00Z'
        T.publish_tree(T.Cfg(), T.CATALOG, {path: T.jdump(att) + b'\n'}, 'age attestation', overwrite=True)
        tip = self.tip(self.shard_b)
        code, out, err = self.cli('sync', '--checkpoint', 'pr', env=self.host_b())
        self.assertEqual(code, 2)
        self.assertIn('repo-attestation-stale', self.receipt_b()['error'])
        self.assertEqual(self.tip(self.shard_b), tip)
        att['checked_at'] = T.now_iso()
        att['collaborators_count'] = 1
        T.publish_tree(T.Cfg(), T.CATALOG, {path: T.jdump(att) + b'\n'}, 'bad attestation', overwrite=True)
        code, out, err = self.cli('sync', '--checkpoint', 'pr', env=self.host_b())
        self.assertIn('repo-attestation-stale', self.receipt_b()['error'])

    def test_url_style(self):
        env = dict(os.environ)
        try:
            for k in ('TRANSCRIPTS_REMOTE_BASE', 'TRANSCRIPTS_ALLOW_LOCAL_REMOTE'):
                os.environ.pop(k, None)
            os.environ['TRANSCRIPTS_GIT_URL_STYLE'] = 'ssh'
            self.assertEqual(T.Cfg().url('r'), 'git@github.com:ericmacdougall/r.git')
            os.environ['TRANSCRIPTS_GIT_URL_STYLE'] = 'https'
            self.assertEqual(T.Cfg().url('r'), 'https://github.com/ericmacdougall/r.git')
            os.environ['TRANSCRIPTS_GIT_URL_STYLE'] = 'auto'  # the gh stub on PATH fails `gh auth status`
            self.assertEqual(T.Cfg().url('r'), 'git@github.com:ericmacdougall/r.git')
            os.environ['TRANSCRIPTS_GIT_URL_STYLE'] = 'ftp'
            with self.assertRaises(T.Refused):
                T.Cfg()
        finally:
            os.environ.clear()
            os.environ.update(env)


class ReadSideTests(L.Base):

    def _two_sessions(self):
        self.write('claude-projects', 'proj/%s.jsonl' % UUID1,
                   lines(3) + rec(3, text='working on GoodQA #16650 see https://github.com/o/r/pull/12'))
        self.write('claude-projects', 'proj/%s/subagents/agent-a1.jsonl' % UUID1, lines(2, text='sub'))
        self.write('claude-projects', 'proj/%s.jsonl' % UUID2, lines(4, text='goodqa#999 only'))
        code, r = self.sync('pr')
        self.assertEqual(code, 0, r)

    def test_find_by_ticket_and_session(self):
        self._two_sessions()
        code, out = self.main('find', '--ticket', '16650')
        self.assertEqual(code, 0)
        rows = [json.loads(x) for x in out.splitlines()]
        self.assertEqual([r['session'] for r in rows], [UUID1])
        code, out = self.main('find', '--session', UUID1)
        sess = sorted((json.loads(x)['session'], json.loads(x)['parent']) for x in out.splitlines())
        self.assertEqual(sess, sorted([(UUID1, None), ('agent-a1', UUID1)]))
        code, out = self.main('find', '--ticket', '1234567')
        self.assertEqual(code, 1)
        code, out = self.main('find', '--project', '/work/proj', '--host', 'testhost')
        self.assertEqual(len(out.splitlines()), 3)

    def test_reindex_from_sidecars_matches(self):
        self._two_sessions()
        p = self.roots['claude-projects'] / 'proj' / ('%s.jsonl' % UUID2)
        with open(p, 'ab') as f:
            f.write(lines(2, start=10))
        self.sync('pr')

        def dump():
            import sqlite3
            db = sqlite3.connect(str(self.home / 'index.sqlite'))
            rows = sorted(r[0] for r in db.execute('SELECT row FROM chunks'))
            db.close()
            return rows
        self.assertEqual(self.main('reindex')[0], 0)
        from_catalog = dump()
        os.unlink(self.home / 'index.sqlite')
        self.assertEqual(self.main('reindex', '--from-sidecars')[0], 0)
        from_sidecars = dump()
        self.assertEqual(len(from_catalog), 4)
        self.assertEqual(from_sidecars, from_catalog)

    def test_cat_streams_across_chunks(self):
        self.setenv(TRANSCRIPTS_CHUNK_MAX_BYTES=1024)
        data = lines(40)
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, data)
        self.sync('pr')
        self.assertGreater(len(self.chunks()), 3)
        code, out = self.main('cat', UUID1)
        self.assertEqual(code, 0, self.last_err)
        self.assertEqual(out.encode(), data)
        code, out = self.main('cat', UUID1, '--local')
        self.assertEqual(out.encode(), data)

    def test_corrupted_chunk_fails_recover_with_no_output(self):
        """NEG-12: a tampered chunk makes recover and verify fail naming it; nothing is written."""
        self.setenv(TRANSCRIPTS_CHUNK_MAX_BYTES=1024)
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(30))
        self.sync('pr')
        victim = sorted(self.chunks())[1]
        repo, _ = self.chunks()[victim]
        # an ordinary (non-force) commit that swaps the chunk bytes, as a hostile writer could
        tampered = T.compress(b'{"tampered":true}\n')
        tr = T.TmpRepo(T.Cfg(), repo)
        try:
            tip = tr.fetch_tip()
            oid = T.git(T.Cfg(), ['hash-object', '-w', '--stdin'], cwd=tr.dir, inp=tampered).stdout.decode().strip()
            env = {'GIT_INDEX_FILE': tr.index}
            T.git(T.Cfg(), ['read-tree', tip], cwd=tr.dir, env_extra=env)
            T.git(T.Cfg(), ['update-index', '--cacheinfo', '100644,%s,%s' % (oid, victim)], cwd=tr.dir, env_extra=env)
            tree = T.git(T.Cfg(), ['write-tree', '--missing-ok'], cwd=tr.dir, env_extra=env).stdout.decode().strip()
            c = T.git(T.Cfg(), ['commit-tree', tree, '-p', tip, '-m', 'tamper'], cwd=tr.dir).stdout.decode().strip()
            T.git(T.Cfg(), ['push', '-q', 'origin', '%s:refs/heads/main' % c], cwd=tr.dir)
        finally:
            tr.close()
        dest = Path(self.tmp) / 'never'
        code, out = self.main('recover', UUID1, '--to', str(dest))
        self.assertEqual(code, 1)
        self.assertFalse(dest.exists())
        self.assertIn(os.path.basename(victim), self.last_err)
        self.assertIn('zsha256 mismatch', self.last_err)
        code, out = self.main('verify')
        self.assertEqual(code, 1)
        self.assertIn(os.path.basename(victim), out)

    def test_verify_rehash_fills_whole_sha(self):
        p = self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(5))
        self.sync('pr')
        with open(p, 'ab') as f:
            f.write(lines(3, start=5))
        self.sync('pr')
        man = self.state()['files']['claude-projects/p/%s.jsonl' % UUID1]['gens'][0]
        self.assertTrue(man['whole_sha256_pending'])
        self.assertEqual(self.main('verify', '--rehash')[0], 0)
        self.sync('pr')
        g = self.state()['files']['claude-projects/p/%s.jsonl' % UUID1]['gens'][0]
        self.assertEqual(g['whole_sha256'], hashlib.sha256(p.read_bytes()).hexdigest())

    def test_verify_against_source_starts_new_generation(self):
        p = self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(5))
        self.sync('pr')
        st = os.stat(p)
        data = bytearray(p.read_bytes())
        data[20:23] = b'XYZ'
        p.write_bytes(bytes(data))
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))  # same size and mtime: only a full hash sees it
        code, out = self.main('verify', '--against-source')
        self.assertEqual(json.loads(out)['new_generations_scheduled'], 1)
        self.sync('pr')
        self.assertEqual(len([c for c in self.chunks() if '.g2.' in c]), 1)


class OperationsTests(L.Base):

    def test_budget_respected(self):
        """AC-11: a checkpoint run stays within budget + 15 s and resumes next run."""
        L.IdentityRedact.sleep = 0.004
        for u in (UUID1, UUID2, UUID3):
            self.write('claude-projects', 'p/%s.jsonl' % u, lines(600))
        t0 = time.monotonic()
        code, r = self.sync('pr', '--budget-seconds', '2')
        self.assertLess(time.monotonic() - t0, 2 + 15)
        self.assertGreater(r['backlog']['files'], 0)
        pushed1 = r['chunks_pushed']
        L.IdentityRedact.sleep = 0.0
        code, r = self.sync('pr')
        self.assertEqual(r['backlog']['files'], 0)
        self.assertGreater(r['chunks_pushed'], 0)
        self.assertGreaterEqual(pushed1 + r['chunks_pushed'], 3)

    def test_disk_floor_refuses(self):
        self.setenv(TRANSCRIPTS_MIN_FREE_GB=10 ** 9)
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        code, r = self.sync('pr')
        self.assertEqual(r['status'], 'disk-low')
        self.assertIn('disk-low free=', r['error'])
        self.assertEqual(self.chunks(), {})
        code, out = self.main('check')
        self.assertEqual(code, 3)  # never ok outranks failed
        self.setenv(TRANSCRIPTS_MIN_FREE_GB=0)
        self.sync('pr')
        self.setenv(TRANSCRIPTS_MIN_FREE_GB=10 ** 9)
        self.sync('pr')
        code, out = self.main('check')
        self.assertEqual(code, 2)
        self.assertIn('disk-low', out)

    def test_incident_kill_switch_blocks_push(self):
        """AC-15: the host-wide kill switch stops every push (shards and catalog)."""
        p = self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        self.sync('pr')
        self.assertEqual(self.main('incident', '--kind', 'fakekind', '--shard', self.shard_repos()[0])[0], 0)
        self.assertIn('incident/fakekind.json', self.tree(T.CATALOG))
        tips = {r: self.tip(r) for r in self.repos()}
        with open(p, 'ab') as f:
            f.write(lines(3, start=3))
        code, r = self.sync('pr')
        self.assertEqual(r['status'], 'killswitch')
        self.assertEqual({x: self.tip(x) for x in self.repos()}, tips)
        code, out = self.main('check')
        self.assertEqual(code, 2)
        self.assertIn('killswitch', out)

    def test_incident_rescan_finds_kind_in_other_shard(self):
        self.setenv(TRANSCRIPTS_SHARD_CAP_BYTES=200)
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3, text='harmless'))
        self.sync('pr')
        self.write('claude-projects', 'p/%s.jsonl' % UUID2, lines(3, text='CANARYKIND leaked'))
        self.sync('pr')
        shards = self.shard_repos()
        self.assertEqual(len(shards), 2)
        leak_repo = [c[0] for p, c in self.chunks().items() if UUID2 in p][0]
        other = [s for s in shards if s != leak_repo][0]
        self.main('incident', '--kind', 'canary', '--shard', other)
        L.IdentityRedact.flag_marker = b'CANARYKIND'  # the patched ruleset now recognises the kind
        code, out = self.main('verify', '--rescan', '--kind', 'canary')
        self.assertEqual(code, 1)
        res = json.loads(out)
        self.assertTrue(res['findings'])
        self.assertEqual({f['repo'] for f in res['findings']}, {leak_repo})
        self.assertTrue((self.home / 'killswitch.json').exists())
        L.IdentityRedact.flag_marker = None
        code, out = self.main('verify', '--rescan', '--kind', 'canary')
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)['killswitch_cleared'])
        self.assertTrue(json.loads(out)['catalog_incident_cleared'])
        self.assertFalse((self.home / 'killswitch.json').exists())
        inc = json.loads(self.blob(T.CATALOG, self.tree(T.CATALOG)['incident/canary.json']))
        self.assertTrue(inc['cleared'])

    def test_catalog_incident_from_host_a_stops_host_b(self):
        """AC-15: incident/KIND.json in the catalog stops every host's publisher until a clean rescan clears it."""
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        self.sync('pr')
        self.assertEqual(self.main('incident', '--kind', 'leak')[0], 0)
        # host B: its own state dir, sources and host label, same remotes
        b_src = Path(self.tmp) / 'srcb'
        (b_src / 'p').mkdir(parents=True)
        (b_src / 'p' / ('%s.jsonl' % UUID2)).write_bytes(lines(3, start=40))
        b_env = {'TRANSCRIPTS_HOME': str(Path(self.tmp) / 'stateb'), 'TRANSCRIPTS_HOST': 'hostb',
                 'TRANSCRIPTS_SOURCES': json.dumps({'claude-projects': str(b_src)})}
        code, out, err = self.cli('sync', '--checkpoint', 'pr', env=b_env)
        self.assertEqual(code, 2, err[-300:])
        rb = T.read_json(str(Path(self.tmp) / 'stateb' / 'receipts' / 'last.json'))
        self.assertEqual(rb['status'], 'killswitch')
        self.assertIn('leak', rb['error'])
        self.assertFalse(any(p.startswith('hostb/') for p in self.chunks()))
        code, out = self.main('verify', '--rescan', '--kind', 'leak')
        self.assertEqual(code, 0)
        code, out, err = self.cli('sync', '--checkpoint', 'pr', env=b_env)
        self.assertEqual(code, 0, err[-300:] + out)
        self.assertTrue(any(p.startswith('hostb/') for p in self.chunks()))

    def test_unconfigured_is_never_ok(self):
        code, r = self.sync('pr')  # roots exist but hold no transcripts
        self.assertEqual(r['status'], 'unconfigured')
        self.assertFalse(r['ok'])
        code, out = self.main('check', '--json')
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)['status'], 'unconfigured')
        self.setenv(TRANSCRIPTS_SOURCES=json.dumps({'claude-projects': str(Path(self.tmp) / 'absent')}))
        code, r = self.sync('pr')
        self.assertEqual(r['status'], 'unconfigured')
        self.assertFalse((self.home / 'receipts' / 'last-ok.json').exists())

    def test_dry_run_writes_nothing(self):
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        code, out = self.main('sync', '--checkpoint', 'pr', '--dry-run')
        self.assertEqual(code, 0)
        self.assertIn('would_archive', out)
        self.assertFalse((self.home / 'state.json').exists())
        self.assertEqual(self.repos(), [])

    def test_unreachable_remote_fails_within_budget(self):
        """NEG-10: git network steps hang; the run fails inside budget + 15 s and leaves a receipt."""
        real_git = shutil.which('git', path=L.GIT_DIR)
        stub = self.stub / 'git'
        stub.write_text('#!/bin/sh\nfor a in "$@"; do case "$a" in ls-remote|fetch|push) exec sleep 600;; esac; done\n'
                        'exec %s "$@"\n' % real_git)
        stub.chmod(0o755)
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        t0 = time.monotonic()
        code, out, err = self.cli('sync', '--checkpoint', 'pr', '--budget-seconds', '4', timeout=60)
        self.assertLess(time.monotonic() - t0, 4 + 15)
        self.assertEqual(code, 2)
        r = self.receipt()
        self.assertEqual(r['status'], 'failed')
        self.assertEqual(self.main('check')[0], 3)

    def test_failing_file_is_held_not_the_run(self):
        orig = T.gate_metadata

        def gate(side):
            if side['session'] == UUID1:
                raise T.Refused('metadata')
            return orig(side)
        T.gate_metadata = gate
        self.addCleanup(setattr, T, 'gate_metadata', orig)
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        self.write('claude-projects', 'p/%s.jsonl' % UUID2, lines(3))
        code, r = self.sync('pr')
        self.assertFalse(r['ok'], r)  # gate F1: any held file makes the run not ok; the other file still archives
        self.assertEqual(r['status'], 'held')
        self.assertEqual([h['reason'] for h in r['held']], ['refused:metadata'])
        self.assertEqual([UUID2 in p for p in self.chunks()], [True])
        code, out = self.main('check', '--json')  # no ok receipt yet (the only run held a file): never-ok (3)
        self.assertEqual(code, 3)
        self.assertIn('held=1 (refused:metadata=1)', json.loads(out)['reasons'])
        self.assertNotIn(UUID1, (self.home / 'alerts.jsonl').read_text())

    def test_catalog_readme_missing_refuses(self):
        orig = T.README_SRC
        T.README_SRC = str(Path(self.tmp) / 'nope.md')
        self.addCleanup(setattr, T, 'README_SRC', orig)
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        code, r = self.sync('pr')
        self.assertEqual(r['status'], 'failed')
        self.assertIn('README', r['error'])

    def test_lost_state_never_shrinks_catalog_index(self):
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        gone = self.write('claude-projects', 'p/%s.jsonl' % UUID2, lines(3, start=10))
        self.sync('pr')
        index = self.tree(T.CATALOG)['index/testhost.jsonl']
        for name in ('state.json', 'meta', 'index.sqlite'):
            pth = self.home / name
            shutil.rmtree(pth) if pth.is_dir() else pth.unlink()
        gone.unlink()
        code, r = self.sync('pr')
        self.assertEqual(r['status'], 'failed')
        self.assertIn('looks lost', r['error'])
        self.assertEqual(self.tree(T.CATALOG)['index/testhost.jsonl'], index)

    def test_host_label_is_pinned(self):
        os.environ.pop('TRANSCRIPTS_HOST')
        self.env.pop('TRANSCRIPTS_HOST')
        cfg = T.Cfg()
        T.ensure_home(cfg)
        self.assertEqual((self.home / 'host').read_text().strip(), cfg.host)
        (self.home / 'host').write_text('pinned-mac\n')
        self.assertEqual(T.Cfg().host, 'pinned-mac')

    def test_backfill_defers_on_load(self):
        self.setenv(TRANSCRIPTS_IGNORE_LOAD=0)
        orig = os.getloadavg
        os.getloadavg = lambda: (10.0 ** 6, 0, 0)
        try:
            code, out = self.main('backfill', '--budget-seconds', '5')
        finally:
            os.getloadavg = orig
        self.assertEqual(code, 0)
        r = self.receipt()
        self.assertEqual(r['status'], 'deferred')
        self.assertFalse((self.home / 'receipts' / 'last-ok.json').exists())
        self.assertEqual(self.main('check')[0], 3)


class HoldOwnerTests(L.Base):
    """Gate F1 (PR #316 run 123d8933): one owner of hold state; every hold retries; a hold is never reported ok."""
    K1 = 'claude-projects/p/%s.jsonl' % UUID1
    K2 = 'claude-projects/p/%s.jsonl' % UUID2

    def test_run_cap_holds_only_the_top_contributor(self):
        """A small all-omitted file trips the run cap; its benign neighbour with one omission still archives."""
        L.IdentityRedact.omit_marker = b'OMITME'
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, b''.join(rec(i, text='OMITME %d' % i) for i in range(99)))
        self.write('claude-projects', 'p/%s.jsonl' % UUID2,
                   b''.join(rec(i, text='OMITME' if i == 500 else None) for i in range(1000)))
        code, r = self.sync('pr')
        names = list(self.chunks())
        self.assertTrue(any(UUID2 in n for n in names), names)
        self.assertFalse(any(UUID1 in n for n in names), names)
        self.assertEqual([h['path_sha12'] for h in r['held']], [T.sha12(self.K1)])
        side = self.sidecar(next(n for n in names if UUID2 in n))
        self.assertEqual(side['omitted'], [{'line': 501, 'kind': 'fakekind'}])
        self.assertFalse(r['ok'])
        self.assertNotEqual(code, 0)
        self.assertNotEqual(self.main('check')[0], 0)

    def test_any_hold_makes_the_run_not_ok_and_keeps_last_ok_stale(self):
        self.write('claude-projects', 'p/%s.jsonl' % UUID2, lines(3))
        code, r = self.sync('pr')
        self.assertTrue(r['ok'], r)
        ok_before = self.receipt('last-ok.json')
        self.setenv(TRANSCRIPTS_CHUNK_MAX_BYTES=4096)
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(2) + rec(2, text='z' * 5000))
        code, r = self.sync('pr')
        self.assertEqual(r['status'], 'held')
        self.assertFalse(r['ok'])
        self.assertEqual(code, 2)
        self.assertEqual(self.receipt('last-ok.json'), ok_before)  # a held run never refreshes last-ok
        code, out = self.main('check', '--json')
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)['held'], {'count': 1, 'by_reason': {'record-over-max': 1}})
        code, out = self.main('check')
        self.assertIn('held=1', out)

    def test_held_file_is_retried_when_due(self):
        """A hold is not permanent: once its retry is due the file is visited again, even with no source change."""
        self.setenv(TRANSCRIPTS_HOLD_BACKOFF_SECONDS=0)
        L.IdentityRedact.omit_marker = b'OMITME'
        self.write('claude-projects', 'p/%s.jsonl' % UUID1,
                   b''.join(rec(i, text='OMITME' if i < 6 else None) for i in range(100)))
        code, r = self.sync('pr')
        self.assertEqual([h['reason'] for h in r['held']], ['omission-cap'])
        code, r = self.sync('pr')  # due again at once (backoff 0), same ruleset: retried and held again
        self.assertEqual(self.state()['files'][self.K1]['held']['attempts'], 2)
        L.IdentityRedact.omit_marker = None  # whatever caused the omissions is gone; the ruleset is unchanged
        code, r = self.sync('pr')
        self.assertEqual(r['held'], [])
        self.assertTrue(r['ok'], r)
        self.assertTrue(any(UUID1 in n for n in self.chunks()))

    def test_backoff_grows_and_waits(self):
        cfg = T.Cfg()
        delays = [T.hold_delay(cfg, n) for n in range(1, 12)]
        self.assertEqual(delays, sorted(delays))
        self.assertGreater(delays[0], 0)
        self.assertEqual(delays[-1], T.HOLD_BACKOFF_MAX)
        L.IdentityRedact.omit_marker = b'OMITME'
        self.write('claude-projects', 'p/%s.jsonl' % UUID1,
                   b''.join(rec(i, text='OMITME' if i < 6 else None) for i in range(100)))
        self.sync('pr')
        held = self.state()['files'][self.K1]['held']
        self.assertEqual(held['attempts'], 1)
        self.assertGreater(T.parse_iso(held['retry_at']), time.time())
        self.sync('pr')  # not due: the file is not visited, so the attempt count stands
        self.assertEqual(self.state()['files'][self.K1]['held']['attempts'], 1)
        L.IdentityRedact.RULESET_VERSION = 'test-identity-2'  # a rules change makes every hold due at once
        L.IdentityRedact.omit_marker = None
        code, r = self.sync('pr')
        self.assertEqual(r['held'], [])

    def test_collision_stays_held_and_realerts_when_due(self):
        self.setenv(TRANSCRIPTS_HOLD_BACKOFF_SECONDS=0)
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        cfg = T.Cfg()
        T.ensure_home(cfg)
        month = time.strftime('%Y-%m', time.gmtime())
        repo = 'agent-transcripts-testhost-%s-p1' % month
        path, _ = T.chunk_path(cfg, 'claude-projects', 'p/%s.jsonl' % UUID1, 1, 1,
                               '2026-11-01T00-00-00Z', '2026-11-01T00-00-02Z')
        T.Remote(cfg).ensure(repo)
        T.publish_tree(cfg, repo, {path: b'someone else\n'}, 'pre-existing')
        self.sync('pr')
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3, start=3), mode='ab')
        code, r = self.sync('pr')
        self.assertEqual([h['reason'] for h in r['held']], ['collision'])
        self.assertEqual(self.state()['files'][self.K1]['held']['attempts'], 2)
        self.assertFalse(r['ok'])
        self.assertEqual(self.tree(repo)[path], T.git_blob_sha(b'someone else\n'))

    def test_a_run_that_visits_nothing_still_reports_the_hold(self):
        """A receipt from a run that never visits files (a backfill deferred on load) still carries the held files
        from state, so check stays non-ok with the count."""
        orig = T.gate_metadata

        def gate(side):
            if side['session'] == UUID1:
                raise T.Refused('metadata')
            return orig(side)
        T.gate_metadata = gate
        self.addCleanup(setattr, T, 'gate_metadata', orig)
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        self.write('claude-projects', 'p/%s.jsonl' % UUID2, lines(3))
        self.sync('pr')
        self.setenv(TRANSCRIPTS_IGNORE_LOAD='0')
        with mock.patch.object(T.os, 'getloadavg', lambda: (1e6, 1e6, 1e6)):
            code, out = self.main('backfill', '--budget-seconds', '5')
        self.assertEqual(code, 0)
        self.assertEqual(self.receipt()['status'], 'deferred')
        code, out = self.main('check', '--json')
        self.assertNotEqual(code, 0)
        self.assertEqual(json.loads(out)['held'], {'count': 1, 'by_reason': {'refused:metadata': 1}})

    def test_only_the_hold_owner_writes_hold_state(self):
        """Guard: no code path outside the owner may set, clear or pop a file's hold."""
        import ast
        tree = ast.parse(Path(T.__file__).read_text(encoding='utf-8'))
        writers = set()
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef):
                continue
            for node in ast.walk(fn):
                targets = node.targets if isinstance(node, ast.Assign) else (
                    [node.target] if isinstance(node, (ast.AugAssign, ast.AnnAssign)) else [])
                for t in targets:
                    if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) and t.slice.value == 'held':
                        writers.add(fn.name)
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ('pop', 'setdefault', 'update') and node.args
                        and isinstance(node.args[0], ast.Constant) and node.args[0].value == 'held'):
                    writers.add(fn.name)
        self.assertEqual(writers, {'hold', 'release', 'begin_retry'})


class DeltaGateTests(L.Base):
    """Pre-empted delta-gate checks for PR #316: copy-only under a write trap, and visibility per run."""

    def test_base_isolates_environment_between_tests(self):
        """Guard: a setenv in one test never reaches the next (a leaked TRANSCRIPTS_TEST_NO_GH once turned 48 later
        tests into gh-less refusals)."""
        seen = {}

        class Pair(L.Base):
            def test_1_sets(self_):
                self_.setenv(TRANSCRIPTS_TEST_NO_GH='1', TRANSCRIPTS_HOLD_BACKOFF_SECONDS='0')

            def test_2_reads(self_):
                seen['leaked'] = sorted(k for k in ('TRANSCRIPTS_TEST_NO_GH', 'TRANSCRIPTS_HOLD_BACKOFF_SECONDS')
                                        if k in os.environ)
        result = unittest.TestResult()
        unittest.TestSuite([Pair('test_1_sets'), Pair('test_2_reads')]).run(result)
        self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
        self.assertEqual(seen['leaked'], [])
        self.assertNotIn('TRANSCRIPTS_TEST_NO_GH', os.environ)

    def test_no_write_call_ever_targets_a_source(self):
        """AC-7 by construction: every call that could change a source (write-mode open, unlink, rename, replace,
        truncate, chmod, utime, rmdir, mkdir, links) is trapped while sync, verify, cat and recover run; none may
        name a path under a source root. A control write proves the trap fires."""
        import builtins
        self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(20))
        self.write('claude-wals', '%s/main.jsonl' % UUID2, lines(2) + b'{"partial')
        src = os.path.realpath(self.src)
        hits = []

        def under(path):
            try:
                return os.path.realpath(os.fspath(path)).startswith(src + os.sep)
            except TypeError:
                return False  # an fd

        def trap(name, orig, is_write):
            def wrapper(*a, **kw):
                if a and under(a[0]) and is_write(a, kw):
                    hits.append((name, os.path.relpath(os.path.realpath(os.fspath(a[0])), src)))
                if name in ('rename', 'replace') and len(a) > 1 and under(a[1]):
                    hits.append((name + '-target', os.fspath(a[1])))
                return orig(*a, **kw)
            return wrapper
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        traps = {
            (os, 'open'): lambda a, kw: bool((a[1] if len(a) > 1 else kw.get('flags', 0)) & write_flags),
            (builtins, 'open'): lambda a, kw: any(c in str(a[1] if len(a) > 1 else kw.get('mode', 'r'))
                                                  for c in 'wax+'),
        }
        for fn in ('unlink', 'remove', 'rename', 'replace', 'truncate', 'chmod', 'utime', 'rmdir', 'mkdir',
                   'makedirs', 'symlink', 'link'):
            traps[(os, fn)] = lambda a, kw: True
        for (mod, fn), is_write in traps.items():
            orig = getattr(mod, fn)
            setattr(mod, fn, trap(fn, orig, is_write))
            self.addCleanup(setattr, mod, fn, orig)
        snap = self.snapshot()
        code, r = self.sync('pr')
        self.assertEqual(code, 0, r)
        self.main('verify')
        self.main('cat', UUID1)
        self.main('recover', UUID1, '--to', str(Path(self.tmp) / 'rec'), '--from', 'local')
        self.main('verify', '--against-source')
        self.assertEqual(hits, [])
        self.assertEqual(self.snapshot(), snap)
        with open(self.roots['claude-projects'] / ('p/%s.jsonl' % UUID1), 'ab') as f:  # control: the trap fires
            f.write(lines(1, start=20))
        self.assertEqual([h[0] for h in hits], ['open'])
        hits.clear()
        snap = self.snapshot()
        self.sync('pr')
        self.assertEqual(hits, [])
        self.assertEqual(self.snapshot(), snap)

    def test_visibility_is_checked_every_run_in_both_url_styles(self):
        """The privacy check is chosen by gh availability, never by the git URL style, and a new run never reuses an
        earlier run's pass: after a good push, a repo turned public refuses the next push in every combination."""
        f = self.write('claude-projects', 'p/%s.jsonl' % UUID1, lines(3))
        code, r = self.sync('pr')
        self.assertEqual(code, 0, r)
        stubs = {'1': {'*': {'unauth_status': 200}},  # without gh: an unauthenticated read succeeds
                 '0': {'*': {'visibility': 'PUBLIC'}}}  # with gh: the API reports public
        n = 3
        for style in ('https', 'ssh'):
            for no_gh in ('0', '1'):
                with self.subTest(style=style, no_gh=no_gh):
                    with mock.patch.object(T.Cfg, 'url_style', property(lambda self_, s=style: s)):
                        self.setenv(TRANSCRIPTS_TEST_NO_GH=no_gh)
                        with open(f, 'ab') as fh:
                            fh.write(lines(1, start=n))
                        n += 1
                        tips = {x: self.tip(x) for x in self.repos()}
                        (self.remote / 'repo-checks.json').write_text(json.dumps(stubs[no_gh]))
                        code, r = self.sync('pr')
                        os.unlink(self.remote / 'repo-checks.json')
                        self.assertEqual(code, 2, r)
                        self.assertEqual(r['status'], 'refused')
                        self.assertEqual({x: self.tip(x) for x in self.repos()}, tips)


if __name__ == '__main__':
    unittest.main()
