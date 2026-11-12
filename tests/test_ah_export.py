"""`ah export` (GoodQA goodqa#15788, pi-dev-port H1): one session's WALs as a self-contained, redacted, local-only
HTML file. Idea adapted from Pi's /export (pi.dev, MIT); Pi's /share upload is deliberately absent."""

import ast
from html.parser import HTMLParser
import io
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import ah  # noqa: E402
import ah_export  # noqa: E402

NOW = 1_800_000_000.0
SESSION = 'sess-export-0001'
# Alphanumeric fixture secrets, built by concatenation so this file holds no scannable credential literal and
# html.escape cannot change their bytes (acceptance review r1 finding 3).
ANTHROPIC = 'sk-ant-' + 'api03' + 'A1b2C3d4E5f6G7h8I9j0KLMNOPqrstuvWXyz'
GITHUB = 'ghp_' + 'Z9y8X7w6V5u4T3s2R1q0PONMLKJihgfedcba'
GITHUB2 = 'ghp_' + 'Q1w2E3r4T5y6U7i8O9p0AsDfGhJkLzXcVbNm'
PEM_BODY = 'MIIEowIBAAKCAQEA' + 'exportfixturebody0123456789ABCDEFGH'
PEM = '-----BEGIN ' + 'RSA PRIVATE KEY-----\n' + PEM_BODY + '\n-----END ' + 'RSA PRIVATE KEY-----'
PASSWORD = 'hunter2' + 'correcthorsebattery'
EMAIL_LOCAL = 'janeoperator'
BANNER = ("Local and private. Redacted by pattern; this is not a guarantee. Names, hostnames, ticket text and phone "
          "numbers are not removed. Review this file before sharing it with anyone. ah never uploads it.")
ALLOWED_TAGS = {'html', 'head', 'meta', 'title', 'style', 'body', 'header', 'main', 'section', 'h1', 'h2', 'h3', 'p',
                'details', 'summary', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'code', 'span', 'ul', 'li', 'strong'}


def iso(ts):
    return time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(ts))


def jl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'a', encoding='utf-8') as fh:
        for r in rows:
            fh.write((r if isinstance(r, str) else json.dumps(r)) + '\n')


def segments(secret, prefix_len):
    """Every 12-character window of the secret after its well-known prefix: catches truncated leaks."""
    body = secret[prefix_len:]
    return {body[i:i + 12] for i in range(0, max(1, len(body) - 11))}


class Tags(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.attrs, self.first_head_child, self._in_head, self.text = [], [], None, False, []

    def handle_starttag(self, tag, attrs):
        if self._in_head and self.first_head_child is None:
            self.first_head_child = (tag, dict(attrs))
        if tag == 'head':
            self._in_head = True
        self.tags.append(tag)
        self.attrs.extend(name for name, _ in attrs)

    def handle_data(self, data):
        self.text.append(data)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        p = mock.patch.dict(os.environ, {'AH_HOME': str(self.home), 'HOME': str(self.home),
                                         'CLAUDE_CODE_SESSION_ID': '', 'CLAUDE_SESSION_ID': ''})
        p.start()
        self.addCleanup(p.stop)
        self.w = self.home / '.claude' / 'wals' / SESSION
        jl(self.w / 'main.jsonl', [
            {'at': iso(NOW - 9000), 'event': 'subagent', 'agent_id': 'owner1', 'agent_type': 'task-owner'},
            {'at': iso(NOW - 8900), 'event': 'subagent', 'agent_id': 'rt2', 'agent_type': 'red-team'},
            {'at': iso(NOW - 8800), 'event': 'pretool', 'tool': 'Bash', 'target_chars': 12},
            {'at': iso(NOW - 8000), 'event': 'decision', 'id': 'wdec1', 'note': 'ship the export behind no flag',
             'source': 'user:11111111-2222-4333-8444-555555555555/00000000-0000-4000-8000-000000000001 "ok"'},
            {'at': iso(NOW - 7900), 'event': 'decision', 'id': 'wdec2', 'note': 'lead target 1000 -> 50 verified leads',
             'source': 'inferred: from file:x -- judgement'},
            {'at': iso(NOW - 6000), 'event': 'ask', 'id': 'wask1', 'note': 'approve the export PR', 'reason': 'policy',
             'source': 'user:x/y "z"'},
        ])
        jl(self.w / 'agent-owner1.jsonl', [
            {'at': iso(NOW - 8500), 'event': 'intent', 'id': 'wi1', 'note': 'PENDING_REAL_TEST EXP-1: export renders'},
            {'at': iso(NOW - 4000), 'event': 'check', 'id': 'wc1', 'note': 'REALLY_TESTED EXP-1: unittest PASS at abc1234'},
            {'at': iso(NOW - 3500), 'event': 'commit', 'id': 'wcm1', 'note': 'abc1234 feat(ah): export'},
            {'at': iso(NOW - 2000), 'event': 'blocker', 'id': 'wb1', 'note': 'GoodQA returned 403 for the smoke key'},
            {'at': iso(NOW - 1000), 'event': 'handoff', 'id': 'wh1', 'note': 'handoff: export ready for review'},
        ])
        jl(self.w / 'agent-rt2.jsonl', [
            {'at': iso(NOW - 3000), 'event': 'result', 'id': 'wr2', 'note': 'red-team: no material findings'},
        ])

    def export(self, *extra, now=NOW, session=SESSION):
        argv = ['export', '--session', session, *extra]
        args = ah.build_parser().parse_args(argv)
        with mock.patch('time.time', return_value=now):
            return ah.run(args, self.home)

    def html(self, result):
        return Path(result['path']).read_bytes().decode('utf-8')

    def exports_root(self):
        return self.home / '.agent-harness' / 'work' / SESSION / 'exports'


class FullExport(Base):
    def test_full_export_sections(self):
        r = self.export()
        self.assertTrue(r['ok'])
        page = self.html(r)
        for needle in ('owner1', 'task-owner', 'rt2', 'red-team', 'ship the export behind no flag',
                       'PENDING_REAL_TEST EXP-1', 'abc1234 feat(ah): export', 'GoodQA returned 403',
                       'handoff: export ready for review', 'red-team: no material findings', 'approve the export PR'):
            self.assertIn(needle, page, needle)
        for section in ('VERIFIED', 'FAILED', 'PENDING', 'LIVE', 'CLAIMED', 'BLOCKED', 'ASKS open',
                        'ASSUMPTIONS and TARGET_MISMATCH', 'COMMITS'):
            self.assertIn(section, page, section)
        self.assertIn('TARGET_MISMATCH', page)  # wdec2 moved a target without a user source
        self.assertEqual(r['agents'], 3)  # main plus two agent WALs
        self.assertNotIn('target_chars', page)  # hook metadata is counted, not rendered

    def test_classes_match_ah_status(self):
        """Adversarial review r3 finding 2: classes are computed on raw rows, so a cap or mask cannot change them."""
        jl(self.w / 'agent-owner1.jsonl', [
            {'at': iso(NOW - 900), 'event': 'check', 'note': 'REALLY_TESTED LONG-1: ' + 'z' * 2100 + ' FAILED'},
            {'at': iso(NOW - 890), 'event': 'status', 'note': 'DEPLOYED to 10.1.2.3 build abc1234def'},
            {'at': iso(NOW - 880), 'event': 'decision', 'note': 'keep sourced', 'assumption': False,
             'source': 'user:x/y "z"'},
        ])
        since = float('inf')
        with mock.patch('time.time', return_value=NOW):
            direct = ah.status_report(self.home, SESSION, since, now=NOW)
        seen = {}
        real = ah.status_report

        def spy(home, session, since_s, now=None, **kw):
            result = real(home, session, since_s, now=now, **kw)
            seen['report'] = result
            return result
        with mock.patch.object(ah, 'status_report', side_effect=spy):
            self.export()
        exported = seen['report']

        def classes(report):
            return {key: sorted(((e.get('id'), e.get('event'), e.get('label'), e.get('verdict'), e.get('note'))
                                 for e in report.get(key) or []), key=repr)
                    for key in ('verified', 'failed', 'live', 'live_legacy', 'pending', 'claimed', 'blockers',
                                'asks_open', 'assumptions', 'decisions', 'commits')}
        self.assertEqual(classes(exported), classes(direct))
        self.assertTrue(all('row' in e for e in exported['verified'] + exported['failed']))
        # The page, not just the report: LONG-1 sits under FAILED only, the IP deploy row under LIVE.
        page = self.html(self.export())

        def section(title):
            start = page.index('<h3>' + title)
            end = page.find('<h3>', start + 4)
            return page[start:end if end != -1 else len(page)]
        self.assertIn('LONG-1', section('FAILED'))
        self.assertNotIn('LONG-1', section('VERIFIED'))
        self.assertIn('build abc1234def', section('LIVE (deploy'))
        self.assertIn('[ip]', section('LIVE (deploy'))

    def test_section_cap_counts_the_rest(self):
        jl(self.w / 'agent-owner1.jsonl', [
            {'at': iso(NOW - 2500 + i), 'event': 'commit', 'note': 'c%04d feat(x): y' % i}
            for i in range(ah_export.SECTION_CAP + 7)])
        page = self.html(self.export())
        self.assertIn('8 more not shown (section capped at %d' % ah_export.SECTION_CAP, page)


class Redaction(Base):
    def test_secrets_everywhere_redacted(self):
        # Token shapes need a non-word character before their prefix (redact.py \b; goodqa#15790 tracks glued tokens)
        jl(self.w / 'main.jsonl', [{'at': iso(NOW - 600), 'event': 'subagent', 'agent_id': 'id-' + GITHUB2,
                                    'agent_type': 'x'}])
        jl(self.w / ('agent-' + GITHUB + '.jsonl'), [{'at': iso(NOW - 590), 'event': 'status', 'note': 'named wal'}])
        jl(self.w / 'agent-owner1.jsonl', [
            {'at': iso(NOW - 500), 'event': 'decision', 'id': 'wsec', 'note': f'key {ANTHROPIC} and {GITHUB}\n{PEM}',
             'source': f'password={PASSWORD}', 'reason': f'mail {EMAIL_LOCAL}@example.com from 10.20.30.40',
             'ref': GITHUB, 'extra': ANTHROPIC, 'nested': {GITHUB2: 'v'}},
            {'at': iso(NOW - 450), 'event': 'status', 'note': {'deep': ['password=' + PASSWORD, f'token={GITHUB2}'],
                                                               'password': PASSWORD}},
            {'at': iso(NOW - 440), 'event': 'status', 'note': 'path /Users/janeoperator/proj and /home/janeoperator/x'},
        ])
        r = self.export()
        raw = Path(r['path']).read_text(encoding='utf-8')
        for secret, plen in ((ANTHROPIC, 12), (GITHUB, 4), (GITHUB2, 4), (PEM_BODY, 0)):
            for seg in segments(secret, plen):
                self.assertNotIn(seg, raw, secret[:10])
        self.assertNotIn(PASSWORD, raw)
        self.assertNotIn(EMAIL_LOCAL, raw)
        self.assertNotIn('10.20.30.40', raw)
        self.assertIn('[REDACTED:', raw)
        self.assertIn('@example.com', raw)
        self.assertGreater(r['redactions'], 0)

    def test_invisible_split_token_redacted(self):
        """Adversarial delta finding 12: controls are removed before redaction, so a split token is still caught."""
        body = GITHUB[4:]
        notes = ['split ghp_​' + body, 'split ghp_؜' + body, 'split ghp_⁦' + body,
                 'split ghp_\x07' + body]
        jl(self.w / 'agent-owner1.jsonl', [{'at': iso(NOW - 300 + i), 'event': 'status', 'note': n}
                                           for i, n in enumerate(notes)])
        raw = self.html(self.export())
        for seg in segments(GITHUB, 4):
            self.assertNotIn(seg, raw)
        for ch in ('​', '؜', '⁦', '\x07'):
            self.assertNotIn(ch, raw)

    def test_straddling_secrets_redacted(self):
        # straddles status_report's 240-character note cut, leaving 16 body characters (too few for the pattern)
        at240 = 'y' * 219 + ' ' + GITHUB
        at_cap = 'x' * (ah_export.FIELD_CAP - 11) + ' ' + GITHUB2  # straddles the export's own field cap
        jl(self.w / 'agent-owner1.jsonl', [
            {'at': iso(NOW - 400), 'event': 'decision', 'note': at240, 'source': 'user:x/y "z"'},
            {'at': iso(NOW - 390), 'event': 'blocker', 'note': at240},
            {'at': iso(NOW - 380), 'event': 'status', 'note': at_cap},
        ])
        raw = Path(self.export()['path']).read_text(encoding='utf-8')
        for secret in (GITHUB, GITHUB2):
            for seg in segments(secret, 4):
                self.assertNotIn(seg, raw, seg)

    def test_redactor_unavailable_refuses_and_writes_nothing(self):
        with mock.patch.object(ah_export, '_load_redactor', side_effect=ImportError('gone')):
            with self.assertRaises(ah.AhError) as caught:
                self.export()
        self.assertEqual(caught.exception.code, 'redactor_unavailable')
        root = self.exports_root()
        self.assertEqual(list(root.iterdir()) if root.exists() else [], [])


class Injection(Base):
    HOSTILE = ('<script>alert(1)</script><img src=x onerror=alert(2)></details></pre>'
               '<a href="javascript:alert(3)">x</a>" onmouseover="alert(4)'
               '<style>@import "evil.css"; body{background:url(//evil.test/x)}</style>'
               '<link rel=stylesheet href=//evil.test/s.css><meta http-equiv="refresh" content="0;url=file:///etc">')

    def test_markup_injection_escaped(self):
        jl(self.w / 'main.jsonl', [
            {'at': iso(NOW - 300), 'event': 'subagent', 'agent_id': '<b>evil\nid</b>', 'agent_type': '<i>t</i>'},
            {'at': iso(NOW - 200), 'event': 'status', 'id': 'wx', 'note': self.HOSTILE, 'source': self.HOSTILE},
        ])
        page = self.html(self.export())
        parsed = Tags()
        parsed.feed(page)
        self.assertLessEqual(set(parsed.tags), ALLOWED_TAGS, set(parsed.tags) - ALLOWED_TAGS)
        self.assertFalse([a for a in parsed.attrs if a.lower().startswith('on')], parsed.attrs)
        self.assertIn(self.HOSTILE.replace('\n', ' ')[:60], ''.join(parsed.text))  # rendered, as text
        self.assertIn('&lt;script&gt;', page)

    def test_no_network_and_no_external_refs(self):
        jl(self.w / 'main.jsonl', [{'at': iso(NOW - 200), 'event': 'status', 'note': self.HOSTILE}])

        def refuse(*_a, **_k):
            raise AssertionError('export opened a socket')
        with mock.patch.object(socket, 'socket', side_effect=refuse), \
                mock.patch.object(socket, 'create_connection', side_effect=refuse):
            page = self.html(self.export())
        parsed = Tags()
        parsed.feed(page)
        self.assertFalse({'src', 'href', 'srcset', 'action'} & {a.lower() for a in parsed.attrs})
        self.assertEqual(re.findall(r'(?i)http-equiv="([^"]*)"', page), ['Content-Security-Policy'])  # the CSP meta only
        # outside text nodes (escaped user text may mention url( as text): check the markup skeleton only
        skeleton = re.sub(r'>[^<]*<', '><', page)
        self.assertNotRegex(skeleton, r'(?i)url\(|@import|<link|file:|=\s*["\']?//')
        style = re.search(r'(?s)<style>(.*?)</style>', page).group(1)
        self.assertNotRegex(style, r'(?i)url\(|@import')
        self.assertEqual(parsed.first_head_child[0], 'meta')
        csp = parsed.first_head_child[1].get('content', '')
        for directive in ("default-src 'none'", "base-uri 'none'", "form-action 'none'"):
            self.assertIn(directive, csp)


class Output(Base):
    def test_private_modes_and_unique_names(self):
        root = self.exports_root()
        root.mkdir(parents=True, mode=0o755)
        os.chmod(root, 0o755)
        a = self.export()
        b = self.export()
        self.assertNotEqual(a['path'], b['path'])
        for r in (a, b):
            p = Path(r['path'])
            self.assertEqual(p.parent, root)
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
            self.assertTrue(p.name.endswith('.html'))
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        self.assertEqual([f for f in os.listdir(root) if not f.endswith('.html')], [])

    def test_out_inside_a_repository_is_refused(self):
        repo = self.home / 'proj'
        (repo / 'sub').mkdir(parents=True)
        (repo / '.git').mkdir()
        with self.assertRaises(ah.AhError) as caught:
            self.export('--out', str(repo / 'sub' / 'x.html'))
        self.assertEqual(caught.exception.code, 'out_in_repo')
        self.assertFalse((repo / 'sub' / 'x.html').exists())
        (repo / '.git').rmdir()
        (repo / '.git').write_text('gitdir: /elsewhere\n')  # a linked worktree marks itself with a .git file
        with self.assertRaises(ah.AhError) as caught:
            self.export('--out', str(repo / 'sub' / 'y.html'))
        self.assertEqual(caught.exception.code, 'out_in_repo')

    def test_default_path_refused_when_home_is_a_repository(self):
        (self.home / '.git').mkdir()
        with self.assertRaises(ah.AhError) as caught:
            self.export()
        self.assertEqual(caught.exception.code, 'out_in_repo')

    def test_out_existing_or_symlink_is_refused(self):
        d = self.home / 'out'
        d.mkdir()
        existing = d / 'a.html'
        existing.write_text('keep')
        with self.assertRaises(ah.AhError) as caught:
            self.export('--out', str(existing))
        self.assertEqual(caught.exception.code, 'out_exists')
        self.assertEqual(existing.read_text(), 'keep')
        link = d / 'b.html'
        link.symlink_to(d / 'missing.html')
        with self.assertRaises(ah.AhError) as caught:
            self.export('--out', str(link))
        self.assertEqual(caught.exception.code, 'out_symlink')
        self.assertFalse((d / 'missing.html').exists())

    def test_exports_dir_symlink_and_sync_roots_refused(self):
        elsewhere = self.home / 'elsewhere'
        elsewhere.mkdir()
        root = self.exports_root()
        root.parent.mkdir(parents=True)
        root.symlink_to(elsewhere)
        with self.assertRaises(ah.AhError) as caught:
            self.export()
        self.assertEqual(caught.exception.code, 'out_symlink')
        self.assertEqual(list(elsewhere.iterdir()), [])
        for sync in ('Dropbox', 'Dropbox (Personal)', 'Library/CloudStorage/GoogleDrive-x', 'Library/Mobile Documents/x'):
            d = self.home / sync
            d.mkdir(parents=True)
            with self.assertRaises(ah.AhError) as caught:
                self.export('--out', str(d / 'e.html'))
            self.assertEqual(caught.exception.code, 'out_in_sync_root', sync)

    def test_sync_root_reached_through_a_symlink_is_refused(self):
        (self.home / 'Dropbox').mkdir()
        (self.home / 'innocent').symlink_to(self.home / 'Dropbox')
        with self.assertRaises(ah.AhError) as caught:
            self.export('--out', str(self.home / 'innocent' / 'e.html'))
        self.assertEqual(caught.exception.code, 'out_in_sync_root')

    def test_desktop_gets_a_sync_warning(self):
        d = self.home / 'Desktop'
        d.mkdir()
        r = self.export('--out', str(d / 'e.html'))
        self.assertIn('sync_warning', r)

    def test_out_bad_suffix_or_missing_parent(self):
        for bad in (str(self.home / 'x.txt'), str(self.home / 'nope' / 'x.html')):
            with self.assertRaises(ah.AhError) as caught:
                self.export('--out', bad)
            self.assertEqual(caught.exception.code, 'bad_request', bad)

    def test_explicit_out_is_written_0600(self):
        d = self.home / 'out2'
        d.mkdir()
        r = self.export('--out', str(d / 'e.html'))
        self.assertEqual(Path(r['path']), d / 'e.html')
        self.assertEqual(stat.S_IMODE((d / 'e.html').stat().st_mode), 0o600)
        self.assertNotIn('sync_warning', r)

    def test_crash_before_link_leaves_nothing(self):
        with mock.patch.object(ah_export.os, 'link', side_effect=OSError('boom')):
            with self.assertRaises(Exception):
                self.export()
        root = self.exports_root()
        self.assertEqual(list(root.iterdir()) if root.exists() else [], [])

    def test_too_large_refuses_and_leaves_nothing(self):
        with mock.patch.object(ah_export, 'MAX_OUTPUT', 2048):
            with self.assertRaises(ah.AhError) as caught:
                self.export()
        self.assertEqual(caught.exception.code, 'too_large')
        root = self.exports_root()
        self.assertEqual(list(root.iterdir()) if root.exists() else [], [])


class Inputs(Base):
    def test_unknown_session_and_bad_ids(self):
        with self.assertRaises(ah.AhError) as caught:
            self.export(session='no-such-session')
        self.assertEqual(caught.exception.code, 'session_unknown')
        for bad in ('../etc', 'a/b', '.', '..', 'a\nb', 'a\x00b'):
            with self.assertRaises(ah.AhError) as caught:
                self.export(session=bad)
            self.assertEqual(caught.exception.code, 'session_invalid', repr(bad))
        with mock.patch.dict(os.environ, {'CLAUDE_CODE_SESSION_ID': '../x'}):
            args = ah.build_parser().parse_args(['export'])
            with self.assertRaises(ah.AhError) as caught:
                ah.run(args, self.home)
        self.assertEqual(caught.exception.code, 'session_invalid')

    def test_symlinked_session_dir_refused(self):
        alias = self.home / '.claude' / 'wals' / 'sess-alias'
        alias.symlink_to(self.w)
        with self.assertRaises(ah.AhError) as caught:
            self.export(session='sess-alias')
        self.assertEqual(caught.exception.code, 'session_unknown')

    def test_codex_session_root(self):
        cw = self.home / '.agent-harness' / 'codex-wals' / 'sess-codex-01'
        jl(cw / 'main.jsonl', [{'at': iso(NOW - 100), 'event': 'decision', 'note': 'codex side decision',
                                'source': 'user:x/y "z"'}])
        page = self.html(self.export(session='sess-codex-01'))
        self.assertIn('codex side decision', page)

    def test_malformed_rows_are_skipped_and_counted(self):
        with open(self.w / 'agent-owner1.jsonl', 'ab') as fh:
            fh.write(b'not json\n[1,2]\n{"event": "status", "at": "x", "note": 42}\n')
            fh.write(b'{"event": "status", "note": ["a", {"b": 1}]}\n\xff\xfe broken utf8\n')
            fh.write(b'[' * 100_000 + b']' * 100_000 + b'\n')  # RecursionError in json.loads
            fh.write(b'{"event": "status", "note": "lone \\ud800 surrogate"}\n')
            nested = 'x'
            for _ in range(200):
                nested = {'k': nested}
            fh.write(json.dumps({'event': 'status', 'note': nested}).encode() + b'\n')
        r = self.export()
        self.assertTrue(r['ok'])
        self.assertGreaterEqual(r['rows_skipped'], 3)

    def test_bounds_priority_and_unread(self):
        jl(self.w / 'agent-bulk.jsonl', [{'at': iso(NOW - 100 + i / 1000), 'event': 'status', 'note': f'row {i}'}
                                         for i in range(ah_export.MAX_ROWS + 1000)])
        jl(self.w / 'agent-owner1.jsonl', [{'at': iso(NOW - 50), 'event': 'status', 'note': 'L' * 50_000}])
        r = self.export()
        self.assertGreaterEqual(r['rows_omitted'], 1000)
        self.assertLessEqual(r['rows_rendered'], ah_export.MAX_ROWS)
        page = self.html(r)
        self.assertIn('omitted', page)
        self.assertNotIn('L' * (ah_export.FIELD_CAP + 1), page)
        for early in ('PENDING_REAL_TEST EXP-1', 'ship the export behind no flag', 'approve the export PR',
                      'handoff: export ready for review', 'GoodQA returned 403'):
            self.assertIn(early, page, early)  # priority rows survive the cap

    def test_symlinked_wal_not_read_anywhere(self):
        other = self.home / '.claude' / 'wals' / 'other-session'
        jl(other / 'main.jsonl', [{'at': iso(NOW - 100), 'event': 'decision', 'note': 'OTHER SESSION SECRET PLAN',
                                   'source': 'user:x/y "z"'},
                                  {'at': iso(NOW - 90), 'event': 'check', 'note': 'REALLY_TESTED OTHER-1: x PASS'}])
        (self.w / 'agent-link.jsonl').symlink_to(other / 'main.jsonl')
        r = self.export()
        page = self.html(r)
        self.assertNotIn('OTHER SESSION SECRET PLAN', page)
        self.assertNotIn('OTHER-1', page)
        self.assertIn('agent-link.jsonl', page)
        self.assertTrue(any(u['wal'] == 'agent-link.jsonl' for u in r['unread']))

    def test_oversized_wal_listed_unread(self):
        jl(self.w / 'agent-big.jsonl', [{'at': iso(NOW - 10), 'event': 'status', 'note': 'BIG FILE ROW ' + 'b' * 400}])
        with mock.patch.object(ah_export, 'WAL_LIMIT', 256):
            r = self.export()
        self.assertTrue(any(u['wal'] == 'agent-big.jsonl' for u in r['unread']))
        self.assertNotIn('BIG FILE ROW', self.html(r))

    def test_agent_and_since_filters(self):
        page = self.html(self.export('--agent', 'rt2'))
        self.assertIn('red-team: no material findings', page)
        self.assertNotIn('handoff: export ready for review', page)
        self.assertIn('session-wide', page)
        page = self.html(self.export('--since', '1h'))
        self.assertIn('handoff: export ready for review', page)  # 1000 s old
        self.assertNotIn('ship the export behind no flag', page)  # 8000 s old


class Presentation(Base):
    def test_banner_exact_and_visible(self):
        page = self.html(self.export())
        self.assertEqual(page.count(BANNER), 1)
        before = page[:page.index(BANNER)]
        self.assertEqual(before.count('<details'), before.count('</details>'))  # not inside a details element


class Installers(unittest.TestCase):
    @staticmethod
    def listed(installer):
        tree = ast.parse((ROOT / installer).read_text(encoding='utf-8'))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.endswith('.py'):
                names.add(node.value)
        return names

    @staticmethod
    def local_imports(node):
        """Harness modules imported anywhere inside an AST node, module level or inside functions."""
        found = set()
        for n in ast.walk(node):
            if isinstance(n, ast.Import):
                found |= {a.name.split('.')[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
                found.add(n.module.split('.')[0])
        return {m for m in found if (HOOKS / (m + '.py')).is_file()}

    @classmethod
    def export_chain(cls):
        """Walk the imports the export path can load (adversarial delta finding A). ah.py is walked only at module
        level and inside status_report, since export calls nothing else in it; every other module reached is walked
        in full, including lazy function-level imports, so a missing transitive helper fails here."""
        ah_tree = ast.parse((HOOKS / 'ah.py').read_text(encoding='utf-8'))
        start = set()
        for n in ah_tree.body:
            if isinstance(n, (ast.Import, ast.ImportFrom)) or (
                    isinstance(n, ast.FunctionDef) and n.name == 'status_report'):
                start |= cls.local_imports(n)
        seen, todo = {'ah'}, ['ah_export', *sorted(start)]
        while todo:
            module = todo.pop()
            if module in seen:
                continue
            seen.add(module)
            todo += sorted(cls.local_imports(ast.parse((HOOKS / (module + '.py')).read_text(encoding='utf-8'))))
        return seen

    def test_import_walk_reaches_known_chain(self):
        chain = self.export_chain()
        for module in ('ah_export', 'ah', 'redact', 'safe_input', 'goals_view', 'mission_coverage'):
            self.assertIn(module, chain)

    def test_installer_lists_cover_import_chain(self):
        needed = self.export_chain()
        for installer in ('install.py', 'install_codex.py'):
            listed = self.listed(installer)
            for module in needed:
                self.assertIn(module + '.py', listed, f'{installer} lacks {module}.py')


class Cli(Base):
    def test_main_prints_one_json_line(self):
        out = io.StringIO()
        with mock.patch('sys.stdout', out):
            code = ah.main(['export', '--session', SESSION])
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertTrue(data['ok'])
        self.assertTrue(Path(data['path']).is_file())


if __name__ == '__main__':
    unittest.main()
