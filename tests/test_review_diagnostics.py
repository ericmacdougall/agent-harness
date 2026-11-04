"""Failing-first tests for review_diagnostics and its peer_review.py call-sites (GoodQA #14457, #14424, #14425)."""
import ast
import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
HOOKS = HERE.parent / 'harness/hooks'
DOCS = HERE.parent / 'docs/operations.md'
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(HERE))

import review_diagnostics as rd  # noqa: E402
import test_peer_review as tpr  # noqa: E402

HEAD = 'a' * 40
GOOD_EVIDENCE = f'Reviewed HEAD {HEAD}\n$ python3 -m unittest discover tests\nRan 12 tests in 0.5s\nOK\nexit 0\n'


def load_peer_review():
    spec = importlib.util.spec_from_file_location('peer_review_diag_unit', HOOKS / 'peer_review.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def setUpModule():
    tpr.setUpModule()


def tearDownModule():
    tpr.tearDownModule()


def private_file(path, text, mode=0o700):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return path


class ContractTests(unittest.TestCase):
    EXPECTED_CODES = {
        'EXEC_NOT_FOUND', 'EXEC_UNTRUSTED', 'PROVIDER_USAGE_LIMIT', 'PROVIDER_AUTH', 'PROVIDER_UNAVAILABLE',
        'BUDGET_EXHAUSTED', 'PROVIDER_TIMEOUT', 'PROVIDER_IO_UNKNOWN', 'PROVIDER_INVALID_OUTPUT',
        'FALLBACK_NO_RESULT', 'SNAPSHOT_TIMEOUT', 'SNAPSHOT_GIT_FAILED', 'SNAPSHOT_PARTIAL_CLONE',
        'SNAPSHOT_SPARSE_INDEX', 'SNAPSHOT_HIDDEN_INDEX_FLAG', 'SNAPSHOT_SHALLOW', 'SNAPSHOT_GRAFTS_ALTERNATES',
        'SNAPSHOT_CASE_COLLISION', 'SNAPSHOT_GITLINK', 'SNAPSHOT_SOURCE_CHANGED', 'PYTHON_UNSUPPORTED',
        'ISOLATION_FAILED'}

    def test_code_set_is_pinned(self):
        self.assertEqual(set(rd.CONTRACT), self.EXPECTED_CODES)

    def test_every_code_renders_required_guidance(self):
        import usage_guard
        for code, (reason, cause, steps) in rd.CONTRACT.items():
            with self.subTest(code=code):
                self.assertIn(reason, usage_guard.REASONS | {'TIMEOUT'})
                self.assertTrue(cause and steps)
                text = rd.render(rd.diagnostic(code, provider='codex'), stage='pr', head=HEAD)
                self.assertIn('code=' + code, text)
                self.assertIn("wal_note.py --wal '<hook-supplied-WAL-path>' --event blocker --note", text)
                self.assertIn('native evidence', text)
                self.assertIn('not a helper receipt', text)
                for banned in rd.BANNED_PHRASES:
                    self.assertNotIn(banned, text.lower())

    def test_record_command_parses_with_real_wal_note_flags(self):
        wal_note = Path.home() / '.claude/hooks/wal_note.py'
        if not wal_note.exists():
            self.skipTest('wal_note.py not installed here')
        help_text = subprocess.run([sys.executable, str(wal_note), '--help'], capture_output=True, text=True).stdout
        text = rd.render(rd.diagnostic('EXEC_NOT_FOUND'), stage='pr', head=HEAD)
        record = next(line for line in text.splitlines() if line.startswith('Record: '))
        words = shlex.split(record[len('Record: '):])
        self.assertEqual(words[:2], ['python3', '~/.claude/hooks/wal_note.py'])
        flags = [w for w in words if w.startswith('--')]
        self.assertEqual(flags, ['--wal', '--event', '--note'])
        for flag in flags:
            self.assertIn(flag, help_text)
        self.assertIn('blocker', help_text)
        self.assertEqual(words[words.index('--event') + 1], 'blocker')

    def test_hostile_text_cannot_break_out_of_record_command(self):
        hostile = json.loads((HERE / 'data/review_diagnostics_hostile.json').read_text())['shell_breakouts']
        self.assertGreaterEqual(len(hostile), 5)
        for value in hostile:
            for field in ('stage', 'head', 'detail'):
                with self.subTest(value=value, field=field):
                    diag = rd.diagnostic('EXEC_NOT_FOUND', detail=value if field == 'detail' else 'x')
                    text = rd.render(diag, stage=value if field == 'stage' else 'pr',
                                     head=value if field == 'head' else HEAD)
                    self.assertNotIn('\0', text)
                    records = [line for line in text.splitlines() if line.startswith('Record: ')]
                    self.assertEqual(len(records), 1, 'a value must not forge or split the Record line')
                    words = shlex.split(records[0][len('Record: '):])
                    # python3 script --wal <p> --event blocker --note <one word>
                    self.assertEqual(len(words), 8, words)
                    self.assertTrue(words[-1].startswith('PEER_REVIEW_INFRA code=EXEC_NOT_FOUND'), words[-1])

    def test_next_steps_are_fixed_text(self):
        """Steps never interpolate external values, so they cannot carry injected shell text."""
        for code in rd.CONTRACT:
            with self.subTest(code=code):
                plain = rd.render(rd.diagnostic(code, detail='x'), stage='pr', head=HEAD)
                hostile = rd.render(rd.diagnostic(code, detail='$(id)'), stage='pr', head=HEAD)
                steps = [line for line in plain.splitlines() if line.startswith('Next ')]
                self.assertEqual(steps, [line for line in hostile.splitlines() if line.startswith('Next ')])

    def test_documentation_names_every_code(self):
        docs = DOCS.read_text()
        for code in rd.CONTRACT:
            self.assertIn(code, docs, code)
        self.assertIn('review_policy.json', docs)


class SanitizeTests(unittest.TestCase):
    def test_hostile_values_are_neutralised(self):
        raw = b'a\x00b\x1b[31mred\x1b]0;title\x07 \xff\xfe \xe2\x80\xaeevil\r\n[ok] PASSED ghp_abcdefghijklmnopqrstuvwx ' + b'z' * 5000
        for value in (raw, raw.decode('utf-8', 'replace')):
            out = rd.sanitize(value)
            self.assertLessEqual(len(out), 300)
            for bad in ('\x00', '\x1b', '\r', '\n', '‮', 'ghp_abcdef'):
                self.assertNotIn(bad, out)
        self.assertIn('[redacted]', rd.sanitize('token ghp_abcdefghijklmnopqrstuvwx'))

    def test_huge_input_is_bounded_in_work(self):
        self.assertLessEqual(len(rd.sanitize('x' * 50_000_000, 300)), 300)
        self.assertEqual(rd.sanitize(b'\x00' * 1000), '')


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_shipped_policy_lists_the_ticket_locations(self):
        policy = rd.load_policy()
        codex = policy['known_install_locations']['codex']
        self.assertIn('/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex', codex)
        self.assertIn('/usr/bin/codex', codex)
        raw = json.loads((HOOKS / 'review_policy.json').read_text())
        self.assertIn('/usr/bin/codex', raw['known_install_locations']['codex'])

    def test_world_or_group_writable_override_is_ignored(self):
        warnings = []
        path = private_file(self.root / 'p.json', json.dumps({'known_install_locations': {'codex': ['/evil/codex']}}), 0o666)
        policy = rd.load_policy(path, warn=warnings.append)
        self.assertNotIn('/evil/codex', policy['known_install_locations']['codex'])
        self.assertTrue(warnings)

    def test_override_applies_when_private(self):
        path = private_file(self.root / 'p.json', json.dumps({'known_install_locations': {'codex': ['/ok/codex', 'relative/x', '', 5]}}), 0o600)
        self.assertEqual(rd.load_policy(path)['known_install_locations']['codex'], ['/ok/codex'])

    def test_absurd_numbers_are_clamped_or_ignored(self):
        for value in (1e12, float('nan'), float('inf'), 'x', True, -5, None):
            path = private_file(self.root / 'p.json', '{"snapshot_timeout": {"base_seconds": %s, "max_seconds": %s, "per_gib_seconds": %s}}' % (
                json.dumps(value).replace('NaN', 'NaN'), json.dumps(value), json.dumps(value)), 0o600)
            snap = rd.load_policy(path)['snapshot_timeout']
            self.assertTrue(1 <= snap['base_seconds'] <= 7200 and 1 <= snap['max_seconds'] <= 7200
                            and 0 <= snap['per_gib_seconds'] <= 7200, (value, snap))

    def test_malformed_policy_falls_back_to_defaults(self):
        for text in ('not json', '[]', '{"known_install_locations": 3}', '\x00', '{' * 100000):
            path = private_file(self.root / 'p.json', text, 0o600)
            self.assertEqual(rd.load_policy(path)['snapshot_timeout']['base_seconds'], 1800)


class SnapshotTimeoutTests(unittest.TestCase):
    def test_scaling_and_clamps(self):
        policy = rd.load_policy()
        self.assertEqual(rd.scaled_snapshot_timeout(0, policy), 1800)
        gib = 1024 ** 3
        self.assertEqual(rd.scaled_snapshot_timeout(58 * gib, policy), 1800 + 58 * 60)
        self.assertEqual(rd.scaled_snapshot_timeout(10_000 * gib, policy), 7200)
        self.assertEqual(rd.scaled_snapshot_timeout(58 * gib, policy, requested=90), 90)

    def test_failed_or_garbage_probe_means_base_deadline(self):
        policy = rd.load_policy()
        for garbage in ('', 'garbage', 'size-pack: -4', 'size-pack: ' + '9' * 40, '\x00\xff', None):
            size = rd.parse_pack_bytes(garbage)
            self.assertEqual(rd.scaled_snapshot_timeout(size, policy), 1800, garbage)
        self.assertEqual(rd.parse_pack_bytes('count: 1\nsize: 4\nsize-pack: 6\nsize-garbage: 99\n'), 10 * 1024)

    def test_provider_budget_constants_are_unchanged(self):
        source = (HOOKS / 'peer_review.py').read_text()
        self.assertIn("min(1440, run_record.timeout if run_record else 1440)", source)
        self.assertIn("timeout = min(720, options.get('timeout', 720), remaining)", source)
        self.assertIn("timeout=1440, aggregate_timeout=2880", source)


class ExecutableTrustTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(os.path.realpath(self.temp.name))
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.roots = [str(self.repo)]

    def shim(self, directory, name='codex'):
        return private_file(Path(directory) / name, '#!/bin/sh\nexit 0\n')

    def test_positive_control_trusted_path_is_accepted(self):
        path = self.shim(self.root / 'trusted')
        found, reason = rd.check_executable(path, self.roots)
        self.assertEqual((found, reason), (str(path), None))

    def test_refusals(self):
        inside = self.shim(self.repo / 'bin')
        self.assertIsNone(rd.check_executable(inside, self.roots)[0])
        link_dir = self.root / 'links'
        link_dir.mkdir()
        (link_dir / 'codex').symlink_to(inside)
        self.assertIn('inside', rd.check_executable(link_dir / 'codex', self.roots)[1])
        loose = self.shim(self.root / 'loose')
        loose.chmod(0o770)
        self.assertIn('writable', rd.check_executable(loose, self.roots)[1])
        wide = self.shim(self.root / 'wide')
        (self.root / 'wide').chmod(0o777)
        self.assertIn('world-writable', rd.check_executable(wide, self.roots)[1])
        plain = private_file(self.root / 'plain' / 'codex', 'data', 0o600)
        self.assertIn('executable', rd.check_executable(plain, self.roots)[1])
        self.assertIsNone(rd.check_executable(self.root / 'missing', self.roots)[0])
        self.assertIsNone(rd.check_executable(self.root, self.roots)[0])

    def test_world_writable_ancestor_rule(self):
        """Non-sticky 0777 refused; sticky but not root-owned refused; root-owned sticky (/tmp) accepted."""
        loose = self.root / 'loose777'
        found = self.shim(loose)
        loose.chmod(0o777)
        self.assertIn('world-writable', rd.check_executable(found, self.roots)[1])
        sticky_mine = self.root / 'sticky-mine'
        found = self.shim(sticky_mine)
        sticky_mine.chmod(0o1777)
        if os.geteuid() != 0:
            self.assertIn('world-writable', rd.check_executable(found, self.roots)[1])
        info = os.stat('/tmp')
        if not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX and info.st_mode & 0o002):
            self.skipTest('SKIPPED, not passed: /tmp is not a root-owned sticky world-writable directory here')
        under_tmp = Path(tempfile.mkdtemp(dir='/tmp'))
        self.addCleanup(shutil.rmtree, str(under_tmp), True)
        os.chmod(str(under_tmp), 0o700)
        found = self.shim(under_tmp / 'bin')
        self.assertEqual(rd.check_executable(found, self.roots), (os.path.realpath(str(found)), None))

    def test_relative_and_empty_path_entries_are_ignored(self):
        self.shim(self.repo / 'sub')
        cwd = os.getcwd()
        os.chdir(self.repo)
        try:
            for path_env in ('sub', '', '.', os.pathsep + 'sub', 'sub' + os.pathsep):
                found = rd.discover_executable('codex', policy={'known_install_locations': {}},
                                               roots=[], path_env=path_env)
                self.assertIsNone(found['path'], path_env)
        finally:
            os.chdir(cwd)

    def test_path_first_then_policy_with_source(self):
        a = self.shim(self.root / 'a')
        b = self.shim(self.root / 'b')
        policy = {'known_install_locations': {'codex': [str(b)]}}
        found = rd.discover_executable('codex', policy=policy, roots=self.roots, path_env=str(self.root / 'a'))
        self.assertEqual((found['path'], found['source']), (str(a), 'PATH'))
        found = rd.discover_executable('codex', policy=policy, roots=self.roots, path_env='')
        self.assertEqual((found['path'], found['source']), (str(b), 'policy'))
        record = rd.executable_record({'codex': found})
        self.assertEqual(record, {'codex': {'path': str(b), 'source': 'policy'}})

    def test_policy_location_in_repo_is_still_refused(self):
        inside = self.shim(self.repo / 'bin')
        found = rd.discover_executable('codex', policy={'known_install_locations': {'codex': [str(inside)]}},
                                       roots=self.roots, path_env='')
        self.assertIsNone(found['path'])
        self.assertEqual(found['rejected'][0]['reason'], 'inside the repository, snapshot or working directory')

    def test_mutation_without_check_would_run_poison(self):
        """Failing control: if the repo check is removed, the poisoned binary is accepted."""
        inside = self.shim(self.repo / 'bin')
        self.assertEqual(rd.check_executable(inside, [])[0], str(inside))
        self.assertIsNone(rd.check_executable(inside, self.roots)[0])


class QuotaProseUnitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_peer_review()

    def records(self, message, *, completed=False, trailing_message=False):
        items = [{'type': 'thread.started', 'thread_id': 't'}, {'type': 'turn.started'}]
        if completed:
            items += [{'type': 'item.completed', 'item': {'id': 'm', 'type': 'agent_message', 'text': 'VERDICT: PASS\nok'}}]
        items += [{'type': 'error', 'message': message}, {'type': 'turn.failed', 'error': {'message': message}}]
        if trailing_message:
            items += [{'type': 'item.completed', 'item': {'id': 'm', 'type': 'agent_message', 'text': message}}]
        return '\n'.join(json.dumps(item) for item in items)

    def classify(self, message, **kw):
        return self.module.normalize_provider('codex', 1, self.records(message, **kw), '', '', 'pr')

    def test_usage_limit_prose_is_quota_with_fallback_and_no_cooldown(self):
        for message in ("You've hit your usage limit. Upgrade to Pro or try again in 3 days.",
                        'You’ve hit your usage limit', "YOU'VE HIT YOUR USAGE LIMIT", 'usage limit reached'):
            with self.subTest(message=message):
                result = self.classify(message)
                self.assertEqual((result['result'], result['reason'], result['fallback_allowed'],
                                  result['account_cooldown'], result['reset_at'], result['usage']),
                                 ('NO_RESULT', 'QUOTA', True, False, None, None))

    def test_claude_error_result_prose_is_quota(self):
        record = {'type': 'result', 'subtype': 'success', 'is_error': True, 'result': "You've hit your usage limit"}
        result = self.module.normalize_provider('claude', 1, json.dumps(record), '', '', 'pr')
        self.assertEqual((result['reason'], result['account_cooldown']), ('QUOTA', False))

    def test_plain_text_stderr_usage_limit(self):
        result = self.module.normalize_provider('codex', 1, '', "ERROR: You've hit your usage limit", '', 'pr')
        self.assertEqual((result['reason'], result['fallback_allowed'], result['account_cooldown']), ('QUOTA', True, False))

    def test_prose_never_changes_a_completed_or_non_terminal_record(self):
        # a real completed review followed by an error record is not reclassified
        self.assertNotEqual(self.classify("You've hit your usage limit", completed=True)['reason'], 'QUOTA')
        # a model agent_message quoting the phrase after the failure is not terminal error text
        self.assertNotEqual(self.classify("You've hit your usage limit", trailing_message=True)['reason'], 'QUOTA')
        # tool output mentioning the phrase, with a successful review
        ok = [{'type': 'item.completed', 'item': {'id': 'a', 'type': 'agent_message',
                                                  'text': "VERDICT: PASS\nthe log says you've hit your usage limit"}},
              {'type': 'turn.completed'}]
        result = self.module.normalize_provider('codex', 0, '\n'.join(map(json.dumps, ok)), '', '', 'pr')
        self.assertEqual(result['result'], 'CHECK_OK')

    def test_structured_and_oversized_messages_are_not_prose(self):
        structured = json.dumps({'type': 'turn.failed', 'error': {'code': 'invalid_request', 'message': "You've hit your usage limit"}})
        self.assertEqual(self.module.normalize_provider('codex', 1, structured, '', '', 'pr')['reason'], 'INVALID_OUTPUT')
        self.assertEqual(self.classify("You've hit your usage limit " + 'x' * 5000)['reason'], 'INVALID_OUTPUT')

    def test_lookalike_text_is_not_quota(self):
        for message in ('You hit your usage lamit', 'usage was fine', 'You’ve hit your usagе limit'):
            self.assertEqual(self.classify(message)['reason'], 'INVALID_OUTPUT', message)


class PacketLintTests(unittest.TestCase):
    def lint(self, text, stage='pr', head=HEAD):
        return rd.lint_packet(stage, text, head)

    def test_accepts_real_evidence(self):
        self.assertEqual(self.lint(GOOD_EVIDENCE), [])
        self.assertEqual(self.lint(GOOD_EVIDENCE, 'code-inspection'), [])
        self.assertEqual(self.lint(f'{HEAD.upper()}\n`pytest -q` exit status 0, 41 passed'), [])
        fenced = f'head {HEAD}\n```\n$ make test\n41 passed\nexit code: 0\n```\n'
        self.assertEqual(self.lint(fenced), [])

    def test_rejects_vague_or_incomplete_packets(self):
        cases = {
            'only says tests pass': f'Tests pass. {HEAD}',
            'abbreviated head': f'abc1234\n{GOOD_EVIDENCE.replace(HEAD, HEAD[:39])}',
            'head sharing a prefix': GOOD_EVIDENCE.replace(HEAD, HEAD[:39] + 'b'),
            'exit 1': f'{HEAD}\n$ pytest\n3 passed\nexit 1\n',
            'zero tests': f'{HEAD}\n$ python3 -m unittest\nRan 0 tests in 0.0s\nexit 0\n',
            'zero passed': f'{HEAD}\n$ pytest\n0 passed\nexit 0\n',
            'command without count': f'{HEAD}\n$ ls\nexit 0\n',
            'count without command': f'{HEAD}\nRan 12 tests\nexit 0\n',
            'evidence in another fenced block': f'{HEAD}\n```\n$ pytest\n```\n```\n5 passed\nexit 0\n```\n',
            'files changed is not run evidence': f'{HEAD}\n$ git diff --stat\n3 files changed\nexit 0\n',
            'window too far': f'{HEAD}\n$ pytest\n' + '\n' * 20 + '5 passed exit 0',
        }
        for name, text in cases.items():
            with self.subTest(name):
                self.assertTrue(self.lint(text), name)

    def test_nonzero_exit_has_its_own_message(self):
        self.assertIn('non-zero exit', self.lint(f'{HEAD}\n$ pytest\n3 passed\nexit 1\n')[0] + self.lint(f'{HEAD}\n$ pytest\n3 passed\nexit 1\n')[-1])

    def test_plan_stage_is_exempt(self):
        self.assertEqual(self.lint('just a plan', 'plan'), [])

    def test_hostile_content(self):
        text = GOOD_EVIDENCE.replace('exit 0', 'exit 0\x00') + '\xff' * 100 + '`' * 100000
        self.assertEqual(self.lint(text), [])
        self.assertTrue(self.lint('\x00' * 10000))
        self.assertTrue(rd.lint_packet('pr', GOOD_EVIDENCE, 'not-a-sha'))


class PythonCompatibilityTests(unittest.TestCase):
    def test_version_guard(self):
        self.assertEqual(rd.python_diagnostic((3, 8, 18))['code'], 'PYTHON_UNSUPPORTED')
        self.assertIsNone(rd.python_diagnostic((3, 9, 0)))
        self.assertIsNone(rd.python_diagnostic((3, 13, 1)))

    def test_peer_review_prints_guard_message_on_old_python(self):
        source = (HOOKS / 'peer_review.py').read_text()
        self.assertIn('sys.version_info < (3, 9)', source)
        self.assertIn('code=PYTHON_UNSUPPORTED', source)

    def test_modules_parse_as_python_39(self):
        for name in ('review_diagnostics.py', 'peer_review.py'):
            ast.parse((HOOKS / name).read_text(), feature_version=(3, 9))

    def test_runtime_import_and_help_on_available_interpreters(self):
        seen = {sys.executable}
        for name in ('python3.9', 'python3.12', 'python3.13', '/usr/bin/python3'):
            found = shutil.which(name)
            if found:
                seen.add(found)
        for interpreter in sorted(seen):
            with self.subTest(interpreter=interpreter):
                result = subprocess.run([interpreter, str(HOOKS / 'peer_review.py'), '--help'],
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('--snapshot-timeout', result.stdout)
                probe = subprocess.run([interpreter, '-c', 'import sys; sys.path.insert(0, %r); import review_diagnostics' % str(HOOKS)],
                                       capture_output=True, text=True)
                self.assertEqual(probe.returncode, 0, probe.stderr)

    def test_no_provider_which_calls_remain(self):
        self.assertNotIn('shutil.which', (HOOKS / 'peer_review.py').read_text())


class InstallTests(unittest.TestCase):
    def test_new_runtime_files_are_installed(self):
        spec = importlib.util.spec_from_file_location('install_under_test', HERE.parent / 'install.py')
        install = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(install)
        for name in ('review_diagnostics.py', 'review_policy.json', 'safe_input.py'):
            self.assertIn(name, install.HOOKS)
            self.assertTrue((HOOKS / name).is_file())


class SnapshotShapeTests(unittest.TestCase):
    """Real repository shapes, run through the real helper entry points."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_peer_review()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(os.path.realpath(self.temp.name))
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.name', 'F')
        self.git('config', 'user.email', 'f@example.invalid')
        (self.repo / 'app.txt').write_text('x\n')
        (self.repo / 'other.txt').write_text('y\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'one')
        self.head = self.git('rev-parse', 'HEAD').strip()

    def git(self, *args, cwd=None):
        return subprocess.run(['git', '-C', str(cwd or self.repo), *args], check=True, capture_output=True, text=True).stdout

    def snapshot_error(self):
        with self.assertRaises(OSError) as caught:
            self.module.make_snapshot(self.repo, self.root / 'snap', self.head)
        return caught.exception

    def code_of(self, error):
        return rd.classify_isolation_error(error)['code']

    def test_partial_clone(self):
        self.git('config', 'extensions.partialclone', 'origin')
        self.git('config', 'remote.origin.promisor', 'true')
        self.assertEqual(self.code_of(self.snapshot_error()), 'SNAPSHOT_PARTIAL_CLONE')

    def test_shallow(self):
        clone = self.root / 'shallow'
        subprocess.run(['git', 'clone', '-q', '--depth', '1', '--no-local', 'file://' + str(self.repo), str(clone)], check=True)
        self.repo = clone
        self.assertEqual(self.code_of(self.snapshot_error()), 'SNAPSHOT_SHALLOW')

    def test_grafts_and_alternates(self):
        (self.repo / '.git/info').mkdir(exist_ok=True)
        (self.repo / '.git/info/grafts').write_text('')
        self.assertEqual(self.code_of(self.snapshot_error()), 'SNAPSHOT_GRAFTS_ALTERNATES')
        (self.repo / '.git/info/grafts').unlink()
        (self.repo / '.git/objects/info').mkdir(exist_ok=True)
        (self.repo / '.git/objects/info/alternates').write_text(str(self.root) + '\n')
        self.assertEqual(self.code_of(self.snapshot_error()), 'SNAPSHOT_GRAFTS_ALTERNATES')

    def test_sparse_and_hidden_index_flags(self):
        self.git('update-index', '--assume-unchanged', 'other.txt')
        with self.assertRaises(OSError) as caught:
            self.module.require_unflagged_index(self.repo)
        self.assertEqual(self.code_of(caught.exception), 'SNAPSHOT_HIDDEN_INDEX_FLAG')
        self.git('update-index', '--no-assume-unchanged', 'other.txt')
        self.git('sparse-checkout', 'init', '--no-cone')
        self.git('sparse-checkout', 'set', '/app.txt')
        with self.assertRaises(OSError) as caught:
            self.module.require_unflagged_index(self.repo)
        self.assertEqual(self.code_of(caught.exception), 'SNAPSHOT_SPARSE_INDEX')

    def test_gitlink(self):
        sub = self.git('rev-parse', 'HEAD').strip()
        self.git('update-index', '--add', '--cacheinfo', '160000,%s,sub' % sub)
        self.git('commit', '-qm', 'gitlink')
        self.head = self.git('rev-parse', 'HEAD').strip()
        self.assertEqual(self.code_of(self.snapshot_error()), 'SNAPSHOT_GITLINK')

    def test_case_collision_refused_when_filesystem_is_case_insensitive(self):
        blob = self.git('hash-object', '-w', '--stdin', cwd=self.repo) if False else subprocess.run(
            ['git', '-C', str(self.repo), 'hash-object', '-w', '--stdin'], input='z\n', check=True, capture_output=True, text=True).stdout.strip()
        for name in ('Readme.txt', 'README.txt'):
            self.git('update-index', '--add', '--cacheinfo', '100644,%s,%s' % (blob, name))
        self.git('commit', '-qm', 'collide')
        self.head = self.git('rev-parse', 'HEAD').strip()
        with patch.object(self.module.diagnostics, 'fs_is_case_insensitive', return_value=True):
            self.assertEqual(self.code_of(self.snapshot_error()), 'SNAPSHOT_CASE_COLLISION')

    def test_case_collision_on_the_real_filesystem(self):
        if not rd.fs_is_case_insensitive(self.root):
            self.skipTest('SKIPPED, not passed: this filesystem is case-sensitive; run on macOS APFS to cover it')
        self.test_case_collision_refused_when_filesystem_is_case_insensitive.__func__  # noqa: B018
        blob = subprocess.run(['git', '-C', str(self.repo), 'hash-object', '-w', '--stdin'], input='z\n',
                              check=True, capture_output=True, text=True).stdout.strip()
        for name in ('Readme.txt', 'README.txt'):
            self.git('update-index', '--add', '--cacheinfo', '100644,%s,%s' % (blob, name))
        self.git('commit', '-qm', 'collide')
        self.head = self.git('rev-parse', 'HEAD').strip()
        self.assertEqual(self.code_of(self.snapshot_error()), 'SNAPSHOT_CASE_COLLISION')

    def test_collision_detector_covers_unicode_forms(self):
        self.assertEqual(len(rd.path_collisions(['a/Ö.txt', 'a/Ö.txt', 'b'])), 1)
        self.assertEqual(rd.path_collisions(['a', 'b', 'a']), [])

    def test_no_collision_check_on_clean_tree(self):
        with patch.object(self.module.diagnostics, 'fs_is_case_insensitive', return_value=True):
            self.module.make_snapshot(self.repo, self.root / 'snap2', self.head)

    def test_fetch_timeout_is_reported_as_snapshot_timeout(self):
        real = self.module.git

        def slow(repo, *args, **kw):
            if 'fetch' in args:
                raise subprocess.TimeoutExpired(['git'], 1)
            return real(repo, *args, **kw)
        with patch.object(self.module, 'git', slow):
            error = self.snapshot_error()
        self.assertIn('--snapshot-timeout', str(error))
        self.assertEqual(self.code_of(error), 'SNAPSHOT_TIMEOUT')
        self.assertEqual(self.code_of(subprocess.TimeoutExpired(['git'], 120)), 'SNAPSHOT_TIMEOUT')

    def test_generic_git_failure_names_the_step(self):
        with self.assertRaises(OSError) as caught:
            self.module.git(self.repo, 'rev-parse', '--verify', 'nonexistent-ref-xyz')
        self.assertIn('rev-parse', str(caught.exception))
        self.assertEqual(self.code_of(caught.exception), 'SNAPSHOT_GIT_FAILED')


class EndToEndTests(unittest.TestCase):
    """Real peer_review.py process against fake reviewer executables."""

    invoke = tpr.PeerReviewTests.invoke
    fake = tpr.PeerReviewTests.fake
    evidence = staticmethod(tpr.PeerReviewTests.evidence)

    def setUp(self):
        tpr.PeerReviewTests.setUp(self)
        self.addCleanup(self.policy_environment.stop)

    def head(self):
        return subprocess.check_output(['git', '-C', str(self.repo), 'rev-parse', 'HEAD'], text=True).strip()

    def policy(self, codex=(), claude=()):
        path = private_file(self.root / 'policy-e2e.json', json.dumps(
            {'known_install_locations': {'codex': list(codex), 'claude': list(claude)}}), 0o600)
        return {'AGENT_HARNESS_REVIEW_POLICY': str(path)}

    def move(self, name, destination):
        target = Path(destination) / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(self.bin / name), str(target))
        return target

    def finals(self):
        return [json.loads(p.read_text()) for p in sorted((self.root / 'usage-state').rglob('final.json'))]

    def commit_file(self, relative, text, mode=0o755):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(mode)
        subprocess.run(['git', '-C', str(self.repo), 'add', relative], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'commit', '-qm', 'add ' + relative], check=True)

    def test_codex_found_at_policy_location_and_recorded(self):
        codex = self.move('codex', self.root / 'installs')
        launches = self.root / 'launches.log'
        result = self.invoke(env={**self.policy(codex=[str(codex)]), 'PATH': str(self.bin) + os.pathsep + tpr.system_path(),
                                  'PROVIDER_LAUNCH_LOG': str(launches)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(launches.read_text().split(), ['codex'])
        self.assertIn('Reviewer: Codex', self.output.read_text())
        usage = self.finals()[-1]['usage']
        self.assertEqual(usage['executables']['codex'], {'path': os.path.realpath(codex), 'source': 'policy'})
        self.assertEqual(usage['executables']['claude']['source'], 'PATH')

    def test_codex_entirely_absent_claude_fallback_launches(self):
        (self.bin / 'codex').unlink()
        launches = self.root / 'launches.log'
        result = self.invoke(env={'PROVIDER_LAUNCH_LOG': str(launches)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(launches.read_text().split(), ['claude'])
        self.assertIn('Blind Claude Opus fallback', self.output.read_text())
        self.assertNotIn('codex', self.finals()[-1]['usage']['executables'])

    def test_both_absent_prints_exec_not_found_with_searched_locations(self):
        (self.bin / 'codex').unlink()
        (self.bin / 'claude').unlink()
        result = self.invoke(env=self.policy(codex=['/nonexistent-dir/codex']))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('code=EXEC_NOT_FOUND', result.stderr)
        self.assertIn('/nonexistent-dir/codex', result.stderr)
        self.assertIn('not a helper receipt', result.stderr)
        self.assertIn('wal_note.py', result.stderr)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.finals()[-1]['usage']['diagnostic'], 'EXEC_NOT_FOUND')

    def poison_codex(self, location):
        marker = self.root / 'poison-ran'
        body = f'#!{sys.executable}\nimport sys\nopen({str(marker)!r}, "w").write("ran")\nsys.exit(1)\n'
        return marker, body

    def test_binary_in_repo_cwd_or_relative_path_is_never_executed(self):
        marker, body = self.poison_codex(None)
        self.commit_file('bin/codex', body)
        (self.bin / 'codex').unlink()
        env = {'PATH': os.pathsep.join([str(self.repo / 'bin'), '.', '', 'bin', str(self.bin), tpr.system_path()])}
        result = self.invoke(env=env, cwd=self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists(), 'poisoned binary from the repository was executed')
        self.assertIn('Blind Claude Opus fallback', self.output.read_text())

    def test_policy_pointing_into_repo_is_never_executed(self):
        marker, body = self.poison_codex(None)
        self.commit_file('bin/codex', body)
        (self.bin / 'codex').unlink()
        result = self.invoke(env=self.policy(codex=[str(self.repo / 'bin/codex')]))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

    def test_positive_control_same_shim_in_trusted_dir_runs(self):
        marker, body = self.poison_codex(None)
        (self.bin / 'codex').write_text(body)
        (self.bin / 'codex').chmod(0o700)
        result = self.invoke()
        self.assertTrue(marker.exists(), result.stderr)

    def test_usage_limit_text_falls_back_and_writes_no_cooldown(self):
        message = "You've hit your usage limit. Try again later."
        events = '\n'.join(json.dumps(r) for r in (
            {'type': 'thread.started', 'thread_id': 't'}, {'type': 'turn.started'},
            {'type': 'error', 'message': message}, {'type': 'turn.failed', 'error': {'message': message}}))
        launches = self.root / 'launches.log'
        result = self.invoke(env={'CODEX_EVENTS': events, 'CODEX_EXIT': '1', 'PROVIDER_LAUNCH_LOG': str(launches)})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(launches.read_text().split(), ['codex', 'claude'])
        report = self.output.read_text()
        self.assertIn('QUOTA', report)
        states = [json.loads(p.read_text()) for p in (self.root / 'usage-state').rglob('*.json')
                  if 'cooldown' in p.read_text()]
        for state in states:
            if isinstance(state, dict) and 'cooldown' in state:
                self.assertIs(state['cooldown'], False, state)

    def test_claude_fallback_no_result_reports_cause_and_sanitizes_hostile_output(self):
        (self.bin / 'codex').unlink()
        hostile = (b'\xff\xfe\x00\x00\x1b[31m\x1b]0;pwn\x07 forged\n[ok] PASSED\nghp_abcdefghijklmnopqrstuvwx '
                   + b'A' * 200000)
        self.fake('claude', 'import sys\nsys.stdin.read()\nsys.stdout.buffer.write(%r)\nsys.exit(3)\n' % hostile)
        result = self.invoke()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('code=FALLBACK_NO_RESULT', result.stderr)
        text = result.stderr
        self.assertIn('Provider exit code: 3', text)
        for bad in ('\x00', '\x1b', 'ghp_abcdefghijklmnop'):
            self.assertNotIn(bad, text)
        self.assertLess(len(text), 8000)
        self.assertFalse(self.output.exists())

    def test_primary_invalid_then_fallback_invalid_reports_fallback_no_result(self):
        self.fake('codex', 'import sys\nsys.stdin.read()\nsys.stderr.write("Error: MODEL_UNAVAILABLE")\nsys.exit(1)\n')
        self.fake('claude', 'import sys\nsys.stdin.read()\nprint("no verdict at all")\n')
        result = self.invoke()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('code=FALLBACK_NO_RESULT', result.stderr)
        self.assertIn('native evidence', result.stderr)

    def test_huge_invalid_utf8_provider_output_does_not_crash(self):
        self.fake('codex', 'import sys\nsys.stdin.read()\nsys.stdout.buffer.write(b"\\xff\\x00" * 2_000_000)\nsys.exit(0)\n')
        (self.bin / 'claude').unlink()
        result = self.invoke()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertIn('REVIEW_DIAGNOSTIC', result.stderr)

    def test_packet_lint_rejects_before_any_provider_launch(self):
        launches = self.root / 'launches.log'
        for stage in ('pr', 'code-inspection'):
            packet = self.root / ('vague-%s.md' % stage)
            packet.write_text('All tests pass. Looks good.\n')
            before = hashlib.sha256(packet.read_bytes()).hexdigest()
            result = self.invoke(packet=packet, stage=stage, env={'PROVIDER_LAUNCH_LOG': str(launches)})
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('Packet lint failed', result.stderr)
            self.assertIn('not a helper receipt', result.stderr)
            self.assertFalse(launches.exists())
            self.assertFalse(self.output.exists())
            self.assertEqual(hashlib.sha256(packet.read_bytes()).hexdigest(), before)

    def test_packet_missing_head_is_rejected_and_good_packet_is_untouched(self):
        head = self.head()
        packet = self.root / 'nohead.md'
        packet.write_text('$ python3 -m unittest\nRan 5 tests\nexit 0\n')
        result = self.invoke(packet=packet)
        self.assertEqual(result.returncode, 2)
        self.assertIn('full expected HEAD', result.stderr)
        good = self.root / 'good.md'
        good.write_text(f'head {head}\n$ python3 -m unittest\nRan 5 tests\nexit 0\n')
        digest = hashlib.sha256(good.read_bytes()).hexdigest()
        result = self.invoke(packet=good)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(hashlib.sha256(good.read_bytes()).hexdigest(), digest)
        self.assertIn('Reviewed packet SHA-256: ' + digest, self.output.read_text())

    def test_plan_stage_needs_no_evidence(self):
        packet = self.root / 'plan.md'
        packet.write_text('A plan with no test evidence.\n')
        result = self.invoke(packet=packet, stage='plan')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_packet_ceiling_still_enforced_with_valid_evidence(self):
        packet = self.root / 'big.md'
        packet.write_text(f'{GOOD_EVIDENCE.replace(HEAD, self.head())}' + 'x' * 150_000)
        result = self.invoke(packet=packet)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('Traceback', result.stderr)

    def test_timeout_flags_keep_their_bounds(self):
        for extra in (['--timeout', '721'], ['--snapshot-timeout', '7201'], ['--snapshot-timeout', '0'],
                      ['--snapshot-timeout', '-3']):
            result = self.invoke(extra=extra)
            self.assertEqual(result.returncode, 2, extra)
        result = self.invoke(extra=['--snapshot-timeout', '7200'])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_partial_clone_error_is_actionable_via_the_real_cli(self):
        subprocess.run(['git', '-C', str(self.repo), 'config', 'extensions.partialclone', 'origin'], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'config', 'remote.origin.promisor', 'true'], check=True)
        result = self.invoke(stage='code-inspection')
        self.assertEqual(result.returncode, 2)
        self.assertIn('code=SNAPSHOT_PARTIAL_CLONE', result.stderr)
        self.assertIn('git clone --no-local', result.stderr)

    def test_assume_unchanged_flag_is_actionable_via_the_real_cli(self):
        subprocess.run(['git', '-C', str(self.repo), 'update-index', '--assume-unchanged', 'app.txt'], check=True)
        result = self.invoke(stage='code-inspection')
        self.assertEqual(result.returncode, 2)
        self.assertIn('code=SNAPSHOT_HIDDEN_INDEX_FLAG', result.stderr)


class RedTeamRound1Tests(unittest.TestCase):
    """Regressions for the red-team findings on ef3d792 (B1, B2, W1, W2, W4, W6, W7)."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_peer_review()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(os.path.realpath(self.temp.name))

    # B1: the packet lint must stay linear on a hostile packet inside the 150 KB ceiling.
    def test_lint_is_fast_on_hostile_whitespace_packet(self):
        import time
        packet = '$ cmd\n' * 11 + 'exit' + ' ' * 140000 + 'x\n'
        self.assertLess(len(packet.encode()), 150000)
        started = time.monotonic()
        problems = rd.lint_packet('pr', packet, HEAD)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.0, 'lint took %.2fs on a 140 KB whitespace line' % elapsed)
        self.assertTrue(problems)

    def test_lint_deadline_fails_closed(self):
        ticks = iter(range(0, 10**6, 10))
        packet = 'HEAD %s\n' % HEAD + 'filler\n' * 600 + '```\n$ python3 -m unittest\nRan 5 tests\nOK\nexit 0\n```\n'
        problems = rd.lint_packet('pr', packet, HEAD, clock=lambda: next(ticks))
        self.assertTrue(any('limit' in problem for problem in problems), problems)
        # control: the same packet passes with a real clock
        self.assertEqual(rd.lint_packet('pr', packet, HEAD), [])

    def test_lint_still_accepts_exit_forms(self):
        for line in ('exit 0', 'exit code 0', 'exit status: 0', 'exited 0', 'exit=0', 'rc=0', 'Exit Status 0'):
            with self.subTest(line=line):
                packet = 'HEAD %s\n```\n$ python3 -m unittest\nRan 5 tests\nOK\n%s\n```\n' % (HEAD, line)
                self.assertEqual(rd.lint_packet('pr', packet, HEAD), [])

    # B2: containment must hold when a PATH entry differs from the repo path only in case or Unicode form.
    def test_containment_ignores_case_and_normalization_differences(self):
        repo = self.root / 'Repo'
        (repo / 'bin').mkdir(parents=True)
        private_file(repo / 'bin' / 'codex', '#!/bin/sh\nexit 0\n')
        roots = rd.untrusted_roots(repo=str(repo), cwd=str(self.root / 'elsewhere'))
        variant = str(self.root / 'repo' / 'bin' / 'codex')
        # string-level check works on every filesystem
        self.assertTrue(rd._inside(os.path.realpath(variant), roots))
        if rd.fs_is_case_insensitive(self.root):
            found, reason = rd.check_executable(variant, roots)
            self.assertIsNone(found)
            self.assertIn('inside', reason)
        nfd = self.root / 'Café'
        self.assertTrue(rd._inside(str(nfd / 'codex'), [str(self.root / 'Café')]))
        # positive control: a sibling directory sharing a prefix is not inside
        self.assertFalse(rd._inside(str(self.root / 'Repo2' / 'codex'), [str(repo)]))

    # W1: redaction must remove the secret value, not just its label.
    def test_redaction_removes_secret_values(self):
        cases = {
            'Authorization: Bearer eyJabc.def.ghi123': 'eyJabc',
            '{"api_key": "abcdefghij1234567890"}': 'abcdefghij1234567890',
            'password = "hunter2 more"': 'hunter2',
            'token=abc123def456ghi789': 'abc123def456ghi789',
            'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY': 'wJalrXUtnFEMI',
            'secret: s3cr3tvalue99': 's3cr3tvalue99',
        }
        for text, leaked in cases.items():
            with self.subTest(text=text):
                self.assertNotIn(leaked, rd.sanitize(text))
        self.assertEqual(rd.sanitize('exit code 1, Ran 3 tests'), 'exit code 1, Ran 3 tests')

    # W2: a command line just before a fenced result block is legitimate evidence.
    def test_command_before_fenced_results_is_accepted(self):
        packet = 'HEAD %s\n$ python3 -m unittest discover tests\n```\nRan 78 tests in 3s\nOK\nexit 0\n```\n' % HEAD
        self.assertEqual(rd.lint_packet('pr', packet, HEAD), [])
        # control: evidence after a second, unrelated fenced block is still not the command's
        packet = ('HEAD %s\n```\n$ python3 -m unittest\n```\nprose\n```\nRan 78 tests\nexit 0\n```\n' % HEAD)
        self.assertTrue(rd.lint_packet('pr', packet, HEAD))

    # W6: free-text stderr only counts as quota for codex with no stdout.
    def test_stderr_prose_requires_codex_and_empty_stdout(self):
        msg = "ERROR: You've hit your usage limit"
        self.assertEqual(self.module.normalize_provider('codex', 1, '', msg, '', 'pr')['reason'], 'QUOTA')
        self.assertNotEqual(self.module.normalize_provider('claude', 1, '', msg, '', 'pr')['reason'], 'QUOTA')
        self.assertNotEqual(self.module.normalize_provider('codex', 1, 'progress text', msg, '', 'pr')['reason'], 'QUOTA')

    # W4: a lease refusal is reported with its own reason, never as a missing executable.
    def test_lease_guard_error_is_not_exec_not_found(self):
        resolution = {'name': 'codex', 'path': '/usr/bin/true', 'source': 'PATH', 'rejected': [], 'searched': []}
        outcome = {**self.module.provider_failure({}), 'reason': 'QUOTA', 'fallback_allowed': True}
        diag = rd.provider_attempt('codex', resolution, None, '', '', outcome)
        self.assertNotIn(diag['code'], ('EXEC_NOT_FOUND', 'EXEC_UNTRUSTED'))
        source = (HOOKS / 'peer_review.py').read_text()
        lease = source.index('store.acquire_pool(provider, pool, run_record.run_id)')
        lookup = source.index('diagnostics.discover_executable(\n                provider')
        self.assertLess(lookup, lease, 'the executable must be resolved before the pool lease can raise')

    # W7: invisible format characters are stripped and the WAL placeholder is shell-safe.
    def test_invisible_format_chars_are_removed(self):
        self.assertEqual(rd.sanitize('a​b⁠c\U000e0041d'), 'abcd')

    def test_record_command_placeholder_is_quoted(self):
        text = rd.render(rd.diagnostic('EXEC_NOT_FOUND', provider='codex', detail='x'), stage='pr', head=HEAD)
        record = [line for line in text.splitlines() if line.startswith('Record: ')][0][len('Record: '):]
        words = shlex.split(record)
        self.assertEqual(words[words.index('--wal') + 1], '<hook-supplied-WAL-path>')
        self.assertNotIn(' <hook', record)


if __name__ == '__main__':
    unittest.main()
