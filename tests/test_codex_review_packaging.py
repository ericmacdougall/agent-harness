"""Exercise review helpers from a real disposable Codex installation."""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

import install_codex


ROOT = Path(__file__).resolve().parents[1]
REVIEW_FILES = ('peer_review.py', 'review_diagnostics.py', 'review_policy.json',
                'resource_budget.py', 'kimi_review.py')

BOOTSTRAP = r'''
import importlib, json, os, pathlib, runpy, sys
home, artifacts = map(pathlib.Path, sys.argv[1:3])
operation, arguments = sys.argv[3], sys.argv[4:]
sys.path.insert(0, str(artifacts))
allowed_reads = (home.resolve(), pathlib.Path(sys.base_prefix).resolve())

def contained(path, roots):
    return any(path == root or root in path.parents for root in roots)

def audit(event, args):
    if event in {'subprocess.Popen', 'os.system', 'socket.connect', 'socket.getaddrinfo'}:
        raise AssertionError('unexpected external execution or network access')
    if event == 'open' and not isinstance(args[0], int):
        path = pathlib.Path(os.fsdecode(args[0])).resolve()
        mode, flags = args[1:3]
        writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        if writing and not contained(path, (home.resolve(),)):
            raise AssertionError('write outside disposable home')
        if not contained(path, allowed_reads):
            raise AssertionError('read outside copied artifacts and interpreter')

sys.addaudithook(audit)

if operation == 'origins':
    modules = {name: importlib.import_module(name) for name in arguments}
    for module in modules.values():
        assert pathlib.Path(module.__file__).resolve().parent == artifacts.resolve()
    print(json.dumps({name: pathlib.Path(module.__file__).name for name, module in modules.items()}))
elif operation == 'help':
    sys.argv = [str(artifacts / arguments[0]), *arguments[1:]]
    runpy.run_path(sys.argv[0], run_name='__main__')
elif operation == 'task-parse':
    import ah
    args = ah.build_parser().parse_args([
        'task', 'register', '--task', 'fixture', '--owner-agent', 'fixture-owner',
        '--scope', 'synthetic parser only', '--ticket', 'GoodQA harness#1',
        '--source', 'inferred:synthetic fixture',
    ])
    assert args.cmd == 'task' and args.sub == 'register' and args.task == 'fixture'
    print('parsed without registration')
elif operation == 'wal':
    import wal, wal_note
    path = home / '.agent-harness' / 'codex-wals' / 'fixture-session' / 'main.jsonl'
    wal_note.append(path, {'event': 'check', 'note': 'synthetic fixture'})
    assert json.loads(path.read_text()) == {'event': 'check', 'note': 'synthetic fixture'}
    assert pathlib.Path(wal.__file__).parent == artifacts
    print('native WAL append observed')
elif operation == 'lint':
    import provenance, spec_flow
    ticket_queries = []
    def synthetic_ticket(project, number):
        ticket_queries.append((project, number))
        assert (project, number) == ('harness', 1)
        return 'found', 'Synthetic fixture ticket'
    provenance.TICKET_LOOKUP = synthetic_ticket
    result = spec_flow.main(['lint', arguments[0], '--repo', str(home / 'empty-cwd')])
    assert ticket_queries or provenance.ticket_cache().get('harness#1', {}).get('title') == 'Synthetic fixture ticket'
    assert pathlib.Path(sys.modules['resource_budget'].__file__).resolve().parent == artifacts.resolve()
    sys.exit(result)
else:
    raise AssertionError('unknown fixed test operation')
'''


@unittest.skipUnless(install_codex.tomllib is not None, 'installer requires Python3.11+')
class CopiedCodexReviewHelpers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='codex-review-package-')
        cls.home = Path(cls.temporary.name)
        cls.cwd = cls.home / 'empty-cwd'
        cls.cwd.mkdir()
        codex = cls.home / '.codex'
        codex.mkdir()
        cls.sentinels = {name: ('fixture preserve ' + name).encode()
                         for name in ('AGENTS.md', 'config.toml', 'hooks.json')}
        for name, value in cls.sentinels.items():
            (codex / name).write_bytes(value)
        install_codex.install(cls.home, apply=True, hooks_only=True)
        cls.artifacts = codex / 'agent-harness'
        cls.spec = cls.home / 'spec.md'
        cls.spec.write_text(textwrap.dedent(f'''\
            # Spec: Copied artifact availability

            Ticket: GoodQA harness#1
            Author: agent:fixture (claude-opus-5-5)
            Click-test: not-applicable (synthetic command-line fixture only)
            Sign-off: main

            ## Outcome
            Copied helper modules support a complete synthetic spec.
            ## Scope
            - In: local fixture command-line entry points.
            - Out: external execution.
            ## Acceptance criteria
            - AC-1: the copied artifact lints the synthetic spec. Verify by: this focused copied-artifact check.
              Source: ticket:GoodQA harness#1
            ## Negative cases
            - NEG-1 (AC-1): missing criteria fail lint.
              Source: ticket:GoodQA harness#1
            ## Resource budget
            Host: vm:fixture
            Capacity: fixture VM, 8 GB memory, 4 cores, 50 GB disk
            Fan-out: agents=1 jobs=1 processes=2 browser_pages=0 test_workers=1
            Peak memory: 1 GB (method: synthetic fixture)
            CPU: 1 cores (method: synthetic fixture)
            Disk: 1 GB (method: synthetic fixture)
            Network: 1 MB (method: synthetic fixture)
            Wall time: 1 min
            Cap and kill: no background job is started by this fixture
            Checkpoint: synthetic local result
            ## Risks
            - A missing copied module prevents command execution.
        '''))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def child(self, operation, *args):
        environment = {
            'HOME': str(self.home), 'PATH': os.defpath, 'LANG': 'C.UTF-8',
            'PYTHONDONTWRITEBYTECODE': '1',
        }
        return subprocess.run([
            sys.executable, '-B', '-c', BOOTSTRAP, str(self.home), str(self.artifacts),
            operation, *args,
        ], cwd=self.cwd, env=environment, capture_output=True, text=True, timeout=10)

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_installed_files_match_sources_and_preserve_native_mapping(self):
        for name in (*REVIEW_FILES, 'wal_note.py', 'native_context.py',
                     'native_user_source.py', 'native_admission.py'):
            with self.subTest(name=name):
                self.assertTrue((self.artifacts / name).is_file(), name)
                self.assertEqual((self.artifacts / name).read_bytes(),
                                 (ROOT / 'harness' / 'hooks' / name).read_bytes())
        self.assertEqual((self.artifacts / 'wal.py').read_bytes(),
                         (ROOT / 'codex' / 'hooks' / 'wal.py').read_bytes())
        for name, value in self.sentinels.items():
            self.assertEqual((self.home / '.codex' / name).read_bytes(), value)

    def test_help_and_imports_use_copied_files_without_effects(self):
        self.assert_ok(self.child('origins', 'peer_review', 'review_diagnostics',
                                  'resource_budget', 'kimi_review', 'wal_note'))
        for script, args in (
            ('peer_review.py', ('--help',)), ('resource_budget.py', ('--help',)),
            ('wal_note.py', ('--help',)), ('kimi_review.py', ('--help',)),
            ('ah.py', ('task', 'register', '--help')),
        ):
            with self.subTest(script=script):
                result = self.child('help', script, *args)
                self.assert_ok(result)
                self.assertIn('usage:', result.stdout.lower())

    def test_register_parser_and_native_wal_append(self):
        self.assert_ok(self.child('task-parse'))
        self.assert_ok(self.child('wal'))

    def test_ordinary_spec_lint_runs_copied_resource_gate(self):
        result = self.child('lint', str(self.spec))
        self.assert_ok(result)
        self.assertEqual(json.loads(result.stdout)['status'], 'PASS')
        broken = self.home / 'broken-spec.md'
        broken.write_text(self.spec.read_text().replace('- AC-1:', '- UNUSED-1:'))
        result = self.child('lint', str(broken))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['status'], 'FAIL')

    def test_removing_copied_dependency_cannot_fall_back_to_source(self):
        path = self.artifacts / 'review_diagnostics.py'
        if not path.exists():
            self.fail('baseline did not package review_diagnostics.py')
        retained = path.read_bytes()
        path.unlink()
        try:
            result = self.child('origins', 'peer_review')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('ModuleNotFoundError', result.stderr)
        finally:
            path.write_bytes(retained)
