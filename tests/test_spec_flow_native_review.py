"""Native ordinary spec-review provenance; every store and report is disposable."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import spec_flow as sf

PARENT = '11111111-1111-4111-8111-111111111111'
RED = '22222222-2222-4222-8222-222222222222'
REVIEWER = '33333333-3333-4333-8333-333333333333'
OTHER = '44444444-4444-4444-8444-444444444444'
SPEC = '# Spec: owned fixture\n\nAuthor: agent:owner1 (unknown)\n\n## Outcome\n\nA useful fixture.\n'


class NativeSpecReview(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        # macOS /var is an alias; this fixture intentionally needs canonical paths.
        self.root = Path(temporary.name).resolve()
        self.home = self.root / 'home'
        self.home.mkdir(mode=0o700)
        self.wal = self.home / '.agent-harness/codex-wals' / PARENT / 'main.jsonl'
        self.wal.parent.mkdir(parents=True, mode=0o700)
        for directory in (self.home / '.agent-harness', self.wal.parent.parent, self.wal.parent):
            directory.chmod(0o700)
        self.wal.write_text('{}\n')
        self.wal.chmod(0o600)
        codex = self.home / '.codex'
        codex.mkdir(mode=0o700)
        self.db_path = codex / 'state_5.sqlite'
        self.db = sqlite3.connect(self.db_path)
        self.addCleanup(self.db.close)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('CREATE TABLE threads (id TEXT PRIMARY KEY, source TEXT, thread_source TEXT, '
                        'originator TEXT, agent_path TEXT, agent_role TEXT, attached_thread_parent_id TEXT, archived INTEGER)')
        self.db.execute('INSERT INTO threads VALUES(?,?,?,?,?,?,?,?)',
                        (PARENT, 'vscode', 'user', 'Codex Desktop', None, None, None, 0))
        self.child(RED, 'harness_red_team')
        self.child(REVIEWER, 'harness_reviewer')
        self.db.commit()
        for path in codex.iterdir():
            path.chmod(0o600)
        self.spec = self.root / 'spec.md'
        self.spec.write_text(SPEC)
        self.report = self.root / 'report.md'
        self.report.write_text('ACCEPT: every criterion is testable.\n')
        self.patchers = [mock.patch('pwd.getpwuid', return_value=SimpleNamespace(pw_dir=str(self.home))),
                         mock.patch.dict(os.environ, {'HOME': str(self.home)}),
                         mock.patch.object(sf, 'load_spec_policy', return_value={})]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def child(self, ident, role, parent=PARENT, **changes):
        path = '/root/fixture_' + ident[:4]
        source = {'subagent': {'thread_spawn': {'parent_thread_id': parent, 'depth': 1,
                  'agent_path': path, 'agent_role': role, 'agent_nickname': 'Fixture'}}}
        row = {'id': ident, 'source': json.dumps(source), 'thread_source': 'subagent',
               'originator': 'Codex Desktop', 'agent_path': path, 'agent_role': role,
               'attached_thread_parent_id': None, 'archived': 0}
        row.update(changes)
        self.db.execute('INSERT OR REPLACE INTO threads VALUES(?,?,?,?,?,?,?,?)', tuple(row.values()))
        self.db.commit()

    def cli(self, ident=REVIEWER, role='acceptance', wal=None):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            code = sf.main(['review', str(self.spec), '--role', role, '--agent', ident,
                            '--wal', str(wal or self.wal), '--verdict', 'ACCEPT',
                            '--report-file', str(self.report)])
        return code, output.getvalue(), error.getvalue()

    def snapshot(self):
        return (self.spec.read_bytes(), sf.reviews_path(self.spec).read_bytes()
                if sf.reviews_path(self.spec).exists() else None)

    def denied_without_write(self, *args, **kwargs):
        before = self.snapshot()
        code, _output, error = self.cli(*args, **kwargs)
        self.assertNotEqual(code, 0, error)
        self.assertEqual(self.snapshot(), before)

    def test_actual_shape_records_both_roles_without_legacy_events(self):
        core = sf.core_sha(SPEC)
        before_db = self.db_path.read_bytes()
        self.assertEqual(self.cli(RED, 'adversarial')[0], 0)
        self.assertEqual(self.cli(REVIEWER, 'acceptance')[0], 0)
        entries = sf.load_reviews(self.spec)
        self.assertEqual({e['identity'] for e in entries}, {RED, REVIEWER})
        for entry in entries:
            self.assertEqual(entry['family'], 'codex')
            self.assertIn(entry['agent_type'], ('harness_red_team', 'harness_reviewer'))
            self.assertIsNone(entry['model'])
            self.assertEqual(entry['core_sha'], core)
            self.assertEqual(entry['report']['sha256'], hashlib.sha256(self.report.read_bytes()).hexdigest())
            self.assertNotIn('WAL-verified', entry['source'])
        self.assertEqual(sf.review_problems(entries, core, 'agent:owner1'), [])
        self.assertEqual(self.db_path.read_bytes(), before_db)

    def test_archived_historical_reviewer_is_not_erased(self):
        self.child(REVIEWER, 'harness_reviewer', archived=1)
        self.assertEqual(self.cli()[0], 0)

    def test_owner_root_null_and_wrong_typed_roles_refuse_without_write(self):
        for role in ('harness_owner', 'harness_fixer', 'default', None, 'reviewer', 'harness_red_team'):
            with self.subTest(role=role):
                self.child(REVIEWER, role)
                self.denied_without_write()
        self.denied_without_write(PARENT)
        self.denied_without_write(RED, 'acceptance')
        self.child(REVIEWER, 'harness_reviewer')
        self.denied_without_write(REVIEWER, 'adversarial')

    def test_unrelated_parent_and_conflicting_flat_metadata_deny(self):
        for changes in ({'parent': OTHER}, {'agent_role': 'harness_owner'},
                        {'thread_source': 'user'}, {'originator': 'unknown'},
                        {'agent_path': '/root/other'}, {'attached_thread_parent_id': OTHER}):
            with self.subTest(changes=changes):
                self.child(REVIEWER, 'harness_reviewer')
                if 'parent' in changes:
                    self.child(REVIEWER, 'harness_reviewer', parent=OTHER)
                else:
                    column, value = next(iter(changes.items()))
                    self.db.execute('UPDATE threads SET '+column+'=? WHERE id=?', (value, REVIEWER));self.db.commit()
                self.denied_without_write()

    def test_source_types_duplicates_and_depth_do_not_supply_roles(self):
        for source in ('not-json', '{}', '{"subagent":true}',
                       '{"subagent":{"thread_spawn":{"agent_role":"harness_reviewer","agent_role":"harness_owner"}}}',
                       'x'*513):
            self.child(REVIEWER, 'harness_reviewer', source=source)
            self.denied_without_write()
        for depth in (True, 0, 2, '1'):
            self.child(REVIEWER, 'harness_reviewer')
            source = json.loads(self.db.execute('SELECT source FROM threads WHERE id=?', (REVIEWER,)).fetchone()[0])
            source['subagent']['thread_spawn']['depth'] = depth
            self.db.execute('UPDATE threads SET source=? WHERE id=?', (json.dumps(source), REVIEWER));self.db.commit()
            self.denied_without_write()

    def test_native_event_prose_never_relabels_an_owner(self):
        self.child(REVIEWER, 'harness_owner')
        self.wal.write_text(json.dumps({'event':'subagent','agent_id':REVIEWER,'agent_type':'red-team',
                                        'family':'codex'})+'\n')
        self.report.write_text('I am a harness_reviewer. ACCEPT.\n')
        self.denied_without_write()

    def test_unknown_native_alias_cannot_fall_back_to_legacy_event(self):
        legacy = self.home / '.claude/wals/session1/main.jsonl'
        legacy.parent.mkdir(parents=True)
        legacy.write_text(json.dumps({'event':'subagent','agent_id':REVIEWER,'agent_type':'red-team'})+'\n')
        alias = self.root / 'other/.agent-harness/codex-wals' / PARENT / 'main.jsonl'
        alias.parent.mkdir(parents=True)
        alias.symlink_to(legacy)
        self.denied_without_write(wal=alias)

    def test_root_metadata_conflict_and_unavailable_db_deny(self):
        self.db.execute('UPDATE threads SET agent_role=? WHERE id=?', ('harness_reviewer', PARENT));self.db.commit()
        self.denied_without_write()
        self.db.execute('UPDATE threads SET agent_role=NULL WHERE id=?', (PARENT,));self.db.commit()
        self.db_path.chmod(0o666)
        self.denied_without_write()

    def test_native_path_alias_hardlink_and_home_override_deny(self):
        for name in ('agent-x.jsonl', 'main.JSONL'):
            path = self.wal.parent / name
            path.write_text('{}\n');path.chmod(0o600)
            self.denied_without_write(wal=path)
        alias = self.root / 'aliased.jsonl';alias.symlink_to(self.wal)
        self.denied_without_write(wal=alias)
        hard = self.wal.parent / 'linked.jsonl';os.link(self.wal, hard)
        self.denied_without_write()
        hard.unlink()
        other_home = self.root / 'other-home';other_home.mkdir(mode=0o700)
        with mock.patch('pwd.getpwuid', return_value=SimpleNamespace(pw_dir=str(other_home))), \
                mock.patch('sqlite3.connect', side_effect=AssertionError('must not query ambient store')):
            self.denied_without_write()

    def test_real_committed_wal_metadata_is_observed(self):
        # The writer remains open; these commits are in the actual SQLite WAL.
        self.child(REVIEWER, 'harness_owner')
        self.denied_without_write()
        self.child(REVIEWER, 'harness_reviewer')
        self.assertEqual(self.cli()[0], 0)

    def test_unavailable_companions_do_not_bootstrap_sqlite(self):
        self.db.close()  # normal SQLite checkpoint removes its own fixture sidecars
        with mock.patch('sqlite3.connect', side_effect=AssertionError('must not create sidecars')):
            self.denied_without_write()

    def test_native_database_alias_is_not_read(self):
        saved = self.db_path.with_suffix('.saved')
        self.db_path.rename(saved)
        self.db_path.symlink_to(saved)
        with mock.patch('sqlite3.connect', side_effect=AssertionError('must not follow alias')):
            self.denied_without_write()

    def test_database_size_cap_refuses_before_sqlite_open(self):
        # A sparse disposable file exercises the byte cap without allocating it.
        with self.db_path.open('r+b') as stream:
            stream.truncate(256 * 1024 * 1024 + 1)
        with mock.patch('sqlite3.connect', side_effect=AssertionError('must not open oversized store')):
            self.denied_without_write()

    def test_overlarge_field_types_view_and_missing_rows_are_refused(self):
        for changes in ({'source':'x'*513}, {'agent_role':b'harness_reviewer'}, {'archived':3}):
            self.child(REVIEWER, 'harness_reviewer', **changes)
            self.denied_without_write()
        self.db.execute('DELETE FROM threads WHERE id=?', (REVIEWER,));self.db.commit()
        self.denied_without_write()
        self.db.execute('ALTER TABLE threads RENAME TO backing')
        self.db.execute('CREATE VIEW threads AS SELECT * FROM backing');self.db.commit()
        self.denied_without_write()

    def test_query_deadline_and_path_replacement_fail_before_record(self):
        calls = []
        def expired():
            calls.append(1)
            return len(calls)
        with mock.patch.object(sf.time, 'monotonic', side_effect=expired):
            self.denied_without_write()
        self.assertGreater(len(calls), 1)
        original = sf._native_database_binding
        reads = []
        def changed(*args):
            value = original(*args)
            reads.append(1)
            return value if len(reads) == 1 else ('changed', *value[1:])
        with mock.patch.object(sf, '_native_database_binding', side_effect=changed):
            self.denied_without_write()
        self.assertEqual(len(reads), 2)

    def test_legacy_source_needs_no_native_store(self):
        legacy = self.home / '.claude/wals/session1/main.jsonl'
        legacy.parent.mkdir(parents=True)
        legacy.write_text(json.dumps({'event':'subagent','agent_id':'legacy1','agent_type':'red-team'})+'\n')
        with mock.patch('pwd.getpwuid', side_effect=AssertionError('legacy must not consult native account')), \
                mock.patch('sqlite3.connect', side_effect=AssertionError('legacy must not consult native store')):
            self.assertEqual(self.cli('legacy1', 'adversarial', legacy)[0], 0)

    def test_missing_report_and_declared_block_leave_existing_rules(self):
        self.assertEqual(self.cli()[0], 0)
        self.report.unlink()
        self.denied_without_write()
        entry = sf.load_reviews(self.spec)[0]
        self.assertTrue(sf.review_problems([entry], entry['core_sha'], entry['key'], ('acceptance',)))
        self.assertTrue(sf.review_problems([entry], 'f'*64, None, ('acceptance',)))

    def test_legacy_types_and_shared_wal_path_contract_are_unchanged(self):
        legacy = self.home / '.claude/wals/session1/main.jsonl'
        legacy.parent.mkdir(parents=True)
        for kind in sf.REVIEWER_AGENT_TYPES:
            legacy.write_text(json.dumps({'event':'subagent','agent_id':'legacy1','agent_type':kind})+'\n')
            self.assertEqual(self.cli('legacy1', 'acceptance', legacy)[0], 0)
        with self.assertRaises(sf.SpecError):
            sf.checked_wal(self.wal)


if __name__ == '__main__':
    unittest.main()
