"""Production identity controls using native no-id WAL records, not invented event IDs."""
import json
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "harness/hooks"), str(ROOT / "harness/mission_control")]
import collectors as col
import events as ev
import safeio


class ProductionIdentity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.hub = ev.Hub(max_rate=1000)
        self.health = col.Health(self.hub)
        patcher = mock.patch.dict('os.environ', {'MC_HOME': str(self.base)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_native_no_id_records_and_identical_notes_keep_distinct_ids(self):
        root = self.base / "codex"
        path = root / "thread" / "main.jsonl"
        path.parent.mkdir(parents=True)
        path.write_text("")
        tailer = col.WalTailer(self.hub, self.health, safeio.Reader([root]), [(root, "codex")])
        tailer.tick(time.time())
        record = {"at": "2026-11-10T19:00:00Z", "event": "intent", "note": "ordinary work"}
        path.write_text((json.dumps(record) + "\n") * 2)
        tailer.tick(time.time())
        ids = [row["id"] for row in self.hub.recent()]
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(set(ids)), 2)

    def test_same_location_across_runtimes_has_distinct_identity(self):
        roots = [(self.base / "a", "claude"), (self.base / "b", "codex")]
        for root, _ in roots:
            p = root / "same" / "main.jsonl"
            p.parent.mkdir(parents=True)
            p.write_text("")
        tailer = col.WalTailer(self.hub, self.health, safeio.Reader([r for r, _ in roots]), roots)
        tailer.tick(time.time())
        for root, _ in roots:
            (root / "same/main.jsonl").write_text(json.dumps({"event": "intent", "note": "same"}) + "\n")
        tailer.tick(time.time())
        self.assertEqual(len({e["id"] for e in self.hub.recent()}), 2)

    def test_registry_codex_is_not_relabelled_claude(self):
        class Runner:
            def run(self, *args, **kwargs):
                return 0, json.dumps({"session": "main", "owners": [{"agent_id": "codex-worker",
                    "harness": "openai", "runtime": "codex", "thread": "thread", "state": "working"}]})
        owners = col.Owners(self.hub, self.health, Runner(), None)
        owners.tick(time.time())
        self.assertEqual(owners.rows[0]["runtime"], "codex")
        self.assertEqual(owners.rows[0]["harness"], "openai")

    def test_native_backgrounds_are_not_duplicate_thread_ids(self):
        class Tailer:
            last_items = {("codex", "thread", "main"): {"at": ev.iso(), "note": "main"},
                          ("codex", "thread", "background"): {"at": ev.iso(), "note": "background"}}
        owners = col.Owners(self.hub, self.health, None, Tailer())
        rows = owners.codex_rows(time.time())
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({r["agent_id"] for r in rows}), 2)

    def test_five_registered_projects_include_missing_and_stale_without_false_live(self):
        projects = [{'project': 'Project ' + str(i), 'thread_id': 'thread-000' + str(i)} for i in range(5)]
        (self.base / 'projects.json').write_text(json.dumps({'projects': projects}))
        class Tailer:
            last_items = {('codex', 'thread-0000', 'main'): {'at': ev.iso(), 'note': 'current'},
                          ('codex', 'thread-0001', 'main'): {'at': '2020-01-01T00:00:00Z', 'note': 'old'}}
        owners = col.Owners(self.hub, self.health, None, Tailer())
        rows = owners.codex_rows(time.time())
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(r['runtime'] == 'codex' for r in rows))
        self.assertEqual({r['state'] for r in rows}, {'observed', 'stale', 'unknown'})

    def test_failed_project_registry_keeps_named_rows_visibly_stale(self):
        (self.base / 'projects.json').write_text(json.dumps({'projects': [{'project': 'Project', 'thread_id': 'thread-0000'}]}))
        class Tailer:
            last_items = {('codex', 'thread-0000', 'main'): {'at': ev.iso(), 'note': 'current'}}
        owners = col.Owners(self.hub, self.health, None, Tailer())
        owners.codex_rows(time.time())
        (self.base / 'projects.json').write_text('{broken')
        row = owners.codex_rows(time.time())[0]
        self.assertEqual(row['name'], 'Project')
        self.assertTrue(row['source_stale'])

    def test_registry_main_and_two_workers_without_wals_remain_distinct(self):
        class Runner:
            def run(self, *args, **kwargs):
                return 0, json.dumps({'owners': [{'agent_id': worker, 'agent': worker, 'runtime': 'codex',
                    'thread': 'thread-0000', 'state': 'working'} for worker in ('main', 'worker-a', 'worker-b')]})
        owners = col.Owners(self.hub, self.health, Runner(), None)
        owners.tick(time.time())
        self.assertEqual({r['agent'] for r in owners.rows}, {'main', 'worker-a', 'worker-b'})

    def test_codex_registry_cannot_borrow_claude_wal_thread(self):
        class Runner:
            def run(self, *args, **kwargs):
                return 0, json.dumps({'owners': [{'agent_id': 'worker-a', 'runtime': 'codex', 'state': 'working'}]})
        class Tailer:
            last_items = {('claude', 'claude-thread', 'worker-a'): {'at': ev.iso()}}
            def last_for(self, *args):
                return self.last_items.get(args)
        owners = col.Owners(self.hub, self.health, Runner(), Tailer())
        owners.tick(time.time())
        self.assertEqual(owners.rows[0]['thread'], '')
        self.assertEqual(owners.rows[0]['agent'], 'worker-a')

    def test_native_app_observation_ttl_never_becomes_last_activity(self):
        class Tailer:
            last_items = {}
        now = 1794337200
        for delta, expected in ((0, 'observed'), (120, 'observed'), (121, 'stale'), (-1, 'unknown')):
            with self.subTest(delta=delta):
                value = {'schema': 'mc.native-project-observations/1', 'ttl_seconds': 120,
                    'observed_at_utc': ev.iso(now - delta), 'projects': [{'project': 'Project', 'thread_id': 'thread-0000',
                    'runtime': 'codex', 'provider': None, 'model': None, 'last_activity_at': None,
                    'observation_source': 'codex_app.wait_threads', 'native_status': {'type': 'active'}}]}
                (self.base / 'projects.json').write_text(json.dumps(value))
                row = col.Owners(self.hub, self.health, None, Tailer()).codex_rows(now)[0]
                self.assertEqual(row['state'], expected)
                self.assertFalse(row.get('last_activity'))
                self.assertFalse(row.get('model'))
