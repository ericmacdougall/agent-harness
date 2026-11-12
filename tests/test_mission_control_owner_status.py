"""Supervised owner visibility, independent of Claude owner discovery (GoodQA #15585)."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'harness' / 'hooks'))
sys.path.insert(0, str(REPO / 'harness' / 'mission_control'))
import collectors as col
import events as ev
import safeio


class SupervisedOwners(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve() / 'owners'  # macOS: /var is a link to /private/var
        self.root.mkdir()
        self.hub = ev.Hub()
        self.health = col.Health(self.hub)

    def write(self, name='mission-control', **changes):
        row = dict(name=name, harness='openai', model='gpt-6.1-sol', stream='mission-control',
                   ticket='goodqa#15585', state='running', supervisor_pid=123, thread='thread-a',
                   last_activity='2026-11-10T03:00:00Z', last_reply='A measured reply', last_status='WORKING')
        row.update(changes)
        folder = self.root / name
        folder.mkdir(exist_ok=True)
        (folder / 'status.json').write_text(json.dumps(row))
        return folder

    def collector(self):
        return col.SupervisedOwners(self.hub, self.health, safeio.Reader([self.root]), self.root,
                                    alive=lambda pid: pid == 123)

    def test_unchanged_status_is_not_republished_every_tick(self):  # mc-perf: was an owners snapshot every 2 s
        self.write()
        seen = []
        c = col.SupervisedOwners(self.hub, self.health, safeio.Reader([self.root]), self.root,
                                 alive=lambda pid: pid == 123, on_change=lambda: seen.append(1))
        for now in (1, 3, 5, 7):
            c.run(now)
        self.assertEqual(len(seen), 1, "four ticks over an unchanged status publish once")
        self.write(last_reply='A newer reply')
        c.run(9)
        self.assertEqual((len(seen), c.rows[0]['last_reply']), (2, 'A newer reply'))
        c.alive = lambda pid: False  # the supervisor died: same file, different state
        c.run(11)
        self.assertEqual((len(seen), c.rows[0]['state']), (3, 'offline'))
        c.run(13)
        self.assertEqual(len(seen), 3)

    def test_a_wal_line_alone_republishes_within_a_cycle(self):  # r1 F2: status file unchanged, WAL moved
        self.write()
        seen = []
        tailer = type('Tailer', (), {})()
        tailer.last_items = {('codex', 'thread-a', 'main'): {'at': '2026-11-10T03:00:00Z', 'event': 'note', 'note': 'x',
                                                             'active_at': '2026-11-10T03:00:00Z'}}
        c = col.SupervisedOwners(self.hub, self.health, safeio.Reader([self.root]), self.root,
                                 alive=lambda pid: pid == 123, on_change=lambda: seen.append(1))
        c.tailer = tailer
        c.run(1); c.run(3)
        self.assertEqual(len(seen), 1)
        tailer.last_items[('codex', 'thread-a', 'main')] = dict(
            tailer.last_items[('codex', 'thread-a', 'main')], progress_at='2026-11-10T03:05:00Z')
        c.run(5)
        self.assertEqual(len(seen), 2, "new progress on the supervised thread publishes on the next 2 s tick")
        tailer.last_items[('codex', 'thread-a', 'main')] = dict(
            tailer.last_items[('codex', 'thread-a', 'main')], active_at='2026-11-10T03:06:00Z')
        c.run(7)
        self.assertEqual(len(seen), 3, "new activity publishes too")
        tailer.last_items[('codex', 'thread-other', 'main')] = {'at': '2026-11-10T04:00:00Z', 'active_at': '2026-11-10T04:00:00Z'}
        c.run(9)
        self.assertEqual(len(seen), 3, "a WAL line on a thread nobody supervises is not a reason to publish")

    def test_parsed_cache_drops_owners_that_are_gone(self):  # r1 F3
        import shutil
        self.write('mission-control'); gone = self.write('old-owner')
        c = self.collector(); c.run(1)
        self.assertEqual(set(c.parsed), {'mission-control', 'old-owner'})
        shutil.rmtree(gone)
        c.run(3)
        self.assertEqual([r['name'] for r in c.rows], ['mission-control'])
        self.assertEqual(set(c.parsed), {'mission-control'})

    def test_named_owner_fields_and_live_state(self):
        self.write()
        c = self.collector(); c.run(1)
        self.assertEqual(len(c.rows), 1)
        r = c.rows[0]
        self.assertEqual((r['agent_id'], r['harness'], r['model'], r['stream'], r['state']),
                         ('openai:mission-control', 'openai', 'gpt-6.1-sol', 'mission-control', 'live'))
        self.assertEqual((r['ticket'], r['last_reply'], r['thread']), ('goodqa#15585', 'A measured reply', 'thread-a'))
        self.assertNotIn('supervisor_pid', r)
        self.assertNotIn('dir', r)

    def test_idle_blocked_stopped_and_dead_are_distinct(self):
        self.write('waiting', state='idle', last_status='WAITING')
        self.write('blocked', state='idle', last_status='BLOCKED')
        self.write('stopped', state='stopped', supervisor_pid=None)
        self.write('dead', supervisor_pid=456)
        c = self.collector(); c.run(1)
        self.assertEqual({r['name']: r['state'] for r in c.rows},
                         dict(waiting='waiting', blocked='blocked', stopped='stopped', dead='offline'))

    def test_bad_snapshot_retains_visibly_stale_rows_then_recovers(self):
        folder = self.write(); c = self.collector(); c.run(1)
        (folder / 'status.json').write_text('{incomplete')
        c.run(2)
        self.assertEqual(c.rows[0]['name'], 'mission-control')
        self.assertTrue(c.rows[0]['source_stale'])
        self.assertEqual(self.health.rows['codex-owners']['status'], 'error')
        self.write(last_reply='Recovered'); c.run(3)
        self.assertFalse(c.rows[0]['source_stale'])
        self.assertEqual(c.rows[0]['last_reply'], 'Recovered')

    def test_symlink_root_directory_status_and_fifo_are_refused_without_blocking(self):
        folder = self.write(); c = self.collector(); c.run(1)
        status = folder / 'status.json'; status.rename(folder / 'saved.json')
        status.symlink_to(folder / 'saved.json'); c.run(2)
        self.assertTrue(c.rows[0]['source_stale'])
        status.unlink(); os.mkfifo(status); c.run(3)
        self.assertTrue(c.rows[0]['source_stale'])
        status.unlink(); (folder / 'saved.json').rename(status)
        folder.rename(self.root / 'saved'); folder.symlink_to(self.root / 'saved', target_is_directory=True)
        c.run(4); self.assertTrue(c.rows[0]['source_stale'])
        alias = self.root.parent / 'alias'; alias.symlink_to(self.root, target_is_directory=True)
        c = col.SupervisedOwners(self.hub, self.health, safeio.Reader([alias]), alias)
        c.run(5); self.assertEqual(c.rows, [])
        self.assertEqual(self.health.rows['codex-owners']['status'], 'error')

    def test_oversize_wrong_identity_and_missing_source_are_errors(self):
        folder = self.write(); c = self.collector(); c.run(1)
        (folder / 'status.json').write_text(' ' * (65536 + 1)); c.run(2)
        self.assertTrue(c.rows[0]['source_stale'])
        self.write(name='mission-control'); d=json.loads((folder/'status.json').read_text())
        d['name']='other'; (folder/'status.json').write_text(json.dumps(d)); c.run(3)
        self.assertTrue(c.rows[0]['source_stale'])
        self.root.rename(self.root.parent/'gone'); c.run(4)
        self.assertEqual(self.health.rows['codex-owners']['status'], 'error')
        self.assertEqual(len(c.rows), 1)

    def test_empty_source_is_success_and_replies_are_redacted(self):
        c=self.collector(); c.run(1)
        self.assertEqual(c.rows, [])
        self.assertEqual(self.health.rows['codex-owners']['status'], 'ok')
        token='gh'+'p_'+'Z9y8X7w6V5u4T3s2R1q0P9o8N7m6'
        self.write(last_reply='token '+token); c.run(2)
        self.assertNotIn(token, c.rows[0]['last_reply'])

    def test_claude_failure_does_not_hide_supervised_owner_or_publish_duplicates(self):
        self.write(); managed=self.collector(); managed.run(1)
        runner=mock.Mock(); runner.run.return_value=(4,'{}')
        owners=col.Owners(self.hub,self.health,runner,None)
        owners.supervised=managed; managed.on_change=owners.publish
        owners.run(2)
        managed.run(3)
        self.assertEqual([r['agent_id'] for r in owners.rows], ['openai:mission-control'])
        self.assertEqual(self.health.rows['owners']['status'],'error')
        self.assertEqual(self.health.rows['codex-owners']['status'],'ok')


    def test_scan_budget_and_healthy_removal(self):
        self.write(); c=self.collector(); c.run(1)
        (self.root/'mission-control'/'status.json').unlink()
        (self.root/'mission-control').rmdir(); c.run(2)
        self.assertEqual(c.rows, [])
        for n in range(129): (self.root/f'owner-{n}').mkdir()
        c.run(3)
        self.assertEqual(self.health.rows['codex-owners']['status'], 'error')

    def test_wal_thread_is_not_duplicated_by_named_supervisor(self):
        self.write(); c=self.collector(); c.run(1)
        tailer=mock.Mock()
        tailer.last_items={('codex','thread-a','main'):{'at':'2026-11-10T03:00:00Z'},
                           ('codex','unmanaged','main'):{'at':'2026-11-10T02:00:00Z'}}
        owners=col.Owners(self.hub,self.health,mock.Mock(),tailer)
        owners.supervised=c; owners.publish()
        self.assertEqual([r['agent_id'] for r in owners.rows], ['openai:mission-control','codex:unmanaged:main'])

    def test_named_supervisor_preserves_wal_progress_for_at_risk(self):
        self.write(); c=self.collector(); c.run(1)
        tailer=mock.Mock()
        tailer.last_items={('codex','thread-a','main'):{'at':'2026-11-10T02:59:00Z', 'note':'next step',
                            'progress_at':'2026-11-10T02:58:00Z', 'progress_event':'check',
                            'progress_note':'REALLY_TESTED fixture passed'}}
        owners=col.Owners(self.hub,self.health,mock.Mock(),tailer)
        owners.supervised=c; owners.publish()
        self.assertEqual(owners.rows[0]['last_item']['progress_at'], '2026-11-10T02:58:00Z')
        self.assertEqual(owners.rows[0]['last_item']['note'], 'next step')
        self.assertEqual(owners.rows[0]['last_item']['active_at'], '2026-11-10T03:00:00Z')
        self.assertNotIn('progress_at', c.rows[0]['last_item'], 'do not mutate the raw supervisor snapshot')

    def test_claude_snapshot_retained_on_failure_is_visibly_stale_and_recovers(self):
        runner=mock.Mock(); runner.run.return_value=(0,json.dumps({'session':'main-sess','owners':[
            {'agent_id':'claude123','state':'live','model':'recorded-model','task':'work'}]}))
        owners=col.Owners(self.hub,self.health,runner,None); owners.run(1)
        runner.run.return_value=(4,'{}'); owners.run(2)
        self.assertTrue(owners.rows[0].get('source_stale'))
        self.assertEqual(owners.rows[0]['model'], 'recorded-model')
        runner.run.return_value=(0,'{}'); owners.run(2.5)
        self.assertEqual(len(owners.rows),1)
        self.assertTrue(owners.rows[0].get('source_stale'))
        runner.run.return_value=(0,json.dumps({'session':'main-sess','owners':[
            {'agent_id':'claude123','state':'live'}]})); owners.run(3)
        self.assertFalse(owners.rows[0].get('source_stale',False))

    def test_known_owner_missing_status_is_stale_but_unprovisioned_directory_is_not_an_owner(self):
        (self.root/'unprovisioned').mkdir()
        folder=self.write(); c=self.collector(); c.run(1)
        self.assertEqual(len(c.rows),1)
        (folder/'status.json').rename(folder/'preserved.json'); c.run(2)
        self.assertEqual(len(c.rows),1)
        self.assertTrue(c.rows[0]['source_stale'])
        self.assertEqual(self.health.rows['codex-owners']['status'],'error')

    def test_tool_activity_does_not_retimestamp_last_reply(self):
        self.write(turn_ended='2026-11-10T02:00:00Z',last_activity='2026-11-10T03:00:00Z')
        c=self.collector(); c.run(1)
        self.assertEqual(c.rows[0]['last_item']['at'],'2026-11-10T02:00:00Z')
        self.assertEqual(c.rows[0]['last_item']['active_at'],'2026-11-10T03:00:00Z')


if __name__ == '__main__': unittest.main()
