"""PR 257 review v1 follow-ups (goodqa#16117).

F1: /api/state and every stream message carry one ordering: a per-process generation and the hub revision. The page
replays an update it held during a state load only when it is newer than the installed snapshot and from the same
process (harness/mission_control/web/tests/resync-freshness.test.mjs). Here: the server side of that stamp.

F2: a failed os.stat of the initiatives file is retried. After a good read, a metadata failure (the parent directory
not traversable) and its recovery leave inode, size and mtime unchanged, so the file must be read again rather than
the cached error repeated for ever.
"""

import io
import json
import os
import re
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_mission_control import ServerHarness, mcs  # noqa: E402
from test_mission_control_producer_reads import col, ev, safeio  # noqa: E402


class StreamStamp(unittest.TestCase):
    def test_each_hub_has_its_own_random_generation(self):
        a, b = ev.Hub(), ev.Hub()
        self.assertTrue(re.fullmatch(r"[0-9a-f]{16}", getattr(a, "generation", "")), "a hub has a hex generation")
        self.assertNotEqual(a.generation, b.generation, "a restarted process must not reuse the old generation")

    def test_a_frame_id_is_generation_dot_revision(self):
        hub = ev.Hub()
        client = hub.attach()
        hub.snapshot("owners", [])
        frame = client.take(0)[0].decode()
        self.assertIn(f"id: {getattr(hub, 'generation', '?')}.{hub.seq}\n", frame)

    def test_position_is_read_under_the_lock(self):
        hub = ev.Hub()
        hub.snapshot("owners", [])
        self.assertEqual(hub.position(), {"generation": hub.generation, "revision": 1})

    def test_resume_after_accepts_only_this_generation(self):
        hub = ev.Hub()
        resume = getattr(ev, "resume_after", None)
        self.assertIsNotNone(resume, "the Last-Event-ID parser exists")
        self.assertEqual(resume(f"{hub.generation}.7", hub.generation), 7)
        self.assertEqual(resume("0123456789abcdef.7", hub.generation), 0, "another process's revision means nothing here")
        for value in ("7", "", None, f"{hub.generation}.x", f"{hub.generation}.-1", f"{hub.generation}.7.1", "a.b.c"):
            with self.subTest(value=value):
                self.assertEqual(resume(value, hub.generation), 0)


class StateCarriesTheStamp(ServerHarness):
    # review v4 F7: the snapshot must hold exactly what was broadcast up to its stamp. A dataset newer than the stamp
    # is overwritten by an older frame above the stamp; one older than it is never corrected by a frame at or below it.
    def frames(self, client):
        out = []
        for raw in client.take(0) or []:
            head, _, rest = raw.decode().partition("\nevent: ")
            name, _, body = rest.partition("\ndata: ")
            out.append((int(head.split(".")[-1]), name, json.loads(body)))
        return out

    def assert_matches_broadcast(self, state, frames, names=("owners", "reads", "health", "initiatives", "asks", "ledger", "chat")):
        revision = state["stream"]["revision"]
        for name in names:
            sent = [data for seq, frame_name, data in frames if frame_name == name and seq <= revision]
            if sent:
                self.assertEqual(state[name], sent[-1], f"{name}: the snapshot is not the last {name} frame at or below its stamp {revision}")

    def publish_owners(self, n):
        rows = [{"id": f"row-{n}"}]
        self.app.owners.rows = rows
        self.app.hub.snapshot("owners", rows)

    def test_updates_published_while_the_state_is_collected_match_its_stamp(self):
        client = self.app.hub.attach()
        client.maxlen = 10 ** 6
        self.publish_owners(1)
        real = self.app.initiatives.snapshot

        def collect_while_publishing(*args, **kwargs):  # two owners updates land while the state is being collected
            self.publish_owners(2)
            self.publish_owners(3)
            return real(*args, **kwargs)

        with mock.patch.object(self.app.initiatives, "snapshot", collect_while_publishing):
            state = self.app.state()
        self.assertIn("stream", state)
        self.assert_matches_broadcast(state, self.frames(client))

    def test_concurrent_publishes_never_give_a_snapshot_newer_or_older_than_its_stamp(self):
        client = self.app.hub.attach()
        client.maxlen = 10 ** 6
        self.publish_owners(0)
        stop = threading.Event()

        def publisher():
            n = 1
            while not stop.is_set() and n < 20000:
                self.publish_owners(n)
                n += 1

        thread = threading.Thread(target=publisher, daemon=True)
        thread.start()
        try:
            states = [self.app.state() for _ in range(60)]
        finally:
            stop.set()
            thread.join(10)
        frames = self.frames(client)
        for state in states:
            self.assert_matches_broadcast(state, frames, names=("owners",))

    def test_the_served_state_has_the_stamp(self):
        cookie, _ = self.login()
        resp, data = self.request("GET", "/api/state", {"Cookie": cookie, "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(resp.status, 200)
        body = json.loads(data)
        self.assertEqual(body.get("stream", {}).get("generation"), self.app.hub.generation)
        self.assertIsInstance(body["stream"]["revision"], int)


class ChatSnapshotFailureRetries(ServerHarness):
    """Sweep for F2's shape: refresh_chat cached the chat store's signature before building the snapshot, so a build
    that raised left an unchanged store never published again (and the next tick reported the chat read ok)."""

    def test_a_failed_chat_snapshot_is_built_again_with_an_unchanged_store(self):
        self.app.refresh_chat()
        self.assertIn("chat", self.app.hub.snapshots)
        self.app.hub.snapshots.pop("chat")
        self.app.chat_sig = None  # the store changes once: the next refresh must build a snapshot
        calls = []
        real = self.app.chat_snapshot

        def flaky():
            calls.append(1)
            if len(calls) == 1:
                raise OSError("chat state briefly unreadable")
            return real()

        with mock.patch.object(self.app, "chat_snapshot", flaky):
            with self.assertRaises(OSError):
                self.app.refresh_chat()
            self.assertNotIn("chat", self.app.hub.snapshots)
            self.app.refresh_chat()  # nothing in the store changed since the failure
        self.assertEqual(len(calls), 2, "the snapshot that raised is built again")
        self.assertIn("chat", self.app.hub.snapshots)


class ReconnectReplay(unittest.TestCase):
    """A browser reconnect sends Last-Event-ID; the ring is replayed only for an id from this process."""

    def run_stream(self, last_event_id):
        hub = ev.Hub(max_rate=10_000)
        for n in range(3):
            hub.publish(ev.make("system", "test", f"event {n}", eid=f"e:{n}"))
        stop = threading.Event()
        sink = io.BytesIO()
        real_attach = hub.attach

        def attach():
            client = real_attach()
            client.take = lambda timeout: (stop.set(), None)[1]
            return client

        hub.attach = attach
        auth = SimpleNamespace(session=lambda cookie, touch=False: ("sid", {}))
        h = SimpleNamespace(app=SimpleNamespace(auth=auth, hub=hub, stop=stop),
                            headers={"Last-Event-ID": last_event_id(hub)},
                            connection=SimpleNamespace(settimeout=lambda value: None), wfile=sink,
                            send_response=lambda status: None, send_header=lambda *a: None, end_headers=lambda: None,
                            deny=lambda status, reason: None, close_connection=False)
        mcs.Handler.stream(h, "sid")
        return sink.getvalue().decode()

    def test_same_generation_resumes_after_the_id(self):
        out = self.run_stream(lambda hub: f"{hub.generation}.1")
        self.assertNotIn("event 0", out)
        self.assertIn("event 1", out)
        self.assertIn("event 2", out)

    def test_another_generation_or_a_bare_number_replays_nothing(self):
        for header in (lambda hub: "0123456789abcdef.1", lambda hub: "1"):
            with self.subTest():
                self.assertNotIn("event", self.run_stream(header))


class InitiativesMetadataFailureRecovers(unittest.TestCase):
    def setUp(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory(prefix="mc-16117-stat-")
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve() / "inner"
        self.dir.mkdir()
        self.path = self.dir / "initiatives.json"
        self.path.write_text(json.dumps([{"id": "leads", "initiative": "Leads", "state": "At risk"}]))
        self.hub = ev.Hub(max_rate=10_000)
        self.health = col.Health(self.hub)
        real = safeio.Reader([self.dir])
        self.reads = []

        class Counting:
            def read(inner, path, limit):
                self.reads.append(path)
                return real.read(path, limit)

        self.source = col.Initiatives(self.hub, self.health, Counting(), self.path)

    def signature(self):
        info = os.stat(self.path)
        return info.st_ino, info.st_size, info.st_mtime_ns

    def assert_recovered(self, sig):
        self.assertEqual(self.signature(), sig, "the file did not change")
        self.assertEqual(len(self.reads), 2, "the unchanged file is read again after the metadata failure")
        self.assertEqual(self.health.rows["initiatives"]["status"], "ok")
        self.assertEqual((self.source.stale, self.source.error, [i["id"] for i in self.source.items]), (False, "", ["leads"]))
        self.assertNotIn("initiative", [e["kind"] for e in self.hub.recent()], "a recovery of the same file is no update")

    def test_a_stat_failure_then_recovery_reads_again(self):
        self.source.run(time.time())
        self.assertEqual((self.health.rows["initiatives"]["status"], len(self.reads)), ("ok", 1))
        sig = self.signature()
        real_stat = os.stat

        def denied(path, *args, **kwargs):
            if Path(path) == self.path:
                raise PermissionError(13, "Permission denied")
            return real_stat(path, *args, **kwargs)

        with mock.patch.object(col.os, "stat", denied):
            self.source.run(time.time() + 3)
        self.assertEqual(self.health.rows["initiatives"]["status"], "error")
        self.assertTrue(self.source.stale)
        self.source.run(time.time() + 6)
        self.assert_recovered(sig)

    @unittest.skipIf(os.geteuid() == 0, "chmod cannot take a directory away from root")
    def test_parent_directory_not_traversable_then_restored(self):
        self.source.run(time.time())
        self.assertEqual(len(self.reads), 1)
        sig = self.signature()
        os.chmod(self.dir, 0)
        self.addCleanup(os.chmod, self.dir, 0o700)  # runs before the tempdir cleanup
        self.source.run(time.time() + 3)
        self.assertEqual(self.health.rows["initiatives"]["status"], "error")
        os.chmod(self.dir, 0o700)
        self.source.run(time.time() + 6)
        self.assert_recovered(sig)

    def test_a_change_during_the_outage_is_still_an_update(self):  # control: read_failed keeps the old signature
        self.source.run(time.time())
        with mock.patch.object(col.os, "stat", side_effect=PermissionError(13, "Permission denied")):
            self.source.run(time.time() + 3)
        self.path.write_text(json.dumps([{"id": "leads", "initiative": "Leads"}, {"id": "b", "initiative": "B"}]))
        self.source.run(time.time() + 6)
        self.assertEqual([i["id"] for i in self.source.items], ["leads", "b"])
        self.assertIn("initiative", [e["kind"] for e in self.hub.recent()])


if __name__ == "__main__":
    unittest.main()
