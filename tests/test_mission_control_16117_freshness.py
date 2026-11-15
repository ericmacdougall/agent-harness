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
