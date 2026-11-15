"""PR 234 review v12 follow-ups (goodqa#16117): F1 lost lines without the search term, F3 initiatives retry.

F1: the requirements and asks producers find their records by a needle ("requirement", "ask"). A line torn before
the needle, or a line that is not JSON at all, never reached their validator, so the read said ok with nothing
skipped. Each such line may have held the searched record, so it is counted as skipped; a torn last line written
inside the append grace is a write in progress and is not.

F3: the initiatives collector took the file signature before reading, so after a failed read an unchanged file was
never read again. Permissions restored, the same bytes and mtime: the next tick must read it and recover.
(F2, the reconnect resync ordering, is in harness/mission_control/web/tests/resync-order.test.mjs.)
"""

import json
import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_mission_control_producer_reads import OLD, SID, Home, ah, col, ev, prov, safeio  # noqa: E402

TORN = ('{"event":"a', '{"event":"req', "not-json")
# which producer each broken line can have belonged to: a torn leading event name counts only for the producers whose
# event it could still become; a line with no leading event (or not JSON at all) counts for every producer
LOST = {'{"event":"a': ("asks",), '{"event":"req': ("requirements",), "not-json": ("requirements", "asks"),
        '{"event":"': ("requirements", "asks"), '{"at":"2026-11-15T00:00:00Z","event":"as': ("requirements", "asks"),
        '{"event":"ask_res': ("asks",), '{"event":"result","note":"x': (), '{"event":"res': (),
        '{"event":"requirement_x","n': (), '{"event":"asking': ()}


class LostLinesWithoutTheNeedle(unittest.TestCase):
    def requirements(self, home):
        return ah.requirements_view(home.home, SID)["read"]

    def asks(self, home):
        return prov.ask_items(SID, home.home / ".claude")["read"]

    def check(self, text, end):
        home = Home(self)
        home.append(home.main, text + end, age=OLD)  # nobody has written it for 30 minutes
        for name, read in (("requirements", self.requirements(home)), ("asks", self.asks(home))):
            want = ("partial", 1) if name in LOST[text] else ("ok", 0)
            self.assertEqual((read["state"], read["skipped"]), want, (name, read))

    def test_a_complete_line_without_the_term_is_lost_to_each_producer_it_could_belong_to(self):
        for text in LOST:
            with self.subTest(line=text):
                self.check(text, "\n")

    def test_an_old_torn_tail_without_the_term_is_lost(self):
        for text in LOST:
            with self.subTest(line=text):
                self.check(text, "")  # unterminated

    def test_a_torn_agent_wal_line_is_lost_for_asks(self):
        home = Home(self)
        home.append(home.agent, '{"event":"a\n', age=OLD)
        self.assertEqual(self.asks(home)["state"], "partial")
        self.assertEqual(self.asks(home)["skipped"], 1)

    def test_a_fresh_torn_tail_is_a_write_in_progress(self):  # control: the append grace still holds
        for text in TORN:
            with self.subTest(line=text):
                home = Home(self)
                home.append(home.main, text)  # written now
                for name, read in (("requirements", self.requirements(home)), ("asks", self.asks(home))):
                    self.assertEqual((read["state"], read["skipped"]), ("ok", 0), (name, read))

    def test_valid_records_and_blank_lines_are_not_lost(self):  # control: no false loss
        home = Home(self)
        home.append(home.main, "\n" + json.dumps({"event": "note", "note": "x", "at": None}) + "\n\n", age=OLD)
        for read in (self.requirements(home), self.asks(home)):
            self.assertEqual((read["state"], read["skipped"]), ("ok", 0), read)

    def test_a_lost_line_holding_the_term_is_counted_once(self):  # the needle scan owns it; the integrity pass skips it
        # each producer's own torn line once; the other producer's torn line names another event, so it is not lost
        home = Home(self)
        home.append(home.main, '{"event":"requirement","id":\n{"event":"ask","id":\n', age=OLD)
        self.assertEqual(self.requirements(home)["skipped"], 1)
        self.assertEqual(self.asks(home)["skipped"], 1)
        for text, read in (('{"event":"requirement","id":\n', self.requirements), ('{"event":"ask","id":\n', self.asks)):
            home = Home(self)
            home.append(home.main, text, age=OLD)
            self.assertEqual(read(home)["skipped"], 1, text)

    def test_an_unreadable_wal_in_the_integrity_pass_is_unread_not_ok(self):
        home = Home(self)
        real = prov.lost_lines_without

        def refuse(path, needles):
            raise prov.Problem("file-unreadable", "cannot read main.jsonl (PermissionError)")
        prov.lost_lines_without = refuse
        self.addCleanup(setattr, prov, "lost_lines_without", real)
        for read in (self.requirements(home), self.asks(home)):
            self.assertNotEqual(read["state"], "ok", read)
            self.assertTrue(read["unread"], read)

    def test_the_integrity_pass_counts(self):
        home = Home(self)
        path = home.main
        home.append(path, "[1,2]\n7\n{\"ok\":1}\n" + "x" * 64 + "\n", age=OLD)
        self.assertEqual(prov.lost_lines_without(path, (b'"requirement"',)), 3)  # a list, a number, a non-JSON line


class InitiativesRecoverWithoutAChange(unittest.TestCase):
    def setUp(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory(prefix="mc-16117-")
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()
        self.path = self.dir / "initiatives.json"
        self.path.write_text(json.dumps([{"id": "leads", "initiative": "Leads", "state": "At risk"}]))
        self.hub = ev.Hub(max_rate=10_000)
        self.health = col.Health(self.hub)

    def test_a_refused_read_recovers_on_the_same_signature(self):
        real = safeio.Reader([self.dir])
        attempts = []

        class Flaky:
            def read(self, path, limit):
                attempts.append(path)
                if len(attempts) == 1:
                    raise safeio.Refused("permission denied")
                return real.read(path, limit)

        source = col.Initiatives(self.hub, self.health, Flaky(), self.path)
        before = os.stat(self.path)
        source.run(time.time())
        self.assertEqual(self.health.rows["initiatives"]["status"], "error")
        self.assertTrue(source.stale)
        source.run(time.time() + 3)
        after = os.stat(self.path)
        self.assertEqual((before.st_ino, before.st_size, before.st_mtime_ns), (after.st_ino, after.st_size, after.st_mtime_ns))
        self.assertEqual(len(attempts), 2, "the unchanged file is read again while its last read failed")
        self.assertEqual(self.health.rows["initiatives"]["status"], "ok")
        self.assertEqual((source.stale, source.error, [i["id"] for i in source.items]), (False, "", ["leads"]))
        self.assertNotIn("initiative", [e["kind"] for e in self.hub.recent()], "a recovery of the same file is no update")

    @unittest.skipIf(os.geteuid() == 0, "chmod cannot take a file away from root")
    def test_permission_restored_with_unchanged_contents(self):
        source = col.Initiatives(self.hub, self.health, safeio.Reader([self.dir]), self.path)
        source.run(time.time())
        self.assertEqual(self.health.rows["initiatives"]["status"], "ok")
        sig = os.stat(self.path).st_mtime_ns
        os.chmod(self.path, 0)
        self.addCleanup(os.chmod, self.path, 0o600)
        source.sig = None  # as after a restart: the first read after the refusal
        source.run(time.time() + 3)
        self.assertEqual(self.health.rows["initiatives"]["status"], "error")
        os.chmod(self.path, 0o600)
        self.assertEqual(os.stat(self.path).st_mtime_ns, sig)
        source.run(time.time() + 6)
        self.assertEqual(self.health.rows["initiatives"]["status"], "ok")
        self.assertFalse(source.stale)

    def test_an_unchanged_good_file_is_not_read_again(self):  # control: a good read still caches
        real = safeio.Reader([self.dir])
        attempts = []

        class Counting:
            def read(self, path, limit):
                attempts.append(path)
                return real.read(path, limit)

        source = col.Initiatives(self.hub, self.health, Counting(), self.path)
        source.run(time.time())
        source.run(time.time() + 3)
        self.assertEqual(len(attempts), 1)


if __name__ == "__main__":
    unittest.main()
