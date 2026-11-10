"""Sign-in survives restarts, and every sign-in hint names a command that exists (GoodQA #15585 hotfix)."""
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "harness" / "hooks"))
sys.path.insert(0, str(REPO / "harness" / "mission_control"))
os.environ.setdefault("MC_HOOKS", str(REPO / "harness" / "hooks"))

import mission_control_install as mci  # noqa: E402
import server as mcs  # noqa: E402

KEY = b"k" * 32


def auth(store, key=KEY):
    return mcs.Auth(lambda: key, 47615, store=store)


def cookie(sid):
    return f"other=1; mc_sid={sid}"


class PersistentSessions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Path(self.tmp.name) / "sessions.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_session_survives_a_restart_with_the_same_csrf(self):
        first = auth(self.store)
        sid = first.redeem(mcs.mint_code(KEY))
        self.assertTrue(sid)
        _, before = first.session(cookie(sid))
        restarted = auth(self.store)  # a new process: only the file carries the session over
        got, after = restarted.session(cookie(sid))
        self.assertEqual(got, sid)
        self.assertEqual(after["csrf"], before["csrf"])

    def test_the_file_is_private_and_holds_no_cookie_or_csrf(self):
        first = auth(self.store)
        sid = first.redeem(mcs.mint_code(KEY))
        _, info = first.session(cookie(sid))
        raw = self.store.read_text()
        self.assertEqual(stat.S_IMODE(os.stat(self.store).st_mode), 0o600)
        self.assertNotIn(sid, raw)
        self.assertNotIn(info["csrf"], raw)
        self.assertEqual(list(json.loads(raw)["sessions"]), [mcs.Auth._hash(sid)])

    def test_another_secret_expiry_revoke_and_damage_all_sign_out(self):
        first = auth(self.store)
        sid = first.redeem(mcs.mint_code(KEY))
        self.assertEqual(auth(self.store, key=b"x" * 32).session(cookie(sid)), (None, None))  # secret rotated
        later = time.time() + mcs.SESSION_TTL_S + 5
        self.assertEqual(auth(self.store).session(cookie(sid), now=later), (None, None))  # expired
        again = auth(self.store)
        sid2 = again.redeem(mcs.mint_code(KEY))
        again.revoke_all()
        self.assertEqual(auth(self.store).session(cookie(sid2)), (None, None))  # revoke is persisted
        self.store.write_text("{not json")
        self.assertEqual(auth(self.store).sessions, {})  # damaged file: signed out, no crash

    def test_a_symlinked_store_is_not_read(self):
        real = Path(self.tmp.name) / "elsewhere.json"
        writer = auth(real)
        sid = writer.redeem(mcs.mint_code(KEY))
        self.store.symlink_to(real)
        self.assertEqual(auth(self.store).session(cookie(sid)), (None, None))

    def test_the_real_app_persists_and_demo_does_not(self):
        with tempfile.TemporaryDirectory() as home:
            os.chmod(home, 0o700)
            app = mcs.App(port=0, root=Path(home), initiatives=None, remote=False, fabric_bin=None,
                          start_threads=False, codex=False)
            self.assertEqual(app.auth.store, Path(home) / "sessions.json")
        demo_home = Path(self.tmp.name) / "demo"
        os.environ_backup = dict(os.environ)
        try:
            os.environ["MC_HOME"] = str(demo_home)
            demo_app = mcs.build_app(SimpleNamespace(port=0, demo=True, demo_host=None, initiatives=None,
                                                     no_remote=False, no_codex=False, fabric_bin=None, web=None))
            self.assertIsNone(demo_app.auth.store)  # a demo restart still signs out (AC-23/AC-27)
        finally:
            os.environ.clear()
            os.environ.update(os.environ_backup)


class SignInHints(unittest.TestCase):
    HINT = re.compile(r"~/(\.[A-Za-z0-9_./-]+?server\.py)")

    def hinted_paths(self):
        found = set()
        for path in (REPO / "harness" / "mission_control" / "server.py",
                     REPO / "harness" / "mission_control" / "web" / "js" / "store.js"):
            found.update(self.HINT.findall(path.read_text()))
        return found

    def test_every_hinted_path_exists_after_install(self):
        hinted = self.hinted_paths()
        self.assertEqual(hinted, {".agent-harness/mission-control/app/server.py"})
        with tempfile.TemporaryDirectory() as home:
            mci.install_app(Path(home))
            for relative in hinted:
                self.assertTrue((Path(home) / relative).is_file(), relative)

    def test_the_mc_launcher_runs_the_installed_server_and_never_replaces_a_foreign_mc(self):
        with tempfile.TemporaryDirectory() as home:
            home = Path(home)
            mci.install_app(home)
            self.assertIn("launcher", mci.install_launcher(home))
            launcher = home / ".local" / "bin" / "mc"
            self.assertTrue(os.access(launcher, os.X_OK))
            text = launcher.read_text()
            target = re.search(r'exec /usr/bin/python3 "([^"]+)" open', text).group(1)
            self.assertTrue(Path(target).is_file())
            self.assertIn("launcher", mci.install_launcher(home))  # our own launcher is refreshed
            launcher.write_text("#!/bin/sh\necho midnight commander\n")
            self.assertIn("not ours", mci.install_launcher(home))
            self.assertIn("midnight commander", launcher.read_text())
        self.assertIn("`mc`", (REPO / "harness" / "mission_control" / "web" / "js" / "store.js").read_text())
        self.assertIn(b"<code>mc</code>", (REPO / "harness" / "mission_control" / "server.py").read_bytes())


if __name__ == "__main__":
    unittest.main()
