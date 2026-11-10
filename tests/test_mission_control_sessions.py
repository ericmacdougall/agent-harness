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
        sid = first.redeem(mcs.mint_code(KEY, first.launch_generation))
        self.assertTrue(sid)
        _, before = first.session(cookie(sid))
        restarted = auth(self.store)  # a new process: only the file carries the session over
        got, after = restarted.session(cookie(sid))
        self.assertEqual(got, sid)
        self.assertEqual(after["csrf"], before["csrf"])

    def test_the_file_is_private_and_holds_no_cookie_or_csrf(self):
        first = auth(self.store)
        sid = first.redeem(mcs.mint_code(KEY, first.launch_generation))
        _, info = first.session(cookie(sid))
        raw = self.store.read_text()
        self.assertEqual(stat.S_IMODE(os.stat(self.store).st_mode), 0o600)
        self.assertNotIn(sid, raw)
        self.assertNotIn(info["csrf"], raw)
        self.assertEqual(list(json.loads(raw)["sessions"]), [mcs.Auth._hash(sid)])

    def test_another_secret_expiry_revoke_and_damage_all_sign_out(self):
        first = auth(self.store)
        sid = first.redeem(mcs.mint_code(KEY, first.launch_generation))
        self.assertEqual(auth(self.store, key=b"x" * 32).session(cookie(sid)), (None, None))  # secret rotated
        later = time.time() + mcs.SESSION_TTL_S + 5
        self.assertEqual(auth(self.store).session(cookie(sid), now=later), (None, None))  # expired
        again = auth(self.store)
        sid2 = again.redeem(mcs.mint_code(KEY, again.launch_generation))
        again.revoke_all()
        self.assertEqual(auth(self.store).session(cookie(sid2)), (None, None))  # revoke is persisted
        self.store.write_text("{not json")
        self.assertEqual(auth(self.store).sessions, {})  # damaged file: signed out, no crash

    def test_rotating_the_secret_under_a_running_server_signs_everyone_out(self):  # red-team M1
        secret = {"key": KEY}
        running = mcs.Auth(lambda: secret["key"], 47615, store=self.store)
        sid = running.redeem(mcs.mint_code(KEY, running.launch_generation))
        secret["key"] = b"r" * 32  # rotate-secret runs in another process
        later = time.time() + mcs.TOUCH_PERSIST_S + 5
        self.assertEqual(running.session(cookie(sid), now=later), (None, None))  # at once, no restart needed
        running.redeem(mcs.mint_code(b"r" * 32, running.launch_generation))  # a new login saves under the new key...
        restarted = mcs.Auth(lambda: secret["key"], 47615, store=self.store)
        self.assertEqual(restarted.session(cookie(sid)), (None, None))  # ...without the old session
        self.assertEqual(len(restarted.sessions), 1)

    def test_a_session_has_an_absolute_lifetime_and_a_missing_secret_signs_out(self):  # red-team L1, L9
        first = auth(self.store)
        start = time.time()
        sid = first.redeem(mcs.mint_code(KEY, first.launch_generation), now=start)
        step = start
        while step < start + mcs.SESSION_TTL_S - 60:  # kept busy, never idle
            step += 3600
            self.assertIsNotNone(first.session(cookie(sid), now=step)[0])
        self.assertEqual(first.session(cookie(sid), now=start + mcs.SESSION_TTL_S + 5), (None, None))

        def missing():
            raise FileNotFoundError("secret")
        sid2 = first.redeem(mcs.mint_code(KEY, first.launch_generation))
        first.key_loader = missing
        self.assertEqual(first.session(cookie(sid2)), (None, None))

    def test_a_secret_unreadable_at_start_keeps_the_saved_sessions(self):  # delta red-team L-a
        instance = auth(self.store)
        sid = instance.redeem(mcs.mint_code(KEY, instance.launch_generation))
        readable = {"ok": False}

        def loader():
            if not readable["ok"]:
                raise FileNotFoundError("secret")
            return KEY
        started = mcs.Auth(loader, 47615, store=self.store)
        self.assertEqual(started.session(cookie(sid)), (None, None))  # signed out while unreadable
        readable["ok"] = True
        self.assertEqual(started.session(cookie(sid))[0], sid)  # back, and nothing was wiped
        self.assertEqual(auth(self.store).session(cookie(sid))[0], sid)

    def test_a_symlinked_store_is_not_read(self):
        real = Path(self.tmp.name) / "elsewhere.json"
        writer = auth(real)
        sid = writer.redeem(mcs.mint_code(KEY, writer.launch_generation))
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


class LauncherQuoting(unittest.TestCase):
    def test_a_home_with_shell_metacharacters_is_quoted(self):  # red-team L2
        import shlex
        home = Path('/tmp/o"$(touch pwned)`x`\\ q')
        argv = shlex.split(mci.launcher_text(home).splitlines()[-1])
        self.assertEqual(argv[:3], ["exec", "/usr/bin/python3", str(mci.app_dir(home) / "server.py")])


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
            target = __import__("shlex").split(text.splitlines()[-1])[2]
            self.assertTrue(Path(target).is_file())
            self.assertIn("launcher", mci.install_launcher(home))  # our own launcher is refreshed
            launcher.write_text("#!/bin/sh\necho midnight commander\n")
            self.assertIn("not ours", mci.install_launcher(home))
            self.assertIn("midnight commander", launcher.read_text())
        self.assertIn("`mc`", (REPO / "harness" / "mission_control" / "web" / "js" / "store.js").read_text())
        self.assertIn(b"<code>mc</code>", (REPO / "harness" / "mission_control" / "server.py").read_bytes())


if __name__ == "__main__":
    unittest.main()
