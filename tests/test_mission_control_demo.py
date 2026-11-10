"""Demo mode guards and behaviour (GoodQA #15585): fixture-only data for click-tests behind a Funnel."""
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "harness" / "hooks"))
sys.path.insert(0, str(REPO / "harness" / "mission_control"))
os.environ.setdefault("MC_HOOKS", str(REPO / "harness" / "hooks"))

import demo  # noqa: E402
import mc_chat  # noqa: E402
import server as mcs  # noqa: E402

SERVER = REPO / "harness" / "mission_control" / "server.py"


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def demo_args(port, host=None):
    return SimpleNamespace(port=port, demo=True, demo_host=host, initiatives=None, no_remote=False, no_codex=False,
                           fabric_bin=None, web=None)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mc-demo-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "mc"
        patcher = mock.patch.dict(os.environ, {"MC_HOME": str(self.root)})
        patcher.start()
        self.addCleanup(patcher.stop)


class Guards(Base):
    def test_demo_host_needs_demo(self):
        with self.assertRaises(demo.DemoError):
            demo.check_demo_host("box.tail1234.ts.net", False)
        err = subprocess.run([sys.executable, str(SERVER), "serve", "--port", str(free_port()), "--demo-host",
                              "box.tail1234.ts.net"], capture_output=True, text=True, timeout=20,
                             env={**os.environ, "MC_HOME": str(self.root)})
        self.assertEqual(err.returncode, 2)
        self.assertIn("--demo-host needs --demo", err.stderr)

    def test_demo_host_must_be_a_ts_net_name(self):
        self.assertEqual(demo.check_demo_host("Box.tail1234.ts.net", True), "box.tail1234.ts.net")
        for bad in ("evil.com", "ts.net", "box.ts.net.evil.com", "box.ts.net:443", "https://box.ts.net",
                    "box.ts.net/x", "-box.ts.net", "box..ts.net", "127.0.0.1", "localhost", "box.ts.net.",
                    "b ox.ts.net", "box.ts.net\r\nX: y"):
            with self.subTest(bad=bad), self.assertRaises(demo.DemoError):
                demo.check_demo_host(bad, True)

    def test_demo_refuses_the_real_home(self):
        fake_home = self.base / "home"
        real = fake_home / ".agent-harness" / "mission-control"
        real.mkdir(parents=True)
        with mock.patch.object(Path, "home", return_value=fake_home):
            for bad in (None, "", str(real), str(real / "chat"), str(fake_home / ".agent-harness"),
                        str(real) + "/../mission-control"):
                with self.subTest(bad=bad), self.assertRaises(demo.DemoError):
                    demo.check_demo_home(bad)
            ok = fake_home / ".agent-harness" / "work" / "s" / "mc-clicktest"
            self.assertEqual(demo.check_demo_home(str(ok)), ok.resolve())

    def test_serve_demo_with_the_real_home_exits_before_touching_it(self):
        fake_home = self.base / "home"
        real = fake_home / ".agent-harness" / "mission-control"
        env = {**os.environ, "HOME": str(fake_home), "MC_HOME": str(real)}
        err = subprocess.run([sys.executable, str(SERVER), "serve", "--demo", "--port", str(free_port())],
                             capture_output=True, text=True, timeout=20, env=env)
        self.assertEqual(err.returncode, 2)
        self.assertIn("refusing --demo", err.stderr)
        self.assertFalse(real.exists(), "nothing was created in the real home")

    def test_demo_never_constructs_the_real_runner_or_a_process(self):
        with mock.patch.object(mcs, "Runner", side_effect=AssertionError("real Runner built in demo mode")), \
                mock.patch("subprocess.Popen", side_effect=AssertionError("process started in demo mode")), \
                mock.patch("subprocess.run", side_effect=AssertionError("process run in demo mode")):
            app = mcs.build_app(demo_args(free_port()))
            self.assertIsInstance(app.runner, demo.DemoRunner)
            now = time.time()
            for collector in app.collectors:
                collector.run(now)
            app.codex.step()
        self.assertTrue(app.demo)
        self.assertEqual({k for k, _ in app.runner.calls} - {"ah-owners", "ah-ticket-comments", "gh-user"}, set())
        with self.assertRaises(PermissionError):
            app.runner.run("remote-wal-probe")
        self.assertEqual(len(app.owners.rows), len(demo.OWNERS))
        states = {r["agent_id"]: r for r in app.owners.rows}
        self.assertTrue(states["a4held0demo"]["disposition"]["live"], "a held owner is in the fixture")
        self.assertEqual(app.health.rows["github"]["status"], "error", "the failing source is in the fixture")

    def test_demo_app_refuses_without_its_fixture(self):
        with self.assertRaises(demo.DemoError):
            mcs.App(port=1, root=self.root, initiatives=None, remote=False, fabric_bin=None, demo=True,
                    start_threads=False)

    def test_launch_agent_never_runs_demo(self):
        import mission_control_install as mci  # noqa: PLC0415
        for verb in ("install-launchd", "uninstall-launchd"):
            argv = mci.service_argv(Path("/x/home"), verb)
            self.assertFalse([a for a in argv if a.startswith("--demo")], argv)
        self.assertNotIn("--demo", mcs.plist_text(47615, "/usr/bin/python3"))


class Http(Base):
    """A demo App behind a real server, with a Funnel host allowed."""

    HOST = "box.tail1234.ts.net"

    def setUp(self):
        super().setUp()
        self.port = free_port()
        self.app = mcs.build_app(demo_args(self.port, self.HOST))
        self.server = mcs.Server(self.app, REPO / "harness" / "mission_control" / "web", mcs.make_logger(self.root))
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, headers=None, body=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        hdrs = {"Host": host or self.HOST}
        hdrs.update(headers or {})
        try:
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            return resp, resp.read()
        finally:
            conn.close()

    def login(self, host=None):
        resp, _ = self.request("GET", "/launch?c=" + mcs.mint_code(mc_chat.secret()), {"Sec-Fetch-Site": "none"},
                               host=host)
        self.assertEqual(resp.status, 303)
        cookie = resp.getheader("Set-Cookie").split(";")[0]
        resp, data = self.request("GET", "/api/state", {"Cookie": cookie, "Sec-Fetch-Site": "same-origin"},
                                  host=host)
        self.assertEqual(resp.status, 200)
        return cookie, json.loads(data)

    def send(self, cookie, csrf, key, origin=None):
        body = json.dumps({"to": "claude", "session": demo.DEMO_SESSION, "text": "hello demo",
                           "client_key": key}).encode()
        return self.request("POST", "/api/chat", {"Cookie": cookie, "X-MC-CSRF": csrf, "Content-Type":
                                                  "application/json", "Origin": origin or f"https://{self.HOST}"},
                            body)

    def test_funnel_host_works_only_with_its_https_origin(self):
        demo.DemoLoop(self.root, threading.Event()).heartbeat()
        cookie, state = self.login()
        self.assertEqual(self.send(cookie, state["csrf"], "key-demo-0001", origin=f"http://{self.HOST}")[0].status,
                         403)
        self.assertEqual(self.send(cookie, state["csrf"], "key-demo-0001", origin="https://evil.ts.net")[0].status,
                         403)
        self.assertEqual(self.send(cookie, state["csrf"], "key-demo-0001")[0].status, 201)
        self.assertEqual(self.request("GET", "/api/state", {"Cookie": cookie}, host="other.ts.net")[0].status, 403)

    def test_dropped_first_response_then_same_key_retry_is_one_message(self):
        demo.DemoLoop(self.root, threading.Event()).heartbeat()
        self.app.demo_drop_first = True
        cookie, state = self.login()
        with self.assertRaises((http.client.RemoteDisconnected, ConnectionError, http.client.BadStatusLine)):
            self.send(cookie, state["csrf"], "key-retry-0001")
        resp, data = self.send(cookie, state["csrf"], "key-retry-0001")
        self.assertEqual(resp.status, 200, data)
        self.assertEqual(len(mc_chat.inbox(self.root)), 1)

    def test_delayed_accept(self):
        demo.DemoLoop(self.root, threading.Event()).heartbeat()
        self.app.demo_delay_s = 1.0
        cookie, state = self.login()
        start = time.time()
        self.assertEqual(self.send(cookie, state["csrf"], "key-delay-0001")[0].status, 201)
        self.assertGreaterEqual(time.time() - start, 1.0)


    def test_junk_launch_codes_never_block_a_genuine_one(self):
        # NEG-23: behind a Funnel every client is 127.0.0.1; a scanner must not lock the tester out.
        for n in range(25):
            self.assertEqual(self.request("GET", f"/launch?c=junk{n}.AAAA", {"Sec-Fetch-Site": "none"})[0].status,
                             401)
        cookie, state = self.login()
        self.assertTrue(cookie.startswith("mc_sid="))

    def test_funnel_cookie_is_secure_and_loopback_cookie_works_over_http(self):
        resp, _ = self.request("GET", "/launch?c=" + mcs.mint_code(mc_chat.secret()), {"Sec-Fetch-Site": "none"})
        self.assertIn("; Secure", resp.getheader("Set-Cookie"))
        resp, _ = self.request("GET", "/launch?c=" + mcs.mint_code(mc_chat.secret()), {"Sec-Fetch-Site": "none"},
                               host=f"127.0.0.1:{self.port}")
        self.assertEqual(resp.status, 303)
        self.assertNotIn("Secure", resp.getheader("Set-Cookie"))

    def test_healthz_names_the_build_but_no_paths_or_hostname(self):
        resp, data = self.request("GET", "/healthz")
        value = json.loads(data)
        self.assertEqual(resp.status, 200)
        self.assertTrue(value["demo"])
        self.assertRegex(value["build"]["digest"], r"^[0-9a-f]{16}$")
        self.assertIn(value["build"]["hooks"], ("checkout", "installed"))
        self.assertNotIn(str(Path.home()), data.decode())
        short = socket.gethostname().split(".")[0]
        if not set(short.lower()) <= set("0123456789abcdef"):  # a hex-only name could collide with the digest
            self.assertNotIn(short, data.decode())
        head = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True)
        if head.returncode == 0:  # AC-26: run from a checkout, the commit must be the checkout's HEAD, not None
            self.assertEqual(value["build"]["commit"], head.stdout.strip())
        _cookie, state = self.login()
        self.assertEqual(state["host"], "demo")

    def test_a_ts_net_host_is_refused_unless_it_was_allowed(self):
        # NEG-20: only the one --demo-host name is accepted; the real server never passes one, so it refuses them all.
        cookie, _state = self.login()
        self.assertEqual(self.request("GET", "/healthz", host="erics-macbook-air.tail980dbb.ts.net")[0].status, 403)
        plain = mcs.build_app(demo_args(free_port()))
        self.assertNotIn(self.HOST, plain.auth.hosts)
        self.assertEqual({h for h in plain.auth.hosts if "ts.net" in h}, set())


class DemoHome(Base):
    """NEG-21 and NEG-22: demo writes stay inside a claimed disposable home."""

    def test_unmarked_non_empty_home_is_refused(self):
        self.root.mkdir(parents=True)
        (self.root / "notes.txt").write_text("someone else's directory\n")
        with self.assertRaises(demo.DemoError):
            demo.prepare_home(self.root)
        self.assertFalse((self.root / demo.MARKER).exists())

    def test_symlinked_working_directory_is_refused(self):
        outside = self.base / "real-sources"
        outside.mkdir()
        demo.prepare_home(self.root)
        (self.root / "sources").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(demo.DemoError):
            demo.prepare_home(self.root)
        with self.assertRaises(demo.DemoError):
            mcs.build_app(demo_args(free_port()))
        self.assertEqual(list(outside.iterdir()), [])

    def test_nested_symlinks_anywhere_in_the_home_are_refused(self):
        # N2 (adversarial re-review): demo/wals, a session folder and log/server.log were written through.
        for n, planted in enumerate(("demo/wals", f"demo/wals/{demo.DEMO_SESSION}", "log/server.log")):
            with self.subTest(planted=planted):
                decoy = self.base / f"decoy-{n}"
                decoy.mkdir()
                home = self.base / ("h-" + planted.replace("/", "-"))
                demo.prepare_home(home)
                link = home / planted
                link.parent.mkdir(parents=True, exist_ok=True)
                target = decoy / "server.log" if planted.endswith(".log") else decoy
                link.symlink_to(target, target_is_directory=not planted.endswith(".log"))
                with mock.patch.dict(os.environ, {"MC_HOME": str(home)}):
                    with self.assertRaises(demo.DemoError):
                        mcs.build_app(demo_args(free_port()))
                self.assertEqual(list(decoy.iterdir()), [])

    def test_url_demo_host_refuses_an_unmarked_copy_holding_a_secret(self):
        # L-c: a backup copy of the real home elsewhere must not sign Funnel codes with the real secret.
        copy = self.base / "backup-of-real-home"
        copy.mkdir()
        mc_chat.secret(copy)
        out = subprocess.run([sys.executable, str(SERVER), "url", "--port", "47699", "--demo-host", "box.tail1234.ts.net"],
                             capture_output=True, text=True, timeout=30, env={**os.environ, "MC_HOME": str(copy)})
        self.assertEqual(out.returncode, 2, out.stdout)
        self.assertNotIn("launch?c=", out.stdout)

    def test_fixture_writes_never_follow_a_planted_file_symlink(self):
        demo.prepare_home(self.root)
        mcs.build_app(demo_args(free_port()))
        victim = self.base / "victim.json"
        victim.write_text("untouched\n")
        target = self.root / "demo" / "initiatives.json"
        target.unlink()
        target.symlink_to(victim)
        with self.assertRaises(OSError):
            demo.seed(self.root)
        self.assertEqual(victim.read_text(), "untouched\n")

    def test_serve_refuses_an_unmarked_home_before_writing_anything(self):
        self.root.mkdir(parents=True)
        (self.root / "keep").write_text("x")
        proc = subprocess.run([sys.executable, str(SERVER), "serve", "--demo", "--port", str(free_port())],
                              capture_output=True, text=True, timeout=30, env={**os.environ, "MC_HOME": str(self.root)})
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["keep"])

    def test_url_demo_host_needs_a_demo_home_and_never_mints_a_secret(self):
        fake_home = self.base / "home"
        fake_home.mkdir()
        env = {k: v for k, v in os.environ.items() if k != "MC_HOME"}
        env["HOME"] = str(fake_home)
        argv = [sys.executable, str(SERVER), "url", "--port", "47699", "--demo-host", "box.tail1234.ts.net"]
        unset = subprocess.run(argv, capture_output=True, text=True, timeout=30, env=env)
        self.assertEqual(unset.returncode, 2, unset.stdout)
        self.assertNotIn("launch?c=", unset.stdout)
        real = subprocess.run(argv, capture_output=True, text=True, timeout=30,
                              env={**env, "MC_HOME": str(fake_home / ".agent-harness" / "mission-control")})
        self.assertEqual(real.returncode, 2, real.stdout)
        fresh = subprocess.run(argv, capture_output=True, text=True, timeout=30,
                               env={**env, "MC_HOME": str(self.root)})
        self.assertEqual(fresh.returncode, 2, fresh.stdout)
        self.assertEqual([p for p in fake_home.rglob("secret")] + [p for p in self.base.rglob("secret")], [])


class EchoAndActivity(Base):
    def test_echo_replies_after_the_delay_and_only_once(self):
        mc_chat.ensure_dirs()
        loop = demo.DemoLoop(self.root, threading.Event())
        loop.heartbeat()
        record, _ = mc_chat.new_message("claude", "hi", client_key="key-echo-0001", session=demo.DEMO_SESSION)
        now = time.time()
        loop.echo(now)
        self.assertEqual(mc_chat.state(record["id"])["status"], "queued", "not before the delay")
        loop.echo(now + demo.ECHO_AFTER_S + 0.1)
        loop.echo(now + demo.ECHO_AFTER_S + 5)
        replies = [r for r in mc_chat.outbox(self.root) if r["reply_to"] == record["id"]]
        self.assertEqual([r["text"] for r in replies], [demo.ECHO_TEXT])
        self.assertEqual(mc_chat.state(record["id"])["status"], "answered")

    def test_pulses_write_valid_drop_lines_inside_mc_home(self):
        mc_chat.ensure_dirs()
        (self.root / "sources").mkdir(exist_ok=True)
        demo.seed(self.root)
        loop = demo.DemoLoop(self.root, threading.Event())
        for n in range(6):
            loop.pulse(time.time() + n)
        lines = (self.root / "sources" / "demo.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 6)
        self.assertTrue(all(json.loads(line)["schema"] == "mc.event/1" for line in lines))


class LaunchCode(Base):
    def test_demo_serve_prints_a_code_to_the_terminal_only(self):
        port = free_port()
        proc = subprocess.Popen([sys.executable, str(SERVER), "serve", "--demo", "--port", str(port), "--demo-host",
                                 "box.tail1234.ts.net"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                env={**os.environ, "MC_HOME": str(self.root)})
        try:
            lines = []
            deadline = time.time() + 20
            while time.time() < deadline and not any("launch (60 s" in line for line in lines):
                lines.append(proc.stdout.readline())
        finally:
            proc.terminate()
            proc.communicate(timeout=10)
        launch = [line for line in lines if "launch (60 s" in line]
        self.assertEqual(len(launch), 1, lines)
        self.assertIn("https://box.tail1234.ts.net/launch?c=", launch[0])
        code = launch[0].split("?c=")[1].strip()
        logged = "".join(p.read_text(errors="replace") for p in (self.root / "log").glob("*"))
        self.assertNotIn(code, logged)
        self.assertNotIn("launch?c=", logged)


if __name__ == "__main__":
    unittest.main()
