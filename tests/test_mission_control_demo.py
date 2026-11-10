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
