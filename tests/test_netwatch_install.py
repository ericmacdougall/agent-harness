import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
import unittest.mock
import zipfile
from pathlib import Path

import netwatch_install as nw

VERSION = "v9.9.9"


def tar_archive(key, members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "symlink":
                info.type, info.linkname = tarfile.SYMTYPE, data.decode()
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def zip_archive(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


class FakeRun:
    """Stands in for subprocess.run against the installed binary: `version`
    prints what the file says it is, `install` records the call."""

    def __init__(self, install_code=0, status_out="service: not installed\n"):
        self.calls = []
        self.install_code = install_code
        self.status_out = status_out

    def __call__(self, args, **kwargs):
        self.calls.append(args[1:])
        if args[1] == "version":
            body = Path(args[0]).read_bytes().decode()
            return subprocess.CompletedProcess(args, 0, stdout=f"netwatch {body}\n", stderr="")
        if args[1] == "status":
            return subprocess.CompletedProcess(args, 0, stdout=self.status_out, stderr="")
        return subprocess.CompletedProcess(args, self.install_code, stdout="installed\n", stderr="boom\n")


class NetwatchInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        # The suite may itself run with the opt-out set; these tests choose it.
        env = unittest.mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop(nw.OPT_OUT_ENV, None)
        self.key = "linux_amd64"
        self.archive = tar_archive(self.key, [(f"netwatch_{VERSION}_{self.key}/netwatch", VERSION.encode(), "file"),
                                              (f"netwatch_{VERSION}_{self.key}/README.md", b"docs", "file")])
        self.pin = self.write_pin(hashlib.sha256(self.archive).hexdigest())
        self.urls = []

    def write_pin(self, digest, key=None, binary=VERSION.encode()):
        path = self.home / "pin.json"
        path.write_text(json.dumps({"version": VERSION, "repo": "example/netwatch",
                                    "assets": {key or self.key: {"sha256": digest,
                                                                  "binary_sha256": hashlib.sha256(binary).hexdigest()}}}))
        return path

    def download(self, data):
        def fetch(url):
            self.urls.append(url)
            return data
        return fetch

    def status(self, run=None, data=None, register=True, **kwargs):
        return nw.status(self.home, True, pin_path=self.pin, key=self.key, run=run or FakeRun(),
                         download=self.download(self.archive if data is None else data), register=register, **kwargs)

    def test_installs_pinned_binary_and_registers_service(self):
        run = FakeRun()
        line = self.status(run)
        self.assertIn(f"installed {VERSION}", line)
        binary = self.home / ".agent-harness" / "bin" / "netwatch"
        self.assertEqual(binary.read_bytes(), VERSION.encode())
        self.assertTrue(os.access(binary, os.X_OK))
        self.assertEqual(self.urls, [f"https://github.com/example/netwatch/releases/download/{VERSION}/"
                                     f"netwatch_{VERSION}_{self.key}.tar.gz"])
        self.assertEqual(run.calls[-1], ["install"])
        self.assertFalse((binary.parent / "README.md").exists())

    def test_digest_mismatch_installs_nothing(self):
        self.pin = self.write_pin("0" * 64)
        run = FakeRun()
        line = self.status(run)
        self.assertIn("does not match the pin", line)
        self.assertFalse((self.home / ".agent-harness" / "bin" / "netwatch").exists())
        self.assertNotIn(["install"], run.calls)

    def test_current_binary_skips_download_and_reregisters_only_if_not_running(self):
        self.status()
        self.urls.clear()
        run = FakeRun(status_out="service: loaded, state running, pid 42\n")
        line = self.status(run)
        self.assertIn("up to date", line)
        self.assertEqual(self.urls, [])
        self.assertNotIn(["install"], run.calls)
        run = FakeRun(status_out="service: not loaded\n")
        self.status(run)
        self.assertEqual(run.calls[-1], ["install"])

    def test_tampered_binary_is_replaced_without_being_run(self):
        self.status()
        binary = self.home / ".agent-harness" / "bin" / "netwatch"
        binary.write_bytes(VERSION.encode() + b" ")  # claims the pinned version, wrong bytes
        self.urls.clear()
        run = FakeRun()
        self.assertIn(f"installed {VERSION}", self.status(run))
        self.assertEqual(len(self.urls), 1)
        self.assertEqual(binary.read_bytes(), VERSION.encode())

    def test_unverified_binary_claiming_newer_version_is_replaced_unrun(self):
        binary = self.home / ".agent-harness" / "bin" / "netwatch"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"v10.0.0")
        run = FakeRun()
        self.assertIn(f"installed {VERSION}", self.status(run))
        self.assertEqual(binary.read_bytes(), VERSION.encode())
        self.assertEqual(run.calls[0], ["version"])  # only the new, verified binary ran
        self.assertEqual(len([c for c in run.calls if c == ["version"]]), 1)

    def test_running_detection_is_exact(self):
        for line, running in [("service: loaded, state running, pid 42", True),
                              ("service: loaded, state not running, pid -", False),
                              ("service: netwatch.service active/running (enabled), pid 7", True),
                              ("service: netwatch.service inactive/dead (enabled), pid 0", False),
                              ("service: Scheduled Task netwatch: Running", True),
                              ("service: Scheduled Task netwatch: Ready", False)]:
            self.assertEqual(bool(nw.RUNNING.search(line)), running, line)
        self.status()
        run = FakeRun(status_out="service: loaded, state not running, pid -\n")
        self.status(run)
        self.assertEqual(run.calls[-1], ["install"])

    def test_real_home_ignores_home_override(self):
        old = os.environ.get("HOME")
        os.environ["HOME"] = str(self.home)
        try:
            self.assertNotEqual(nw.real_home(), self.home)
        finally:
            if old is None:
                os.environ.pop("HOME")
            else:
                os.environ["HOME"] = old

    def test_non_default_home_never_registers_the_service(self):
        run = FakeRun()
        line = nw.status(self.home, True, pin_path=self.pin, key=self.key, run=run,
                         download=self.download(self.archive))
        self.assertIn("service not registered (non-default home)", line)
        self.assertNotIn(["install"], run.calls)
        self.assertNotIn(["status"], run.calls)

    def test_installer_skips_netwatch_for_non_default_home(self):
        import install
        line = install.netwatch_status(self.home, True, None)
        self.assertIn("non-default --home", line)
        self.assertFalse((self.home / ".agent-harness").exists())

    def test_binary_digest_mismatch_inside_good_archive(self):
        self.pin = self.write_pin(hashlib.sha256(self.archive).hexdigest(), binary=b"other")
        line = self.status()
        self.assertIn("does not match the pinned binary_sha256", line)
        self.assertFalse((self.home / ".agent-harness" / "bin" / "netwatch").exists())

    def test_old_version_is_upgraded(self):
        binary = self.home / ".agent-harness" / "bin" / "netwatch"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"v0.0.1")
        self.assertIn(f"installed {VERSION}", self.status())
        self.assertEqual(binary.read_bytes(), VERSION.encode())

    def test_archive_without_expected_member_or_with_link_is_refused(self):
        real = f"netwatch_{VERSION}_{self.key}/README.md"
        for members in ([("evil/../../netwatch", b"x", "file")],
                        # A link to a real member resolves, so only isreg() refuses it.
                        [(real, VERSION.encode(), "file"),
                         (f"netwatch_{VERSION}_{self.key}/netwatch", b"README.md", "symlink")]):
            data = tar_archive(self.key, members)
            self.pin = self.write_pin(hashlib.sha256(data).hexdigest())
            line = self.status(data=data)
            self.assertIn("not installed", line)
            self.assertFalse((self.home / ".agent-harness" / "bin" / "netwatch").exists())
            self.assertFalse((self.home.parent / "netwatch").exists())

    def test_binary_reporting_wrong_version_is_not_registered(self):
        data = tar_archive(self.key, [(f"netwatch_{VERSION}_{self.key}/netwatch", b"v1.0.0", "file")])
        self.pin = self.write_pin(hashlib.sha256(data).hexdigest(), binary=b"v1.0.0")
        run = FakeRun()
        line = self.status(run, data=data)
        self.assertIn("does not report", line)
        self.assertNotIn(["install"], run.calls)

    def test_service_failure_is_reported_not_raised(self):
        self.assertIn("service registration failed (boom)", self.status(FakeRun(install_code=1)))

    def test_download_error_is_reported_not_raised(self):
        def failing(url):
            raise OSError("network down")
        line = nw.status(self.home, True, pin_path=self.pin, key=self.key, run=FakeRun(), download=failing)
        self.assertIn("not installed (OSError: network down)", line)

    def test_windows_zip(self):
        self.key = "windows_amd64"
        self.archive = zip_archive([(f"netwatch_{VERSION}_{self.key}/netwatch.exe", VERSION)])
        self.pin = self.write_pin(hashlib.sha256(self.archive).hexdigest())
        self.assertIn(f"installed {VERSION}", self.status())
        self.assertTrue((self.home / ".agent-harness" / "bin" / "netwatch.exe").is_file())
        self.assertTrue(self.urls[0].endswith(".zip"))

    def test_windows_zip_directory_member_refused(self):
        self.key = "windows_amd64"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(f"netwatch_{VERSION}_{self.key}/netwatch.exe/", "")
        self.archive = buf.getvalue()
        self.pin = self.write_pin(hashlib.sha256(self.archive).hexdigest())
        self.assertIn("not installed", self.status())

    def test_fetch_size_cap(self):
        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False
        big = Response(b"x" * (nw.MAX_ARCHIVE + 1))
        with unittest.mock.patch("urllib.request.urlopen", return_value=big):
            with self.assertRaises(ValueError):
                nw.fetch("https://example.com/x")

    def test_state_file_fifo_or_link_does_not_hang(self):
        state = self.home / ".agent-harness" / nw.STATE_FILE
        state.parent.mkdir()
        os.mkfifo(state)
        self.assertTrue(nw.choice(self.home, None))
        state.unlink()
        target = self.home / "elsewhere.json"
        target.write_text('{"enabled": false}')
        state.symlink_to(target)
        self.assertTrue(nw.choice(self.home, None))

    def test_symlinked_harness_dir_is_refused(self):
        elsewhere = self.home / "elsewhere"
        elsewhere.mkdir()
        (self.home / ".agent-harness").symlink_to(elsewhere)
        self.assertIn("not installed", self.status())
        self.assertFalse((elsewhere / "bin").exists())

    def test_preview_and_opt_out_write_nothing(self):
        run = FakeRun()
        line = nw.status(self.home, False, pin_path=self.pin, key=self.key, run=run, download=self.download(b""))
        self.assertIn("would install", line)
        self.assertEqual(run.calls, [])
        self.assertIn("opted out", nw.status(self.home, True, False, pin_path=self.pin, key=self.key))
        self.assertEqual(self.urls, [])
        self.assertFalse((self.home / ".agent-harness").exists())

    def test_unsupported_platform(self):
        self.assertIsNone(nw.platform_key("freebsd", "amd64"))
        self.assertEqual(nw.platform_key("win32", "AMD64"), "windows_amd64")
        self.assertEqual(nw.platform_key("darwin", "arm64"), "darwin_arm64")
        self.assertIn("no v9.9.9 release", nw.status(self.home, True, pin_path=self.pin, key="windows_arm64"))

    def test_choice_is_remembered_and_env_opts_out(self):
        self.assertTrue(nw.choice(self.home, None))
        nw.save_choice(self.home, False)
        self.assertFalse(nw.choice(self.home, None))
        self.assertTrue(nw.choice(self.home, True))
        self.assertEqual(os.stat(self.home / ".agent-harness" / nw.STATE_FILE).st_mode & 0o777, 0o600)
        nw.save_choice(self.home, True)
        os.environ[nw.OPT_OUT_ENV] = "0"
        self.assertFalse(nw.choice(self.home, None))

    def test_non_https_download_refused(self):
        with self.assertRaises(ValueError):
            nw.fetch("http://example.com/x")

    def test_shipped_pin_is_valid_and_covers_release_platforms(self):
        pin = nw.load_pin()
        self.assertEqual(set(pin["assets"]), {"darwin_arm64", "darwin_amd64", "linux_amd64", "linux_arm64",
                                              "windows_amd64"})
        self.assertEqual(pin["repo"], "ericmacdougall/netwatch")


if __name__ == "__main__":
    unittest.main()
