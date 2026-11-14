"""bg_job.py wait-remote and wait --ssh-job (goodqa#15565 items 7 and 8; spec notes/goodqa-15565-wait-remote/spec.md).

ssh is never run: the tests replace bg_job._ssh_once with a small remote that answers the fixed template the way a POSIX
shell would (absent file exit 10, unreadable exit 11, size line then the appended bytes capped at 64 KiB)."""
import argparse
import io
import re
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import bg_job  # noqa: E402

GOOD_HOST = "t2-dev"
GOOD_FILE = "/home/eric/logs/suite.log"


def serve(content, command):
    """What the fixed remote template prints for a file holding `content` (None absent, 'dir' unreadable)."""
    if content is None:
        return 10, b"", ""
    if content == "dir":
        return 11, b"", ""
    off = int(re.search(r"tail -c \+(\d+) --", command).group(1))
    return 0, b"%d\n" % len(content) + content[off - 1:off - 1 + bg_job.READ_CAP], "__bgjob_rc=0\n"


class Remote:
    """A scripted remote: `steps` is a list; each entry is bytes/None/'dir' (the file's content at that call), a tuple
    (status, stdout, stderr) returned as is, or a callable(call_index) -> one of those. The last entry repeats."""

    def __init__(self, *steps):
        self.steps, self.calls = list(steps), []

    def __call__(self, host, command, budget=None):
        self.calls.append((host, command))
        self.budgets = getattr(self, "budgets", []) + [budget]
        step = self.steps[min(len(self.calls) - 1, len(self.steps) - 1)]
        if callable(step):
            step = step(len(self.calls) - 1)
        if isinstance(step, tuple):
            return step
        return serve(step, command)


def args(**kw):
    base = dict(host=GOOD_HOST, file=GOOD_FILE, until_file_line="ALL PASSED", fail_line=None, include_existing=False,
                from_offset=None, timeout=3.0, poll=0.05, max_infra_polls=3)
    base.update(kw)
    return argparse.Namespace(**base)


def run(remote, **kw):
    out = io.StringIO()
    with mock.patch.object(bg_job, "_ssh_once", remote), mock.patch.object(bg_job, "_wait_alert") as alert, \
            mock.patch.object(bg_job, "file_judged_by_guard", return_value=(True, "")), redirect_stdout(out):
        code = bg_job.cmd_wait_remote(args(**kw))
    return code, out.getvalue(), alert


class Matching(unittest.TestCase):
    def test_a_line_appended_after_the_first_look_is_found_and_no_content_is_printed(self):
        remote = Remote(b"old run\n", b"old run\nrunning\n", b"old run\nrunning\nsecret-looking ALL PASSED\n")
        code, out, _alert = run(remote)
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "LINE_FOUND host=%s file=%s" % (GOOD_HOST, GOOD_FILE))
        self.assertNotIn("secret-looking", out)

    def test_the_earlier_runs_line_already_in_the_file_does_not_end_the_wait(self):
        # NEG-3: an appended log holds the previous run's result
        code, out, alert = run(Remote(b"Ran 3 tests ALL PASSED\n"), timeout=1.0)
        self.assertEqual(code, 3)
        self.assertIn("TIMEOUT", out)
        alert.assert_called_once()

    def test_include_existing_matches_what_is_already_there(self):
        code, _out, _a = run(Remote(b"Ran 3 tests ALL PASSED\n"), include_existing=True)
        self.assertEqual(code, 0)

    def test_text_split_across_two_polls_matches(self):
        remote = Remote(b"", b"ALL PA", b"ALL PASSED")
        self.assertEqual(run(remote)[0], 0)

    def test_a_file_that_appears_later_holds_only_new_bytes(self):
        code, _out, _a = run(Remote(None, None, b"ALL PASSED\n"))
        self.assertEqual(code, 0)

    def test_a_truncated_file_is_judged_from_its_start(self):
        remote = Remote(b"x" * 50, b"x" * 50 + b"more", b"short", b"short\nALL PASSED\n")
        self.assertEqual(run(remote)[0], 0)

    def test_a_longer_word_around_the_text_still_matches_as_a_substring(self):
        self.assertEqual(run(Remote(b"", b"xxALL PASSEDyy"))[0], 0)

    def test_the_text_is_not_a_pattern(self):
        code, _o, _a = run(Remote(b"", b"ALL PASSED"), until_file_line="ALL.PASSED", timeout=1.0)
        self.assertEqual(code, 3)

    def test_more_than_one_read_of_new_bytes_is_read_on_without_sleeping(self):
        big = b"a" * (bg_job.READ_CAP + 10) + b"ALL PASSED"
        self.assertEqual(run(Remote(b"", big), timeout=20)[0], 0)

    def test_a_fail_line_ends_the_wait_as_a_failure_and_wins_over_the_success_line(self):
        code, out, _a = run(Remote(b"", b"FAILED (errors=1)\nALL PASSED\n"), fail_line="FAILED (")
        self.assertEqual(code, 1)
        self.assertIn("FAIL_LINE_FOUND", out)


class Errors(unittest.TestCase):
    def test_a_directory_or_unreadable_file_is_unproven_at_once_not_a_timeout(self):
        remote = Remote("dir")
        code, out, _a = run(remote, timeout=30)
        self.assertEqual(code, 2)
        self.assertIn("not a readable regular file", out)
        self.assertEqual(len(remote.calls), 1)

    def test_any_other_remote_status_is_unproven_and_not_retried(self):
        remote = Remote((2, b"", "tail: i/o error"))
        code, out, _a = run(remote)
        self.assertEqual((code, len(remote.calls)), (2, 1))
        self.assertIn("exit 2", out)

    def test_a_banner_empty_output_or_garbled_size_is_unproven_never_a_reset(self):
        # NEG-17: an rc file echoing before the size must not make the wait re-read the file and match an old result
        for out in (b"Welcome to t2-dev\n5\nALL PASSED", b"", b"garbage", b"-1\nALL PASSED", b"12abc\nALL PASSED"):
            with self.subTest(out):
                self.assertEqual(run(Remote((0, out, "")), include_existing=True)[0], 2)

    def test_the_banner_does_not_reset_a_wait_in_progress(self):
        remote = Remote(b"old ALL PASSED\n", (0, b"Welcome\n14\nold ALL PASSED\n", ""))
        self.assertEqual(run(remote)[0], 2)

    def test_a_burst_over_the_cap_with_the_fail_line_early_and_the_text_late_is_a_failure(self):
        # NEG-14: advancing to the reported size would skip the middle and turn this into a pass
        burst = b"FAILED (errors=1)\n" + b"x" * 130000 + b"\nALL PASSED\n"
        code, out, _a = run(Remote(b"", burst), fail_line="FAILED (")
        self.assertEqual((code, "FAIL_LINE_FOUND" in out), (1, True))

    def test_text_at_byte_70000_and_in_the_middle_of_200_kib_is_found(self):
        for burst in (b"x" * 70000 + b"ALL PASSED", b"y" * 100000 + b"ALL PASSED" + b"z" * 100000):
            with self.subTest(len(burst)):
                self.assertEqual(run(Remote(b"", burst), timeout=20)[0], 0)

    def test_the_offset_advances_by_bytes_received_not_by_the_reported_size(self):
        remote = Remote(b"", b"a" * 100000)
        run(remote, timeout=0.3)
        offsets = [int(re.search(r"tail -c \+(\d+) --", c).group(1)) for _h, c in remote.calls]
        self.assertEqual(offsets[:4], [1, 1, 65537, 100001])  # first look, then first chunk, second chunk, then caught up

    def test_a_file_created_between_polls_with_the_text_in_it_is_found(self):
        # NEG-15, with connection failures before and an absent file after
        down = (255, b"", "reset")
        self.assertEqual(run(Remote(down, down, None, b"ALL PASSED\n"), max_infra_polls=5)[0], 0)

    def test_a_line_written_while_the_link_was_down_counts_as_existing(self):
        # NEG-15, second half: pinned both ways
        down = (255, b"", "reset")
        steps = (down, down, b"run started\nALL PASSED\n")
        self.assertEqual(run(Remote(*steps), max_infra_polls=5, timeout=1.0)[0], 3)
        self.assertEqual(run(Remote(*steps), max_infra_polls=5, include_existing=True)[0], 0)

    def test_from_offset_finds_a_line_written_before_the_first_poll(self):
        old = b"earlier ALL PASSED\n"
        remote = Remote(old + b"new run\nALL PASSED\n")
        self.assertEqual(run(remote, from_offset=len(old))[0], 0)
        self.assertEqual(run(Remote(old), from_offset=len(old), timeout=0.5)[0], 3)  # the earlier result stays hidden

    def test_from_offset_cannot_be_combined_with_include_existing_or_be_negative(self):
        for kw in ({"from_offset": 5, "include_existing": True}, {"from_offset": -1}, {"from_offset": 2 ** 50}):
            with self.subTest(kw):
                out = io.StringIO()
                with mock.patch.object(bg_job, "_ssh_once", Remote(b"")), redirect_stdout(out):
                    self.assertEqual(bg_job.cmd_wait_remote(args(**kw)), 64)

    def test_a_connection_failure_that_succeeds_on_the_retry_is_not_infra(self):
        remote = Remote((255, b"", "Connection reset by peer"), b"", b"ALL PASSED")
        code, _o, _a = run(remote)
        self.assertEqual(code, 0)
        self.assertEqual(remote.calls[0][1], remote.calls[1][1])  # the retry repeats the same read-only call

    def test_a_dead_link_ends_in_infra_after_n_polls_each_retried_once(self):
        remote = Remote((255, b"", "Connection timed out"))
        code, out, alert = run(remote, max_infra_polls=3)
        self.assertEqual(code, 5)
        self.assertIn("INFRA host=%s polls=3" % GOOD_HOST, out)
        self.assertEqual(len(remote.calls), 6)
        alert.assert_called_once()

    def test_a_successful_poll_resets_the_infra_count(self):
        down, up = (255, b"", "reset"), b""
        remote = Remote(down, down, up, down, down, b"ALL PASSED")
        code, _o, _a = run(remote, max_infra_polls=2)
        self.assertEqual(code, 0)

    def test_ssh_refusals_are_unproven_not_infra_and_not_retried(self):
        for text in ("user@h: Permission denied (publickey).", "Host key verification failed.",
                     "ssh: Could not resolve hostname nope: Name or service not known"):
            with self.subTest(text):
                remote = Remote((255, b"", text))
                code, out, _a = run(remote)
                self.assertEqual((code, len(remote.calls)), (2, 1))
                self.assertIn("ssh refused", out)
                self.assertNotIn("INFRA", out)

    def test_a_multi_line_changed_host_key_banner_is_still_a_refusal(self):
        banner = ("Warning: Permanently added 't2-dev' (ED25519) to the list of known hosts.\n@@@@@@@@@@@@@@@@@@@@\n"
                  "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n@@@@@@@@@@@@@@@@@@@@\n"
                  "Host key verification failed.\n")
        remote = Remote((255, b"", banner))
        code, out, _a = run(remote)
        self.assertEqual((code, len(remote.calls)), (2, 1))
        self.assertIn("ssh refused", out)

    def test_the_stderr_line_is_bounded_and_sanitised(self):
        remote = Remote((255, b"", "\x1b[31m" + "x" * 500 + "\n"))
        _c, out, _a = run(remote, max_infra_polls=1)
        line = out.strip()
        self.assertLess(len(line), 260)
        self.assertNotIn("\x1b", line)

    def test_a_hung_ssh_call_counts_as_a_connection_failure(self):
        with StubSsh("exec sleep 30") as stub:
            t0 = time.monotonic()
            status, out, err = bg_job._ssh_once(GOOD_HOST, "x", 0.5)
        self.assertEqual(status, 255)
        self.assertIn("timed out", err)
        self.assertLess(time.monotonic() - t0, 5)
        stub.assert_reaped()


class StubSsh:
    """A stand-in for /usr/bin/ssh: a shell script (argv ignored unless the body reads it) in a private directory, patched into
    bg_job.SSH. Its pid is written to a file so a test can prove the process was stopped and reaped."""

    def __init__(self, body):
        self.body = body

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.pidfile = self.dir / "pid"
        self.argfile = self.dir / "args"
        script = self.dir / "ssh"
        script.write_text("#!/bin/sh\necho $$ > %s\nfor a in \"$@\"; do printf '%%s\\n' \"$a\" >> %s; done\n%s\n"
                          % (self.pidfile, self.argfile, self.body))
        script.chmod(0o700)
        self.patch = mock.patch.object(bg_job, "SSH", str(script))
        self.patch.start()
        return self

    def __exit__(self, *exc):
        self.patch.stop()
        try:
            self.pid = int(self.pidfile.read_text())
        except (OSError, ValueError):
            self.pid = None
        self.tmp.cleanup()

    def assert_reaped(self):
        import os
        assert self.pid, "the stub never ran"
        try:
            os.kill(self.pid, 0)
        except ProcessLookupError:
            return  # gone: stopped and reaped, not left running or as a zombie
        raise AssertionError("the ssh process %d is still there" % self.pid)


class Command(unittest.TestCase):
    def test_the_ssh_argv_is_fixed_and_the_file_is_one_quoted_word(self):
        import shlex
        hostile = "x; touch /tmp/pwn $(id) `id` 'q' -rf"
        with StubSsh("printf '0\\n'; echo __bgjob_rc=0 >&2") as stub:
            bg_job._poll(GOOD_HOST, shlex.quote(hostile), 7, time.monotonic() + 10)
            argv = stub.argfile.read_text().split("\n")[:-1]
        self.assertEqual(argv[:8], ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5",
                                    "-o", "ServerAliveCountMax=2"])
        self.assertEqual(argv[8:10], ["--", GOOD_HOST])
        self.assertEqual(len(argv), 11)
        self.assertEqual(argv[10], bg_job.REMOTE_TEMPLATE.format(f=shlex.quote(hostile), off=8))
        self.assertNotIn("ssh_binary", dir(bg_job.cmd_wait_remote))

    def test_the_template_distinguishes_absent_from_unreadable(self):
        self.assertIn("exit 10", bg_job.REMOTE_TEMPLATE)
        self.assertIn("exit 11", bg_job.REMOTE_TEMPLATE)
        self.assertIn("head -c 65536", bg_job.REMOTE_TEMPLATE)


class RealTemplate(unittest.TestCase):
    """The real template run in a local POSIX sh (F2): what the remote shell would do with it."""

    def sh(self, path, offset=1, fake_tail=None):
        import shlex
        import os
        command = bg_job.REMOTE_TEMPLATE.format(f=shlex.quote(str(path)), off=offset)
        env = {"PATH": os.environ["PATH"]}
        if fake_tail:
            env["PATH"] = fake_tail + ":" + env["PATH"]
        done = subprocess.run(["/bin/sh", "-c", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=30)
        return done.returncode, done.stdout, done.stderr.decode()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_missing_file_and_directory_have_their_own_exit_codes(self):
        self.assertEqual(self.sh(self.tmp / "nope")[0], 10)
        self.assertEqual(self.sh(self.tmp)[0], 11)

    def test_a_normal_read_gives_the_size_the_bytes_and_a_zero_marker(self):
        f = self.tmp / "log"
        f.write_bytes(b"hello world")
        code, out, err = self.sh(f, offset=7)
        self.assertEqual((code, out.split(b"\n")[0].strip(), out.split(b"\n")[1], err.strip()), (0, b"11", b"world", "__bgjob_rc=0"))

    def test_a_failing_tail_is_visible_not_hidden_by_head(self):
        # F2: `tail | head` returns head's status; a tail that fails must show in the marker and make _poll UNPROVEN
        f = self.tmp / "log"
        f.write_bytes(b"data")
        bindir = self.tmp / "bin"
        bindir.mkdir()
        (bindir / "tail").write_text("#!/bin/sh\nprintf partial\nexit 1\n")
        (bindir / "tail").chmod(0o700)
        code, out, err = self.sh(f, fake_tail=str(bindir))
        self.assertEqual(code, 0)  # head's status: exactly what the marker exists to expose
        self.assertEqual(out.split(b"\n")[1], b"partial")
        self.assertIn("__bgjob_rc=1", err)
        with mock.patch.object(bg_job, "_ssh_once", return_value=(code, out, err)):
            kind, _s, _d, note = bg_job._poll(GOOD_HOST, "'x'", 0, time.monotonic() + 5)
        self.assertEqual(kind, "failed")
        self.assertIn("tail exit 1", note)

    def test_a_missing_read_marker_is_unproven(self):
        with mock.patch.object(bg_job, "_ssh_once", return_value=(0, b"4\ndata", "")):
            self.assertEqual(bg_job._poll(GOOD_HOST, "'x'", 0, time.monotonic() + 5)[0], "failed")

    def test_a_read_cut_off_by_head_at_the_cap_is_a_full_read(self):
        f = self.tmp / "big"
        f.write_bytes(b"x" * (bg_job.READ_CAP * 3))
        code, out, err = self.sh(f)
        self.assertEqual(len(out.partition(b"\n")[2]), bg_job.READ_CAP)
        with mock.patch.object(bg_job, "_ssh_once", return_value=(code, out, err)):
            self.assertEqual(bg_job._poll(GOOD_HOST, "'x'", 0, time.monotonic() + 5)[0], "ok")
        with mock.patch.object(bg_job, "_ssh_once", return_value=(0, b"5\nab", "__bgjob_rc=141\n")):  # 141 on a short read
            self.assertEqual(bg_job._poll(GOOD_HOST, "'x'", 0, time.monotonic() + 5)[0], "failed")


class Capture(unittest.TestCase):
    """F3: both streams are read with a hard byte cap; on overflow the process is stopped and reaped."""

    def test_stdout_past_the_cap_stops_and_reaps_the_process(self):
        with StubSsh("exec yes aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") as stub:
            t0 = time.monotonic()
            status, out, err = bg_job._ssh_once(GOOD_HOST, "x", 20)
        self.assertEqual(status, bg_job.OVERFLOW)
        read = int(re.search(r"after (\d+) bytes", err).group(1))
        self.assertEqual(read, bg_job.READ_CAP + 64)  # capture stopped exactly at the cap, never buffered more
        self.assertLess(time.monotonic() - t0, 10)
        stub.assert_reaped()

    def test_stderr_past_the_cap_is_bounded_and_reaped_too(self):
        with StubSsh("exec yes bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb >&2") as stub:
            status, out, err = bg_job._ssh_once(GOOD_HOST, "x", 20)
        self.assertEqual(status, 255)
        self.assertLessEqual(len(err), 2000)
        stub.assert_reaped()

    def test_a_poll_reports_an_overflow_as_unproven_not_a_match(self):
        with StubSsh("exec yes cccccccccccccccccccccccccccccccc") as stub:
            kind, _s, _d, note = bg_job._poll(GOOD_HOST, "'x'", 0, time.monotonic() + 20)
        self.assertEqual(kind, "failed")
        self.assertIn("read cap", note)
        stub.assert_reaped()

    def test_the_call_bound_applies_even_when_the_budget_is_larger(self):
        with mock.patch.object(bg_job, "SSH_CALL_BOUND", 0.5), StubSsh("exec sleep 30") as stub:
            t0 = time.monotonic()
            status, _o, _e = bg_job._ssh_once(GOOD_HOST, "x", 1000)
        self.assertEqual(status, 255)
        self.assertLess(time.monotonic() - t0, 5)
        stub.assert_reaped()

    def test_a_small_normal_answer_passes_through(self):
        with StubSsh("printf '3\\nabc'; echo __bgjob_rc=0 >&2"):
            self.assertEqual(bg_job._ssh_once(GOOD_HOST, "x", 10), (0, b"3\nabc", "__bgjob_rc=0\n"))


class Deadline(unittest.TestCase):
    """F1: --timeout bounds the whole wait, retries and late answers included."""

    def test_each_attempt_is_capped_at_the_remaining_budget(self):
        remote = Remote(b"", b"")
        run(remote, timeout=2.0)
        self.assertTrue(remote.budgets)
        self.assertTrue(all(b is not None and 0 < b <= 2.0 for b in remote.budgets), remote.budgets)

    def test_a_slow_failed_attempt_leaves_no_time_for_the_retry(self):
        def slow_reset(_i):
            time.sleep(1.3)
            return (255, b"", "Connection reset by peer")

        remote = Remote(slow_reset)
        t0 = time.monotonic()
        code, out, _a = run(remote, timeout=1.0)
        self.assertEqual(code, 3)
        self.assertIn("TIMEOUT", out)
        self.assertEqual(len(remote.calls), 1)  # the retry is not attempted past the deadline
        self.assertLess(time.monotonic() - t0, 4)

    def test_a_match_that_arrives_after_the_deadline_is_not_accepted(self):
        def late_match(i):
            if i == 0:
                return b""
            time.sleep(1.2)
            return b"ALL PASSED\n"

        code, out, _a = run(Remote(late_match), timeout=1.0)
        self.assertEqual(code, 3)
        self.assertIn("TIMEOUT", out)
        self.assertNotIn("LINE_FOUND", out)

    def test_a_real_slow_ssh_is_cut_at_the_remaining_budget_not_the_call_bound(self):
        with StubSsh("exec sleep 30"):
            t0 = time.monotonic()
            status, _o, err = bg_job._ssh_once(GOOD_HOST, "x", 0.4)
        self.assertEqual(status, 255)
        self.assertLess(time.monotonic() - t0, 3)


class Refusals(unittest.TestCase):
    def refused(self, **kw):
        remote = Remote(b"")
        out = io.StringIO()
        with mock.patch.object(bg_job, "_ssh_once", remote), redirect_stdout(out):
            code = bg_job.cmd_wait_remote(args(**kw))
        self.assertEqual(code, 64, (kw, out.getvalue()))
        self.assertEqual(remote.calls, [], kw)  # nothing reached ssh
        return out.getvalue()

    def test_hostile_hosts_never_reach_ssh(self):
        for host in ("-oProxyCommand=touch /x", "-F/etc/passwd", "h ost", "h;id", "a@b@c", "", "a" * 100, ".hidden", "h\nost"):
            with self.subTest(host):
                self.refused(host=host)

    def test_bad_files_texts_and_numbers_never_reach_ssh(self):
        for kw in ({"file": "a\nb"}, {"file": "a\0b"}, {"file": "a\rb"}, {"file": "x" * 513}, {"file": ""},
                   {"file": "~/logs/x"}, {"until_file_line": ""}, {"until_file_line": "a\nb"}, {"until_file_line": "x" * 201},
                   {"fail_line": "a\nb"}, {"timeout": None}, {"timeout": 0}, {"timeout": -1}, {"timeout": float("nan")},
                   {"timeout": 100000}, {"timeout": float("inf")}, {"poll": 0.01}, {"poll": 61}, {"poll": float("nan")},
                   {"max_infra_polls": 0}, {"max_infra_polls": 21}):
            with self.subTest(kw):
                self.refused(**kw)

    def test_the_tilde_refusal_tells_the_caller_what_to_do(self):
        self.assertIn("remote home", self.refused(file="~/logs/x"))

    def test_hostile_file_names_that_are_allowed_reach_ssh_only_quoted(self):
        for name in ("x; touch /tmp/pwn", "$(id)", "`id`", "-rf", "it's"):
            with self.subTest(name):
                remote = Remote(b"", b"ALL PASSED")
                code, _o, _a = run(remote, file=name)
                self.assertEqual(code, 0)
                import shlex
                self.assertIn(shlex.quote(name), remote.calls[0][1])

    def test_secret_and_protected_files_are_refused_before_ssh_by_command_guard(self):
        for name in (".config/goodqa/user-token", "/home/u/.config/gq-browser/key", ".ssh/id_ed25519",
                     "/home/eric/.ssh/id_ed25519", ".kube/config", "/home/u/.aws/credentials",
                     ):
            with self.subTest(name):
                remote = Remote(b"")
                out = io.StringIO()
                with mock.patch.object(bg_job, "_ssh_once", remote), redirect_stdout(out):
                    code = bg_job.cmd_wait_remote(args(file=name))
                self.assertEqual((code, remote.calls), (64, []), name)
                self.assertIn("command_guard", out.getvalue())

    def test_ordinary_logs_including_run_kit_and_claude_logs_are_allowed_by_the_guard(self):
        # the tool's main use: job logs live under ~/.agent-harness/work and ~/.claude
        for path in ("/home/eric/logs/suite.log", "/home/eric/.agent-harness/work/s1/suite.log",
                     ".agent-harness/work/s1/suite.log", "/home/eric/.claude/hooks-test/out.log", "logs/suite.log"):
            with self.subTest(path):
                self.assertEqual(bg_job.file_judged_by_guard(path), (True, ""))

    def test_a_wait_that_always_gets_a_full_read_is_still_bounded_by_the_timeout(self):
        # H1: the read-on shortcut must not skip the deadline
        class Endless:
            calls = 0

            def __call__(self, host, command, budget=None):
                Endless.calls += 1
                return 0, b"%d\n" % (10 ** 17) + b"a" * bg_job.READ_CAP, "__bgjob_rc=0\n"

        t0 = __import__("time").time()
        code, out, _a = run(Endless(), timeout=1.0, include_existing=True)
        self.assertEqual(code, 3)
        self.assertIn("TIMEOUT", out)
        self.assertLess(__import__("time").time() - t0, 5)

    def test_no_guard_means_no_wait(self):
        with mock.patch.dict(sys.modules, {"command_guard": None}):
            allowed, why = bg_job.file_judged_by_guard("/home/eric/logs/suite.log")
        self.assertFalse(allowed)
        self.assertIn("could not judge", why)

    def test_there_is_no_way_to_set_the_ssh_binary_or_options_from_the_command_line(self):
        with mock.patch.object(sys, "argv", ["bg_job.py", "wait-remote", "--host", "h", "--file", "/x", "--until-file-line", "t",
                                             "--timeout", "1", "--ssh", "/bin/sh"]):
            with self.assertRaises(SystemExit):
                with redirect_stdout(io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
                    bg_job.main()


class SshJob(unittest.TestCase):
    def wait_for(self, code, *flags):
        with tempfile.TemporaryDirectory() as tmp:
            record = {"pid": 1, "nonce": "n", "log": "l", "status": str(Path(tmp) / "st")}
            out = io.StringIO()
            with mock.patch.object(bg_job, "load_record", return_value=(record, "")), \
                    mock.patch.object(bg_job, "read_status", return_value=(code, "")), redirect_stdout(out):
                ns = argparse.Namespace(name="job", dir=tmp, timeout=1.0, ssh_job="--ssh-job" in flags)
                return bg_job.cmd_wait(ns), out.getvalue()

    def test_255_is_infra_only_with_the_flag_and_keeps_the_status_visible(self):
        code, out = self.wait_for(255, "--ssh-job")
        self.assertEqual(code, 5)
        self.assertIn("INFRA", out)
        self.assertIn("EXIT_STATUS=255", out)

    def test_without_the_flag_nothing_changes(self):
        code, out = self.wait_for(255)
        self.assertEqual(code, 1)
        self.assertIn("EXITED name=job EXIT_STATUS=255", out)

    def test_other_statuses_are_unchanged_with_the_flag(self):
        self.assertEqual(self.wait_for(0, "--ssh-job")[0], 0)
        self.assertEqual(self.wait_for(1, "--ssh-job")[0], 1)


class Advice(unittest.TestCase):
    def test_the_lint_for_a_remote_wait_loop_names_wait_remote(self):
        import bg_lint
        found = bg_lint.lint("until ssh t2-dev 'grep -q DONE /tmp/x.log'; do sleep 5; done; tail /tmp/x.log")
        text = " ".join(message for _name, message in found)
        self.assertIn("wait-remote", text)

    def test_the_docstring_lists_the_exit_codes(self):
        doc = bg_job.__doc__
        for token in ("LINE_FOUND", "FAIL_LINE_FOUND", "UNPROVEN", "TIMEOUT", "INFRA", "exit 5", "64"):
            self.assertIn(token, doc)


if __name__ == "__main__":
    unittest.main()
