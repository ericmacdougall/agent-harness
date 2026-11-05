"""Hardening found by the gate audit: spec files are read as bounded regular files, never FIFOs or symlinks."""

import contextlib
import io
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import spec_flow as sf  # noqa: E402


class SpecReadTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def test_fifo_is_refused_without_blocking(self):
        fifo = self.dir / "spec.md"
        os.mkfifo(fifo)
        result = []

        def attempt():
            try:
                sf.read_regular(fifo, 1000)
            except sf.SpecError as error:
                result.append(str(error))
        thread = threading.Thread(target=attempt, daemon=True)
        thread.start()
        thread.join(5)
        if thread.is_alive():  # release the stuck open so the test process can exit
            fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
            os.close(fd)
            thread.join(5)
            self.fail("read_regular blocked on a FIFO")
        self.assertTrue(result and "regular file" in result[0], result)

    def test_symlinked_spec_refused_by_lint_packet_and_review(self):
        secret = self.dir / "secret.txt"
        secret.write_text("TOKEN=hunter2\n")
        link = self.dir / "spec.md"
        os.symlink(secret, link)
        for command in (["lint", str(link)], ["packet", str(link), "--out", str(self.dir / "p.md")]):
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                code = sf.main(command)
            self.assertEqual(code, sf.EXIT_USAGE, command)
            self.assertIn("symlink", err.getvalue())

    def test_oversized_spec_refused(self):
        big = self.dir / "big.md"
        big.write_bytes(b"x" * (sf.MAX_SPEC_BYTES + 1))
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = sf.main(["lint", str(big)])
        self.assertEqual(code, sf.EXIT_USAGE)

    def test_regular_spec_still_reads(self):
        ok = self.dir / "ok.md"
        ok.write_text("# Spec: x\n")
        self.assertEqual(sf.read_spec_text(ok), "# Spec: x\n")



class CommitMessageFileTests(unittest.TestCase):
    def test_fifo_message_file_is_unresolvable_not_a_hang(self):
        import commit_policy as cp
        fifo = Path(tempfile.mkdtemp()) / "msg"
        os.mkfifo(fifo)
        outcome = []

        def attempt():
            try:
                cp.resolve_commit(["-F", str(fifo)], "/", None, {})
            except cp.Unresolvable as error:
                outcome.append(str(error))
            except Exception as error:  # noqa: BLE001
                outcome.append("other:" + type(error).__name__)
        thread = threading.Thread(target=attempt, daemon=True)
        thread.start()
        thread.join(5)
        if thread.is_alive():
            fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
            os.close(fd)
            thread.join(5)
            self.fail("resolve_commit blocked reading a FIFO message file")
        self.assertTrue(outcome and "regular file" in outcome[0], outcome)


if __name__ == "__main__":
    unittest.main()
