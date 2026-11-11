"""Local launcher contract only: every exec is a double, never the native helper."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "harness" / "hooks" / "goodqa_browser.py"
SPEC = importlib.util.spec_from_file_location("goodqa_browser", SOURCE)
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)
EXPECTED_HELPER = "/Applications/goodqa.app/Contents/Resources/agent/goodqa-agentd"
UNAVAILABLE = "goodqa-local-browser: native browser client unavailable\n"
USAGE = "goodqa-local-browser: no arguments are supported\n"


class ExecHandoff(BaseException):
    """Stand in for exec's nonreturning process-image replacement."""


class LauncherContract(unittest.TestCase):
    def run_launcher(self, args=(), *, mode=stat.S_IFREG | 0o755,
                     stat_error=None, exec_error=None, exec_returns=False):
        out, err = io.StringIO(), io.StringIO()
        info = os.stat_result((mode, 0, 0, 1, 501, 20, 1, 0, 0, 0))
        effect = None if exec_returns else (exec_error or ExecHandoff())
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                patch.object(launcher.os, "lstat", return_value=info,
                             side_effect=stat_error) as inspected, \
                patch.object(launcher.os, "execv", side_effect=effect) as executed:
            try:
                result = launcher.main(None if args is None else list(args))
            except ExecHandoff:
                result = "exec"
        return result, out.getvalue(), err.getvalue(), inspected, executed

    def assert_unavailable(self, result):
        code, out, err, _, _ = result
        self.assertEqual(code, 69)
        self.assertEqual(out, "")
        self.assertEqual(err, UNAVAILABLE)

    def test_fixed_vector_hands_off_without_waiting_or_output(self):
        code, out, err, inspected, executed = self.run_launcher()
        self.assertEqual(code, "exec")
        self.assertEqual((out, err), ("", ""))
        inspected.assert_called_once_with(EXPECTED_HELPER)
        executed.assert_called_once_with(EXPECTED_HELPER,
            [EXPECTED_HELPER, "browser-client", "mcp-stdio"])

    def test_all_operands_refuse_before_helper_inspection(self):
        for args in [("--help",), ("--agent", "other"), ("--",), ("",)]:
            with self.subTest(args=args):
                code, out, err, inspected, executed = self.run_launcher(args)
                self.assertEqual((code, out, err), (64, "", USAGE))
                inspected.assert_not_called()
                executed.assert_not_called()

    def test_missing_helper_has_fixed_error_and_no_exec(self):
        result = self.run_launcher(stat_error=FileNotFoundError("synthetic-private-detail"))
        self.assert_unavailable(result)
        result[-1].assert_not_called()

    def test_unreadable_metadata_has_no_exception_reflection(self):
        result = self.run_launcher(stat_error=PermissionError("synthetic-private-detail"))
        self.assert_unavailable(result)
        result[-1].assert_not_called()

    def test_symlink_is_not_an_admitted_helper(self):
        result = self.run_launcher(mode=stat.S_IFLNK | 0o777)
        self.assert_unavailable(result)
        result[-1].assert_not_called()

    def test_nonregular_helper_types_refuse(self):
        for kind in [stat.S_IFDIR, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFBLK]:
            with self.subTest(kind=kind):
                result = self.run_launcher(mode=kind | 0o755)
                self.assert_unavailable(result)
                result[-1].assert_not_called()

    def test_helper_without_execute_bits_refuses(self):
        result = self.run_launcher(mode=stat.S_IFREG | 0o644)
        self.assert_unavailable(result)
        result[-1].assert_not_called()

    def test_exec_permission_error_is_truthful_fixed_failure(self):
        result = self.run_launcher(exec_error=PermissionError("synthetic-private-detail"))
        self.assert_unavailable(result)
        result[-1].assert_called_once()

    def test_helper_disappearing_after_inspection_refuses(self):
        self.assert_unavailable(self.run_launcher(exec_error=FileNotFoundError("synthetic-private-detail")))

    def test_unexpected_exec_return_cannot_report_success(self):
        self.assert_unavailable(self.run_launcher(exec_returns=True))

    def test_default_argv_accepts_only_no_operands(self):
        with patch.object(sys, "argv", ["reviewed-wrapper"]):
            self.assertEqual(self.run_launcher(None)[0], "exec")
        with patch.object(sys, "argv", ["reviewed-wrapper", "--url", "synthetic"]):
            code, out, err, inspected, executed = self.run_launcher(None)
            self.assertEqual((code, out, err), (64, "", USAGE))
            inspected.assert_not_called()
            executed.assert_not_called()

    def test_environment_cannot_choose_target_or_registration(self):
        with patch.dict(os.environ, {"GOODQA_HELPER": "/synthetic/other",
                "GOODQA_AGENT_ID": "sibling", "GOODQA_REGISTRATION": "sibling"}):
            result = self.run_launcher()
        self.assertEqual(result[0], "exec")
        result[-1].assert_called_once_with(EXPECTED_HELPER,
            [EXPECTED_HELPER, "browser-client", "mcp-stdio"])


if __name__ == "__main__":
    unittest.main()
