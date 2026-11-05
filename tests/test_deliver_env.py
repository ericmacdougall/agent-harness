"""deliver.py main(): GIT_EDITOR is ignored, store-redirection variables are scrubbed, routing variables still refuse."""
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))


def load_deliver():
    spec = importlib.util.spec_from_file_location("deliver_env_under_test", HOOKS / "deliver.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


deliver = load_deliver()


class GitEditor(unittest.TestCase):
    def main_with(self, env, result=0):
        args = SimpleNamespace(phase="finish")
        with mock.patch.object(deliver, "parse_args", return_value=args), \
                mock.patch.object(deliver, "finish", return_value=result) as finish, \
                mock.patch.dict(os.environ, env, clear=False):
            code = deliver.main()
            return code, finish.called, dict(os.environ)

    def test_editor_variables_are_ignored_and_removed_for_children(self):
        code, called, environ = self.main_with({"GIT_EDITOR": "vim", "GIT_SEQUENCE_EDITOR": "vim"})
        self.assertEqual((code, called), (0, True))
        self.assertNotIn("GIT_EDITOR", environ)
        self.assertNotIn("GIT_SEQUENCE_EDITOR", environ)

    def test_routing_variables_still_refuse_and_the_message_names_them(self):
        out = []
        with mock.patch.object(deliver, "report", lambda status, message, **kw: out.append((status, message))):
            code, called, _ = self.main_with({"GIT_DIR": "/x", "GIT_WORK_TREE": "/y"})
        self.assertEqual((code, called), (2, False))
        self.assertEqual(out[0][0], "BLOCKED_POLICY")
        self.assertIn("GIT_DIR", out[0][1])
        self.assertIn("GIT_WORK_TREE", out[0][1])

    def test_store_redirection_variables_are_removed_before_a_real_run(self):  # review F5
        code, called, environ = self.main_with({"HARNESS_TEST_SCOPE_ROOT": "/tmp/x", "HARNESS_TEST_SCOPE_HOST": "evil"})
        self.assertEqual((code, called), (0, True))
        self.assertNotIn("HARNESS_TEST_SCOPE_ROOT", environ)
        self.assertNotIn("HARNESS_TEST_SCOPE_HOST", environ)

    def test_allowed_variables_are_untouched(self):
        code, called, environ = self.main_with({"GIT_AUTHOR_NAME": "t", "GIT_PAGER": "cat"})
        self.assertEqual((code, called), (0, True))
        self.assertEqual(environ["GIT_AUTHOR_NAME"], "t")


if __name__ == "__main__":
    unittest.main()
