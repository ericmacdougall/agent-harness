"""Command strings are non-executing parser fixtures, never shell commands."""
import unittest

from test_merge_gate import mg


class InertArgumentPositions(unittest.TestCase):
    def test_exact_remote_metadata_paths_are_data(self):
        command = ("ssh t2-dev 'ls -l /home/eric/.local/bin/gh /home/eric/bin/gh "
                   "/usr/local/bin/gh /usr/bin/gh /home/eric/.config/gh/hosts.yml'")
        self.assertEqual(mg.find_merges(command), [])

    def test_literal_metadata_and_test_operands_are_data(self):
        for command in ('ls -l /usr/bin/gh /usr/local/bin/gh',
                        'test -x /usr/bin/gh', '[ -f /usr/bin/gh ]',
                        'if test -x /usr/bin/gh; then printf present; fi',
                        "printf '%s\\n' /usr/bin/gh", 'stat /usr/bin/gh',
                        'ls /usr/bin/python3 /usr/bin/bash /usr/bin/gh'):
            with self.subTest(command=command):
                self.assertEqual(mg.find_merges(command), [])

    def test_substitutions_and_executor_pipelines_are_still_detected(self):
        for command in ('ls "$(gh pr merge 5 --repo o/r)"',
                        'test -n "$(gh pr merge 5 --repo o/r)"',
                        'ls $(gh pr merge 5 --repo o/r)',
                        "printf '%s' 'gh pr merge 5 --repo o/r' | sh",
                        "echo 'gh pr merge 5 --repo o/r' | xargs sh -c"):
            with self.subTest(command=command):
                self.assertTrue(mg.find_merges(command))

    def test_actual_merge_api_wrappers_and_runtime_forms_are_still_detected(self):
        for command in ('gh pr merge 5 --repo o/r',
                        "gh api graphql -f query='mutation { mergePullRequest(input:{pullRequestId:\"ID\"}) { clientMutationId } }'",
                        'env gh pr merge 5 --repo o/r', 'sudo gh pr merge 5 --repo o/r',
                        'find . -exec gh pr merge 5 --repo o/r \\;',
                        'printf 5 | xargs gh pr merge --repo o/r',
                        "bash -c 'gh pr merge 5 --repo o/r'",
                        'PATH=/unknown ls /usr/bin/gh /other',
                        'PATH=/unknown; ls /usr/bin/gh /other',
                        "python3 -c 'import subprocess; subprocess.run([\"gh\",\"pr\",\"merge\",\"5\"])'",
                        'rg --pre gh pr merge 5', '$EXECUTABLE /usr/bin/gh pr merge 5'):
            with self.subTest(command=command):
                self.assertTrue(mg.find_merges(command))

    def test_grouped_shell_operators_do_not_hide_a_following_executable(self):
        for command in ('SUB=$(echo merge); gh pr $SUB 5',
                        'ls $(echo file); gh pr merge 5 --repo o/r'):
            with self.subTest(command=command):
                self.assertTrue(mg.find_merges(command))
