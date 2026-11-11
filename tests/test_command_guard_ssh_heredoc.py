"""GoodQA #15646: public command strings are DATA, never executed.

CG_HOOKS_DIR can select the untouched source for failure-first evidence. These
tests call analyzer APIs only; any attempted child execution fails the test.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('CG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))
import command_guard as cg
import kill_guard as kg

HOST = 'public-fixture.invalid'
BENIGN = "print(set(['a']))"


def heredoc(command, body=BENIGN, quoted=True, fd=''):
    delimiter = "'PUBLIC_PYTHON'" if quoted else 'PUBLIC_PYTHON'
    return command + ' ' + fd + '<<' + delimiter + '\n' + body + '\nPUBLIC_PYTHON'


class Unowned:
    def check(self, pid, main_netwatch=False):
        return False, 'fixture-unowned', 'the public fixture owns no processes'


class SSHHeredoc(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='cg-public-ssh-')
        self.addCleanup(temporary.cleanup)
        self.home = temporary.name
        self.compiled = cg.Compiled(cg.load_policy(path=self.home + '/absent-cg.json'),
                                    home=self.home, cwd=self.home)
        self.policy = kg.load_policy(self.home + '/absent-kg.json')
        child = mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('fixture execution is forbidden'))
        self.child = child.start()
        self.addCleanup(child.stop)
        self.addCleanup(lambda: self.assertEqual(self.child.call_count, 0, 'analyzer attempted child execution'))
        audit = mock.patch.object(kg, 'audit')
        audit.start()
        self.addCleanup(audit.stop)

    def command(self, text):
        return cg.decide(text, self.compiled, cwd=self.home)

    def signaling(self, text):
        return kg.decide(text, cwd=self.home, compiled=self.compiled, home=self.home,
                         policy=self.policy, ownership=Unowned())

    def parsed(self, text):
        context = cg.Ctx(self.compiled, self.home, False)
        pipeline = cg.parse(cg.Lexer(context, False).lex(text))[0]
        command = pipeline.cmds[0]
        return command.redirs[0], command.words, pipeline

    def test_direct_python_control(self):
        self.assertEqual(self.command(heredoc('python3 -'))[0], 'allow')

    def test_closed_remote_python_stdin_is_code(self):
        commands = (
            "ssh %s 'python3 -'" % HOST,
            'ssh %s python3 -' % HOST,
            'ssh -T %s python3 -' % HOST,
            "ssh -q -p2222 %s '/usr/bin/python3 -I -u - argument'" % HOST,
            "ssh -o BatchMode=yes -oConnectTimeout=3 %s 'python3 -B -'" % HOST,
            "ssh -l public %s 'python -'" % HOST,
            "ssh -- %s 'python3 -'" % HOST,
            'ssh %s -- python3 -' % HOST,
            "/usr/bin/ssh %s 'pypy3 -'" % HOST,
            "ssh %s 'python3.11 -'" % HOST,
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.command(heredoc(command))[0], 'allow')

    def test_shell_and_python_environment_output_stays_blocked(self):
        bodies = (
            ('ssh ' + HOST, 'set'),
            ("ssh %s 'sh -s'" % HOST, 'set'),
            ("ssh %s 'bash -s'" % HOST, 'env'),
            ("ssh %s 'python3 -'" % HOST, 'import os; print(os.environ)'),
            ("ssh %s 'python3 -'" % HOST, 'import os; print(dict(os.environ))'),
        )
        for command, body in bodies:
            with self.subTest(command=command, body=body):
                verdict, message = self.command(heredoc(command, body))
                self.assertEqual(verdict, 'block')
                self.assertIn('env', message)

    def test_unsupported_consumers_retain_shell_analysis(self):
        commands = (
            "ssh %s 'python3 -c pass'" % HOST,
            "ssh %s 'python3 -m public_fixture'" % HOST,
            "ssh %s 'python3 public_fixture.py'" % HOST,
            "ssh %s 'env python3 -'" % HOST,
            "ssh %s 'X=public python3 -'" % HOST,
            "ssh %s 'sh -c \"python3 -\"'" % HOST,
            "ssh %s 'python3 -; sh'" % HOST,
            "ssh %s 'python3 - | sh'" % HOST,
            "ssh %s 'python3 - < public-input'" % HOST,
            "ssh %s 'python3 - # comment'" % HOST,
            "ssh %s 'python3 -\n'" % HOST,
            "ssh %s '$PUBLIC_PROGRAM -'" % HOST,
            "ssh %s 'python* -'" % HOST,
            "ssh -n %s 'python3 -'" % HOST,
            "ssh -f %s 'python3 -'" % HOST,
            "ssh -N %s 'python3 -'" % HOST,
            "ssh -s %s 'python3 -'" % HOST,
            "ssh -G %s 'python3 -'" % HOST,
            "ssh -F public-config %s 'python3 -'" % HOST,
            "ssh -o RemoteCommand=sh %s 'python3 -'" % HOST,
            "ssh -o ProxyCommand=public-proxy %s 'python3 -'" % HOST,
            "ssh %s -p 2222 'python3 -'" % HOST,
            "ssh -p %s 'python3 -'" % HOST,
            "ssh -qTn %s 'python3 -'" % HOST,
            "ssh $PUBLIC_HOST 'python3 -'",
            "PROGRAM=python3; ssh %s '$PROGRAM -'" % HOST,
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.command(heredoc(command))[0], 'block')

    def test_only_unambiguous_stdin_heredoc_qualifies(self):
        command = "ssh %s 'python3 -'" % HOST
        rows = [heredoc(command, fd='1'), heredoc(command, fd='3'),
                heredoc(command + ' < public-input'),
                command + " <<'PUBLIC_PYTHON' < public-input\n" + BENIGN + '\nPUBLIC_PYTHON',
                'printf public | ' + heredoc(command),
                command + " <<'FIRST' <<'SECOND'\n" + BENIGN + '\nFIRST\n' + BENIGN + '\nSECOND']
        for row in rows:
            with self.subTest(row=row):
                self.assertEqual(self.command(row)[0], 'block')
        self.assertEqual(self.command(heredoc(command, fd='0'))[0], 'allow')

    def test_local_expansions_are_scanned_only_for_unquoted_delimiter(self):
        command = "ssh %s 'python3 -'" % HOST
        for body in ('print("$(env)")', 'print("`env`")', 'print("$PUBLIC_SECRET_TOKEN")'):
            with self.subTest(body=body):
                self.assertEqual(self.command(heredoc(command, body, quoted=True))[0], 'allow')
                self.assertEqual(self.command(heredoc(command, body, quoted=False))[0], 'block')
        self.assertEqual(self.command(heredoc(command, 'print("$(printf public)")', quoted=False))[0], 'allow')

    def test_remote_python_body_uses_existing_signaling_policy(self):
        command = "ssh %s 'python3 -'" % HOST
        for body in ('import os; os.kill(424242, 15)', 'import os; os.killpg(424242, 15)',
                     'process.terminate()', 'import subprocess; subprocess.run(["kill", "424242"])'):
            with self.subTest(body=body):
                verdict, rule, _message, _pids = self.signaling(heredoc(command, body))
                self.assertEqual((verdict, rule), ('block', 'script-kill'))
        self.assertEqual(self.signaling(heredoc(command))[0], 'allow')

    def test_local_and_shell_signaling_controls_stay_blocked(self):
        for row in (heredoc('python3 -', 'import os; os.kill(424242, 15)'),
                    "python3 -c 'import os; os.kill(424242, 15)'",
                    heredoc("ssh %s 'sh -s'" % HOST, 'kill 424242')):
            with self.subTest(row=row):
                self.assertEqual(self.signaling(row)[0], 'block')
        # Existing policy removes signal-zero liveness checks; preserve that verdict.
        self.assertEqual(self.signaling(heredoc("ssh %s 'python3 -'" % HOST,
                                               'import os; os.kill(424242, 0)'))[0], 'allow')

    def test_unknown_subclass_retains_script_traversal(self):
        class Recorder(cg.Analyzer):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.calls = []

            def script(self, text, depth, tail_visible=None, ps=None):
                self.calls.append(('script', text))

            def code(self, text, depth):
                self.calls.append(('code', text))

        rd, words, pipeline = self.parsed(heredoc("ssh %s 'python3 -'" % HOST))
        analyzer = Recorder(self.compiled, cwd=self.home)
        analyzer.heredoc(rd, 'ssh', words, pipeline, 0, 0)
        self.assertEqual(analyzer.calls, [('script', rd.body)])

    def test_kill_subclass_keeps_script_traversal_and_real_body_context(self):
        cls = kg.make_analyzer_class(cg)
        analyzer = cls(self.compiled, self.home, False, Unowned(), self.policy, '', main=False)
        rd, words, pipeline = self.parsed(heredoc("ssh %s 'python3 -'" % HOST))
        calls = []
        with mock.patch.object(analyzer, 'script', side_effect=lambda text, *a, **kw: calls.append(text)), \
                mock.patch.object(analyzer, 'check_interpreter') as policy:
            analyzer.heredoc(rd, 'ssh', words, pipeline, 0, 0)
        self.assertEqual(calls, [rd.body])
        policy.assert_called_once_with('python3', [], pipeline.cmds[0])

    def test_classification_does_not_change_caller_parse_state(self):
        analyzer = cg.Analyzer(self.compiled, cwd=self.home)
        analyzer.ctx.vars['PUBLIC'] = 'value'
        analyzer.ctx.aliases['public_alias'] = 'echo'
        rd, words, pipeline = self.parsed(heredoc("ssh %s 'python3 -'" % HOST))
        before = analyzer.ctx.state()
        findings = list(analyzer.ctx.findings)
        self.assertTrue(analyzer._ssh_python_stdin(rd, words, pipeline, 0))
        self.assertEqual(analyzer.ctx.state(), before)
        self.assertEqual(analyzer.ctx.findings, findings)
        # A second lexical pass with an incomplete remote quote must remain isolated.
        words[-1].alts = ["python3 - '"]
        self.assertFalse(analyzer._ssh_python_stdin(rd, words, pipeline, 0))
        self.assertEqual(analyzer.ctx.state(), before)


if __name__ == '__main__':
    unittest.main()
