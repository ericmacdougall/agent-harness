"""Control for the shell sandbox gate: each missing condition refuses, the full set opens, and the real-shell classes
in tests/test_ah_run.py are wired to it. These tests never run a shell."""
import os
import unittest
from unittest import mock

from tests import shell_sandbox


def _open_gate(**over):
    """Keyword probes describing a correct sandbox; override one to break one condition."""
    env = {shell_sandbox.ENV: '1', 'HOME': '/home/sandbox'}
    probes = dict(
        env=env,
        geteuid=lambda: 10001,
        which=lambda name: None,
        exists=lambda path: path == '/.dockerenv',
        access=lambda path, mode: False,
        listdir=lambda path: ['lo'] if path == '/sys/class/net' else [],
        read=lambda: '0::/\n',
    )
    probes.update(over)
    return probes


class Conditions(unittest.TestCase):
    def test_a_correct_sandbox_opens_the_gate(self):
        self.assertEqual(shell_sandbox.reasons(**_open_gate()), [])

    def test_each_missing_condition_is_named(self):
        cases = {
            'marker env': _open_gate(env={'HOME': '/home/sandbox'}),
            'root': _open_gate(geteuid=lambda: 0),
            'sudo on PATH': _open_gate(which=lambda name: '/usr/bin/sudo' if name == 'sudo' else None),
            'doas on PATH': _open_gate(which=lambda name: '/usr/bin/doas' if name == 'doas' else None),
            'sudo at a fixed path': _open_gate(exists=lambda path: path in ('/.dockerenv', '/usr/local/bin/sudo')),
            'su executable': _open_gate(access=lambda path, mode: path == '/usr/bin/su'),
            'no container marker': _open_gate(exists=lambda path: False),
            'network interface': _open_gate(listdir=lambda path: ['lo', 'eth0']),
            'no /sys/class/net': _open_gate(listdir=mock.Mock(side_effect=OSError)),
            'HOME unset': _open_gate(env={shell_sandbox.ENV: '1'}),
            'credential path': _open_gate(exists=lambda path: path in ('/.dockerenv', '/home/sandbox/.ssh')),
        }
        for label, probes in cases.items():
            with self.subTest(label):
                missing = shell_sandbox.reasons(**probes)
                self.assertEqual(len(missing), 1, (label, missing))
        combined = shell_sandbox.reasons(**_open_gate(geteuid=lambda: 0, listdir=lambda path: ['lo', 'eth0'], env={}))
        self.assertEqual(len(combined), 4, combined)  # root, interface, marker env, HOME

    def test_container_marker_forms(self):
        self.assertEqual(shell_sandbox.reasons(**_open_gate(exists=lambda path: path == '/run/.containerenv')), [])
        self.assertEqual(shell_sandbox.reasons(**_open_gate(exists=lambda path: False, env={shell_sandbox.ENV: '1', 'HOME': '/h', 'container': 'podman'})), [])
        self.assertEqual(shell_sandbox.reasons(**_open_gate(exists=lambda path: False, read=lambda: '0::/system.slice/docker-abc.scope\n')), [])
        self.assertEqual(len(shell_sandbox.reasons(**_open_gate(exists=lambda path: False, read=mock.Mock(side_effect=OSError)))), 1)

    def test_require_raises_skiptest_naming_every_reason(self):
        with mock.patch.object(shell_sandbox, 'reasons', return_value=['running as root', 'network interfaces besides lo: eth0']):
            with self.assertRaises(unittest.SkipTest) as caught:
                shell_sandbox.require()
        self.assertIn('running as root; network interfaces besides lo: eth0', str(caught.exception))
        with mock.patch.object(shell_sandbox, 'reasons', return_value=[]):
            shell_sandbox.require()

    def test_this_host_is_refused_unless_it_is_the_sandbox(self):
        """On a developer or delivery host at least one condition fails; inside the runner none does."""
        missing = shell_sandbox.reasons()
        if os.environ.get(shell_sandbox.ENV) == '1':
            self.assertEqual(missing, [])
        else:
            self.assertTrue(missing)


class Wiring(unittest.TestCase):
    """Every class that hands shape strings to a real shell refuses to start when the gate is closed."""
    CLASSES = ('Differential', 'EndState', 'HeredocRule')

    def test_each_real_shell_class_calls_the_gate_first(self):
        from tests import test_ah_run
        for name in self.CLASSES:
            with self.subTest(name):
                cls = getattr(test_ah_run, name)
                with mock.patch.object(shell_sandbox, 'reasons', return_value=['closed for the control']):
                    with self.assertRaises(unittest.SkipTest):
                        cls.setUpClass()

    def test_other_classes_are_not_gated(self):
        """The launcher and hook classes run fixed benign commands (Equivalence included) and keep running on every host."""
        from tests import test_ah_run
        with mock.patch.object(shell_sandbox, 'reasons', return_value=['closed for the control']):
            for name in ('Launcher', 'RewriteHook', 'SshRewrite', 'PausedGroup', 'Equivalence'):
                getattr(test_ah_run, name).setUpClass()
