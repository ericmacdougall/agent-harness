"""Neither the command guard nor the kill guard ever refuses the off switch (harness redesign 2026-11-24).

`harness off` is the owner's way out when a guard misbehaves; a guard that refused it would lock the owner in. Every
command string here is DATA handed to decide()/hook_main(); nothing executes it.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / 'harness' / 'hooks'
sys.path.insert(0, str(HOOKS))

import command_guard as cg  # noqa: E402
import kill_guard as kg  # noqa: E402

SWITCH = ('harness off', 'harness on', 'harness status', '~/.agent-harness/bin/harness off',
          '~/.agent-harness/bin/harness on', '$HOME/.agent-harness/bin/harness off',
          'python3 ~/.claude/hooks/ah_switch.py off', 'python3 ~/.claude/hooks/ah_switch.py on',
          'python3 ~/.claude/hooks/ah_switch.py status', 'ah off', 'ah on',
          'python3 ~/.claude/hooks/ah.py off', 'python3 ~/.claude/hooks/ah.py on')


class GuardsAllowTheSwitch(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='switch-')
        self.addCleanup(tmp.cleanup)
        self.home = os.path.realpath(tmp.name)
        env = mock.patch.dict(os.environ, {'HOME': self.home, 'AH_HOME': self.home})
        env.start()
        self.addCleanup(env.stop)
        self.commands = SWITCH + tuple(c.replace('~', self.home) for c in SWITCH if '~' in c)

    def payload(self, command, model='claude-sonnet-5'):
        return {'tool_name': 'Bash', 'tool_input': {'command': command}, 'session_id': '11111111-2222-3333-4444-555555555555',
                'cwd': self.home, 'model': model}

    def test_the_command_guard_never_refuses_it(self):
        compiled = cg.Compiled(cg.load_policy(), home=self.home, cwd=self.home)
        for command in self.commands:
            with self.subTest(command=command):
                self.assertNotEqual(cg.decide(command, compiled, cwd=self.home, payload=self.payload(command))[0],
                                    'block')
                out, err = io.StringIO(), io.StringIO()
                data = json.dumps(self.payload(command)).encode()
                with mock.patch('sys.stdout', new=out), mock.patch('sys.stderr', new=err):
                    self.assertEqual(cg.hook_main(stdin_bytes=data, marker=False), 0, err.getvalue())

    def test_the_kill_guard_never_refuses_it(self):
        for command in self.commands:
            with self.subTest(command=command):
                self.assertNotEqual(kg.decide(command, cwd=self.home, home=self.home,
                                              payload=self.payload(command))[0], 'block')
                with mock.patch('sys.stdout', new=io.StringIO()), mock.patch('sys.stderr', new=io.StringIO()):
                    self.assertEqual(kg.hook_main(json.dumps(self.payload(command)).encode()), 0)


if __name__ == '__main__':
    unittest.main()
