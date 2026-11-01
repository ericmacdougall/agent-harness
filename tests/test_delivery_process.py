"""Real child processes protect delivery's deadline and output cleanup contract."""

import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'


@unittest.skipUnless(os.name == 'posix', 'Delivery process groups require POSIX')
class DeliveryProcessCleanup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(HOOKS))
        try:
            spec = importlib.util.spec_from_file_location('delivery_process_test', HOOKS / 'deliver.py')
            cls.delivery = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.delivery)
        finally:
            sys.path.remove(str(HOOKS))

    def assert_descendant_stopped(self, *, leader_exits, overflow=False):
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / 'owned-child.json'
            child = (
                'import json,os,signal,time\nfrom pathlib import Path\n'
                'signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
                f'Path({str(pid_file)!r}).write_text(json.dumps({{"pid":os.getpid(),"group":os.getpgrp()}}))\n'
                'time.sleep(30)\n'
            )
            leader = (
                'import subprocess,sys,time\nfrom pathlib import Path\n'
                f'subprocess.Popen([sys.executable,"-c",{child!r}])\n'
                f'pid_file=Path({str(pid_file)!r})\n'
                'deadline=time.monotonic()+3\n'
                'while not pid_file.exists() and time.monotonic()<deadline: time.sleep(.01)\n'
                'if not pid_file.exists(): raise SystemExit(9)\n'
            )
            if overflow:
                leader += 'sys.stdout.write("x"*1024); sys.stdout.flush()\n'
            leader += 'raise SystemExit(0)\n' if leader_exits else 'time.sleep(30)\n'
            try:
                with self.assertRaises(self.delivery.DeliveryError) as refused:
                    self.delivery.bounded([sys.executable, '-c', leader], timeout=5,
                                          limit=64 if overflow else 4096)
                self.assertTrue(pid_file.exists(), 'Child must start before exercising cleanup')
                self.assertEqual(refused.exception.status, 'BLOCKED_LOCAL')
                if overflow:
                    self.assertEqual(refused.exception.facts.get('reason'), 'OUTPUT_LIMIT')
                else:
                    self.assertIn('timed out', refused.exception.message)
                child_state = json.loads(pid_file.read_text())
                deadline = time.monotonic() + 3
                while True:
                    # An orphan may briefly be a zombie before the system reaps it.
                    state = subprocess.run(['ps', '-p', str(child_state['pid']), '-o', 'stat='],
                                           capture_output=True, text=True, timeout=3).stdout.strip()
                    if not state or state.startswith('Z') or time.monotonic() >= deadline:
                        break
                    time.sleep(.02)
                self.assertFalse(state and not state.startswith('Z'),
                                 'A TERM-ignoring descendant survived delivery cleanup')
            finally:
                if pid_file.exists():
                    child_state = json.loads(pid_file.read_text())
                    try:
                        os.killpg(child_state['group'], signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_exited_leader_does_not_skip_descendant_timeout_cleanup(self):
        self.assert_descendant_stopped(leader_exits=True)

    def test_term_exited_leader_does_not_skip_descendant_timeout_cleanup(self):
        self.assert_descendant_stopped(leader_exits=False)

    def test_output_limit_also_stops_descendant_after_leader_exits(self):
        self.assert_descendant_stopped(leader_exits=True, overflow=True)
