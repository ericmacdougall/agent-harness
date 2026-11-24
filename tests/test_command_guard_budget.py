"""H23: the command guard's analysis budget is charged in CPU time, with a wall-clock ceiling behind it.

On a loaded machine the old 3 s wall-clock budget expired on ordinary commands, and the guard refused them as
unanalysable. Budget now reads command_guard.CPU_CLOCK for its limit (limits max_seconds) and command_guard.WALL_CLOCK
only for a much larger ceiling (limits max_wall_seconds). The tests replace those two names with fake clocks, so no
test sleeps and no other deadline in the guard (file reads, git, scans) sees the fake time. Commands are data passed to
decide(), never run."""

import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'harness/hooks'))
sys.path.insert(0, str(ROOT))
import command_guard as cg  # noqa: E402
import command_guard_hook  # noqa: E402
import kill_guard  # noqa: E402

# reads a protected location, so a budget stop refuses it, but is allowed when the analysis finishes; long enough
# that the budget reads its clocks many times
ORDINARY = '; '.join(['wc -l ~/.claude/projects/p/s.jsonl'] * 80)


class Clock:
    """A fake clock: `first` on the first read, then `then` plus `step` per later read."""

    def __init__(self, first=0.0, then=0.0, step=0.0):
        self.first, self.then, self.step, self.reads = first, then, step, 0

    def __call__(self):
        self.reads += 1
        return self.first if self.reads == 1 else self.then + self.step * (self.reads - 2)


class BudgetCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='cg-budget-')
        self.addCleanup(tmp.cleanup)
        self.home = Path(os.path.realpath(tmp.name))
        (self.home / '.claude/projects/p').mkdir(parents=True)
        (self.home / '.claude/projects/p/s.jsonl').write_text('{}\n')
        (self.home / 'w').mkdir()
        patch = mock.patch.dict(os.environ, {'HOME': str(self.home)})
        patch.start()
        self.addCleanup(patch.stop)
        self.compiled = cg.Compiled(cg.load_policy(), cwd=str(self.home / 'w'))

    def decide(self, command, cpu=None, wall=None):
        with mock.patch.object(cg, 'CPU_CLOCK', cpu or cg.CPU_CLOCK), \
                mock.patch.object(cg, 'WALL_CLOCK', wall or cg.WALL_CLOCK):
            return cg.decide(command, self.compiled, cwd=str(self.home / 'w'))


class CpuBudget(BudgetCase):
    def test_the_control_command_is_allowed_with_real_clocks(self):
        self.assertEqual(self.decide(ORDINARY)[0], 'allow')

    def test_a_command_past_the_cpu_budget_is_refused_and_says_so(self):
        cpu = Clock(first=0.0, then=0.0, step=1.0)  # one CPU second per read: past 3 s by the fourth
        verdict, message = self.decide(ORDINARY, cpu=cpu)
        self.assertEqual(verdict, 'block')
        self.assertIn('CPU-time budget', message)
        self.assertNotIn('wall-clock', message)

    def test_an_ordinary_command_passes_when_the_machine_keeps_it_waiting(self):
        # 8 s of wall-clock time pass (the old budget was 3 s), but the analysis used almost no CPU
        wall = Clock(first=0.0, then=8.0)
        self.assertEqual(self.decide(ORDINARY, wall=wall)[0], 'allow')
        self.assertGreater(wall.reads, 2)  # the budget really read the inflated clock

    def test_charging_waiting_time_again_would_refuse_that_command(self):
        # the broken variant: a budget that reads the wall clock for its limit (the old behaviour) refuses the control
        inflated = Clock(first=0.0, then=8.0)
        verdict, message = self.decide(ORDINARY, cpu=inflated)
        self.assertEqual(verdict, 'block')
        self.assertIn('CPU-time budget', message)

    def test_a_stuck_analysis_still_stops_at_the_wall_clock_ceiling(self):
        wall = Clock(first=0.0, then=cg.WALL_CEILING_SECONDS + 1)
        verdict, message = self.decide(ORDINARY, wall=wall)
        self.assertEqual(verdict, 'block')
        self.assertIn('wall-clock ceiling', message)

    def test_the_node_limit_is_unchanged_and_named(self):
        self.compiled.limits = dict(self.compiled.limits, max_nodes=10)
        verdict, message = self.decide(ORDINARY)
        self.assertEqual(verdict, 'block')
        self.assertIn('too large or complex', message)
        self.assertEqual(cg.DEFAULT_POLICY['limits']['max_nodes'], 600000)
        self.assertEqual(cg.DEFAULT_POLICY['limits']['max_depth'], 8)
        self.assertEqual(cg.DEFAULT_POLICY['limits']['max_seconds'], 3.0)

    def test_a_policy_written_before_the_ceiling_existed_still_loads(self):
        limits = {k: v for k, v in cg.DEFAULT_POLICY['limits'].items() if k != 'max_wall_seconds'}
        budget = cg.Budget(limits)
        self.assertEqual(budget.wall_seconds, cg.WALL_CEILING_SECONDS)
        self.assertEqual(cg.hook_alarm_seconds(limits), cg.hook_alarm_seconds(cg.DEFAULT_POLICY['limits']))

    def test_time_an_exemption_check_waits_is_not_charged(self):
        budget = cg.Budget(cg.DEFAULT_POLICY['limits'])
        reads = iter([0.0, 1.0, 101.0, 103.0, 103.0])  # start, enter, leave after 100 s on git, then two reads
        with mock.patch.object(cg, 'WALL_CLOCK', lambda: next(reads)):
            budget.restart(3.0, 12.0)
            with budget.excluded():
                pass
            self.assertEqual(budget.wall_used(), 3.0)
            self.assertIsNone(budget.over())


class Layers(unittest.TestCase):
    """CPU budget < wall ceiling (+ credential pass) < hook alarm < launcher timeout < host hook timeout."""

    def test_the_time_limits_nest(self):
        import install
        limits = cg.DEFAULT_POLICY['limits']
        host = install.command_guard_group(Path('/x'))['hooks'][0]['timeout']
        self.assertLess(limits['max_seconds'], limits['max_wall_seconds'])
        self.assertGreater(cg.hook_cpu_alarm_seconds(limits), limits['max_seconds'])
        self.assertGreater(cg.hook_alarm_seconds(limits), limits['max_wall_seconds'] + cg.CREDENTIAL_PASS_WALL_SECONDS)
        self.assertGreaterEqual(command_guard_hook.CHILD_TIMEOUT, cg.hook_alarm_seconds(limits) + 5)
        self.assertLess(command_guard_hook.CHILD_TIMEOUT, host)
        kill_policy = json.loads((ROOT / 'harness/hooks/kill_guard_policy.json').read_text())
        self.assertEqual(kill_policy['child_timeout_seconds'], kill_guard.DEFAULT_POLICY['child_timeout_seconds'])
        self.assertLess(kill_policy['child_timeout_seconds'], install.kill_guard_group(Path('/x'))['hooks'][0]['timeout'])
        self.assertGreater(kill_policy['child_timeout_seconds'] - 2, limits['max_wall_seconds'])


class HookAlarms(unittest.TestCase):
    def run_hook(self, error):
        def stop(*_args, **_kwargs):
            raise error
        payload = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': ORDINARY}}).encode()
        err, out = io.StringIO(), io.StringIO()
        with mock.patch.object(cg, 'decide', stop), mock.patch('sys.stderr', new=err), \
                mock.patch('sys.stdout', new=out):
            code = cg.hook_main(stdin_bytes=payload, marker=False)
        return code, err.getvalue() + out.getvalue()

    def test_the_refusal_names_the_alarm_that_fired(self):
        code, text = self.run_hook(TimeoutError(cg.HOOK_CPU_LIMIT))
        self.assertEqual(code, 2)
        self.assertIn('CPU-time alarm', text)
        code, text = self.run_hook(TimeoutError(cg.HOOK_WALL_LIMIT))
        self.assertEqual(code, 2)
        self.assertIn('wall-clock alarm', text)

    @unittest.skipUnless(hasattr(signal, 'setitimer'), 'no interval timers')
    def test_the_hook_clears_both_alarms(self):
        self.run_hook(TimeoutError(cg.HOOK_WALL_LIMIT))
        self.assertEqual(signal.getitimer(signal.ITIMER_PROF), (0.0, 0.0))
        self.assertEqual(signal.alarm(0), 0)


if __name__ == '__main__':
    unittest.main()
