"""goodqa#16943: programs that run another command are analysed under every reading of their options.

A launcher (flock, unshare, script, sudo, env, timeout, nsenter, ...) runs a command given as its trailing words or as
an option's shell text. The guard used to find that command with per-program rules that missed options taking a
value, misread `-c`, or ignored the words after a file operand, so the command was never judged. Now one table
(command_guard.LAUNCHERS) holds each launcher's options. `launch_readings` gives every place the command could start:
under each arity an unknown option might have, each operand count, and each word the table skipped that names a
command. A program the guard has no model of is read the same way wherever one of its words names a deleting command
or a shell. The must-fail rows below are the shapes found allowed at origin/main 98d20350; the property test builds
every launcher x option shape x payload from the table itself (seed SEED for the sampled combinations). Commands are
data passed to decide(), never run."""

import os
from pathlib import Path
import random
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'harness/hooks'))
import command_guard as cg  # noqa: E402

SEED = 16943
DELETE = 'rm -rf ~/.claude/projects'
SECRET = 'cat ~/.ssh/id_rsa'
KILL = 'pk' + 'ill -f claude'  # split so the session's own kill hook does not read this file's text as a kill
POWERSHELL = {'start-process', 'start', 'call', 'invoke-command', 'icm'}  # PowerShell spellings, not getopt
# what an operand of each launcher that takes one looks like (a lock file, a new root, a user, a duration, a priority)
OPERAND = {'flock': '/tmp/l', 'script': '/dev/null', 'timeout': '5', 'chroot': '/srv', 'gosu': 'u', 'sg': 'g',
           'taskset': '1', 'chrt': '1', 'su': 'u', 'runuser': 'u'}


class GuardCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='cg-launch-')
        self.addCleanup(tmp.cleanup)
        self.home = Path(os.path.realpath(tmp.name))
        for rel in ('.claude/projects/p', '.ssh', 'w'):
            (self.home / rel).mkdir(parents=True, exist_ok=True)
        (self.home / '.claude/projects/p/s.jsonl').write_text('{}\n')
        (self.home / '.ssh/id_rsa').write_text('not a key\n')
        patch = mock.patch.dict(os.environ, {'HOME': str(self.home)})
        patch.start()
        self.addCleanup(patch.stop)
        self.compiled = cg.Compiled(cg.load_policy(), cwd=str(self.home / 'w'))

    def decide(self, command):
        return cg.decide(command, self.compiled, cwd=str(self.home / 'w'))

    def verdict(self, command):
        return self.decide(command)[0]


class Readings(unittest.TestCase):
    """launch_readings on literal words: where the command can start, and what shell text runs."""

    @staticmethod
    def read(name, line):
        words = [cg._literal_word(t) for t in line.split()]
        return cg.launch_readings(cg.LAUNCHERS[name], words)

    def test_option_values_operands_and_text(self):
        self.assertEqual(self.read('flock', '-w 5 /tmp/l rm x'), ([3], []))
        self.assertEqual(self.read('flock', '-w5 /tmp/l rm x'), ([2], []))
        self.assertEqual(self.read('flock', '/tmp/l -c x'), ([1], ['x']))  # `flock FILE -c TEXT`
        self.assertEqual(self.read('flock', '/tmp/l -w 1 rm x'), ([1], []))  # getopt stops at the lock file
        self.assertEqual(self.read('unshare', '-c rm x'), ([1], []))  # -c is --map-current-user, not text
        self.assertEqual(self.read('script', '-c x /dev/null rm y'), ([3], ['x']))
        self.assertIn(3, self.read('script', '-t 0 /dev/null rm y')[0])  # BSD: -t takes the next word
        self.assertIn(2, self.read('script', '-t 0 /dev/null rm y')[0])  # util-linux: it does not
        self.assertEqual(self.read('su', 'u -c x')[1], ['x'])  # options after the user
        self.assertEqual(self.read('sudo', 'FOO=1 -u u rm x'), ([3], []))
        self.assertEqual(self.read('timeout', '-s KILL 5 rm x'), ([3], []))

    def test_an_unknown_option_is_read_both_ways(self):
        self.assertEqual(self.read('flock', '-Z 5 /tmp/l rm x')[0], [2, 3])
        self.assertEqual(self.read('flock', '--zz 5 /tmp/l rm x')[0], [2, 3])

    def test_too_many_places_is_none(self):
        words = [cg.Word() for _ in range(cg.LAUNCH_READINGS_CAP + 2)]
        for w in words:
            w.alts, w.dynamic = ['$X'], True
        self.assertIsNone(cg.launch_readings(cg.LAUNCHERS['flock'], words))


class MustFail(GuardCase):
    """Every shape found allowed at 98d20350, and the other options the review named, blocks now."""

    ROWS = [
        # unshare: -c is --map-current-user (util-linux 2.38+), and its valued options were read as the command
        'unshare -c {}', 'unshare -c -- {}', "unshare -c sh -c '{}'", 'unshare -S 0 {}', 'unshare -G 0 {}',
        'unshare --propagation private {}', 'unshare -R / {}', 'unshare -w /tmp {}', 'unshare --setgroups deny {}',
        # script: BSD `script [file [command ...]]` and util-linux `script -c TEXT [file]`
        'script /dev/null {}', 'script -q /dev/null {}', 'script -q /dev/null -- {}', "script -c 'echo hi' /dev/null {}",
        'script -q -c x {}', 'script -t 0 /dev/null {}', 'script -E never /dev/null {}', 'script -F /dev/null {}',
        "script -qc '{}' /dev/null", "script --command='{}' /dev/null", 'script -a -k -q /dev/null {}',
        # flock: -w/--timeout/-E take a value, and -c only after the lock file
        'flock -w 5 /tmp/l {}', 'flock -c x /tmp/l {}', 'flock -E 1 /tmp/l {}', 'flock --timeout 5 /tmp/l {}',
        'flock --conflict-exit-code 1 /tmp/l {}', 'flock -w5 /tmp/l {}', 'flock --wait=5 /tmp/l {}', 'flock -nw 5 /tmp/l {}',
        "flock /tmp/l -c '{}'", 'flock -s -w 5 /tmp/l {}',
        # other wrappers whose valued options were read as the command
        'runuser -u u -- {}', 'runuser -u u {}', 'sudo -r R {}', 'sudo -t T {}', 'sudo -h host {}', 'sudo FOO=1 {}',
        'env -P /bin {}', 'env -a NAME {}', 'strace -a 40 {}', 'time -p {}', 'xargs -i {}', 'nsenter -S 0 {}',
        'ionice -t {}', 'exec -a name {}', "watch -n 1 '{}'", "sg g '{}'",
        # programs the guard has no model of, and launchers it handled only for other subcommands
        'mytool {}', 'mytool run -- {}', 'some-launcher -x 3 {}', 'systemd-run --user {}', 'uv run {}',
        "nix-shell --run '{}'", "trap '{}' EXIT", 'tmux new-session -d {}',
    ]

    def test_every_row_blocks(self):
        allowed = [row for row in self.ROWS if self.verdict(row.format(DELETE)) != 'block']
        self.assertEqual(allowed, [])

    def test_a_secret_read_behind_a_launcher_blocks(self):
        for row in ('flock -w 5 /tmp/l {}', 'unshare -c {}', 'script -q /dev/null {}', 'sudo -r R {}', 'env -P /bin {}'):
            self.assertEqual(self.verdict(row.format(SECRET)), 'block', row)

    def test_a_kill_behind_a_launcher_is_judged_like_the_kill_alone(self):
        alone = self.verdict(KILL)
        self.assertNotEqual(alone, 'allow')
        for row in ('flock -w 5 /tmp/l {}', 'unshare -c {}', 'script -q /dev/null {}', 'timeout -s KILL 5 {}'):
            self.assertEqual(self.verdict(row.format(KILL)), alone, row)

    def test_a_variable_or_a_relative_path_behind_a_launcher_is_resolved_like_any_command(self):
        for command in ('D=~/.claude/projects; flock -Z x rm -rf "$D"', 'cd ~/.claude && flock -w 1 /tmp/l rm -rf projects',
                        'flock $X /tmp/l %s' % DELETE, 'flock "$X" /tmp/l %s' % DELETE):
            self.assertEqual(self.verdict(command), 'block', command)

    def test_a_directory_the_launcher_moves_its_command_to_is_judged(self):
        claude = str(self.home / '.claude')
        for command in ('sudo -D %s rm -rf projects' % claude, 'sudo --chdir=%s rm -rf projects' % claude,
                        'unshare -w %s rm -rf projects' % claude, 'unshare --wd=%s rm -rf projects' % claude,
                        'nsenter --wd=%s rm -rf projects' % claude, 'env -C %s rm -rf projects' % claude,
                        'env --chdir=%s rm -rf projects' % claude):
            self.assertEqual(self.verdict(command), 'block', command)

    def test_a_launched_cd_or_chdir_option_does_not_move_the_rest_of_the_line(self):
        # the rest of the line still runs in ~/.claude, so its relative deletion is judged there
        for command in ('cd ~/.claude && env -C /tmp true; rm -rf projects',
                        'cd ~/.claude && sudo -D /tmp true; rm -rf projects',
                        'cd ~/.claude && nohup cd /tmp; rm -rf projects',
                        'cd ~/.claude && flock /tmp/l cd /tmp; rm -rf projects'):
            self.assertEqual(self.verdict(command), 'block', command)

    def test_nested_ambiguous_launchers_are_bounded(self):
        # each `nohup -Z 1` doubles the readings; the analysis stays bounded and the deletion still blocks
        for depth in (4, 10, 16):
            command = ' '.join(['nohup -Z 1'] * depth) + ' ' + DELETE
            self.assertEqual(self.verdict(command), 'block', depth)
        harmless = ' '.join(['nohup -Z 1'] * 10) + ' make'
        verdict, message = self.decide(harmless)
        self.assertEqual(verdict, 'block')
        self.assertIn('launcher-unparsed', message)

    def test_a_launcher_whose_command_cannot_be_placed_is_refused(self):
        command = 'flock %s /tmp/l make' % ' '.join('"$A%d"' % k for k in range(cg.LAUNCH_READINGS_CAP + 1))
        verdict, message = self.decide(command)
        self.assertEqual(verdict, 'block')
        self.assertIn('launcher-unparsed', message)


class TableProperty(GuardCase):
    """Built from LAUNCHERS: every launcher, with each of its options in each spelling, then the payload."""

    def shapes(self, name, spec):
        lead = [OPERAND.get(name, '')] if max(spec.operands) else []
        lead = [w for w in lead if w]
        out = [[]]
        for opt in sorted(spec.value):
            out.append([opt, '1'])
            out.append([opt + '=1'] if opt.startswith('--') else [opt + '1'] if len(opt) == 2 else [opt, '1'])
        out.extend([opt] for opt in sorted(spec.flags))
        out.extend([[opt] for opt in sorted(spec.attached)])
        out.append(['--'] if not lead else [])
        out.extend((['-Z'], ['-Z', '1'], ['--zz'], ['--zz', '1']))  # an option the table does not know
        return [shape + lead for shape in out]

    def rows(self, payload):
        for name, spec in sorted(cg.LAUNCHERS.items()):
            if name in POWERSHELL:
                continue
            for shape in self.shapes(name, spec):
                yield '%s %s %s' % (name, ' '.join(shape), payload)

    def test_every_launcher_option_shape_blocks_the_deletion(self):
        rows = list(self.rows(DELETE))
        self.assertGreater(len(rows), 400)
        allowed = [row for row in rows if self.verdict(row) != 'block']
        self.assertEqual(allowed, [])

    def test_sampled_option_combinations_block_every_payload_class(self):
        rng = random.Random(SEED)
        kill_alone = self.verdict(KILL)
        names = sorted(set(cg.LAUNCHERS) - POWERSHELL)
        misses = []
        for _ in range(120):
            name = rng.choice(names)
            spec = cg.LAUNCHERS[name]
            shapes = self.shapes(name, spec)
            lead = [OPERAND[name]] if name in OPERAND and max(spec.operands) else []
            picked = [w for shape in rng.sample(shapes, min(3, len(shapes))) for w in shape if w not in lead]
            line = ' '.join([name] + picked + lead)
            for payload, want in ((DELETE, 'block'), (SECRET, 'block'), (KILL, kill_alone)):
                if self.verdict(line + ' ' + payload) != want:
                    misses.append((line, payload))
        self.assertEqual(misses, [], 'seed %d' % SEED)


class FalsePositives(GuardCase):
    """Must-allow controls: a launcher running a harmless command, and tools that only name a verb as data."""

    ROWS = [
        'flock /tmp/l make test', 'flock -w 5 /tmp/l make', 'script -q /dev/null git status', 'unshare -r true',
        'timeout 5 git status', 'env FOO=1 make', 'xargs -0 echo', 'watch -n 1 ls', 'sudo -u u ls ~/.claude/projects',
        'sudo grep rm ~/.claude/projects', 'nice -n 5 rm -rf /tmp/x', 'uv run pytest', 'make clean', 'python3 x.py',
        'rg rm ~/.claude/projects/p/s.jsonl', 'grep -r rm ~/.claude/projects', 'man rm', 'which rm',
        "git commit -m '%s'" % DELETE, "ah ticket comment --body 'rm is refused'", 'mytool rm /tmp/x',
        'mytool kill 123', 'jq . ~/.claude/projects/p/s.jsonl', 'wc -l ~/.claude/projects/p/s.jsonl',
        # prose given to an unknown program is data, even when it starts with a command word or names a protected path
        "codex exec 'move the old logs to the archive and find what changed'",
        'kimi "find out why it can\'t start"', "ah ticket comment --body 'script `x` runs time sleep'",
        "claude -p 'copy ~/.claude/projects notes into the report'",
        "ah ticket comment --body '%s was refused, as expected'" % DELETE,
    ]

    def test_harmless_rows_are_allowed(self):
        refused = [row for row in self.ROWS if self.verdict(row) != 'allow']
        self.assertEqual(refused, [])

    def test_a_launched_cd_does_not_move_the_rest_of_the_line(self):
        # the launched command is its own process; a shell builtin (`command cd`) does move this shell
        self.assertEqual(self.verdict('flock /tmp/l cd ~/.claude; rm -rf projects'), 'allow')
        self.assertEqual(self.verdict('command cd ~/.claude; rm -rf projects'), 'block')


if __name__ == '__main__':
    unittest.main()
