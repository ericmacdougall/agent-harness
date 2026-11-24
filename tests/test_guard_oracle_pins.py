"""Pins for the differential shell oracle's findings (goodqa#17059, goodqa#17060, goodqa#17073).

Each row is a text that bash, dash or zsh really ran with a marker where `{X}` stands (tests/guard_shell_oracle.py,
seed 1, on the dev host: bash 5.2.21, dash, zsh 5.9; the shells and modes that ran it are recorded per row), and that
a guard allowed at main (d56a8cb0) or at a reviewed head of PR 348 or 349. Both guards must refuse every row with
their twin in place of the marker. The oracle itself is a dev-host job; these rows keep each fixed class pinned in
the focused suite.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'harness' / 'hooks'))
sys.path.insert(0, str(ROOT / 'tests'))
import command_guard as cg  # noqa: E402
import kill_guard as kg  # noqa: E402

DELETE = 'rm -rf ' + '~/.claude/projects'
KILL = 'kill -9 ' + '-1'
ALL = 'bash, dash, zsh (-c, eval)'

# (class, template, shells that ran the marker)
PINS = [
    # \r, \f and \v are word characters: a lone one is a command, and a later `case` is its argument (348 F1)
    ('blank', '\r case y in; {X}', ALL),
    ('blank', '\v case y in; {X}', ALL),
    ('blank', '\f case y in; {X}', ALL),
    ('blank', '\r\tcase y in; {X}', ALL),
    ('blank', 'true; \r case y in; {X}', ALL),
    ('blank', 'if true; then \r case y in; {X}; fi', ALL),
    ('blank', 'echo if case y in; \r case esac in; {X}', ALL),  # refused at main, allowed at f34fbadf
    # a backslash before \r\n quotes the \r; the line feed still ends the command (goodqa#17073)
    ('line join', 'echo x \\\r\n{X}\n', ALL),
    ('line join', 'true; echo x \\\r\n{X}\n', ALL),
    # aliases and disabled keywords defined on an earlier line (348 F2)
    ('alias', 'shopt -s expand_aliases\nBASH_ALIASES[case]=echo\ncase y in; {X}', 'bash (-c, eval, file)'),
    ('alias', "shopt -s expand_aliases\neval 'alias case=echo'\ncase y in; {X}", 'bash (-c, eval, file); zsh file'),
    ('alias', 'galiases[case]=echo\ncase y in; {X}', 'zsh file'),
    ('alias', 'disable -r case\ncase y in; {X}', 'zsh file'),
    # a case statement in an odd place
    ('case', 'echo done case x in; {X}', ALL),  # 346 P1
    ('case', 'case x in $({X})) true ;; esac', ALL),  # 348 P1, a substitution in a pattern
    ('case', 'case y in };{X}', 'zsh (-c, eval)'),  # zsh ends a case at `}` (oracle)
    ('case', 'function f case y in;{X}', 'dash (-c, eval)'),  # dash has no `function` keyword (oracle)
    # substitution extents (349)
    ('extent', 'echo "${x:-$(true }; {X})}"', 'bash, dash'),
    ('extent', 'echo $(case a in a) {X};; esac)', ALL),
    ('extent', 'echo "$(echo case in a)" ; {X} ; echo ")"', ALL),  # refused at main, allowed at a9c5649b
    ('extent', 'echo $(echo "$(echo case in a)" ; {X} ; echo ")")', ALL),
    ('extent', 'echo "${x:-\'}"; {X}; echo "\'}"', 'dash, zsh (-c, eval)'),  # 349 F5: `'` in "${..}"
    # zsh reads a `$((..))` that is not arithmetic as a command substitution (oracle)
    ('arith', 'echo $((case a in a) {X};; esac))', 'zsh (-c, eval)'),
    ('arith', 'echo $((echo ")"; {X}))', 'zsh (-c, eval)'),
    # bash reads text glued after `NAME=( .. )` as part of the assignment, and runs the next word (oracle)
    ('array', 'x=()\rfi {X}', 'bash (-c, eval)'),
    ('array', 'x=()zzz {X}', 'bash (-c, eval)'),
]

# ordinary shell that must stay allowed (the over-refusal the review named, and plain forms near the pins)
ALLOWED = [
    'f() { case "$1" in a|b) echo x ;; *) exit 64 ;; esac; }',  # 348 F3
    'case "$1" in a) echo a ;; esac',
    'x=$(case a in a) echo 1;; esac)',
    'echo $(( (1 + 2) * 3 )) $((x)) $(( 1 + 2 ))',
    'x=(a b); echo "${x[@]}"',
    'printf "%s\\r\\n" a',
]


# where a `$(` that opens at index 0 ends, as bash 5.2 and dash end it: (text, the inner script)
EXTENTS = [
    ('$(echo case in a)" ; X ; echo ")', 'echo case in a'),  # `case` as an argument opens nothing
    ('$(case a in a) b;; esac) tail', 'case a in a) b;; esac'),
    ('$(case a in (a) b;; (c) d;; esac) tail', 'case a in (a) b;; (c) d;; esac'),
    ('$(case a in a) b;;& *) c;; esac) tail', 'case a in a) b;;& *) c;; esac'),
    ('$(x=1 case a in a) b;; esac) tail', 'x=1 case a in a'),  # after an assignment `case` is a command name
    ('$(f() { case "$1" in a|b) echo;; esac; }) tail', 'f() { case "$1" in a|b) echo;; esac; }'),
    ('$(true # )\nX) tail', 'true # )\nX'),
    ("$(echo $'a\\'b'; X) tail", "echo $'a\\'b'; X"),
    ('$(cat <<E\n)\nE\nX) tail', 'cat <<E\n)\nE\nX'),
    ('$(echo "`echo )`") tail', 'echo "`echo )`"'),
    ('$(echo ${x:-(}; b) tail', 'echo ${x:-(}; b'),
    ('$(echo "${x:-$(true }; b)}") tail', 'echo "${x:-$(true }; b)}"'),
]


class Extent(unittest.TestCase):
    def test_the_scan_ends_each_substitution_where_the_shells_do(self):
        wrong = []
        for text, inner in EXTENTS:
            end = cg.scan_balanced(text, 2)
            if text[2:end - 1] != inner:
                wrong.append((text, text[2:end - 1]))
        self.assertEqual(wrong, [])


class Pins(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix='pins-'))
        (self.home / '.claude' / 'projects').mkdir(parents=True)
        patch = mock.patch.dict(os.environ, {'HOME': str(self.home)})
        patch.start()
        self.addCleanup(patch.stop)
        self.compiled = cg.Compiled(cg.load_policy(), cwd=str(self.home))

    def verdicts(self, template):
        c = cg.decide(template.replace('{X}', DELETE), self.compiled, cwd=str(self.home))[0]
        k = kg.decide(template.replace('{X}', KILL), cwd=str(self.home), home=str(self.home))[0]
        return c, k

    def test_every_pin_is_refused_by_both_guards(self):
        wrong = [(cls, t, ran, self.verdicts(t)) for cls, t, ran in PINS if self.verdicts(t) != ('block', 'block')]
        self.assertEqual(wrong, [])

    def test_the_twins_alone_are_refused(self):
        self.assertEqual(self.verdicts('{X}'), ('block', 'block'))

    def test_ordinary_shell_near_the_pins_is_allowed(self):
        wrong = [(t, v) for t in ALLOWED for v in [self.verdicts(t)] if v != ('allow', 'allow')]
        self.assertEqual(wrong, [])


if __name__ == '__main__':
    unittest.main()
