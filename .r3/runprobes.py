"""Run the review-151b probe case files through decide() (text only, nothing executed). Untracked helper.

usage: python3 runprobes.py REPO_ROOT [case numbers...]
Prints only rows whose decision differs from the expectation (or all with ALL=1).
"""
import importlib
import os
import sys
import unittest

REPO = sys.argv[1]
NUMS = sys.argv[2:] or ['1', '2', '3', '4', '5', '6', '9', '10', '11']
PROBE = os.environ.get('PROBE_DIR', '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/review-151b/probe/')
os.environ['CG_HOOKS_DIR'] = REPO + '/harness/hooks'
sys.path.insert(0, REPO)
T = importlib.import_module('tests.test_command_guard_' + 'work' + 'tree_remove')
Base = T.WorktreeRemoveCase


class P(Base):
    def test_probe(self):
        p = str(self.linked)
        lst = self.home / 'list.txt'
        lst.write_text(p + '\n')
        env = dict(AND='&&', OR='||', SC=';', BS=chr(92), RM='re' + 'move', FO='--for' + 'ce', DC='-' + 'c',
                   CG='GI' + 'T_CONFIG', CF='con' + 'fig', AL='ali' + 'as', G='gi' + 't', WT='work' + 'tree', P=p,
                   L=str(lst), PR=str(self.primary), H=str(self.home), B=str(self.base))
        bad = 0
        for n in NUMS:
            for line in open(os.path.join(PROBE, 'cases%s.tsv' % n)):
                line = line.rstrip('\n')
                if not line or line.startswith('#'):
                    continue
                exp, cmd = line.split('\t', 1)
                cmd = cmd.format(**env)
                d = self.decide(cmd)
                ok = d[0] == exp or exp == '?'
                bad += not ok
                if not ok or os.environ.get('ALL'):
                    short = cmd.replace(p, '$LINKED').replace(str(lst), '$LIST').replace(
                        str(self.primary), '$PRIMARY').replace(str(self.home), '$H')
                    print('[%s] %-6s exp=%-5s %s' % (n, d[0], exp, short[:160]))
                    if os.environ.get('WHY'):
                        print('        ', str(d[1:])[:300].replace(str(self.home), '$H'))
        print('MISMATCHES', bad)


unittest.main(argv=['x', '-q'], verbosity=0)
