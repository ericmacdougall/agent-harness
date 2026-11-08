"""Text-only decide() probes over the same fixture the suite uses. Candidate commands are never executed.

usage: guard_probe.py HEAD_REPO BASE_REPO CASES.tsv
Each case line: expected verdict <tab> command, with {P} {L} {B} {H} {PR} {P2} {OUT} {OP} placeholders replaced.
Lines starting with @cwd=KEY set the cwd for the following cases (PR default, B, P, OP).
Runs each case against both revisions (each in a subprocess fixture) and prints head and base verdicts.
"""
import importlib
import json
import os
import subprocess
import sys
import time
import unittest

MODE = os.environ.get('RT_SIDE')
if not MODE:
    head, base, cases = sys.argv[1:4]
    out = {}
    per_side = float(os.environ.get('RT_SIDE_SECONDS', '240'))
    for side, repo in (('head', head), ('base', base)):
        env = dict(os.environ, RT_SIDE=side, RT_REPO=repo, RT_CASES=cases)
        proc = subprocess.Popen([sys.executable, __file__], env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)
        rows = []
        limit = time.monotonic() + per_side
        for l in proc.stdout:
            if l.startswith('{'):
                rows.append(json.loads(l))
            if time.monotonic() > limit:
                proc.kill()
                print('SIDE TIMED OUT', side, 'after', len(rows))
                break
        out[side] = rows
    if len(out['base']) < len(out['head']):
        out['base'] += [dict(v='?') for _ in range(len(out['head']) - len(out['base']))]
    flagged = 0
    for h, b in zip(out['head'], out['base']):
        mark = ''
        if h['exp'] != '?' and h['v'] != h['exp']:
            mark = '  <== HEAD-MISMATCH'
            flagged += 1
        new = ' NEW' if h['v'] != b['v'] else ''
        print('%-5s base=%-5s exp=%-5s %s%s%s' % (h['v'], b['v'], h['exp'], h['cmd'], mark, new))
        if os.environ.get('WHY'):
            print('        ', h['why'])
    print('flagged', flagged, 'of', len(out['head']))
    sys.exit(0)

REPO = os.environ['RT_REPO']
os.environ['CG_HOOKS_DIR'] = REPO + '/harness/hooks'
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
T = importlib.import_module('tests.test_command_guard_' + 'work' + 'tree_remove')
Base = T.WorktreeRemoveCase


class P(Base):
    def test_probe(self):
        p = str(self.linked)
        lst = self.home / 'list.txt'
        lst.write_text(p + '\n')
        # a second linked worktree of the same repo, and a repo outside every protected root (like ~/wt/x on t2-dev)
        p2 = self.base / 'linked2'
        T.git(self.primary, 'worktree', 'add', '-q', '-b', 'linked2', str(p2))
        outside_primary = self.home / 'wt' / 'prim'
        outside_primary.mkdir(parents=True)
        T.git(outside_primary, 'init', '-q', '-b', 'main')
        (outside_primary / 'a').write_text('x')
        T.git(outside_primary, 'add', 'a')
        T.git(outside_primary, 'commit', '-q', '-m', 'x')
        outside = self.home / 'wt' / 'out'
        T.git(outside_primary, 'worktree', 'add', '-q', '-b', 'out', str(outside))
        T.git(outside_primary, 'worktree', 'add', '-q', '-b', 'out2', str(self.home / 'wt' / 'out2'))
        env = dict(P=p, L=str(lst), PR=str(self.primary), H=str(self.home), B=str(self.base), P2=str(p2),
                   OUT=str(outside), OP=str(outside_primary), WT=str(self.home / 'wt'))
        cwds = dict(PR=str(self.primary), B=str(self.base), P=p, OP=str(outside_primary), WT=str(self.home / 'wt'))
        cwd = cwds['PR']
        for line in open(os.environ['RT_CASES'], encoding='utf-8'):
            line = line.rstrip('\n')
            if not line or line.startswith('#'):
                continue
            if line.startswith('@cwd='):
                cwd = cwds[line[5:]]
                continue
            exp, cmd = line.split('\t', 1)
            cmd = cmd.replace('\\n', '\n') if exp.endswith('+nl') else cmd
            exp = exp.replace('+nl', '')
            for k in sorted(env, key=len, reverse=True):
                cmd = cmd.replace('{' + k + '}', env[k])
            started = time.monotonic()
            d = self.decide(cmd, cwd=cwd)
            secs = time.monotonic() - started
            why = ('%.2fs ' % secs) + str(d[1:])[:260].replace('\n', ' ')
            short = cmd
            for k, tag in ((p, '$P'), (str(p2), '$P2'), (str(outside), '$OUT'), (str(outside_primary), '$OP'),
                           (str(self.primary), '$PR'), (str(self.base), '$B'), (str(self.home), '$H')):
                short = short.replace(k, tag)
                why = why.replace(k, tag)
            print(json.dumps(dict(v=d[0], exp=exp, cmd=short.replace('\n', '\\n')[:190], why=why)), flush=True)


unittest.main(argv=['x', '-q'], verbosity=0)
