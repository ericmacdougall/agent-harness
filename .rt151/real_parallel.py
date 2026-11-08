"""What real GNU parallel builds. Uses --dry-run (prints, never runs) with fake paths; the few cases that must really
execute run only `echo` writing a marker inside the run_probe sandbox TMPDIR. Nothing is removed."""
import os
import subprocess
import sys
import tempfile

PAR = sys.argv[1]
t = tempfile.mkdtemp()
X = '/nonexistent/wt'


def run(argv, env=None, stdin=None, dry=True):
    e = dict(os.environ)
    e.update(env or {})
    cmd = ['perl', PAR, '--will-cite'] + (['--dry-run'] if dry else []) + argv
    d = subprocess.run(cmd, env=e, capture_output=True, text=True, timeout=20, input=stdin if stdin is not None else '',
                       cwd=t)
    return d.returncode, (d.stdout + d.stderr).strip().replace(t, '$T')[:400].replace('\n', ' | ')


DRY = [
    ('PARALLEL holds the command', ['echo-target', ':::', 'never'], {'PARALLEL': 'rm -rf'}),
    ('PARALLEL holds the command, no template', [':::', X], {'PARALLEL': 'rm -rf'}),
    ('PARALLEL -I', ['echo {1}; rm -rf XX', ':::', X], {'PARALLEL': '-I XX'}),
    ('--trim takes a value', ['--trim', 'lr', 'rm', '-rf', ':::', X], None),
    ('--tri abbreviated', ['--tri', 'lr', 'rm', '-rf', ':::', X], None),
    ('--parens', ['--parens', ',,,,', 'rm -rf ,,s/x//,,', ':::', X + 'x'], None),
    ('negative positional', ['echo {1}; rm -rf {-1}', ':::', 'x', ':::', X], None),
    ('newline in a ::: argument', ['rm', '-rf', ':::', 'a\n' + X], None),
    ('-d splits ::: argument', ['-d', ',', 'rm', '-rf', ':::', 'a,' + X], None),
    ('--colsep without placeholder', ['--colsep', ',', 'rm', '-rf', ':::', 'a,' + X], None),
    ('-C space', ['-C', ' ', 'rm', '-rf', ':::', 'a ' + X], None),
    ('-C with {}', ['-C', ',', 'rm -rf {}', ':::', 'a,' + X], None),
    ('{//} with trailing slash', ['rm -rf {//}', ':::', X + '/x/'], None),
    ('{.} on trailing dot', ['rm -rf {.}', ':::', X + '.'], None),
    ('{#} per job', ['rm -rf /wt/linked{#}', ':::', 'a', 'b'], None),
    ('{%} per slot', ['-j2', 'rm -rf /wt/linked{%}', ':::', 'a', 'b'], None),
    ('--wd shows cd', ['--wd', '/nonexistent/base', 'rm', '-rf', 'linked', ':::', 'x'], None),
    ('empty source, template runs?', ['rm -rf ' + X, ':::'], None),
    ('empty source then a source', ['rm -rf ' + X, ':::', ':::', 'a'], None),
    ('source then empty source', ['rm -rf', ':::', X, ':::'], None),
    ('-N0 empty', ['-N0', 'rm -rf ' + X, ':::'], None),
    ('empty source args appended', ['rm', '-rf', ':::', ':::', X], None),
    ('--link with empty', ['rm', '-rf', ':::', ':::+', X], None),
    ('sh -c word loses quotes', ['sh', '-c', 'rm -rf {}', ':::', X], None),
    ('-q keeps quotes', ['-q', 'sh', '-c', 'rm -rf {}', ':::', X], None),
    ('{} glued in -I form', ['-I', '{}', 'rm -rf {}/linked', ':::', '/nonexistent/base'], None),
    ('--rpl', ['--rpl', '{x} $_="' + X + '"', 'rm', '-rf', '{x}', ':::', 'a'], None),
    ('--plus {..}', ['--plus', 'echo {..}', ':::', 'a.b.c'], None),
    ('numbered with -n2 (refused by guard)', ['-n2', 'echo {2}', ':::', 'a', 'b'], None),
    ('-X context', ['-X', 'rm -rf x{}y', ':::', '1', '2'], None),
    ('args repeated via {} {}', ['echo {} {}', ':::', 'a'], None),
    ('--link semantics', ['--link', 'echo {1} {2}', ':::', 'a', 'b', ':::', 'c', 'd'], None),
    (':::+ semantics', ['echo {1} {2}', ':::', 'a', 'b', ':::+', 'c', 'd'], None),
    ('-a - with template', ['-a', '-', 'rm', '-rf'], None),
    ('sem style --semaphore dry', ['--semaphore', 'echo', 'hi'], None),
    ('--version prints', ['--version'], None),
    ('--arg-file-sep', ['--arg-file-sep', '@@', 'echo', '@@', '/dev/null'], None),
    ('moreutils-style -- args', ['-j2', '--', 'echo', 'a'], None),
    ('abbrev --max-a', ['--max-a', '1', 'echo', ':::', 'a'], None),
    ('case-insensitive --TRIM', ['--TRIM', 'lr', 'rm', '-rf', ':::', X], None),
]
print('parallel', run(['--version'], dry=False)[1][:60])
for label, argv, env in DRY:
    rc, out = run(argv, env)
    print('[%s] rc=%s\n    %s %s\n    => %s' % (label, rc, env or '', argv, out))

# stdin
for label, argv, data in (
        ('stdin {}', ['rm -rf {}'], X + '\n'),
        ('stdin no template', [], 'rm -rf ' + X + '\n'),
        ('xargs-supplied ::: at end', ['rm', '-rf', ':::', X], '')):
    print('[%s] %s\n    => %s' % (label, argv, run(argv, stdin=data)))

# really executed, marker only: does the option run a command or perl?
m = os.path.join(t, 'marker')


def fired():
    if os.path.exists(m):
        os.unlink(m)
        return True
    return False


REAL = [
    ('--limit runs a shell command', ['--limit', 'echo LIMIT >> %s; exit 0' % m, 'echo', ':::', 'a']),
    ('--filter evals perl', ['--filter', 'system(q(echo FILTER >> %s)); 1' % m, 'echo', ':::', 'a']),
    ('--tagstring evals perl', ['--tagstring', '{= system(q(echo TAG >> %s)) =}' % m, 'echo', ':::', 'a']),
    ('--results evals perl', ['--results', '{= system(q(echo RES >> %s)) =}' % m, 'echo', ':::', 'a']),
    ('--compress-program runs a command', ['--compress', '--compress-program', 'sh -c "echo COMP >> %s; cat"' % m, 'echo',
                                           ':::', 'a']),
    ('--ssh runs a command', ['--ssh', 'sh -c "echo SSH >> %s" #' % m, '-S', 'x', 'echo', ':::', 'a']),
    ('-S with a custom ssh command', ['-S', 'sh -c "echo SSHLOGIN >> %s" # x' % m, 'echo', ':::', 'a']),
    ('--wd changes the working directory', ['--wd', '/usr', 'pwd', ':::', 'a']),
    ('--wd {= =} evals', ['--wd', '{= system(q(echo WD >> %s)); $_="/" =}' % m, 'pwd', ':::', 'a']),
    ('--joblog {= =}', ['--joblog', '{= system(q(echo JL >> %s)) =}' % m, 'echo', ':::', 'a']),
]
for label, argv in REAL:
    rc, out = run(argv, dry=False)
    print('[REAL %s] rc=%s fired=%s\n    %s\n    => %s' % (label, rc, fired(), [a.replace(t, '$T') for a in argv], out))
