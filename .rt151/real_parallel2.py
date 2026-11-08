"""Second round of GNU parallel checks: --dry-run with fake paths, and a marker-only run for --wd. Nothing is removed."""
import os
import subprocess
import sys
import tempfile

PAR = sys.argv[1]
t = tempfile.mkdtemp()
X = '/nonexistent/wt'


def run(argv, dry=True, stdin=''):
    cmd = ['perl', PAR, '--will-cite'] + (['--dry-run'] if dry else []) + argv
    d = subprocess.run(cmd, env=dict(os.environ), capture_output=True, text=True, timeout=20, input=stdin, cwd=t)
    return d.returncode, (d.stdout + d.stderr).strip().replace(t, '$T')[:300].replace('\n', ' | ')


for label, argv in (
        ('-q, template {} takes the whole value', ['-q', 'sh', '-c', '{}', ':::', 'rm -rf ' + X]),
        ('-q, quoted word with {} inside', ['-q', 'sh', '-c', 'cd {}; rm -rf .', ':::', X]),
        ('--parens builds a path', ['--parens', ',,,,', 'rm -rf ,,s:^:/nonexistent/:,,', ':::', 'wt']),
        ('--arg-sep with an empty source', ['--arg-sep', '@@', 'rm', '-rf', '@@', '@@', X]),
        (':::: /dev/null then a source', ['rm', '-rf', '::::', '/dev/null', ':::', X]),
        ('empty string source', ['rm', '-rf', ':::', '', ':::', X]),
        ('--trim then sem-style', ['--semaphore', '--trim', 'lr', 'rm', '-rf', X]),
        ('--tmpdir then --trim', ['--tmpdir', t, '--trim', 'lr', 'rm', '-rf', ':::', X]),
        ('--version with no input', ['--number-of-cores']),
        ('--number-of-threads', ['--number-of-threads']),
        ('--plus', ['--plus', 'echo {..}', ':::', 'a.b.c']),
        ('negative in stdin', ['rm -rf {-1}'])):
    print('[%s] %s\n    => %s' % (label, argv, run(argv, stdin=X + '\n')))

# --wd with a directory that exists: pwd's output shows where the job ran. Only prints.
d = os.path.join(t, 'dir')
os.mkdir(d)
print('[--wd real]', run(['--wd', d, 'pwd; true', ':::', 'a'], dry=False))
print('[--wd dry]', run(['--wd', d, 'rm', '-rf', 'linked', ':::', 'x']))
print('[no --wd real]', run(['pwd; true', ':::', 'a'], dry=False))
# sem --wait with nothing running must return at once
print('[sem --wait]', run(['--semaphore', '--wait', '--id', 'rt151'], dry=False))
