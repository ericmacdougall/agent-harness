"""Grammar fuzz for internal errors: analyze() on random git and parallel strings. Text only, nothing executed.
Reports every exception other than Blocked and RecursionError, because decide() answers those from a raw-text scan."""
import collections
import os
import random
import sys
import tempfile
import time

REPO, SECONDS = sys.argv[1], float(sys.argv[2])
sys.path.insert(0, REPO + '/harness/hooks')
import command_guard as cg  # noqa: E402

home = os.path.realpath(tempfile.mkdtemp())
os.environ['HOME'] = home
cwd = os.path.join(home, 'r')
os.makedirs(cwd)
compiled = cg.Compiled(cg.load_policy(path=os.path.join(home, 'none.json')), home=home, cwd=cwd)
rng = random.Random(151)

PAR = ['parallel', 'sem', 'parallel -k', 'parallel -j', 'parallel --', 'parallel -I', 'parallel -I ""', "parallel -I '('",
       "parallel -I '\\'", 'parallel --arg-sep', 'parallel --arg-sep=', "parallel --arg-sep ''", 'parallel --arg-file-sep :::',
       'parallel --arg-sep ::::', 'parallel -a', 'parallel -a -', 'parallel -i', 'parallel -i@', 'parallel -e', 'parallel -D',
       'parallel --replace', 'parallel --replace=', 'parallel --=x', 'parallel --=', 'parallel -', 'parallel -q', 'parallel -0k',
       'parallel --dnr {}', 'parallel --bnr {}', 'parallel --er {', 'parallel --seqreplace {#}', 'parallel -I {1}', 'parallel -I {=',
       'parallel --colsep', 'parallel -N0', 'parallel -n', 'parallel --pipe', 'parallel --semaphore', 'parallel --id', 'parallel "$X"',
       'parallel $X', 'parallel $(x)', 'parallel {a,b}', 'parallel --{a,b}', 'parallel -I{a,b}']
GIT = ['git', 'git -c', 'git -C', 'git -c alias.a', 'git -c alias.a=', 'git -c alias.a=!', 'git -c alias.a="', "git -c 'alias.a=\"'",
       "git -c 'alias.a=\\'", 'git -c =x', 'git -c "$X"', 'git -c $X', 'git -c "alias.a=$X"', 'git --config-env', 'git --config-env=',
       'git --config-env=a', 'git --config-env=alias.a=', 'git -C ""', 'git -C "$X"', 'git -C $(x)', 'git -C ~nouser', 'git -C /',
       'git -C .', 'git -C {a,b}', 'GIT_CONFIG_COUNT=999 git', 'GIT_CONFIG_COUNT=١ git', 'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.a git',
       'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.a GIT_CONFIG_VALUE_0= git', 'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.a GIT_CONFIG_VALUE_0="$(x)" git',
       'GIT_CONFIG_PARAMETERS=x git', 'export GIT_CONFIG_COUNT=1; git', 'git-worktree', 'git --git-dir', 'git --git-dir=', 'git --work-tree']
SUB = ['a', 'worktree', 'config', 'status', '""', "''", '"$X"', '$X', '$(x)', '{a,b}', '-', '--', '{}', ':::', '::::', 'list', 'remove', 'move',
       'prune', 'alias.a', 'alias.', 'alias', '--rename-section', 'rename-section', '--force', '-f', '--path=', '--x=', '--x=$X', '=', '==', '.', '..',
       '/', '//', '~', '~nouser', './x', '../', 'x/', '\\', '\\\\', '%', '{', '}', '{=', '=}', '{1}', '{0}', '{99999999999999999999}', '{-1}', '{.}',
       '{/}', '{//}', '{/.}', '{#}', '{%}', '{1.}', '{1//}', '{1/.}', ':::+', '::::+', '@@', '*', '?', '[a]', '$', '$$', '$@', '"$@"', '${X}', '${X:-y}',
       '$((1))', '<(x)', '>(x)', '$\'a\\nb\'', '$\'\\0\'', '\x7f', '\u00a0', '\udc80', '\ud83d\ude00', 'a b', '"a b"', "'a b'", ';', '&&', '|', '&', '>x',
       '2>&1', '<x', '#', '!', '!x', "'!x'", '"!x"', '\n', 'x=y', 'GIT_DIR=x', '-c', '-C', '-I', '-a', '-q', '--arg-sep', '--', '---', '-=', '--=', '-j4',
       '-kqj', '-0', '-X', '-m', '-N2', '-C,', '--colsep', '--trim', '--plus', '--rpl', '--header', '--pipe', '--wait', '--bar']
count = 0
errors = collections.Counter()
samples = {}
stop = time.monotonic() + SECONDS
while time.monotonic() < stop:
    head = rng.choice(PAR + GIT)
    body = ' '.join(rng.choice(SUB) for _ in range(rng.randint(0, 9)))
    text = head + ' ' + body
    if rng.random() < 0.15:
        text = 'echo a | xargs ' + text
    count += 1
    try:
        cg.analyze(text, compiled, cwd=cwd)
    except (cg.Blocked, RecursionError):
        pass
    except Exception as error:  # noqa: BLE001
        key = '%s: %s' % (type(error).__name__, str(error)[:80])
        errors[key] += 1
        samples.setdefault(key, text)
print('strings', count, 'distinct internal errors', len(errors))
for key, n in errors.most_common(20):
    print(n, key, '\n   sample:', repr(samples[key])[:220])
