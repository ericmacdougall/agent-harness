"""Grammar fuzz for the ah-run hook against real shells (GoodQA goodqa#14548).

usage: python3 tests/ah_run_fuzz.py SEED CASES SECONDS [--hook-only] [--control REV] [--show K]

Generates CASES distinct commands from SEED (atoms from the round 5 and round 6 fuzzers plus the r6 classes), each holding the
marker line `echo HIDDEN-LINE`; one in seven has a program word respelled as macOS's file system still finds it (r9 F1, with
shell_sandbox.fold_links on PATH in the sandbox). Checks every case:
  B  uncertain is never allowed (allow-all rule, default mode)                       -> must be 0
  A  certain, not denied in bypass, and a shell prints the marker (typed text)        -> must be 0 outside `limit` tags
  A2 the same for the hook's rewritten text                                           -> must be 0
  C  a rewritten command's stdout differs from the typed one's (stub ssh: stdin only) -> reported
  D  uncertain, not denied in bypass, and a shell prints the marker                   -> reported (what the literal rule missed)
`--hook-only` runs no shell (any host): B, counts and exceptions. Without it every case runs in every shell present, which is
allowed only inside the shell sandbox (tests/shell_sandbox.py). `--control REV` runs the same cases against the hook at an older
commit (read with git from this checkout) to show the fuzz can find holes. Worst case per shell run: echo/true/read/: strings,
a fresh private temp cwd, 2 s; stray empty files there. A case naming sudo or another privilege tool never reaches a shell.
"""
import io
import json
import os
import random
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ARGS = sys.argv[1:]
SEED, CASES, LIMIT = int(ARGS[0]), int(ARGS[1]), float(ARGS[2])
HOOK_ONLY = '--hook-only' in ARGS
CONTROL = ARGS[ARGS.index('--control') + 1] if '--control' in ARGS else None
SHOW = int(ARGS[ARGS.index('--show') + 1]) if '--show' in ARGS else 8
BASE = Path(tempfile.mkdtemp())
HOOKS = ROOT / 'harness' / 'hooks'
if CONTROL:
    archive = subprocess.run(['git', '-c', 'safe.directory=*', '-C', str(ROOT), 'archive', CONTROL, 'harness/hooks'], capture_output=True, check=True, timeout=60).stdout
    tarfile.open(fileobj=io.BytesIO(archive)).extractall(str(BASE / 'control'), **({'filter': 'data'} if hasattr(tarfile, 'data_filter') else {}))
    HOOKS = BASE / 'control' / 'harness' / 'hooks'
sys.path[:0] = [str(ROOT), str(HOOKS)]
os.environ['AGENT_HARNESS_RESERVE_DIR'] = str(BASE / 'reserve')
os.environ.pop('AGENT_HARNESS_TASK', None)
import ah_run  # noqa: E402
import host_table  # noqa: E402
from tests import shell_sandbox  # noqa: E402
from tests.test_ah_run import assert_no_real_sudo, names_a_privilege_tool  # noqa: E402

assert Path(ah_run.__file__).resolve().parent == HOOKS.resolve(), ah_run.__file__
if not HOOK_ONLY:
    shell_sandbox.require()
HOME = BASE / 'home'
(HOME / '.claude').mkdir(parents=True)
POLICY = BASE / 'policy.json'
POLICY.write_text(json.dumps({'hosts': {'dev2.example.test': {'role': 'worker', 'ah_run': '/opt/ah/ah_run.py'}}, 'self': []}))
BIN = BASE / 'bin'
BIN.mkdir()
(BIN / 'ssh').write_text('#!/bin/sh\n[ "$1" = "-G" ] && exit 0\ncat\n')
(BIN / 'ssh').chmod(0o755)
if not HOOK_ONLY:
    shell_sandbox.fold_links(str(BIN))  # r9 F1: folded spellings resolve, as on a case-insensitive Mac
ENV = {**os.environ, 'PATH': '%s:%s' % (BIN, os.environ['PATH']), 'HOME': str(HOME)}
SHELLS = {}
for name, path in (('bash5', '/opt/homebrew/bin/bash'), ('bash5', '/usr/bin/bash'), ('bash3', '/usr/local/bin/bash'), ('bash3', '/bin/bash'), ('zsh', '/bin/zsh'),
                   ('sh', '/bin/sh'), ('dash', '/bin/dash'), ('ksh', '/bin/ksh')):
    if name not in SHELLS and os.access(path, os.X_OK) and path not in SHELLS.values():
        SHELLS[name] = path
if HOOK_ONLY:
    SHELLS = {}

rng = random.Random(SEED)
H = 'echo HIDDEN-LINE'
# -- round 5 atoms (fuzz3)
TOK = ['echo', 'true', 'read x', ' ', ' ', ' ', '\n', '\n', '\n', '<<E', "<<'E'", '<<"E"', '<<-E', '<<\\E', '<< E', '<<<', '<<', 'E', 'E', '\tE', "'", "'", '"', '"', '#', ' #', '\\',
       '\\\n', '\\\n', '$', '$x', '${x}', '${', '}', "$'", '$"', '`', '$(', '(', ')', '((', '))', '$((', '$[', ']', ';', ';;', '&', '&&', '|', '||', '|&', '&>', '<', '>', '<>', '<&',
       '>&', '=', 'case x in x)', 'esac', 'if true; then', 'fi', 'for i in 1; do', 'done', '{ ', '; }', 'a=', '[', '[[', ']]', '!', '~', '\r', '\t', '2', ',', 'time ', 'ssh dev2 cat',
       'ssh ext cat', "ssh dev2 'cat > f'", 'ssh dev2 ls', H, H, H]
OPEN = ['true <<E', 'echo a <<E', "true <<'E'", 'true <<-E', 'read x <<E', 'true <<A <<E', 'ssh dev2 cat <<E', "ssh dev2 cat <<'E'", "ssh ext cat <<'E'", "ssh dev2 'cat > f' <<'E'"]
BODY = ['E\\\n', 'b\\\n', 'b \\\n', '\\\n', '\n', H + '\n', 'E\n', "'\n", '"\n', '`\n', '$(\n', 'ssh dev2 ls\n', '# c\n', 'E \n', 'x\n']
# -- round 6 atoms (the r6 reviewer's grammar fuzz)
OPS = [':-', '-', ':=', '=', ':+', '+', ':?', '#', '##', '%', '%%', '/', '//', ':', '^', '^^', ',', ',,', '@']
WORDS = ['', 'a', ' ', ' #', '#', ' a #', '\\}', '$x', '$(true)', '`true`', '(', ')', ';', '&', '|', '<', '>', '<<E', '\\\\', '[', ']', '{', '${y}', '${y:-}', '${y:- #}', '$((1))',
         '$[1]', "\\'", '\\"', '$', '!', '~', '=', '*', '?', '\t#', ' \\#', '\\ #', "'", '"', "' '", '" "']
ANSI = ['', 'a', '\\\\', '\\n', '\\x27', '\\047', '\\u0027', '\\c', '\\cx', '\\c\\\\', '\\e', '\\"', '\\?', '\\x', '\\8', '\\400', '\\ca', "\\'", '\\1', '#', ' #', '"', '`', '$(', '\\\n', '\n']
GROUPS = ['$(true)', '$(true;true)', '$( true )', '$( (true) )', '$((1))', '$((1)', '$(( 1 ))', '$((16#f))', '$((1<<2))', '$((1 #))', '((1))', '((1)', '((1))#', '$[1]', '$[1',
          '`true`', '`echo \\`true\\``', '`true #`', '$(true #)', '$(case x in x) true;; esac)', '$(for i in 1; do true; done)', '$(if true; then true; fi)', '$({ true; })',
          '$(f() { true; })', '<(true)', '>(true)', '=(true)', '$(<f)', '$(\n true\n)', '$(true\n)', '`\ntrue\n`', '${ true; }', '${| true; }', '${\ttrue; }']
WORDFORMS = ['a[1 #]=b', 'a[ #]=b', 'a=(b #c)', 'a=(b\n)', 'a+=(b)', '@(a #b)', '?(a #b)', '*(a #b)', '!(a #b)', 'a(b #c)', '$x[1 #]', '${x[1 #]}', '[a #b]', '{a,b #}', '{ #',
             '} #', '$#', '$#x', '${#x}', '$+x', '$~x', '$=x', '$^x', "$$'a'", "$#'a'", '$"a"', '\\#', '\\ #', '\\\t#', 'a\\ #', 'a#', '#', ' #', ';#', '&#', ')#', '}#', '>#',
             '\\\n#', ' \\\n#', 'a\\\nb', '\\\n', '\\\\\n', '[[ a = a #b ]]', '[[ a < b ]]', 'let a=1', 'case x in a #b) ;; esac', 'for i in a #b\ndo true; done', 'time true #',
             '{ true; } #', '(true)#', 'function f { true; }', 'f() { true; }', 'f()(true)', '<f', '>f', '2>&1', '&>f', '<<<a', '<<< #', '~', '=true', '<1-2>', '\r', '\f',
             '\v', 'a\rb', '\x7f', '\xa0', '　#', 'é#', '\f#', '\v#', '\x1c#', '\x85#', '\xa0#', 'a\f#', '\x1f']
# -- round 6 classes: parse-changing words and quoted-code hosts (B19-B22)
HOSTS = ['function f { %s; }; f', 'f () { %s; }; f', "alias e='%s'\ne", "shopt -s expand_aliases\nalias e='%s'\ne", 'repeat 1 %s', 'noglob %s', 'nocorrect %s',
         'if [[ 1 = 1 ]] %s', '{ true } always { %s }', 'for i in 1 { %s }', 'for i (1) %s', "trap '%s' EXIT", "eval '%s'", "bash -c '%s'", 'echo "${ %s; }"',
         'find . -maxdepth 0 -exec %s \\;', 'echo | xargs %s', "env -S '%s'", "emulate sh -c '%s'", "x='$(%s)'; echo ${(e)x}", "PS4='$(%s)'; set -x; true",
         "ssh -o 'ProxyCommand=%s' dev2 ls", 'nice -n 1 %s', 'stdbuf -o0 %s', 'command %s', 'exec %s', 'echo %s | sh', 'sh <<<"%s"',
         # r7 review: the program behind a wrapper spelling, source and . input, ~ paths, code through a variable (H1, M1, M2, L1)
         'source <(echo %s)', '. <(echo %s)', "echo '%s' | . /dev/stdin", "echo '%s' | . /proc/self/fd/0", "source /dev/fd/0 <<< '%s'",
         "source /proc/self/fd/0 <<< '%s'", ". /proc/self/fd/3 3<<'E'\n%s\nE", "bash /proc/self/fd/3 3<<'E'\n%s\nE", '~/../../../../../../../../bin/%s', 'p=\'$(\'; t="a[${p}%s >&3)]"; { echo $((t)); } 3>&1',
         'p=\'$(\'; v="a[${p}%s >&3)]"; { printf -v "$v" x; } 3>&1',
         # r8 review (round 3): a subscript in a builtin's variable name (F2)
         'p=\'$(\'; t="b[${p}%s >&3)]"; { read \'a[t]\' <<< x; } 3>&1', 'p=\'$(\'; t="b[${p}%s >&3)]"; { printf -v \'a[t]\' x; } 3>&1',
         'p=\'$(\'; t="b[${p}%s >&3)]"; { [ -v \'a[t]\' ]; } 3>&1']
# every spelling of the wrappers the hook reads through, known and unknown, chained before the marker (r7 H1)
WRAPS = ['nice', 'nice -n5', 'nice -n 5', 'nice --adjustment 5', 'nice --adjustment=5', 'nice --10', 'nice -10', 'nice -+3', 'nice 5', 'nice --adj=5',
         'timeout 5', 'timeout --signal KILL 5', 'timeout -sKILL 5', 'timeout --kill-after 1 5', 'timeout -k1 5', 'timeout -fv 5', 'timeout 5x',
         'env', 'env -i', 'env -vS', 'env -u X', 'env -uX', 'env -P /bin', 'env -a x', 'env A=1', 'env - A=1', 'env --unset X', 'env --chdir=/',
         'exec', 'exec -la x', 'exec -a x', 'exec -c', 'exec -x', 'command', 'command -p', 'command -pV', 'command -x', 'builtin', 'builtin -x',
         'time', 'time -p', 'time -o /dev/null', 'time -v', 'nohup', 'nohup --', 'nohup -x', '--', '-n', '5']
FIRST = ['', '', 'echo "$(echo \'x\')"\n', 'echo $(true)\n', 'true # x\n', "echo 'a'\n"]
SEP = ['; ', '\n', ' && ', ' | ', ' || ', ' & ', ';', '&&', '|', '\n\n', ';\n', '&\n']
TAIL = ['', '', '', ' #', " #'", ' #"', "\n#'", '\n#"', " '", ' "', '\n`', ' `', '\n)', ')', '\n}', '}', '))', ']', "\n$'", ' #`', '\nE', '\nE\n']
CMD = ['true', 'echo a', ':', 'true a']


def soup(a, b):
    return ''.join(rng.choice(TOK) for _ in range(rng.randint(a, b)))


def atom():
    r = rng.random()
    if r < .2:
        return '${x%s%s}' % (rng.choice(OPS), rng.choice(WORDS))
    if r < .3:
        return "$'%s'" % rng.choice(ANSI)
    if r < .45:
        return rng.choice(GROUPS)
    if r < .9:
        return rng.choice(WORDFORMS)
    return '"%s"' % rng.choice(['$(true)', '`true`', '$((1))', '${x}', "'", '#', ' #', "$'", '\\"', '\\`', '${x:- #}', '${ true; }'])


def gen():
    r = rng.random()
    if r < .12:
        return rng.choice(OPEN) + rng.choice(['', ' ', ' #', "'", '"', ' \\\n', ' ' + soup(1, 3), ';', ' |', ' &', ')']) + '\n' + soup(0, 6) + '\n' + H + '\nE\n' + soup(0, 4)
    if r < .22:
        return rng.choice(OPEN) + rng.choice(['', ' ']) + '\n' + ''.join(rng.choice(BODY) for _ in range(rng.randint(0, 6))) + 'E\n' + rng.choice(['', H + '\n', 'echo a \\\n' + H + '\n', soup(0, 3)])
    if r < .3:
        return soup(3, 16)
    if r < .55:
        return rng.choice(CMD) + ' ' + atom() + rng.choice(['', '', ' ' + atom()]) + rng.choice(SEP) + H + rng.choice(TAIL)
    if r < .68:
        return atom() + rng.choice(SEP) + H + rng.choice(TAIL)
    if r < .82:
        return rng.choice(FIRST) + rng.choice(HOSTS) % H + rng.choice(['', '', '\n', '; true', rng.choice(TAIL)])
    if r < .92:
        return ' '.join(rng.choice(WRAPS) for _ in range(rng.randint(1, 3))) + ' ' + H + rng.choice(['', '', ' #', '; true'])
    return rng.choice(CMD) + ' ' + atom() + rng.choice(SEP) + atom() + rng.choice(SEP) + H + rng.choice(TAIL)


FOLD_WORD = re.compile(r'(?:^|(?<=[ \t\n;&|(\'"]))(%s)(?=[ \t\n;&|)\'"]|$)' % '|'.join(shell_sandbox.FOLDED_SPELLINGS))


def fold_mutation(command):
    """r8 review F1: one program word spelled as macOS's file system still finds it (`ECHO`, `NICE`, `ba\u017fh`)."""
    found = list(FOLD_WORD.finditer(command))
    if not found:
        return command
    hit = rng.choice(found)
    return command[:hit.start(1)] + rng.choice(shell_sandbox.FOLDED_SPELLINGS[hit.group(1)]) + command[hit.end(1):]


PY_BLANK = re.compile('[\\f\\v\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]')


def tags(command):
    """Which reported class a hit belongs to, so a control run shows what it found."""
    found = [name for name, pattern in (('py-blank', PY_BLANK), ('ansi-c', re.compile(r'\\c')), ('funsub', re.compile(r'\$\{[ \t\n|]')),
                                         ('param-hash', re.compile(r'\$\{[^}]*[ \t\n]#')), ('paren-hash', re.compile(r'[@?*+!a-z]\([^)]*[ \t\n]#')),
                                         ('subscript-hash', re.compile(r'\[[^\]]*[ \t\n]#')),
                                         ('r7-wrapper', re.compile(r'(?:^|[ ;&|])(?:nice|timeout|env|exec|command|builtin|time|nohup) -')),
                                         ('r7-source', re.compile(r'(?:source|\.) (?:<\(|/dev/|/proc/)')), ('r7-tilde', re.compile(r'~/\.\.')),
                                         ('r7-variable', re.compile(r'\$\(\(t\)\)|printf -v')),
                                         ('r9-fold', re.compile('|'.join(s for spellings in shell_sandbox.FOLDED_SPELLINGS.values() for s in spellings))),
                                         ('r9-name', re.compile(r"'a\[t\]'")),
                                         ('host', re.compile(r'function |\(\) \{|alias |repeat |noglob|nocorrect|always|trap |eval |-c \'|-exec|xargs|env -S|emulate|\(e\)|PS4|ProxyCommand|nice |stdbuf|exec |\| sh|sh <<<|\]\] echo|for i (in 1 \{|\()')))
             if pattern.search(command)]
    return found or ['NEW']


def settings(**lists):
    (HOME / '.claude' / 'settings.json').write_text(json.dumps({'permissions': lists}))


def decide(command, mode):
    payload = {'session_id': 's', 'tool_name': 'Bash', 'tool_input': {'command': command}, 'cwd': str(BASE), 'permission_mode': mode}
    return ah_run.decide(payload, home=str(HOME), env={'AGENT_HARNESS_RESOURCE_POLICY': str(POLICY)}, ancestors=lambda: []).get('hookSpecificOutput', {})


def stdout(shell, command):
    assert_no_real_sudo(command)
    cwd = tempfile.mkdtemp(dir=str(BASE))
    try:
        return subprocess.run([shell, '-c', command], env=ENV, cwd=cwd, capture_output=True, timeout=2, stdin=subprocess.DEVNULL).stdout.decode('utf-8', 'replace')  # bytes: text mode turns a CR into a line end
    except (subprocess.TimeoutExpired, ValueError):
        return None
    finally:
        shutil.rmtree(cwd, ignore_errors=True)


def shows(text):
    return text is not None and 'HIDDEN-LINE' in text.split('\n')


def resolve(target, ssh_args=(), run=None):
    return host_table.Resolved({'dev2': 'dev2.example.test'}.get(target, 'elsewhere.example.test'), 22)


RECURSIVE = re.compile(r'(?:^|[;&|\n ])(echo|true|read|cat|sh|bash|eval|alias|e|f|command|exec|nice|stdbuf|env|ssh)[ \t]*\([ \t]*\)')


def main():
    counts = dict(seen=0, certain=0, uncertain=0, deny=0, shell_cases=0, rewritten=0, exceptions=0, skipped=0)
    found = {key: [] for key in ('A', 'A2', 'B', 'C', 'D')}
    done, started = set(), time.monotonic()
    with mock.patch.object(host_table, 'resolve', resolve):
        while counts['seen'] < CASES and time.monotonic() - started < LIMIT:
            command = gen()
            if rng.random() < .15:
                command = fold_mutation(command)
            if command in done or '\0' in command or not command.strip(' \t\n'):
                continue
            if RECURSIVE.search(command) or names_a_privilege_tool(command):  # a function named like the command it calls recurses; the table has those rows
                counts['skipped'] += 1
                continue
            done.add(command)
            counts['seen'] += 1
            try:
                settings(deny=['Bash(echo HIDDEN-LINE:*)'])
                out = decide(command, 'bypassPermissions')
                uncertain = ah_run.parse_command(command).uncertain
                settings(allow=['Bash(*)'])
                default = decide(command, 'default').get('permissionDecision')
            except Exception as error:  # noqa: BLE001 -- any exception is a finding
                counts['exceptions'] += 1
                print('EXC', type(error).__name__, repr(command)[:200])
                continue
            counts['uncertain' if uncertain else 'certain'] += 1
            if uncertain and default == 'allow':
                found['B'].append(('-', command))
            if out.get('permissionDecision') == 'deny':
                counts['deny'] += 1
                continue
            if not SHELLS:
                continue
            counts['shell_cases'] += 1
            payload = shlex.split(out['updatedInput']['command'])[-1] if 'updatedInput' in out else None
            changed = payload is not None and payload != command
            counts['rewritten'] += changed
            for name, shell in SHELLS.items():
                typed = stdout(shell, command)
                if shows(typed):
                    found['D' if uncertain else 'A'].append((name, command))
                if changed:
                    new = stdout(shell, payload)
                    if shows(new) and not uncertain:
                        found['A2'].append((name, command))
                    if new != typed and stdout(shell, command) == typed:  # a second typed run screens out $$ and the like
                        found['C'].append((name, command))
    by_tag = {}
    for _shell, command in found['A']:
        for tag in tags(command):
            by_tag[tag] = by_tag.get(tag, 0) + 1
    report = {'seed': SEED, 'hook': 'control ' + CONTROL if CONTROL else 'head', 'shells': sorted(SHELLS), 'seconds': round(time.monotonic() - started, 1), **counts,
              **{key: len({command for _shell, command in rows}) for key, rows in found.items()}, 'A_by_tag': by_tag}
    print(json.dumps(report, sort_keys=True))
    for key, rows in found.items():
        for shell, command in sorted(set(rows), key=lambda row: len(row[1]))[:SHOW]:
            print(key, shell, ','.join(tags(command)), repr(command)[:200])
    return 1 if counts['exceptions'] or (not CONTROL and (found['A'] or found['A2'] or found['B'])) else 0


if __name__ == '__main__':
    raise SystemExit(main())
