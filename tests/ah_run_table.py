"""Maintains tests/fixtures/ah_run/differential.json, the hook's differential table (GoodQA goodqa#14548).

`--columns` (any host, no shell runs): adds the rows below that the table lacks, recomputes every row's hook columns
(verdict, deny in bypass, rewritten) and writes the table back. It refuses to write when an existing row moves toward
certain or loses its deny: a row may only move toward uncertain and toward deny. Prints each moved row.

`--pin OUT` (only inside the shell sandbox, tests/shell_sandbox.py): runs every live row in every shell present, writes the
shell columns (ran, unstable) and `pinned_on` for this host to OUT; `--pin -` prints the table between PINNED-TABLE-BEGIN and
PINNED-TABLE-END lines instead, for a sandbox whose files do not outlive the run. Live rows print only the echo marker; a row naming sudo
or another privilege tool is data only and never reaches a shell. PATH holds shell_sandbox.fold_links, the sandbox's stand-in for
macOS finding `ECHO` or `ba\u017fh` as echo or bash (r9 F1).

Run from the repository root: `python3 tests/ah_run_table.py --columns` or `python3 tests/ah_run_table.py --pin /tmp/table.json`.
"""
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'harness' / 'hooks')]
BASE = Path(tempfile.mkdtemp())
os.environ['AGENT_HARNESS_RESERVE_DIR'] = str(BASE / 'reserve')
os.environ.pop('AGENT_HARNESS_TASK', None)
import ah_run  # noqa: E402
import host_table  # noqa: E402
from tests import shell_sandbox  # noqa: E402
from tests.test_ah_run import assert_no_real_sudo, names_a_privilege_tool  # noqa: E402

FIXTURE = ROOT / 'tests' / 'fixtures' / 'ah_run' / 'differential.json'
FIRST = 'echo "$(echo \'x\')"\n'  # an unrelated first line that makes the text uncertain (r6 hand3 A)
NEW_ROWS = [  # (group, name, shape, kind); kind `limit` names what the hook does not claim
    ('r6-B15', 'param-blank-hash', 'echo ${x:- #}; %s', 'hidden'),
    ('r6-B15', 'param-tab-hash', 'echo ${x:-\t#}; %s', 'hidden'),
    ('r6-B15', 'param-word-hash', 'echo ${x:-a #b}; %s', 'hidden'),
    ('r6-B15', 'param-pct-hash', 'echo ${x% #}; %s', 'hidden'),
    ('r6-B15', 'subscript-hash', 'echo ${x[1 #]}; %s', 'hidden'),
    ('r6-B15', 'param-and', 'true ${x:- #} && %s', 'hidden'),
    ('r6-B15', 'param-pipe', 'true ${x:- #} | %s', 'hidden'),
    ('r6-B15', 'param-newline-hash', 'echo ${x:-\n#}; %s', 'hidden'),
    ('r6-B15', 'extglob-at', 'echo @(a #b); %s', 'hidden'),
    ('r6-B15', 'extglob-shopt', 'shopt -s extglob\necho @(a #b); %s', 'hidden'),
    ('r6-B15', 'noglob-paren', 'noglob true a(b #c); %s', 'hidden'),
    ('r6-B15', 'array-assign', ': a=(b #c) & %s', 'hidden'),
    ('r6-B15', 'subscript-assign', 'a[1 #]=b|%s', 'hidden'),
    ('r6-B16', 'ansi-c-newline', "echo $'\\c'\n%s\n#'", 'hidden'),
    ('r6-B16', 'ansi-c-semicolon', "echo $'\\c' ; %s #'", 'hidden'),
    ('r6-B16', 'ansi-c-pipe', "true $'\\c' | %s #'", 'hidden'),
    ('r6-B17', 'funsub', 'echo ${ %s; }', 'hidden'),
    ('r6-B17', 'funsub-dq', 'echo "${ %s; }"', 'hidden'),
    ('r6-B17', 'funsub-tab', 'echo ${\t%s; }', 'hidden'),
    ('r6-B17', 'funsub-heredoc', 'cat <<E\n${ %s; }\nE', 'hidden'),
    ('r6-B17', 'funsub-valueless', 'echo ${| %s; }', 'hidden'),
    ('r6-B18', 'formfeed-hash', '\f# ; %s', 'hidden'),
    ('r6-B18', 'formfeed-line', '\f#x\n%s', 'hidden'),
    ('r6-B18', 'vtab-line', '\v#x\n%s', 'hidden'),
    ('r6-B18', 'nbsp-line', '\u00a0#x\n%s', 'hidden'),
    ('r6-B18', 'nel-line', '\u0085#x\n%s', 'hidden'),
    ('r6-B18', 'ideographic-line', '\u3000#x\n%s', 'hidden'),
    ('r6-B18', 'fs-line', '\x1c#x\n%s', 'hidden'),
    ('r6-B18', 'cr-line', '\r#x\n%s', 'hidden'),
    ('r6-B19', 'function-brace', 'function f { %s; }; f', 'hidden'),
    ('r6-B19', 'function-paren', 'function f () { %s; }; f', 'hidden'),
    ('r6-B19', 'name-paren', 'f () { %s; }; f', 'hidden'),
    ('r6-B19', 'name-paren-newline', 'f()\n{\n%s\n}\nf', 'hidden'),
    ('r6-B20', 'alias-heredoc', 'alias t="echo \'"\nt <<E #\'\n%s\nE', 'hidden'),
    ('r6-B20', 'alias-plain', "alias e='%s'\ne", 'hidden'),
    ('r6-B20', 'alias-shopt', "shopt -s expand_aliases\nalias e='%s'\ne", 'hidden'),
    ('r6-B20', 'alias-setopt', "setopt aliases\nalias e='%s'\ne", 'hidden'),
    ('r6-B20', 'histchars', "histchars='x'\n%s", 'hidden'),
    ('r6-B20', 'emulate', "emulate sh -c '%s'", 'hidden'),
    ('r6-B21', 'repeat', 'repeat 1 %s', 'hidden'),
    ('r6-B21', 'noglob', 'noglob %s', 'hidden'),
    ('r6-B21', 'nocorrect', 'nocorrect %s', 'hidden'),
    ('r6-B21', 'short-if', 'if [[ 1 = 1 ]] %s', 'hidden'),
    ('r6-B21', 'always', '{ true } always { %s }', 'hidden'),
    ('r6-B21', 'brace-if', 'if true { %s }', 'hidden'),
    ('r6-B21', 'brace-for', 'for i in 1 { %s }', 'hidden'),
    ('r6-B21', 'paren-for', 'for i (1) %s', 'hidden'),
    ('r6-B21', 'brace-while', 'while true { %s; break }', 'hidden'),
    ('r6-B21', 'foreach', 'foreach i (1)\n%s\nend', 'hidden'),
    ('r6-B21', 'amp-pipe', 'true &| %s', 'hidden'),
    ('r6-B22', 'funsub', FIRST + 'echo "${ %s; }"', 'hidden'),
    ('r6-B22', 'function', FIRST + 'function f { %s; }; f', 'hidden'),
    ('r6-B22', 'alias', FIRST + "alias e='%s'\ne", 'hidden'),
    ('r6-B22', 'repeat', FIRST + 'repeat 1 %s', 'hidden'),
    ('r6-B22', 'noglob', FIRST + 'noglob %s', 'hidden'),
    ('r6-B22', 'short-if', FIRST + 'if [[ 1 = 1 ]] %s', 'hidden'),
    ('r6-B22', 'always', FIRST + '{ true } always { %s }', 'hidden'),
    ('r6-B22', 'trap', FIRST + "trap '%s' EXIT", 'hidden'),
    ('r6-host', 'trap-exit', "trap '%s' EXIT", 'hidden'),
    ('r6-host', 'trap-debug', "trap '%s' DEBUG; true", 'hidden'),
    ('r6-host', 'eval', "eval '%s'", 'hidden'),
    ('r6-host', 'bash-c', "bash -c '%s'", 'hidden'),
    ('r6-host', 'sh-c', "sh -c '%s'", 'hidden'),
    ('r6-host', 'find-exec', 'find . -maxdepth 0 -exec %s \\;', 'hidden'),
    ('r6-host', 'xargs', 'echo | xargs %s', 'hidden'),
    ('r6-host', 'git-alias', "git -c alias.z='!%s' z", 'hidden'),
    ('r6-host', 'env-split', "env -S '%s'", 'hidden'),
    ('r6-host', 'ps4', "PS4='$(%s)'; set -x; true", 'hidden'),
    ('r6-host', 'zsh-e-flag', "x='$(%s)'; echo ${(e)x}", 'hidden'),
    ('r6-host', 'zsh-glob-qualifier', "echo *(e:'%s':)", 'hidden'),
    ('r6-host', 'arith-subscript', "x='a[$(%s)]'; [[ $x -eq 0 ]]", 'hidden'),
    ('r6-host', 'let-subscript', "let 'a[$(%s)]=1'", 'hidden'),
    ('r6-host', 'printf-v', "printf -v 'a[$(%s)]' x", 'hidden'),
    ('r6-host', 'declare', "declare 'a[$(%s)]=1'", 'hidden'),
    ('r6-host', 'test-v', "test -v 'a[$(%s)]'", 'hidden'),
    ('r6-host', 'mapfile-callback', "echo | mapfile -C '%s' -c 1 x", 'hidden'),
    ('r6-host', 'compgen-w', "compgen -W '$(%s)'", 'hidden'),
    ('r6-host', 'source-dev', ". /dev/stdin <<'E'\n%s\nE", 'hidden'),
    ('r6-wrapper', 'stdbuf', 'stdbuf -o0 %s', 'hidden'),
    ('r6-wrapper', 'nice', 'nice -n 1 %s', 'hidden'),
    ('r6-wrapper', 'timeout', 'timeout 5 %s', 'hidden'),
    ('r6-wrapper', 'command-p', 'command -p %s', 'hidden'),
    ('r6-wrapper', 'exec', 'exec %s', 'hidden'),
    ('r6-wrapper', 'busybox', 'busybox sh -c "%s"', 'hidden'),
    ('r6-path', 'absolute', '/bin/echo HIDDEN-LINE', 'hidden'),
    ('r6-path', 'relative', './echo HIDDEN-LINE', 'hidden'),
    ('r6-path', 'glob-question', '/bin/ec?o HIDDEN-LINE', 'hidden'),
    ('r6-path', 'glob-bracket', '/bin/ec[h]o HIDDEN-LINE', 'hidden'),
    ('r6-path', 'double-quoted-arg', 'echo "HIDDEN-LINE"', 'hidden'),
    ('r6-path', 'quoted-program', "'echo' HIDDEN-LINE", 'hidden'),
    ('r6-path', 'built-program-name', 'ec$(true)ho HIDDEN-LINE', 'limit'),
    ('r6-path', 'substituted-program', '$(echo echo) HIDDEN-LINE', 'limit'),
    ('r6-state', 'shopt', 'shopt -s expand_aliases\n%s', 'hidden'),
    ('r6-state', 'setopt', 'setopt aliases\n%s', 'hidden'),
    ('r6-state', 'set-o', 'set -o posix\n%s', 'hidden'),
    ('r6-state', 'unalias', 'unalias -a\n%s', 'hidden'),
    ('r6-state', 'bash-aliases', "BASH_ALIASES[e]='%s'\ne", 'hidden'),
    ('r6-state', 'zsh-aliases', "aliases[e]='%s'\ne", 'hidden'),
    ('r6-state', 'zsh-functions', "functions[f]='%s'\nf", 'hidden'),
    ('r6-state', 'enable-n', 'enable -n echo\n%s', 'hidden'),
    ('r6-state', 'path', 'PATH=/nonexistent:$PATH\n%s', 'hidden'),
    ('r6-state', 'hash-renames-a-program', 'hash -p /bin/echo e\ne HIDDEN-LINE', 'limit'),
    ('r6-limit', 'built-from-data', 'x=ec; y=ho; $x$y HIDDEN-LINE', 'limit'),
    ('r6-limit', 'read-from-a-body', "read -r x y <<'E'\n%s\nE\n$x $y", 'hidden'),
    ('r6-limit', 'python-c', 'python3 -c \'print("HIDDEN-LINE")\'', 'limit'),
    ('r6-limit', 'python-stdin', "python3 - <<'E'\nprint('HIDDEN-LINE')\nE", 'limit'),
    ('r6-limit', 'awk', "awk 'BEGIN { print \"HIDDEN-LINE\" }'", 'limit'),
    ('r6-limit', 'bash-env-file', 'BASH_ENV=./missing bash -c true', 'limit'),
    ('r6-limit', 'program-reads-env', 'GIT_PAGER="echo HIDDEN-LINE" git --no-pager log -1 >/dev/null 2>&1; true', 'limit'),
    ('r6-N22', 'proxy-command', "ssh -o 'ProxyCommand=%s' dev2 ls", 'hidden'),
    ('r6-N22', 'known-hosts-command', "ssh -o 'KnownHostsCommand=%s' dev2 ls", 'hidden'),
    ('r6-N22', 'local-command', "ssh -o PermitLocalCommand=yes -o 'LocalCommand=%s' dev2 ls", 'hidden'),
    ('r6-N22', 'attached-proxy', "ssh '-oProxyCommand %s' dev2 ls", 'hidden'),
    ('r6-N22', 'scp-proxy', "scp -o 'ProxyCommand=%s' a dev2:b", 'hidden'),
    ('r6-N22', 'session-type-none', 'ssh -o SessionType=none dev2', 'limit'),
    ('r6-N22', 'session-type-subsystem', 'ssh -o SessionType=subsystem dev2 sftp', 'limit'),
    ('r6-N22', 'config-file-proxy', 'ssh -F ./ssh_config dev2 ls', 'limit'),
    # r7 review (Opus max, round 2): wrapper spellings the old peel misread (H1), source and . reading a descriptor or a
    # substitution (M1), a program named through ~ (M2), and code a variable carries into arithmetic or a name (L1)
    ('r7-H1', 'nice-attached', 'nice -n5 %s', 'hidden'),
    ('r7-H1', 'nice-long-space', 'nice --adjustment 5 %s', 'hidden'),
    ('r7-H1', 'nice-long-equals', 'nice --adjustment=5 %s', 'hidden'),
    ('r7-H1', 'nice-double-dash-number', 'nice --10 %s', 'hidden'),
    ('r7-H1', 'timeout-long-signal', 'timeout --signal KILL 5 %s', 'hidden'),
    ('r7-H1', 'timeout-long-kill-after', 'timeout --kill-after 1 5 %s', 'hidden'),
    ('r7-H1', 'env-cluster-split', "env -vS '%s'", 'hidden'),
    ('r7-H1', 'env-bsd-path', 'env -P /bin %s', 'hidden'),
    ('r7-H1', 'exec-cluster-name', 'exec -la x %s', 'hidden'),
    ('r7-H1', 'time-output', 'time -o /dev/null %s', 'hidden'),
    ('r7-H1', 'nice-attached-nohup', 'nice -n5 nohup %s', 'hidden'),
    ('r7-H1', 'nice-attached-bash-heredoc', "nice -n5 bash <<'E'\n%s\nE", 'hidden'),
    ('r7-H1', 'sudo-cluster', 'sudo -Eu root %s', 'hidden'),
    ('r7-M1', 'source-procsub', 'source <(echo %s)', 'hidden'),
    ('r7-M1', 'dot-procsub', '. <(echo %s)', 'hidden'),
    ('r7-M1', 'source-proc-fd-here-string', "source /proc/self/fd/0 <<< '%s'", 'hidden'),
    ('r7-M1', 'dot-proc-fd-pipe', "echo '%s' | . /proc/self/fd/0", 'hidden'),
    ('r7-M1', 'dot-dev-stdin-pipe', "echo '%s' | . /dev/stdin", 'hidden'),
    ('r7-M1', 'dot-proc-fd-heredoc', ". /proc/self/fd/3 3<<'E'\n%s\nE", 'hidden'),
    ('r7-M1', 'bash-proc-fd-heredoc', "bash /proc/self/fd/3 3<<'E'\n%s\nE", 'hidden'),
    ('r7-M2', 'tilde-dotdot-program', '~/../../../../../../../../bin/%s', 'hidden'),
    ('r7-L1', 'arith-variable', 'p=\'$(\'; t="a[${p}%s >&3)]"; { echo $((t)); } 3>&1', 'hidden'),
    ('r7-L1', 'printf-dynamic-name', 'p=\'$(\'; v="a[${p}%s >&3)]"; { printf -v "$v" x; } 3>&1', 'hidden'),
    # r8 review (Opus max, round 3): a program spelled in another case or Unicode form, which macOS's file system finds (F1;
    # the sandbox stands in with shell_sandbox.fold_links), and a subscript in a builtin's variable name (F2)
    ('r8-F1', 'upper-program', 'ECHO HIDDEN-LINE', 'hidden'),
    ('r8-F1', 'capital-program', 'Echo HIDDEN-LINE', 'hidden'),
    ('r8-F1', 'upper-path-program', '/BIN/ECHO HIDDEN-LINE', 'hidden'),
    ('r8-F1', 'quoted-upper-program', '"ECHO" HIDDEN-LINE', 'hidden'),
    ('r8-F1', 'upper-assign-program', 'X=1 ECHO HIDDEN-LINE', 'hidden'),
    ('r8-F1', 'upper-after-redirect', '2>/dev/null ECHO HIDDEN-LINE', 'hidden'),
    ('r8-F1', 'upper-nice', 'NICE -n 5 %s', 'hidden'),
    ('r8-F1', 'upper-env', 'ENV %s', 'hidden'),
    ('r8-F1', 'upper-env-split', "ENV -S '%s'", 'hidden'),
    ('r8-F1', 'upper-nohup', 'NOHUP %s', 'hidden'),
    ('r8-F1', 'upper-timeout', 'TIMEOUT 5 %s', 'hidden'),
    ('r8-F1', 'upper-bash-c', "BASH -c '%s'", 'hidden'),
    ('r8-F1', 'upper-bash-heredoc', "BASH <<'E'\n%s\nE", 'hidden'),
    ('r8-F1', 'long-s-bash-heredoc', '"ba\u017fh" <<\'E\'\n%s\nE', 'hidden'),
    ('r8-F1', 'kelvin-ksh-c', '"\u212a\u017fh" -c \'%s\'', 'hidden'),
    ('r8-F2', 'read-subscript-name', 'p=\'$(\'; t="b[${p}%s >&3)]"; { read \'a[t]\' <<< x; } 3>&1', 'hidden'),
    ('r8-F2', 'printf-subscript-name', 'p=\'$(\'; t="b[${p}%s >&3)]"; { printf -v \'a[t]\' x; } 3>&1', 'hidden'),
    ('r8-F2', 'printf-attached-subscript-name', 'p=\'$(\'; t="b[${p}%s >&3)]"; { printf -v\'a[t]\' x; } 3>&1', 'hidden'),
    ('r8-F2', 'test-subscript-name', 'p=\'$(\'; t="b[${p}%s >&3)]"; { test -v \'a[t]\'; } 3>&1', 'hidden'),
    ('r8-F2', 'bracket-subscript-name', 'p=\'$(\'; t="b[${p}%s >&3)]"; { [ -v \'a[t]\' ]; } 3>&1', 'hidden'),
    ('r8-limit', 'unknown-launcher', 'prlimit --nofile=64 %s', 'limit'),  # GoodQA goodqa#14793: a launcher outside the grammar
    # r9 native review (Opus max): `NAME+=v` is an assignment to bash, zsh and ksh, and env reads any word holding `=` as one
    ('r9-N1', 'plus-assign', 'A+=1 %s', 'hidden'),
    ('r9-N1', 'env-any-equals', 'env A-B=1 %s', 'hidden'),
    ('r9-N1', 'env-quoted-assign', "env 'A=1' %s", 'hidden'),
]
RULE = 'Bash(echo HIDDEN-LINE:*)'
SSH_STUB = '#!/bin/sh\n[ "$1" = "-G" ] && { for last; do :; done; printf "hostname %s\\nport 22\\n" "$last"; exit 0; }\ncat\n'
SUDO_STUB = '#!/bin/sh\nexit 126\n'


def resolve(target, ssh_args=(), run=None):
    return host_table.Resolved({'dev2': 'dev2.example.test'}.get(target, 'elsewhere.example.test'), 22)


class Hook:
    def __init__(self):
        self.home = BASE / 'home'
        (self.home / '.claude').mkdir(parents=True, exist_ok=True)
        self.policy = BASE / 'policy.json'
        self.policy.write_text(json.dumps({'hosts': {'dev2.example.test': {'role': 'worker', 'ah_run': '/opt/ah/ah_run.py'}}, 'self': []}))
        (self.home / '.claude' / 'settings.json').write_text(json.dumps({'permissions': {'deny': [RULE]}}))

    def bypass(self, command):
        payload = {'session_id': 's', 'tool_name': 'Bash', 'tool_input': {'command': command}, 'cwd': str(BASE), 'permission_mode': 'bypassPermissions'}
        with mock.patch.object(host_table, 'resolve', resolve):
            return ah_run.decide(payload, home=str(self.home), env={'AGENT_HARNESS_RESOURCE_POLICY': str(self.policy)}, ancestors=lambda: [])['hookSpecificOutput']


def hook_columns(table):
    hook, line = Hook(), table['line']
    for row in table['rows']:
        command = row['shape'].replace('%s', line)
        out = hook.bypass(command)
        row['verdict'] = 'uncertain' if ah_run.parse_command(command).uncertain else 'certain'
        row['deny'] = out.get('permissionDecision') == 'deny'
        if 'updatedInput' not in out:
            row['rewritten'] = 'none'
        else:
            row['rewritten'] = 'same' if shlex.split(out['updatedInput']['command'])[-1] == command else 'changed'
        if names_a_privilege_tool(row['shape']):
            row['live'] = False


REGROUP = {('quiet-data', "cat <<'E' | xargs echo"): ('r6-host', 'xargs-body')}  # r6: xargs runs its input as program words


def columns():
    table = json.loads(FIXTURE.read_text())
    for row in table['rows']:
        row['group'], row['name'] = REGROUP.get((row['group'], row['name']), (row['group'], row['name']))
    before = {(row['group'], row['name']): (row['verdict'], row['deny'], row['rewritten']) for row in table['rows']}
    shapes = {row['shape'] for row in table['rows']}
    added = 0
    for group, name, shape, kind in NEW_ROWS:
        if (group, name) in before or shape in shapes:
            continue
        table['rows'].append({'group': group, 'name': name, 'shape': shape, 'kind': kind, 'ran': [], 'unstable': [],
                              'verdict': None, 'deny': None, 'rewritten': None})
        added += 1
    hook_columns(table)
    moved, defects = [], []
    for row in table['rows']:
        old = before.get((row['group'], row['name']))
        if old is None:
            continue
        new = (row['verdict'], row['deny'], row['rewritten'])
        if new != old:
            moved.append((row['group'], row['name'], old, new))
            if (old[0] == 'uncertain' and new[0] == 'certain') or (old[1] and not new[1]):
                defects.append(row['name'])
    for group, name, old, new in moved:
        print('moved %s:%s %s -> %s' % (group, name, '/'.join(map(str, old)), '/'.join(map(str, new))))
    print('rows %d, added %d, moved %d, defects %d' % (len(table['rows']), added, len(moved), len(defects)))
    if defects:
        print('refusing to write: a row moved toward certain or lost its deny: %s' % ', '.join(defects))
        return 1
    FIXTURE.write_text(json.dumps(table, indent=0, sort_keys=True) + '\n')
    return 0


def shells():
    found = {}
    for name, path in (('bash', '/bin/bash'), ('bash', '/opt/homebrew/bin/bash'), ('bash', '/usr/local/bin/bash'), ('bash', '/usr/bin/bash'), ('zsh', '/bin/zsh'), ('zsh', '/usr/bin/zsh'),
                       ('sh', '/bin/sh'), ('dash', '/bin/dash'), ('dash', '/usr/bin/dash'), ('ksh', '/bin/ksh'), ('ksh', '/usr/bin/ksh')):
        if os.access(path, os.X_OK):
            version = subprocess.run([path, '-c', 'echo ${BASH_VERSION:-}${ZSH_VERSION:-}${KSH_VERSION:-}'], capture_output=True, timeout=10).stdout.decode('utf-8', 'replace').strip('\n')
            key = name if name != 'bash' else 'bash' + version[:1]
            found.setdefault(key, (path, version))
    return found


def pin(output):
    shell_sandbox.require()  # every live row reaches real shells: only inside the sandbox container
    table = json.loads(FIXTURE.read_text())
    found = shells()
    binary = BASE / 'bin'
    binary.mkdir()
    for name, text in (('ssh', SSH_STUB), ('sudo', SUDO_STUB)):
        (binary / name).write_text(text); (binary / name).chmod(0o755)
    shell_sandbox.fold_links(str(binary))  # r9 F1: folded spellings resolve, as on a case-insensitive Mac
    (BASE / 'home').mkdir(exist_ok=True)  # an existing HOME, as the fuzz has: `~/../bin/x` resolves only through one (r7 M2)
    env = {**os.environ, 'PATH': '%s:%s' % (binary, os.environ['PATH']), 'HOME': str(BASE / 'home')}

    def stdout(path, command):
        assert_no_real_sudo(command)
        cwd = tempfile.mkdtemp(dir=str(BASE))
        try:
            return subprocess.run([path, '-c', command], env=env, cwd=cwd, capture_output=True, timeout=5, stdin=subprocess.DEVNULL).stdout.decode('utf-8', 'replace')
        except subprocess.TimeoutExpired:
            return None

    for row in table['rows']:
        if not row.get('live', True) or names_a_privilege_tool(row['shape']):
            row['live'], row['ran'], row['unstable'] = False, [], []
            continue
        command = row['shape'].replace('%s', table['line'])
        ran, unstable = [], []
        for name, (path, _version) in found.items():
            outs = [stdout(path, command) for _ in range(8 if '|' in command or '/dev/' in command else 3)]  # a pipeline into a shell can race
            seen = {text is not None and 'HIDDEN-LINE' in text.split('\n') for text in outs}
            if True in seen:
                ran.append(name)
            if len(seen) > 1:
                unstable.append(name)
        row['ran'], row['unstable'] = sorted(ran), sorted(unstable)
    table['pinned_on'] = {'platform': sys.platform, 'shells': {name: version for name, (_path, version) in sorted(found.items())}}
    text = json.dumps(table, indent=0, sort_keys=True) + '\n'
    if output == '-':
        sys.stdout.write('PINNED-TABLE-BEGIN\n' + text + 'PINNED-TABLE-END\n')
    else:
        Path(output).write_text(text)
    print('pinned %d rows on %s: %s' % (len(table['rows']), sys.platform, ', '.join('%s %s' % (k, v) for k, (_p, v) in sorted(found.items()))))
    return 0


if __name__ == '__main__':
    if sys.argv[1:2] == ['--columns']:
        raise SystemExit(columns())
    if sys.argv[1:2] == ['--pin'] and len(sys.argv) == 3:
        raise SystemExit(pin(sys.argv[2]))
    print(__doc__)
    raise SystemExit(2)
