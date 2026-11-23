"""Command-text rules for the takeover cleanup tools, shared by command_guard and kill_guard (goodqa#16441).

ACCIDENT PREVENTION, NOT AN ACCESS CONTROL: this sees command text only. No rule here reads, binds or checks a caller
identity any more: the tools no longer accept one (no --caller-session, no session variable, no ancestry), so there is
nothing for a spelling to forge (rescue of the round-2 BLOCK at a810e331, which removed rules G2, G3 and G4). What holds
is the code behind these rules: the verifier's foreign-session check with an always-unknown caller, takeover.py's
retired-session predicate, the hook's payload-bound own grant and ah_kill's own refusals. Two rules remain:

  W2  `ah.py takeover ...` must be one literal command of the documented grammar (no variable, substitution, glob, chain,
      pipe, redirect, leading assignment or --via); over ssh only the read-only `status --evidence-only --json` exists.
      kill_guard reuses the grammar (_takeover_problem) so a reason that says "kill" is not read as code.
  G5  The user's enable script, by either name (enable-takeover-cleanup.sh or enable_takeover_cleanup.py): an ALLOWLIST.
      A command that names it may carry no long option but --dry-run, --verify, --ref, --repo and --host, anywhere in
      the line (nested shells included), unless the whole line is one read-only command such as grep. An unknown
      spelling loses access, never gains it. The script itself also refuses --apply and --undo without a person: no
      agent variable, a terminal on stdin and stdout, and a typed nonce.

Stdlib only. refusal() returns None (allow) or one short refusal text.
"""
from __future__ import annotations

import os
import re
import shlex

ASSIGN = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')
OPERATOR = re.compile(r'^[;&|<>()]+$')
WRAPPERS = {'env', 'bash', 'sh', 'zsh', 'dash', 'command', 'exec', 'nohup', 'time', 'sudo', 'nice', 'xargs', 'eval', 'timeout'}
SHELLS = {'bash', 'sh', 'zsh', 'dash'}
ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
TICKET_RE = re.compile(r'^GoodQA [a-z0-9-]{1,32}#[0-9]{1,7}$')
PATH_RE = re.compile(r'^/[A-Za-z0-9_@+=:,.\- /]{1,1000}$')
FORM = ('python3 -I ~/.claude/hooks/ah.py takeover (status|claim|plan|cleanup) --from SESSION [that subcommand\'s flags] '
        '(Codex: ~/.codex/agent-harness/ah.py); one literal command, no variable, substitution, glob, chain, pipe, redirect, '
        'leading assignment or --via; over ssh only `takeover status --from S --evidence-only --json`')
# flag -> None (boolean) | tuple of choices | validator name; repeatable flags are listed in REPEAT
SUBS = {
    'status': {'--from': 'id', '--action': ('worktrees', 'processes'), '--evidence-only': None, '--json': None},
    'claim': {'--from': 'id', '--reason': 'text', '--ticket': 'ticket'},
    'plan': {'--from': 'id', '--action': ('worktrees', 'processes')},
    'cleanup': {'--from': 'id', '--action': ('worktrees', 'processes', 'stale-helpers'), '--reason': 'text',
                '--ticket': 'ticket', '--path': 'path', '--pid': 'pid', '--apply': None},
}
REPEAT = {'--path': 64, '--pid': 64}
SCRIPTS = ('enable-takeover-cleanup', 'enable_takeover_cleanup')  # the .sh front and the .py it runs
SCRIPT_OPTIONS = ('--dry-run', '--verify', '--ref', '--repo', '--host')
READ_ONLY = {'grep', 'rg', 'egrep', 'fgrep', 'git', 'cat', 'less', 'more', 'head', 'tail', 'sed', 'awk', 'wc', 'diff', 'ls',
             'file', 'stat', 'shasum', 'sha256sum', 'md5', 'echo', 'printf'}


def _tokens(text):
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ''
    return list(lexer)


def _segments(tokens):
    segment = []
    for token in tokens:
        if OPERATOR.fullmatch(token):
            if segment:
                yield segment
            segment = []
        else:
            segment.append(token)
    if segment:
        yield segment


def _commands(tokens, via='top', depth=0):
    """(assignment prefix, command words, via) for every simple command: wrappers stripped, ssh remote strings and
    `sh -c` bodies followed. via is top, ssh, sh or wrap, so W2 can tell a plain command from a nested one. Not a
    security boundary: G5 does not depend on it (it reads every word of the flattened text)."""
    for segment in _segments(tokens):
        index, prefix = 0, []
        while index < len(segment) and ASSIGN.match(segment[index]):
            prefix.append(segment[index])
            index += 1
        rest = segment[index:]
        if not rest:
            continue
        yield prefix, rest, via
        if depth >= 3:
            continue
        head = os.path.basename(rest[0])
        if head == 'ssh':
            last = rest[-1]  # the remote command is the last word
            if len(rest) > 2 and ' ' in last:
                try:
                    yield from _commands(_tokens(last), 'ssh', depth + 1)
                except ValueError:
                    yield [], ['ssh-unparsable', last], 'ssh'
        elif head in SHELLS and '-c' in rest and rest.index('-c') + 1 < len(rest):
            body = rest[rest.index('-c') + 1]
            try:
                yield from _commands(_tokens(body), 'sh', depth + 1)
            except ValueError:
                yield [], ['sh-unparsable', body], 'sh'
        elif head in WRAPPERS and head not in SHELLS:
            inner, extra = rest[1:], []
            while inner and (inner[0].startswith('-') or ASSIGN.match(inner[0])):
                if ASSIGN.match(inner[0]):
                    extra.append(inner[0])
                inner = inner[1:]
            if inner:
                yield prefix + extra, inner, 'wrap'


def _program(command):
    """(script basename, argument words) after `python3 [-I|-B|-u]...`; for a direct script the head itself."""
    if not command:
        return '', []
    head = os.path.basename(command[0])
    if re.fullmatch(r'python3?(?:\.\d+)?', head):
        words = command[1:]
        while words and words[0] in ('-I', '-B', '-u', '-E', '-s', '-S'):
            words = words[1:]
        return (os.path.basename(words[0]) if words else ''), words
    return head, command


def _ah_path_ok(word, remote=False):
    home = os.path.expanduser('~')
    allowed = ('.claude/hooks/ah.py', '.codex/agent-harness/ah.py') if remote else ()
    local = ('~/.claude/hooks/ah.py', '~/.codex/agent-harness/ah.py', os.path.join(home, '.claude/hooks/ah.py'),
             os.path.join(home, '.codex/agent-harness/ah.py'))
    return word in local or word in allowed or (remote and word in ('~/' + a for a in allowed))


def _valid(kind, value):
    if isinstance(kind, tuple):
        return value in kind
    if kind == 'id':
        return bool(ID_RE.fullmatch(value))
    if kind == 'ticket':
        return bool(TICKET_RE.fullmatch(value))
    if kind == 'text':
        return 0 < len(value) <= 500 and not re.search(r'[$`\x00-\x1f\x7f]', value)
    if kind == 'path':
        return bool(PATH_RE.fullmatch(value)) and '..' not in value.split('/')
    if kind == 'pid':
        return bool(re.fullmatch(r'[0-9]{1,7}', value)) and int(value) > 1
    return False


def _takeover_problem(command, remote=False):
    """None when `command` is one literal takeover command of the grammar, else why not."""
    head, words = _program(command)
    if not _ah_path_ok(words[0] if words else '', remote):
        return 'it must run the installed ah.py by its exact path'
    if command[0] not in ('python3', 'python') or command[1:2] != ['-I'] or words is command:
        return 'it must be `python3 -I <installed ah.py>`'
    rest = words[1:]
    if not rest or rest[0] != 'takeover' or len(rest) < 2 or rest[1] not in SUBS:
        return 'the subcommand must be status, claim, plan or cleanup'
    sub, grammar, flags, seen = rest[1], SUBS[rest[1]], rest[2:], {}
    index = 0
    while index < len(flags):
        key, eq, value = flags[index].partition('=') if flags[index].startswith('--') else (flags[index], '', '')
        if key not in grammar:
            return 'unknown flag %s for takeover %s' % (key[:30], sub)
        kind = grammar[key]
        if kind is None:
            if eq:
                return '%s takes no value' % key
        else:
            if not eq:
                index += 1
                if index >= len(flags):
                    return '%s needs a value' % key
                value = flags[index]
            if not _valid(kind, value):
                return 'the value of %s is not accepted' % key
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > REPEAT.get(key, 1):
            return '%s may not be repeated' % key
        index += 1
    if '--from' not in seen:
        return '--from is required'
    if sub == 'claim' and not {'--reason', '--ticket'} <= set(seen):
        return 'claim needs --reason and --ticket'
    if sub == 'cleanup' and not {'--action', '--reason', '--ticket'} <= set(seen):
        return 'cleanup needs --action, --reason and --ticket'
    if remote and not (sub == 'status' and '--evidence-only' in seen and '--json' in seen and set(seen) <= {'--from', '--evidence-only', '--json'}):
        return 'over ssh only `takeover status --from S --evidence-only --json` exists'
    return None


def _flat(text):
    return re.sub(r'[\'"\\]', '', text)


def _base(word):
    return os.path.basename(_flat(word).rstrip('/'))


def _script_refusal(text):
    """G5: None, or why a command that names the user's enable script is refused (see the module docstring)."""
    flat = _flat(text)
    if not any(stem in flat for stem in SCRIPTS):
        return None
    try:
        tokens = _tokens(text)
    except ValueError:
        return 'a command that names the enable script could not be parsed; run it alone and plainly'
    if tokens and not any(OPERATOR.fullmatch(t) for t in tokens) and _base(tokens[0]) in READ_ONLY:
        return None  # one read-only command (grep, cat, git ...) that only reads the script
    for word in re.split(r'[\s;&|<>()`$=]+', flat):
        if word.startswith('--') and word != '--' and word not in SCRIPT_OPTIONS:
            return ('the enable script runs only with --dry-run or --verify (and --ref, --repo, --host) when an agent '
                    'runs it; %s is the user\'s (they run --apply and --undo themselves in a terminal)' % word[:30])
    return None


def refusal(command, session=None, home=None, only=None):
    """None, or the refusal text, for a command outside the allowed takeover forms. `only` limits the rules to some of
    W2 and G5. `session` and `home` are accepted for the callers' signature and ignored: no rule depends on who calls."""
    def on(code):
        return only is None or code in only

    text = command if isinstance(command, str) else ' '.join(map(str, command))
    if on('G5'):
        found = _script_refusal(text)
        if found:
            return found
    if not on('W2') or 'takeover' not in _flat(text):
        return None
    try:
        tokens = _tokens(text)
        found = list(_commands(tokens))
    except ValueError:
        return ('the command could not be parsed and names ah.py next to the word takeover; write it as one plain '
                'literal command') if 'ah.py' in _flat(text) else None
    top = [c for _p, c, via in found if via == 'top']
    chained = any(OPERATOR.fullmatch(t) for t in tokens)
    for prefix, cmd, via in found:
        if cmd[0] in ('ssh-unparsable', 'sh-unparsable'):
            body = _flat(cmd[1])
            if 'ah.py' in body and 'takeover' in body:
                return 'a nested command that could not be parsed names ah.py next to the word takeover'
            continue
        bases = [_base(w) for w in cmd]
        if bases[0] in READ_ONLY:
            continue
        at = [i for i, b in enumerate(bases) if b == 'ah.py' and cmd[i + 1:i + 2] == ['takeover']]
        if not at:
            continue
        if via in ('wrap', 'sh'):
            problem = 'it may not be wrapped in another command'
        elif prefix:
            problem = 'a leading environment assignment is not allowed'
        elif via == 'ssh':
            problem = None if len(top) == 1 and not chained else 'it is not the only command on the line'
            problem = problem or _takeover_problem(cmd, remote=True)
        else:
            problem = 'it is not the only command on the line' if len(top) != 1 or chained \
                else _takeover_problem(cmd, remote=False)
        if problem:
            return 'ah.py takeover: %s. Form: %s' % (problem, FORM)
    return None
