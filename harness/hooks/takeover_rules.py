"""Command-text rules for the takeover cleanup tools, shared by command_guard and kill_guard (goodqa#16441).

ACCIDENT PREVENTION, NOT AN ACCESS CONTROL: like the install-files rule, this sees command text only, so a program that
speaks ssh or sets its environment by itself is invisible to it. What holds is the code behind it: the verifier's
foreign-session check, takeover.py's retired-session predicate and ah_kill's own refusals. These rules only stop an agent
from taking the shortcuts that would make those checks pointless:

  W2  `ah.py takeover ...` must be one literal command of the documented grammar (no variable, substitution, glob, chain,
      pipe, redirect, leading assignment or --via); over ssh only the read-only `status --evidence-only --json` exists.
  G2  `command_guard.py remove-worktree --caller-session X` is never typed by an agent (ah worktree-remove relays it).
  G3  A command that assigns CLAUDE_CODE_SESSION_ID or CODEX_THREAD_ID and also runs a harness tool is refused: the
      caller identity the tools read must not be set by the caller.
  G4  `wal.py continuation --wal P` may name only the caller's own session WAL.
  G5  `enable-takeover-cleanup.sh --apply|--undo` is the user's script; an agent may only dry-run or verify it.

Stdlib only. refusal() returns None (allow) or one short refusal text.
"""
from __future__ import annotations

import hashlib
import os
import re
import shlex

TOOLS = ('ah.py', 'command_guard.py', 'kill_guard.py', 'wal.py', 'takeover.py', 'enable-takeover-cleanup.sh')
SCRIPT = 'enable-takeover-cleanup.sh'
ID_VAR = re.compile(r'^(?:CLAUDE_CODE_SESSION_ID|CLAUDE_SESSION_ID|CODEX_THREAD_ID)=')
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


def safe_id(value):
    """codex/hooks/wal.py safe_id, copied so this module needs nothing else: the Codex WAL directory name of a session."""
    original = str(value or 'unknown')
    cleaned = re.sub(r'[^A-Za-z0-9._-]', '_', original)
    if (cleaned == original and cleaned == cleaned.lower() and len(cleaned) <= 120
            and cleaned.strip('.') and not cleaned.startswith('z-')):
        return cleaned
    digest = hashlib.sha256(original.encode(errors='replace')).hexdigest()[:20]
    stem = cleaned.lower()[:97].strip('.') or '_'
    return 'z-%s-%s' % (stem, digest)


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
    `sh -c` bodies followed. via is top, ssh, sh or wrap, so a rule can tell a plain command from a nested one."""
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


# Review F1 (BLOCK at db950737): the rules used to look for a tool only in the program slot after a fixed set of python
# flags, so `python3 -IB`, `-X utf8`, `-W ignore`, a quoted word or a trailing `# it's` walked past them. Now:
#   * a tool is found at ANY word position (its basename), whatever interpreter options come before it;
#   * G3 is judged on the quote-flattened text: an assignment of a session variable anywhere next to any harness tool;
#   * text that cannot be parsed is refused when it names a harness tool next to a word of an enabled rule;
#   * a dynamic word ($, `) in a direct verifier call, or in a continuation WAL path, is refused.
# This is still the second layer: the verifier works the caller out from its own ancestry (takeover.resolve_caller).
TOOL_STEMS = ('ah.py', 'command_guard', 'kill_guard', 'wal.py', 'takeover.py', 'ah_worktree', SCRIPT)
ID_ASSIGN = re.compile(r'(?:CLAUDE_CODE_SESSION_ID|CLAUDE_SESSION_ID|CODEX_THREAD_ID)\s*:?=')
RULE_WORDS = {'G2': ('remove-worktree', 'caller-session'), 'G3': ('CLAUDE_CODE_SESSION_ID', 'CLAUDE_SESSION_ID', 'CODEX_THREAD_ID'),
              'G4': ('continuation',), 'G5': (SCRIPT,), 'W2': ('takeover',)}
READ_ONLY = {'grep', 'rg', 'egrep', 'fgrep', 'git', 'cat', 'less', 'more', 'head', 'tail', 'sed', 'awk', 'wc', 'diff', 'ls',
             'file', 'stat', 'shasum', 'sha256sum', 'md5', 'echo', 'printf'}
DYNAMIC = re.compile(r'[$`]')


def _base(word):
    return os.path.basename(_flat(word).rstrip('/'))


def _values(words, flag):
    """Every value of `flag` (`--flag V` or `--flag=V`) in words."""
    out = []
    for index, word in enumerate(words):
        if word == flag and index + 1 < len(words):
            out.append(words[index + 1])
        elif word.startswith(flag + '='):
            out.append(word.split('=', 1)[1])
    return out


def refusal(command, session=None, home=None, only=None):
    """None, or the refusal text, for a command that touches the takeover tools outside the allowed forms. `only` limits the
    rules to some of G2, G3, G4, G5, W2 (kill_guard has no payload session, so it runs G3, G5 and W2 only)."""
    def on(code):
        return only is None or code in only

    text = command if isinstance(command, str) else ' '.join(map(str, command))
    flat = _flat(text)
    enabled = [code for code in RULE_WORDS if on(code)]
    if not any(word in flat for code in enabled for word in RULE_WORDS[code]):
        return None
    names_tool = any(stem in flat for stem in TOOL_STEMS)
    # G3: the caller must not set the identity the harness tools read (any spelling: prefix, env, export, ${X:=...})
    if on('G3') and names_tool and ID_ASSIGN.search(flat):
        return ('the caller identity (CLAUDE_CODE_SESSION_ID / CODEX_THREAD_ID) is read by the harness tools and may not be '
                'set in a command that runs them')
    try:
        tokens = _tokens(text)
        found = list(_commands(tokens))
    except ValueError:
        return ('the command could not be parsed and names a harness tool next to a takeover word; write it as one plain '
                'literal command') if names_tool else None
    top = [c for _p, c, via in found if via == 'top']
    chained = any(OPERATOR.fullmatch(t) for t in tokens)
    for prefix, cmd, via in found:
        if cmd[0] in ('ssh-unparsable', 'sh-unparsable'):
            body = _flat(cmd[1])
            if any(stem in body for stem in TOOL_STEMS) and any(w in body for c in enabled for w in RULE_WORDS[c]):
                return 'a nested command that could not be parsed names a harness tool next to a takeover word'
            continue
        bases = [_base(w) for w in cmd]
        head = bases[0]
        # G5: the user's script, in any position, unless the command only reads it
        if on('G5') and SCRIPT in bases and head not in READ_ONLY \
                and any(t in ('--apply', '--undo') or t.startswith(('--apply=', '--undo=')) for t in cmd):
            return ('enable-takeover-cleanup.sh --apply and --undo are run by the user only; an agent may run --dry-run or '
                    '--verify')
        verifier = any(b.startswith('command_guard') for b in bases) and head not in READ_ONLY
        # G2: an agent never passes --caller-session (ah worktree-remove derives and relays it); a dynamic word in a direct
        # verifier call could spell the subcommand or the flag
        if on('G2') and verifier and ('remove-worktree' in cmd or any(w.startswith('--caller-session') for w in cmd)):
            if any(w.startswith('--caller-session') for w in cmd):
                return ('command_guard.py remove-worktree --caller-session is passed by `ah.py worktree-remove` only; the '
                        'verifier works the caller out itself. Use `ah.py worktree-remove` or `ah.py takeover`')
        if on('G2') and verifier and any(DYNAMIC.search(w) for w in cmd) and ('remove-' in flat or 'caller' in flat):
            return 'a direct command_guard.py call with a variable or substitution in it is refused; spell it literally'
        # G4: only the caller's own continuation checkpoint
        if on('G4') and 'wal.py' in bases and 'continuation' in cmd and head not in READ_ONLY:
            wals = _values(cmd, '--wal')
            own = safe_id(session) if session else None
            if not wals or any(DYNAMIC.search(w) or os.path.basename(os.path.dirname(w)) != own for w in wals):
                return 'wal.py continuation may update only the caller\'s own session checkpoint'
        # W2: `ah.py takeover` anywhere in the command must be the one literal form
        if on('W2') and head not in READ_ONLY:
            at = [i for i, b in enumerate(bases) if b == 'ah.py' and cmd[i + 1:i + 2] == ['takeover']]
            if at:
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
