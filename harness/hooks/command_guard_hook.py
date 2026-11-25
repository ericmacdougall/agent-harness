#!/usr/bin/env python3
"""Fail-closed launcher for command_guard.py (GoodQA #14471). Registered as the PreToolUse hook command.

Codex treats a crashing or timing-out hook as "allow", and Claude Code does so unless the hook entry carries
`onFailure: block`. This launcher therefore never relies on the host: it runs the analyser in a child process with
a watchdog, passes its answer through, and when the child crashes, cannot start, prints garbage or runs out of
time, it decides from the raw text itself: a guarded shell tool whose input names a protected harness location,
a secret source, or a code-execution step plus a destructive verb is blocked (exit 2); anything else is allowed
with a note on stderr. It imports nothing outside the standard library and never imports command_guard.

The probe here is deliberately duplicated from command_guard.py (PROTECTED_TEXT, SECRET_TEXT, EXEC_TEXT,
DESTROY_TEXT, CRED_TEXT) so that a broken or missing analyser cannot also break the fallback.
"""

import json
import os
import re
import subprocess
import sys

CHILD_TIMEOUT = 25.0  # both installers register this hook with 30 s; 5 s are left for the fallback's own answer
MAX_STDIN = 8 * 1024 * 1024
GUARD = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'command_guard.py')
GUARDED_TOOLS = {'bash', 'powershell', 'shell', 'local_shell', 'exec_command', 'unified_exec', 'write_stdin',
                 'container.exec'}
COMMAND_KEYS = ('command', 'cmd', 'script', 'chars', 'input')

PROTECTED_TEXT = re.compile(r'(?i)\.(?:claude|codex|agent-harness)(?![\w-])|(?:^|[/\s\'"])wals?(?:/|$|[\s\'"])|'
                            r'main\.jsonl|\.wal\.jsonl')
SECRET_TEXT = re.compile(r'(?i)\brclone\b|\bauth\s+token\b|--show-token|\bprintenv\b|(?:^|[;&|(\s])(?:env|set|export'
                         r'|declare|typeset)(?:\s+-[px])?\s*(?:$|[;&|)])|credentials|\bid_(?:rsa|dsa|ecdsa|ed25519)\b'
                         r'|\.env\b|auth\.json|\.npmrc|\.netrc|\.pgpass|hosts\.yml|rclone\.conf|find-(?:generic|'
                         r'internet)-password|dump-keychain|/environ\b|(?:TOKEN|SECRET|PASSWORD|API_?KEY)\b')
EXEC_TEXT = re.compile(r'(?i)\|\s*(?:sudo\s+)?(?:ba|z|k|da|)sh\b|\beval\b|\b(?:ba|z|)sh\s+-[a-z]*c\b|'
                       r'\b(?:python[0-9.]*|node|perl|ruby)\s+-[a-z]*[ce]\b|base64\s+-[dD]|xxd\s+-r|\bsource\s+<\(')
DESTROY_TEXT = re.compile(r'(?i)\b(?:rm|rmdir|unlink|shred|truncate|mv|rmtree|remove|unlinksync|rmsync|dd|find)\b')
CRED_TEXT = re.compile(r'(?i)/goodqa(?![\w.-])|gq-browser|goodqa-hive|\.config/+[^\s/;&|<>()]*[*?\[{]'
                       r'|(?:^|[\s/=~:])\.(?:ssh|aws|gnupg|kube|docker)(?![\w-])|\.config/+(?:gh|gcloud|rclone)(?![\w-])'
                       r'|\.vault-token|\.git-credentials')


# --- calls that only record text (goodqa#17149, goodqa#17094)
#
# records_only() is the one place that says "this whole command is nothing but plain calls of an installed harness tool
# that records text". A word of such a call is data for that tool, so no guard needs to read it as a command. It is a
# closed grammar: whatever it does not list is not a recording call, and the caller keeps its ordinary judgement.

RECORD_CONTROL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')
# One word is bare, or single-quoted, or double-quoted, never glued together, so bash and zsh read exactly one literal
# word: no expansion, substitution, escape, history, glob, brace, comment or zsh `=word`.
RECORD_TOKEN = re.compile(r"(?P<gap>[ \t]+)|(?P<op>;|&&|\n)|'(?P<single>[^']*)'|\"(?P<double>[^\"$`\\!]*)\"|"
                          r"(?P<bare>(?:~/)?(?![=#~])[A-Za-z0-9_@%+:,./#=-]+)")
# `NAME=literal` as a statement of its own, and `$NAME` or "$NAME" as a whole word later. A closed list of names: none is
# read by a shell, Python or a harness tool, so setting one changes nothing but the words that use it.
RECORD_NAME = r"(?P<name>[A-Za-z]|wal|WAL|note|NOTE|text|TEXT|body|BODY|tool|TOOL|hooks|HOOKS|ah|AH|py|PY|msg|MSG)"
RECORD_PLAIN = re.compile(r'[A-Za-z0-9_@%+:,./#-]+')
RECORD_ASSIGN = re.compile(RECORD_NAME + r"=(?:'(?P<single>[^']*)'|\"(?P<double>[^\"$`\\!]*)\"|"
                                         r"(?P<bare>(?:~/)?(?![#~])[A-Za-z0-9_@%+:,./#-]+))(?=[ \t]*(?:;|&&|\n))")
RECORD_USE = re.compile(r'(?P<quote>")?\$(?P<brace>\{)?' + RECORD_NAME + r'(?(brace)\}|(?![A-Za-z0-9_\[:]))(?(quote)")')
RECORD_WAL = re.compile(r'/\.claude/wals/[A-Za-z0-9._-]{1,120}/[A-Za-z0-9._-]{1,120}\.jsonl')
RECORD_EVENTS = frozenset(('intent', 'scope', 'decision', 'risk', 'check', 'commit', 'blocker', 'status', 'handoff',
                           'result', 'requirement', 'deploy'))  # not ask or ask_resolved: they open and settle asks
RECORD_TICKET = re.compile(r'(?:GoodQA ?)?[A-Za-z][A-Za-z0-9-]{0,62}#[1-9][0-9]{0,9}')
RECORD_PATH = re.compile(r'/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+')


def _record_statements(command, assignments=False):
    """[[word, ...], ...] for a command made of literal words joined by `;`, `&&` or a newline, else None. A word is
    (value, was bare); a bare `~/` is expanded, as both shells do for an argument word. With `assignments`, a statement
    may also be one RECORD_ASSIGN, and a word one RECORD_USE of a name assigned before it (read as that value)."""
    if len(command) > 65536 or RECORD_CONTROL.search(command):
        return None
    home = os.path.expanduser('~')
    statements, words, at, glued, last, held = [], [], 0, False, '', {}
    while at < len(command):
        if assignments and not words:
            match = RECORD_ASSIGN.match(command, at)
            if match:
                kind = next(k for k in ('single', 'double', 'bare') if match.group(k) is not None)
                value = match.group(kind)
                held[match.group('name')] = home + value[1:] if kind == 'bare' and value.startswith('~/') else value
                at, words = match.end(), [None]
                continue
        if assignments and not glued:
            match = RECORD_USE.match(command, at)
            if match:
                value = held.get(match.group('name'))
                plain = value is not None and bool(RECORD_PLAIN.fullmatch(value))
                if value is None or not (plain or match.group('quote')):
                    return None  # unset here, or text an unquoted expansion splits or globs in bash
                at, glued = match.end(), True
                words.append((value, plain))
                continue
        match = RECORD_TOKEN.match(command, at)
        if match is None:
            return None
        at, kind = match.end(), match.lastgroup
        if kind == 'gap':
            glued = False
        elif kind == 'op':
            glued = False
            if words:
                if words != [None]:
                    statements.append(words)
                words, last = [], match.group()
            elif match.group() != '\n' or last == '&&':
                return None  # an operator with no command before it, or a line break after `&&`
        else:
            if glued:
                return None  # two pieces make one word
            value, glued = match.group(kind), True
            if kind == 'bare' and value.startswith('~/'):
                value = home + value[1:]
            words.append((value, kind == 'bare'))
    if words:
        statements.append(words)
    elif last == '&&':
        return None
    return statements or None


def _record_options(rest, allowed, flags=()):
    """{option: value} when `rest` is only `--option VALUE` pairs and flags from these lists, each at most once. No
    abbreviation, no `--option=VALUE`, no value that starts with a dash."""
    found, at = {}, 0
    while at < len(rest):
        name, bare = rest[at]
        if not bare or name in found:
            return None
        if name in flags:
            found[name], at = '', at + 1
            continue
        if name not in allowed or at + 1 >= len(rest) or rest[at + 1][0].startswith('-'):
            return None
        found[name], at = rest[at + 1][0], at + 2
    return found


def _record_tool(path):
    """The name of the installed tool `path` is, else ''. Every part is ours, not a symlink and writable only by us."""
    home = os.path.expanduser('~')
    name = os.path.basename(path)
    if name not in ('wal_note.py', 'ah.py', 'usage_guard.py') or not RECORD_PATH.fullmatch(home) \
            or os.path.normpath(home) != home or path != home + '/.claude/hooks/' + name:
        return ''
    try:
        for part in (home + '/.claude', home + '/.claude/hooks', path):
            info = os.lstat(part)
            if os.path.islink(part) or info.st_uid != os.getuid() or info.st_mode & 0o022:
                return ''
    except (OSError, AttributeError):
        return ''
    return name if os.path.isfile(path) else ''


def _records(words):
    """True for one plain call of a recording tool: `wal_note.py` with these options, `ah.py ticket get|comments REF` or
    `ticket comment REF --body ...`, or a manual `usage_guard.py reconcile`. None of them starts, signals, deletes or
    publishes a file. `--source file:...` is out, because provenance then opens the file it names."""
    if words[0] != ('python3', True):
        return False
    at = 1
    while at < len(words) and words[at] in (('-I', True), ('-B', True), ('-u', True)):
        at += 1
    if at >= len(words):
        return False
    tool, rest = _record_tool(words[at][0]), words[at + 1:]
    if tool == 'wal_note.py':
        got = _record_options(rest, ('--wal', '--event', '--note', '--source', '--reason', '--owner', '--ref', '--goal',
                                     '--ticket', '--result'), ('--live',))
        home = os.path.expanduser('~')
        return bool(got and '--note' in got and got.get('--event') in RECORD_EVENTS
                    and got.get('--wal', '').startswith(home) and RECORD_WAL.fullmatch(got['--wal'][len(home):])
                    and '/../' not in got['--wal'] and '/./' not in got['--wal']
                    and 'file:' not in got.get('--source', '').casefold())
    if tool == 'ah.py' and len(rest) > 2 and rest[0] == ('ticket', True) and rest[1][1] \
            and RECORD_TICKET.fullmatch(rest[2][0]):
        if rest[1][0] in ('get', 'comments'):
            return len(rest) == 3
        got = _record_options(rest[3:], ('--body', '--session', '--key'))
        return bool(rest[1][0] == 'comment' and got and '--body' in got)
    if tool == 'usage_guard.py' and rest[:1] == [('reconcile', True)]:
        got = _record_options(rest[1:], ('--run', '--actor', '--reason', '--evidence'))
        return bool(got and len(got) == 4 and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}', got['--run']))
    return False


def records_only(command, assignments=False):
    """True when `command` is one or more plain recording calls, joined by `;`, `&&` or newlines, and nothing else (with
    `assignments`: nothing else but literal assignments the calls use)."""
    statements = _record_statements(command, assignments) if isinstance(command, str) else None
    return bool(statements) and all(_records(words) for words in statements)


def payload_records_only(payload, assignments=False):
    """records_only() for the one command of a Bash tool call. Text typed into a running shell, a list, a second command
    field and every other tool are judged as before: their state or shell is not known here. kill_guard, merge_gate and
    dropped_gate call this with `assignments`; the launcher's own fast path does not."""
    if not isinstance(payload, dict) or payload.get('tool_name') != 'Bash':
        return False
    tool_input = payload.get('tool_input')
    return isinstance(tool_input, dict) and not any(k in tool_input for k in COMMAND_KEYS[1:]) \
        and records_only(tool_input.get('command'), assignments)


def guarded_text(raw):
    """(is_guarded_tool, text to probe). Unparsable input is treated as guarded, probing the whole payload."""
    try:
        payload = json.loads(raw)
    except ValueError:
        return True, raw
    if not isinstance(payload, dict):
        return True, raw
    tool = str(payload.get('tool_name') or payload.get('toolName') or '').casefold()
    tool_input = payload.get('tool_input') or payload.get('toolInput') or {}
    has_command = isinstance(tool_input, dict) and any(k in tool_input for k in COMMAND_KEYS[:3])
    if tool and tool not in GUARDED_TOOLS and not tool.startswith(('bash', 'shell', 'exec')) and not has_command:
        return False, ''
    if isinstance(tool_input, dict):
        parts = []
        for key in COMMAND_KEYS:
            value = tool_input.get(key)
            if isinstance(value, list):
                parts.append(' '.join(str(v) for v in value))
            elif isinstance(value, str):
                parts.append(value)
        return True, '\n'.join(parts) or raw
    return True, raw if not isinstance(tool_input, str) else tool_input


def payload_cwd(raw):
    """The working directory the command runs in (Codex workdir, else the payload cwd), or None."""
    try:
        payload = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    tool_input = payload.get('tool_input') if isinstance(payload.get('tool_input'), dict) else {}
    for value in (tool_input.get('workdir'), payload.get('cwd')):
        if isinstance(value, str) and value:
            return value
    return None


def sensitive(text, cwd=None):
    t = text[:4_000_000]
    if PROTECTED_TEXT.search(t) or SECRET_TEXT.search(t) or (EXEC_TEXT.search(t) and DESTROY_TEXT.search(t)):
        return True
    if CRED_TEXT.search(t) or CRED_TEXT.search(re.sub(r'[\'"\\]', '', t)):
        return True  # a credential location (receipt r7: fail closed when the analyser crashes or times out)
    if cwd and DESTROY_TEXT.search(t):
        try:
            real = os.path.realpath(cwd)
        except (OSError, ValueError):
            real = cwd
        return any(PROTECTED_TEXT.search(place.replace('\\', '/') + '/') for place in (cwd, real))
    return False


def fallback(raw, why):
    guarded, text = guarded_text(raw)
    if guarded and sensitive(text, payload_cwd(raw)):
        sys.stderr.write('command_guard BLOCKED [guard_failure]: the analyser %s and the command names a protected '
                         'harness location, a credential location, a secret source or a code-execution step with a '
                         'destructive verb. Safe '
                         'alternative: split the command into simple steps; run `python3 %s doctor` to check the '
                         'guard.\n' % (why, GUARD))
        return 2
    if guarded:
        sys.stderr.write('command_guard: analyser %s; the command looked harmless and was allowed\n' % why)
    return 0


def read_stdin():
    data = b''
    stream = sys.stdin.buffer
    while len(data) <= MAX_STDIN:
        chunk = stream.read(65536)
        if not chunk:
            return data, False
        data += chunk
    return data, True


def main():
    try:
        data, oversized = read_stdin()
    except Exception:  # noqa: BLE001 - cannot read the payload at all: nothing to judge
        sys.stderr.write('command_guard: could not read the hook payload\n')
        return 0
    raw = data.decode('utf-8', 'replace')
    if oversized:
        guarded, _ = guarded_text(raw[:MAX_STDIN])
        if guarded:
            sys.stderr.write('command_guard BLOCKED [oversized-input]: the tool input is larger than the guard '
                             'analyses. Safe alternative: put the commands in a script file and run it.\n')
            return 2
        return 0
    if not guarded_text(raw)[0]:
        return 0  # Read, Write, Edit, MCP...: not a shell command, and Codex sends every tool here (no matcher)
    try:
        if payload_records_only(json.loads(raw)):
            return 0  # only recording calls: nothing for the analyser to find, and nothing for it to time out on
    except Exception:  # noqa: BLE001 - the fast path never decides a refusal; the analyser does
        pass
    try:
        child = subprocess.run([sys.executable, '-I', GUARD, 'hook'], input=data, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=CHILD_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        return fallback(raw, 'timed out')
    except Exception as error:  # noqa: BLE001
        return fallback(raw, 'could not start (%s)' % type(error).__name__)
    if child.returncode in (0, 2):
        out = child.stdout.decode('utf-8', 'replace')
        if out.strip():
            try:
                json.loads(out)
            except ValueError:
                return fallback(raw, 'printed invalid output')
            sys.stdout.write(out)
        sys.stderr.write(child.stderr.decode('utf-8', 'replace')[:4000])
        return child.returncode
    return fallback(raw, 'crashed (exit %d)' % child.returncode)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:  # noqa: BLE001 - last resort: never let a launcher bug become a silent allow
        sys.stderr.write('command_guard BLOCKED [guard_failure]: the launcher failed. Run the guard doctor.\n')
        sys.exit(2)
