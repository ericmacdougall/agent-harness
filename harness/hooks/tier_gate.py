#!/usr/bin/env python3
"""PreToolUse enforcement of the model ladder (GoodQA goodqa#14527).

Agent, Task and Workflow spawns must match the task's computed rung: lower only with a recorded
reason, review-only rungs never for writing, the top writing rung only with the user's recorded
permission. When the rung cannot be determined the spawn is allowed at the lowest rung (model and
effort rewritten through updatedInput) and a reset record is written. Bash lines that launch
claude or codex are checked the same way (advisory in warn mode). SubagentStart/Stop keep a
per-session live-agent count under a cap. Everything is a pure function of the hook input, the
tier table and the ledger; no model judgement.
"""

from __future__ import annotations

import json
import threading
import os
from pathlib import Path
import re
import shlex
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import liveness  # noqa: E402
import escalation as esc  # noqa: E402
import model_tiers as tiers  # noqa: E402
import safe_input  # noqa: E402

SPAWN_TOOLS = {'Agent', 'Task', 'Workflow'}
REVIEWER_TYPES = {'red-team', 'click-tester', 'reviewer'}
DOWNGRADE = re.compile(r'\[rung-below:([^\]]{3,200})\]')
REVIEW_MARK = re.compile(r'\[review:[^\]]+\]')
LIVE_CAP_DEFAULT = 12


def hook_result(decision, reason=None, updated=None, context=None):
    out = {'hookEventName': 'PreToolUse'}
    if decision == 'context':
        out['additionalContext'] = context
        return {'hookSpecificOutput': out}
    if decision == 'deny':
        out.update(permissionDecision='deny', permissionDecisionReason=reason)
    elif decision == 'allow':
        out['permissionDecision'] = 'allow'
        if reason: out['permissionDecisionReason'] = reason
        if updated is not None: out['updatedInput'] = updated
    if context: out['additionalContext'] = context
    return {'hookSpecificOutput': out}


def requested_spec(tool_input, policy):
    """What the caller asked for, classified, or None when no model was named (inherit)."""
    model = tool_input.get('model')
    effort = tool_input.get('effort')
    if model is None and effort is None:
        return None
    found = tiers.classify(model if model is not None else 'sonnet', effort, policy)
    if found is None:
        return None
    return {**found, 'model': model if model is not None else 'sonnet'}


def decide_spawn(data, policy, ledger, *, session_id=None):
    """The decision for one Agent/Task/Workflow call. Returns (decision, reason, updated_input, facts)."""
    tool_input = data.get('tool_input') if isinstance(data.get('tool_input'), dict) else {}
    prompt, description = str(tool_input.get('prompt') or ''), str(tool_input.get('description') or '')
    subagent_type = str(tool_input.get('subagent_type') or '')
    is_reviewer = subagent_type in REVIEWER_TYPES or bool(REVIEW_MARK.search(prompt + ' ' + description))
    facts = {'reviewer_spawn': is_reviewer, 'subagent_type': subagent_type}
    task = esc.task_key_from(prompt, description)
    resets = []
    generated = task is None
    if generated:
        # A stable generated key: the first sighting is a recorded reset; later spawns reuse its ledger
        # so failures keep counting (never wiped on every spawn).
        task = esc.generated_key(session_id or '', description or prompt[:200])
        if not ledger.path(task).exists():
            resets.append(('missing_task_key', 'spawn carried no [task:<key>] token; generated ' + task))
    facts['task'] = task
    status = None
    try:
        status = ledger.status(task)
    except esc.LedgerError as error:
        code = error.code if error.code in esc.RESET_CODES else 'state_corrupt'
        if code == 'lock_timeout':
            try: ledger.pending_reset(task, code, error.message)
            except OSError: pass
            facts['reset'] = ['lock_timeout']
        else:
            resets.append((code, error.message))
    except tiers.TierError as error:
        resets.append(('tier_table_error', str(error)))
    lowest = policy['lowest_rung']
    if resets:
        for code, detail in resets:
            try:
                status = ledger.reset(task, code, detail)
            except (esc.LedgerError, tiers.TierError):
                status = None
        facts['reset'] = [code for code, _ in resets]
    if status is None or resets or facts.get('reset') == ['lock_timeout']:
        required = lowest
        if generated and status is not None and not resets:
            required = status['rung']  # a known generated key keeps its earned rung
    else:
        required = status['rung']
    facts['required_rung'] = required
    if is_reviewer:
        choice = tiers.reviewer_for(policy, required if status is not None else None, 'claude')
        target_rung = choice['rung'] or required
        facts['reviewer_rung'] = target_rung
    else:
        target_rung = required
    target = tiers.spawn_spec(policy, target_rung, 'claude')
    requested = requested_spec(tool_input, policy)
    facts['requested'] = requested
    blocked = status['blocked_by'] if status else []

    def permitted(rung):
        """Only the task's own recorded permission. Review F1 and main's rule: there is no session-wide grant, so
        an untagged spawn never inherits a permission the user gave for another task."""
        return bool((status or {}).get('permission'))

    def permission_denied(rung):
        return ('rung %s needs the user permission for task %s. Fix: %s (then add [task:%s] to the Agent description)'
                % (rung, task, esc.approve_fix(task), task))

    # The user's own stop comes first: a computed rung that needs permission is reported as such even
    # when the launch or spend ceilings are reached at the same time.
    if policy['rungs'][target_rung]['needs_user_permission'] and not permitted(target_rung):
        return 'deny', permission_denied(target_rung), None, facts
    # R12: a fork keeps its parent's model, which the hook cannot see or rewrite; it is never a rung escape.
    if subagent_type == 'fork' and policy['rungs'][target_rung]['writable'] and target_rung != policy['lowest_rung']:
        return 'deny', 'fork inherits the parent model, which the ladder cannot verify for task %s at rung %s; spawn a typed agent' % (task, target_rung), None, facts
    if blocked and not is_reviewer:
        return 'deny', 'ladder limit reached for task %s (%s): human sign-off needed' % (task, ', '.join(blocked)), None, facts
    if requested is None:
        updated = {**tool_input, 'model': target['model'], 'effort': target['effort']}
        return 'allow', 'rung %s applied (no model named)' % target_rung, updated, facts
    req_rung = requested['rung']
    req_entry = policy['rungs'][req_rung]
    if not is_reviewer and not req_entry['writable']:
        return 'deny', 'rung %s (%s %s) is review-only; writing spawns use %s' % (req_rung, requested['model'], requested['effort'], target_rung), None, facts
    if req_entry['needs_user_permission'] or policy['rungs'][target_rung]['needs_user_permission']:
        needed = max(req_rung, target_rung)
        if not permitted(needed):
            return 'deny', permission_denied(needed), None, facts
        if req_entry['needs_user_permission'] and req_rung != target_rung and req_entry['writable']:
            # A granted top-rung request is honoured as asked (the grant is the user's word), not downgraded to
            # the computed rung: on 2026-11-08 the ladder said "would deny" to the very spawn the user had just approved.
            return 'allow', 'rung %s granted by the user for task %s' % (req_rung, task), None, facts
    if req_rung == target_rung:
        return 'allow', 'rung %s matches' % target_rung, None, facts
    order = tiers.rung_order(policy)
    if order.index(req_rung) < order.index(target_rung):
        reason = DOWNGRADE.search(prompt + ' ' + description)
        if reason:
            facts['downgrade_reason'] = reason.group(1)
            return 'allow', 'below rung %s with recorded reason' % target_rung, None, facts
        return 'deny', 'task %s is at rung %s; %s %s is below it (add [rung-below:<reason>] to go lower)' % (task, target_rung, requested['model'], requested['effort']), None, facts
    # Above the computed rung: writers are downgraded deterministically, but an explicit reviewer request must not
    # silently become a weaker review. Name both rungs so the caller can retry at the effective target deliberately.
    if is_reviewer:
        return 'deny', ('reviewer request %s %s is rung %s, above the effective target rung %s; explicit above-target '
                        'reviewer model/effort is denied, not downgraded' % (
                            requested['model'], requested['effort'], req_rung, target_rung)), None, facts
    updated = {**tool_input, 'model': target['model'], 'effort': target['effort']}
    return 'allow', 'requested %s %s is above rung %s; downgraded' % (requested['model'], requested['effort'], target_rung), updated, facts


LAUNCH = re.compile(r'(^|[\s;&|(/`\'"=\\])(claude|codex|rescue\.py|peer_review\.py)(\s|$|[\'"`)])', re.IGNORECASE)
SHELL_STRING_HOSTS = ('bash', 'sh', 'zsh', 'dash', 'ksh', 'su', 'sudo')
ENV_MODEL = re.compile(r'(?:^|\s)(?:export\s+)?(?:ANTHROPIC_MODEL|CLAUDE_MODEL)=([^\s;&|]+)')
MAX_NESTING = 2
MAX_LAUNCH_LINE = 64 * 1024  # bytes; larger launch-bearing lines are refused, never parsed
PURE_SHELLS = ('bash', 'sh', 'zsh', 'dash', 'ksh')
WRAPPER_VALUE_OPTIONS = {'sudo': ('-u', '-g', '-C', '-h', '-p', '-U', '-r', '-t', '-T'), 'nice': ('-n',), 'timeout': ('-s', '-k'),
                         'env': ('-u', '-C', '-S'), 'nohup': (), 'time': (), 'command': (), 'exec': ()}


def _unquote(value):
    """One layer of matching quotes: export ANTHROPIC_MODEL="claude-sonnet-4-5"."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
        return value[1:-1]
    return value


def reads_stdin_as_script(segment):
    """True for a shell host with no -c: it runs what is piped into it."""
    try:
        words = shlex.split(segment)
    except ValueError:
        return False
    # The shell may sit behind wrappers (sudo, env, nice, time, command, exec, nohup): look past them.
    index = 0
    while index < len(words):
        base = words[index].rsplit('/', 1)[-1].lower()
        if base in ('sudo', 'env', 'nice', 'time', 'command', 'exec', 'nohup', 'timeout') or '=' in words[index] and not words[index].startswith('-'):
            index += 1
            while index < len(words) and words[index].startswith('-'):
                option = words[index]; index += 1  # the wrapper's own options (sudo -u eric, nice -n 5, timeout -s KILL)
                if option in WRAPPER_VALUE_OPTIONS.get(base, ()) and index < len(words):
                    index += 1  # its value (per wrapper: sudo's -n takes none, nice's -n does)
            if base == 'timeout' and index < len(words) and words[index][:1].isdigit():
                index += 1
            continue
        break
    if index >= len(words) or words[index].rsplit('/', 1)[-1].lower() not in PURE_SHELLS:
        return False
    return not any(w.startswith('-') and not w.startswith('--') and 'c' in w[1:] for w in words[index + 1:])


def split_segments(command):
    """The segments of split_segments_with_seps, without the separators."""
    return split_segments_with_seps(command)[0]


def split_segments_with_seps(command):
    """Returns (segments, seps); seps[i] is the operator before segments[i] ('' for the first). Split a shell line on unquoted ;, &&, ||, |, & and newlines; quotes, backslashes and redirections
    such as 2>&1 or &> are kept inside their segment. Subshell and brace grouping is not parsed: a launch
    inside (...) still lands in some segment and is still checked."""
    segments, seps, current, quote, i = [], [], [], None, 0
    pending = ''
    while i < len(command):
        ch = command[i]
        if quote:
            current.append(ch)
            if ch == '\\' and quote == '"' and i + 1 < len(command):
                current.append(command[i + 1]); i += 2; continue
            if ch == quote:
                quote = None
            i += 1; continue
        if ch in ('"', "'"):
            quote = ch; current.append(ch); i += 1; continue
        if ch == '\\' and i + 1 < len(command):
            current.append(ch); current.append(command[i + 1]); i += 2; continue
        if ch == '\n' or ch in ';|&':
            redirect = ch == '&' and ((i > 0 and command[i - 1] in '<>') or (i + 1 < len(command) and command[i + 1] == '>'))
            if redirect:
                current.append(ch); i += 1; continue
            segments.append(''.join(current)); seps.append(pending); current = []
            pending = ch if ch in '|&;' else ';'
            if ch in '|&' and i + 1 < len(command) and command[i + 1] == ch:
                pending = ch * 2; i += 1
            i += 1; continue
        current.append(ch); i += 1
    segments.append(''.join(current)); seps.append(pending)
    kept = [(text.strip(), sep) for text, sep in zip(segments, seps) if text.strip()]
    if kept:
        kept[0] = (kept[0][0], '')
    return [text for text, _ in kept], [sep for _, sep in kept]


def program_name(word, command_position=False):
    """The program a shlex word names, past `=`, quotes, backticks and `$(`. A substitution such as
    `$(which claude)` names its last token (the substitution yields that program's path). A quoted word
    is a candidate only in command position (`"claude" -p ...`); elsewhere it is prose (`-m "... codex"`)."""
    quoted = word[:1] in ('"', "'")
    substitution = '$(' in word or '`' in word
    if quoted and not substitution and not command_position:
        return ''
    pieces = [piece for piece in re.split(r'[=`$(\'"]', word) if piece.strip()]
    if not pieces:
        return ''
    tail = pieces[-1].strip()
    if substitution:
        tail = tail.split()[-1]
    elif ' ' in tail:
        return ''
    return tail.rsplit('/', 1)[-1].rstrip('`)\'"').lower()


def command_program(words):
    """The program in command position: past leading env assignments and wrappers (sudo, env, nice, time, command,
    exec, nohup, timeout with their options), the first word or a substitution there."""
    index = 0
    while index < len(words):
        word = words[index]
        base = word.rsplit('/', 1)[-1].lower()
        if base in ('sudo', 'env', 'nice', 'time', 'command', 'exec', 'nohup', 'timeout') or ('=' in word and not word.startswith('-') and '$(' not in word and '`' not in word):
            index += 1
            while index < len(words) and words[index].startswith('-'):
                option = words[index]; index += 1
                if option in WRAPPER_VALUE_OPTIONS.get(base, ()) and index < len(words):
                    index += 1
            if base == 'timeout' and index < len(words) and words[index][:1].isdigit():
                index += 1
            continue
        if '$(' in word or '`' in word:
            # shlex splits an unquoted substitution into several words: join until it closes.
            joined, end = word, index
            while end + 1 < len(words) and (joined.count('(') > joined.count(')') or joined.count('`') % 2 == 1):
                end += 1; joined += ' ' + words[end]
            return program_name(joined, command_position=True)
        return program_name(word, command_position=True)
    return ''


def nested_strings(segment):
    return [text for text, _ in nested_items(segment)]


def nested_items(segment):
    """Strings inside a segment that the shell would run as commands: substitutions ($(...), backticks) and
    the string argument of bash/sh/zsh -c, su/sudo -c, eval and ssh HOST. Quoted prose elsewhere is not one."""
    try:
        words = shlex.split(segment)
    except ValueError:
        return []
    found = []  # (text, inherits_env): an ssh remote does not inherit the local export
    shell_seen = False
    for index, word in enumerate(words):
        if '`' in word or '$(' in word:
            found.append((word, True))
        if shell_seen and word.startswith('<<<'):
            operand = word[3:] or (words[index + 1] if index + 1 < len(words) else '')
            found.append((operand, True))
        base = word.rsplit('/', 1)[-1].lower()
        if base in SHELL_STRING_HOSTS:
            shell_seen = True
            for later in range(index + 1, min(index + 6, len(words))):
                flag = words[later]
                if flag.startswith('-') and not flag.startswith('--') and 'c' in flag[1:] and later + 1 < len(words):
                    operand = later + 1
                    if words[operand] == '--' and operand + 1 < len(words): operand += 1  # bash -c -- 'string'
                    found.append((words[operand], True)); break  # -c, -lc, -ic: the next word is the shell string
        elif base == 'eval':
            found.append((' '.join(words[index + 1:]), True))
        elif base == 'ssh':
            rest = words[index + 1:]
            host_seen = False
            skip = False
            for item in rest:
                if skip:
                    skip = False; continue
                if not host_seen and item.startswith('-'):
                    skip = len(item) == 2 and item[1] in 'bcDEeFIiJLlmOopQRSWw'
                    continue
                if not host_seen:
                    host_seen = True; continue
                found.append((' '.join(rest[rest.index(item):]), False)); break
    return [(text, env) for text, env in found if LAUNCH.search(text)]


def decide_bash(data, policy, ledger, depth=0, env_model=None):
    """Advisory check of launch lines: every launch segment of a compound line is checked on its own, as are
    the shell strings and substitutions inside it (one level down, bounded), and any denied part denies the
    line, so a later harmless launch cannot mask an earlier one. A model set by an earlier
    `export ANTHROPIC_MODEL=` applies to later claude segments that name none."""
    tool_input = data.get('tool_input') if isinstance(data.get('tool_input'), dict) else {}
    command = str(tool_input.get('command') or '')
    if not LAUNCH.search(command):
        return 'allow', None, None, {}
    if depth == 0 and len(command) > MAX_LAUNCH_LINE:
        # The hook has a 10 s budget under onFailure block: a launch-bearing line this large is refused
        # instead of parsed (split it, or put the script in a file and run that).
        return 'deny', 'launch line too large to check (%d bytes > %d): split it or run it from a file' % (len(command), MAX_LAUNCH_LINE), None, {'oversize': len(command)}
    results = []
    segments, seps = split_segments_with_seps(command)
    for number, segment in enumerate(segments):
        assignment = ENV_MODEL.search(segment)
        if assignment:
            env_model = _unquote(assignment.group(1))
        if LAUNCH.search(segment):
            results.append(_decide_launch(segment, policy, ledger, env_model=env_model, session_id=data.get('session_id')))
        if depth < MAX_NESTING:
            items = nested_items(segment)
            if number and seps[number] == '|' and reads_stdin_as_script(segment):
                # `echo '<launch>' | bash`: the producer's quoted words are the script the shell runs.
                try: producer = shlex.split(segments[number - 1])
                except ValueError: producer = []
                items += [(word, True) for word in producer[1:] if LAUNCH.search(word)]
            for inner, inherits in items:
                results.append(decide_bash({'tool_input': {'command': inner}, 'session_id': data.get('session_id')}, policy, ledger, depth + 1,
                                           env_model=env_model if inherits else None))
    if not results:
        return 'allow', None, None, {'segments': 0}
    for decision, reason, updated, facts in results:
        if decision == 'deny':
            return 'deny', reason, None, dict(facts, segments=len(results))
    reasons = [reason for _, reason, _, _ in results if reason]
    return 'allow', ('; '.join(reasons) or None), None, dict(results[0][3], segments=len(results))


def _decide_launch(command, policy, ledger, env_model=None, session_id=None):
    """One launch segment: same rule as a spawn, reported as context or deny."""
    try:
        words = shlex.split(command)
    except ValueError:
        # The shell would refuse it too; an unparsable launch line is never a silent allow.
        return 'deny', 'launch line cannot be parsed (unterminated quote)', None, {'unparsed': True}
    model = effort = task = author_rung = None
    author_harness = 'unknown'
    programs = [program_name(w, command_position=(index == 0)) for index, w in enumerate(words)]
    if not any(name in programs for name in ('claude', 'codex', 'rescue.py', 'peer_review.py')):
        # The launch name sits only inside quoted text (prose, or a shell string that nested_strings
        # checks on its own): the flags of this program are not launch flags (`git commit -m "..."`).
        return 'allow', None, None, {'quoted_only': True}
    for index, word in enumerate(words):
        if word == '--model' and index + 1 < len(words): model = words[index + 1]
        if word == '-m' and command_program(words) == 'codex' and index + 1 < len(words): model = words[index + 1]
        if word.startswith('--model='): model = word.split('=', 1)[1]
        if word == '--effort' and index + 1 < len(words): effort = words[index + 1]
        if word.startswith('--effort='): effort = word.split('=', 1)[1]
        if word == '-c' and index + 1 < len(words):
            if words[index + 1].startswith('model_reasoning_effort='): effort = words[index + 1].split('=', 1)[1]
            if words[index + 1].startswith('model='): model = words[index + 1].split('=', 1)[1]
        if word.startswith('ANTHROPIC_MODEL=') or word.startswith('CLAUDE_MODEL='): model = word.split('=', 1)[1]
        if word.lower() in ('export',) and index + 1 < len(words) and words[index + 1].split('=', 1)[0] in ('ANTHROPIC_MODEL', 'CLAUDE_MODEL') and '=' in words[index + 1]:
            model = words[index + 1].split('=', 1)[1]
        if word == '--task' and index + 1 < len(words): task = words[index + 1]
        if word.startswith('--task='): task = word.split('=', 1)[1]
        if word == '--author-rung' and index + 1 < len(words): author_rung = words[index + 1]
        if word.startswith('--author-rung='): author_rung = word.split('=', 1)[1]
        if word == '--author-harness' and index + 1 < len(words): author_harness = words[index + 1]
    task = task or esc.task_key_from(command)
    basenames = [w.rsplit('/', 1)[-1].lower() for w in words]
    if model is None and env_model and 'claude' in programs:
        model = env_model  # set by an earlier segment's export
    facts = {'model': model, 'effort': effort, 'task': task}
    if 'peer_review.py' in basenames:
        # A review launch: the reviewer rung follows from the author rung (the installed ledger's rung for a
        # --task-only line); a permission rung needs the installed ledger's record, checked here so a forged
        # state dir in the helper's env cannot stand in. The line then falls through: a review token never
        # exempts another launch on the same line.
        if author_rung is None and task is not None:
            try:
                author_rung = ledger.status(task)['rung']
            except (esc.LedgerError, tiers.TierError) as error:
                facts['ladder_error'] = getattr(error, 'code', 'error')
        selection = tiers.reviewer_for(policy, author_rung, author_harness, {'openai': True, 'claude': True})
        if selection.get('rung') and policy['rungs'][selection['rung']]['needs_user_permission']:
            permission = None
            if task is not None:
                try:
                    permission = ledger.status(task).get('permission')
                except (esc.LedgerError, tiers.TierError) as error:
                    facts['ladder_error'] = getattr(error, 'code', 'error')
            if not permission:
                return 'deny', 'review at %s needs recorded user permission for task %s' % (selection['rung'], task or '(none)'), None, facts
    if model is None:
        return 'allow', None, None, facts
    requested = tiers.classify(model, effort, policy)
    if requested is None:
        return 'deny', 'launch names a model not on the tier table: ' + model, None, facts
    entry = policy['rungs'][requested['rung']]
    status = None
    if task is not None:
        try:
            status = ledger.status(task)
        except (esc.LedgerError, tiers.TierError) as error:
            facts['ladder_error'] = getattr(error, 'code', 'error')
    # Permission and review-only checks come first: no task means no recorded permission (no session grant).
    if entry['needs_user_permission'] and not (status or {}).get('permission'):
        return 'deny', 'launch at %s needs the user permission for task %s. Fix: %s' % (
            requested['rung'], task or '(none)', esc.approve_fix(task)), None, facts
    if not entry['writable'] and 'rescue.py' in basenames:
        return 'deny', 'rescue at %s is review-only' % requested['rung'], None, facts
    if task is None:
        # A Bash line cannot be rewritten: without a task, above the lowest writing rung is denied
        # (a rescue.py line names its rung by ticket and is checked by rescue.py itself).
        lowest = tiers.writing_rungs(policy)[0]
        order = tiers.rung_order(policy)
        if order.index(requested['rung']) > order.index(lowest) and 'rescue.py' not in basenames:
            return 'deny', 'launch at %s without --task: only the lowest rung %s runs without a task' % (requested['rung'], lowest), None, facts
        return 'allow', 'launch without --task: lowest rung applies', None, facts
    if status is None:
        return 'allow', 'ladder state unreadable (%s): lowest rung applies' % facts.get('ladder_error', 'error'), None, facts
    if status.get('needs_user_permission') and not status.get('permission') and 'rescue.py' not in basenames:
        # The task has climbed to a permission rung: like the spawn path, nothing launches for it below
        # that rung either until approve-top records the user's answer.
        return 'deny', 'task %s is computed at %s, which needs the user permission before any launch. Fix: %s' % (
            task, status['rung'], esc.approve_fix(task)), None, facts
    order = tiers.rung_order(policy)
    if order.index(requested['rung']) > order.index(status['rung']) and 'rescue.py' not in basenames:
        return 'deny', 'launch at %s is above task %s rung %s' % (requested['rung'], task, status['rung']), None, facts
    return 'allow', None, None, facts


def live_path(session_id):
    root = esc.state_root() / 'live'
    root.mkdir(mode=0o700, exist_ok=True)
    return root / (re.sub(r'[^A-Za-z0-9_-]', '_', session_id or 'unknown')[:80] + '.json')


def _read_live(path):
    """The live-agent map ({} when absent); a file past 256 KiB is rejected, never read whole."""
    if not path.exists():
        return {}
    return json.loads(safe_input.read_bounded(path, 262144).decode('utf-8'))


def live_update(session_id, agent_id, *, start, agent_type=None):
    import fcntl
    path = live_path(session_id)
    lock = os.open(path.with_suffix('.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            live = _read_live(path)
            if not isinstance(live, dict): live = {}
        except (OSError, ValueError, safe_input.InputRejected):
            live = {}
        key = str(agent_id or 'unknown')
        live = _expire_live(live)
        if start:
            live[key] = {'at': esc.now(), 'type': str(agent_type or '')}
        else:
            live.pop(key, None)
        tmp = path.with_suffix('.tmp')
        tmp.write_text(json.dumps(live, sort_keys=True)); os.chmod(tmp, 0o600); os.replace(tmp, path)
        return len(live)
    finally:
        os.close(lock)


def _expire_live(live, ttl=None):
    """Drop entries older than the TTL (default 30 minutes): a crashed agent never stops."""
    from datetime import datetime, timedelta, timezone
    ttl = ttl if ttl is not None else int(tiers.load_policy().get('caps', {}).get('live_ttl_seconds', 1800))
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=ttl)
    kept = {}
    for key, value in live.items():
        at = value.get('at') if isinstance(value, dict) else value  # older maps stored the bare timestamp
        try:
            if datetime.fromisoformat(str(at)) >= cutoff: kept[key] = value
        except ValueError:
            continue
    return kept


def live_count(session_id):
    path = live_path(session_id)
    try:
        live = _read_live(path)
        return len(_expire_live(live)) if isinstance(live, dict) else 0
    except (OSError, ValueError, safe_input.InputRejected):
        return 0


HELPER_TYPES_DEFAULT = ['red-team', 'click-tester', 'reviewer', 'fixer', 'Explore', 'Plan', 'claude-code-guide',
                        'statusline-setup']
# Running states of `ah owners` (liveness.py). Review F3: an owner that waits quietly on a long command, or has gone
# SILENT, still holds its slot; only a stopped owner (done, handoff, waiting-on-x, returned, DROPPED) frees it.
RUNNING_STATES = ('live', 'working', 'quiet', 'SILENT')  # SILENT also covers SILENT-HIGH (prefix)


def owner_types(policy):
    return set(policy.get('caps', {}).get('owner_types') or ['task-owner', 'general-purpose', 'claude', 'fork', ''])


def helper_types(policy):
    return set(policy.get('caps', {}).get('helper_types') or HELPER_TYPES_DEFAULT)


def counts_as_owner(agent_type, policy, flagged=False):
    """Only a known helper type is exempt (50bca42: an unknown or invented label is an owner). Review F3: the type
    decides, not only the `owner` flag of `ah owners`, which marks task-owner agents alone."""
    agent_type = str(agent_type or '')
    return bool(flagged) or agent_type in owner_types(policy) or agent_type not in helper_types(policy)


OWNER_COUNT_DEADLINE_S = 4.0  # the hook has a 10 s timeout and fails closed; the owner scan must never use it all


class _Deadline(BaseException):  # not Exception: no `except Exception` inside the scan may swallow it
    pass


def _owners_with_deadline(home, session_id, seconds):
    """ah.owners(), abandoned after `seconds` (main thread only, SIGALRM). A timeout raises _Deadline so the caller can
    use the SubagentStart live map instead of letting the whole hook time out (which blocks every spawn)."""
    import signal  # noqa: PLC0415
    import ah  # noqa: PLC0415
    if not hasattr(signal, 'setitimer') or threading.current_thread() is not threading.main_thread():
        return ah.owners(home, session_id)

    def expired(_signum, _frame):
        raise _Deadline()
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return ah.owners(home, session_id)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _slot_freed(row):
    """A silent owner frees its slot when main disposed of it the way the liveness alerts already accept
    (liveness.row_disposed, goodqa#15322): the work was reassigned, closed, superseded or written off, or a named wait is
    still live. Reassigned counts whether or not the replacement is live right now (that is its own alert), and a wait
    counts only while live. A `resumed` owner is working, so it keeps its slot, and `ah` still marking
    decision_required keeps it too. GoodQA #15565: af265a5 (reassigned, successor returned) and a0680533 (live wait)
    were SILENT-HIGH and disposed, yet held two of the four slots."""
    disp = row.get('disposition')
    if not isinstance(disp, dict) or disp.get('kind') == 'resumed':
        return False
    return liveness.row_disposed(row)


IDLE_OWNER_MAX_S = liveness.SILENT_S  # an owner-type agent `ah` calls idle-helper holds its slot while it is merely quiet


def _counts_while_idle(row):
    """`ah owners` flags only task-owner agents as owners, so a quiet general-purpose owner is classified idle-helper.
    It is still running (never stopped), so it holds a slot while its idle time is known and under IDLE_OWNER_MAX_S (a longer-idle one is stale, not working)."""
    idle = row.get('idle_s')
    return str(row.get('state') or '') == 'idle-helper' and isinstance(idle, (int, float)) and idle < IDLE_OWNER_MAX_S


def live_owner_ids(session_id, policy):
    """Agent ids of the session's live owners: from `ah owners` (WAL activity, so a long-running owner never drops out
    of the count) when the session has a main WAL, else from the SubagentStart live map filtered by owner type."""
    try:
        data = _owners_with_deadline(Path(os.environ.get('AH_HOME') or esc.installed_home()), str(session_id),
                                     OWNER_COUNT_DEADLINE_S)
        return sorted(r['agent_id'] for r in data.get('owners') or []
                      if counts_as_owner(r.get('type'), policy, r.get('owner'))
                      and (str(r.get('state') or '').startswith(RUNNING_STATES) or _counts_while_idle(r))
                      # a silent owner that main disposed of (reassigned, closed, ...) frees its slot; an owner that is
                      # live, working or quiet always counts, whatever its disposition (red-team C3)
                      and (str(r.get('state') or '').startswith(('live', 'working', 'quiet')) or _counts_while_idle(r)
                           or not _slot_freed(r)))
    except (Exception, _Deadline):  # noqa: BLE001,B036 - no main WAL yet, a partial install or a scan past its deadline: the live map decides
        pass
    try:
        live = _expire_live(_read_live(live_path(session_id)))
    except (OSError, ValueError, safe_input.InputRejected):
        return []
    return sorted(key for key, value in live.items()
                  if counts_as_owner(value.get('type', '') if isinstance(value, dict) else '', policy))


def owner_cap_decision(session_id, tool_input, policy):
    """Deny an owner-type spawn once the session's live owners reach caps.session_owner_agents (scenario B3.17:
    memory says at most 4 active owners; 12 ran). Helpers (reviewers, click-testers, fixers, Explore, Plan) are
    not owners and pass. Returns (reason, owner_ids) or (None, owner_ids)."""
    cap = policy.get('caps', {}).get('session_owner_agents')
    sub_type = str((tool_input or {}).get('subagent_type') or '')
    if not cap or not counts_as_owner(sub_type, policy):
        return None, []
    owners = live_owner_ids(session_id, policy)
    if len(owners) < int(cap):
        return None, owners
    return ('owner cap %d reached for this session: live owners %s. Fix: finish or hand off one of them (python3 %s owners), '
            'route this work to the owner that already holds its stream, or spawn a helper type (red-team, click-tester, '
            'fixer, Explore), which does not count' % (int(cap), ', '.join(o[:12] for o in owners),
                                                      Path(__file__).resolve().parent / 'ah.py')), owners


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    action = argv[0] if argv else 'hook'
    unreadable = None
    try:
        data = json.loads(safe_input.read_stdin_bounded().decode('utf-8', errors='replace'))
    except safe_input.InputRejected as error:
        data, unreadable = {}, 'hook input rejected (%s)' % getattr(error, 'code', 'stdin')
    except ValueError:
        data, unreadable = {}, 'hook input is not JSON'
    if not isinstance(data, dict):
        data, unreadable = {}, unreadable or 'hook input is not an object'
    if unreadable and action == 'hook':
        # Input the hook cannot read (an over-bound stdin from a huge command, or malformed JSON) is never a
        # silent allow: the tool call is refused in enforce and flagged in warn, the same as an oversize line.
        mode = 'enforce'
        try: mode = tiers.load_policy().get('mode', 'enforce')
        except Exception: pass  # noqa: BLE001
        reason = unreadable + ': the ladder cannot check this call; split the command or run it from a file'
        print(json.dumps(hook_result('context', context='ladder (warn mode): would deny: ' + reason) if mode == 'warn'
                         else hook_result('deny', reason)))
        return 0
    tool = str(data.get('tool_name') or '')
    command = str((data.get('tool_input') or {}).get('command') or '') if isinstance(data.get('tool_input'), dict) else ''
    applies = tool in SPAWN_TOOLS or (tool == 'Bash' and LAUNCH.search(command))
    try:
        return _main(action, data, tool, command, applies)
    except BaseException as error:  # noqa: BLE001  the hook runs with onFailure block: it must always answer
        if action == 'hook' and applies:
            mode = 'enforce'
            try: mode = tiers.load_policy().get('mode', 'enforce')
            except Exception: pass  # noqa: BLE001
            reason = 'ladder state unusable (%s): %s' % (type(error).__name__, str(error)[:160])
            if mode == 'warn':
                print(json.dumps(hook_result('context', context='ladder (warn mode): would deny: ' + reason)))
            else:
                print(json.dumps(hook_result('deny', reason)))
        return 0


def _main(action, data, tool, command, applies):
    session_id = data.get('session_id')
    try:
        policy = tiers.load_policy()
        mode = policy['mode']
        ledger = esc.Ledger(policy=policy)
    except tiers.TierError as error:
        # Fail closed on an unreadable table, but only where the ladder applies: spawns and launch lines.
        if applies:
            print(json.dumps(hook_result('deny', 'tier table error: %s' % error)))
        return 0
    if action in ('start', 'stop'):
        count = live_update(session_id, data.get('agent_id'), start=(action == 'start'), agent_type=data.get('agent_type'))
        cap = int(policy.get('caps', {}).get('session_live_agents', LIVE_CAP_DEFAULT))
        if action == 'start' and count > cap:
            print(json.dumps({'hookSpecificOutput': {'hookEventName': 'SubagentStart',
                              'additionalContext': 'live agents %d exceed the cap %d; stop some before spawning more' % (count, cap)}}))
        return 0
    if tool in SPAWN_TOOLS:
        cap = int(policy.get('caps', {}).get('session_live_agents', LIVE_CAP_DEFAULT))
        tool_input = data.get('tool_input') if isinstance(data.get('tool_input'), dict) else {}
        cap_reason, owners = owner_cap_decision(session_id, tool_input, policy)
        if live_count(session_id) >= cap:
            decision, reason, updated, facts = 'deny', 'live agents at the cap %d for this session' % cap, None, {}
        elif cap_reason:
            decision, reason, updated, facts = 'deny', cap_reason, None, {'owner_cap': owners}
        else:
            decision, reason, updated, facts = decide_spawn(data, policy, ledger, session_id=session_id)
    elif tool == 'Bash':
        decision, reason, updated, facts = decide_bash(data, policy, ledger)
    else:
        return 0
    record = {'at': esc.now(), 'tool': tool, 'decision': decision, 'reason': reason, 'mode': mode, 'facts': facts}
    try:
        log = esc.state_root() / 'gate.jsonl'
        esc.rotate_log(log)
        with open(log, 'a', encoding='utf-8') as handle:
            handle.write(json.dumps(record, sort_keys=True, default=str) + '\n')
        os.chmod(log, 0o600)
    except OSError:
        pass
    if decision == 'allow' and updated is None:
        return 0  # nothing to change; the decision and its reason are in gate.jsonl
    if mode == 'warn':
        # Warn mode only speaks, and only about a refusal: the "would apply updatedInput" chatter for an allowed
        # spawn was ceremony with no effect (scenario B24: enforce it or say nothing).
        if decision != 'deny':
            return 0
        print(json.dumps(hook_result('context', context='ladder (warn mode): would deny: %s' % reason)))
        return 0
    print(json.dumps(hook_result(decision, reason, updated)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
