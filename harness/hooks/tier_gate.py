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
import os
from pathlib import Path
import re
import shlex
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import escalation as esc  # noqa: E402
import model_tiers as tiers  # noqa: E402

SPAWN_TOOLS = {'Agent', 'Task', 'Workflow'}
REVIEWER_TYPES = {'red-team', 'click-tester', 'reviewer'}
DOWNGRADE = re.compile(r'\[rung-below:([^\]]{3,200})\]')
REVIEW_MARK = re.compile(r'\[review:[^\]]+\]')
LIVE_CAP_DEFAULT = 40


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
    # The user's own stop comes first: a computed rung that needs permission is reported as such even
    # when the launch or spend ceilings are reached at the same time.
    if policy['rungs'][target_rung]['needs_user_permission'] and not (status or {}).get('permission'):
        return 'deny', 'task %s reached rung %s, which needs the user permission recorded by escalation.py approve-top' % (task, target_rung), None, facts
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
        permission = (status or {}).get('permission')
        if not permission:
            return 'deny', 'rung %s needs the user permission recorded by escalation.py approve-top for task %s' % (max(req_rung, target_rung), task), None, facts
    if req_rung == target_rung:
        return 'allow', 'rung %s matches' % target_rung, None, facts
    order = tiers.rung_order(policy)
    if order.index(req_rung) < order.index(target_rung):
        reason = DOWNGRADE.search(prompt + ' ' + description)
        if reason:
            facts['downgrade_reason'] = reason.group(1)
            return 'allow', 'below rung %s with recorded reason' % target_rung, None, facts
        return 'deny', 'task %s is at rung %s; %s %s is below it (add [rung-below:<reason>] to go lower)' % (task, target_rung, requested['model'], requested['effort']), None, facts
    # Above the computed rung: not earned, downgrade deterministically.
    updated = {**tool_input, 'model': target['model'], 'effort': target['effort']}
    return 'allow', 'requested %s %s is above rung %s; downgraded' % (requested['model'], requested['effort'], target_rung), updated, facts


LAUNCH = re.compile(r'(^|[\s;&|(/])(claude|codex|rescue\.py|peer_review\.py)(\s|$)')


def decide_bash(data, policy, ledger):
    """Advisory check of claude/codex/rescue launch lines: same rule, reported as context or deny."""
    tool_input = data.get('tool_input') if isinstance(data.get('tool_input'), dict) else {}
    command = str(tool_input.get('command') or '')
    if not LAUNCH.search(command):
        return 'allow', None, None, {}
    try:
        words = shlex.split(command)
    except ValueError:
        return 'allow', None, None, {'unparsed': True}
    model = effort = task = author_rung = None
    author_harness = 'unknown'
    for index, word in enumerate(words):
        if word in ('--model', '-m') and index + 1 < len(words): model = words[index + 1]
        if word.startswith('--model='): model = word.split('=', 1)[1]
        if word == '--effort' and index + 1 < len(words): effort = words[index + 1]
        if word.startswith('--effort='): effort = word.split('=', 1)[1]
        if word == '-c' and index + 1 < len(words):
            if words[index + 1].startswith('model_reasoning_effort='): effort = words[index + 1].split('=', 1)[1]
            if words[index + 1].startswith('model='): model = words[index + 1].split('=', 1)[1]
        if word.startswith('ANTHROPIC_MODEL=') or word.startswith('CLAUDE_MODEL='): model = word.split('=', 1)[1]
        if word == '--task' and index + 1 < len(words): task = words[index + 1]
        if word.startswith('--task='): task = word.split('=', 1)[1]
        if word == '--author-rung' and index + 1 < len(words): author_rung = words[index + 1]
        if word.startswith('--author-rung='): author_rung = word.split('=', 1)[1]
        if word == '--author-harness' and index + 1 < len(words): author_harness = words[index + 1]
    task = task or esc.task_key_from(command)
    facts = {'model': model, 'effort': effort, 'task': task}
    basenames = [w.rsplit('/', 1)[-1] for w in words]
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
    # Permission and review-only checks come first: no task means no recorded permission.
    if entry['needs_user_permission'] and not (status or {}).get('permission'):
        return 'deny', 'launch at %s needs recorded user permission for task %s' % (requested['rung'], task or '(none)'), None, facts
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
    order = tiers.rung_order(policy)
    if order.index(requested['rung']) > order.index(status['rung']) and 'rescue.py' not in basenames:
        return 'deny', 'launch at %s is above task %s rung %s' % (requested['rung'], task, status['rung']), None, facts
    return 'allow', None, None, facts


def live_path(session_id):
    root = esc.state_root() / 'live'
    root.mkdir(mode=0o700, exist_ok=True)
    return root / (re.sub(r'[^A-Za-z0-9_-]', '_', session_id or 'unknown')[:80] + '.json')


def live_update(session_id, agent_id, *, start):
    import fcntl
    path = live_path(session_id)
    lock = os.open(path.with_suffix('.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            live = json.loads(path.read_text()) if path.exists() else {}
            if not isinstance(live, dict): live = {}
        except (OSError, ValueError):
            live = {}
        key = str(agent_id or 'unknown')
        live = _expire_live(live)
        if start:
            live[key] = esc.now()
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
    for key, at in live.items():
        try:
            if datetime.fromisoformat(str(at)) >= cutoff: kept[key] = at
        except ValueError:
            continue
    return kept


def live_count(session_id):
    path = live_path(session_id)
    try:
        live = json.loads(path.read_text()) if path.exists() else {}
        return len(_expire_live(live)) if isinstance(live, dict) else 0
    except (OSError, ValueError):
        return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    action = argv[0] if argv else 'hook'
    try:
        data = json.load(sys.stdin)
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
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
        count = live_update(session_id, data.get('agent_id'), start=(action == 'start'))
        cap = int(policy.get('caps', {}).get('session_live_agents', LIVE_CAP_DEFAULT))
        if action == 'start' and count > cap:
            print(json.dumps({'hookSpecificOutput': {'hookEventName': 'SubagentStart',
                              'additionalContext': 'live agents %d exceed the cap %d; stop some before spawning more' % (count, cap)}}))
        return 0
    if tool in SPAWN_TOOLS:
        cap = int(policy.get('caps', {}).get('session_live_agents', LIVE_CAP_DEFAULT))
        if live_count(session_id) >= cap:
            decision, reason, updated, facts = 'deny', 'live agents at the cap %d for this session' % cap, None, {}
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
        # Warn mode only speaks: no permissionDecision (which would skip the prompt) and no updatedInput.
        text = 'ladder (warn mode): would %s: %s' % (decision, reason or 'apply updatedInput %s' % json.dumps(updated or {}, sort_keys=True)[:200])
        print(json.dumps(hook_result('context', context=text)))
        return 0
    print(json.dumps(hook_result(decision, reason, updated)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
