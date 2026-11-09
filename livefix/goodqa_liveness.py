"""goodqa fleet liveness: measure whether the fleet is actually moving, every 2 min, and act when it is not
(goodqa-liveness.timer on DEV).

  goodqa fleet liveness [--apply --ticket T --reason R] [--json]      one pass: measure, diagnose, remedy, alert (dry run unless --apply)
  goodqa fleet liveness --replay --since ISO [--until ISO] [--json]   the same detector over the recorded timeline (events.log, the
                                                                      lane-floor journal, gq-queue refusals): when each finding first fired
  goodqa fleet liveness overrides [--clear CONFIG.KEY --apply ...]    the rule modes this tool flipped to warn (runtime state)

Why (Eric 2026-10-23, relayed by @coordinator ~21:5xZ, goodqa#7925): "why is it that every time i walk away thinking i can trust you
to keep work moving, i came back to some fucked off scneario where everything is halted on someting stupid". Each stall that day was
found late by a 10-min sweep and fixed by hand: a whole-repo lease starving lane-floor, the Postship-flow gate refusing every bug
brief, an install drain at 0 running, a clone-EOF train STOP, GoodQA merging nothing 12:00-19:03.

Live host health: every failed unit type, unparsed/count census alarms, unknown RED after 3 passes,
first-sight journal tails, output leaks, disk-fill ETA; warn by default, enforce stops mapped timers once per episode.

Findings (pure: evaluate(sample, state, cfg) and per-class detectors):
  service-failing:N enabled managed service has service_fail_runs (4) consecutive failures; names blank worker messages
  service-inert:N   enabled warn service has service_inert_min_actions (50) actions in service_inert_days (7) with zero effects
  service-unknown   unreadable/truncated service events or an older collector; alert only, outside --replay
  git-credentials: per-host config drift and ship-environment probes; retained until two healthy observations, never auto-repaired.
  running-starved   running < floor/2 for starve_seconds (240)
  queue-idle        queued > 0 and running == 0 for idle_seconds (120)
  floor-starved     lane-floor's last run had shortfall >= 5 and fewer briefs available than half of it, with >= 5 skips, for
                    starve_seconds (a lease or a rule starving dispatch while some lanes still run)
  merge-stall:P     product P (goodqa, timbar, optin) has rows merging but no merge for merge_stall_minutes (90); the top STOP class
  mass-stop         >= 5 grade failures of one STOP class in 15 min (a train-wide infrastructure STOP)
  train-stalled:P   product P has a merge train (merge_train >= 2), more than train_stall_min_merging (10) rows merging, and no train
                    grade verdict PASS for train_stall_hours (3); names the top train STOP classes, the last PASS and the train in
                    grade now (goodqa#7956: 39 of 40 GoodQA train grades STOPped on 2026-10-23 while trains kept running)
  deploy-lag:P      product P's origin/main has been ahead of what is live for more than deploy_lag_minutes (60; ruling 82, Eric
                    2026-10-24 ~02:10Z: "you're going to stop letting things sit for 4 hours without deploying." "(or 7)"): the
                    live sha (GoodQA /v1/version sourceSha; OptinRouter and Timbar from their ship status line, else their
                    readback), the commits and minutes behind (since the oldest unshipped main-line commit landed; commits that
                    only touch global plus per-product deploy_lag_ignore regex paths do not count) and every known blocker: an install drain or fleet
                    pause, the runner's ship wave (running or failing), ship-watch incidents, the DEV ship timer's refused pass.
                    warn: the Coordinator alert ticket; enforce: also a comment on the product's release ticket. Read every
                    deploy_lag_every_seconds (600) per product; before opening or updating a lag alert, re-read within the same
                    budget and suppress caught-up findings (failed reads retain the finding); not part of --replay
  land-lag:RUN/ROW  READY or exact PASS pin candidate awaiting landing/activation: safety alarms at 10 minutes, other at 60;
                    other clears on candidate ancestry; safety additionally needs activation + independent refusal evidence;
                    all discovered rows persist conservative debt before git checks/budget cutoff; unknown caps too;
                    ownership uses NUL-delimited paths and header metadata; each retained candidate needs its own proof
  autocommit-stalled  the live tree (/home/eric/repos/harness, git dir harness-scratch.git) has uncommitted changes or local commits while origin/main is
                    ahead of it, or has uncommitted changes and no commit, for autocommit_stall_minutes (10), WHATEVER the cause (goodqa#11505: three
                    stalls in one evening, a stale zero-byte index.lock, a pre-commit crash on a non-UTF-8 fixture, a guard refusal, all found by an
                    agent and by no detector). Read-only (git ls-remote + status with --no-optional-locks); the title names the cause classified from
                    the autocommit log tail (stale-index-lock, pre-commit-crash, guard-refusal, push-rejected, integrate-dirty, unknown) and the lines
                    carry the lock facts, the counts and the last log lines. Repeated `pre-commit guards left uncommitted` entries are
                    counted per path across successes (autocommit_refusal_min, default 20, spanning the stall hold); recent pending refusals still alert. Alert only: the self-heal of a stale lock lives in the autocommit itself
  rule-refusing:R   one admission / brief rule refused > max_refusals (5) distinct ready briefs in the last lane-floor run plus
                    gq-queue's refusals of the last 10 min -> the rule is flipped to warn (bin/rule_overrides.py) and alerted
Diagnosis of the first three, in order: an install drain and its holders (rows still running/merging/reviewing), the fleet
paused or halted, lane-floor (gate refusal, top skip reason, refusals by rule), gq-queue refusals, test broker saturation, limit
pauses. Remedies, only the safe ones, each at most once per remedy_cooldown_seconds: start goodqa-autopilot.service (its
drain-holders rule pauses 1-3 holders of a drain over 10 min; train-innocent and the rest), start lane-floor.service, flip a
refusing rule to warn. Otherwise ONE rolling alert ticket per alert key (assigned to Coordinator, under goodqa#6099; a land-lag lane
family shares one; gq-clutter S1): a repeat observation rewrites one marked status block in its description, comments only on
transitions and at most one reminder per alert_comment_minutes on a material change; when the finding clears (absent past clear_seconds) the filer posts a recovery comment and CLOSES the
ticket to done (goodqa#13953); a still-firing finding is never closed, and git-credentials (landed dark) stays comment-only.
Never deletes, cancels or pauses anything else itself. Journal:
lanes/engine-logs/goodqa-liveness.log; state ~/.local/state/goodqa-liveness/state.json; config config/fleet-liveness.json; doc
docs/ops/FLEET-LIVENESS.md; tests bin/test_goodqa_liveness.py. LANE:ticket-lifecycle-20261023."""
import calendar
import collections
import fcntl
import fnmatch
import inspect
import math
import json
import os
import re
import subprocess
import sys
import time

import goodqa_cli as C

CONFIG = os.path.join(C.CODE_ROOT, 'config', 'fleet-liveness.json')
STATE = os.path.expanduser('~/.local/state/goodqa-liveness/state.json')
REFUSALS = os.path.expanduser('~/.local/state/gq-queue/refusals.jsonl')
AUTOPILOT_STATE = os.path.expanduser('~/.local/state/goodqa-autopilot/state.json')
REMOTE = os.path.join(C.CODE_ROOT, 'bin', 'goodqa_liveness_remote.py')
DEV2 = os.path.join(C.CODE_ROOT, 'bin', 'dev2')
DOC = 'docs/ops/FLEET-LIVENESS.md'
LANE = 'LANE:ticket-lifecycle-20261023'
PRODUCTS = ('goodqa', 'timbar', 'optin')
HAWK_JOURNAL = ('/home/eric/.hawkeye/harness/hawk-journal',)
STATE_LINE = re.compile(r'^(\S+Z) state\s+(\S+) -> (\S+) \| (.*)$')
FLEET_LINE = re.compile(r'^(\S+Z) fleet\s+fleet=(\w+) \| (.*)$')
INSTALL = re.compile(r'install\.sh ([0-9a-f]{7,40})')
LF_SHORT = re.compile(r'shortfall (\d+), this run takes at most \d+; (\d+) brief\(s\) available')
LF_IDLE = re.compile(r'shortfall (-?\d+) is below')
LF_SKIP = re.compile(r'^skip (\S+): (.*)$')
# Admission / brief rules a refusal names, and the runtime switch that turns each to warn (bin/rule_overrides.py).
RULES = [
    dict(id='postship-flow', match=r'Postship-flow', config='ticket-lifecycle', key='bug_brief_postship', warn='warn'),
    dict(id='tests-lint', match=r'TESTS lint|tests_lint|\(relative-testrun\)|\(unknown-suite\)|\(cmd-no-counts\)', config='tests-lint',
         key='from_file', warn='warn'),
    dict(id='current-state', match=r'Current state', config='lane-floor', key='require_current_state', warn=False),
    dict(id='brief-tickets', match=r'render of its|brief_tickets|does not reproduce|not the render', config='lane-floor',
         key='brief_tickets', warn='warn'),
]


# ------------------------------------------------------------------------------------------------ config, state
def _read_liveness_config(f):
    # Keep decoding separate from validation, including the existing config mutation seam.
    return json.load(f)


def load_config(path=None):
    with open(path or os.environ.get('GOODQA_LIVENESS_CONFIG') or CONFIG) as f:
        cfg = _read_liveness_config(f)
    if cfg.get('git_credentials_mode', 'on') not in ('on', 'off'):
        raise C.CliError('git_credentials_mode must be on or off')
    ignores = cfg.get('host_health', {}).get('failed_units', {}).get('ignore', [])
    if not isinstance(ignores, list):
        raise C.CliError('host_health.failed_units.ignore must be a list')
    for entry in ignores:
        if (not isinstance(entry, dict) or not isinstance(entry.get('glob'), str) or not entry['glob'].strip() or
                not isinstance(entry.get('reason'), str) or not entry['reason'].strip()):
            raise C.CliError('host_health.failed_units.ignore entry %r requires glob and reason strings' % entry)
    return cfg


def state_path():
    return os.environ.get('GOODQA_LIVENESS_STATE') or STATE


def load_state(path=None):
    try:
        with open(path or state_path()) as f:
            st = json.load(f)
    except (OSError, ValueError):
        st = {}
    for k in ('since', 'alerts', 'remedied'):
        st.setdefault(k, {})
    return st


def save_state(st, path=None):
    p = path or state_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = '%s.tmp.%d' % (p, os.getpid())
    with open(tmp, 'w') as f:
        json.dump(st, f, indent=1, sort_keys=True)
    os.replace(tmp, p)


def ts(s):
    m = re.match(r'^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)', str(s or ''))
    return float(calendar.timegm(tuple(int(x) for x in m.groups()) + (0, 0, 0))) if m else 0.0


def iso(t):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(t))


# ------------------------------------------------------------------------------------------------ pure: classification
def rule_of(text):
    for r in RULES:
        if re.search(r['match'], text or ''):
            return r['id']
    return None


def skip_class(reason):
    m = re.match(r'owned paths overlap active (\S+)', reason)
    if m:
        return 'owned paths overlap active %s' % m.group(1)
    if reason.startswith('held until'):
        return 'held on a dependency'
    if 'back-fill refused' in reason or 'refused' in reason[:40]:
        return 'refused by rule %s' % (rule_of(reason) or 'other')
    return C.cap(re.sub(r'\b[0-9a-f]{7,40}\b|\d+', 'N', reason), 60, tail=False)


def stop_class(reason):
    r = reason or ''
    if re.search(r'merge train workspace|git clone|unexpected EOF|early EOF|fetch-pack', r):
        return 'train workspace / clone failure (infrastructure)'
    if 'CONFLICT' in r:
        return 'merge conflict (repair queued)'
    if re.search(r'regrade bound|unresolved group', r):
        return 'train bisection bound spent'
    if re.search(r'no evidence that tests executed|did not run tests|silent success', r):
        return 'TESTS line runs nothing countable'
    if re.search(r'new failure|not ok|FAIL', r):
        return 'test failure on the merged side'
    if re.search(r'timeout|timed out|wait-max', r, re.I):
        return 'timeout / wait limit'
    return C.cap(re.sub(r'\b[0-9a-f]{7,40}\b', 'SHA', r), 60, tail=False)


def parse_lane_floor(lines):
    """Lane-floor journal lines (with their ISO timestamps) -> the runs: [{at, end, shortfall, available, gate, skips{class: n},
    refused{rule: set(briefs)}, queued}] in order."""
    runs, cur = [], None
    for line in lines:
        m = re.match(r'^(\S+)\s+\S+\s+(\S+)\[\d+\]:\s*(.*)$', line) or re.match(r'^(\S+)\s+\S+\s+(\S+):\s*(.*)$', line)
        if not m:
            continue
        when, who, text = ts(m.group(1)), m.group(2), m.group(3)
        if who.startswith('systemd') and 'Starting lane-floor' in text:
            cur = dict(at=when, end=None, shortfall=None, available=None, gate=None, skips=collections.Counter(), refused={}, queued=0)
            runs.append(cur)
            continue
        if cur is None:
            continue
        if who.startswith('systemd') and ('Finished lane-floor' in text or 'Deactivated' in text or 'Failed' in text):
            cur['end'] = when
            continue
        if not text.startswith('lane-floor: '):
            continue
        t = text[len('lane-floor: '):]
        s = LF_SHORT.search(t)
        if s:
            cur['shortfall'], cur['available'] = int(s.group(1)), int(s.group(2))
            continue
        s = LF_IDLE.search(t)
        if s and cur['shortfall'] is None:
            cur['shortfall'] = int(s.group(1))
            continue
        if t.startswith('REFUSED:'):
            cur['gate'] = C.cap(t, 200, tail=False)
            continue
        if t.startswith('QUEUED '):
            cur['queued'] += 1
            continue
        s = LF_SKIP.match(t)
        if s:
            cls = skip_class(s.group(2))
            cur['skips'][cls] += 1
            rule = rule_of(s.group(2)) if 'refused' in s.group(2) else None
            if rule:
                cur['refused'].setdefault(rule, set()).add(s.group(1))
    for r in runs:
        r['end'] = r['end'] or r['at']
    return runs


def refusals_by_rule(rows, since):
    """gq-queue refusals.jsonl rows since `since` -> ({rule: set(briefs)}, Counter(class))."""
    by_rule, classes = {}, collections.Counter()
    for r in rows:
        if ts(r.get('ts')) < since:
            continue
        reason = str(r.get('reason') or '')
        if str(r.get('rc')) == '75':
            classes['busy: ' + C.cap(re.sub(r'^.*gq-queue: busy: ', '', reason), 50, tail=False)] += 1
            continue
        rule = rule_of(reason)
        classes['refused: %s' % (rule or 'other')] += 1
        if rule:
            by_rule.setdefault(rule, set()).add(r.get('brief') or r.get('task'))
    return by_rule, classes


# ------------------------------------------------------------------------------------------------ pure: the detector
def diagnose(s, cfg):
    """Why the fleet is not running, in the known order. -> (lines, remedies [dict(kind, ...)])."""
    lines, remedies = [], []
    d = s.get('drain')
    if d:
        holders = s.get('holders') or []
        mins = (s['at'] - d['since']) / 60.0
        lines.append('install drain %s for %.0f min (%s); %d session(s) still hold it%s' % (
            d.get('install') or '?', mins, C.cap(d.get('reason') or '', 120, tail=False), len(holders),
            (': ' + ', '.join(holders[:6])) if holders else ': no session; the installer itself (ship qualification or activation) or an '
            'in-flight merge (mergeBusy) holds it'))
        if mins >= 10 and 0 < len(holders) <= 3:
            remedies.append(dict(kind='start-unit', unit='goodqa-autopilot.service', why='drain-holders: pause the %d holder(s) of a '
                                 'drain over 10 min (they resume after undrain)' % len(holders)))
    fs = (s.get('fleet_state') or '').split(' ')[0]
    if fs and fs not in ('running', ''):
        lines.append('the fleet is %s (%s)' % (fs.upper(), C.cap(s.get('fleet_state') or '', 100, tail=False)))
    lf = s.get('lane_floor')
    if lf:
        if lf.get('gate'):
            lines.append('lane-floor refuses at its gate: %s' % lf['gate'])
        sf, av = lf.get('shortfall'), lf.get('available')
        top = [kv for kv in (lf['skips'].most_common(4) if lf.get('skips') else []) if kv[0] != 'held on a dependency'][:3]
        lines.append('lane-floor %s: shortfall %s, %s brief(s) available; top skips: %s' % (
            iso(lf['at'])[11:16], sf, '?' if av is None else av, '; '.join('%s x%d' % kv for kv in top) or 'none'))
        if lf.get('refused'):
            lines.append('lane-floor refusals by rule: %s' % ', '.join('%s %d' % (k, len(v)) for k, v in sorted(lf['refused'].items())))
        if s['at'] - (lf.get('end') or lf['at']) > float(cfg.get('lane_floor_stale_seconds', 300)) or (av or 0) > 0:
            remedies.append(dict(kind='start-unit', unit='lane-floor.service', why='re-run lane-floor now (last run %s, %s available)' % (
                iso(lf['at'])[11:16], av)))
    gq = s.get('gq_refusals') or collections.Counter()
    if gq:
        lines.append('gq-queue refusals, last 10 min: %s' % ', '.join('%s x%d' % kv for kv in gq.most_common(3)))
    b = s.get('broker')
    if b and (b.get('off') or b.get('queued', 0) >= int(cfg.get('broker_queue_max', 20))
              or b.get('max_wait_s', 0) >= int(cfg.get('broker_wait_max_s', 900))):
        lines.append('test broker saturated: %s running, %s queued, longest wait %s s%s' % (
            b.get('running'), b.get('queued'), b.get('max_wait_s'), ' (KILL SWITCH ON)' if b.get('off') else ''))
    if s.get('limit_pauses'):
        lines.append('%d row(s) stopped on a usage / session limit in the last 30 min' % s['limit_pauses'])
    if not remedies:
        remedies.append(dict(kind='start-unit', unit='goodqa-autopilot.service', why='run the autopilot rules (resumes, successors, '
                             'train-innocent) on the current snapshot'))
    return lines, remedies


def blocking_skips(lf):
    """Skips that keep a READY brief out (overlaps, refusals, gates), not the briefs held on purpose until a dependency merges."""
    return sum(n for cls, n in (lf.get('skips') or {}).items() if cls != 'held on a dependency')


def _held(st, key, cond, at, need):
    """A condition that must hold `need` seconds: st['since'][key] remembers when it began."""
    if not cond:
        st['since'].pop(key, None)
        return False
    st['since'].setdefault(key, at)
    return at - st['since'][key] >= need


def train_stop_class(head):
    """The class of one train grade's STOP head (grade.json Reason before the reclassified tool-check list)."""
    h = head or ''
    if re.search(r'did not run tests \(status empty\)', h):
        return 'bare targeted testrun: control selects nothing (status empty)'
    m = re.search(r'\(control rc=(-?\d+) merged rc=(-?\d+)\)', h)
    if m and m.group(1) == m.group(2) and m.group(1) in ('124', '143', '137'):
        return 'grade command timed out / killed on both sides (rc %s)' % m.group(1)
    if m and m.group(1) == m.group(2) and m.group(1) == '127':
        return 'command missing in the grade env (rc 127 both sides)'
    if re.search(r'nonzero exit without identifiable', h) and m and m.group(1) == m.group(2):
        return 'fails on main too (same rc both sides)'
    if re.search(r'tested tree \S+, not this side', h):
        return 'TESTS line pins another tree (--sha / --repo)'
    if re.search(r'changed tracked files', h):
        return 'raw TESTS line dirtied the tree (not through bin/testrun)'
    if re.search(r'grade task stopped or review changed', h):
        return 'grade cancelled (a car changed or was held)'
    if re.search(r'no evidence that tests executed|no test executed', h):
        return 'TESTS line runs nothing countable (no test counts)'
    if re.search(r'could not complete', h):
        return 'grade command could not complete (rc %s/%s)' % (m.groups() if m else ('?', '?'))
    return stop_class(re.sub(r'--wait-max \d+|--timeout \d+', '', h))


def evaluate(s, st, cfg):
    """Pure: one sample -> findings [dict(cls, title, lines, remedies)]; st['since'] carries the durations."""
    out = []
    at, floor = s['at'], int(s.get('floor') or cfg.get('floor_default', 40))
    running, queued = int(s.get('running') or 0), int(s.get('queued') or 0)
    starve = float(cfg.get('starve_seconds', 240))
    starved = _held(st, 'running-starved', running < floor / 2.0, at, starve)
    idle = _held(st, 'queue-idle', queued > 0 and running == 0, at, float(cfg.get('idle_seconds', 120)))
    lf = s.get('lane_floor') or {}
    sf, av = lf.get('shortfall'), lf.get('available')
    lf_starved = _held(st, 'floor-starved', bool(lf) and (sf or 0) >= int(cfg.get('floor_min_shortfall', 5)) and av is not None
                       and av < (sf or 0) / 2.0 and blocking_skips(lf) >= int(cfg.get('floor_min_skips', 5)), at, starve)
    for cls, hit, title in (('queue-idle', idle, '%d queued, 0 running' % queued),
                            ('running-starved', starved and not idle, '%d running, below half the floor of %d' % (running, floor)),
                            ('floor-starved', lf_starved and not (idle or starved), 'lane-floor starved: shortfall %s, %s available' % (sf, av))):
        if hit:
            lines, remedies = diagnose(s, cfg)
            out.append(dict(cls=cls, title=title, lines=lines, remedies=remedies))
    stall = float(cfg.get('merge_stall_minutes', 90)) * 60
    for p in PRODUCTS:
        merging = int((s.get('merging') or {}).get(p) or 0)
        last = s.get('last_merge', {}).get(p)
        if merging > 0 and last and at - last > stall:
            stops = collections.Counter(stop_class(g['reason']) for g in s.get('grade_failed') or [] if g.get('product') == p)
            out.append(dict(cls='merge-stall:%s' % p, title='%s: %d row(s) merging, no merge for %.0f min' % (p, merging, (at - last) / 60.0),
                            lines=['last %s merge %s' % (p, iso(last)), 'top STOP classes (3 h): %s' % (
                                '; '.join('%s x%d' % kv for kv in stops.most_common(3)) or 'none recorded')], remedies=[
                                dict(kind='start-unit', unit='goodqa-autopilot.service', why='train-innocent / merge-flow-watchdog rules')]))
    window = float(cfg.get('train_stall_hours', 3)) * 3600
    for p, cars in sorted((s.get('merge_trains') or {}).items()):
        merging = int((s.get('merging') or {}).get(p) or 0)
        if p not in PRODUCTS or int(cars or 0) < 2 or merging <= int(cfg.get('train_stall_min_merging', 10)):
            continue
        tv = [v for v in s.get('train_verdicts') or [] if v.get('product') == p and ts(v['ts']) <= at]
        passes = [v for v in tv if v.get('verdict') == 'PASS']
        last_pass = ts(passes[-1]['ts']) if passes else None
        landed = (s.get('last_grade_pass') or {}).get(p)          # a `merged | GRADE PASS` landing (retention may have swept its grade.json)
        if landed and landed <= at and (last_pass is None or landed > last_pass):
            last_pass = landed
            passes = passes + [dict(ts=iso(landed), lead='(merged | GRADE PASS)')]
        if last_pass and at - last_pass <= window:
            continue
        inwin = [v for v in tv if at - ts(v['ts']) <= window]
        verdicts = collections.Counter(v.get('verdict') for v in inwin)
        stops = collections.Counter(train_stop_class(v.get('head')) for v in inwin if v.get('verdict') != 'PASS')
        running = [r for r in s.get('train_running') or [] if r.get('product') == p]
        out.append(dict(cls='train-stalled:%s' % p, title='%s: %d row(s) merging, no merge-train PASS for %s' % (
            p, merging, ('%.0f min' % ((at - last_pass) / 60.0)) if last_pass else 'the whole lookback'), lines=[
            'last train PASS: %s' % ('%s (lead %s)' % (passes[-1]['ts'], passes[-1]['lead']) if passes else 'none recorded'),
            'train verdicts (%.0f h): %s' % (window / 3600, ', '.join('%s x%d' % kv for kv in verdicts.most_common()) or 'none: no train finished'),
            'top train STOP classes: %s' % ('; '.join('%s x%d' % kv for kv in stops.most_common(3)) or 'none recorded'),
            'train in grade now: %s' % (', '.join('%s (%s, started %s, last write %s)' % (r['lead'], r.get('dir'), r.get('started'), r.get('last'))
                                                  for r in running[:2]) or 'none')], remedies=[
            dict(kind='start-unit', unit='goodqa-autopilot.service', why='train-poison-hold holds cars whose TESTS cannot pass a train grade')]))
    recent = [g for g in s.get('grade_failed') or [] if at - ts(g['ts']) <= 900]
    for cls, n in collections.Counter(stop_class(g['reason']) for g in recent).items():
        if n >= int(cfg.get('mass_stop_min', 5)):
            out.append(dict(cls='mass-stop', title='%d grade failures in 15 min: %s' % (n, cls), lines=[
                'tasks: %s' % C.cap(', '.join(g['task'] for g in recent if stop_class(g['reason']) == cls), 600, tail=False)], remedies=[
                dict(kind='start-unit', unit='goodqa-autopilot.service', why='train-innocent resumes cars not attributed to the STOP')]))
            break
    refused = {}
    for rule, briefs in (lf.get('refused') or {}).items():
        refused.setdefault(rule, set()).update(briefs)
    for rule, briefs in (s.get('gq_refused') or {}).items():
        refused.setdefault(rule, set()).update(briefs)
    for rule, briefs in sorted(refused.items()):
        if len(briefs) > int(cfg.get('max_refusals', 5)):
            spec = next(r for r in RULES if r['id'] == rule)
            out.append(dict(cls='rule-refusing:%s' % rule, title='rule %s refused %d ready briefs in one pass' % (rule, len(briefs)),
                            lines=['briefs: %s' % ', '.join(sorted(os.path.basename(b or '?') for b in briefs)[:12]),
                                   'flipped to warn at runtime: %s.%s = %r (bin/rule_overrides.py); make it permanent in config/%s.json '
                                   'or clear it with `goodqa fleet liveness overrides --clear %s.%s --apply`' % (
                                       spec['config'], spec['key'], spec['warn'], spec['config'], spec['config'], spec['key'])],
                            remedies=[dict(kind='rule-warn', config=spec['config'], key=spec['key'], value=spec['warn'], rule=rule),
                                      dict(kind='start-unit', unit='lane-floor.service', why='re-run lane-floor with the rule warning')]))
    return out + deploy_lag_findings(s, cfg)


# ------------------------------------------------------------------------------------------------ ready work awaiting landing/activation (O8)
def collect_land_lag_remote(home=None, ledger_text=None, known=None, limits=None):
    """Read-only dev2 collector, also executable offline against a fixture HOME. No fetch, writes or landing.

    land-proof.json lives beside receipt/pin-queue.json. Its landed_sha is checked against origin/main;
    candidate ancestry and independently observed activation/refusal are checked before a cached gate clears.
    """
    import glob
    import pathlib
    import subprocess
    import json
    import re
    import time
    root = pathlib.Path(home or pathlib.Path.home())
    errors, rows = [], []
    limits = limits or {}
    started = time.monotonic()
    deadline = started + float(limits.get('land_lag_budget_seconds', 20))
    calls_left = int(limits.get('land_lag_git_calls', 24))
    ready_left = int(limits.get('land_lag_ready_checks', 8))

    def signature(directory):
        values = []
        for name in ('receipt', 'worktree', 'spec.md', 'base', 'land-proof.json', 'pin-queue.json'):
            try:
                info = (directory / name).stat()
                values.append((name, info.st_mtime_ns, info.st_size))
            except OSError:
                values.append((name, None, None))
        return json.dumps(values)


    def read(path):
        try:
            return path.read_text(errors='replace')[:262144]
        except OSError:
            return ''

    def owner_identity(wt):
        # Capture candidate identity even when enrichment has no remaining git budget.
        # A worktree path and its base are reusable; the symbolic branch is task-bound.
        gitdir = wt / '.git'
        pointer = read(gitdir).strip() if gitdir.is_file() else ''
        if pointer.startswith('gitdir: '):
            gitdir = pathlib.Path(pointer[8:])
            if not gitdir.is_absolute():
                gitdir = wt / gitdir
        head = read(gitdir / 'HEAD').strip()
        branch = head[5:] if head.startswith('ref: refs/heads/') else None
        sha = head
        if branch:
            common = read(gitdir / 'commondir').strip()
            common_dir = gitdir / common if common else gitdir
            sha = read(common_dir / branch).strip()
            if not sha:
                for line in read(common_dir / 'packed-refs').splitlines():
                    fields = line.split()
                    if len(fields) == 2 and fields[1] == branch:
                        sha = fields[0]
                        break
        return branch, sha if re.fullmatch('[0-9a-f]{40}', sha) else None

    def document(path):
        try:
            value = json.loads(read(path))
            return value if isinstance(value, dict) else {}
        except ValueError:
            return {}

    def git(wt, *args):
        nonlocal calls_left
        remaining = deadline - time.monotonic()
        if calls_left <= 0 or remaining <= 0:
            return 124, ''
        calls_left -= 1
        try:
            cmd = ['git', '--git-dir=' + str(wt)] if str(wt).endswith('.git') else ['git', '-C', str(wt)]
            p = subprocess.run(cmd + list(args), capture_output=True, text=True, errors='surrogateescape',
                               timeout=min(0.75, remaining))
            return p.returncode, p.stdout if '-z' in args else p.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            return 124, ''

    def ancestry(wt, sha):
        if not re.fullmatch('[0-9a-f]{40}', str(sha or '')):
            return None
        rc, _ = git(wt, 'merge-base', '--is-ancestor', sha, 'origin/main')
        return True if rc == 0 else False if rc == 1 else None

    def finish(row, directory, wt):
        row['worktree'] = str(wt)
        row['checked_at'] = time.time()
        row['signature'] = signature(directory)
        if row.get('source') == 'runner':
            rc, email = git(wt, 'show', '-s', '--format=%ae', row.get('candidate_sha') or 'INVALID')
            row['author'] = email if rc == 0 and '@' in email else None
            name_rc, name = git(wt, 'show', '-s', '--format=%an', row.get('candidate_sha') or 'INVALID')
            row['author_identity_complete'] = bool(rc == 0 and name_rc == 0 and row['author'] and name.strip())
            row['author_aliases'] = [x for x in (row['author'], name) if x]
        row['landed'] = ancestry(wt, row.get('candidate_sha'))
        proof = document(directory / 'land-proof.json')
        landed = proof.get('landed_sha')
        row['proof'] = proof
        row['proof_landed'] = ancestry(wt, landed)
        row['gate_candidate_sha'] = row.get('candidate_sha')
        row['proof_contains_candidate'] = False
        if landed:
            rc, _ = git(wt, 'merge-base', '--is-ancestor', row['gate_candidate_sha'] or 'INVALID', landed)
            row['proof_contains_candidate'] = rc == 0
        declared = re.search(r'^Ticket:\s*(goodqa#\d+)\b', land_lag_headers(row.get('spec', '')), re.M | re.I)
        row['ticket'] = declared.group(1) if declared else ledger_tickets.get(row['key'])
        if row['landed'] is None:
            errors.append(row['key'] + ': candidate ancestry to origin/main unreadable')
        rows.append(row)

    if ledger_text is None:
        ledger_text = read(root / 'repos/harness/docs/ops/ERIC-OBLIGATIONS.md') or read(root / 'repos/gorunner/docs/ops/ERIC-OBLIGATIONS.md')
    ledger_tickets = {}
    for line in (ledger_text or '').splitlines():
        if not line.startswith('|'):
            continue
        cells = [cell.strip() for cell in line.strip('|').split('|')]
        # The obligations table's Step and Owner/run columns bind source identity to ticket.
        if len(cells) >= 5:
            ticket = re.search(r'goodqa#\d+', cells[1])
            for key in re.findall(r'\bcodex\s+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)', cells[4]):
                if ticket:
                    ledger_tickets[key] = ticket.group()

    pending = []
    owners = root / '.local/state/codex-owners'
    for receipt in owners.glob('*/*/receipt'):
        text = read(receipt)
        if not re.match(r'^READY(?:\s|$|\()', text):
            continue
        d = receipt.parent
        wt = pathlib.Path(read(d / 'worktree').strip())
        branch, captured_sha = owner_identity(wt)
        pending.append((dict(key='/'.join(d.parts[-2:]), source='codex-owner', receipt=text,
                             spec=read(d / 'spec.md'), author=read(d / 'account').strip(),
                             branch=branch, captured_sha=captured_sha, base=read(d / 'base').strip(),
                             ready_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(receipt.stat().st_mtime))),
                        d, wt))

    config = document(root / 'repos/gorunner/gorunner/config.json')
    if not config:
        config = document(root / 'repos/gorunner/config.json')
    runner = root / '.local/share/gorunner/tasks'
    for pin in sorted(runner.glob('*/pin-queue.json')):
        d, q = pin.parent, document(pin)
        if q.get('repo') != 'harness' or not q.get('candidate_sha'):
            continue
        # A pin queue is not itself evidence of a PASS: verify the exact retained candidate.
        grades = [document(pathlib.Path(p)) for p in glob.glob(str(d / 'merge-grade*/grade.json'))]
        if not any(g.get('Verdict') == 'PASS' and g.get('Commit') == q['candidate_sha']
                   and g.get('Tip') == q.get('reviewed_sha') for g in grades):
            continue
        repo = (config.get('repos') or {}).get('harness') or str(root / 'repos/harness-scratch.git')
        brief = read(root / 'repos/gorunner/gorunner/tasks' / (d.name + '.md'))
        if not brief:
            brief = read(root / 'repos/gorunner/tasks' / (d.name + '.md'))
        pending.append((dict(key='runner/' + d.name, source='runner', task_id=d.name, candidate_sha=q['candidate_sha'],
                    ready_at=q.get('queued_at') or time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(pin.stat().st_mtime)),
                    spec=brief, paths=q['paths'] if isinstance(q.get('paths'), list) else [],
                    paths_unreadable=not (isinstance(q.get('paths'), list) and
                                          all(isinstance(p, str) and p for p in q['paths'])),
                    author=None), d, pathlib.Path(repo)))
    # Retained debt remains bound to its original tree and SHA after a directory is reassigned.
    for key, retained in (known or {}).items():
        source_key = retained.get('source_key') or key
        if (retained.get('class') not in ('safety', 'unknown') or not retained.get('candidate_sha')
                or not retained.get('directory') or not retained.get('worktree')):
            continue
        if any(r.get('candidate_sha') == retained['candidate_sha'] and r['key'] == source_key
               for r, _, _ in pending):
            continue
        retry = dict(retained, key=key, retained=True)
        pending.append((retry, pathlib.Path(retained['directory']), pathlib.Path(retained['worktree'])))
    # Share one fair queue across owner and PASS rows; slow rows cannot monopolize the next pass.
    pending.sort(key=lambda item: ((known or {}).get(item[0]['key'], {}).get('checked_at', 0), item[0]['key']))
    for row, d, wt in pending:
        key = row['key']
        previous = (known or {}).get(key) or {}
        if row.get('retained') and limits.get('land_lag_discovery_only'):
            continue
        # A landed candidate is immutable; its receipt/proof inputs invalidate this read cache.
        if (not limits.get('land_lag_discovery_only')
                and (row.get('retained') or (row.get('candidate_sha') and row.get('candidate_sha') == previous.get('candidate_sha')))
                and previous.get('landed') is True and previous.get('signature') == signature(d)
                and not previous.get('paths_unreadable') and previous.get('class') != 'unknown'
                and not previous.get('needs_reclassification')
                and not previous.get('identity_inconsistent')
                and previous.get('author_identity_complete') is not False
                and (row.get('source') != 'runner' or previous.get('author_identity_complete') is True)):
            rows.append(dict(previous))
            continue
        if limits.get('land_lag_discovery_only') or ready_left <= 0 or calls_left <= 0 or time.monotonic() >= deadline:
            if row.get('retained'):
                rows.append(dict(previous or row))
                continue
            # Every discovered READY/PASS candidate contributes debt, even before HEAD can be read.
            # A deferred observation cannot resolve or overwrite a retained candidate's ownership.
            rows.append(dict(row, paths_unreadable=True, deferred=True, checked_at=0,
                             worktree=str(wt), base=row.get('base') or read(d / 'base').strip(),
                             directory=str(d), signature=signature(d)))
            continue
        ready_left -= 1
        row['directory'] = str(d)
        row.pop('deferred', None)
        if row['source'] == 'codex-owner':
            rc, row['candidate_sha'] = ((0, row['candidate_sha']) if row.get('retained')
                                        else git(wt, 'rev-parse', '--verify',
                                                 row.get('captured_sha') or row.get('branch') or 'INVALID'))
            if rc:
                row['candidate_sha'] = None
                row['identity_unreadable'] = True
                errors.append(key + ': HEAD unreadable')
            # Classify the captured object, never a new HEAD from a reusable worktree.
            # A concurrent checkout makes this observation unusable as completion proof.
            if not row.get('retained'):
                live_branch, live_sha = owner_identity(wt)
                row['identity_inconsistent'] = bool(
                    not row.get('candidate_sha') or not live_sha
                    or live_branch != row.get('branch') or live_sha != row['candidate_sha'])
                if row['identity_inconsistent']:
                    errors.append(key + ': captured candidate disagrees with current worktree identity')
            else:
                row.pop('identity_inconsistent', None)
            base = row.get('base') or ''
            row['base'] = base
            rc, changed = git(wt, 'diff', '--name-only', '-z', base + '..' + (row['candidate_sha'] or 'INVALID')) if re.fullmatch('[0-9a-f]{40}', base) else (128, '')
            row['paths_unreadable'] = bool(rc)
            row['paths'] = [path for path in changed.split('\0') if path] if not rc else []
            if rc:
                errors.append(key + ': changed paths unreadable (base/HEAD)')
        finish(row, d, wt)
    # The lanes discovered THIS read (a READY codex-owner receipt, or a harness pin queue with its exact PASS grade),
    # excluding retained debt: a cached key whose lane is not here was superseded, cancelled or deleted. Only its
    # alert is closed (gq-clutter S1); the admission-gate debt in land-lag.json is unchanged.
    discovered = sorted({row['key'] for row, _, _ in pending if not row.get('retained')})
    result = dict(rows=rows, errors=errors, discovered=discovered)
    # The gorunner state of each discovered runner task (one read-only `gorunner status -json`, requested by the
    # caller at most every land_lag_runner_states_seconds and bounded under the dev2 call's 30 s): a cancelled,
    # merged, shipped, superseded or vanished task keeps its pin queue on disk, so discovery alone cannot see it.
    ids = sorted({row['task_id'] for row, _, _ in pending
                  if row.get('source') == 'runner' and not row.get('retained') and row.get('task_id')})
    room = min(float(limits.get('land_lag_runner_states_timeout', 8)), 22.0 - (time.monotonic() - started))
    if limits.get('land_lag_runner_states') and not limits.get('land_lag_discovery_only') and ids and room >= 1:
        gorunner = root / 'repos/gorunner'
        cfg_path = gorunner / 'gorunner/config.json'
        if not cfg_path.exists():
            cfg_path = gorunner / 'config.json'
        try:
            p = subprocess.run([str(gorunner / 'bin/gorunner'), '-config', str(cfg_path), 'status', '-json'], cwd=str(gorunner),
                               capture_output=True, text=True, errors='replace', timeout=room)
            tasks = json.loads(p.stdout).get('tasks') if p.returncode == 0 else None
            if isinstance(tasks, list):
                by = {t.get('id'): t for t in tasks if isinstance(t, dict)}
                found = [i for i in ids if i in by]
                # An empty or foreign task list (wrong data dir, a restarted daemon) is no evidence; nor is a read
                # where most discovered tasks are missing: only a minority may read as `absent` (red-team F3).
                if found and len(ids) - len(found) <= len(ids) // 2:
                    result['runner_states'] = {
                        i: dict(state=str((by.get(i) or {}).get('state') or 'absent'),
                                superseded_by=(by.get(i) or {}).get('superseded_by') or None) for i in ids}
        except (OSError, subprocess.SubprocessError, ValueError, AttributeError):
            pass                                   # no runner states this read: discovery presence still applies
    return result


# gorunner task states after which a READY/PASS candidate can no longer land as-is: its land-lag ALERT closes (the
# gate debt is unchanged). `absent`: the task vanished from `gorunner status` while its pin queue remained on disk.
RUNNER_DONE_STATES = frozenset(('cancelled', 'merged', 'shipped', 'absent'))
# For a SAFETY record only the states where its candidate can no longer land at all (landing alone does not clear it).
RUNNER_GONE_STATES = frozenset(('cancelled', 'absent'))
LAND_LAG_CLEAR = 'landed SHA on origin/main + activation proof + independently observed negative-control refusal (all bound to SHA)'


def land_lag_headers(spec):
    """Return only column-zero metadata in the opening brief header, never body/examples."""
    import re
    headers = []
    for line in str(spec or '').splitlines():
        if not line.strip():
            continue
        # Briefs commonly start with a title, followed by metadata and then ## TASK.
        if line.startswith('# ') and not headers:
            continue
        if re.match(r'^[A-Za-z][A-Za-z0-9_-]*:\s*', line):
            headers.append(line)
            continue
        break
    return '\n'.join(headers)


def land_lag_class(row):
    # Only metadata headers and actual changed files convey ownership. Instructions in prose do not.
    text = land_lag_headers(row.get('spec'))
    if (re.search(r'^(?:Ticket|Parent):\s*goodqa#(?:1049[5-9]|1050[01])\b', text, re.M | re.I)
            or re.search(r'^Security-review:\s*required\s*$', text, re.M | re.I)):
        return 'safety'
    guard = re.compile(r'(?:bin/[^/]*guard[^/]*|boxops/register-claude-hooks\.py|bin/rq[^/]*|'
                       r'config/finish-gate\.json|bin/lane-registry-hook\.py|bin/cause-receipt-guard\.py|'
                       r'bin/land_lag_cap\.py|bin/goodqa_liveness\.py|bin/finish_gate\.py)')
    paths = row.get('paths')
    if any(isinstance(path, str) and guard.fullmatch(path) for path in (paths if isinstance(paths, list) else [])):
        return 'safety'
    return 'unknown' if row.get('paths_unreadable') else 'other'


def land_lag_proven(row):
    if (row.get('identity_inconsistent') or row.get('author_identity_complete') is False
            or (row.get('source') == 'runner' and row.get('author_identity_complete') is not True)):
        return False
    p = row.get('proof') or {}
    if not isinstance(p, dict):
        return False
    sha = p.get('landed_sha')
    if not (isinstance(sha, str) and SHA40.fullmatch(sha) and row.get('proof_landed') is True
            and row.get('proof_contains_candidate') is True):
        return False
    author = row.get('author')
    author = author.strip().casefold() if isinstance(author, str) else ''
    activation, refusal = p.get('activation'), p.get('negative_control')
    if not author or not isinstance(activation, dict) or not isinstance(refusal, dict):
        return False
    for evidence in (activation, refusal):
        try:
            observed = ts(evidence.get('observed_at'))
        except (ValueError, OverflowError):
            return False
        if not (evidence.get('sha') == sha and observed
                and all(isinstance(evidence.get(k), str) and evidence[k].strip() for k in ('observer', 'evidence'))):
            return False
    authors = {author} | {str(x).strip().casefold() for x in row.get('author_aliases') or []}
    return (str(refusal.get('observer') or '').strip().casefold() not in authors and refusal.get('refused') is True
            and isinstance(refusal.get('command'), str) and bool(refusal['command'].strip()) and type(refusal.get('exit_code')) is int
            and refusal['exit_code'] > 0)


def land_lag_timestamp(value):
    try:
        return ts(value)
    except (ValueError, TypeError, OverflowError):
        return 0.0


def land_lag_same_candidate(previous, current):
    """Require positive stable identity, with no conflicting identity or discovery locator."""
    stable = ('task_id', 'branch', 'candidate_sha', 'captured_sha')
    if any(previous.get(field) and current.get(field) and previous[field] != current[field]
           for field in stable + ('worktree', 'base')):
        return False
    return any(previous.get(field) and previous[field] == current.get(field) for field in stable)


def land_lag_author_aliases(*rows):
    # Retain every candidate-bound author identity, including aliases first learned by enrichment.
    aliases = set()
    for row in rows:
        for value in [row.get('author')] + list(row.get('author_aliases') or []):
            if isinstance(value, str) and value.strip():
                aliases.add(value.strip().casefold())
    return sorted(aliases)


def land_lag_findings(reading, st, cfg, now):
    """Stable run/scenario keys preserve first READY across reassignment and failed/missing reads.

    Every discovered identity starts with conservative debt. Only its own positively read ordinary
    ownership and landing, or its own independent activation/refusal completion proof, can resolve it.
    Confirmed safety ownership stays bound to the original candidate across metadata changes.
    """
    cache = st.setdefault('land_lag', {})
    resolved = {}
    for row in reading.get('rows') or []:
        key = row.get('key')
        if not key:
            continue
        source_key = row.get('source_key') or key
        candidate = row.get('candidate_sha')
        old = cache.get(key)
        unclassified_identity = not (isinstance(candidate, str) and SHA40.fullmatch(candidate))
        if unclassified_identity and not row.get('deferred'):
            row = dict(row, identity_unreadable=True, paths_unreadable=True)
        # Locators separate observations, but only stable identity can establish continuity.
        # A reused tree/base never grants a replacement authority over unidentified debt.
        locator = lambda value: tuple(value.get(field) for field in ('task_id', 'branch', 'captured_sha', 'worktree', 'base'))
        provisional = source_key + '@pending'
        if ((row.get('deferred') or unclassified_identity) and old
                and (old.get('candidate_sha') or locator(old) != locator(row))):
            key, old = provisional, cache.get(provisional)
            if old and locator(old) != locator(row):
                import hashlib
                key = provisional + '-' + hashlib.sha256(repr(locator(row)).encode()).hexdigest()[:16]
                old = cache.get(key)
        elif not row.get('deferred') and not row.get('retained') and not unclassified_identity:
            for pending_key, pending in list(cache.items()):
                if ((pending.get('source_key') or pending_key) == source_key
                        and not pending.get('candidate_sha')
                        and land_lag_same_candidate(pending, row)):
                    key, old = pending_key, pending
                    break
        if candidate:
            matching = next((k for k, value in cache.items()
                             if (value.get('source_key') or k) == source_key
                             and value.get('candidate_sha') == candidate), None)
            if matching:
                key, old = matching, cache[matching]
            elif old and ((old.get('candidate_sha') and old['candidate_sha'] != candidate)
                          or (old.get('identity_unreadable') and not land_lag_same_candidate(old, row))
                          or (not old.get('candidate_sha') and not land_lag_same_candidate(old, row))):
                # Keep A at its stable key for finishing adapters; B receives its own debt.
                key = source_key + '@' + candidate
                old = cache.get(key)
        if old and old.get('identity_unreadable') and unclassified_identity:
            continue  # another unidentified observation cannot replace this retained identity
        classification = 'unknown' if row.get('identity_inconsistent') else land_lag_class(row)
        if (old and old.get('class') == 'safety'
                and (row.get('paths_unreadable') or land_lag_class(old) == 'safety')):
            classification = 'safety'  # original positive ownership is immutable until own completion proof
        if old and old.get('identity_unreadable') and not land_lag_same_candidate(old, row):
            classification = 'unknown'
        if classification == 'other' and row.get('landed') is True and not row.get('identity_inconsistent'):
            cache.pop(key, None)
            resolved[key] = 'candidate landed on origin/main'
            continue
        aliases = land_lag_author_aliases(old or {}, row)
        proof_row = dict(row, author=(old or {}).get('author') or row.get('author'),
                         author_aliases=aliases)
        checked_candidate = row.get('gate_candidate_sha') or candidate
        if (land_lag_proven(proof_row) and candidate == checked_candidate
                and (not old or not old.get('candidate_sha') or old['candidate_sha'] == candidate)):
            cache.pop(key, None)
            resolved[key] = 'completion proof: landed, activated and independently refused'
            continue
        first = min(land_lag_timestamp(row.get('ready_at')) or now, land_lag_timestamp((old or {}).get('first_ready_at')) or now)
        record = dict(old or {}, **row)
        record.update(key=key, source_key=source_key)
        if not unclassified_identity and old and land_lag_same_candidate(old, row):
            record.pop('identity_unreadable', None)
        if old and old.get('class') == 'safety' and land_lag_class(old) == 'safety':
            fields = ('spec',) if old.get('paths_unreadable') else ('spec', 'paths', 'paths_unreadable', 'base')
            for field in fields:
                if field in old:
                    record[field] = old[field]
        if old:
            record['author'] = old.get('author') or row.get('author')
        record['author_aliases'] = aliases
        record.update(first_ready_at=iso(first), **{'class': classification})
        if classification == 'unknown':
            # Saturating diagnostic; each pass still receives the collector's bounded fair retry.
            record['reclassification_attempts'] = min(3, int((old or {}).get('reclassification_attempts', 0)) + 1)
            record['needs_reclassification'] = True
        else:
            record.pop('reclassification_attempts', None)
            record.pop('needs_reclassification', None)
        cache[key] = record
    discovered = reading.get('discovered')
    present = set(discovered) if isinstance(discovered, list) else None
    # Presence is judged PER SOURCE (owner receipts and runner pin queues are separate globs; red-team F2) and the
    # verdict is STICKY on the record (`undiscovered`; red-team delta R1/F1), for EVERY record before any age or class
    # exit, so the breaker always counts only lanes not yet marked:
    # - a source that discovered nothing is no evidence this read (a wrong HOME, an unreadable or missing directory);
    # - a lane missing from a source with evidence is marked at once, unless more than half (minimum
    #   land_lag_stale_breaker_min) of that source's unmarked lanes vanish in the same read: a mass vanish is marked
    #   only after the same lanes stay missing for land_lag_stale_confirm_seconds (the breaker holds, then recovers);
    # - a lane discovered again clears both marks. A read with no evidence leaves every mark as it was.
    def source_of(record, key):
        return 'runner' if (record.get('source_key') or key).startswith('runner/') else 'owner'
    if present is not None:
        breaker_min = int(cfg.get('land_lag_stale_breaker_min', 5))
        confirm = float(cfg.get('land_lag_stale_confirm_seconds', 1800))
        for key, record in cache.items():
            if (record.get('source_key') or key) in present:
                record.pop('undiscovered', None)
                record.pop('missing_since', None)
                record.pop('missing_held', None)
        for source in ('runner', 'owner'):
            if not any(('runner' if k.startswith('runner/') else 'owner') == source for k in present):
                continue
            active = [(k, r) for k, r in cache.items() if source_of(r, k) == source and not r.get('undiscovered')]
            gone = [(k, r) for k, r in active if (r.get('source_key') or k) not in present]
            mass = len(gone) > max(breaker_min, len(active) // 2)
            for key, record in gone:
                try:
                    since = float(record.get('missing_since'))
                except (TypeError, ValueError):            # absent or malformed persisted value: start the clock now
                    since = now
                record['missing_since'] = since
                if mass:
                    record['missing_held'] = True          # a held vanish stays held even if new lanes shrink the ratio
                if not record.get('missing_held') or now - since >= confirm:
                    record['undiscovered'] = ('lane %s no longer discovered: superseded, cancelled or deleted'
                                              % (record.get('source_key') or key))
    runner_states = reading.get('runner_states') if isinstance(reading.get('runner_states'), dict) else {}
    findings = []
    unresolved = ['%s: ownership unknown; needs reclassification (bounded fair retry, attempt %s/3)' %
                  (key, row.get('reclassification_attempts', 0))
                  for key, row in sorted(cache.items()) if row.get('class') == 'unknown']
    if reading.get('errors') or unresolved:
        findings.append(dict(cls='land-lag-unreadable', title='ready-work landing detector incomplete',
                             lines=list(reading.get('errors') or []) + unresolved, remedies=[]))
    for key, record in sorted(cache.items()):
        age = max(0, (now - land_lag_timestamp(record['first_ready_at'])) / 60)
        if record['class'] == 'unknown':
            record.update(age_minutes=round(age, 1), clear_criteria=LAND_LAG_CLEAR + '; or own successful changed-path classification to other')
            continue  # Unresolved state is not a confirmed permanent landing-lag ticket.
        criteria = LAND_LAG_CLEAR if record['class'] == 'safety' else 'candidate SHA on origin/main'
        record.update(age_minutes=round(age, 1), clear_criteria=criteria)
        limit = 10 if record['class'] == 'safety' else float(cfg.get('land_lag_minutes', 60))
        if age < limit:
            continue
        finding = (dict(cls='land-lag:' + key, title='%s %s ready but not activated for %.0f min' % (record['class'], key, age),
                             lines=['first READY %s; candidate %s; landed %s' % (record['first_ready_at'], record.get('candidate_sha'), record.get('landed')),
                                    'clear only with ' + criteria,
                                    ('ADVISORY ONLY: land_lag_cap is NOT wired into admission (signed-but-unlanded; '
                                     'enforcement tracked in goodqa#10796) -- this does not cap admission today; never auto-land'
                                     if record['class'] == 'safety' else 'ordinary lag alert; never auto-land')] +
                                   (['collector: ' + '; '.join(reading['errors'])] if reading.get('errors') else []), remedies=[],
                        severity='high' if record['class'] == 'safety' else 'normal', minutes=round(age, 1)))
        task = runner_states.get(record.get('task_id')) if record.get('source') == 'runner' else None
        # A SAFETY (or unknown-ownership) record is not cleared by landing or by its lane going quiet (it needs landed +
        # activation + an independent refusal; red-team F1): its alert closes only when the candidate can no longer land.
        guarded = record['class'] in ('safety', 'unknown')     # unknown ownership may be safety: same rule
        done = RUNNER_GONE_STATES if guarded else RUNNER_DONE_STATES
        # Staleness is STICKY (red-team delta R1): `undiscovered` (marked above) and `runner_done` are set only on
        # positive evidence and cleared only on positive evidence the other way (rediscovery; a fresh non-final runner
        # state), so a read with no evidence can neither close a live alert nor reopen a correct close. A guarded
        # record keeps its `undiscovered` mark (it leaves the breaker count) but the mark never closes its alert.
        if isinstance(task, dict):
            if task.get('state') in done or task.get('superseded_by'):
                record['runner_done'] = 'runner task %s is %s' % (record.get('task_id'), 'superseded by %s' % task['superseded_by']
                                                                   if task.get('superseded_by') else task.get('state'))
            else:
                record.pop('runner_done', None)
        why = (None if guarded else record.get('undiscovered')) or record.get('runner_done')
        if why:
            # The lane is superseded, cancelled or deleted (or can no longer land). The debt stays in the gate;
            # act() closes the ALERT within this pass (gq-clutter S1).
            finding['stale'] = why
        findings.append(finding)
    # A key that resolved this pass (ordinary landing, or completion proof) closes its open alert within the pass, not
    # after clear_seconds; emitted only when that alert exists, so a plain reading's findings are unchanged.
    for key, why in sorted(resolved.items()):
        alerts = st.get('alerts') or {}
        # The family alert, or a legacy per-lane alert that act() has not consolidated yet (its first pass).
        if any(x and x.get('ref') and not x.get('cleared')
               for x in (alerts.get(alert_key('land-lag:' + key)), alerts.get('land-lag:' + key))):
            findings.append(dict(cls='land-lag:' + key, title='%s resolved' % key, lines=[why], remedies=[], stale=why))
    return findings


def load_land_lag(st, path=None):
    """The dedicated gate survives a reset of unrelated liveness timer state. Corruption is never overwritten healthy."""
    path = path or os.path.join(os.path.dirname(state_path()), 'land-lag.json')
    try:
        with open(path) as f:
            saved = json.load(f)
        if not isinstance(saved, dict) or not isinstance(saved.get('findings'), list):
            raise ValueError('expected findings list')
        for row in saved['findings']:
            if (not isinstance(row, dict) or not isinstance(row.get('key'), str) or not row['key']
                    or row.get('class') not in ('safety', 'other', 'unknown') or not land_lag_timestamp(row.get('first_ready_at'))):
                raise ValueError('invalid gate finding')
        st['land_lag'] = {row['key']: row for row in saved['findings']}
    except FileNotFoundError:
        if os.path.exists(os.path.join(os.path.dirname(path), 'land-lag.bootstrapped')):
            return 'land-lag state unreadable: missing after bootstrap'
    except (OSError, ValueError) as exc:
        return 'land-lag state unreadable: ' + str(exc)
    return None


def save_land_lag(st, now, path=None, errors=None):
    path = path or os.path.join(os.path.dirname(state_path()), 'land-lag.json')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = path + '.tmp.%s' % os.getpid()
    with open(temporary, 'w') as f:
        json.dump(dict(schema=1, checked_at=iso(now), findings=list((st.get('land_lag') or {}).values()),
                       complete=not bool(errors), clear_criteria=LAND_LAG_CLEAR), f, indent=1, sort_keys=True)
    os.replace(temporary, path)
    marker = os.path.join(os.path.dirname(path), 'land-lag.bootstrapped')
    with open(marker, 'a'):
        pass


# ------------------------------------------------------------------------------------------------ samples
# ------------------------------------------------------------------------------------------------ deploy lag (ruling 82)
WAVE_RUNNING = ('building', 'qualifying', 'baseline', 'deploying', 'verifying', 'scoped')
STATUS_GOOD = ('current', 'shipped', 'disabled', 'dry-run-qualified', 'settled')
SHA40 = re.compile(r'^[0-9a-f]{40}$')
WATCH_PRODUCT = {'optinrouter': 'optin'}


def live_from_status(rec):
    """The live sha a DEV ship timer's last pass record proves, or None: `current` means main was live at the check, `shipped`
    names the new live release (optin-ship: sha; timbar-preview-ship: main / live_after)."""
    rec = rec if isinstance(rec, dict) else {}
    if rec.get('outcome') not in ('current', 'shipped'):
        return None
    after = rec.get('live_after')
    for v in ((after.get('sourceSha') if isinstance(after, dict) else after), rec.get('main'), rec.get('sha')):
        if isinstance(v, str) and SHA40.match(v):
            return v
    return None


def merge_pages(text):
    """`gh api --paginate --jq` prints one JSON document per page: commits concatenated in order, files from every page."""
    dec, i, pages = json.JSONDecoder(), 0, []
    text = text.strip()
    while i < len(text):
        doc, j = dec.raw_decode(text, i)
        pages.append(doc)
        i = j
        while i < len(text) and text[i].isspace():
            i += 1
    if not pages:
        raise ValueError('empty compare output')
    out = dict(pages[0], commits=[], files=[])
    for pg in pages:
        out['commits'] += pg.get('commits') or []
        out['files'] += pg.get('files') or []
    return out


def reduce_compare(cmp, now, ignore, pushes=None):
    """GitHub compare live...main (reduced by gh --jq) -> the lag. Minutes count from the first push to main that put an unshipped
    commit on it (GitHub repository activity: when main became ahead of production). Without push records, from the oldest
    MAIN-LINE commit's committer time (first-parent from main's head; a branch's own commits can be days older, and a merge
    composed before it was pushed reads early)."""
    commits = cmp.get('commits') or []
    by = {c.get('sha'): c for c in commits}
    chain, cur = [], commits[-1].get('sha') if commits else None
    while cur in by and len(chain) <= len(commits):
        chain.append(by[cur])
        ps = by[cur].get('parents') or []
        cur = ps[0] if ps else None
    landed = min((ts(c.get('date')) for c in chain if ts(c.get('date'))), default=None)
    since_src, unshipped = 'main-line commit time', set(by)
    clock_push = None
    if pushes:
        mine = [x for x in pushes if x.get('after') in unshipped and ts(x.get('ts'))]
        # a push whose own files are known and all ignored (the deploy's chore(deploy) receipts) does not start the clock; a push
        # whose files were not read counts (conservative)
        product = [x for x in mine if 'files' not in x or any(not any(re.search(p, f) for p in ignore) for f in x['files'] or [])]
        if product:
            first = min(product, key=lambda x: ts(x['ts']))
            landed, clock_push = ts(first['ts']), first.get('after')
            since_src = 'first push of an unshipped product change to main'
            if all(x.get('after') in unshipped for x in pushes):
                since_src += ' (every listed push is unshipped: a lower bound)'
        elif mine:
            since_src = 'main-line commit time (every unshipped push read touches only ignored paths)'
    files = [f for f in cmp.get('files') or [] if isinstance(f, str)]
    product = [f for f in files if not any(re.search(p, f) for p in ignore)]
    capped = len(files) >= 300                          # GitHub lists at most 300 files: an unlisted rest may be product code
    ahead = int(cmp.get('ahead_by') or 0)
    return dict(clock_push=clock_push, pushes_seen=[x.get('after') for x in pushes or []],
                status=cmp.get('status'), ahead=ahead, since_source=since_src, behind=int(cmp.get('behind_by') or 0), mainline=len(chain),
                truncated=ahead > len(commits), main=commits[-1].get('sha') if commits else None, landed=landed,
                minutes=round((now - landed) / 60.0, 1) if landed else None, files=len(files),
                product_files=len(product) + (1 if capped and not product else 0))


def deploy_blockers(s, p, spec):
    lines = []
    if s.get('drain'):
        lines.append('install drain since %s (install %s)' % (iso(s['drain']['since']), s['drain'].get('install') or '?'))
    fleet = str(s.get('fleet_state') or '')
    if fleet and not fleet.startswith('running'):
        lines.append('fleet: %s' % C.cap(fleet, 160, tail=False))
    w = (s.get('ship_waves') or {}).get(p)
    if isinstance(w, dict) and w.get('stage') != 'shipped':
        stage = w.get('stage')
        label = ('ship qualifying' if stage == 'scoped' else 'deploy running') if stage in WAVE_RUNNING else 'ship refused or failed'
        quiet = (s.get('at') or 0) - ts(w.get('updated'))
        lines.append('%s: runner ship wave %s %s since %s (%s, retries %s) at %s: %s' % (
            label, w.get('id'), stage, w.get('started'),
            'no update for %.0f min' % (quiet / 60.0) if ts(w.get('updated')) and s.get('at') else 'updated %s' % w.get('updated'),
            w.get('retries'), w.get('sha'), C.cap(str(w.get('reason') or ''), 240, tail=False)))
    for key, inc in sorted((s.get('ship_watch') or {}).items()):
        if not isinstance(inc, dict):
            continue
        if WATCH_PRODUCT.get(inc.get('product'), inc.get('product')) == p and not str(key).startswith('runner:'):
            lines.append('ship-watch %s: %s since %s: %s' % (inc.get('source'), inc.get('kind'), str(inc.get('since') or '')[:19],
                                                            C.cap(inc.get('reason') or '', 200, tail=False)))
    rec = ((s.get('deploy_lag') or {}).get(p) or {}).get('status_record')
    if isinstance(rec, dict) and rec.get('outcome') and rec.get('outcome') not in ('current', 'shipped', 'settled'):
        lines.append('%s: %s last pass %s at %s: %s' % ('ship disabled' if rec.get('outcome') in ('disabled', 'dry-run-qualified')
                                                       else 'ship refused', spec.get('status_name') or p, rec.get('outcome'),
                                                                  rec.get('finished') or rec.get('finished_at') or '?',
                                                                  C.cap(rec.get('reason') or '', 200, tail=False)))
    return lines


def deploy_lag_findings(s, cfg):
    mode = cfg.get('deploy_lag_mode', 'warn')
    if mode == 'off':
        return []
    out, limit = [], float(cfg.get('deploy_lag_minutes', 60))
    specs = cfg.get('deploy_lag_products') or {}
    after = int(cfg.get('deploy_lag_unreadable_after', 3))
    for p, d in sorted((s.get('deploy_lag') or {}).items()):
        spec = specs.get(p) or {}
        if d.get('error') and int(d.get('failures') or 0) >= after:
            out.append(dict(cls='deploy-lag-unreadable:%s' % p, title='%s deploy lag unreadable for %d reads' % (p, d['failures']),
                            lines=['since %s: %s' % (iso(d.get('stale_since') or d.get('at') or 0), d['error']),
                                   'last good reading: %s' % ('live %s, %s commit(s) ahead' % (d['live'][:12], d.get('ahead'))
                                                              if d.get('live') else 'none')],
                            remedies=[], post=spec.get('release_ticket') if mode == 'enforce' else None, mode=mode))
        if not d.get('live') or not d.get('ahead') or not d.get('product_files') or d.get('minutes') is None or d['minutes'] <= limit:
            continue
        blockers = deploy_blockers(s, p, spec)
        if d.get('error'):                  # the source broke: the last good reading keeps the alert (never a false "recovered")
            blockers = ['source unreadable since %s (%d failed read(s)): %s; this is the last good reading' % (
                iso(d.get('stale_since') or 0), int(d.get('failures') or 0), d['error'])] + blockers
        out.append(dict(cls='deploy-lag:%s' % p, title='%s main ahead of production by %d main-line commit(s) (%d total) for %.0f min' % (
            p, d.get('mainline') or 0, d['ahead'], d['minutes']),
                        lines=['live %s (%s); main %s; %d main-line commit(s)%s, %d product file(s) changed%s' % (
                                   (d.get('live') or '?')[:12], d.get('live_source'), (d.get('main') or '?')[:12], d.get('mainline') or 0,
                                   ' (more than the compare lists: minutes are a lower bound)' if d.get('truncated') else '',
                                   d.get('product_files') or 0, '; live is NOT on main (diverged by %d)' % d['behind'] if d.get('behind') else ''),
                               'main ahead of production since %s (%s)' % (iso(d['landed']), d.get('since_source') or '?')] +
                              (blockers or ['blocker: none known (no ship wave running or failing, no refused ship pass, the fleet '
                                            'running): the release owner deploys main now']),
                        remedies=[], post=spec.get('release_ticket') if mode == 'enforce' else None, mode=mode))
    return out


def live_sample(snap, cfg, lf_runs, refusals, now):
    rows = snap.get('rows') or {}
    merging = collections.Counter(r['product'] for r in rows.get('merging') or [])
    drain = None
    lf = (snap.get('last_fleet') or {})
    if lf.get('state') == 'drain':
        m = INSTALL.search(lf.get('reason') or '')
        drain = dict(since=ts(lf['ts']), reason=lf.get('reason'), install=m.group(1)[:12] if m else None)
    holders = [r['id'] for k in ('running', 'reviewing') for r in rows.get(k) or []] if drain else []
    last_lf = next((r for r in reversed(lf_runs) if r['end'] <= now), None)
    gq_rule, gq_cls = refusals_by_rule(refusals, now - 600)
    counts = snap.get('counts') or {}
    return dict(at=now, floor=cfg.get('floor'), running=counts.get('running', 0), queued=counts.get('queued', 0), merging=dict(merging),
                last_merge={k: ts(v) for k, v in (snap.get('last_merge') or {}).items()}, drain=drain, holders=holders,
                fleet_state=snap.get('fleet'), lane_floor=last_lf, gq_refusals=gq_cls, gq_refused=gq_rule, broker=snap.get('broker'),
                grade_failed=snap.get('grade_failed') or [], limit_pauses=len(snap.get('limit_pauses') or []),
                train_verdicts=snap.get('train_verdicts') or [], train_running=snap.get('train_running') or [],
                last_grade_pass={k: ts(v) for k, v in (snap.get('last_grade_pass') or {}).items()},
                merge_trains=snap.get('merge_trains') or {}, ship_waves=snap.get('ship_waves') or {},
                **{k: snap[k] for k in ('services', 'services_error') if k in snap})


def replay_samples(lines, repo_of, cfg, lf_runs, refusals, since, until, step=120, train_verdicts=None, merge_trains=None):
    """Samples every `step` s from the recorded timeline (events state/fleet lines from the start of the file, so the state counts
    are exact), the lane-floor journal and gq-queue refusals."""
    state, last_merge, drain, gf, grade_pass = {}, {}, None, [], {}
    prod = lambda task: repo_of.get(task) or next((p for pre, p in (('goodqa-', 'goodqa'), ('timbar-', 'timbar'), ('optin-', 'optin'))
                                                   if task.startswith(pre)), 'other')
    out, i, t = [], 0, since
    parsed = []
    for line in lines:
        m = STATE_LINE.match(line)
        if m:
            parsed.append(('s', ts(m.group(1))) + m.groups()[1:])
            continue
        f = FLEET_LINE.match(line)
        if f:
            parsed.append(('f', ts(f.group(1)), f.group(2), f.group(3)))
    parsed.sort(key=lambda x: x[1])
    while t <= until:
        while i < len(parsed) and parsed[i][1] <= t:
            e = parsed[i]
            if e[0] == 's':
                _, when, task, to, reason = e
                state[task] = to
                if to == 'merged':
                    last_merge[prod(task)] = when
                    if reason.startswith('GRADE PASS'):
                        grade_pass[prod(task)] = when
                elif to == 'grade-failed':
                    gf.append(dict(ts=iso(when), task=task, product=prod(task), reason=reason))
            else:
                _, when, fs, reason = e
                if fs == 'drain':
                    m = INSTALL.search(reason)
                    drain = dict(since=when, reason=reason, install=m.group(1)[:12] if m else None)
                elif fs == 'undrain':
                    drain = None
            i += 1
        c = collections.Counter(state.values())
        merging = collections.Counter(prod(k) for k, v in state.items() if v == 'merging')
        holders = [k for k, v in state.items() if v in ('running', 'reviewing')] if drain else []
        last_lf = next((r for r in reversed(lf_runs) if r['end'] <= t), None)
        if last_lf and t - last_lf['end'] > 900:
            last_lf = None                                 # no lane-floor record for this time (journal rotated)
        recent_ref = [r for r in refusals if t - 600 <= ts(r.get('ts')) <= t]
        gq_rule, gq_cls = refusals_by_rule(recent_ref, t - 600)
        out.append(dict(at=t, floor=cfg.get('floor'), running=c['running'], queued=c['queued'], merging=dict(merging),
                        last_merge=dict(last_merge), drain=drain, holders=sorted(holders)[:20], fleet_state='running',
                        lane_floor=last_lf, gq_refusals=gq_cls, gq_refused=gq_rule, broker=None,
                        grade_failed=[g for g in gf if t - ts(g['ts']) <= 3 * 3600], limit_pauses=0,
                        train_verdicts=[v for v in train_verdicts or [] if ts(v['ts']) <= t], train_running=[],
                        last_grade_pass=dict(grade_pass),
                        merge_trains=merge_trains or {}))
        t += step
    return out


# ------------------------------------------------------------------------------------------------ effects
LIVE_TREE = '/home/eric/repos/harness'
LIVE_GIT_DIR = '/home/eric/repos/harness-scratch.git'
AUTOCOMMIT_LOG = os.path.expanduser('~/.local/state/harness-autocommit.log')


_LOG_LINE = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?\s+(.*)$')
_LOG_RC = re.compile(r'^(\S+)\s+rc=(\d+)\b')                    # an autocommit entry: "<git dir> rc=<n> <commit subject>"; the subject is free text and is never searched
_LOG_ISSUE = re.compile(r'^(\S+)\s+(?:ERROR\b|WARN integrate upstream: (?!ff\b|ahead\b|merged\b))')       # a logged failure of that repo


def _log_kind(body):
    """'ok' | 'fail' | 'crash' | None for one log entry body (structure only: a commit subject saying ERROR is not a failure)."""
    if body.startswith('PRE-COMMIT HOOK CRASH'):                  # the hook writes the marker first; a commit subject that mentions it is just a subject
        return 'crash'
    m = _LOG_RC.match(body)
    if m:
        return 'ok' if int(m.group(2)) == 0 else 'fail'
    return 'fail' if _LOG_ISSUE.match(body) else None


def parse_autocommit_log(text, now, repo=None):
    """Pure: the autocommit log (UTC timestamps, one entry per line, git's own stderr lines between them, several repos sharing the file) -> dict(last_ok_age_s,
    last_fail_age_s, fail_since_age_s (the oldest failure AFTER the last success), crash_age_s (newest PRE-COMMIT HOOK CRASH, any repo: the hook logs no repo),
    after_ok (the text after the last success, only this repo's entries and the raw git lines that follow them)). With `repo` (a git dir) only that repo's
    entries count for ok/fail. refusals maps each path to count/first_ts/last_ts over the whole tail, across successes.
    Space-containing paths require the following rc=1 autocommit names to agree. An unparsable timestamp line is skipped, never fatal."""
    last_ok = last_fail = fail_since = crash = None
    keep, mine = [], True
    refusals, pending_spaces = {}, None

    def record_refusals(paths, when):
        for path in set(paths):
            entry = refusals.setdefault(path, dict(count=0, first_ts=when, last_ts=when))
            entry['count'] += 1
            entry['first_ts'] = min(entry['first_ts'], when)
            entry['last_ts'] = max(entry['last_ts'], when)

    lines = (text or '').splitlines()
    for ln in lines:
        m = _LOG_LINE.match(ln)
        if not m:
            if mine:
                keep.append(ln)                                       # a raw git/stderr line belongs to the entry before it
            continue
        try:
            t = calendar.timegm(time.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S'))
        except ValueError:
            continue
        body = m.group(2)
        kind = _log_kind(body)
        if kind == 'crash':
            crash = t
        mine = (not repo) or body.startswith(repo + ' ') or kind == 'crash'
        if not mine or 'CLEARED stale index.lock' in body:
            continue
        # Match the producer's entry, never a free-text commit subject.
        refusal = re.fullmatch(r'\S+ pre-commit guards left uncommitted: (\d+) path\(s\): (.+)', body)
        if refusal:
            paths = refusal.group(2).split(', ')
            if len(paths) == min(int(refusal.group(1)), 20) and all(paths):
                if any(' ' in path for path in paths):
                    pending_spaces = (paths, t)
                else:
                    record_refusals(paths, t)
        elif _LOG_RC.match(body):
            if pending_spaces:
                paths, when = pending_spaces
                companion = re.fullmatch(r'\S+ rc=1 autocommit: (\d+) file\(s\) (.+)', body)
                if companion and int(companion.group(1)) >= len(paths) and companion.group(2) == ' '.join(paths):
                    record_refusals(paths, when)
            pending_spaces = None
        if kind == 'ok':
            last_ok, fail_since, keep = t, None, []
        else:
            keep.append(ln)
            if kind in ('fail', 'crash'):
                last_fail = t
                fail_since = fail_since or t
    age = lambda t: None if t is None else max(0.0, now - t)
    return dict(last_ok_age_s=age(last_ok), last_fail_age_s=age(last_fail), fail_since_age_s=age(fail_since), crash_age_s=age(crash), after_ok='\n'.join(keep), refusals=refusals)


def _classify_text(t):
    if re.search(r"Unable to create '[^']*[/\\]index\.lock': File exists", t, re.I) and not re.search(r'another git process seems to be running', t, re.I):
        return 'stale-index-lock'
    if re.search(r"index\.lock.*Permission denied|Permission denied.*index\.lock", t, re.I):
        return 'index-lock-permission'
    if re.search(r'another git process seems to be running', t, re.I):
        return 'git-writer-busy'
    if re.search(r'PRE-COMMIT HOOK CRASH|UnicodeDecodeError', t):
        return 'pre-commit-crash'
    if re.search(r'HARNESS-CHECK refused|OLD-PATH GUARD refused|pre-commit guards left uncommitted', t, re.I):
        return 'guard-refusal'
    if re.search(r'integrate upstream: dirty', t):
        return 'integrate-dirty'
    if re.search(r'master\s*->\s*main[^\n]*(non-fast-forward|rejected)|\[rejected\]\s+master\s*->\s*main', t):
        return 'push-rejected'
    return 'unknown'


def classify_autocommit_log(tail):
    """Pure: the cause of an autocommit stall from the log text AFTER the last success. The NEWEST evidence wins: lines are examined from the newest backwards, each
    together with the line after it (git's lock error spans two lines); a self-heal line is not a cause."""
    lines = [x for x in (tail or '').splitlines() if 'CLEARED stale index.lock' not in x][-200:]
    for i in range(len(lines) - 1, -1, -1):
        c = _classify_text('\n'.join(lines[i:i + 2]))
        if c != 'unknown':
            return c
    return 'unknown'


AUTOCOMMIT_HINT = {
    'stale-index-lock': 'a zero-byte index.lock with no holder blocks every git write; the autocommit clears a verified-stale one itself; by hand: confirm 0 bytes, > 5 min old, `fuser` empty, then rm that one file',
    'pre-commit-crash': 'a staged file crashes the pre-commit hook: list it with `git --git-dir=%s diff --cached --name-only`, store it as text (base64) and unstage; the hook now fails open per guard and logs a PRE-COMMIT HOOK CRASH line' % LIVE_GIT_DIR,
    'index-lock-permission': 'index.lock exists but git cannot create or replace it (permissions or ownership of the git dir): fix the ownership, do not delete anything',
    'git-writer-busy': 'another git process is running in the live tree (an active writer, not a stale lock): wait; if it never ends, find the process',
    'unpushed-commits': 'local-only commits stayed unpushed: the push is failing or never ran (a non-fast-forward, a remote that is down); merge master with origin/main in an isolated worktree and publish under the lock',
    'guard-refusal': 'the harness quality gate refused an added file (the log names the path); for an HC001 backup copy, history is git: remove the copy, preserving it on a preserve/<topic> branch first if its bytes are not in git; liveness performs no remedy',
    'integrate-dirty': 'the upstream integrate refuses a dirty tree: see why the commit does not complete (log lines above)',
    'push-rejected': 'pushes are rejected non-fast-forward: merge master with origin/main in an isolated worktree and publish under the lock (AGENTS.md DRIFT rule)',
    'unknown': 'read ~/.local/state/harness-autocommit.log from the first failure',
}


def service_findings(sample, st, cfg):
    """Read-only managed-service alerts; act owns ticket cooldown and recovery."""
    if sample.get('services_error') or not isinstance(sample.get('services'), dict):
        return [dict(cls='service-unknown', title='managed service collection UNKNOWN',
                     lines=[str(sample.get('services_error') or 'services missing from remote snapshot')], remedies=[])]
    out = []
    need = int(cfg.get('service_fail_runs', 4))
    days = cfg.get('service_inert_days', 7)
    for name, service in sorted(sample['services'].items()):
        if service.get('enabled') is not True:
            continue
        ends = service.get('ends') or []  # newest first, bounded by the collector
        consecutive = []
        for end in ends:
            if end.get('result') != 'fail':
                break
            consecutive.append(end)
        if len(consecutive) >= need:
            reason = consecutive[0].get('reason') or ''
            message = reason
            if not reason.strip() or re.search(r'exit status \d+:\s*$', reason):
                message += ' (blank reason: the worker gave no message; check the dev2 journal for oom-kill)'
            out.append(dict(cls='service-failing:' + name, title='managed service %s: %d consecutive failed runs' % (name, len(consecutive)),
                            lines=['%d consecutive failures; first %s; last %s; last ok %s' %
                                   (len(consecutive), consecutive[-1]['ts'], consecutive[0]['ts'], service.get('last_ok') or 'never'),
                                   'newest reason: ' + message], remedies=[]))
        actions = service.get('actions') or {}
        if (service.get('mode') == 'warn' and sum(actions.values()) >= int(cfg.get('service_inert_min_actions', 50))
                and not any(actions.get(outcome, 0) for outcome in ('applied', 'spawned', 'escalated'))):
            out.append(dict(cls='service-inert:' + name, title='%s: only previews for %s days (warn mode)' % (name, days),
                            lines=['%d action lines in the last %s days; outcomes %s; lifetime total %s' %
                                   (sum(actions.values()), days, json.dumps(actions, sort_keys=True), service.get('actions_total', 0)),
                                   'BUG-BRIEFER.md: before switching bug-briefer to enforce, all 9 enforce-gate tickets '
                                   'goodqa#10939-#10947 must be closed and their fixes landed; the loaded config must set enforce_allowed: true. '
                                   'Liveness only alerts; it never switches service mode.'], remedies=[]))
    return out


def autocommit_findings(s, st, cfg):
    """Pure: findings from sample['autocommit'] (Effects.autocommit_state). The autocommit runs from tool-call hooks, so a quiet fleet leaves timer-written files
    uncommitted and the live tree behind without any stall: a stall needs EVIDENCE OF FAILED ATTEMPTS in the autocommit log for this repo (a failure with no
    success since) persisting `autocommit_stall_minutes`, by the log's own timestamps OR by our own observation clock (the log tail is bounded, so a wedge older
    than the tail is still seen every pass), while work is pending; or repeated per-path guard refusals spanning the hold
    across successes, with recent evidence and pending work; or a verified-stale zero-byte index.lock beside pending work. A fresh PRE-COMMIT HOOK CRASH (a
    guard bypassed) is reported on its own, even when the git state cannot be read. Unreadable state is a finding after the hold, never all-clear."""
    ac = s.get('autocommit')
    if not ac:
        return []
    at, need = s['at'], float(cfg.get('autocommit_stall_minutes', 10)) * 60
    out = []
    lg = ac.get('log') or {}
    crash = lg.get('crash_age_s')
    if crash is not None and crash <= float(cfg.get('autocommit_crash_report_minutes', 60)) * 60:
        out.append(dict(cls='precommit-hook-crashed', title='a pre-commit guard CRASHED %.0f min ago and failed open (a staged path went unchecked)' % (crash / 60.0), lines=[
            'the hook logs PRE-COMMIT HOOK CRASH and lets the commit through (goodqa#11526): find the crash line in ~/.local/state/harness-autocommit.log, the staged file, and fix the guard',
            'log tail: %s' % C.cap((ac.get('log_tail') or '(empty)').replace('\n', ' | '), 600)], remedies=[]))
    if ac.get('error'):
        held = _held(st, 'autocommit-unreadable', True, at, need)
        if held:
            out.append(dict(cls='autocommit-stalled', title='autocommit state unreadable: %s' % C.cap(str(ac['error']), 120), lines=[
                'the live tree could not be inspected for %.0f min (%s)' % ((at - st['since']['autocommit-unreadable']) / 60.0, ac['error'])], remedies=[]))
        return out
    _held(st, 'autocommit-unreadable', False, at, need)
    dirty, ahead, behind = int(ac.get('dirty') or 0), ac.get('ahead'), bool(ac.get('behind'))
    pending = dirty > 0 or ahead is None or ahead > 0
    lock = ac.get('lock') or {}
    stale_lock = bool(lock.get('exists')) and not lock.get('size') and not lock.get('holder') and float(lock.get('age_s') or 0) > max(300.0, need)
    fs, lf, lo = lg.get('fail_since_age_s'), lg.get('last_fail_age_s'), lg.get('last_ok_age_s')
    recent_fail = lf is not None and lf <= need and (lo is None or lo > lf)             # a failure in the last hold window with no success since
    observed = _held(st, 'autocommit-failing', recent_fail and (pending or behind), at, need)
    failing = recent_fail and (pending or behind) and ((fs is not None and fs >= need) or observed)
    oldest = ac.get('ahead_oldest') or ''
    if st.get('ahead_oldest') != oldest:                                               # a different oldest unpushed commit = the previous one was published: restart the clock
        st['ahead_oldest'] = oldest
        st['since'].pop('autocommit-ahead', None)
    stuck_ahead = _held(st, 'autocommit-ahead', bool(oldest), at, need)      # the SAME commit stays unpushed (the async push errors carry no timestamps); an unknown ahead alone is not a stall (a quiet tree behind a moved origin is normal)
    persistent_refusals = {
        path: evidence for path, evidence in (lg.get('refusals') or {}).items()
        if evidence['count'] >= int(cfg.get('autocommit_refusal_min', 20))
        and evidence['last_ts'] - evidence['first_ts'] >= need
        and 0 <= at - evidence['last_ts'] <= need
    }
    refused = bool(persistent_refusals) and (pending or behind)
    if refused or failing or stuck_ahead or (stale_lock and (dirty > 0 or behind)):
        cause = classify_autocommit_log(lg.get('after_ok') or '')                      # never the raw tail: a success line's subject must not decide the cause
        if refused:
            cause = 'guard-refusal'
        if stale_lock and cause == 'unknown':
            cause = 'stale-index-lock'
        if stuck_ahead and cause == 'unknown':
            cause = 'unpushed-commits'
        lock_line = ('index.lock: %d bytes, %.0f s old, %s' % (lock.get('size', 0), lock.get('age_s', 0), 'HELD by pid %s' % lock['holder'] if lock.get('holder') else 'no holder')
                     if lock.get('exists') else 'no index.lock')
        title = 'live tree autocommit stalled (%s)' % cause
        work = '%d uncommitted, %s local-only commit(s), %s' % (
            dirty, '?' if ahead is None else ahead, 'behind origin/main' if behind else 'not behind')
        if cause != 'guard-refusal':
            title += ': ' + work
        out.append(dict(cls='autocommit-stalled', title=title, lines=[
            'cause (from the autocommit log): %s: %s' % (cause, AUTOCOMMIT_HINT[cause]),
            '%s; failing for %s, last success %s ago' % (lock_line, '%.0f min' % (fs / 60.0) if fs is not None else 'at least %.0f min (observed)' % (need / 60.0),
                                                          '%.0f min' % (lo / 60.0) if lo is not None else 'never in the log window'),
            'log tail: %s' % C.cap((ac.get('log_tail') or '(empty)').replace('\n', ' | '), 600)] + [
            'guard-refusal path: %s; count: %d; first: %s; last: %s' % (path, e['count'], iso(e['first_ts']), iso(e['last_ts']))
            for path, e in sorted(persistent_refusals.items())] + ([work] if cause == 'guard-refusal' else []), remedies=[]))
    return out


# ------------------------------------------------------------------------------------------------ bounded host health (live only)
def health_unit(name):
    return isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.@:-]+\.(service|timer|scope|socket|mount|path|slice|target|device|swap|automount)', name) is not None and not name.startswith('-')


def health_path(path):
    return (isinstance(path, str) and path.startswith(('/', '~/')) and
            '..' not in path.split('/') and '\x00' not in path and '\n' not in path)


def health_scrub(text, limit=300):
    # Scrub BEFORE truncating, so a credential spanning the limit cannot leak a prefix.
    text = re.sub(r'(?i)(bearer\s+|(?:token|password|passwd|secret|api[_-]?key)\s*[=:]\s*)[^\s,;]+', r'\1[REDACTED]', str(text))
    text = re.sub(r'(?i)(?:sk-|gh[pousr]_|github_pat_)[A-Za-z0-9_-]+|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[REDACTED]', text)
    text = re.sub(r'(https?://)[^/\s:@]+:[^@\s]+@', r'\1[REDACTED]@', text)
    return text if len(text) <= limit else text[:limit-12] + ' [truncated]'


def collect_host_health(spec, budget, run=None, clock=None):
    """Self-contained source sent over the existing dev2 helper; argv only, one deadline."""
    import os
    import stat
    import subprocess
    import time
    clock = clock or time.monotonic
    deadline = clock() + budget

    def command(argv):
        left = deadline - clock()
        if left <= 0:
            raise TimeoutError('host health deadline')
        r = (run or subprocess.run)(argv, capture_output=True, text=True, errors='replace', timeout=left,
                                    env=dict(os.environ, LC_ALL='C', SYSTEMD_COLORS='0', SYSTEMD_PAGER='cat'))
        if r.returncode:
            raise OSError('host health command failed: ' + argv[0])
        return r.stdout

    try:
        result = dict(units=[], dirs={}, disks={}, unparsed=[], failed_lines=0, failed_lines_by_scope={})
        for user in (True, False):
            scope = ['--user'] if user else []
            output = command(['systemctl', *scope, '--failed', '--no-legend', '--plain'])
            lines = [line for line in output.splitlines() if line.strip()]
            result['failed_lines_by_scope']['user' if user else 'system'] = len(lines)
            result['failed_lines'] += len(lines)
            for line in lines:
                parts = line.split()
                if not parts:
                    continue
                if len(parts) < 4 or not health_unit(parts[0]):
                    result['unparsed'].append(health_scrub(line))
                    continue
                unit = parts[0]
                props = command(['systemctl', *scope, 'show', unit, '--property=ActiveState,SubState,Result,ExecMainStatus,InactiveEnterTimestamp'])
                props = dict(x.split('=', 1) for x in props.splitlines() if '=' in x)
                if 'ActiveState' not in props:
                    raise ValueError('missing ActiveState')
                journal = command(['journalctl', *scope, '-u', unit, '-n', '40', '--output=cat', '--no-pager'])
                tail = health_scrub('\n'.join(journal.strip().splitlines()[-40:]), limit=4096)
                tail = tail.encode('utf-8')[:4096].decode('utf-8', errors='ignore')
                result['units'].append(dict(unit=unit, user=user, active=props['ActiveState'], sub=props.get('SubState', parts[3]),
                                            Result=props.get('Result', ''), ExecMainStatus=props.get('ExecMainStatus', ''),
                                            InactiveEnterTimestamp=props.get('InactiveEnterTimestamp', ''),
                                            journal=health_scrub(journal.strip().splitlines()[-1] if journal.strip() else ''),
                                            journal_tail=tail or 'no journal entries (rotated)'))
        for directory in spec.get('output_dirs', []):
            path = directory['path']
            if not health_path(path):
                raise ValueError('invalid output path')
            entries = []
            try:
                with os.scandir(os.path.expanduser(path)) as listing:
                    for entry in listing:
                        if clock() >= deadline:
                            raise TimeoutError('host health deadline')
                        if len(entries) >= 500:
                            raise ValueError('output listing exceeds 500 entries')
                        info = entry.stat(follow_symlinks=False)
                        kind = 'file' if stat.S_ISREG(info.st_mode) else ('dir' if stat.S_ISDIR(info.st_mode) else 'other')
                        entries.append(dict(name=entry.name, size=info.st_size, mtime=info.st_mtime, type=kind))
            except FileNotFoundError:
                # Missing output directory is a known empty directory, not a read failure.
                entries = []
            result['dirs'][path] = entries
        for fs in spec.get('filesystems', []):
            if not health_path(fs):
                raise ValueError('invalid filesystem path')
            rows = command(['df', '-Pk', '--', os.path.expanduser(fs)]).splitlines()
            fields = rows[-1].split() if len(rows) >= 2 else []
            if len(fields) < 6:
                raise ValueError('invalid df reading')
            total, used, free = map(int, fields[1:4])
            if total <= 0 or min(used, free) < 0:
                raise ValueError('invalid df sizes')
            result['disks'][fs] = dict(total_kb=total, used_kb=used, free_kb=free)
        return result
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
        return dict(error=type(exc).__name__ + ': host health unknown')


def stop_health_timer(service, timer, user, budget, run=None):
    """Re-read the service immediately before the only write: stopping its configured timer."""
    import subprocess
    import time
    if not health_unit(service) or not service.endswith('.service') or not health_unit(timer) or not timer.endswith('.timer'):
        return 2, 'invalid service/timer'
    deadline = time.monotonic() + budget
    scope = ['--user'] if user else []
    try:
        args = dict(capture_output=True, text=True)
        r = (run or subprocess.run)(['systemctl', *scope, 'show', service, '--property=ActiveState', '--value'],
                                    timeout=max(0.001, deadline-time.monotonic()), **args)
        if r.returncode or r.stdout.strip() != 'failed':
            return 2, 'service is not confirmed failed; timer unchanged'
        r = (run or subprocess.run)(['systemctl', *scope, 'stop', timer],
                                    timeout=max(0.001, deadline-time.monotonic()), **args)
        return r.returncode, 'timer stop succeeded' if r.returncode == 0 else 'timer stop failed'
    except (OSError, subprocess.SubprocessError):
        return 2, 'timer stop unknown/failed'


def host_health_findings(readings, st, cfg, now):
    """Successful samples advance hysteresis; persistent unknown raises its own census alarm."""
    cache = st.setdefault('host_health', {})
    policy = cfg.get('host_health', {})
    failed_policy = policy.get('failed_units', {})
    out = []
    for host, reading in readings.items():
        if host not in ('dev', 'dev2'):
            continue
        state = cache.setdefault(host, dict(units={}, findings={}, disks={}))
        unknown_cls = 'host-health-unknown:' + host
        if not reading or reading.get('error'):
            state['unknown_count'] = state.get('unknown_count', 0) + 1
            state['unknown_clean'] = 0
            if state['unknown_count'] >= int(cfg.get('unit_census_unknown_samples', 3)):
                error_type = str((reading or {}).get('error', '')).split(':', 1)[0]
                if not re.fullmatch(r'[A-Za-z]+Error', error_type):
                    error_type = 'UnknownError'
                state['findings'][unknown_cls] = dict(cls=unknown_cls, title='unit census unreadable on ' + host,
                    lines=[error_type], remedies=[])
            out.extend(dict(f, remedies=[]) for f in state['findings'].values())
            for cls, alert in st['alerts'].items():
                if (cls.startswith(tuple(k + ':' + host + ':' for k in ('unit-failing', 'output-leak', 'disk-fill-eta'))) or
                        cls in ('host-health-unknown:' + host, 'host-health-unparsed:' + host, 'host-health-census:' + host)):
                    alert.pop('absent_since', None)
            continue
        current = {}
        def finding(cls, title, lines, remedies=None):
            current[cls] = dict(cls=cls, title=title, lines=lines, remedies=remedies or [])

        state['unknown_count'] = 0
        state['unknown_clean'] = state.get('unknown_clean', 0) + 1
        if state['unknown_clean'] < 2 and unknown_cls in state['findings']:
            current[unknown_cls] = dict(state['findings'][unknown_cls], remedies=[])
        unparsed = reading.get('unparsed', [])
        if unparsed:
            finding('host-health-unparsed:' + host, 'unparsed failed units on ' + host,
                    [health_scrub(line) for line in unparsed])
        accounted = len(reading.get('units', [])) + len(unparsed)
        if accounted != reading.get('failed_lines', accounted):
            finding('host-health-census:' + host, 'failed unit census mismatch on ' + host,
                    ['%s failed lines; %d units plus unparsed' % (reading['failed_lines'], accounted)])
        units = {}
        for row in reading.get('units', []):
            unit = row.get('unit')
            if (health_unit(unit) and row.get('active') == 'failed' and
                    not any(fnmatch.fnmatchcase(unit, entry['glob']) for entry in failed_policy.get('ignore', []))):
                units[unit] = row
        for unit in set(units) | set(state['units']):
            record = state['units'].setdefault(unit, dict(count=0, clean=0, last=None, stopped=False))
            cls = 'unit-failing:%s:%s' % (host, unit)
            if record['last'] is not None and now-record['last'] < float(cfg.get('unit_failed_sample_gap_seconds', 60)):
                if cls in state['findings']:
                    current[cls] = dict(state['findings'][cls], remedies=[])
                continue
            record['last'] = now
            if unit not in units:
                record['count'] = 0
                record['clean'] += 1
                if record['clean'] < int(cfg.get('unit_clean_samples', 2)):
                    if cls in state['findings']:
                        current[cls] = dict(state['findings'][cls], remedies=[])
                else:
                    record['stopped'] = False
                    record['tail_pending'] = True
                continue
            row = units[unit]
            record['clean'] = 0
            record['count'] += 1
            if record['count'] < int(cfg.get('unit_failed_samples', 2)):
                if cls in state['findings']:
                    current[cls] = dict(state['findings'][cls], remedies=[])
                continue
            if 'first_tail' not in record or record.get('tail_pending'):
                record['first_tail'] = health_scrub(row.get('journal_tail', row.get('journal', '')), limit=4096)
                record['first_tail'] = record['first_tail'].encode('utf-8')[:4096].decode('utf-8', errors='ignore')
                record['first_tail'] = record['first_tail'] or 'no journal entries (rotated)'
                record['tail_pending'] = False
            timer = failed_policy.get('autostop', {}).get(unit)
            remedies = []
            scope = '--user ' if row.get('user') is True else ''
            lines = ['%s: Result=%s ExecMainStatus=%s failed at %s; %s' % (
                unit, row.get('Result'), row.get('ExecMainStatus'), row.get('InactiveEnterTimestamp'), health_scrub(row.get('journal', '')))]
            lines.append('journal tail at first sight:\n' + record['first_tail'])
            if timer and health_unit(timer) and timer.endswith('.timer') and unit.endswith('.service'):
                lines.append('After fixing on %s: systemctl %sreset-failed %s; systemctl %sstart %s' % (host, scope, unit, scope, timer))
                if cfg.get('unit_autostop_mode', 'warn') == 'enforce' and not record['stopped'] and isinstance(row.get('user'), bool):
                    remedies.append(dict(kind='stop-timer', host=host, service=unit, unit=timer, user=row['user'], why='allow-listed failed unit'))
            finding(cls, '%s failed on %s' % (unit, host), lines, remedies)

        for directory in policy.get('output_dirs', []):
            path = directory['path']
            if directory['host'] != host or not health_path(path):
                continue
            cls = 'output-leak:%s:%s' % (host, path)
            entries = reading.get('dirs', {}).get(path)
            if entries is None:
                if cls in state['findings']:
                    current[cls] = state['findings'][cls]
                continue
            total = sum(e['size'] for e in entries)
            files = [e for e in entries if e['type'] == 'file']
            leaks = [e for e in files if (
                any(fnmatch.fnmatchcase(e['name'], g) for g in directory['leak_globs']) and
                now-e['mtime'] > directory['leak_grace_min']*60) or (
                not any(fnmatch.fnmatchcase(e['name'], g) for g in directory['allow']) and e['size'] > directory['max_file_gb']*1024**3)]
            if leaks or total > directory['max_dir_gb']*1024**3:
                oldest = sorted(files, key=lambda e:e['mtime'])[:3]
                biggest = sorted(files, key=lambda e:e['size'], reverse=True)[:3]
                finding(cls, 'job output leak on %s: %s' % (host, path), [
                    '%d suspect files, %d entries, %.2f GB top-level total' % (len(leaks), len(entries), total/1024**3),
                    'oldest: ' + ', '.join(repr(e['name']) for e in oldest),
                    'biggest: ' + ', '.join(repr(e['name']) for e in biggest)])

        for fs, disk in reading.get('disks', {}).items():
            if not health_path(fs):
                continue
            cls = 'disk-fill-eta:%s:%s' % (host, fs)
            ring = state['disks'].setdefault(fs, [])
            ring[:] = [p for p in ring if now-float(cfg.get('disk_fill_window_minutes', 60))*60 <= p[0] < now]
            ring.append([now, disk['used_kb']])
            ring_limit = 120
            ring[:] = ring[-ring_limit:]
            if len(ring) < 10:
                if cls in state['findings']:
                    current[cls] = state['findings'][cls]
                continue
            xs = [(p[0]-now)/3600 for p in ring]
            ys = [p[1] for p in ring]
            mx, my = sum(xs)/len(xs), sum(ys)/len(ys)
            denominator = sum((x-mx)**2 for x in xs)
            slope = sum((x-mx)*(y-my) for x,y in zip(xs,ys))/denominator if denominator else 0
            free, total = disk['free_kb'], disk['total_kb']
            eta = free/slope if slope > 0 else math.inf
            halt = max(0, free-total*float(cfg.get('disk_halt_free_pct', 8))/100)/slope if slope > 0 else math.inf
            if slope > 0 and ((eta < float(cfg.get('disk_fill_eta_hours', 48)) and
                              slope > float(cfg.get('disk_fill_min_gb_per_h', 5))*1024**2) or
                             free/total*100 < float(cfg.get('disk_fill_warn_free_pct', 15))):
                finding(cls, 'disk filling on %s: %s' % (host, fs), [
                    'growth %.2f GB/h; free %.2f GB (%.2f%%); %.2f h to full, %.2f h to fleet halt (%s%% free)' % (
                        slope/1024**2, free/1024**2, free/total*100, eta, halt, cfg.get('disk_halt_free_pct', 8)),
                    'Inspect: goodqa disk top --host %s; goodqa disk writers' % host])
        # A missing filesystem reading is unknown, never a clean filesystem.
        for cls, f in state['findings'].items():
            if cls.startswith('disk-fill-eta:') and cls.split(':', 2)[2] not in reading.get('disks', {}):
                current[cls] = f
        state['findings'] = current
        out.extend(current.values())
    return out


def git_credentials_findings(reading, st, host, policy=None):
    """Keep each host/kind episode until two healthy ticks; UNKNOWN never counts as recovery."""
    import goodqa_maintain as M
    required = (policy or {}).get('clear_after_ok_ticks', 2)
    prefix = 'git-credentials:%s:' % host
    retained = st.setdefault('git_credentials', {}).setdefault(host, {})
    failures = {r['key']: r for r in reading.get('findings', [])}
    if reading.get('status') != 'OK' and not failures and not retained:
        key = prefix + 'collector'
        failures[key] = dict(key=key, what='UNKNOWN: credential observation unavailable')
    out = []
    for key in sorted(set(failures) | set(retained)):
        record = retained.setdefault(key, {'ok_ticks': 0})
        if key in failures:
            record['ok_ticks'] = 0
            ev = M.git_credential_scrub(json.dumps(reading.get('last_event') or {}, sort_keys=True))
            record['finding'] = dict(cls=key, title='git credentials on %s (%s)' % (host, key.rsplit(':', 1)[-1]),
                                     lines=[M.git_credential_scrub(failures[key]['what']), 'Last event evidence: ' + ev], remedies=[])
        elif prefix + 'collector' not in failures and (
                reading.get('scope_statuses', {}).get(key.rsplit(':', 1)[-1]) == 'OK' or
                reading.get('status') == 'OK'):
            record['ok_ticks'] += 1
        else:
            record['ok_ticks'] = 0
        if record['ok_ticks'] < required:
            if record.get('finding'):
                out.append(record['finding'])
        else:
            alert = st.get('alerts', {}).get(key)
            if alert is not None:
                alert['recovery_evidence'] = M.git_credential_scrub(json.dumps(dict(
                    observed_at=reading.get('observed_at'), probe=reading.get('probe'), ok_ticks=record['ok_ticks'])))
            retained.pop(key, None)
    return out


class Effects:
    def __init__(self, cfg):
        self.cfg = cfg

    def git_credentials(self):
        import goodqa_maintain as M
        import goodqa_skills as S
        here = S.box()
        readings = {here: M.git_credentials_check(host=here)}
        if here == 'dev':
            try:
                rc, output, _ = C.run([DEV2, '-t', '220',
                    'goodqa maintain check --class git-credentials --host here --json'], timeout=240)
                rep = json.loads(output)
                if rc not in (0, 1):
                    raise ValueError('remote observation failed')
                readings['dev2'] = rep['git_credentials']['dev2']
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                readings['dev2'] = dict(status='UNKNOWN', findings=[])
        return readings

    def _health_program(self, host, program, budget):
        if host not in ('dev', 'dev2'):
            return dict(error='unknown host')
        argv = ([sys.executable, '-B', '-'] if host == 'dev' else
                [DEV2, '-t', str(max(1, int(budget))), '-p', '-'])
        rc, output, _ = C.run(argv, timeout=budget, input=program)
        if rc:
            return dict(error='host health transport unknown')
        try:
            result = json.loads(output)
            if not isinstance(result, dict):
                raise ValueError('expected object')
            return result
        except ValueError:
            return dict(error='invalid host health JSON')

    def host_health(self, host):
        policy = self.cfg.get('host_health', {})
        spec = dict(output_dirs=[d for d in policy.get('output_dirs', []) if d['host'] == host],
                    filesystems=policy.get('filesystems', {}).get(host, []))
        budget = float(self.cfg.get('host_health_budget_seconds', 25))
        program = 'import re, json\n' + '\n'.join(inspect.getsource(f) for f in
            (health_unit, health_path, health_scrub, collect_host_health))
        program += '\nprint(json.dumps(collect_host_health(%r, %r)))\n' % (spec, budget)
        result = self._health_program(host, program, budget)
        if not result.get('error') and not (isinstance(result.get('units'), list) and
                isinstance(result.get('dirs'), dict) and isinstance(result.get('disks'), dict)):
            return dict(error='invalid host health sections')
        return result

    def stop_timer(self, host, service, unit, user):
        mapping = self.cfg.get('host_health', {}).get('failed_units', {}).get('autostop', {})
        if (self.cfg.get('unit_autostop_mode', 'warn') != 'enforce' or
                not health_unit(service) or not service.endswith('.service') or mapping.get(service) != unit or
                not health_unit(unit) or not unit.endswith('.timer') or not isinstance(user, bool)):
            return 2, 'stop refused: outside allow-list/enforce policy'
        budget = float(self.cfg.get('host_health_budget_seconds', 25))
        program = 'import re, json\n' + inspect.getsource(health_unit) + '\n' + inspect.getsource(stop_health_timer)
        program += '\nprint(json.dumps(dict(result=stop_health_timer(%r, %r, %r, %r))))\n' % (service, unit, user, budget)
        result = self._health_program(host, program, budget)
        return tuple(result['result']) if 'result' in result else (2, 'stop transport unknown')

    def autocommit_state(self, git_dir=None, work_tree=None, remote='origin', log=None, run=None, budget_s=None, now=None):
        """Read-only facts about the live tree's autocommit: counts, lock, last commit age, remote relation, parsed log. Never writes, locks or fetches. All git calls
        and the fuser probe share ONE deadline (autocommit_budget_seconds, 40) so a slow remote cannot starve the liveness pass; an unknown remote is an ERROR, never
        all-clear; the LOG is read first and returned even with an error, so a bypassed guard (crash line) is reported whatever the git state is."""
        gd, wt, log = git_dir or LIVE_GIT_DIR, work_tree or LIVE_TREE, log or AUTOCOMMIT_LOG
        now = now or time.time()
        tail, parsed = '', {}
        try:
            with open(log, 'rb') as f:
                f.seek(0, 2)
                f.seek(max(0, f.tell() - 65536))
                tail = f.read(65536).decode('utf-8', 'replace')
            parsed = parse_autocommit_log(tail, now, repo=gd)
        except (OSError, ValueError):
            tail, parsed = '', {}
        base = dict(log=parsed, log_tail='\n'.join(tail.strip().splitlines()[-12:]))
        try:
            budget = float(budget_s if budget_s is not None else (self.cfg or {}).get('autocommit_budget_seconds', 40))
            deadline = time.monotonic() + budget

            def left_s():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise subprocess.TimeoutExpired('autocommit_state', 0)
                return left

            def git(*a, per=12):
                return (run or subprocess.run)(['git', '--no-optional-locks', '--git-dir', gd, '--work-tree', wt, *a], capture_output=True, text=True,
                                               errors='replace', timeout=min(per, left_s()))
            head = git('log', '-1', '--format=%ct', 'master')
            if head.returncode:
                return dict(base, error='git log master failed: %s' % C.cap(head.stderr, 100))
            st = git('status', '--porcelain=v1', '--untracked-files=normal')
            if st.returncode:
                return dict(base, error='git status failed: %s' % C.cap(st.stderr, 100))
            dirty = len([x for x in st.stdout.splitlines() if x.strip()])
            ref = git('ls-remote', remote, 'refs/heads/main', per=15)
            remote_sha = (ref.stdout.split() or [''])[0] if ref.returncode == 0 else ''
            if not remote_sha:
                return dict(base, error='git ls-remote %s main failed or empty (rc=%s): %s' % (remote, ref.returncode, C.cap(ref.stderr, 100)))
            known = git('cat-file', '-e', remote_sha + '^{commit}').returncode == 0
            behind = True                                             # an object we do not have means origin/main has commits we have not integrated
            if known:
                behind = git('merge-base', '--is-ancestor', remote_sha, 'master').returncode != 0
                ah = git('rev-list', 'master', '--not', remote_sha)
            else:
                ah = git('rev-list', 'master', '--not', 'refs/remotes/%s/main' % remote)       # unknown tip: commits our own (stale) origin/main ref does not contain: the push updates that ref, so a published commit leaves this set
            toks = ah.stdout.split() if ah.returncode == 0 else None
            shas = toks if toks is not None and all(re.fullmatch(r'[0-9a-f]{40}', x) for x in toks) else None       # any odd output = unknown, never zero
            ahead = None if shas is None else len(shas)
            ahead_oldest = shas[-1] if shas else ''                       # the OLDEST unpushed commit: persistence is judged on THIS commit, not on a count that a healthy push cycle keeps above zero
            lockp = os.path.join(gd, 'index.lock')
            lock = dict(exists=False)
            if os.path.lexists(lockp):
                lk = os.lstat(lockp)
                holder = ''
                try:
                    fu = subprocess.run(['fuser', lockp], capture_output=True, text=True, timeout=min(5, left_s()))
                    holder = fu.stdout.strip().split()[0] if fu.stdout.strip() else ''
                    if fu.returncode not in (0, 1) or (fu.returncode == 1 and fu.stderr.strip()):
                        holder = 'unknown'                            # fuser failed: ownership unproven is never "no holder"
                except (OSError, subprocess.SubprocessError):
                    holder = 'unknown'
                lock = dict(exists=True, size=lk.st_size, age_s=max(0.0, now - lk.st_mtime), holder=holder)
            return dict(base, dirty=dirty, ahead=ahead, ahead_oldest=ahead_oldest, behind=behind, last_commit_age_s=max(0.0, now - int(head.stdout.strip() or 0)), lock=lock,
                        remote_sha=remote_sha)
        except (OSError, subprocess.SubprocessError, ValueError, TypeError) as exc:
            return dict(base, error='%s: %s' % (type(exc).__name__, C.cap(str(exc), 100)))

    def snapshot(self, replay_since=None):
        argv = [DEV2, '-t', '90', '-p', REMOTE] + (['--replay-since', replay_since] if replay_since else
                 ['--service-inert-days', str(getattr(self, 'cfg', {}).get('service_inert_days', 7))])
        rc, out, err = C.run(argv, timeout=150)
        if rc != 0:
            raise C.CliError('dev2 snapshot failed (rc %s): %s' % (rc, C.cap(err or out, 300)), C.EXIT_UNAVAILABLE)
        try:
            snap = json.loads(out)
        except ValueError:
            raise C.CliError('dev2 snapshot is not JSON: %s' % C.cap(out, 200), C.EXIT_UNAVAILABLE)
        if snap.get('error'):
            raise C.CliError('dev2 snapshot: %s' % snap['error'], C.EXIT_UNAVAILABLE)
        return snap

    def land_lag_rows(self, known=None, limits=None):
        import inspect
        try:
            with open(os.path.join(C.CODE_ROOT, 'docs/ops/ERIC-OBLIGATIONS.md')) as f:
                ledger = f.read()
        except OSError:
            ledger = ''
        program = (inspect.getsource(land_lag_headers) + '\n' + inspect.getsource(collect_land_lag_remote) +
                   '\nprint(__import__("json").dumps(collect_land_lag_remote(ledger_text=' + repr(ledger) + ', known=' + repr(known or {}) + ', limits=' + repr(limits or {}) + ')))\n')
        rc, out, err = C.run([DEV2, '-t', '30', '-p', '-'], timeout=65, input=program)
        if rc:
            return dict(rows=[], errors=['dev2 land-lag read failed: ' + C.cap(err or out, 200)])
        try:
            result = json.loads(out)
            if not isinstance(result, dict) or not isinstance(result.get('rows'), list):
                raise ValueError('expected rows list')
            return result
        except ValueError as exc:
            return dict(rows=[], errors=['dev2 land-lag invalid JSON: ' + str(exc)])

    def lane_floor_lines(self, since):
        rc, out, _ = C.run(['journalctl', '--user', '-u', 'lane-floor.service', '--since', since, '--no-pager', '-o', 'short-iso'],
                           timeout=60)
        return out.splitlines() if rc == 0 else []

    def autopilot_looping(self, path=None):
        """The tasks the autopilot loop-cap rule holds as looping (its state file; {} when unreadable)."""
        try:
            with open(path or AUTOPILOT_STATE) as f:
                return set((json.load(f).get('looping') or {}).keys())
        except (OSError, ValueError, AttributeError):
            return set()

    def refusals(self):
        rows = []
        try:
            with open(REFUSALS, errors='replace') as f:
                lines = f.readlines()
                for line in lines[max(0, len(lines) - 3000):]:
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        continue
        except OSError:
            pass
        return rows

    def lane_floor_floor(self):
        try:
            with open(os.path.join(C.CODE_ROOT, 'config', 'lane-floor.json')) as f:
                return int(json.load(f).get('floor') or 0) or None
        except (OSError, ValueError):
            return None

    def ship_watch(self, path=None):
        try:
            with open(path or os.path.expanduser('~/.local/share/ship-watch/state.json')) as f:
                return json.load(f).get('incidents') or {}
        except (OSError, ValueError, AttributeError):
            return {}

    def json_cmd(self, argv, timeout=150):
        rc, out, err = C.run([sys.executable, '-B'] + [os.path.join(C.CODE_ROOT, argv[0])] + list(argv[1:]), timeout=timeout)
        try:
            return json.loads(out) if out.strip() else None, rc, C.cap((err or '').strip(), 200)
        except ValueError:
            return None, rc, 'not JSON: %s' % C.cap(out, 120)

    def http_json(self, url, timeout=20):
        import urllib.request
        with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'goodqa-liveness'}), timeout=timeout) as r:
            return json.loads(r.read(1 << 20).decode())

    def gh_compare(self, repo, base, head='main', timeout=30):
        jq = ('{status, ahead_by, behind_by, commits: [.commits[] | {sha, parents: [.parents[].sha], date: .commit.committer.date}], '
              'files: [.files[]?.filename]}')
        rc, out, err = C.run(['gh', 'api', '--paginate', 'repos/%s/compare/%s...%s?per_page=100' % (repo, base, head), '--jq', jq],
                             timeout=timeout)
        if rc != 0:                         # an ordinary exception: C.CliError is a SystemExit and would end the whole pass (B1)
            raise RuntimeError('gh compare %s: rc %s %s' % (repo, rc, C.cap((err or out).strip(), 200)))
        return merge_pages(out)

    def gh_pushes(self, repo, ref='refs/heads/main', timeout=20):
        """The latest 100 pushes to main (GitHub repository activity), newest first: [{ts, before, after}]."""
        rc, out, err = C.run(['gh', 'api', 'repos/%s/activity?ref=%s&per_page=100' % (repo, ref), '--jq',
                              '[.[] | {ts: .timestamp, before: .before, after: .after}]'], timeout=timeout)
        return json.loads(out) if rc == 0 and out.strip() else []

    def gh_push_files(self, repo, before, after, timeout=20):
        """The files one push changed (compare before...after, first page: enough to tell receipts from product code)."""
        rc, out, err = C.run(['gh', 'api', 'repos/%s/compare/%s...%s?per_page=1' % (repo, before, after), '--jq', '[.files[]?.filename]'],
                             timeout=timeout)
        if rc != 0:
            raise RuntimeError('gh compare %s push: rc %s %s' % (repo, rc, C.cap((err or out).strip(), 200)))
        return json.loads(out)

    def start_unit(self, unit):
        rc, out, err = C.run(['systemctl', '--user', 'start', '--no-block', unit], timeout=30)
        return rc, C.cap((err or out).strip(), 200)

    def rule_warn(self, config, key, value, why):
        import rule_overrides as RO
        RO.set_value(config, key, value, why)
        return 0, 'override %s.%s = %r' % (config, key, value)

    def _ticket_timeout(self, default):
        """Clamp one ticket-API call to the configured ceiling AND to act()'s remaining per-pass alert budget
        (`_alert_deadline`, set by act()), so one slow GoodQA call cannot push the pass past its unit
        TimeoutStartSec (goodqa#14007). A floor keeps every call long enough to do real work."""
        t = float(self.cfg.get('ticket_timeout_seconds', default))
        deadline = getattr(self, '_alert_deadline', None)
        if deadline is not None:
            t = min(t, deadline - time.monotonic())
        return max(5.0, t)

    def ticket_new(self, title, body, idem):
        p = os.path.join(os.path.dirname(state_path()), 'alert-body.md')
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'w') as f:
            f.write(body)
        rc, out, err = C.run([os.path.join(C.CODE_ROOT, 'bin', 'goodqa'), 'ticket', 'new', 'goodqa', title, '--body-file', p, '--idem', idem,
                              '--assign', 'coordinator', '--parent', self.cfg.get('alert_parent', 'goodqa#6099'), '--label', 'fleet-liveness',
                              '--no-similar-check'], timeout=self._ticket_timeout(180))
        m = re.search(r'\b([a-z][a-z0-9-]*#\d+)\b', out or '')
        return (m.group(1) if rc == 0 and m else None), C.cap((err or out).strip(), 300)

    def ticket_status(self, ref):
        try:
            rc, out, _ = C.run([os.path.join(C.CODE_ROOT, 'bin', 'goodqa'), 'ticket', 'show', ref,
                                '--json', '--wait', '0'], timeout=self._ticket_timeout(120))
            row = json.loads(out) if rc == 0 else None
            return row.get('status') if isinstance(row, dict) else None
        except (ValueError, OSError, subprocess.SubprocessError, C.CliError):
            return None

    def ticket_writer(self, ref):
        import goodqa_bugs as B
        if not hasattr(self, '_tickets'):
            self._tickets = B.Effects()
        fx = self._tickets
        issue = fx.resolve(ref)
        if B.owner_touches(issue, fx._owner_ids):
            fx.quiet(issue['id'])
        return fx, issue

    def ticket_patch(self, ref, status):
        fx, issue = self.ticket_writer(ref)
        fx.patch(issue['id'], {'status': status}, 'liveness:%s:%s:%s' % (issue['id'], status, issue.get('updatedAt')))

    def moved_copy(self, ref):
        fx, issue = self.ticket_writer(ref)
        links = fx.api.get('/issues/%s/links' % issue['id'])
        for endpoint in links.get('duplicates') or []:
            target = endpoint.get('issue') or endpoint
            copy = fx.issue(target['id'])
            labels = {x.get('name') if isinstance(x, dict) else x for x in copy.get('labels') or []}
            project = fx.api.get('/projects/%s' % copy['projectId'])
            project = project.get('project', project)
            if (project.get('slug') == 'work-tracker-automatic' and copy.get('status') in
                    ('triage', 'todo', 'backlog', 'in_progress', 'in_review') and 'moved-from-goodqa' in labels):
                return 'work-tracker-automatic#%s' % copy['number']
        return None

    def duplicate_survivor(self, ref, hops=3):
        """-> 'slug#N' of the first OPEN canonical ticket that `ref` is a `duplicates` link to, following a canonical ticket
        that is itself closed as a duplicate up to `hops` links (a visited set breaks a cycle). -> None only when every read
        succeeded and no open ticket was found (the caller then reopens the alert). RAISES on any read failure: the caller
        defers instead of reopening a ticket a person closed on purpose (red-team F3)."""
        fx, issue = self.ticket_writer(ref)
        seen = {issue['id']}
        frontier = [issue['id']]
        for _ in range(hops):
            nxt = []
            for iid in frontier:
                links = fx.api.get('/issues/%s/links' % iid)
                for endpoint in links.get('duplicates') or []:
                    target = endpoint.get('issue') or endpoint
                    if target['id'] in seen:
                        continue
                    seen.add(target['id'])
                    sv = fx.issue(target['id'])
                    if sv.get('archivedAt'):
                        continue
                    if sv.get('status') not in CLOSED_ALERT_STATUSES:
                        project = fx.api.get('/projects/%s' % sv['projectId'])
                        project = project.get('project', project)
                        return '%s#%s' % (project.get('slug'), sv['number'])
                    if sv.get('status') == 'duplicate':
                        nxt.append(target['id'])
            frontier = nxt
            if not frontier:
                break
        return None

    def undo_copy(self, ref, copy):
        fx, original = self.ticket_writer(ref)
        fx, target = self.ticket_writer(copy)
        if target.get('status') not in ('triage', 'todo', 'backlog', 'in_progress', 'in_review'):
            return
        fx.link_duplicate(target['id'], original['id'], 'liveness:undo-copy:%s:link' % target['id'])
        fx.comment(target['id'], 'Live alert restored to **%s**; this moved snapshot is a duplicate.' % ref,
                   'liveness:undo-copy:%s:comment' % target['id'])
        fx.patch(target['id'], {'status': 'duplicate'}, 'liveness:undo-copy:%s:status' % target['id'])

    def comment(self, ref, body):
        p = os.path.join(os.path.dirname(state_path()), 'alert-comment.md')
        with open(p, 'w') as f:
            f.write(body)
        rc, out, err = C.run([os.path.join(C.CODE_ROOT, 'bin', 'goodqa'), 'ticket', 'comment', ref, '--body-file', p],
                             timeout=self._ticket_timeout(120))
        return rc, C.cap((err or out).strip(), 200)

    def ticket_status_block(self, ref, block):
        """Rewrite this filer's ONE marked status block in the alert ticket's own description (gq-clutter S1): a repeat
        observation updates the block in place (a description edit posts no comment) instead of a new comment every
        alert_comment_minutes. -> True when the description changed. Raises on an API failure; act() catches it."""
        import hashlib
        fx, issue = self.ticket_writer(ref)
        have = issue.get('description') or ''
        want = put_status_block(have, block)
        if want == have:
            return False
        fx.patch(issue['id'], {'description': want},
                 'liveness:status:%s:%s' % (issue['id'], hashlib.sha256(want.encode('utf-8', 'replace')).hexdigest()[:16]))
        return True

    def hawk(self, body):
        for p in HAWK_JOURNAL:
            if os.path.exists(p):
                return C.run([p, 'append', '--kind', 'wal', '--body-stdin'], timeout=30, input=body)
        return 127, '', 'no hawk journal'


# ------------------------------------------------------------------------------------------------ rolling alerts
# gq-clutter S1 (2026-11-04): the filer re-posted the whole alert body as a comment every alert_comment_minutes (30)
# for as long as a finding held, and opened one ticket per lane x candidate SHA, so successor lanes (-r2, -r3,
# -successor, -sol-YYYYMMDD) and every new candidate each got a new ticket, and a lane that was superseded,
# cancelled or deleted never cleared: ~35.5k comments in 27 h across 303 tickets (goodqa#11653 alone took 604).
# Now: one ticket per alert KEY (a land-lag lane FAMILY: successor suffixes and the candidate SHA stripped), a repeat
# observation only bumps counters in state and, at most every alert_status_minutes, rewrites ONE marked status block
# in the ticket's description; comments are posted only on transitions (opened is the ticket itself; escalated,
# recovered, reopened) plus at most one reminder per alert_comment_minutes (1440) and only when something material
# (severity, the member set, the title with its numbers masked) changed since the last comment.
STATUS_OPEN = '<!-- fleet-liveness:status -->'
STATUS_CLOSE = '<!-- /fleet-liveness:status -->'
SEVERITY = {'low': 0, 'normal': 1, 'high': 2, 'critical': 3}
# Successor / round / engine / date suffixes a lane name accretes as it is re-run; stripped repeatedly from the end.
LANE_SUFFIX = re.compile(r'-(?:r\d+|successor|sol|opus|fable|astra|terra|codex|fix\d*|merge|blindfix|testfix|rescue|redo|\d{8})$')


def lane_family(name):
    """'go-rebuild-p0-failure-contract-r6-sol-20261027-fix-sol' -> 'go-rebuild-p0-failure-contract'. Never empty."""
    name = str(name or '').strip().lower()
    previous = None
    while previous != name:
        previous = name
        stripped = LANE_SUFFIX.sub('', name)
        if stripped:
            name = stripped
    return name


def alert_key(cls):
    """The alert-ticket key of a finding class. A land-lag finding is keyed by its lane FAMILY, so a successor lane
    (foo-r2, foo-r3, foo-successor, foo-sol-20261101) and every candidate SHA / provisional key of it (`@<sha>`,
    `@pending-<hash>`) share ONE ticket: `land-lag:runner:<family>` for a runner task, `land-lag:owner:<family>` for
    a codex-owner lane (its run directory, o8-run1 / o8-astra, is dropped: successor runs rename it). Every other
    class keeps its own key. Idempotent: alert_key(alert_key(c)) == alert_key(c)."""
    cls = str(cls)
    if not cls.startswith('land-lag:'):
        return cls
    key = cls[len('land-lag:'):]
    if re.match(r'^(?:runner|owner):', key):
        return cls
    key = key.split('@', 1)[0]
    if key.startswith('runner/'):
        return 'land-lag:runner:' + lane_family(key[len('runner/'):])
    return 'land-lag:owner:' + lane_family(key.split('/', 1)[-1])


def finding_severity(f):
    s = f.get('severity') or 'normal'
    return s if s in SEVERITY else 'normal'


def merge_family(key, fs):
    """One finding per alert key: a singleton whose key is its own class passes through unchanged; a lane family is
    led by its most severe, oldest member and lists the members (capped) in its lines."""
    if len(fs) == 1 and fs[0]['cls'] == key:
        return dict(fs[0], members=[key])
    members = sorted({f['cls'] for f in fs})
    lead = max(fs, key=lambda f: (SEVERITY[finding_severity(f)], float(f.get('minutes') or 0)))
    shown = ', '.join('`%s`' % m for m in members[:10]) + (' (+%d more)' % (len(members) - 10) if len(members) > 10 else '')
    return dict(lead, cls=key, members=members, severity=finding_severity(lead),
                title='%s (lane family `%s`, %d member(s))' % (lead['title'], key.split(':', 2)[-1], len(members)),
                lines=list(lead['lines']) + ['family members (%d): %s' % (len(members), shown)],
                remedies=[r for f in fs for r in f.get('remedies') or []])


def material_digest(f):
    """What a reminder comment must be about: severity, the member set and the title with every number masked (an
    age ticking up is not news)."""
    import hashlib
    title = re.sub(r'\d+(?:\.\d+)?', '#', str(f.get('title') or ''))
    raw = json.dumps([finding_severity(f), sorted(f.get('members') or [f['cls']]), title])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def defang_markers(text):
    """Finding text (journal tails, lane names) can never carry a status-block marker into a description."""
    return str(text).replace('<!--', '<! --')


def put_status_block(desc, block):
    """Replace the LAST marked status block in `desc` (the filer appends its block at the end), or append one. The block
    text cannot forge a marker, and a stray marker earlier in a human-edited description is left alone (red-team F8)."""
    desc = desc or ''
    block = defang_markers(block).strip()
    wrapped = STATUS_OPEN + '\n' + block + '\n' + STATUS_CLOSE
    i = desc.rfind(STATUS_OPEN)
    j = desc.find(STATUS_CLOSE, i + len(STATUS_OPEN)) if i >= 0 else -1
    if i >= 0 and j >= 0:
        return desc[:i] + wrapped + desc[j + len(STATUS_CLOSE):]
    return (desc.rstrip() + '\n\n' if desc.strip() else '') + wrapped


def status_block(key, a):
    members = a.get('members') or []
    lines = ['**Fleet liveness status** (rewritten in place each update; comments only on opened / escalated / recovered / '
             'reopened, plus at most one reminder per day when something material changed)', '',
             '- alert key: `%s`' % key,
             '- state: %s' % ('recovered' if a.get('cleared') else 'open'),
             '- occurrences: %d (passes that observed it%s)' % (int(a.get('occurrences') or 0),
                                                               '; recurrences %d' % a['recurrences'] if a.get('recurrences') else ''),
             '- first_seen: %s' % iso(float(a.get('first_seen') or a.get('opened') or 0)),
             '- last_seen: %s' % iso(float(a.get('last_seen') or a.get('opened') or 0)),
             '- last: %s' % C.cap(str(a.get('last_value') or ''), 300, tail=False),
             '- severity: %s' % (a.get('severity') or 'normal')]
    if a.get('last_minutes') is not None:
        lines.append('- last minutes: %s' % a['last_minutes'])
    if len(members) > 1 or (members and members[0] != key):
        lines.append('- members (%d): %s' % (len(members), ', '.join('`%s`' % m for m in members[:10]) +
                                              (' (+%d more)' % (len(members) - 10) if len(members) > 10 else '')))
    return C.cap('\n'.join(lines), 3000, tail=False)


def consolidate_alerts(st, now):
    """One-time, local (no ticket I/O) migration of alerts keyed by a pre-family class (`land-lag:runner/foo-r2@sha`)
    onto their alert_key: the oldest open legacy ticket of a family is ADOPTED as the family's ticket (no new ticket),
    every other open legacy ticket of the family is marked `merged_into` and is closed once as a duplicate by act()'s
    reconcile loop. Idempotent; already-cleared legacy entries are left as history."""
    alerts = st.setdefault('alerts', {})
    groups = {}
    for cls, a in list(alerts.items()):
        key = alert_key(cls)
        if key == cls or not isinstance(a, dict) or a.get('cleared') or a.get('merged_into'):
            continue
        if not a.get('ref'):
            alerts.pop(cls)                # a failed legacy filing has no ticket; the family files its own if still live
            continue
        groups.setdefault(key, []).append(cls)
    for key, legacy in groups.items():
        legacy.sort(key=lambda c: (float(alerts[c].get('opened') or 0), str(alerts[c].get('ref'))))
        target = alerts.get(key)
        if not target or target.get('cleared') or not target.get('ref'):
            adopted = alerts.pop(legacy[0])
            target = dict(adopted, members=sorted(set(adopted.get('members') or []) | {legacy[0]}),
                          adopted_from=legacy[0], adopted_at=now)
            alerts[key] = target
            legacy = legacy[1:]
        for cls in legacy:
            alerts[cls]['merged_into'] = key
    return st


# ------------------------------------------------------------------------------------------------ the pass
def observe(a, f, now):
    """Rolling counters for a repeat observation: local state only, no ticket I/O (gq-clutter S1)."""
    a['occurrences'] = int(a.get('occurrences') or 0) + 1
    a.setdefault('first_seen', float(a.get('opened') or now))
    a['last_seen'] = now
    a['last_value'] = C.cap(str(f.get('title') or ''), 300, tail=False)
    a['last_minutes'] = f.get('minutes')
    a['members'] = list(f.get('members') or [f['cls']])
    a.setdefault('severity', finding_severity(f))      # a legacy alert adopts its current severity: never a false escalation
    a.setdefault('comment_digest', material_digest(f))  # ... and its current material digest: no reminder storm on deploy


def act(findings, st, cfg, fx, apply, now, sample=None, left=None, reconcile=True, alert_budget=None, clock=time.monotonic):
    """Remedies (rate-limited) and ONE rolling alert ticket per alert key (alert_key: a land-lag lane family shares one
    ticket across successor lanes and candidate SHAs; gq-clutter S1). A repeat observation bumps local counters and, at
    most every alert_status_minutes, rewrites the ticket's marked status block (Effects.ticket_status_block) instead of
    commenting. Comments only on transitions: escalated (severity rose), recovered (+ close, below), reopened (a
    recurrence within alert_reopen_days of the recovery reopens the SAME ticket; later opens a new one), plus at most
    one reminder per alert_comment_minutes and only when material_digest changed. A land-lag finding marked `stale`
    (its lane is no longer discovered, or it landed) is not live and its alert closes within the pass. On recovery a
    comment and a close (status done) for operational classes that cleared, comment-only for landed-dark
    git-credentials (goodqa#13953). Legacy per-class alerts are consolidated onto their key (consolidate_alerts); the
    non-adopted siblings are closed once as duplicates.

    The ticket-API I/O (filing, status blocks, comments, status reads, recovery closes) runs within a per-pass wall
    budget (`alert_budget`, default `act_budget_seconds`; goodqa#14007). When the budget is spent act() stops
    making new ticket calls for the remaining findings and reports them 'deferred: alert budget spent' instead of
    hanging, so a large finding board cannot push the pass past the unit TimeoutStartSec; run_pass then still
    reaches save_state, the alerts already filed persist (recent alerts are not re-filed), and deferred findings
    retry next pass until the backlog drains. Remedies (start-unit, rule-warn) are cheap and always run. A dry
    run performs no ticket WRITES (it may still read a ticket's status) and so never defers."""
    report = []
    reread_products = {}
    if left is None:
        start = time.monotonic()
        left = lambda: float(cfg.get('deploy_lag_budget_seconds', 80)) - (time.monotonic() - start)
    budget = float(cfg.get('act_budget_seconds', 120)) if alert_budget is None else max(0.0, float(alert_budget))
    alert_start = clock()
    def alert_room():
        return budget - (clock() - alert_start)
    try:                              # real Effects clamps each ticket call to this monotonic deadline
        fx._alert_deadline = alert_start + budget
    except (AttributeError, TypeError):
        pass
    cool = float(cfg.get('remedy_cooldown_seconds', 600))
    every = float(cfg.get('alert_comment_minutes', 1440)) * 60           # reminder cadence, and only on a material change
    status_every = float(cfg.get('alert_status_minutes', 60)) * 60       # status-block rewrite cadence
    reopen_window = float(cfg.get('alert_reopen_days', 7)) * 86400        # a recurrence inside it reopens the same ticket
    # The description PATCH (status block, duplicate close) goes over goodqa_bugs HTTP, which the CLI deadline clamp
    # does not cover: start one only with this much alert budget left, so a slow API cannot carry the pass past its
    # unit timeout (red-team F4; goodqa#14007). A sync-only pass is optional and simply waits for the next pass.
    write_reserve = float(cfg.get('alert_write_reserve_seconds', 60))
    consolidate_alerts(st, now)
    live = set()
    stale = {}
    groups = collections.OrderedDict()
    for f in findings:
        key = alert_key(f['cls'])
        if f.get('stale'):
            stale.setdefault(key, f['stale'])
            continue
        groups.setdefault(key, []).append(f)
    for key, family in groups.items():
        f = merge_family(key, family)
        reread = None
        a = st['alerts'].get(f['cls'])
        is_open = bool(a and a.get('ref') and not a.get('cleared'))
        recur = bool(a and a.get('cleared') and a.get('ref') and not f['cls'].startswith('git-credentials:')
                     and now - float(a['cleared']) < reopen_window)
        escalate = bool(is_open and SEVERITY[finding_severity(f)] > SEVERITY.get(a.get('severity') or finding_severity(f), 1))
        remind = bool(is_open and now - float(a.get('commented') or 0) >= every
                      and material_digest(f) != a.get('comment_digest', material_digest(f)))
        sync = bool(is_open and now - float(a.get('status_synced') or a.get('commented') or a.get('opened') or 0) >= status_every)
        announce = not a or a.get('cleared') or not a.get('ref') or escalate or remind
        due = announce or sync
        if apply and announce and f['cls'].startswith(('deploy-lag:', 'deploy-lag-unreadable:')):
            p = f['cls'].split(':', 1)[1]
            spec = (cfg.get('deploy_lag_products') or {}).get(p) or {}
            cache = st.setdefault('deploy_lag', {})
            if p not in reread_products:
                new = collect_deploy_lag(p, spec, cfg, fx, now, left)
                cache[p] = keep_deploy_lag_reading(cache.get(p) or {}, new, now)
                reread_products[p] = new
            new = reread_products[p]
            if new.get('error'):
                reread = 're-read: failed: %s; keeping the last finding' % new['error']
            else:
                fresh_sample = dict(sample or {}, deploy_lag={p: cache[p]})
                fresh = next((x for x in deploy_lag_findings(fresh_sample, cfg) if x['cls'] == f['cls']), None)
                if fresh is None:
                    note = 're-read: source readable' if f['cls'].startswith('deploy-lag-unreadable:') else 're-read: caught up'
                    report.append(dict(cls=f['cls'], title=f['title'], lines=[note], remedies=[],
                                       alert='suppressed'))
                    continue
                f = dict(fresh, members=f.get('members') or [fresh['cls']])
                reread = 're-read: lag still present'
        live.add(f['cls'])
        rec = dict(cls=f['cls'], title=f['title'], lines=f['lines'], remedies=[], alert=None)
        if f.get('members') and f['members'] != [f['cls']]:
            rec['members'] = f['members']
        if reread:
            rec['lines'] = list(rec['lines']) + [reread]
        for r in f['remedies']:
            rk = '%s|%s' % (r['kind'], r.get('unit') or '%s.%s' % (r.get('config'), r.get('key')))
            if r.get('host', ''):
                rk += '|' + r['host']
            if now - float(st['remedied'].get(rk) or 0) < cool:
                rec['remedies'].append(dict(r, result='cooldown'))
                continue
            if not apply:
                rec['remedies'].append(dict(r, result='would'))
                continue
            if r['kind'] == 'stop-timer':
                record = st['host_health'][r['host']]['units'][r['service']]
                if record['stopped']:
                    continue
                # Latch attempts, including failures, before performing the external effect.
                record['stopped'] = True
                rc, note = fx.stop_timer(r['host'], r['service'], r['unit'], r['user'])
                fx.hawk('host-health stop-timer %s %s rc=%s %s' % (r['host'], r['unit'], rc, note))
            elif r['kind'] == 'start-unit':
                rc, note = fx.start_unit(r['unit'])
            else:
                rc, note = fx.rule_warn(r['config'], r['key'], r['value'], f['title'])
            st['remedied'][rk] = now
            rec['remedies'].append(dict(r, result='rc=%s %s' % (rc, note)))
        a = st['alerts'].get(f['cls'])
        if apply and is_open:
            observe(a, f, now)                             # every observing pass, deferred or not: local only
        body = '\n'.join(['**Fleet liveness: %s** (%s)' % (f['title'], iso(now)), ''] + ['- ' + x for x in rec['lines']] + [
            '', 'Remedies this pass: %s' % ('; '.join('%s %s: %s' % (r['kind'], r.get('unit') or r.get('rule'), r['result'])
                                                    for r in rec['remedies']) or 'none'),
            '', '(goodqa fleet liveness, %s; it never deletes, cancels or pauses anything itself)' % DOC])
        # Per-pass alert budget (goodqa#14007): a finding files/comments/reads a ticket only when `due` (which now
        # includes a stored ref=None from a failed filing, so a burst of failed filings can never retry ungated and
        # revive the death spiral). Once the budget for that I/O is spent, defer the rest of this pass's findings
        # rather than hang. Remedies above already ran; a non-due finding (recent alert) makes no call and is never
        # deferred.
        if apply and due and alert_room() <= 0:
            rec['alert'] = ('open %s (deferred: alert budget spent)' % a['ref']) if (a and a.get('ref') and not a.get('cleared')) else 'deferred: alert budget spent'
            report.append(rec)
            continue
        if apply and due and (recur or not announce) and alert_room() < write_reserve:
            # a status-only sync, or a recurrence reopen (its triage PATCH is HTTP too): retried on the next pass
            rec['alert'] = '%s %s (deferred: alert budget reserve)' % ('cleared' if recur else 'open', a['ref'])
            report.append(rec)
            continue
        human_reopened = False
        if due and a and a.get('ref') and not a.get('cleared'):
            status = fx.ticket_status(a['ref'])
            if status is None:
                rec['lines'] = list(rec['lines']) + ['ticket status unreadable: %s' % a['ref']]
                rec['alert'] = 'open %s' % a['ref']
                report.append(rec)
                continue
            if status == 'duplicate':
                # A person closed this alert as a duplicate of a live canonical ticket: follow it. Do NOT reopen the alert;
                # append one line to the open canonical ticket, at most once an hour per alert. No open canonical ticket
                # (closed, unreadable or no `duplicates` link) -> fall through to the reopen below.
                try:
                    survivor = fx.duplicate_survivor(a['ref'])
                except Exception:                        # noqa: BLE001 - a failed lookup defers: never reopens a human close
                    if apply:
                        a['status_synced'] = now - status_every + DUP_RETRY_SECONDS      # retry in ~10 min, not every pass
                    rec['alert'] = 'open %s (duplicate lookup failed; retrying later)' % a['ref']
                    report.append(rec)
                    continue
                if survivor:
                    if not apply:
                        rec['alert'] = 'would note on %s (duplicate %s)' % (survivor, a['ref'])
                    else:
                        # Gate the NEXT lookup: without this the alert stays due and costs ~6 calls on every 2-minute pass.
                        # severity too: a stored severity below the finding's keeps `escalate` (and so `due`) true on every pass
                        a.update(status_synced=now, commented=now, comment_digest=material_digest(f), severity=finding_severity(f))
                        if now - float(a.get('dup_noted') or 0) < DUP_NOTE_SECONDS:
                            rec['alert'] = 'duplicate %s of %s (noted recently)' % (a['ref'], survivor)
                        elif alert_room() < write_reserve:
                            rec['alert'] = 'duplicate %s of %s (note deferred: alert budget reserve)' % (a['ref'], survivor)
                        else:
                            rc, _note = fx.comment(survivor, dup_note_line(f, a['ref'], now))
                            if rc == 0:
                                a['dup_noted'] = now
                            rec['alert'] = 'noted on %s (duplicate %s)' % (survivor, a['ref'])
                    report.append(rec)
                    continue
            if status in CLOSED_ALERT_STATUSES and now - float(a.get('reopened') or 0) >= 3600:
                if not apply:
                    rec['alert'] = 'would reopen %s' % a['ref']
                    report.append(rec)
                    continue
                if alert_room() < write_reserve:         # the triage PATCH is HTTP too (red-team delta R2)
                    rec['alert'] = 'open %s (reopen deferred: alert budget reserve)' % a['ref']
                    report.append(rec)
                    continue
                fx.ticket_patch(a['ref'], 'triage')
                a['reopened'] = now
                fx.comment(a['ref'], 'Reopened: the fleet liveness finding `%s` still holds; keep this alert open until it clears.' % f['cls'])
                a.update(commented=now, comment_digest=material_digest(f))
                human_reopened = True
        digest = material_digest(f)
        if apply:
            if recur:
                # A recurrence within alert_reopen_days of the recovery reopens the SAME ticket (one comment), never a new one.
                # Unless a person closed it as a duplicate of an open canonical ticket: then note there and track it again.
                try:
                    dsv = fx.duplicate_survivor(a['ref']) if fx.ticket_status(a['ref']) == 'duplicate' else None
                except Exception:                          # noqa: BLE001 - defer, never reopen a human close on a failed read
                    rec['alert'] = 'recurrence of %s: duplicate lookup failed; retrying next pass' % a['ref']
                    report.append(rec)
                    continue
                if dsv:
                    for k in ('absent_since', 'recovery_commented', 'close_reason'):
                        a.pop(k, None)
                    a.update(cleared=None, recurrences=int(a.get('recurrences') or 0) + 1, severity=finding_severity(f))
                    observe(a, f, now)
                    rc, _note = fx.comment(dsv, dup_note_line(f, a['ref'], now))
                    a.update(commented=now, comment_digest=digest, status_synced=now)
                    if rc == 0:
                        a['dup_noted'] = now
                    rec['alert'] = 'recurred; noted on %s (duplicate %s)' % (dsv, a['ref'])
                    report.append(rec)
                    continue
                try:
                    fx.ticket_patch(a['ref'], 'triage')
                except Exception:                          # noqa: BLE001 - a failed reopen retries next pass, never wedges
                    rec['alert'] = 'reopen of %s failed; retrying next pass' % a['ref']
                    report.append(rec)
                    continue
                for k in ('absent_since', 'recovery_commented', 'close_reason'):
                    a.pop(k, None)
                a.update(cleared=None, reopened=now, recurrences=int(a.get('recurrences') or 0) + 1,
                         severity=finding_severity(f))
                observe(a, f, now)
                fx.comment(a['ref'], '**Fleet liveness: reopened** at %s: `%s` recurred within %g days of its recovery, so '
                           'this alert is tracked here again.\n\n%s' % (iso(now), f['cls'], reopen_window / 86400, body))
                a.update(commented=now, comment_digest=digest)
                rec['alert'] = 'reopened %s' % a['ref']
                sync = True
            elif not a or a.get('cleared') or not a.get('ref'):
                fresh_alert = dict(opened=now, commented=now, first_seen=now, last_seen=now, occurrences=1,
                                   last_value=C.cap(str(f['title']), 300, tail=False), last_minutes=f.get('minutes'),
                                   members=list(f.get('members') or [f['cls']]), severity=finding_severity(f),
                                   comment_digest=digest, status_synced=now)
                opening = defang_markers(body) + '\n\n' + put_status_block('', status_block(f['cls'], fresh_alert))
                ref, note = fx.ticket_new('Fleet liveness: %s' % f['title'], opening, ('liveness-' + f['cls'].replace(':', '-') if f['cls'].startswith(('service-failing:', 'service-inert:', 'service-unknown'))
                    else 'liveness-%s-%s' % (f['cls'].replace(':', '-'), iso(now)[:13])))
                st['alerts'][f['cls']] = dict(fresh_alert, ref=ref, last=C.cap(body, 2000, tail=False), note=note)
                rec['alert'] = 'opened %s' % (ref or 'FAILED: ' + note)
                sync = False
            elif escalate:
                fx.comment(a['ref'], '**Fleet liveness: escalated** at %s: `%s` severity %s -> %s.\n\n%s'
                           % (iso(now), f['cls'], a.get('severity') or 'normal', finding_severity(f), body))
                a.update(severity=finding_severity(f), commented=now, comment_digest=digest)
                rec['alert'] = 'escalated %s' % a['ref']
                sync = True
            elif remind and not human_reopened:
                fx.comment(a['ref'], body)                 # the one reminder per alert_comment_minutes: something material changed
                a.update(commented=now, comment_digest=digest)
                rec['alert'] = 'updated %s' % a['ref']
                sync = True
            else:
                rec['alert'] = ('reopened %s' if human_reopened else 'open %s') % a.get('ref')
            a = st['alerts'].get(f['cls'])
            if sync and a and a.get('ref') and not a.get('cleared') and hasattr(fx, 'ticket_status_block'):
                if alert_room() < write_reserve:
                    rec['lines'] = list(rec['lines']) + ['status block deferred: alert budget reserve']
                    sync = False
            if sync and a and a.get('ref') and not a.get('cleared') and hasattr(fx, 'ticket_status_block'):
                try:
                    fx.ticket_status_block(a['ref'], status_block(f['cls'], a))
                    a.update(status_synced=now, status_synced_occurrences=a.get('occurrences'))
                    if str(rec['alert']).startswith('open '):
                        rec['alert'] = 'open %s (status updated)' % a['ref']
                except Exception as exc:                   # noqa: BLE001 - a failed block write retries next pass
                    rec['lines'] = list(rec['lines']) + ['status block not written: %s' % C.cap(str(exc), 120)]
        else:
            if recur:
                rec['alert'] = 'would reopen %s' % a['ref']
            else:
                rec['alert'] = 'would open' if not a or a.get('cleared') else 'open %s' % a.get('ref')
        if f.get('post'):                                  # deploy-lag in enforce: the release owner's ticket too, on the alert's transitions
            if apply and str(rec['alert']).startswith(('opened', 'updated', 'reopened', 'escalated')):
                rc, note = fx.comment(f['post'], body)
                rec['posted'] = '%s rc=%s %s' % (f['post'], rc, note)
            else:
                rec['posted'] = ('would post to ' if not apply else 'not this pass: ') + f['post']
        elif f.get('mode') == 'warn':
            rec['posted'] = 'warn mode: the Coordinator alert only, nothing posted to the release ticket'
        report.append(rec)
    # A stale land-lag key (its lane superseded / cancelled / deleted: no longer discovered; or its candidate landed)
    # is known absent NOW: skip the clear_seconds hysteresis so its alert closes within this pass (gq-clutter S1).
    clear_after = float(cfg.get('clear_seconds', 600))
    for key, why in stale.items():
        a = st['alerts'].get(key)
        if key in live or not a or a.get('cleared') or not reconcile:
            continue
        a['absent_since'] = min(float(a.get('absent_since') or now), now - clear_after)
        a['close_reason'] = why
    for cls, a in st['alerts'].items():
        if a.get('merged_into') and not a.get('cleared'):
            # A legacy per-class alert whose family ticket was adopted from a sibling: close it ONCE as a duplicate,
            # naming the family ticket (consolidate_alerts). A human-closed or unreadable ticket is never patched.
            target = st['alerts'].get(a['merged_into']) or {}
            if not apply or not a.get('ref') or not target.get('ref'):
                continue
            if alert_room() < write_reserve:
                report.append(dict(cls=cls, title='consolidated', alert='consolidation close deferred: alert budget reserve'))
                continue
            try:
                status_now = fx.ticket_status(a['ref'])
            except Exception:                              # noqa: BLE001
                status_now = None
            if status_now in CLOSED_ALERT_STATUSES:
                a['cleared'] = now
                report.append(dict(cls=cls, title='consolidated', alert='already closed ' + str(a['ref'])))
                continue
            if status_now is None:
                report.append(dict(cls=cls, title='consolidated', alert='consolidation pending on ' + str(a['ref'])))
                continue
            if not a.get('recovery_commented'):
                fx.comment(a['ref'], '**Fleet liveness: consolidated** at %s: `%s` is now tracked on %s (alert key `%s`, '
                           'one ticket per lane family; gq-clutter S1). Closing this one as a duplicate. (goodqa fleet liveness, %s)'
                           % (iso(now), cls, target['ref'], a['merged_into'], DOC))
                a['recovery_commented'] = now
            try:
                fx.ticket_patch(a['ref'], 'duplicate')
                a['cleared'] = now
                report.append(dict(cls=cls, title='consolidated', alert='closed %s as duplicate of %s' % (a['ref'], target['ref'])))
            except Exception:                              # noqa: BLE001 - a close failure retries next pass
                report.append(dict(cls=cls, title='consolidated', alert='consolidation close pending on ' + str(a['ref'])))
            continue
        if 'service-unknown' in live and cls.startswith(('service-failing:', 'service-inert:')):
            # Collection failure is not evidence of service recovery.
            a.pop('absent_since', None)
            continue
        # A disabled detector is known absent even when another collection fails.
        # Unobserved rules still require a successful pass before recovery.
        if not reconcile and not (cls.startswith('git-credentials:') and
                                  cfg.get('git_credentials_mode', 'on') == 'off'):
            continue
        if cls in live:
            a.pop('absent_since', None)
            continue
        if not a.get('cleared'):
            a.setdefault('absent_since', now)
            if now - a['absent_since'] < clear_after:
                continue                                   # hysteresis: a flapping condition keeps one ticket
            is_gc = cls.startswith('git-credentials:')     # for the report verb below
            closed = False
            status_now = None
            if apply and a.get('ref'):
                if alert_room() <= 0:                        # budget spent: defer this close; absent_since persists, retries next pass (goodqa#14007)
                    report.append(dict(cls=cls, title='recovered', alert='recovery close deferred: alert budget spent'))
                    continue
                if not cls.startswith('git-credentials:') and alert_room() < write_reserve:
                    # the `done` PATCH is goodqa_bugs HTTP outside the CLI clamp (red-team delta R2): defer, retry next pass
                    report.append(dict(cls=cls, title='recovered', alert='recovery close deferred: alert budget reserve'))
                    continue
                if cls.startswith('git-credentials:'):
                    # The git-credentials detector is landed-dark (OFF pending hardening); its recovery stays
                    # comment-only (never naming clearing evidence when the detector was switched off), and the
                    # ticket is NOT closed and its status is NOT read here -- that carve-out is owned by the
                    # hardening work, not this filer.
                    if cfg.get('git_credentials_mode', 'on') == 'off':
                        suffix = '; detector switched off (landed dark pending hardening)'
                    else:
                        suffix = '; clearing evidence: ' + a.get('recovery_evidence', 'unavailable')
                    fx.comment(a['ref'], '**Fleet liveness: recovered** at %s: `%s` no longer holds. (goodqa fleet liveness, %s)' % (iso(now), cls, DOC) + suffix)
                    a['cleared'] = now
                else:
                    # The filer owns its own alert: on a confirmed recovery (absent past clear_seconds, or a stale
                    # land-lag key whose lane is gone or landed) it CLOSES the ticket as done, with a one-time evidence
                    # comment, so recovered `^Fleet liveness:` alerts do not pile up open waiting on a human
                    # (goodqa#13953; they are excluded from the lifecycle board's duplicate-closer by
                    # config/ticket-lifecycle.json board.duplicates.skip_patterns). A still-firing finding is in
                    # `live` above and never reaches here, so a live condition is never closed. ticket_status and
                    # ticket_patch are network/API calls that can raise (HTTP, timeout, a refused owner quiet write);
                    # on ANY failure `cleared` stays unset and the pass finishes normally (so the caller still saves
                    # state), the comment is posted only ONCE (the `recovery_commented` marker), and the close retries
                    # next pass -- never wedging the pass or re-commenting every pass (blind review R1). A ticket a
                    # human already closed (done/wont_fix/duplicate/cancelled/on_production) or an unreadable status
                    # is never patched.
                    try:
                        status_now = fx.ticket_status(a['ref'])
                    except Exception:                      # noqa: BLE001 - a status read failure must never end the pass
                        status_now = None
                    if not a.get('recovery_commented'):
                        why = ' (%s)' % a['close_reason'] if a.get('close_reason') else ''
                        fx.comment(a['ref'], '**Fleet liveness: recovered** at %s: `%s` no longer holds%s; closing this alert. '
                                   'A recurrence within %g days reopens it. (goodqa fleet liveness, %s)'
                                   % (iso(now), cls, why, reopen_window / 86400, DOC))
                        a['recovery_commented'] = now
                    if status_now in CLOSED_ALERT_STATUSES:
                        a['cleared'] = now                 # already closed downstream; nothing to patch
                    elif status_now is not None:
                        try:
                            fx.ticket_patch(a['ref'], 'done')
                            closed = True
                            a['cleared'] = now
                        except Exception:                  # noqa: BLE001 - a close failure retries next pass, never wedges
                            pass
                    # status_now is None (unreadable): comment posted once; retry the close when it is readable.
            if not a.get('ref'):
                verb = 'recovered (no ticket)'
            elif not apply:
                verb = ('would note recovery on ' if is_gc else 'would close ') + str(a['ref'])
            elif is_gc:
                verb = 'noted recovery on ' + str(a['ref'])
            elif closed:
                verb = 'closed ' + str(a['ref'])
            elif status_now in CLOSED_ALERT_STATUSES:
                verb = 'already closed ' + str(a['ref'])
            else:
                verb = 'recovery noted, close pending on ' + str(a['ref'])
            report.append(dict(cls=cls, title='recovered', alert=verb))
    try:                              # clear the clamp so later direct ticket calls (reopen_closed) are not throttled
        fx._alert_deadline = None
    except (AttributeError, TypeError):
        pass
    return report


def collect_deploy_lag(p, spec, cfg, fx, now, left=None):
    """One product -> the reduced lag (or error). Never raises; every call is bounded by its own timeout AND the pass's remaining
    deploy-lag budget (left(): seconds), so slow sources can never push the pass past the unit's TimeoutStartSec (B1)."""
    left = left or (lambda: 1e9)

    def budget(default):
        t = min(float(default), left())
        if t < 3:
            raise RuntimeError('deploy-lag budget spent before this read')
        return int(t)
    d = dict(at=now)
    try:
        rec = None
        if spec.get('status_cmd'):
            rec, _, _ = fx.json_cmd(spec['status_cmd'], timeout=budget(30))
            d['status_record'] = {k: rec.get(k) for k in ('outcome', 'reason', 'finished', 'finished_at', 'checked', 'sha', 'main')} \
                if isinstance(rec, dict) else None
        live = live_from_status(rec)
        if live:                             # a status line proves what is live only while it is fresh
            seen = max(ts((rec or {}).get(k)) for k in ('checked', 'finished', 'finished_at'))
            if not seen or now - seen > float(cfg.get('deploy_lag_status_max_age_seconds', 900)):
                live = None
        d['live_source'] = 'status line'
        if not live and spec.get('live_url'):
            v = fx.http_json(spec['live_url'], timeout=budget(15))
            live, d['live_source'], d['version'] = v.get(spec.get('live_field', 'sourceSha')), spec['live_url'], v.get('version')
        if not live and spec.get('live_cmd'):
            v, rc, err = fx.json_cmd(spec['live_cmd'], timeout=budget(spec.get('live_timeout', 90)))
            live, d['live_source'] = (v or {}).get(spec.get('live_field', 'sourceSha')), ' '.join(spec['live_cmd'])
        if not (isinstance(live, str) and SHA40.match(live)):
            return dict(d, error='live sha unreadable (%s)' % d.get('live_source'))
        d['live'] = live
        ignore = list(cfg.get('deploy_lag_ignore') or []) + list(spec.get('deploy_lag_ignore') or [])
        cmp = fx.gh_compare(spec['github'], live, timeout=budget(30))
        pushes = []
        if cmp.get('ahead_by') and hasattr(fx, 'gh_pushes'):
            pushes = fx.gh_pushes(spec['github'], timeout=budget(20)) or []
            unshipped = {c.get('sha') for c in cmp.get('commits') or []}
            mine = sorted([x for x in pushes if x.get('after') in unshipped], key=lambda x: ts(x.get('ts')))
            for x in mine[:int(cfg.get('deploy_lag_push_checks', 6))]:   # oldest first, until one changes product code
                if not (SHA40.match(str(x.get('before') or '')) and hasattr(fx, 'gh_push_files')) or left() < 10:
                    break
                try:
                    x['files'] = fx.gh_push_files(spec['github'], x['before'], x['after'], timeout=budget(20))
                except Exception:  # noqa: BLE001 - unknown files: the push counts (conservative)
                    break
                if any(not any(re.search(pt, f) for pt in ignore) for f in x['files'] or []):
                    break
        d.update(reduce_compare(cmp, now, ignore, pushes))
    except (Exception, SystemExit) as e:  # noqa: BLE001 - one product's read failure is a report line, never the end of the pass
        d['error'] = '%s: %s' % (type(e).__name__, C.cap(str(e), 200))
    return d


def keep_deploy_lag_reading(old, new, now):
    """A failed read retains the last good values and ages them, never a false recovery."""
    if new.get('error'):
        fails = int(old.get('failures') or 0) + 1
        base = old if old.get('live') else new
        new = dict(base, at=now, error=new['error'], failures=fails, stale_since=old.get('stale_since') or now)
        if new.get('landed'):
            new['minutes'] = round((now - new['landed']) / 60.0, 1)
    elif (old.get('live') == new.get('live') and new.get('live')
          and old.get('product_files') and new.get('product_files')
          and old.get('ahead') and new.get('ahead') and old.get('landed') and new.get('landed')
          and old.get('clock_push') and old['clock_push'] not in new.get('pushes_seen', [])):
        # The bounded activity response can lose older pushes. A fresh push or
        # retry is not recovery: retain the observed backlog's clock until live
        # advances or the deployable diff clears.
        if old['landed'] < new['landed']:
            new = dict(new, landed=old['landed'], minutes=round((now - old['landed']) / 60.0, 1),
                       clock_push=old['clock_push'],
                       since_source=old.get('since_source', 'previously observed unshipped product change'))
    return new


def deploy_lag(cfg, fx, st, now, clock=time.monotonic, left=None):
    """Per product, re-read at most every deploy_lag_every_seconds (the Timbar readback takes about a minute), within
    deploy_lag_budget_seconds for the whole collection; cached in state. A failed read keeps the last good reading (marked stale
    with the error and a failure count), so a broken source never clears an open alert (B2)."""
    if cfg.get('deploy_lag_mode', 'warn') == 'off' or not hasattr(fx, 'gh_compare'):
        return {}
    cache = st.setdefault('deploy_lag', {})
    every = float(cfg.get('deploy_lag_every_seconds', 600))
    if left is None:
        start, total = clock(), float(cfg.get('deploy_lag_budget_seconds', 80))
        left = lambda: total - (clock() - start)
    for p, spec in sorted((cfg.get('deploy_lag_products') or {}).items()):
        old = cache.get(p) or {}
        if now - float(old.get('at') or 0) >= every and left() >= 5:
            new = collect_deploy_lag(p, spec, cfg, fx, now, left)
            cache[p] = keep_deploy_lag_reading(old, new, now)
        elif old.get('landed'):
            cache[p] = dict(old, minutes=round((now - old['landed']) / 60.0, 1))
    for p in [k for k in cache if k not in (cfg.get('deploy_lag_products') or {})]:
        cache.pop(p)
    return cache


def land_lag_state_alarm(error, st, cfg, fx, apply, now, durable=False):
    """Deliver gate-state failures before remote collection; retain failed notifications for retry."""
    pending = st.get('land_lag_state_alarm') or {}
    if not error and not (pending.get('pending') or pending.get('ticket_pending')):
        if apply and st.pop('land_lag_state_alarm', None) is not None and durable:
            save_state(st)
        return []
    message = error or pending['message']
    finding = dict(cls='land-lag-state-unreadable', title='admission gate state unreadable',
                   lines=[message], remedies=[])
    if apply:
        # Persist the intent before either delivery call. A process interruption retries next pass.
        if error and (not pending or pending.get('message') != message):
            pending = dict(message=message, pending=True, ticket_pending=True)
            st['land_lag_state_alarm'] = pending
        if durable:
            save_state(st)
    try:
        report = act([finding], st, cfg, fx, apply, now, reconcile=False)
    except (OSError, RuntimeError, C.CliError) as exc:
        report = [dict(finding, alert='FAILED: ' + str(exc))]
    if apply:
        pending['ticket_pending'] = not bool((st['alerts'].get(finding['cls']) or {}).get('ref'))
    if apply and pending.get('pending'):
        try:
            result = fx.hawk('%s fleet liveness: land-lag-state-unreadable: %s; @coordinator' % (iso(now), message))
            # Effects.hawk returns the journal command's exit status; test doubles may return None.
            if result is None or result[0] == 0:
                pending['pending'] = False
            else:
                pending['last_error'] = str(result)
        except (OSError, RuntimeError, C.CliError) as exc:
            pending['last_error'] = str(exc)
    if apply and not error and not (pending.get('pending') or pending.get('ticket_pending')):
        st.pop('land_lag_state_alarm', None)
    if apply and durable:
        save_state(st)
    return report if error else []


def _act_budget(cfg, elapsed):
    """The seconds act()'s ticket-API phase may spend this pass: the `act_budget_seconds` ceiling, never more than
    what is left of `pass_budget_seconds` after `elapsed` seconds of collection, and never below the floor so a pass
    always makes some progress (goodqa#14007)."""
    return max(float(cfg.get('act_budget_floor_seconds', 10)),
               min(float(cfg.get('act_budget_seconds', 120)),
                   float(cfg.get('pass_budget_seconds', 240)) - elapsed))


def run_pass(cfg, fx, apply, now=None, state=None):
    now = now or time.time()
    pass_mono = time.monotonic()
    # act()'s alert-I/O budget: never run the ticket phase past pass_budget_seconds, whatever collection cost,
    # so the pass (plus save_state/journal after) finishes under the unit's TimeoutStartSec (goodqa#14007).
    def act_budget():
        return _act_budget(cfg, time.monotonic() - pass_mono)
    st = state if state is not None else load_state()
    gate_error = load_land_lag(st) if state is None else None
    early_report = land_lag_state_alarm(gate_error, st, cfg, fx, apply, now, durable=state is None)
    health = {}
    if hasattr(fx, 'host_health'):
        for host in ('dev', 'dev2'):
            try:
                health[host] = fx.host_health(host)
            except (OSError, RuntimeError, subprocess.SubprocessError, C.CliError):
                health[host] = dict(error='host collection unknown')
    health_findings = host_health_findings(health, st, cfg, now)
    try:
        known = dict(st.get('land_lag_observed') or {}, **(st.get('land_lag') or {}))
        reading = dict(rows=[], errors=[])
        if isinstance(fx, Effects):
            discovery = fx.land_lag_rows(known, dict(cfg, land_lag_discovery_only=True))
            land_lag_findings(discovery, st, cfg, now)
            if apply and not gate_error:
                save_land_lag(st, now, errors=discovery['errors'])
            known.update(st.get('land_lag') or {})
            # gorunner task states (gq-clutter S1 supersede close) at most every land_lag_runner_states_seconds; a
            # recent cached read stands in between, an old one is dropped (no evidence beats stale evidence).
            cached = st.get('land_lag_runner_states') if isinstance(st.get('land_lag_runner_states'), dict) else {}
            st['land_lag_runner_states'] = cached
            every_states = float(cfg.get('land_lag_runner_states_seconds', 600))
            ask = now - float(cached.get('attempted') or cached.get('at') or 0) >= every_states
            if ask:
                cached['attempted'] = now          # a failed or timed-out read is not retried every pass (red-team F5)
            reading = fx.land_lag_rows(known, dict(cfg, land_lag_runner_states=ask))
            if isinstance(reading.get('runner_states'), dict):
                cached.update(at=now, states=reading['runner_states'])
            elif isinstance(cached.get('states'), dict) and now - float(cached.get('at') or 0) < 3 * every_states:
                reading = dict(reading, runner_states=cached['states'])
        elif hasattr(fx, 'land_lag_rows'):
            reading = fx.land_lag_rows(known)
        observed = st.setdefault('land_lag_observed', {})
        observed.update({row['key']: row for row in reading.get('rows') or [] if row.get('key')})
        gate_findings = land_lag_findings(reading, st, cfg, now)
        if gate_error:
            gate_findings.append(dict(cls='land-lag-state-unreadable', title='admission gate state unreadable', lines=[gate_error], remedies=[]))
        # Persist the admission cap before slower snapshot/deploy/ticket calls, even if those later time out.
        if apply and not gate_error:
            save_land_lag(st, now, errors=reading['errors'])
        snap = fx.snapshot()
        cfg = dict(cfg, floor=fx.lane_floor_floor() or cfg.get('floor_default', 40))
        lf_runs = parse_lane_floor(fx.lane_floor_lines(iso(now - 1800).replace('T', ' ').rstrip('Z')))
        sample = live_sample(snap, cfg, lf_runs, fx.refusals(), now)
        start = time.monotonic()
        left = lambda: float(cfg.get('deploy_lag_budget_seconds', 80)) - (time.monotonic() - start)
        sample['deploy_lag'] = deploy_lag(cfg, fx, st, now, left=left)
        sample['ship_watch'] = fx.ship_watch() if hasattr(fx, 'ship_watch') else {}
        sample['autocommit'] = fx.autocommit_state() if hasattr(fx, 'autocommit_state') else {}
        if cfg.get('git_credentials_mode', 'on') == 'on' and hasattr(fx, 'git_credentials'):
            try:
                credential_readings = fx.git_credentials()
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                credential_readings = {host: dict(status='UNKNOWN', findings=[]) for host in
                                       (st.get('git_credentials') or {C._host(): {}})}
            for host, reading in credential_readings.items():
                health_findings += git_credentials_findings(reading, st, host)
        findings = (gate_findings + evaluate(sample, st, cfg) + autocommit_findings(sample, st, cfg) +
                    service_findings(sample, st, cfg) +
                    health_findings)
    except (OSError, RuntimeError, subprocess.SubprocessError, C.CliError) as exc:
        for host in (list(st.get('git_credentials', {})) if cfg.get('git_credentials_mode', 'on') == 'on' else []):
            health_findings += git_credentials_findings(dict(status='UNKNOWN', findings=[]), st, host)
        health_report = act(health_findings, st, cfg, fx, apply, now, reconcile=False, alert_budget=act_budget())
        if apply and state is None:
            save_state(st)
        return dict(at=iso(now), apply=apply, findings=early_report + health_report, collection_error=getattr(exc, 'msg', str(exc)),
                    running=None, queued=None, floor=cfg.get('floor', cfg.get('floor_default', 40)),
                    drain=None, merging=None)
    report = act(findings, st, cfg, fx, apply, now, sample=sample, left=left, alert_budget=act_budget())
    # loop-cap metric (coordinator 2026-10-23 ~22:4xZ): the share of running lanes the autopilot holds as looping
    running_ids = {r.get('id') for r in (snap.get('rows') or {}).get('running') or []}
    looping = (fx.autopilot_looping() if hasattr(fx, 'autopilot_looping') else set()) & running_ids
    share = round(len(looping) / len(running_ids), 3) if running_ids else 0.0
    out = dict(at=iso(now), apply=apply, running=sample['running'], queued=sample['queued'], floor=cfg['floor'],
               drain=bool(sample['drain']), merging=sample['merging'], findings=report,
               deploy_lag={p: {k: d.get(k) for k in ('live', 'main', 'ahead', 'minutes', 'error', 'live_source')}
                           for p, d in sorted((sample.get('deploy_lag') or {}).items())},
               looping_running=sorted(looping), looping_share=share)
    if apply:
        C.journal('goodqa-liveness', dict(event='pass', lane=LANE, running=sample['running'], queued=sample['queued'],
                                          deploy_lag={p: dict(ahead=d.get('ahead'), minutes=d.get('minutes'), error=d.get('error'),
                                                              failures=d.get('failures'))
                                                      for p, d in sorted((sample.get('deploy_lag') or {}).items())},
                                          looping=len(looping), looping_share=share,
                                          findings=[dict(cls=r['cls'], alert=r.get('alert'), remedies=[x.get('result') for x in r.get('remedies') or []])
                                                    for r in report]))
        if any(r.get('remedies') or (r.get('alert') or '').startswith('opened') for r in report):
            fx.hawk('%s fleet liveness: %s' % (iso(now), '; '.join('%s %s' % (r['cls'], r.get('alert')) for r in report)))
        if state is None:
            save_state(st)
    return out


def replay(cfg, fx, since, until):
    snap = fx.snapshot(replay_since=since)
    cfg = dict(cfg, floor=fx.lane_floor_floor() or cfg.get('floor_default', 40))
    lf_runs = parse_lane_floor(fx.lane_floor_lines(since.replace('T', ' ').rstrip('Z')))
    samples = replay_samples(snap['lines'], snap.get('repo_of') or {}, cfg, lf_runs, fx.refusals(), ts(since), ts(until),
                             train_verdicts=snap.get('train_verdicts'), merge_trains=snap.get('merge_trains'))
    st = dict(since={}, alerts={}, remedied={})
    first, open_ = [], {}
    for s in samples:
        found = {f['cls']: f for f in evaluate(s, st, cfg)}
        for cls, f in found.items():
            if cls not in open_:
                open_[cls] = s['at']
                first.append(dict(at=iso(s['at']), cls=cls, title=f['title'], lines=f['lines'][:4]))
        for cls in list(open_):
            if cls not in found:
                first.append(dict(at=iso(s['at']), cls=cls, title='cleared after %.0f min' % ((s['at'] - open_.pop(cls)) / 60.0)))
    return dict(since=since, until=until, samples=len(samples), lane_floor_runs=len(lf_runs),
                lane_floor_from=iso(lf_runs[0]['at']) if lf_runs else None, events=first)


# ------------------------------------------------------------------------------------------------ CLI
class _Lock:
    def __enter__(self):
        p = state_path() + '.lock'
        os.makedirs(os.path.dirname(p), exist_ok=True)
        self.f = open(p, 'w')
        try:
            fcntl.flock(self.f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise C.CliError('another fleet liveness pass is running', 75)
        return self

    def __exit__(self, *a):
        self.f.close()


def human(rep):
    if 'events' in rep:
        out = ['liveness replay %s .. %s: %d samples; lane-floor journal from %s' % (rep['since'], rep['until'], rep['samples'],
                                                                                     rep['lane_floor_from'])]
        for e in rep['events']:
            out.append('  %s %-24s %s' % (e['at'][11:16], e['cls'], e['title']))
            for line in e.get('lines') or []:
                out.append('        %s' % C.cap(line, 150, tail=False))
        return '\n'.join(out)
    out = ['fleet liveness %s at %s: running %s, queued %s, floor %s, drain %s, merging %s, looping %d of running (%.0f%%)' % (
        'APPLY' if rep['apply'] else 'dry run', rep['at'], rep['running'], rep['queued'], rep['floor'], rep['drain'], rep['merging'],
        len(rep.get('looping_running') or []), 100 * (rep.get('looping_share') or 0))]
    for f in rep['findings']:
        out.append('  %s: %s [%s]' % (f['cls'], f['title'], f.get('alert')))
        for line in f.get('lines') or []:
            out.append('      %s' % C.cap(line, 160, tail=False))
        for r in f.get('remedies') or []:
            out.append('      remedy %s %s: %s' % (r['kind'], r.get('unit') or r.get('rule'), r['result']))
        if f.get('posted'):
            out.append('      release ticket: %s' % f['posted'])
    for p, d in sorted((rep.get('deploy_lag') or {}).items()):
        out.append('  deploy lag %s: %s' % (p, d.get('error') or 'live %s, main %s, %s commit(s) ahead, %s min' % (
            (d.get('live') or '?')[:12], (d.get('main') or '-')[:12], d.get('ahead'), d.get('minutes'))))
    if rep.get('collection_error'):
        out.append('  collection unavailable: ' + rep['collection_error'])
    elif not rep['findings']:
        out.append('  healthy: nothing to do')
    return '\n'.join(out)


CLOSED_ALERT_STATUSES = frozenset(('done', 'wont_fix', 'duplicate', 'cancelled', 'on_production'))
DUP_NOTE_SECONDS = 3600
DUP_RETRY_SECONDS = 600


def dup_note_line(f, ref, now):
    """The ONE line appended to a canonical ticket for an alert closed as its duplicate: finding, alert id, time."""
    title = re.sub(r'[\r\n`@]+', ' ', C.cap(str(f.get('title') or ''), 120))
    cls = re.sub(r'[\r\n`@]+', ' ', C.cap(str(f['cls']), 120))
    return defang_markers('Fleet liveness: `%s` (%s) still holds at %s; alert %s is closed as a duplicate of this ticket.' % (
        cls, title, iso(now), ref))


def reopen_closed(cfg, fx, apply=False, limit=25, state=None, now=None):
    """Fresh detector evidence is mandatory; a stored uncleared alert alone is not evidence of a live condition."""
    import copy
    now = time.time() if now is None else now
    st = load_state() if state is None else state
    rep = run_pass(cfg, fx, False, now=now, state=copy.deepcopy(st))
    if rep.get('collection_error'):
        raise C.CliError('cannot repair alerts: ' + rep['collection_error'], C.EXIT_UNAVAILABLE)
    live = {f['cls'] for f in rep['findings'] if f.get('alert') != 'suppressed'
            and f.get('title') not in ('recovered', 'consolidated')}   # recovery rows are not live (red-team F7)
    rows = []
    for cls, a in st['alerts'].items():
        if a.get('cleared') or cls not in live or not a.get('ref'):
            continue
        status = fx.ticket_status(a['ref'])
        if status not in CLOSED_ALERT_STATUSES:
            continue
        if status == 'duplicate':
            try:
                if fx.duplicate_survivor(a['ref']):
                    continue              # followed to its open canonical ticket, not reopened
            except Exception:             # noqa: BLE001 - an unreadable canonical ticket never reopens a human close
                continue
        rows.append(dict(ref=a['ref'], cls=cls, status=status, copy=fx.moved_copy(a['ref'])))
    repaired = []
    if apply:
        for row in rows[:limit]:
            fx.ticket_patch(row['ref'], 'triage')
            st['alerts'][row['cls']]['reopened'] = now
            fx.comment(row['ref'], 'Reopened: fresh fleet liveness evaluation confirms `%s` still holds.' % row['cls'])
            if row['copy']:
                fx.undo_copy(row['ref'], row['copy'])
            repaired.append(row['ref'])
        if state is None:
            save_state(st)
    return dict(alerts=rows, applied=apply, reopened=repaired)


def cmd_liveness(a):
    cfg = load_config()
    if getattr(a, 'what', None) == 'overrides':
        import rule_overrides as RO
        if a.clear:
            if C.is_apply(a):
                C.need_reason(a)
                C.require_ticket(a)
                name, key = a.clear.split('.', 1)
                had = RO.clear(name, key)
                C.journal('goodqa-liveness', dict(event='override-clear', lane=LANE, key=a.clear, had=had, reason=a.reason))
            C.emit(dict(cleared=a.clear, applied=C.is_apply(a), overrides=RO.load()), a.json, lambda o: json.dumps(o, indent=1))
            return
        C.emit(RO.load(), a.json, lambda o: json.dumps(o, indent=1))
        return
    fx = Effects(cfg)
    if getattr(a, 'what', None) == 'reopen-closed':
        apply = C.is_apply(a)
        if apply:
            C.need_reason(a)
            C.require_ticket(a)
        if a.limit < 1:
            raise C.CliError('--limit must be positive')
        with _Lock():
            rep = reopen_closed(cfg, fx, apply, a.limit)
        C.emit(rep, a.json, lambda o: json.dumps(o, indent=1))
        return
    if a.replay:
        if not a.since:
            raise C.CliError('refused: --replay needs --since ISO')
        C.emit(replay(cfg, fx, a.since, a.until or iso(time.time())), a.json, human)
        return
    apply = C.is_apply(a)
    if apply:
        C.need_reason(a)
        C.require_ticket(a)
    with _Lock():
        rep = run_pass(cfg, fx, apply)
    C.emit(rep, a.json, human)


def register_fleet(fl):
    p = C.json_flag(C.mutating(fl.add_parser('liveness', help='is the fleet moving? measure, diagnose, remedy (lane-floor, autopilot, a '
                                                              'refusing rule to warn; complete failed-unit census with unknown/unparsed/count alarms, journal tails, output-leak/disk-fill checks, mapped timer stops in enforce mode) and alert; safety/unknown land-lag caps ordinary admission; safety clears with candidate-bound independent activation/refusal proof, complete author identity and monotonic aliases; captured candidate identity must agree with the worktree; unidentified debt requires stable task/branch identity; state-error alarms precede collection and retry delivery; re-read deploy lag before alert writes, every 2 min (dry run unless --apply)')))
    p.description = ('Live host health checks every failed unit type in user/system scopes on DEV and dev2. '
                     'Unparsed lines and census count mismatches alert; unreadable census is RED after '
                     'unit_census_unknown_samples (default 3), clearing after two clean readings. '
                     'New failures retain a scrubbed journal tail (40 lines, at most 4096 bytes). '
                     'Ignore globs require a reason. Enforce stops only mapped service timers.')
    p.add_argument('what', nargs='?', choices=('overrides', 'reopen-closed'), help='overrides: rule modes flipped to warn; reopen-closed: list live closed alerts, reopen originals and retire moved copies with --apply --ticket T --reason R')
    p.add_argument('--limit', type=int, default=25, help='reopen-closed: maximum repairs per apply pass (default 25)')
    p.add_argument('--clear', help='with overrides: CONFIG.KEY to remove (with --apply)')
    p.add_argument('--replay', action='store_true', help='run the detector over the recorded timeline instead (read-only)')
    p.add_argument('--since', help='replay start, ISO UTC')
    p.add_argument('--until', help='replay end, ISO UTC (default now)')
    p.set_defaults(fn=cmd_liveness)
