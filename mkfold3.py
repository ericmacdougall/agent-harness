"""Plan area umbrellas for a project fold (main ruling 2026-11-09, goodqa#14977). usage: mkfold.py <project> [--create]
Candidates: open, non-epic, reporter is the user or an agent (no customers/teammates), not yates/optinrouter, no open security finding (label security), not already an umbrella.
All statuses fold (state kept in a ledger row). Children close wont_fix, never done. Writes plan13-<project>.jsonl; with --create also creates the area umbrellas."""
import json, sys, re, time, uuid, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
proj = sys.argv[1]
CREATE = '--create' in sys.argv
R = {}
for l in open(T + 'open_now9.jsonl'):
    j = json.loads(l)
    R[j['id']] = j
C = {o['id']: o for o in json.load(open(T + 'classes9.json'))}
J = json.load(open(T + 'join6.json'))
projects = {p['slug']: p for p in json.load(open(T + 'projects.json'))}
OKREP = {'Eric MacDougall', 'Claude (agent)'}
AREAS = {
    'goodqa': [
        ('Harness, fabric and guard tooling', r'^(\[?[a-z ]*\]? ?)?(harness|fabric|command guard|peer_review|ahd|rw-|selfhost|merge_gate)'),
        ('OptinRouter and data suite', r'^(optin|\[optin)|optin-|data suite|datasuite|scanner|marketplace'),
        ('Runner briefs: GoodQA product work', r'^goodqa-|^gq-|^gqres|^gqf|^req-qacp|^paul-'),
        ('Runner, fleet, lanes and harness', r'runner|fleet|lane|harness|hive|gorunner|brief|dispatch|failover|autopilot|pairing|daemon|worker'),
        ('Desktop, remote control and browser', r'desktop|remote|browser|extension|screen|electron|agent-browser'),
        ('OptinRouter and data suite', r'optin|data suite|datasuite|scanner|marketplace'),
        ('QAC, chat, messages and AI assistant', r'qac|chat|message|assistant|ai-first|conversation|dm\b|thread'),
        ('CRM, GHL parity, outreach and mail', r'crm|ghl|outreach|mail|contact|lead|sequence|campaign|social|calendar|schedul'),
        ('UX, UI, web app and accessibility', r'\bux\b|\bui\b|ux p|click-review|accessib|contrast|focus|modal|button|layout|dark mode|mobile app|responsive|settings'),
        ('Auth, orgs, billing and security', r'auth|login|oauth|sso|token|billing|stripe|org\b|permission|privacy|secret|vault'),
        ('Release, deploy, CI and infra', r'release|deploy|ci\b|pipeline|rollout|migration|backup|disk|dev2|t2-dev|ssh|install|gate|guard|hook'),
        ('Tickets, projects, planning and reporting', r'ticket|project|follow-?up|dashboard|report|sprint|planning|epic|triage|pipeline stage'),
        ('Content, sites and docs', r'content|site|blog|docs|seo|landing|course|lesson|podcast'),
    ],
    'parent-proof': [
        ('Android parent app and device', r'android|device|tablet|kiosk|launcher|accessibility service|sign-?in|pairing|app kill|stay-?awake|battery'),
        ('Windows and macOS agent', r'windows|macos|mac\b|agent runs|session 0|bedtime|black'),
        ('iOS and mobile redesign', r'ios\b|iphone|redesign|parent mobile|testflight'),
        ('Games, flagship and child experience', r'game|flagship|profile|star|score|phaser|play|child|kid|power-up|modal'),
        ('Web, marketing, admin and CSP', r'marketing|admin|csp|bundle|seo|site|web\b|landing|gallery'),
        ('Release, qualification, gates and CI', r'release|gate|qualif|ci\b|deploy|smoke|prod|runbook|walker|store|play store|aab'),
        ('API, auth, push and security', r'api|auth|push|notification|rate limit|uuid|token|mail|otp|security|privacy'),
        ('Operations, tests and tooling', r'test|ops|runbook|script|seed|demo|fixture|log|monitor'),
    ],
    'work-tracker-automatic': [('Lane mirrors and lane work', r'^\[lane\]|lane'), ('Console, takeover and hosts', r'\[console\]|takeover|console|host|dev2|t2-dev'), ('System design and other work-tracker items', r'.')],
}.get(proj, [('All areas', r'.')])
AR = [(n, re.compile(p, re.I)) for n, p in AREAS]


def area(r):
    t = (r['title'] + ' ' + ' '.join(r['labels'])).lower()
    for n, p in AR:
        if p.search(t):
            return n
    return 'Other'


done = set()
for f in ('done5.jsonl', 'done7.jsonl', 'done9.jsonl', 'done10.jsonl', 'done11.jsonl', 'done12.jsonl', 'done13.jsonl', 'done14.jsonl', 'done15.jsonl'):
    try:
        for l in open(T + f):
            j = json.loads(l)
            if j['result'] == 'closed':
                done.add(j['id'])
    except FileNotFoundError:
        pass
rows = collections.defaultdict(list)
skip = collections.Counter()
for i, r in R.items():
    if r['_proj'] != proj or i in done:
        continue
    if r['type'] == 'epic' or (r['title'].lower().startswith(('umbrella', 'merged, awaiting', 'on dev, awaiting', 'lane mirrors ended', 'area:', 'live work:'))) or ('umbrella' in [l.lower() for l in r['labels']] or 'live-work-combined' in [l.lower() for l in r['labels']]):
        skip['epic-or-umbrella'] += 1; continue
    if (r.get('reporter') or {}).get('name') not in OKREP or r.get('externalReporterId'):
        skip['reporter-not-user-or-agent'] += 1; continue
    if 'security' in [l.lower() for l in r['labels']]:
        skip['security-finding'] += 1; continue
    if 'yates' in r['_proj'] or r['_proj'] in ('optinrouter', 'apex_app_pos'):
        skip['excluded-project'] += 1; continue
    o = C.get(i, {})
    pr = sorted(set(J['merged'].get('%s#%d' % (proj, r['number']), [])))[:2]
    own = (r.get('assignee') or {}).get('name') or ('agent-key ' + r['assignedAgentApiKeyId'][:8] if r.get('assignedAgentApiKeyId') else '-')
    active = bool({'wal-72h', 'active-agent'} & set(o.get('prot', [])))
    rows[area(r)].append({'id': i, 'n': r['number'], 'status': r['status'], 'rev': r['revision'], 'title': r['title'], 'proj': 'framebright/' + proj if proj in ('goodqa', 'parent-proof', 'work-tracker-automatic') else proj,
                          'cc': r.get('commentCount') or 0, 'upd': r['updatedAt'], 'owner': own, 'pr': ', '.join(pr) or '-', 'active': active, 'priority': r.get('priority')})
print(proj, 'eligible', sum(len(v) for v in rows.values()), 'skipped', dict(skip))
for a, v in sorted(rows.items(), key=lambda x: -len(x[1])):
    print('  ', len(v), a, '(active %d)' % sum(1 for x in v if x['active']))
if not CREATE:
    sys.exit(0)
P = projects[proj]
out = []
for a, kids in rows.items():
    desc = 'Area umbrella "%s" for %s (goodqa#14977 under-300 push, %s). %d tickets were merged here as wont_fix, never done. Each one has a checklist row in the ledger comments below: link, title, state at merge time, owner, PR and last activity. Tickets under active work (WAL or commit in the last 72h) are marked ACTIVE and keep working here: the owner posts in this umbrella. Reopen any child by setting its status back to the state in its row.' % (a, proj, time.strftime('%Y-%m-%d', time.gmtime()), len(kids))
    iss = None
    try:
        for l in open(T + 'plan13-%s.jsonl' % proj):
            g0 = json.loads(l)
            if g0.get('area') == a:
                iss = {'id': g0['umbrella']['id'], 'number': g0['umbrella']['number']}
    except FileNotFoundError:
        pass
    if iss is None:
        r = gq.call('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title='Area: %s [%s]' % (a, proj), description=desc, type='epic', labels=['umbrella', 'cleanup-2026-11h', 'keep-open'], operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'fold15|%s|%s' % (proj, a)))))
        iss = r.get('issue') if isinstance(r, dict) else None
    if not iss:
        print('UMBRELLA FAIL', a, str(r)[:150]); continue
    out.append({'kind': 'fold', 'umbrella': {'id': iss['id'], 'number': iss['number'], 'slug': proj}, 'note': '', 'area': a, 'children': sorted(kids, key=lambda x: -x['n'])})
with open(T + 'plan17-%s.jsonl' % proj, 'w') as f:
    for g in out:
        f.write(json.dumps(g) + '\n')
print('umbrellas', len(out), [(g['umbrella']['number'], len(g['children'])) for g in out])
