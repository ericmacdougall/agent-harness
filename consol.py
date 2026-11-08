"""Under-300 phase 2: merge agent-filed tickets into their umbrella, reversibly (owner ab8a7d1b, 2026-11-08).
Lives in ticket-cleanup/. usage: python3 consol.py PLAN.jsonl [max_groups]
PLAN lines: {"kind":"parent|cluster|noise","umbrella":{"id","number","slug"}|null,"note":str,"children":[{"id","n","status","rev","title","proj"}]}
Per group: fresh get_issue per child (skip if no longer triage/backlog/todo, owner appeared, changed), copy child comment excerpts into a ledger
comment on the umbrella (idempotent operationId), then bulk close children wont_fix with a note linking the umbrella.
State: done5.jsonl, closes5.tsv, snapshots5/. Undo: python3 reopen5.py [--apply]
"""
import sys, os, json, time, uuid, hashlib
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(HERE)
import gq

TAG = 'cleanup-2026-11c'
TRACK = '861b09c7-cea1-4d8c-96f9-46242f652dbe'  # goodqa#14977
OKSTAT = {'triage', 'backlog', 'todo'}


def call(tool, args):
    for k in range(25):
        d = gq.call(tool, args)
        if isinstance(d, dict) and isinstance(d.get('error'), dict) and d['error'].get('code') == 'rate_limited':
            time.sleep(min(60, 4 * (k + 1)))
            continue
        return d
    return d


def load_done():
    s = {}
    if os.path.exists('done5.jsonl'):
        for l in open('done5.jsonl'):
            try:
                j = json.loads(l)
                if j.get('why') != 'owner-appeared':
                    s[j['id']] = j
            except Exception:
                pass
    return s


def log_done(rec):
    with open('done5.jsonl', 'a') as f:
        f.write(json.dumps(rec) + '\n')


def tsv(row):
    new = not os.path.exists('closes5.tsv')
    with open('closes5.tsv', 'a') as f:
        if new:
            f.write('time\tproject\tnumber\tkind\tfrom\tto\tumbrella\n')
        f.write('\t'.join(str(x).replace('\t', ' ').replace('\n', ' ') for x in row) + '\n')


def inspect(c, noise=False):
    d = call('get_issue', {'issueId': c['id']})
    i = d.get('issue') if isinstance(d, dict) else None
    if not i:
        return c, None, 'unreadable', []
    if i['status'] not in OKSTAT:
        return c, i, 'status-moved:' + i['status'], []
    if int(i['revision']) != int(c['rev']) and i['status'] != c['status']:
        return c, i, 'changed', []
    if i.get('assigneeId') or i.get('currentOwnerId') or i.get('developerId') or (i.get('assignedAgentApiKeyId') and i['status'] == 'todo' and not noise):
        return c, i, 'owner-v2', []
    ex = []
    if int(i.get('commentCount') or 0) > 0:
        r = call('get_issue_comments', {'issueId': c['id']})
        cs = [x for x in (r.get('comments') or []) if x.get('kind', 'comment') != 'system' and TAG not in (x.get('body') or '')] if isinstance(r, dict) else []
        for x in cs[-2:]:
            ex.append('%s %s' % (x.get('createdAt', '')[:10], (x.get('body') or '').replace('\n', ' ')[:300]))
    return c, i, None, ex


def run(plan_file, ngroups):
    plan = [json.loads(l) for l in open(plan_file)]
    g = 0
    for grp in plan:
        if g >= ngroups:
            break
        done = load_done()
        kids = [c for c in grp['children'] if c['id'] not in done]
        if not kids:
            continue
        g += 1
        U = grp.get('umbrella')
        for s in range(0, len(kids), 200):
            part = kids[s:s + 200]
            with ThreadPoolExecutor(int(os.environ.get('THREADS', '5'))) as ex:
                res = list(ex.map(lambda c: inspect(c, grp['kind'] == 'noise'), part))
            ok = []
            for c, i, why, exc in res:
                if why:
                    log_done({'id': c['id'], 'n': c['n'], 'result': 'skipped', 'why': why})
                else:
                    ok.append((c, i, exc))
            if not ok:
                continue
            if U:
                for k in range(0, len(ok), 20):
                    blk = ok[k:k + 20]
                    lines = ['Consolidated members (goodqa#14977 under-300 push, %s). Each ticket below was closed as merged into this umbrella; its full history stays on the closed ticket and it can be reopened (snapshot in the cleanup work dir).' % time.strftime('%Y-%m-%d', time.gmtime()), '']
                    for c, i, exc in blk:
                        lines.append('- #%s [%s, %s] %s' % (c['n'], i['status'], i.get('priority'), (i.get('title') or '')[:160]))
                        for e in exc:
                            lines.append('    - ' + e)
                    body = '\n'.join(lines)[:15000]
                    opid = str(uuid.uuid5(uuid.NAMESPACE_URL, 'ledger5|' + hashlib.sha1(','.join(c['id'] for c, _, _ in blk).encode()).hexdigest()))
                    r = call('comment_on_issue', {'issueId': U['id'], 'body': body, 'operationId': opid})
                    if isinstance(r, dict) and r.get('error'):
                        print('LEDGER FAIL', U['number'], str(r)[:200], flush=True)
                        ok = [t for t in ok if t not in blk]
            if not ok:
                continue
            os.makedirs('snapshots5', exist_ok=True)
            with open('snapshots5/snap-%s.jsonl' % time.strftime('%H%M%S'), 'a') as f:
                for c, i, _ in ok:
                    f.write(json.dumps({'kind': grp['kind'], 'issue': {k: i.get(k) for k in ('id', 'number', 'status', 'labels', 'revision', 'priority')}, 'proj': c['proj']}) + '\n')
                f.flush()
                os.fsync(f.fileno())
            if U:
                tail = 'merged into umbrella %s#%s (its ledger lists this ticket with latest comments).' % (U['slug'], U['number'])
            else:
                tail = grp['note']
            items = [{'issueId': c['id'], 'status': 'wont_fix', 'note': '%s (goodqa#14977 under-300 push): %s Reopen by setting status back to \'%s\'; snapshot kept.' % (TAG, tail, i['status'])} for c, i, _ in ok]
            good = set()
            pending = items
            for attempt in range(6):
                nxt = []
                for s2 in range(0, len(pending), 25):
                    p2 = pending[s2:s2 + 25]
                    d = call('bulk_update_issues', {'items': p2})
                    r = d.get('results', []) if isinstance(d, dict) else []
                    seen = {x.get('issueId') for x in r}
                    for x in r:
                        if x.get('ok'):
                            good.add(x.get('issueId'))
                        elif 'rate_limited' in json.dumps(x):
                            nxt.append(next(y for y in p2 if y['issueId'] == x['issueId']))
                        else:
                            open('bulk_errors5.log', 'a').write(json.dumps(x)[:300] + '\n')
                    nxt += [y for y in p2 if y['issueId'] not in seen]
                pending = nxt
                if not pending:
                    break
                time.sleep(3 * (attempt + 1))
            for c, i, _ in ok:
                if c['id'] in good:
                    log_done({'id': c['id'], 'n': c['n'], 'result': 'closed', 'kind': grp['kind'], 'from': i['status'], 'to': 'wont_fix', 'umb': U['number'] if U else None})
                    tsv([time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), c['proj'], c['n'], grp['kind'], i['status'], 'wont_fix', U['number'] if U else ''])
        print(time.strftime('%H:%M:%S'), 'group', grp['kind'], (U or {}).get('number'), 'children', len(grp['children']), flush=True)
    done = load_done()
    msg = 'Under-300 consolidation (%s): %d closed so far in done5.jsonl (reversible via reopen5.py, ledger comments on umbrellas).' % (plan_file, sum(1 for v in done.values() if v['result'] == 'closed'))
    call('comment_on_issue', {'issueId': TRACK, 'body': msg, 'operationId': str(uuid.uuid4())})
    print(msg)


if __name__ == '__main__':
    run(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 10**9)
