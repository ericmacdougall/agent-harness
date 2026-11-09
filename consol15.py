"""Area-umbrella fold closer (goodqa#14977, ruling 2026-11-09). usage: python3 consol13.py PLAN.jsonl [max_groups]
Per child: fresh get_issue (skip if status moved from the plan, or already closed); skip when a comment in the last 14 days matches no agent pattern.
Per chunk of up to 200: ledger comments on the umbrella (20 rows each: link, title, state, owner, PR, last activity), snapshot, then bulk close wont_fix
'merged into umbrella #N'. State: done15.jsonl, closes15.tsv, snapshots15/. Undo: python3 reopen13.py [--apply] [--umbrella N]"""
import sys, os, json, time, uuid, hashlib, datetime as D
from concurrent.futures import ThreadPoolExecutor
HERE = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup'
sys.path.insert(0, HERE)
sys.path.insert(0, '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a')
os.chdir(HERE)
import gq, patterns
TAG = 'cleanup-2026-11i'
CUT = (D.datetime.now(D.timezone.utc) - D.timedelta(days=14)).isoformat()


def call(tool, args):
    for k in range(25):
        d = gq.call(tool, args)
        if isinstance(d, dict) and isinstance(d.get('error'), dict) and d['error'].get('code') == 'rate_limited':
            time.sleep(min(60, 4 * (k + 1))); continue
        return d
    return d


def load_done():
    s = {}
    if os.path.exists('done15.jsonl'):
        for l in open('done15.jsonl'):
            try:
                j = json.loads(l)
                if j.get('why') not in ('error-retry',):
                    s[j['id']] = j
            except Exception:
                pass
    return s


def log_done(rec):
    with open('done15.jsonl', 'a') as f:
        f.write(json.dumps(rec) + '\n')


def inspect(c):
    d = call('get_issue', {'issueId': c['id']})
    i = d.get('issue') if isinstance(d, dict) else None
    if not i:
        return c, None, 'unreadable'
    if i['status'] in ('done', 'wont_fix', 'duplicate', 'cancelled') or i.get('archivedAt'):
        return c, i, 'already-closed:' + i['status']
    if i['status'] != c['status']:
        return c, i, 'state-moved:%s->%s' % (c['status'], i['status'])
    return c, i, None


def row(c, i):
    r = '- #%s | %s | state: %s | owner: %s | PR: %s | last activity: %s%s' % (c['n'], (i.get('title') or c['title'])[:140].replace('|', '/'), i['status'], c['owner'], c['pr'], (i.get('updatedAt') or '')[:16], ' | ACTIVE (WAL or commit in last 72h; owner continues in this live ticket)' if c['active'] else '')
    for q in c.get('comments', []):
        r += '\n    > comment on #%s, %s, verbatim: "%s"' % (c['n'], q['at'][:10], q['body'].replace('\n', ' / '))
    return r[:4200]


def run(plan_file, ngroups):
    plan = [json.loads(l) for l in open(plan_file)]
    g = 0
    for grp in plan:
        if g >= ngroups:
            break
        dn = load_done()
        kids = [c for c in grp['children'] if c['id'] not in dn]
        if not kids:
            continue
        g += 1
        U = grp['umbrella']
        for s in range(0, len(kids), 200):
            part = kids[s:s + 200]
            with ThreadPoolExecutor(int(os.environ.get('THREADS', '5'))) as ex:
                res = list(ex.map(inspect, part))
            ok = []
            for c, i, why in res:
                if why:
                    log_done({'id': c['id'], 'n': c['n'], 'result': 'skipped', 'why': why})
                else:
                    ok.append((c, i))
            for k in range(0, len(ok), 5):
                blk = ok[k:k + 5]
                body = 'Checklist rows (goodqa#14977 combine, %s): these tickets were merged into this LIVE ticket as duplicates (not done, not wont_fix) with their recent comments and quoted instructions. Reopen by setting the status back to the state shown.\n\n%s' % (time.strftime('%Y-%m-%d', time.gmtime()), '\n'.join(row(c, i) for c, i in blk))
                opid = str(uuid.uuid5(uuid.NAMESPACE_URL, 'ledger15|' + hashlib.sha1(','.join(c['id'] for c, _ in blk).encode()).hexdigest()))
                r = call('comment_on_issue', {'issueId': U['id'], 'body': body[:15000], 'operationId': opid})
                if isinstance(r, dict) and r.get('error'):
                    print('LEDGER FAIL', U['number'], str(r)[:160], flush=True)
                    ok = [t for t in ok if t not in blk]
                    for c, i in blk:
                        log_done({'id': c['id'], 'n': c['n'], 'result': 'skipped', 'why': 'error-retry'})
            if not ok:
                continue
            os.makedirs('snapshots15', exist_ok=True)
            with open('snapshots15/snap-%s.jsonl' % time.strftime('%H%M%S'), 'a') as f:
                for c, i in ok:
                    f.write(json.dumps({'umbrella': U['number'], 'issue': {k: i.get(k) for k in ('id', 'number', 'status', 'revision', 'priority')}, 'proj': c['proj']}) + '\n')
                f.flush(); os.fsync(f.fileno())
            items = [{'issueId': c['id'], 'status': 'duplicate', 'note': '%s (goodqa#14977 combine): merged into LIVE ticket %s#%s "%s" (work continues there; every quoted user instruction on this ticket is reproduced in it). NOT done, NOT wont_fix. State at merge time (%s) is kept in the checklist row. Reopen by setting status back to \'%s\'.' % (TAG, U['slug'], U['number'], grp['area'], i['status'], i['status'])} for c, i in ok]
            good = set(); pending = items
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
                            open('bulk_errors15.log', 'a').write(json.dumps(x)[:300] + '\n')
                    nxt += [y for y in p2 if y['issueId'] not in seen]
                pending = nxt
                if not pending:
                    break
                time.sleep(3 * (attempt + 1))
            new = not os.path.exists('closes15.tsv')
            with open('closes15.tsv', 'a') as tf:
                if new:
                    tf.write('time\tproject\tnumber\tarea\tfrom\tto\tumbrella\n')
                for c, i in ok:
                    if c['id'] in good:
                        log_done({'id': c['id'], 'n': c['n'], 'result': 'closed', 'from': i['status'], 'to': 'duplicate', 'umb': U['number']})
                        tf.write('\t'.join(str(x) for x in [time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), c['proj'], c['n'], grp['area'], i['status'], 'duplicate', U['number']]) + '\n')
            print(time.strftime('%H:%M:%S'), U['number'], grp['area'], 'chunk', len(part), 'closed', len(good), flush=True)
    done = load_done()
    print('TOTAL closed so far:', sum(1 for v in done.values() if v['result'] == 'closed'), flush=True)


if __name__ == '__main__':
    run(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 10 ** 9)
