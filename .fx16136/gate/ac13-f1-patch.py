"""receipt pr1370-v1 F1: ac13-count.py fails closed on records it cannot correlate or read. usage: python3 ac13-f1-patch.py <ac13-count.py>"""
import sys

p = sys.argv[1]
t = open(p).read()


def rep(old, new):
    global t
    assert t.count(old) == 1, old[:80]
    t = t.replace(old, new)


rep('''Exit 0 PASS, 1 FAIL, 2 usage or unreadable input. Output: one JSON object.
"""''', '''UNKNOWN records (receipt pr1370-v1 F1) never let a run PASS. Each one is a record the matcher cannot vouch for:
  - a line holding `{` that is not a JSON object (malformed);
  - a "request completed" with no "incoming request" for its reqId (an orphan: it can be an in-window 500);
  - a launch completion whose statusCode is not an integer 100-599 (a bool is not one) or whose time is not a number;
  - a launch "incoming request" with no completion (superseded by a reused reqId, or still open at the end of the log).
It counts when its time is inside the window, or when it has no usable time. Any such record makes the verdict
INCONCLUSIVE (exit 1) unless a failure already makes it FAIL.
Exit 0 PASS, 1 FAIL or INCONCLUSIVE, 2 usage or unreadable input. Output: one JSON object.
"""''')

rep('''def records(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            i = line.find('{')
            if i < 0: continue
            try: r = json.loads(line[i:])
            except ValueError: continue
            if isinstance(r, dict): yield r
''', '''def records(path):
    """Each JSON object line, or None for a line holding `{` that is not one (counted as unknown, never skipped)."""
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            i = line.find('{')
            if i < 0: continue
            try: r = json.loads(line[i:])
            except ValueError: yield None; continue
            yield r if isinstance(r, dict) else None


def num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None
''')

rep('''def launches(path):
    """[(time, kind, status)] for every completed POST /jobs/<kind>/run with a numeric time."""
    pending, out = {}, []
    for r in records(path):
        rid, msg = r.get('reqId'), r.get('msg')
        if msg == 'incoming request':
            req = r.get('req') or {}
            m = ROUTE.match(str(req.get('url', '')))
            if req.get('method') == 'POST' and m: pending[rid] = m.group(1)
            else: pending.pop(rid, None)
        elif msg == 'request completed' and rid in pending:
            kind = pending.pop(rid)
            st = (r.get('res') or {}).get('statusCode'); t = r.get('time')
            if isinstance(st, int) and isinstance(t, (int, float)): out.append((t, kind, st))
    return out
''', '''def launches(path):
    """([(time, kind, status)] for every completed POST /jobs/<kind>/run, [(time or None, why)] unknown records)."""
    pending, out, unknown = {}, [], []
    for r in records(path):
        if r is None: unknown.append((None, 'malformed')); continue
        rid, msg = r.get('reqId'), r.get('msg')
        if msg == 'incoming request':
            req = r.get('req') if isinstance(r.get('req'), dict) else {}
            m = ROUTE.match(str(req.get('url', '')))
            prev = pending.pop(rid, None)
            if prev and prev[0]: unknown.append((prev[1], 'no completion'))
            pending[rid] = (m.group(1) if req.get('method') == 'POST' and m else None, num(r.get('time')))
        elif msg == 'request completed':
            if rid not in pending: unknown.append((num(r.get('time')), 'orphan completion')); continue
            kind, t_in = pending.pop(rid)
            if not kind: continue
            res = r.get('res') if isinstance(r.get('res'), dict) else {}
            st, t = res.get('statusCode'), num(r.get('time'))
            if isinstance(st, int) and not isinstance(st, bool) and 100 <= st <= 599 and t is not None: out.append((t, kind, st))
            else: unknown.append((t if t is not None else t_in, 'invalid status or time'))
    unknown += [(t_in, 'no completion') for kind, t_in in pending.values() if kind]
    return out, unknown
''')

rep('''        got = launches(a.log)
''', '''        got, unknown = launches(a.log)
''')
rep('''    inwin = [(t, k, st) for t, k, st in got if inside(t, a.since, a.until)]
''', '''    inwin = [(t, k, st) for t, k, st in got if inside(t, a.since, a.until)]
    unk = {}
    for t, why in unknown:
        if t is None or inside(t, a.since, a.until): unk[why] = unk.get(why, 0) + 1
''')
rep('''    print(json.dumps({'verdict': 'FAIL' if failures else 'PASS', 'mode': a.mode, 'counts': counts, 'held_excluded': held,
                      'api_replicas': len(replicas), 'api_replica_sources': replicas, 'failures': failures}, sort_keys=True))
    return 1 if failures else 0
''', '''    verdict = 'FAIL' if failures else 'INCONCLUSIVE' if unk else 'PASS'
    print(json.dumps({'verdict': verdict, 'mode': a.mode, 'counts': counts, 'held_excluded': held, 'unknown': unk,
                      'api_replicas': len(replicas), 'api_replica_sources': replicas, 'failures': failures}, sort_keys=True))
    return 0 if verdict == 'PASS' else 1
''')
open(p, 'w').write(t)
print('patched')
