#!/usr/bin/env python3
"""goodqa#16136 AC-13: count job-dispatcher launch responses per job kind from its container log, fail closed.

Reads the dispatcher's Fastify JSON log (`docker logs --timestamps` output; any prefix before the first `{` is ignored).
A "request completed" line carries res.statusCode and the reqId of the "incoming request" line that carries the URL;
only POST /jobs/<kind>/run requests are counted. Nothing but statusCode, URL, reqId and time is read, so no request
body, header or env value is ever printed.

  --mode pre   positive control: the window must hold at least one 422 (proves the matcher sees launch failures).
  --mode post  after a release:
     2xx on any kind                                   -> ok
     501 on a kind named by --held-empty                -> held (its JOB_IMAGE_* line is "" # held), excluded
     422 on transcode with --guard-held-transcribe      -> held ONLY when matched one-to-one, within --pair-seconds
                                                           (default 5), to its own API line `transcribe: failed to
                                                           launch job` whose 422 body names the guard reason
                                                           `TRANSCODER_MODE=transcribe is held on this guard`
     any other non-2xx on any kind (501 on a non-held kind, 422 on a non-held kind, 5xx, 4xx) -> failure
     --require-2xx KIND: at least one 2xx for KIND, else failure
  API input (--refusals, repeatable): one file per api replica (`docker logs --timestamps <replica>`), or one
  `docker compose logs --timestamps api` file whose lines carry a `<replica> | ` prefix. Every replica must be read:
  the JSON names the replicas seen, and --api-replicas N fails the run when that count differs.
  Pairing reads both logs over the window widened by --pair-seconds on each side, so a held launch that straddles a
  window edge still pairs; an unmatched 422 or held API line inside the window, an in-window API launch-failure line
  for any other reason, and an API launch-failure line without a readable timestamp are failures.
Exit 0 PASS, 1 FAIL, 2 usage or unreadable input. Output: one JSON object.
"""
import argparse, calendar, json, re, sys, time

KINDS = ('scan', 'transcode', 'intelligence-worker', 'suggest-fix-worker')
HOLDABLE = ('intelligence-worker', 'transcode')
ROUTE = re.compile(r'^/jobs/([a-z-]+)/run(?:\?.*)?$')
HELD_TAG = 'TRANSCODER_MODE=transcribe is held on this guard'
API_MARK = 'transcribe: failed to launch job'
API_LINE = re.compile(r'^(?:(\S+)\s+\|\s+)?(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z\s')


def records(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            i = line.find('{')
            if i < 0: continue
            try: r = json.loads(line[i:])
            except ValueError: continue
            if isinstance(r, dict): yield r


def inside(t, since, until):
    return (since is None or t >= since) and (until is None or t < until)


def launches(path):
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


def api_lines(paths):
    """([held times], [other-reason times], untimed count, replicas seen) from the api replica logs."""
    held, other, untimed, replicas = [], [], 0, set()
    for n, path in enumerate(paths):
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                if not line.strip(): continue
                m = API_LINE.match(line)
                if m: replicas.add((n, m.group(1)))
                if API_MARK not in line: continue
                if not m: untimed += 1; continue
                t = calendar.timegm(time.strptime(m.group(2), '%Y-%m-%dT%H:%M:%S')) * 1000 + int((m.group(3) or '0')[:3].ljust(3, '0'))
                (held if 'job-dispatch transcode failed (422)' in line and HELD_TAG in line else other).append(t)
    return held, other, untimed, sorted('%d:%s' % (n, p or 'file') for n, p in replicas)


def pair(a, b, tol):
    """Greedy in time order: each a matched to the earliest unmatched b within tol. Returns (unmatched a, unmatched b)."""
    b = sorted(b); used = [False] * len(b); ua = []
    for t in sorted(a):
        for i, u in enumerate(b):
            if not used[i] and abs(u - t) <= tol: used[i] = True; break
        else: ua.append(t)
    return ua, [u for i, u in enumerate(b) if not used[i]]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('log'); ap.add_argument('--mode', choices=('pre', 'post'), required=True)
    ap.add_argument('--held-empty', action='append', default=[], choices=HOLDABLE)
    ap.add_argument('--guard-held-transcribe', action='store_true')
    ap.add_argument('--refusals', action='append', default=[], help='api replica log (docker logs --timestamps); repeat per replica')
    ap.add_argument('--api-replicas', type=int, help='the number of api replicas that must be read')
    ap.add_argument('--pair-seconds', type=float, default=5.0)
    ap.add_argument('--require-2xx', action='append', default=[], choices=KINDS)
    ap.add_argument('--since', type=int); ap.add_argument('--until', type=int)
    a = ap.parse_args(argv)
    if a.guard_held_transcribe and 'transcode' in a.held_empty:
        ap.error('--guard-held-transcribe and --held-empty transcode are exclusive (a held-empty transcode never reaches the guard)')
    if a.guard_held_transcribe and not a.refusals:
        ap.error('--guard-held-transcribe needs --refusals: a held transcription 422 is excluded only when matched to its API launch-failure line')
    tol = int(a.pair_seconds * 1000)
    try:
        got = launches(a.log)
        held_api, other_api, untimed, replicas = api_lines(a.refusals) if a.refusals else ([], [], 0, [])
    except OSError as e:
        print(json.dumps({'verdict': 'FAIL', 'error': 'unreadable input: %s' % e.strerror})); return 2
    inwin = [(t, k, st) for t, k, st in got if inside(t, a.since, a.until)]
    counts = {}
    for _, k, st in inwin: counts.setdefault(k, {}).setdefault(str(st), 0); counts[k][str(st)] += 1
    failures, held = [], {}
    if a.mode == 'pre':
        if not any(st == 422 for _, _, st in inwin): failures.append('positive control: no 422 in the window (the matcher proves nothing)')
    else:
        for t, k, st in inwin:
            if 200 <= st < 300: continue
            if st == 501 and k in a.held_empty: held[k] = held.get(k, 0) + 1; continue
            if st == 422 and k == 'transcode' and a.guard_held_transcribe: continue
            failures.append('%s %d at %s' % (k, st, t))
        if a.guard_held_transcribe:
            lo = None if a.since is None else a.since - tol; hi = None if a.until is None else a.until + tol
            tc = [t for t, k, st in got if k == 'transcode' and st == 422 and inside(t, lo, hi)]
            ua, ub = pair(tc, [t for t in held_api if inside(t, lo, hi)], tol)
            ua = [t for t in ua if inside(t, a.since, a.until)]; ub = [t for t in ub if inside(t, a.since, a.until)]
            for t in ua: failures.append('transcode 422 at %s has no held API launch-failure line within %ss' % (t, a.pair_seconds))
            for t in ub: failures.append('held API launch-failure line at %s has no transcode 422 within %ss' % (t, a.pair_seconds))
            held['transcode'] = sum(1 for t, k, st in inwin if k == 'transcode' and st == 422) - len(ua)
        bad = [t for t in other_api if inside(t, a.since, a.until)]
        if bad: failures.append('%d transcription launch-failure lines with another reason' % len(bad))
        if untimed: failures.append('%d transcription launch-failure lines without a readable timestamp' % untimed)
        if a.api_replicas is not None and a.refusals and len(replicas) != a.api_replicas:
            failures.append('read %d api replicas, expected %d' % (len(replicas), a.api_replicas))
        for k in a.require_2xx:
            if not any(kk == k and 200 <= st < 300 for _, kk, st in inwin): failures.append('no 2xx for %s' % k)
    print(json.dumps({'verdict': 'FAIL' if failures else 'PASS', 'mode': a.mode, 'counts': counts, 'held_excluded': held,
                      'api_replicas': len(replicas), 'api_replica_sources': replicas, 'failures': failures}, sort_keys=True))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
