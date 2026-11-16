"""goodqa#16136 AC-13 matcher (ac13-count.py): every non-2xx launch on a non-held kind is a failure."""
import json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, 'ac13-count.py')
T0 = 1_800_000_000_000


def _log(tmp_path, launches, name='disp.log'):
    lines = []
    for i, (kind, st) in enumerate(launches):
        rid = 'req-%d' % (i % 3)   # reqIds repeat (a restart resets them); pairing must follow order
        lines.append('2026-11-16T00:00:%02dZ ' % (i % 60) + json.dumps({'level': 30, 'time': T0 + i, 'reqId': rid, 'msg': 'incoming request',
                     'req': {'method': 'POST', 'url': '/jobs/%s/run' % kind}}))
        lines.append(json.dumps({'level': 30, 'time': T0 + i, 'reqId': rid, 'msg': 'request completed', 'res': {'statusCode': st}}))
    lines.append(json.dumps({'level': 30, 'time': T0, 'reqId': 'req-9', 'msg': 'incoming request', 'req': {'method': 'GET', 'url': '/healthz'}}))
    lines.append(json.dumps({'level': 30, 'time': T0, 'reqId': 'req-9', 'msg': 'request completed', 'res': {'statusCode': 503}}))
    p = tmp_path / name; p.write_text('\n'.join(lines) + '\n'); return str(p)


def run(*args):
    r = subprocess.run([sys.executable, TOOL] + list(args), capture_output=True, text=True)
    return r.returncode, json.loads(r.stdout) if r.stdout.strip() else r.stderr


OK = [('scan', 200), ('transcode', 202), ('suggest-fix-worker', 200)]
REQ = ['--require-2xx', 'scan', '--require-2xx', 'transcode', '--require-2xx', 'suggest-fix-worker']


def test_post_pass_with_held_intelligence_501(tmp_path):
    rc, o = run(_log(tmp_path, OK + [('intelligence-worker', 501)] * 3), '--mode', 'post', '--held-empty', 'intelligence-worker', *REQ)
    assert rc == 0 and o['verdict'] == 'PASS' and o['held_excluded'] == {'intelligence-worker': 3}, o


def test_501_on_a_non_held_kind_fails(tmp_path):
    for kind in ('scan', 'suggest-fix-worker', 'transcode'):
        rc, o = run(_log(tmp_path, OK + [(kind, 501)]), '--mode', 'post', '--held-empty', 'intelligence-worker', *REQ)
        assert rc == 1 and any(f.startswith('%s 501' % kind) for f in o['failures']), (kind, o)


def test_422_and_other_non_2xx_on_a_non_held_kind_fail(tmp_path):
    for kind, st in (('scan', 422), ('suggest-fix-worker', 504), ('transcode', 422), ('scan', 429), ('intelligence-worker', 422)):
        rc, o = run(_log(tmp_path, OK + [(kind, st)]), '--mode', 'post', '--held-empty', 'intelligence-worker', *REQ)
        assert rc == 1 and any(f.startswith('%s %d' % (kind, st)) for f in o['failures']), (kind, st, o)


S = 1000   # ms
BODY = ('{"error":"docker run failed before starting a container: docker: Error response from daemon: '
        'job-dispatcher-create-guard: refused (create refused: TRANSCODER_MODE=transcribe is held on this guard)","started":false}')


def _iso(ms):
    import datetime
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def _disp(tmp_path, events, name='disp.log'):
    """events: [(ms offset from T0, kind, status)] as the dispatcher logs them."""
    lines = []
    for n, (dt, kind, st) in enumerate(events):
        rid = 'req-%d' % (n % 2)
        lines.append(json.dumps({'level': 30, 'time': T0 + dt, 'reqId': rid, 'msg': 'incoming request', 'req': {'method': 'POST', 'url': '/jobs/%s/run' % kind}}))
        lines.append(json.dumps({'level': 30, 'time': T0 + dt, 'reqId': rid, 'msg': 'request completed', 'res': {'statusCode': st}}))
    p = tmp_path / name; p.write_text('\n'.join(lines) + '\n'); return str(p)


def _api(tmp_path, held, other=(), untimed=0, prefix=None, name='api.log', extra=()):
    """API replica lines as `docker logs --timestamps` (or, with prefix, `docker compose logs --timestamps api`) prints them."""
    pre = (prefix + '  | ') if prefix else ''
    rows = [pre + '%s transcribe: failed to launch job CloudJobLaunchError: job-dispatch transcode failed (422): %s' % (_iso(T0 + dt), BODY) for dt in held]
    rows += [pre + '%s transcribe: failed to launch job CloudJobLaunchError: job-dispatch transcode failed (422): '
             '{"error":"docker run failed before starting a container: Unable to find image","started":false}' % _iso(T0 + dt) for dt in other]
    rows += [pre + 'transcribe: failed to launch job CloudJobLaunchError: job-dispatch transcode failed (422): ' + BODY] * untimed
    rows += [pre + '%s {"level":30,"msg":"unrelated api line"}' % _iso(T0), pre + '    at HttpJobDispatchClient.runJob (job-dispatch.js:1:1)']
    rows += list(extra)
    p = tmp_path / name; p.write_text('\n'.join(rows) + '\n'); return str(p)


OKT = [(1 * S, 'scan', 200), (2 * S, 'transcode', 202), (3 * S, 'suggest-fix-worker', 200)]
HT = ['--mode', 'post', '--held-empty', 'intelligence-worker', '--guard-held-transcribe'] + REQ
WIN = ['--since', str(T0), '--until', str(T0 + 30 * S)]


def test_held_transcription_422_pairs_with_its_own_api_line(tmp_path):
    d = _disp(tmp_path, OKT + [(10 * S, 'transcode', 422), (20 * S, 'transcode', 422)])
    rc, o = run(d, *HT, *WIN, '--refusals', _api(tmp_path, [11 * S, 19 * S]))
    assert rc == 0 and o['held_excluded']['transcode'] == 2 and o['api_replicas'] == 1, o
    # G1: equal counts are not enough; each 422 needs its own API line within 5 s
    rc, o = run(d, *HT, *WIN, '--refusals', _api(tmp_path, [10 * S, 28 * S]))
    assert rc == 1 and any('20' in f and 'has no held API launch-failure line' in f for f in o['failures']), o
    assert any('has no transcode 422' in f for f in o['failures']), o
    for held in ([11 * S], [11 * S, 19 * S, 25 * S], []):
        rc, o = run(d, *HT, *WIN, '--refusals', _api(tmp_path, held))
        assert rc == 1, (held, o)
    rc, o = run(d, *HT, *WIN, '--refusals', _api(tmp_path, [11 * S, 19 * S], other=[5 * S]))
    assert rc == 1 and any('another reason' in f for f in o['failures']), o
    rc, o = run(d, *HT, *WIN, '--refusals', _api(tmp_path, [11 * S, 19 * S], untimed=1))
    assert rc == 1 and any('without a readable timestamp' in f for f in o['failures']), o


def test_held_launch_straddling_the_window_edge(tmp_path):
    # the 422 is in the window, its API line just after it: they pair
    rc, o = run(_disp(tmp_path, OKT + [(29 * S + 900, 'transcode', 422)]), *HT, *WIN, '--refusals', _api(tmp_path, [31 * S]))
    assert rc == 0 and o['held_excluded']['transcode'] == 1, o
    # the 422 just before the window, its API line inside it: the line is paired, not an orphan
    rc, o = run(_disp(tmp_path, OKT + [(-1 * S, 'transcode', 422)]), *HT, *WIN, '--refusals', _api(tmp_path, [1 * S]))
    assert rc == 0, o
    # beyond the 5 s tolerance nothing pairs
    rc, o = run(_disp(tmp_path, OKT + [(29 * S + 900, 'transcode', 422)]), *HT, *WIN, '--refusals', _api(tmp_path, [40 * S]))
    assert rc == 1 and any('has no held API launch-failure line' in f for f in o['failures']), o


def test_every_api_replica_is_read(tmp_path):
    d = _disp(tmp_path, OKT + [(10 * S, 'transcode', 422), (20 * S, 'transcode', 422)])
    a1 = _api(tmp_path, [10 * S], name='api-1.log'); a2 = _api(tmp_path, [20 * S], name='api-2.log')
    rc, o = run(d, *HT, *WIN, '--api-replicas', '2', '--refusals', a1, '--refusals', a2)
    assert rc == 0 and o['api_replicas'] == 2 and o['held_excluded']['transcode'] == 2, o
    rc, o = run(d, *HT, *WIN, '--api-replicas', '2', '--refusals', a1)
    assert rc == 1 and 'read 1 api replicas, expected 2' in o['failures'], o
    assert any('has no held API launch-failure line' in f for f in o['failures']), o
    # one `docker compose logs --timestamps api` file holding both replicas
    both = tmp_path / 'api-compose.log'
    both.write_text(open(_api(tmp_path, [10 * S], prefix='api-1', name='c1')).read() + open(_api(tmp_path, [20 * S], prefix='api-2', name='c2')).read())
    rc, o = run(d, *HT, *WIN, '--api-replicas', '2', '--refusals', str(both))
    assert rc == 0 and o['api_replicas'] == 2, o


def test_guard_held_transcribe_needs_refusals(tmp_path):
    rc, err = run(_log(tmp_path, OK), '--mode', 'post', '--guard-held-transcribe')
    assert rc == 2 and 'needs --refusals' in err, err


def test_floors_and_positive_control(tmp_path):
    rc, o = run(_log(tmp_path, [('scan', 200)]), '--mode', 'post', *REQ)
    assert rc == 1 and 'no 2xx for transcode' in o['failures'] and 'no 2xx for suggest-fix-worker' in o['failures'], o
    rc, o = run(_log(tmp_path, OK), '--mode', 'pre')
    assert rc == 1 and 'positive control' in o['failures'][0], o
    rc, o = run(_log(tmp_path, OK + [('intelligence-worker', 422)] * 6), '--mode', 'pre')
    assert rc == 0 and o['counts']['intelligence-worker'] == {'422': 6}, o


def test_window_and_unreadable(tmp_path):
    log = _log(tmp_path, OK + [('scan', 500)])
    rc, o = run(log, '--mode', 'post', '--until', str(T0 + 3), *REQ)
    assert rc == 0, o
    rc, o = run(str(tmp_path / 'absent.log'), '--mode', 'post')
    assert rc == 2 and o['verdict'] == 'FAIL', o
