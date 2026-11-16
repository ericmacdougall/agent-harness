"""goodqa#16136 G1/G2: replace the count-pairing test with per-launch time pairing and multi-replica tests."""
import os
D = os.path.dirname(os.path.abspath(__file__))
p = os.path.join(D, 'test_ac13_count.py'); t = open(p).read()
i = t.index('def test_held_transcription_422_must_pair_one_to_one_with_guard_refusals')
j = t.index('def test_guard_held_transcribe_needs_refusals')
new = '''S = 1000   # ms
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
    p = tmp_path / name; p.write_text('\\n'.join(lines) + '\\n'); return str(p)


def _api(tmp_path, held, other=(), untimed=0, prefix=None, name='api.log', extra=()):
    """API replica lines as `docker logs --timestamps` (or, with prefix, `docker compose logs --timestamps api`) prints them."""
    pre = (prefix + '  | ') if prefix else ''
    rows = [pre + '%s transcribe: failed to launch job CloudJobLaunchError: job-dispatch transcode failed (422): %s' % (_iso(T0 + dt), BODY) for dt in held]
    rows += [pre + '%s transcribe: failed to launch job CloudJobLaunchError: job-dispatch transcode failed (422): '
             '{"error":"docker run failed before starting a container: Unable to find image","started":false}' % _iso(T0 + dt) for dt in other]
    rows += [pre + 'transcribe: failed to launch job CloudJobLaunchError: job-dispatch transcode failed (422): ' + BODY] * untimed
    rows += [pre + '%s {"level":30,"msg":"unrelated api line"}' % _iso(T0), pre + '    at HttpJobDispatchClient.runJob (job-dispatch.js:1:1)']
    rows += list(extra)
    p = tmp_path / name; p.write_text('\\n'.join(rows) + '\\n'); return str(p)


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


'''
t = t[:i] + new + t[j:]
i = t.index('def _refusals('); j = t.index('def run(')
t = t[:i] + t[j:]
open(p, 'w').write(t); print('tests edited')
