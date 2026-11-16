

# ---- receipt pr1370-v1 F1: a record the matcher cannot correlate or read never lets a run PASS
def _raw(tmp_path, extra, base=OK, name='disp.log'):
    p = _log(tmp_path, base, name); open(p, 'a').write('\n'.join(extra) + '\n'); return p


def _done(rid, st, t=T0 + 50):
    return json.dumps({'level': 30, 'time': t, 'reqId': rid, 'msg': 'request completed', 'res': {'statusCode': st}})


def _start(rid, kind='scan', t=T0 + 50):
    return json.dumps({'level': 30, 'time': t, 'reqId': rid, 'msg': 'incoming request', 'req': {'method': 'POST', 'url': '/jobs/%s/run' % kind}})


def test_orphan_in_window_500_is_never_pass(tmp_path):
    rc, o = run(_raw(tmp_path, [_done('req-orphan', 500)]), '--mode', 'post', *REQ)
    assert rc == 1 and o['verdict'] == 'INCONCLUSIVE' and o['unknown'] == {'orphan completion': 1}, o


def test_orphan_outside_the_window_is_ignored_and_untimed_counts(tmp_path):
    rc, o = run(_raw(tmp_path, [_done('req-orphan', 500, t=T0 - 10)]), '--mode', 'post', '--since', str(T0), *REQ)
    assert rc == 0 and o['verdict'] == 'PASS', o
    untimed = json.dumps({'level': 30, 'reqId': 'req-orphan', 'msg': 'request completed', 'res': {'statusCode': 500}})
    rc, o = run(_raw(tmp_path, [untimed]), '--mode', 'post', '--since', str(T0), *REQ)
    assert rc == 1 and o['verdict'] == 'INCONCLUSIVE', o


def test_malformed_lines_are_unknown(tmp_path):
    for bad in ('2026-11-16T00:00:59Z {"level":30,"reqId":"req-1","msg":"request completed","res":{"statusCode":500', '[{"a":1}]', '{"x": 1} trailing'):
        rc, o = run(_raw(tmp_path, [bad]), '--mode', 'post', *REQ)
        assert rc == 1 and o['verdict'] == 'INCONCLUSIVE' and o['unknown'] == {'malformed': 1}, (bad, o)


def test_invalid_status_or_time_on_a_launch_is_unknown(tmp_path):
    for st, t in (('500', T0 + 50), (True, T0 + 50), (None, T0 + 50), (99, T0 + 50), (600, T0 + 50), (500.0, T0 + 50), (200, 'later'), (200, True)):
        line = json.dumps({'level': 30, 'time': t, 'reqId': 'req-x', 'msg': 'request completed', 'res': {'statusCode': st}})
        rc, o = run(_raw(tmp_path, [_start('req-x'), line]), '--mode', 'post', *REQ)
        assert rc == 1 and o['verdict'] == 'INCONCLUSIVE' and o['unknown'] == {'invalid status or time': 1}, (st, t, o)
    line = json.dumps({'level': 30, 'time': T0 + 50, 'reqId': 'req-x', 'msg': 'request completed', 'res': 'oops'})
    rc, o = run(_raw(tmp_path, [_start('req-x'), line]), '--mode', 'post', *REQ)
    assert rc == 1 and o['unknown'] == {'invalid status or time': 1}, o


def test_a_launch_without_its_completion_is_unknown(tmp_path):
    rc, o = run(_raw(tmp_path, [_start('req-x')]), '--mode', 'post', *REQ)
    assert rc == 1 and o['verdict'] == 'INCONCLUSIVE' and o['unknown'] == {'no completion': 1}, o
    rc, o = run(_raw(tmp_path, [_start('req-x'), _start('req-x', t=T0 + 51), _done('req-x', 200, t=T0 + 51)]), '--mode', 'post', *REQ)
    assert rc == 1 and o['unknown'] == {'no completion': 1}, 'a reused reqId supersedes the first launch'


def test_a_non_launch_request_still_pairs_and_counts_nothing(tmp_path):
    health = json.dumps({'level': 30, 'time': T0 + 50, 'reqId': 'req-h', 'msg': 'incoming request', 'req': {'method': 'GET', 'url': '/healthz'}})
    rc, o = run(_raw(tmp_path, [health, _done('req-h', 503)]), '--mode', 'post', *REQ)
    assert rc == 0 and o['verdict'] == 'PASS' and o['unknown'] == {}, o


def test_unknown_also_blocks_the_positive_control_and_a_failure_still_wins(tmp_path):
    rc, o = run(_raw(tmp_path, [_done('req-orphan', 500)], base=OK + [('scan', 422)]), '--mode', 'pre')
    assert rc == 1 and o['verdict'] == 'INCONCLUSIVE', o
    rc, o = run(_raw(tmp_path, [_done('req-orphan', 500)], base=OK + [('scan', 500)]), '--mode', 'post', *REQ)
    assert rc == 1 and o['verdict'] == 'FAIL' and o['unknown'] == {'orphan completion': 1}, o
