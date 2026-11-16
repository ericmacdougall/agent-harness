import os
D = os.path.dirname(os.path.abspath(__file__))
p = os.path.join(D, 'ac13-count.py'); t = open(p).read()
for o, n in [("     422 on transcode with --guard-held-transcribe      -> held ONLY when paired one-to-one with a guard refusal\n                                                           line (--refusals) naming TRANSCODER_MODE=transcribe;\n                                                           unpaired 422s and unpaired refusal lines are failures",
"     422 on transcode with --guard-held-transcribe      -> held ONLY when paired one-to-one (by count, in the window)\n                                                           with API `transcribe: failed to launch job` lines\n                                                           (--refusals: the api container log) whose 422 body names\n                                                           the guard reason `TRANSCODER_MODE=transcribe is held on\n                                                           this guard`; unpaired 422s, and launch-failure lines for\n                                                           any other reason, are failures"),
("ap.add_argument('--refusals', help='guard log (JSON lines) holding its refusal lines')", "ap.add_argument('--refusals', help='api container log (docker logs --timestamps) holding its transcription launch-failure lines')"),
("a held transcription 422 is excluded only when paired with a guard refusal line", "a held transcription 422 is excluded only when paired with an API launch-failure line naming the guard hold"),
("'held transcription: %d transcode 422s but %d guard refusal lines naming %s (must pair one-to-one)'", "'held transcription: %d transcode 422s but %d API launch-failure lines naming %s (must pair one-to-one)'"),
("'%d guard refusal lines with another reason'", "'%d transcription launch-failure lines with another reason or no readable timestamp'")]:
    assert t.count(o) == 1, o[:60]; t = t.replace(o, n)
open(p, 'w').write(t)
p = os.path.join(D, 'test_ac13_count.py'); t = open(p).read()
o = t[t.index('def _refusals('):t.index('def run(')]
n = '''def _refusals(tmp_path, n, other=0, untimed=0):
    """API container lines as `docker logs --timestamps` prints them (routes.ts console.error of the launch error)."""
    body = ('{"error":"docker run failed before starting a container: docker: Error response from daemon: '
            'job-dispatcher-create-guard: refused (create refused: TRANSCODER_MODE=transcribe is held on this guard)","started":false}')
    rows = ['2027-01-15T08:00:00.%03dZ transcribe: failed to launch job CloudJobLaunchError: job-dispatch transcode failed (422): %s' % (i, body)
            for i in range(n)]
    rows += ['2027-01-15T08:00:00.000Z transcribe: failed to launch job CloudJobLaunchError: job-dispatch transcode failed (422): '
             '{"error":"docker run failed before starting a container: Unable to find image","started":false}'] * other
    rows += ['transcribe: failed to launch job CloudJobLaunchError: job-dispatch transcode failed (422): ' + body] * untimed
    rows += ['2027-01-15T08:00:00.000Z {"level":30,"msg":"unrelated api line"}', '    at HttpJobDispatchClient.runJob (job-dispatch.js:1:1)']
    p = tmp_path / 'api.log'; p.write_text('\\n'.join(rows) + '\\n'); return str(p)


'''
t = t.replace(o, n)
o = """    rc, o = run(log, *base, '--refusals', _refusals(tmp_path, 2, other=1))
    assert rc == 1 and any('another reason' in f for f in o['failures']), o
"""
assert t.count(o) == 1
t = t.replace(o, o + """    win = ['--since', str(T0), '--until', str(T0 + 10 ** 12)]   # T0 (2027-01-15T08:00Z) is inside the window
    rc, o = run(log, *base, *win, '--refusals', _refusals(tmp_path, 2))
    assert rc == 0 and o['held_excluded'].get('transcode') == 2, o
    rc, o = run(log, *base, *win, '--refusals', _refusals(tmp_path, 2, untimed=1))
    assert rc == 1 and any('no readable timestamp' in f for f in o['failures']), o
""")
open(p, 'w').write(t); print('edited')
