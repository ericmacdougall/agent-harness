"""Local edit of the patch scripts for D1 (guard-log ctl command, probe fakes, D1 tests). python3 edit_d1.py DIR"""
import os, sys
D = sys.argv[1]

p = os.path.join(D, 'patch_ctl.py'); t = open(p).read()
anchor = "open(p, 'w').write(t)\nprint('patched ctl')"
add = r'''rep("""  disk                           one JSON line {"free_gb": N}: free space where the docker store lives (before a load)
""", """  disk                           one JSON line {"free_gb": N}: free space where the docker store lives (before a load)
  guard-log                      one JSON line {"listening": bool, "held": VALUE|null}: what the running create-guard's own
                                 startup line says it enforces (goodqa#16136 D1: the hold is proven by the guard, not the file)
""")
rep("""        if a.cmd == 'disk':""", """        if a.cmd == 'guard-log':
            r = stk.dc('logs', '--no-color', '--no-log-prefix', '--tail', '200', JOB_BLOCK, timeout=60)
            ls = [l for l in r.stdout.split('\\n') if 'job-dispatcher-create-guard listening' in l]
            m = re.search(r'heldEnv=(\\S+)', ls[-1]) if ls else None
            held = m.group(1) if m and m.group(1) != 'none' else None
            out({'listening': bool(ls), 'held': held}); return 0
        if a.cmd == 'disk':""")
rep("""    sub.add_parser('disk')""", """    sub.add_parser('disk'); sub.add_parser('guard-log')""")
'''
assert t.count(anchor) == 1 and 'guard-log' not in t
t = t.replace(anchor, add + anchor); open(p, 'w').write(t)

p = os.path.join(D, 'patch_tests3.py'); t = open(p).read()


def R(a, b):
    global t
    assert t.count(a) == 1, (t.count(a), a[:70]); t = t.replace(a, b)


R("""def _guard_source(R, supports):
    d = os.path.join(R.repo, os.path.dirname(GUARD_SRC)); os.makedirs(d, exist_ok=True)
    open(os.path.join(R.repo, GUARD_SRC), 'w').write('// guard\\n' + ('const held = process.env.GUARD_HELD_ENV;\\n' if supports else ''))""",
  """def _guard_source(R, supports, text=None):
    \"\"\"supports: the built guard behaves (fake docker marker); text: its source mentions GUARD_HELD_ENV (default: same).\"\"\"
    if supports: R.put('guard-held-support', '')
    text = supports if text is None else text
    d = os.path.join(R.repo, os.path.dirname(GUARD_SRC)); os.makedirs(d, exist_ok=True)
    open(os.path.join(R.repo, GUARD_SRC), 'w').write('// guard\\n' + ('const held = process.env.GUARD_HELD_ENV;\\n' if text else ''))""")
R("""    assert 'held: transcribe(guard)' in out, out""",
  """    assert 'guard probe: the built guard refuses' in out and 'guard startup log:' in out, out""")
R("""def test_guard_hold_line_written_and_recorded(tmp_path):""", """def test_transcribe_hold_string_present_behaviour_absent_holds_transcode(R):
    \"\"\"D1: the source names GUARD_HELD_ENV but the built guard starts anyway on a malformed value: hold all of transcode.\"\"\"
    _guard_source(R, False, text=True); _conf(R, 'SELFHOST_JOB_HOLD', 'transcribe')
    sha = R.release('release/wave-61s'); rc, out = R.run('release/wave-61s', sha)
    assert rc == 0, out
    assert R.jobs()['JOB_IMAGE_TRANSCODE'] == BASE_JOBS['JOB_IMAGE_TRANSCODE'] and 'guard lacks GUARD_HELD_ENV' in out, out
    assert 'GUARDPROBE' in R.dlog() and _guard_line(R) == []


def test_guard_not_reporting_hold_after_switch_rolls_back(R):
    \"\"\"D1: the running guard's startup line must name the hold; if it does not, the switch is rolled back.\"\"\"
    before = R.get('live'); _guard_source(R, True); _conf(R, 'SELFHOST_JOB_HOLD', 'transcribe'); R.put('guard-log-missing', '')
    sha = R.release('release/wave-61g'); rc, out = R.run('release/wave-61g', sha)
    assert rc == 5 and 'does not report the transcription hold' in out and 'ROLLED BACK' in out, out
    assert R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.get('live') == before


def test_guard_hold_line_written_and_recorded(tmp_path):""")
R("""    assert 'BUILD goodqa-transcode' not in R.dlog() and 'guard lacks GUARD_HELD_ENV' in out, out
    assert _guard_line(R) == []""", """    assert 'guard lacks GUARD_HELD_ENV' in out and 'GUARDPROBE' in R.dlog(), out
    loads = [l for l in R.dlog().split('\\n') if 'LOAD' in l]
    assert loads and not any('goodqa-transcode' in l for l in loads), loads
    assert _guard_line(R) == []""")
R('''t = t.replace(old4, "    assert 'BUILD goodqa-intelligence-worker' not in R.dlog() and 'held: transcode(whole image) intelligence-worker' in out, out")''',
  '''t = t.replace(old4, "    assert 'BUILD goodqa-intelligence-worker' not in R.dlog() and 'held: intelligence-worker' in out and 'guard lacks GUARD_HELD_ENV' in out, out")''')
fake = r'''old6 = """if a[:2] == ['image', 'inspect']:"""
assert t.count(old6) == 1
t = t.replace(old6, """if a[0] == 'run' and 'src/create-guard-main.ts' in a:          # goodqa#16136 D1: probe of the built guard
    env = dict(a[i + 1].split('=', 1) for i, x in enumerate(a) if x == '-e'); log('GUARDPROBE held=%s' % env.get('GUARD_HELD_ENV'))
    if mark('guard-held-support') and '=' not in env.get('GUARD_HELD_ENV', '='):
        print('Error: GUARD_HELD_ENV must be KEY=VALUE', file=sys.stderr); sys.exit(1)
    print('job-dispatcher-create-guard listening on :2376'); sys.exit(0)
""" + old6, 1)
old7 = """    if sub == 'logs':
"""
assert t.count(old7) == 1
t = t.replace(old7, old7 + """        if 'job-dispatcher-create-guard' in rest:
            m = re.search(r'^      GUARD_HELD_ENV:[ \\\\t]*(\\\\S+)', text, re.M)
            if not mark('guard-log-missing'):
                print('job-dispatcher-create-guard listening on :2376, upstream={}, allowedImages=4' +
                      (', heldEnv=%s' % (m.group(1) if m else 'none') if mark('guard-held-support') else ''))
            sys.exit(0)
""")
'''
anchor = "open(p, 'w').write(t)\nprint('patched tests v2.1')"
assert t.count(anchor) == 1
t = t.replace(anchor, fake + anchor)
open(p, 'w').write(t); print('ok')
