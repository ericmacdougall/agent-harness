"""Third patch (spec v2.1: transcription guard hold, coupling). python3 patch_tests3.py FILE"""
import sys
p = sys.argv[1]; t = open(p).read()
t += r'''


# ---------------------------------------------------------------- goodqa#16136 spec v2.1: transcription guard hold + coupling
GUARD_SRC = 'apps/job-dispatcher/src/create-guard-main.ts'


def _guard_source(R, supports, text=None):
    """supports: the built guard behaves (fake docker marker); text: its source mentions GUARD_HELD_ENV (default: same)."""
    if supports: R.put('guard-held-support', '')
    text = supports if text is None else text
    d = os.path.join(R.repo, os.path.dirname(GUARD_SRC)); os.makedirs(d, exist_ok=True)
    open(os.path.join(R.repo, GUARD_SRC), 'w').write('// guard\n' + ('const held = process.env.GUARD_HELD_ENV;\n' if text else ''))
    base.git('add', '-A', cwd=R.repo); base.git('commit', '-q', '-m', 'guard source', cwd=R.repo)
    base.git('push', '-q', 'origin', 'HEAD:main', cwd=R.repo)


def _guard_line(R):
    t = open(os.path.join(R.vm, 'compose.yaml')).read()
    return [l.strip() for l in t.split('\n') if 'GUARD_HELD_ENV' in l]


def test_transcribe_hold_with_guard_support_pins_transcode(R):
    """AC-16/AC-17: the release's guard implements GUARD_HELD_ENV: transcode (MP4) is pinned, transcription is held at
    the guard by its one line, and the run log and deploy record name the hold."""
    _guard_source(R, True); _conf(R, 'SELFHOST_JOB_HOLD', 'transcribe')
    sha = R.release('release/wave-61t'); rc, out = R.run('release/wave-61t', sha)
    assert rc == 0, out
    assert re.fullmatch(r'goodqa-transcode@sha256:[0-9a-f]{64}', R.jobs()['JOB_IMAGE_TRANSCODE']), R.jobs()
    assert _guard_line(R) == ['GUARD_HELD_ENV: TRANSCODER_MODE=transcribe'], _guard_line(R)
    assert 'guard probe: the built guard refuses' in out and 'guard startup log:' in out, out
    rec = subprocess.run(['git', 'show', 'main:' + subprocess.run(['git', 'ls-tree', '-r', '--name-only', 'main', 'audit/selfhost-deploys'],
                          cwd=R.origin, capture_output=True, text=True).stdout.split()[0]], cwd=R.origin, capture_output=True, text=True).stdout
    assert '"transcribe(guard)"' in rec, rec


def test_transcribe_hold_without_guard_support_holds_transcode(R):
    """AC-17: the release's guard has no GUARD_HELD_ENV: the whole transcode image stays on its current pin (MP4 waits),
    so no transcription container can start in between."""
    _guard_source(R, False); _conf(R, 'SELFHOST_JOB_HOLD', 'transcribe')
    sha = R.release('release/wave-61n'); rc, out = R.run('release/wave-61n', sha)
    assert rc == 0, out
    assert R.jobs()['JOB_IMAGE_TRANSCODE'] == BASE_JOBS['JOB_IMAGE_TRANSCODE'], R.jobs()
    assert 'guard lacks GUARD_HELD_ENV' in out and 'GUARDPROBE' in R.dlog(), out
    loads = [l for l in R.dlog().split('\n') if 'LOAD' in l]
    assert loads and not any('goodqa-transcode' in l for l in loads), loads
    assert _guard_line(R) == []


def test_transcribe_hold_string_present_behaviour_absent_holds_transcode(R):
    """D1: the source names GUARD_HELD_ENV but the built guard starts anyway on a malformed value: hold all of transcode."""
    _guard_source(R, False, text=True); _conf(R, 'SELFHOST_JOB_HOLD', 'transcribe')
    sha = R.release('release/wave-61s'); rc, out = R.run('release/wave-61s', sha)
    assert rc == 0, out
    assert R.jobs()['JOB_IMAGE_TRANSCODE'] == BASE_JOBS['JOB_IMAGE_TRANSCODE'] and 'guard lacks GUARD_HELD_ENV' in out, out
    assert 'GUARDPROBE' in R.dlog() and _guard_line(R) == []


def test_guard_not_reporting_hold_after_switch_rolls_back(R):
    """D1: the running guard's startup line must name the hold; if it does not, the switch is rolled back."""
    before = R.get('live'); _guard_source(R, True); _conf(R, 'SELFHOST_JOB_HOLD', 'transcribe'); R.put('guard-log-missing', '')
    sha = R.release('release/wave-61g'); rc, out = R.run('release/wave-61g', sha)
    assert rc == 5 and 'does not report the transcription hold' in out and 'ROLLED BACK' in out, out
    assert R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.get('live') == before


def test_guard_hold_line_written_and_recorded(tmp_path):
    """AC-16: ctl writes exactly one GUARD_HELD_ENV line in the create-guard block; state reports it; a pin without
    --guard-hold removes it again (the hold is per release, never left behind silently)."""
    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
    rc, o = ctl(*(list(PIN) + ['--guard-hold', 'TRANSCODER_MODE=transcribe']))
    assert rc == 0 and J(o)['guard_hold'] == 'TRANSCODER_MODE=transcribe', o
    t = open(vm / 'compose.yaml').read()
    assert t.count('GUARD_HELD_ENV') == 1 and job_pins(t) == {'job-dispatcher-create-guard': NEW_JOBS}
    args = list(PIN); args[args.index('S1')] = 'S2'
    rc2, o2 = ctl(*args)
    assert rc2 == 0 and J(o2)['guard_hold'] is None and 'GUARD_HELD_ENV' not in open(vm / 'compose.yaml').read(), o2


@pytest.mark.parametrize('value', ['TRANSCODER_MODE=Transcribe', 'TRANSCODER_MODE=frames', 'OTHER=transcribe', 'TRANSCODER_MODE', 'twice'])
def test_ctl_guard_hold_refusals(tmp_path, value):
    """NEG-14: --guard-hold takes exactly one value, TRANSCODER_MODE=transcribe; anything else changes nothing."""
    ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap()
    extra = ['--guard-hold', 'TRANSCODER_MODE=transcribe'] * 2 if value == 'twice' else ['--guard-hold', value]
    rc, o = ctl(*(list(PIN) + extra))
    assert rc == 3 and o.startswith('REFUSED'), o
    assert snap() == before


def test_held_line_marked_and_excluded_from_jobs_missing(tmp_path):
    """B4: a held key's line carries `# held`; state lists it in jobs_held and never in jobs_missing."""
    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
    rc, o = ctl(*(_swap(PIN, INTEL, None) + ['--job-hold', INTEL]))
    assert rc == 0, o
    assert '      %s: %s # held' % (INTEL, BASE_JOBS[INTEL]) in open(vm / 'compose.yaml').read()
    s = J(ctl('state')[1]); assert s['jobs_held'] == [INTEL] and s['jobs_missing'] == [], s
'''
# B4: the earlier hold test expected the held DO ref in jobs_missing; held refs are now excluded
old = "    assert J(o)['jobs'] == want and J(o)['jobs_missing'] == [BASE_JOBS[INTEL]], o"
assert t.count(old) == 1
t = t.replace(old, "    assert J(o)['jobs'] == want and J(o)['jobs_missing'] == [] and J(o)['jobs_held'] == [INTEL], o")
old2 = "    rc2, o2 = ctl(*(_swap(PIN, INTEL, None) + ['--job-hold', INTEL, '--job-hold', INTEL]))"
assert t.count(old2) == 1
t = t.replace(old2, "    args2 = _swap(PIN, INTEL, None) + ['--job-hold', INTEL, '--job-hold', INTEL]; args2[args2.index('S1')] = 'S2'\n    rc2, o2 = ctl(*args2)")
old3 = "'apps/api/Dockerfile', 'apps/web/Dockerfile', 'apps/job-dispatcher/Dockerfile')"
assert t.count(old3) == 1
t = t.replace(old3, "'apps/api/Dockerfile', 'apps/web/Dockerfile', 'apps/job-dispatcher/Dockerfile',\n"
              "           'apps/scan-worker/Dockerfile', 'apps/transcoder/Dockerfile', 'apps/intelligence-worker/Dockerfile',\n"
              "           'apps/suggest-fix-worker/Dockerfile')   # goodqa#16136: the job images are production Dockerfiles too")
old4 = "    assert 'BUILD goodqa-intelligence-worker' not in R.dlog() and 'held: intelligence-worker' in out, out"
assert t.count(old4) == 1
t = t.replace(old4, "    assert 'BUILD goodqa-intelligence-worker' not in R.dlog() and 'held: intelligence-worker' in out and 'guard lacks GUARD_HELD_ENV' in out, out")
old5 = "    assert all(re.fullmatch(r'goodqa-[a-z-]+@sha256:[0-9a-f]{64}', v) for k, v in j.items() if k != INTEL), j"
assert t.count(old5) == 1
t = t.replace(old5, "    assert j['JOB_IMAGE_TRANSCODE'] == BASE_JOBS['JOB_IMAGE_TRANSCODE'], 'default also holds transcribe; this guard cannot, so all of transcode'\n"
              "    assert all(re.fullmatch(r'goodqa-[a-z-]+@sha256:[0-9a-f]{64}', v) for k, v in j.items() if k not in (INTEL, 'JOB_IMAGE_TRANSCODE')), j")
old6 = """if a[:2] == ['image', 'inspect']:"""
assert t.count(old6) == 1
t = t.replace(old6, """if a[0] == 'run' and 'src/create-guard-main.ts' in a:          # goodqa#16136 D1: probe of the built guard
    env = dict(a[i + 1].split('=', 1) for i, x in enumerate(a) if x == '-e'); log('GUARDPROBE held=%s' % env.get('GUARD_HELD_ENV'))
    if mark('guard-held-support') and '=' not in env.get('GUARD_HELD_ENV', '='):
        print('Error: GUARD_HELD_ENV must be KEY=VALUE', file=sys.stderr)   # then a real node stack trace (seen on t2-dev)
        for n in range(12): print('    at frame%d (node:internal/modules/esm/module_job:%d:25)' % (n, n), file=sys.stderr)
        print('Node.js v22', file=sys.stderr); sys.exit(1)
    print('job-dispatcher-create-guard listening on :2376'); sys.exit(124 if mark('guard-old-timeout') else 0)
""" + old6, 1)
old7 = """    if sub == 'logs':
"""
assert t.count(old7) == 1
t = t.replace(old7, old7 + """        if 'job-dispatcher-create-guard' in rest:
            m = re.search(r'^      GUARD_HELD_ENV:[ \\t]*(\\S+)', text, re.M)
            if not mark('guard-log-missing'):
                print('job-dispatcher-create-guard listening on :2376, upstream={}, allowedImages=4' +
                      (', heldEnv=%s' % (m.group(1) if m else 'none') if mark('guard-held-support') else ''))
            sys.exit(0)
""")
open(p, 'w').write(t)
print('patched tests v2.1')
