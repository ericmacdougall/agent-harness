"""receipt bth-pr73-v4b F1 (fixed upstream in 1370's selfhost-ctl.py): every JOB_IMAGE_* key, held ones included, must sit
under services.<svc>.environment, with exact guard/dispatcher parity in the RESOLVED compose.
usage: python3 f73-envkeys-patch.py <release-harness dir> [--tests-only | --src-only]"""
import os, sys

d = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else ''


def edit(name, pairs):
    p = os.path.join(d, name); t = open(p).read()
    for old, new in pairs:
        assert t.count(old) == 1, (name, old[:90])
        t = t.replace(old, new)
    open(p, 'w').write(t)


SRC = [
    # job_lines: a JOB_IMAGE_* line must be under the create-guard's `environment:` mapping, not labels or any other key
    ('''        lines = text.split('\\n'); res = {}; cur = None; in_svc = False
        for i, l in enumerate(lines):
            if l.rstrip() == 'services:': in_svc = True; cur = None; continue
            if l and not l.startswith(' ') and not l.startswith('#'): in_svc = False; cur = None
            m = re.match(r'^  ([A-Za-z0-9_.-]+):\\s*(#.*)?$', l)
            if in_svc and m: cur = m.group(1); continue
            if 'JOB_IMAGE_' not in l.split('#', 1)[0]: continue
            m = JOB_LINE_RE.match(l)
            if not m or not in_svc or cur != JOB_BLOCK:''',
     '''        lines = text.split('\\n'); res = {}; cur = None; in_svc = False; sub = None
        for i, l in enumerate(lines):
            if l.rstrip() == 'services:': in_svc = True; cur = None; sub = None; continue
            if l and not l.startswith(' ') and not l.startswith('#'): in_svc = False; cur = None; sub = None
            m = re.match(r'^  ([A-Za-z0-9_.-]+):\\s*(#.*)?$', l)
            if in_svc and m: cur = m.group(1); sub = None; continue
            m = re.match(r'^    ([A-Za-z0-9_.<-]+):', l)               # review bth-pr73-v4b F1: the service key a line is under
            if in_svc and cur and m: sub = m.group(1)
            if 'JOB_IMAGE_' not in l.split('#', 1)[0]: continue
            m = JOB_LINE_RE.match(l)
            if not m or not in_svc or cur != JOB_BLOCK or sub != 'environment':'''),
    ('''    svcs = stk.resolved(comp)
    want_jobs = {k: v for k, v in stk.jobs(comp).items() if k not in held}
    for s in (JOB_BLOCK, 'job-dispatcher'):
        envs = (svcs.get(s) or {}).get('environment') or {}
        got = {k: envs.get(k) for k in want_jobs}
        if got != want_jobs: raise Refused('resolved compose: %s does not carry the pinned job images (%s)' % (s, got))
''', '''    svcs = stk.resolved(comp)
    marked = set(stk.held_keys(comp))
    want_jobs = {k: v for k, v in stk.jobs(comp).items() if k not in held}
    # review bth-pr73-v4b F1: every key, held ones included ("" in the resolved env), under environment, in both services
    want_env = {k: ('' if k in marked else v) for k, v in stk.jobs(comp).items()}
    for s in (JOB_BLOCK, 'job-dispatcher'):
        envs = (svcs.get(s) or {}).get('environment')
        if not isinstance(envs, dict): raise Refused('resolved compose: %s has no environment mapping' % s)
        got = {k: envs[k] for k in envs if k.startswith('JOB_IMAGE_')}
        if got != want_env:
            raise Refused('resolved compose: %s environment does not carry exactly the job image lines (%s)'
                          % (s, ', '.join('%s=%s' % (k, 'held' if got.get(k) == '' else 'set' if k in got else 'missing') for k in sorted(set(want_env) | set(got)))))
'''),
]

FAKE = [
    # the fake `docker compose config`: JOB_IMAGE_* lines land under the 4-space key they sit in (environment or labels),
    # with "" resolved to the empty string as compose does
    ('''        text = open(files[0]).read(); p0 = {}; jp = {}; cur = None
        for l in text.split('\\n'):
            m = re.match(r'^    image:\\s*(\\S+)', l)
            if m and cur: p0[cur] = m.group(1)
            m = re.match(r'^  ([A-Za-z0-9_.-]+):\\s*(#.*)?$', l)
            if m: cur = m.group(1); continue
            m = re.match(r'^      (JOB_IMAGE_[A-Z0-9_]+):\\s*(\\S+)', l)
            if m and cur: jp.setdefault(cur, {})[m.group(1)] = m.group(2)
''', '''        text = open(files[0]).read(); p0 = {}; jp = {}; lab = {}; cur = None; sub = None
        for l in text.split('\\n'):
            m = re.match(r'^    image:\\s*(\\S+)', l)
            if m and cur: p0[cur] = m.group(1)
            m = re.match(r'^  ([A-Za-z0-9_.-]+):\\s*(#.*)?$', l)
            if m: cur = m.group(1); sub = None; continue
            m = re.match(r'^    ([A-Za-z0-9_.<-]+):', l)
            if m and cur: sub = m.group(1)
            m = re.match(r'^      (JOB_IMAGE_[A-Z0-9_]+):\\s*(\\S+)', l)
            if m and cur:
                v = '' if m.group(2) in ('""', "''") else m.group(2)
                (jp if sub == 'environment' else lab).setdefault(cur, {})[m.group(1)] = v
        if mark('resolved-drop-held'):                      # compose resolves the dispatcher without a held key
            for k in [k for k, v in jp.get('job-dispatcher-create-guard', {}).items() if v == '']: jp.setdefault('job-dispatcher', {})[k] = None
'''),
    ('''        svcs.setdefault('job-dispatcher', {})['environment'] = dict(g, **jp.get('job-dispatcher', {}))
''', '''        svcs.setdefault('job-dispatcher', {})['environment'] = {k: v for k, v in dict(g, **jp.get('job-dispatcher', {})).items() if v is not None}
        for s, kv in lab.items(): svcs.setdefault(s, {})['labels'] = dict(kv)
'''),
]

TESTS = r'''

# ---- receipt bth-pr73-v4b F1: a JOB_IMAGE_* key, held or not, counts only under environment, in both services
HOLD_INTEL = ('--job-hold', 'JOB_IMAGE_INTELLIGENCE_WORKER')
PIN_HELD = PIN0 + tuple(x for k, v in NEW_JOBS.items() if k != 'JOB_IMAGE_INTELLIGENCE_WORKER' for x in ('--job-image', '%s=%s' % (k, v))) + HOLD_INTEL


def _move_intel_to_labels(vm, held):
    p = vm / 'compose.yaml'; t = p.read_text()
    line = next(l for l in t.split('\n') if l.startswith('      JOB_IMAGE_INTELLIGENCE_WORKER:'))
    new = '      JOB_IMAGE_INTELLIGENCE_WORKER: "" # held' if held else line
    t = t.replace(line + '\n', '')
    t = t.replace('  job-dispatcher-create-guard:\n    image: goodqa-job-dispatcher:base\n',
                  '  job-dispatcher-create-guard:\n    image: goodqa-job-dispatcher:base\n    labels:\n' + new + '\n')
    p.write_text(t)


@pytest.mark.parametrize('held', [True, False])
def test_job_key_under_labels_is_refused(tmp_path, held):
    ctl, snap, st, vm, env = ctl_fixture(tmp_path); _move_intel_to_labels(vm, held); before = snap()
    rc, o = ctl(*(PIN_HELD if held else PIN))
    assert rc == 3 and 'outside the job-dispatcher-create-guard &job-images block' in o, o
    assert snap() == before


def test_held_key_pin_passes_and_is_held_in_both_resolved_envs(tmp_path):
    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
    rc, o = ctl(*PIN_HELD)
    assert rc == 0, o
    assert J(o)['jobs_held'] == ['JOB_IMAGE_INTELLIGENCE_WORKER'], o


def test_resolved_compose_dropping_a_held_key_is_refused(tmp_path):
    """The text parser sees the held line, but the RESOLVED dispatcher env lacks it: parity fails closed."""
    ctl, snap, st, vm, env = ctl_fixture(tmp_path); (st / 'resolved-drop-held').write_text(''); before = snap()
    rc, o = ctl(*PIN_HELD)
    assert rc == 3 and 'job-dispatcher environment does not carry exactly the job image lines' in o and 'JOB_IMAGE_INTELLIGENCE_WORKER=missing' in o, o
    assert snap() == before
'''

if mode != '--tests-only':
    edit('selfhost-ctl.py', SRC)
if mode != '--src-only':
    edit('test_rw_ship_selfhost.py', FAKE)
    open(os.path.join(d, 'test_rw_ship_selfhost.py'), 'a').write(TESTS)
print('patched', mode or 'all')
