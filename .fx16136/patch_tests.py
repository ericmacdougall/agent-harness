"""Patch test_rw_ship_selfhost.py for goodqa#16136 (job images). Run on t2-dev: python3 - PATH < patch_tests.py"""
import sys
p = sys.argv[1]; t = open(p).read()


def rep(old, new, count=1):
    global t
    n = t.count(old)
    assert n == count, (n, old[:80])
    t = t.replace(old, new)


# docstring
rep('''  * NEGATIVE CONTROLS: mutated copies''', '''  * goodqa#16136: the four dispatcher job images (scan, transcode, intelligence-worker, suggest-fix-worker) are built,
    transferred, id-checked and pinned as goodqa-<job>@<host image id> in the &job-images anchor; every image the prepared
    compose names must be on the host before the switch; job pins roll back with compose.yaml; restore never runs that check
  * NEGATIVE CONTROLS: mutated copies''')

# fake docker: containerd image store resolves repo@<image id> for a loaded/built image of that repo
rep('''if a[:2] == ['image', 'inspect']:
    ref = a[-1]
    if ref in imgs: print(imgs[ref]); sys.exit(0)
    sys.exit(1)''', '''def resolve(ref):
    if ref in imgs: return imgs[ref]
    m = re.match(r'^([^@]+)@(sha256:[0-9a-f]{64})$', ref)        # containerd store: repo@<image id> of a tag of that repo
    if m and any(k.split(':')[0] == m.group(1) and v == m.group(2) for k, v in imgs.items() if '@' not in k): return m.group(2)
    return None
if a[:2] == ['image', 'inspect']:
    i = resolve(a[-1])
    if i: print(i); sys.exit(0)
    sys.exit(1)''')
rep('''        missing = [p[s] for s in svcs if p[s] not in imgs]''', '''        missing = [p[s] for s in svcs if not resolve(p[s])]''')
rep('''                             'image': imgs[p[s]], 'status': 'running', 'health': h})''',
    '''                             'image': resolve(p[s]), 'status': 'running', 'health': h})''')

# compose fixture: the guard's &job-images anchor carries the four DO-registry pins production has had since the cutover
rep('''    environment: &job-images
      GUARD_ENV: production
''', '''    environment: &job-images
      GUARD_ENV: production
      JOB_IMAGE_SCAN: registry.digitalocean.com/goodqa-prod/bugtracker-scan@sha256:{d1}
      JOB_IMAGE_TRANSCODE: registry.digitalocean.com/goodqa-prod/bugtracker-transcode@sha256:{d2}
      JOB_IMAGE_INTELLIGENCE_WORKER: registry.digitalocean.com/goodqa-prod/bugtracker-intelligence-worker@sha256:{d3}
      JOB_IMAGE_SUGGEST_FIX_WORKER: registry.digitalocean.com/goodqa-prod/bugtracker-suggest-fix-worker@sha256:{d4}
''')
rep('''      <<: *job-images

networks:''', '''      <<: *job-images
      JOB_DISPATCHER_ENV: production

networks:''')
rep('''PROMOTE = r\'\'\'''', '''JOBS = {'JOB_IMAGE_SCAN': ('scan', 'apps/scan-worker'), 'JOB_IMAGE_TRANSCODE': ('transcode', 'apps/transcoder'),
        'JOB_IMAGE_INTELLIGENCE_WORKER': ('intelligence-worker', 'apps/intelligence-worker'),
        'JOB_IMAGE_SUGGEST_FIX_WORKER': ('suggest-fix-worker', 'apps/suggest-fix-worker')}
DO_DIG = {'d1': '4f' * 32, 'd2': 'de' * 32, 'd3': '5a' * 32, 'd4': 'd5' * 32}
BASE_JOBS = {'JOB_IMAGE_SCAN': 'registry.digitalocean.com/goodqa-prod/bugtracker-scan@sha256:' + DO_DIG['d1'],
             'JOB_IMAGE_TRANSCODE': 'registry.digitalocean.com/goodqa-prod/bugtracker-transcode@sha256:' + DO_DIG['d2'],
             'JOB_IMAGE_INTELLIGENCE_WORKER': 'registry.digitalocean.com/goodqa-prod/bugtracker-intelligence-worker@sha256:' + DO_DIG['d3'],
             'JOB_IMAGE_SUGGEST_FIX_WORKER': 'registry.digitalocean.com/goodqa-prod/bugtracker-suggest-fix-worker@sha256:' + DO_DIG['d4']}


def compose_text(env):
    return COMPOSE.format(env=env, **DO_DIG)


def job_pins(text):
    """{KEY: value} for JOB_IMAGE_* lines, per service block: {'svc': {...}}."""
    res = {}; cur = None
    for l in text.split('\\n'):
        m = re.match(r'^  ([A-Za-z0-9_.-]+):\\s*(#.*)?$', l)
        if m: cur = m.group(1); continue
        m = re.match(r'^      (JOB_IMAGE_[A-Z_]+):\\s*(\\S+)', l)
        if m and cur: res.setdefault(cur, {})[m.group(1)] = m.group(2)
    return res


PROMOTE = r\'\'\'''')
rep('''        open(os.path.join(self.vm, 'compose.yaml'), 'w').write(COMPOSE.format(env=self.envd))''',
    '''        open(os.path.join(self.vm, 'compose.yaml'), 'w').write(compose_text(self.envd))''')
rep('''        for d in ('apps/web', 'apps/job-dispatcher'): os.makedirs(os.path.join(self.repo, d), exist_ok=True)''',
    '''        for d in ('apps/web', 'apps/job-dispatcher') + tuple(v[1] for v in JOBS.values()):
            os.makedirs(os.path.join(self.repo, d), exist_ok=True); open(os.path.join(self.repo, d, 'Dockerfile'), 'w').write('FROM scratch\\n')''')
rep('''                   'goodqa-web:other': 'sha256:' + 'e' * 64, 'goodqa-job-dispatcher:base': 'sha256:' + 'c' * 64},''',
    '''                   'goodqa-web:other': 'sha256:' + 'e' * 64, 'goodqa-job-dispatcher:base': 'sha256:' + 'c' * 64,
                   'caddy@sha256:cad': 'sha256:' + '9' * 64},''')
rep('''    def env_sha(self, f='api'):''', '''    def jobs(self, svc='job-dispatcher-create-guard'):
        return job_pins(open(os.path.join(self.vm, 'compose.yaml')).read()).get(svc, {})

    def env_sha(self, f='api'):''')
rep('''    assert R.pins() == BASE_PINS, R.pins()
    assert R.env_sha('api') == before_live''', '''    assert R.pins() == BASE_PINS, R.pins()
    assert R.jobs() == BASE_JOBS, R.jobs()
    assert R.env_sha('api') == before_live''')

# rollback restores the job pins too (AC-11)
rep('''    assert R.pins() == BASE_PINS, 'compose.yaml back on the previous pins'
''', '''    assert R.pins() == BASE_PINS, 'compose.yaml back on the previous pins'
    assert R.jobs() == BASE_JOBS, 'the job image pins roll back with compose.yaml'
''')
# full disk message names the seven images
rep('''        assert rc == 11 and 'NO DISK' in out, out''', '''        assert rc == 11 and 'NO DISK' in out and 'seven images' in out, out''')

# ---- new rw-ship tests
rep('''def test_migrations_applied_before_the_switch(R):''', '''def test_selfhost_release_ships_job_images(R):
    """goodqa#16136 AC-1/AC-2: the four job images are built from the release sha, loaded on the VM with matching ids, and
    the &job-images anchor (guard; the dispatcher inherits it) is pinned to goodqa-<job>@<VM image id>."""
    sha = R.release('release/wave-60j'); rc, out = R.run('release/wave-60j', sha)
    assert rc == 0, out
    vm_imgs = json.load(open(os.path.join(R.st, 'docker', 'images-remote.json')))
    tag = R.pins()['api'].split(':', 1)[1]
    want = {}
    for key, (job, _) in JOBS.items():
        ref = 'goodqa-%s:%s' % (job, tag)
        assert ref in vm_imgs, 'job image %s was not transferred to the VM' % ref
        assert 'BUILD ' + ref in R.dlog(), 'job image %s was not built' % ref
        want[key] = 'goodqa-%s@%s' % (job, vm_imgs[ref])
    assert R.jobs() == want, R.jobs()
    assert all(re.fullmatch(r'goodqa-[a-z-]+@sha256:[0-9a-f]{64}', v) for v in R.jobs().values()), 'AUD-031 digest form'
    assert R.jobs('job-dispatcher') == {}, 'the dispatcher keeps inheriting the anchor, no divergent copy'
    rec = subprocess.run(['git', 'show', 'main:' + subprocess.run(['git', 'ls-tree', '-r', '--name-only', 'main', 'audit/selfhost-deploys'],
                          cwd=R.origin, capture_output=True, text=True).stdout.split()[0]], cwd=R.origin, capture_output=True, text=True).stdout
    assert all('goodqa-%s:%s' % (j, tag) in rec for j, _ in JOBS.values()), 'the deploy record lists the job images'


def test_job_images_build_failure_changes_nothing(R):
    before = R.get('live'); R.put('fail-build', 'goodqa-transcode'); sha = R.release('release/wave-60k')
    rc, out = R.run('release/wave-60k', sha)
    assert rc == 3 and 'build transcode' in out, out
    unchanged(R, before)


def test_migrations_applied_before_the_switch(R):''')

# ---- selfhost-ctl tests
rep('''    (vm / 'compose.yaml').write_text(COMPOSE.format(env=env))''', '''    (vm / 'compose.yaml').write_text(compose_text(env))''', 2)
rep('''                                                                  'goodqa-job-dispatcher:base': 'sha256:c', 'n:api': 'sha256:1', 'n:web': 'sha256:2', 'n:disp': 'sha256:3'}))''',
    '''                                                                  'goodqa-job-dispatcher:base': 'sha256:c', 'n:api': 'sha256:1', 'n:web': 'sha256:2', 'n:disp': 'sha256:3',
                                                                  'caddy@sha256:cad': 'sha256:9',
                                                                  **{'goodqa-%s:t1' % j: 'sha256:' + JID[j] for j, _ in JOBS.values()}}))''')
rep('''PIN = ('pin', '--stamp', 'S1',''', '''def J(o):
    return json.loads(next(l for l in o.split('\\n') if l.startswith('{')))


JID = {'scan': '1' * 64, 'transcode': '2' * 64, 'intelligence-worker': '3' * 64, 'suggest-fix-worker': '4' * 64}
NEW_JOBS = {k: 'goodqa-%s@sha256:%s' % (j, JID[j]) for k, (j, _) in JOBS.items()}
JOBARGS = tuple(x for k, v in NEW_JOBS.items() for x in ('--job-image', '%s=%s' % (k, v)))
PIN0 = ('pin', '--stamp', 'S1',''')
rep(''''--web', 'n:web', '--disp', 'n:disp')


def test_ctl_pin_then''', ''''--web', 'n:web', '--disp', 'n:disp')
PIN = PIN0 + JOBARGS


def test_ctl_pin_then''')
rep('''    a, b = json.loads(s0), json.loads(s1)''', '''    a, b = J(s0), J(s1)''')
rep('''    assert rc == 0 and json.loads(s2)['fp'] == a['fp'] and snap() == before''', '''    assert rc == 0 and J(s2)['fp'] == a['fp'] and snap() == before''')
rep('''    assert a['fp'] != b['fp'] and 'A=1' in open(env / 'api.env').read(), 'other env lines are kept'
''', '''    assert a['fp'] != b['fp'] and 'A=1' in open(env / 'api.env').read(), 'other env lines are kept'
    assert a['jobs'] == BASE_JOBS and b['jobs'] == NEW_JOBS, b.get('jobs')
    assert job_pins(open(vm / 'compose.yaml').read()) == {'job-dispatcher-create-guard': NEW_JOBS}
''')

t += '''

# ---------------------------------------------------------------- goodqa#16136: job image pins + presence check (selfhost-ctl)
def _swap(args, key, value):
    a = list(args); i = a.index('%s=%s' % (key, NEW_JOBS[key])); a[i] = '%s=%s' % (key, value) if value is not None else None
    if value is None: del a[i - 1:i + 1]
    return a


@pytest.mark.parametrize('case', ['mutable-tag', 'wrong-repo', 'unknown-key', 'duplicate-key', 'partial-set', 'metachar',
                                  'bare-id', 'do-ref', 'no-job-args'])
def test_ctl_job_images_refusals_change_nothing(tmp_path, case):
    """NEG-2: every --job-image value that is not exactly goodqa-<the key's own job>@sha256:<64 hex>, once per key, all four."""
    ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap()
    S = 'JOB_IMAGE_SCAN'
    args = {'mutable-tag': lambda: _swap(PIN, S, 'goodqa-scan:latest'),
            'wrong-repo': lambda: _swap(PIN, 'JOB_IMAGE_INTELLIGENCE_WORKER', NEW_JOBS[S]),
            'unknown-key': lambda: list(PIN) + ['--job-image', 'JOB_IMAGE_EVIL=goodqa-scan@sha256:' + JID['scan']],
            'duplicate-key': lambda: list(PIN) + ['--job-image', '%s=%s' % (S, NEW_JOBS[S])],
            'partial-set': lambda: _swap(PIN, 'JOB_IMAGE_TRANSCODE', None),
            'metachar': lambda: _swap(PIN, S, NEW_JOBS[S] + '\\n      GUARD_ENV: dev'),
            'bare-id': lambda: _swap(PIN, S, 'sha256:' + JID['scan']),
            'do-ref': lambda: _swap(PIN, S, BASE_JOBS[S]),
            'no-job-args': lambda: list(PIN0)}[case]()
    rc, o = ctl(*args)
    assert rc in (2, 3) and (rc == 2 or o.startswith('REFUSED')), (rc, o)
    assert snap() == before and not [f for f in os.listdir(vm) + os.listdir(env) if 'pre-rw' in f or 'rw-pin' in f]


@pytest.mark.parametrize('case', ['job-image-absent', 'other-repo-same-id', 'tag-removed-content-kept', 'id-mismatch'])
def test_ctl_pin_refuses_missing_job_image(tmp_path, case):
    """NEG-1 / AC-3: a release-managed job ref the host cannot resolve, by the exact compose string with a matching Id,
    refuses the pin before any change. The fake models the containerd store: repo@digest resolves only while a
    same-repo tag targets that id."""
    ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap()
    p = st / 'docker' / 'images-remote.json'; d = json.loads(p.read_text())
    args = list(PIN)
    if case == 'job-image-absent': d.pop('goodqa-suggest-fix-worker:t1')
    if case == 'other-repo-same-id': args = _swap(PIN, 'JOB_IMAGE_SCAN', 'goodqa-scan@sha256:' + JID['transcode'])
    if case == 'tag-removed-content-kept': d['other-repo:t1'] = d.pop('goodqa-scan:t1')
    if case == 'id-mismatch': (st / 'id-skew').write_text('goodqa-transcode@')
    p.write_text(json.dumps(d))
    rc, o = ctl(*args)
    assert rc == 3 and o.startswith('REFUSED') and 'not present on this host' in o, o
    assert snap() == before and not [f for f in os.listdir(vm) + os.listdir(env) if 'pre-rw' in f or 'rw-pin' in f]


def test_presence_check_uses_prepared_compose(tmp_path):
    """AC-3: the live compose still names the DO-registry job refs, which no host has; the check reads the PREPARED text,
    so the first release of this fix is not refused by the very pins it replaces."""
    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
    assert all(v not in json.loads((st / 'docker' / 'images-remote.json').read_text()) for v in BASE_JOBS.values())
    rc, o = ctl(*PIN)
    assert rc == 0, o
    assert J(o)['missing'] == [] and J(o)['jobs'] == NEW_JOBS and J(o)['jobs_missing'] == []


def test_ctl_job_images_divergent_dispatcher_copy_refuses(tmp_path):
    """The dispatcher must inherit the guard's anchor: a JOB_IMAGE_* line in any other service block would let the two diverge."""
    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
    c = vm / 'compose.yaml'; c.write_text(c.read_text().replace('      JOB_DISPATCHER_ENV: production\\n',
                                                                 '      JOB_DISPATCHER_ENV: production\\n      JOB_IMAGE_SCAN: x@sha256:' + '0' * 64 + '\\n'))
    before = snap(); rc, o = ctl(*PIN)
    assert rc == 3 and 'JOB_IMAGE' in o, o
    assert snap() == before


def test_restore_never_runs_the_presence_check(tmp_path):
    """NEG-7: an emergency rollback to the previous compose proceeds even though its (DO) job refs are not on the host."""
    ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap()
    assert ctl(*PIN)[0] == 0
    rc, o = ctl('restore', '--stamp', 'S1')
    assert rc == 0 and snap() == before, o
    assert J(o)['jobs'] == BASE_JOBS
'''
open(p, 'w').write(t)
print('patched tests')
