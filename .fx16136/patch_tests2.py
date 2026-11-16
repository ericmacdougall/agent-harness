"""Second patch of test_rw_ship_selfhost.py for goodqa#16136 spec v2 (run after patch_tests.py): python3 patch_tests2.py FILE"""
import sys
p = sys.argv[1]; t = open(p).read()


def rep(old, new, count=1):
    global t
    n = t.count(old)
    assert n == count, (n, old[:80])
    t = t.replace(old, new)


rep("""if a[0] == 'info': print(os.environ['FAKE_STATE']); sys.exit(0)""",
    """if a[0] == 'info' and 'DriverStatus' not in ' '.join(a): print(os.environ['FAKE_STATE']); sys.exit(0)""")
# ---- fake docker: id skew marker (a store that resolves loosely), store info, resolved config, --pull, untag after up
rep('''    if m and any(k.split(':')[0] == m.group(1) and v == m.group(2) for k, v in imgs.items() if '@' not in k): return m.group(2)
    return None''', '''    if m and any(k.split(':')[0] == m.group(1) and v == m.group(2) for k, v in imgs.items() if '@' not in k):
        if mark('id-skew') and ref.startswith(markv('id-skew')): return 'sha256:' + 'f' * 64
        return m.group(2)
    return None
if a[0] == 'info':
    print('[["Backing Filesystem","extfs"],["Supports d_type","true"]]' if mark('classic-store') else '[["driver-type","io.containerd.snapshotter.v1"]]')
    sys.exit(0)''')
rep('''    if sub == 'config':
        print(json.dumps({'services': {'api': {'deploy': {'replicas': 2}}, 'web': {'deploy': {'replicas': 2}}, 'job-dispatcher': {},
                                       'job-dispatcher-create-guard': {}, 'caddy': {}}})); sys.exit(0)''', '''    if sub == 'config':                                       # resolved config: images, and the &job-images anchor merged
        text = open(files[0]).read(); p0 = {}; jp = {}; cur = None
        for l in text.split('\\n'):
            m = re.match(r'^    image:\\s*(\\S+)', l)
            if m and cur: p0[cur] = m.group(1)
            m = re.match(r'^  ([A-Za-z0-9_.-]+):\\s*(#.*)?$', l)
            if m: cur = m.group(1); continue
            m = re.match(r'^      (JOB_IMAGE_[A-Z0-9_]+):\\s*(\\S+)', l)
            if m and cur: jp.setdefault(cur, {})[m.group(1)] = m.group(2)
        g = jp.get('job-dispatcher-create-guard', {})
        svcs = {s: {'image': i} for s, i in p0.items()}
        for s in ('api', 'web'): svcs.setdefault(s, {})['deploy'] = {'replicas': 2}
        svcs.setdefault('job-dispatcher-create-guard', {})['environment'] = dict(g)
        svcs.setdefault('job-dispatcher', {})['environment'] = dict(g, **jp.get('job-dispatcher', {}))
        print(json.dumps({'services': svcs})); sys.exit(0)''')
rep('''    if sub == 'up':
        svcs = [x for x in rest if not x.startswith('-')]; p = pins(text)''', '''    if sub == 'up':
        if '--pull' in rest:
            i = rest.index('--pull'); log('PULL ' + rest[i + 1]); rest = rest[:i] + rest[i + 2:]
        svcs = [x for x in rest if not x.startswith('-')]; p = pins(text)''')
rep('''        W('containers.json', cons); log('UP api=%s web=%s disp=%s sha=%s' % (p['api'], p['web'], p['job-dispatcher'], sha))''',
    '''        W('containers.json', cons); log('UP api=%s web=%s disp=%s sha=%s' % (p['api'], p['web'], p['job-dispatcher'], sha))
        if mark('untag-after-up') and sha in markv('untag-after-up'):   # a person untags a job image right after the switch
            pre = markv('untag-after-up').split()[0]
            W('images-%s.json' % side, {k: v for k, v in imgs.items() if not k.startswith(pre)})''')

# ---- lane config: the fixture lifts the default intelligence hold and the VM disk floor (tests below set them on purpose)
rep('''SELFHOST_UP_TIMEOUT=1\\nSELFHOST_BUILD_MIN_FREE_GB=0\\n%s''', '''SELFHOST_UP_TIMEOUT=1\\nSELFHOST_BUILD_MIN_FREE_GB=0\\nSELFHOST_VM_MIN_FREE_GB=0\\nSELFHOST_JOB_HOLD=none\\n%s''')

t += r'''


# ---------------------------------------------------------------- goodqa#16136 spec v2
INTEL = 'JOB_IMAGE_INTELLIGENCE_WORKER'


def _conf(R, key, value):
    c = os.path.join(R.F, 'biz/release-waves/ship.conf'); lines = [l for l in open(c).read().split('\n') if not l.startswith(key + '=')]
    if value is not None: lines.insert(0, '%s=%s' % (key, value))
    open(c, 'w').write('\n'.join(lines))


def test_default_holds_intelligence_worker(R):
    """AC-10a: with no SELFHOST_JOB_HOLD in ship.conf, intelligence-worker is held: its line is unchanged, it is not
    built, and the run says so. The other three are pinned to their loaded ids."""
    _conf(R, 'SELFHOST_JOB_HOLD', None); sha = R.release('release/wave-60h'); rc, out = R.run('release/wave-60h', sha)
    assert rc == 0, out
    j = R.jobs(); assert j[INTEL] == BASE_JOBS[INTEL], j
    assert all(re.fullmatch(r'goodqa-[a-z-]+@sha256:[0-9a-f]{64}', v) for k, v in j.items() if k != INTEL), j
    assert 'BUILD goodqa-intelligence-worker' not in R.dlog() and 'held: intelligence-worker' in out, out


def test_bad_job_hold_value_refuses_before_building(R):
    before = R.get('live'); _conf(R, 'SELFHOST_JOB_HOLD', 'intelligence'); sha = R.release('release/wave-60b')
    rc, out = R.run('release/wave-60b', sha)
    assert rc == 2 and 'SELFHOST_JOB_HOLD' in out, out
    assert 'BUILD' not in R.dlog(); unchanged(R, before)


def test_vm_disk_low_stops_before_transfer(R):
    """NEG-6: the VM's own free space is checked before docker load."""
    before = R.get('live'); _conf(R, 'SELFHOST_VM_MIN_FREE_GB', '999999'); sha = R.release('release/wave-60v')
    rc, out = R.run('release/wave-60v', sha)
    assert rc == 11 and 'NO DISK' in out and 'VM' in out, out
    assert 'LOAD' not in R.dlog(); unchanged(R, before)


def test_job_ref_unresolved_after_switch_rolls_back(R):
    """AC-7: a job ref that stops resolving right after the switch is a switch failure: the previous pins come back."""
    before = R.get('live'); sha = R.release('release/wave-60u'); R.put('untag-after-up', 'goodqa-scan: ' + sha)
    rc, out = R.run('release/wave-60u', sha)
    assert rc == 5 and 'job image refs' in out and 'ROLLED BACK' in out, out
    assert R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.get('live') == before


def test_job_images_id_mismatch_after_transfer_refuses(R):
    """NEG-5: only a job image arrives different on the VM."""
    before = R.get('live'); sha = R.release('release/wave-60m')
    R.put('load-corrupt', '')
    rc, out = R.run('release/wave-60m', sha)
    assert rc == 3 and 'goodqa-scan:' in out and 'not the ones built here' in out, out
    unchanged(R, before)


def test_ctl_pin_refuses_classic_store(tmp_path):
    """AC-5: on a classic (overlay2) store a loaded image's repo@id does not resolve: refuse, change nothing."""
    ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap(); (st / 'classic-store').write_text('')
    rc, o = ctl(*PIN)
    assert rc == 3 and 'containerd' in o, o
    assert snap() == before


def test_third_party_ref_absent_warns_not_refuses(tmp_path):
    """AC-3: a pulled third-party image (caddy) that does not resolve is a WARN, never a refusal of every release."""
    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
    p = st / 'docker' / 'images-remote.json'; d = json.loads(p.read_text()); d.pop('caddy@sha256:cad'); p.write_text(json.dumps(d))
    rc, o = ctl(*PIN)
    assert rc == 0 and 'WARN third-party image not present on this host: caddy@sha256:cad' in o, o


def test_ctl_job_hold_keeps_line_and_skips_presence(tmp_path):
    """AC-10a: --job-hold keeps the current (unresolvable DO) line and exempts it from the presence check."""
    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
    args = _swap(PIN, INTEL, None) + ['--job-hold', INTEL]
    rc, o = ctl(*args)
    assert rc == 0, o
    want = dict(NEW_JOBS); want[INTEL] = BASE_JOBS[INTEL]
    assert J(o)['jobs'] == want and J(o)['jobs_missing'] == [BASE_JOBS[INTEL]], o
    rc2, o2 = ctl(*(_swap(PIN, INTEL, None) + ['--job-hold', INTEL, '--job-hold', INTEL]))
    assert rc2 == 3, 'a repeated hold is refused'


@pytest.mark.parametrize('case', ['fresh', 'untagged'])
def test_state_reports_job_refs_and_missing(tmp_path, case):
    """AC-6 / NEG-11: state lists the job refs, and any that stop resolving land in jobs_missing (not missing)."""
    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
    assert ctl(*PIN)[0] == 0
    if case == 'untagged':
        p = st / 'docker' / 'images-remote.json'; d = json.loads(p.read_text()); d.pop('goodqa-scan:t1'); p.write_text(json.dumps(d))
    rc, o = ctl('state'); s = J(o)
    assert rc == 0 and s['jobs'] == NEW_JOBS and s['missing'] == []
    assert s['jobs_missing'] == ([NEW_JOBS['JOB_IMAGE_SCAN']] if case == 'untagged' else []), s
    if case == 'untagged':
        args = list(PIN); args[args.index('S1')] = 'S2'
        rc2, o2 = ctl(*args)
        assert rc2 == 3 and 'not present on this host' in o2, 'a later pin refuses until the release reloads it'


def test_fp_unchanged_by_job_pin_reporting(tmp_path):
    """AC-6 / C5: the job pins stay outside the fp core; the 5a78109 ctl and this ctl agree on the fp of the same stack."""
    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
    old = tmp_path / 'selfhost-ctl.5a78109.py'
    src = subprocess.run(['git', 'show', '5a78109ac2d3:infra/release-harness/selfhost-ctl.py'], cwd=HERE, capture_output=True, text=True)
    assert src.returncode == 0, src.stderr
    old.write_text(src.stdout)
    e = dict(os.environ, PATH=str(tmp_path / 'stub') + ':' + os.environ['PATH'], FAKE_STATE=str(st), FAKE_SIDE='remote')
    r = subprocess.run(['python3', str(old), '--dir', str(vm), '--env-dir', str(env), 'state'], env=e, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    rc, o = ctl('state')
    assert rc == 0 and J(o)['fp'] == J(r.stdout)['fp']


def test_restore_warns_jobs_down_and_never_runs_presence_check(tmp_path):
    """AC-8: the first rollback restores the DO refs: restore proceeds, and says the jobs are down."""
    ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap()
    assert ctl(*PIN)[0] == 0
    rc, o = ctl('restore', '--stamp', 'S1')
    assert rc == 0 and snap() == before, o
    assert 'WARN jobs down after rollback:' in o and BASE_JOBS['JOB_IMAGE_SCAN'] in o, o


def test_restore_core_image_missing_warns_and_up_never_pulls(tmp_path):
    """AC-8 / NEG-7: restore with a pruned core image still restores and warns; up then fails and never pulls."""
    ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap()
    assert ctl(*PIN)[0] == 0
    p = st / 'docker' / 'images-remote.json'; d = json.loads(p.read_text()); d.pop('goodqa-web:base'); p.write_text(json.dumps(d))
    rc, o = ctl('restore', '--stamp', 'S1')
    assert rc == 0 and snap() == before and 'WARN core image missing: goodqa-web:base' in o, o
    rc2, o2 = ctl('up', '--timeout', '1')
    assert rc2 == 5 and o2.startswith('UP_FAIL'), o2
    assert 'PULL never' in open(st / 'docker.log').read(), 'up must run with --pull never'


@pytest.mark.skipif(os.environ.get('RW_REAL_COMPOSE') != '1', reason='real docker compose run: set RW_REAL_COMPOSE=1 (t2-dev)')
def test_real_compose_resolves_anchor_for_both_services(tmp_path):
    """AC-2 / C6: the real `docker compose config` of the product compose.yaml, re-pinned by this ctl's own rewrite, gives
    both the guard and the dispatcher exactly the four new values (the YAML merge key is resolved by compose, not a regex)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('shctl', CTL); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    src = os.path.join(HERE, '..', 'selfhost', 'app', 'compose.yaml')
    text = open(src).read()
    for envf in sorted(set(re.findall(r'path:[ \t]*(\S+\.env)', text)) | set(re.findall(r'env_file:[ \t]*(\S+\.env)', text))):
        fake = tmp_path / os.path.basename(envf); fake.write_text('X=1\n'); text = text.replace(envf, str(fake))
    stk = m.Stack(str(tmp_path), str(tmp_path), 'rwtest')
    new = {k: 'goodqa-%s@sha256:%s' % (j, JID[j]) for k, (j, _) in JOBS.items()}
    out_text = stk.rejob(text, new)
    (tmp_path / 'compose.yaml').write_text(out_text)
    r = subprocess.run(['docker', 'compose', '-p', 'rwtest', '-f', str(tmp_path / 'compose.yaml'), 'config', '--format', 'json'],
                       capture_output=True, text=True, cwd=str(tmp_path),
                       env=dict(os.environ, **{v: 'rwtest.invalid' for v in re.findall(r'\$\{([A-Z0-9_]+):?\?', text)}))
    assert r.returncode == 0, r.stderr[-800:]
    svcs = json.loads(r.stdout)['services']
    for s in ('job-dispatcher-create-guard', 'job-dispatcher'):
        got = {k: v for k, v in (svcs[s].get('environment') or {}).items() if k.startswith('JOB_IMAGE_')}
        assert got == new, (s, got)
'''
open(p, 'w').write(t)
print('patched tests v2')
