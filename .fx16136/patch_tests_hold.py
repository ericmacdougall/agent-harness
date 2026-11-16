"""goodqa#16136 hold as a launch block: tests. python3 patch_tests_hold.py test_rw_ship_selfhost.py
Existing hold tests asserted the old semantics (held line keeps its old ref); main changed the requirement (option a), so
those assertions now require the held value "" instead. New tests reproduce the gap: a held kind's old image present on
the host would have stayed allowlisted and launchable."""
import sys
p = sys.argv[1]; t = open(p).read()


def rep(old, new, n=1):
    global t
    c = t.count(old)
    assert (c == n) if n else c >= 1, (c, old[:90]); t = t.replace(old, new); return c


counts = {}
counts['intel'] = rep('j[INTEL] == BASE_JOBS[INTEL]', 'j[INTEL] == HELD', 0)
counts['tc-j'] = rep("j['JOB_IMAGE_TRANSCODE'] == BASE_JOBS['JOB_IMAGE_TRANSCODE']", "j['JOB_IMAGE_TRANSCODE'] == HELD", 0)
counts['tc-R'] = rep("R.jobs()['JOB_IMAGE_TRANSCODE'] == BASE_JOBS['JOB_IMAGE_TRANSCODE']", "R.jobs()['JOB_IMAGE_TRANSCODE'] == HELD", 0)
counts['want'] = rep('want[INTEL] = BASE_JOBS[INTEL]', 'want[INTEL] = HELD')
counts['line'] = rep("'      %s: %s # held' % (INTEL, BASE_JOBS[INTEL])", "'      %s: \"\" # held' % INTEL")
rep('"""AC-10a: --job-hold keeps the current (unresolvable DO) line and exempts it from the presence check."""',
    '"""AC-10a: --job-hold writes the held value "" (a launch block) and exempts the key from the presence check."""')
rep('the whole transcode image stays on its current pin (MP4 waits)', 'the whole transcode image is held, its line emptied (MP4 waits)')
if 'the whole transcode image stays on its current pin' in t:
    counts['msg'] = rep('the whole transcode image stays on its current pin', 'the whole transcode image is held', 0)
rep("INTEL = 'JOB_IMAGE_INTELLIGENCE_WORKER'", "INTEL = 'JOB_IMAGE_INTELLIGENCE_WORKER'\nHELD = '\"\"'   # goodqa#16136: a held job line's value")
rep("if a[:2] == ['image', 'inspect'] and '{{.Size}}' in a:", "if a[:2] == ['image', 'inspect']: log('INSPECT ' + repr(a[2:]))\nif a[:2] == ['image', 'inspect'] and '{{.Size}}' in a:")

t = t.rstrip('\n') + '''


# ---- goodqa#16136: a hold blocks launches; it never relies on the old image being absent from the host
def _old_images_present(R):
    import hashlib
    p = os.path.join(R.st, 'docker', 'images-remote.json'); imgs = json.load(open(p))
    for k, ref in BASE_JOBS.items(): imgs[ref] = 'sha256:' + hashlib.sha256(ref.encode()).hexdigest()
    json.dump(imgs, open(p, 'w'))


def test_held_kind_never_starts_even_with_its_old_image_on_the_host(R):
    """Both services get "" for every held kind (the dispatcher answers 501, the guard has no image for it); unheld
    kinds get their new loaded refs."""
    _old_images_present(R); _conf(R, 'SELFHOST_JOB_HOLD', None)
    sha = R.release('release/wave-62h'); rc, out = R.run('release/wave-62h', sha)
    assert rc == 0, out
    pins = job_pins(open(os.path.join(R.vm, 'compose.yaml')).read())
    for svc in ('job-dispatcher-create-guard', 'job-dispatcher'):
        j = pins.get(svc) or pins['job-dispatcher-create-guard']
        assert j[INTEL] == HELD and j['JOB_IMAGE_TRANSCODE'] == HELD, (svc, j)
        for k in ('JOB_IMAGE_SCAN', 'JOB_IMAGE_SUGGEST_FIX_WORKER'):
            assert re.fullmatch(r'goodqa-[a-z-]+@sha256:[0-9a-f]{64}', j[k]), (svc, k, j)
    assert ('      %s: "" # held' % INTEL) in open(os.path.join(R.vm, 'compose.yaml')).read()


def test_unholding_restores_a_real_pin(R):
    _conf(R, 'SELFHOST_JOB_HOLD', 'intelligence-worker'); sha = R.release('release/wave-62u'); rc, out = R.run('release/wave-62u', sha)
    assert rc == 0 and R.jobs()[INTEL] == HELD, (out, R.jobs())
    _conf(R, 'SELFHOST_JOB_HOLD', 'none'); sha2 = R.release('release/wave-62v'); rc2, out2 = R.run('release/wave-62v', sha2)
    assert rc2 == 0, out2
    assert re.fullmatch(r'goodqa-intelligence-worker@sha256:[0-9a-f]{64}', R.jobs()[INTEL]), R.jobs()
    line = next(l for l in open(os.path.join(R.vm, 'compose.yaml')).read().split('\\n') if INTEL + ':' in l)
    assert '# held' not in line, line


def test_held_value_never_reaches_docker(R):
    _old_images_present(R); _conf(R, 'SELFHOST_JOB_HOLD', None)
    sha = R.release('release/wave-62d'); rc, out = R.run('release/wave-62d', sha)
    assert rc == 0, out
    log = R.dlog().split('\\n')
    inspects = [l for l in log if ' INSPECT ' in ' ' + l]
    assert inspects, 'the fixture must log image inspects'
    for l in inspects:   # the held value is never an image argument
        assert ", '']" not in l and "'\\"\\"'" not in l, l
    # before the switch the run reads the live stack (old refs included); once the new stack is up, a held kind's old
    # ref is never looked up again (it is no longer in compose)
    up = next(i for i, l in enumerate(log) if l.startswith('remote UP') and sha in l)
    assert any(' INSPECT ' in ' ' + l for l in log[up:]), 'the post-switch checks must inspect something'
    for l in log[up:]:
        assert BASE_JOBS[INTEL] not in l and BASE_JOBS['JOB_IMAGE_TRANSCODE'] not in l, l


def test_real_compose_held_kind_is_empty_for_both_services(tmp_path):
    """The real `docker compose config`: a held key resolves to "" on both the guard and the dispatcher."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('shctl', CTL); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    src = os.path.join(HERE, '..', 'selfhost', 'app', 'compose.yaml')
    text = open(src).read()
    for envf in sorted(set(re.findall(r'path:[ \\t]*(\\S+\\.env)', text)) | set(re.findall(r'env_file:[ \\t]*(\\S+\\.env)', text))):
        fake = tmp_path / os.path.basename(envf); fake.write_text('X=1\\n'); text = text.replace(envf, str(fake))
    stk = m.Stack(str(tmp_path), str(tmp_path), 'rwtest')
    new = {k: 'goodqa-%s@sha256:%s' % (j, JID[j]) for k, (j, _) in JOBS.items() if k != INTEL}
    (tmp_path / 'compose.yaml').write_text(stk.rejob(text, new, held=[INTEL]))
    r = subprocess.run(['docker', 'compose', '-p', 'rwtest', '-f', str(tmp_path / 'compose.yaml'), 'config', '--format', 'json'],
                       capture_output=True, text=True, cwd=str(tmp_path),
                       env=dict(os.environ, **{v: 'rwtest.invalid' for v in re.findall(r'\\$\\{([A-Z0-9_]+):?\\?', text)}))
    assert r.returncode == 0, r.stderr[-800:]
    svcs = json.loads(r.stdout)['services']
    for s in ('job-dispatcher-create-guard', 'job-dispatcher'):
        got = {k: v for k, v in (svcs[s].get('environment') or {}).items() if k.startswith('JOB_IMAGE_')}
        assert got == dict(new, **{INTEL: ''}), (s, got)
'''
if 'import hashlib' not in t and 'hashlib' not in t.split('\n\n\n')[0]:
    t = t.replace('\nimport json', '\nimport hashlib\nimport json', 1)
open(p, 'w').write(t + '\n'); print('patched tests hold', counts)
