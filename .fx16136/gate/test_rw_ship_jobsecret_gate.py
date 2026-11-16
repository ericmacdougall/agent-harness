"""goodqa#16148 spec v4 AC-8: bin/rw-ship.sh's job-secret unhold gate, whole script, on the fake VM of test_rw_ship_selfhost.py.

intelligence-worker is released only when, before anything is migrated or switched:
  (a) derive-job-secrets.py, streamed from the BOUND release commit (never the working tree) and only when its blob equals the
      binding's derive-blob line, prints exactly `job secret github-app-private-key: written|unchanged` with rc 0;
  (b) dispatcher.env names JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY exactly once;
  (P3) a hardened trial boot of THIS dispatcher image, by its VM digest, reads a fixed fake key ok;
and after the switch (c) a NEW dispatcher container logged the key ok. A (c) failure re-holds intelligence-worker FIRST by a
dispatcher-only recreate (P4 / NEG-19), then rolls back as usual (exit 5), or stops at exit 8 after a migration or when the
re-hold or the rollback fails. Held releases are never gated: a failed derive only warns.
Run: cd infra/release-harness && python3 -m pytest -q -p no:cacheprovider test_rw_ship_jobsecret_gate.py
     (RW_SHIP_UNDER_TEST=<path> for a mutant copy)
"""
import json, os, re, subprocess

import pytest

import test_rw_ship_selfhost as sh
from test_rw_ship_selfhost import INTEL, HELD, BASE_PINS, BASE_JOBS, _conf, bind_release, blob_sha

LINE = 'job secret github-app-private-key: '
DERIVE_BLOB = blob_sha(open(sh.DERIVE_SRC, 'rb').read())
FULL = 'api,web,job-dispatcher,job-dispatcher-create-guard'
DISP_ONLY = 'job-dispatcher,job-dispatcher-create-guard'
MARK = 'PLANTED-REASON-7f3a'          # a derive reason / log text that must never reach the run output


@pytest.fixture
def R(tmp_path):
    r = sh.SRoot(str(tmp_path)); yield r; r.cleanup()


def ups(R): return re.findall(r'^remote UPSVCS (\S+)$', R.dlog(), re.M)
def rd(R):
    d = os.path.join(R.F, 'biz/release-waves/deploys'); return os.path.join(d, sorted(os.listdir(d))[-1])
def derive_runs(R): return len(R.get('derive-runs').split())
def audit(R, sha):
    names = subprocess.run(['git', 'ls-tree', '-r', '--name-only', 'main', 'audit/selfhost-deploys'], cwd=R.origin,
                           capture_output=True, text=True).stdout.split()
    n = [x for x in names if sha[:8] in x]
    return json.loads(subprocess.run(['git', 'show', 'main:' + n[0]], cwd=R.origin, capture_output=True, text=True).stdout) if n else None
def refused_before_anything(R, before, out):
    assert 'REFUSED (job-secret unhold gate, exit 2)' in out, out
    assert R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.env_sha('api') == before
    assert 'MIGRATE' not in R.dlog() and ups(R) == [] and R.get('live') == before
    assert not [f for f in os.listdir(R.vm) if '.pre-rw-' in f]


# ---------------------------------------------------------------- the released path
def test_unheld_release_passes_every_gate_in_order(R):
    sha = R.release('release/js-1'); rc, out = R.run('release/js-1', sha)
    assert rc == 0, out
    assert 'release scripts: bound, OK 4 file(s)' in out, 'the derive-blob line is not a bound file'
    assert R.get('derive-streamed').strip() == DERIVE_BLOB, 'derive must be the bound blob'
    assert 'gate (a) derive from the bound commit: written' in out and 'gate (b) key lines in dispatcher.env: 1' in out, out
    disp = R.pins()['job-dispatcher']; vm_id = json.load(open(os.path.join(R.st, 'docker', 'images-remote.json')))[disp]
    trial = json.loads(R.get('trial-argv'))
    assert trial[trial.index('--boot-check') - 2] == 'goodqa-job-dispatcher@' + vm_id, 'the trial boots THIS image by digest'
    assert ('trial boot of goodqa-job-dispatcher@%s: ok' % vm_id) in out and 'gate (c) dispatcher boot line: ok' in out, out
    log = R.dlog()
    assert log.index('TRIAL ') < log.index('MIGRATE dry') < log.index('UPSVCS'), 'every pre-switch gate runs before migrations'
    ssh = R.get('ssh.log'); assert ssh.index('sudo python3 -I -') < ssh.index(' migrate '), ssh
    assert ups(R) == [FULL], 'one switch, no re-hold'
    assert re.fullmatch(r'goodqa-intelligence-worker@sha256:[0-9a-f]{64}', R.jobs()[INTEL]), R.jobs()
    assert audit(R, sha)['jobSecretGate'] == 'released derive=written key-lines=1 trial=ok'
    assert 'RM -f goodqa-trial-' in log, 'the trial container is always removed'


@pytest.mark.parametrize('body,code,word,ok', [
    (LINE + 'written\n', 0, 'written', True),
    (LINE + 'unchanged\n', 0, 'unchanged', True),
    (LINE + 'REFUSED no %s line\n' % MARK, 2, 'REFUSED-derive', False),
    (LINE + 'written\nextra line\n', 0, 'garbled', False),
    (LINE + 'written\r\n', 0, 'garbled', False),
    (LINE + 'REFUSED x\n', 0, 'garbled', False),
    (LINE + 'written\n', 2, 'garbled', False),
    ('', 0, 'garbled', False),
    (LINE + 'REFUSED a\n' + LINE + 'REFUSED b\n', 2, 'garbled', False),
    (None, 255, 'unreachable', False),
])
def test_unheld_derive_outcomes(R, body, code, word, ok):
    before = R.get('live')
    if body is None: R.put('derive-ssh-fail', '')
    else: R.put('derive-out', body); R.put('derive-rc', str(code))
    sha = R.release('release/js-2'); rc, out = R.run('release/js-2', sha)
    assert ('gate (a) derive from the bound commit: ' + word) in out, out
    assert MARK not in out and MARK not in R.runlogs(), 'a derive reason never leaves the VM'
    if ok: assert rc == 0, out
    else:
        assert rc == 2, out; refused_before_anything(R, before, out)
        assert 'TRIAL' not in R.dlog() and R.state_of('release/js-2')[0] == 'deploy-failed'


@pytest.mark.parametrize('case', ['refused', 'ssh-fail', 'unbound', 'no-blob'])
def test_held_release_is_not_gated(R, case):
    _conf(R, 'SELFHOST_JOB_HOLD', 'intelligence-worker')
    if case == 'refused': R.put('derive-out', LINE + 'REFUSED no source line\n'); R.put('derive-rc', '2')
    if case == 'ssh-fail': R.put('derive-ssh-fail', '')
    if case == 'unbound': R.autobind = False
    if case == 'no-blob': bind_release(R, derive=None)
    sha = R.release('release/js-3'); rc, out = R.run('release/js-3', sha)
    assert rc == 0, out
    assert R.jobs()[INTEL] == HELD and 'TRIAL' not in R.dlog() and 'gate (c)' not in out
    word = {'refused': 'REFUSED-derive', 'ssh-fail': 'unreachable', 'unbound': 'skipped-unbound', 'no-blob': 'REFUSED-no-derive-blob'}[case]
    assert ('derive ' + word) in out and audit(R, sha)['jobSecretGate'] == 'held derive=' + word, out
    assert ('derive-runs' in os.listdir(R.st)) == (case in ('refused', 'ssh-fail'))


# ---------------------------------------------------------------- where derive comes from (lead ruling Q1)
def test_tampered_working_tree_derive_is_ignored(R):
    tampered = b'print("job secret github-app-private-key: written")\n'
    p = os.path.join(R.repo, sh.DERIVE_PATH); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, 'wb').write(tampered)
    sha = R.release('release/js-4')
    open(p, 'wb').write(tampered + b'# and edited again after the release commit\n')
    rc, out = R.run('release/js-4', sha)
    assert rc == 0, out
    assert R.get('derive-streamed').strip() == DERIVE_BLOB != blob_sha(tampered), 'only the bound blob is streamed'


@pytest.mark.parametrize('how,word', [
    ('unbound', 'REFUSED-unbound'),
    ('no-file-no-line', 'REFUSED-no-derive-blob'),
    ('line-without-file', 'REFUSED-not-in-bound-commit'),
    ('blob-mismatch', 'REFUSED-blob-mismatch'),
    ('other-content', 'REFUSED-blob-mismatch'),
])
def test_derive_source_must_be_the_bound_blob(R, how, word):
    before = R.get('live')
    if how == 'unbound': R.autobind = False
    if how == 'no-file-no-line': bind_release(R, derive=None)
    if how == 'line-without-file': bind_release(R, derive=None, blob=DERIVE_BLOB)
    if how == 'blob-mismatch': bind_release(R, blob='0' * 40)
    if how == 'other-content': bind_release(R, derive=b'print(1)\n', blob=DERIVE_BLOB)
    sha = R.release('release/js-5'); rc, out = R.run('release/js-5', sha)
    assert rc == 2 and ('derive from the bound commit: ' + word) in out, out
    refused_before_anything(R, before, out)
    assert 'derive-runs' not in os.listdir(R.st), 'nothing is streamed to the VM'


# ---------------------------------------------------------------- (b) and the trial boot
@pytest.mark.parametrize('body,word', [('', '0'), ('{k}\n{k}\n', '2'), ('{k} \n', '0'), ('#{k}\n', '0'), ('symlink', 'unreadable')])
def test_key_line_must_be_there_exactly_once(R, body, word):
    before = R.get('live'); p = os.path.join(R.envd, 'dispatcher.env')
    if body == 'symlink':
        os.rename(p, p + '.real'); os.symlink(p + '.real', p)
    else: open(p, 'w').write('JOB_DISPATCH_TOKEN=x\n' + body.format(k=sh.JOBSECRET_KEY_LINE))
    sha = R.release('release/js-6'); rc, out = R.run('release/js-6', sha)
    assert rc == 2 and ('gate (b) key lines in dispatcher.env: ' + word) in out, out
    refused_before_anything(R, before, out); assert 'TRIAL' not in R.dlog()


def test_trial_boot_failure_refuses_and_cleans_up(R):
    before = R.get('live'); R.put('trial', 'fail'); sha = R.release('release/js-7'); rc, out = R.run('release/js-7', sha)
    assert rc == 2 and 'trial boot of the new dispatcher image did not read the key file (fail)' in out, out
    refused_before_anything(R, before, out)
    assert 'RM -f goodqa-trial-' in R.dlog()


# ---------------------------------------------------------------- (c) after the switch: re-hold first, then roll back
@pytest.mark.parametrize('line,word', [('', 'missing'), ('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: is a symlink', 'error:symlink')])
def test_gate_c_failure_reholds_then_rolls_back(R, line, word):
    before = R.get('live'); R.put('disp-boot-line', line); sha = R.release('release/js-8'); rc, out = R.run('release/js-8', sha)
    assert rc == 5, out
    assert ('gate (c) dispatcher boot line: ' + word) in out and 'ROLLED BACK' in out, out
    assert ups(R) == [FULL, DISP_ONLY, FULL], 're-hold (dispatcher only) BEFORE the rollback up'
    assert out.index('intelligence-worker re-held') < out.index('ROLLED BACK'), out
    r = rd(R); stamp = os.path.basename(r)
    assert os.path.exists(os.path.join(r, 'pin-%sh.txt' % stamp)) and os.path.exists(os.path.join(R.vm, 'compose.yaml.pre-rw-%sh' % stamp))
    assert R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.get('live') == before
    assert R.state_of('release/js-8')[0] in ('rolled-back', 'deploy-failed') and not R.contains(sha)


def test_gate_c_requires_a_new_container(R):
    R.put('disp-same-hex', ''); sha = R.release('release/js-9'); rc, out = R.run('release/js-9', sha)
    assert rc == 5 and 'was not recreated by the switch (gate c)' in out, out
    assert ups(R) == [FULL, DISP_ONLY, FULL]


def test_gate_c_failure_after_a_migration_holds_and_stops(R):
    R.put('mig-pending', '1'); R.put('disp-boot-line', ''); sha = R.release('release/js-10'); rc, out = R.run('release/js-10', sha)
    assert rc == 8 and 'ROLLBACK REFUSED' in out and 'intelligence-worker was re-held' in out, out
    assert ups(R) == [FULL, DISP_ONLY], 'no rollback across a migration, only the re-hold'
    assert R.jobs()[INTEL] == HELD and R.pins()['api'].startswith('goodqa-api:' + sha[:12])
    assert R.state_of('release/js-10')[0] == 'deploy-unverified' and os.path.exists(R.infl)


def test_rehold_failure_is_exit_8_and_touches_nothing_else(R):
    R.put('disp-boot-line', ''); R.put('up-fail-disp-only', ''); sha = R.release('release/js-11'); rc, out = R.run('release/js-11', sha)
    assert rc == 8 and 'HOLD NOT RE-APPLIED' in out and 'JOB_IMAGE_INTELLIGENCE_WORKER' in out, out
    assert ups(R) == [FULL] and 'UPSVCS-FAILED ' + DISP_ONLY in R.dlog(), 'only the dispatcher pair was tried'
    assert 'ROLLED BACK' not in out and R.state_of('release/js-11')[0] == 'deploy-unverified' and os.path.exists(R.infl)


def test_rollback_restore_failure_reholds_again(R):
    R.put('disp-boot-line', ''); R.put('restore-fail', ''); sha = R.release('release/js-12'); rc, out = R.run('release/js-12', sha)
    assert rc == 8 and 'ROLLBACK NOT CONFIRMED' in out and 'intelligence-worker is re-held' in out, out
    stamp = os.path.basename(rd(R))
    assert ups(R) == [FULL, DISP_ONLY, DISP_ONLY] and os.path.exists(os.path.join(rd(R), 'pin-%sh2.txt' % stamp))
    assert R.jobs()[INTEL] == HELD and R.state_of('release/js-12')[0] == 'deploy-unverified'
