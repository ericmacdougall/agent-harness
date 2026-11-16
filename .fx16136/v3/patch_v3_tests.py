#!/usr/bin/env python3
"""1377 v3 (receipt bugtracker-pr1377-gate-v2): add the failing-first tests for F1-F5. Run from the bugtracker repo root."""
import sys

RH = 'infra/release-harness/'


def edit(path, old, new, count=1):
    t = open(path).read()
    n = t.count(old)
    if n != count:
        sys.exit('anchor %r in %s found %d times, want %d' % (old[:60], path, n, count))
    open(path, 'w').write(t.replace(old, new))


def append(path, text):
    t = open(path).read()
    if text.strip().split('\n')[0] in t: sys.exit('already applied: ' + path)
    open(path, 'w').write(t.rstrip('\n') + '\n\n\n' + text.lstrip('\n'))


# ---------------------------------------------------------------- F5: ac13 float bound
append(RH + 'test_ac13_count.py', r'''
# ---- receipt bugtracker-pr1377-gate-v2 F5 (Medium): a FINITE float beyond +-2**53 is not a time either
OUT_OF_RANGE = ('1e100', '-1e100', '9007199254740994.0', '-9007199254740994.0', '1.7976931348623157e308')


def test_out_of_range_float_time_is_an_untimed_unknown(tmp_path):
    ok = [_start('req-a', t=1000), _done('req-a', 200, t=1001)]
    win = ('--mode', 'post', '--since', '0', '--until', '2000', '--require-2xx', 'scan')
    for raw in OUT_OF_RANGE:
        # the receipt's reproducer: one valid 2xx scan launch, and a scan completion with status 500 at an out-of-range time
        rc, o = run(_raw(tmp_path, ok + [_line('req-o', 'request completed', raw)], base=[]), *win)
        assert isinstance(o, dict) and o['verdict'] != 'PASS' and rc != 0, (raw, o)
        assert rc == 1 and o['verdict'] == 'INCONCLUSIVE' and o['unknown'] == {'orphan completion': 1}, (raw, o)
        # paired with its own launch: the completion time is unusable, never the start time
        rc, o = run(_raw(tmp_path, ok + [_start('req-x', t=1500), _line('req-x', 'request completed', raw)], base=[]), *win)
        assert rc == 1 and o['unknown'] == {'invalid status or time': 1}, (raw, o)
        # a launch that never completes, started at that time
        rc, o = run(_raw(tmp_path, ok + [_line('req-u', 'incoming request', raw)], base=[]), *win)
        assert rc == 1 and o['unknown'] == {'no completion': 1}, (raw, o)


def test_in_range_float_times_are_still_times(tmp_path):
    win = ('--mode', 'post', '--since', '0', '--until', '2000', '--require-2xx', 'scan')
    for raw in ('1001.5', '9007199254740992.0'):
        t_in = raw == '1001.5'
        lines = [_start('req-a', t=1000), _line('req-a', 'request completed', raw, st=200)]
        rc, o = run(_raw(tmp_path, lines, base=[]), *win)
        if t_in: assert rc == 0 and o['verdict'] == 'PASS', (raw, o)
        else: assert o['unknown'] == {} and o['verdict'] != 'PASS', (raw, o)   # a usable time, outside the window
''')

# ---------------------------------------------------------------- F4: envfile-key, every line naming the key
CTLG = RH + 'test_selfhost_ctl_gate.py'
edit(CTLG, '''    rc, out, err = cli(fake, 'envfile-key')
    assert (rc, json.loads(out)) == (0, {'count': 1})
    assert PLANT not in out + err
    (fake / 'etc/dispatcher.env').write_text('A=1\\n')
    assert json.loads(cli(fake, 'envfile-key')[1]) == {'count': 0}
''', '''    rc, out, err = cli(fake, 'envfile-key')
    # receipt bugtracker-pr1377-gate-v2 F4: the padded and the other-path assignments are assignments too
    assert (rc, json.loads(out)) == (0, {'count': 3, 'canonical': 1})
    assert PLANT not in out + err
    (fake / 'etc/dispatcher.env').write_text('A=1\\n')
    assert json.loads(cli(fake, 'envfile-key')[1]) == {'count': 0, 'canonical': 0}


OTHER = KEYLINE.replace('/github-app-private-key', '/other-key')
INLINE = 'JOB_ENV_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=inline-fake'


@pytest.mark.parametrize('lines,want', [
    ([KEYLINE], (1, 1)),
    ([KEYLINE, OTHER], (2, 1)),                      # the receipt's reproducer: a later assignment wins
    ([OTHER, KEYLINE], (2, 1)),
    ([OTHER], (1, 0)),
    ([KEYLINE, KEYLINE], (2, 2)),
    ([KEYLINE + ' '], (1, 0)), (['  ' + KEYLINE], (1, 0)), (['export ' + KEYLINE], (1, 0)),
    ([KEYLINE.replace('=', ' = ', 1)], (1, 0)), ([KEYLINE.replace('=', ':', 1)], (1, 0)),
    ([KEYLINE, INLINE], (2, 1)),                     # the F3 conflict, caught here before any migration
    ([KEYLINE, 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY'], (2, 1)),
    (['# ' + KEYLINE, '  #' + OTHER, KEYLINE], (1, 1)),
    (['A=1'], (0, 0)),
])
def test_envfile_key_counts_every_line_naming_the_key(fake, lines, want):
    (fake / 'etc/dispatcher.env').write_text('\\n'.join(['JOB_DISPATCH_TOKEN=' + PLANT] + lines + ['']))
    rc, out, err = cli(fake, 'envfile-key')
    assert (rc, json.loads(out)) == (0, {'count': want[0], 'canonical': want[1]}), out
    assert PLANT not in out + err
''')

# ---------------------------------------------------------------- F3: the conflict line is never ok, on the VM side
edit(CTLG, '''    ([pino('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ' + PLANT)], 'error:other'),
''', '''    ([pino('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ' + PLANT)], 'error:other'),
    ([pino(CONFLICT_LINE)], 'error:conflict'),             # receipt bugtracker-pr1377-gate-v2 F3
    ([pino(CONFLICT_LINE), pino(OK)], 'ok'),               # (a later ok line from the same boot cannot happen; exact match only)
''')
edit(CTLG, '''# ---- (c) disp-boot ----
''', '''# ---- (c) disp-boot ----
# The dispatcher's own phrase (apps/job-dispatcher/src/job-env-file.ts), read from its source so the two cannot drift.
_TS = (HERE.parent.parent / 'apps/job-dispatcher/src/job-env-file.ts').read_text()
assert "'both JOB_ENV_ and JOB_ENVFILE_ are set'" in _TS
CONFLICT_LINE = 'job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: both JOB_ENV_ and JOB_ENVFILE_ are set'


''')

TSF = 'apps/job-dispatcher/test/job-env-file.test.ts'
edit(TSF, '''  it('boot status lines: ok, or the named error; never the content; boot never throws', () => {
''', '''  it('receipt 1377-v2 F3: boot status reports the JOB_ENV_/JOB_ENVFILE_ conflict that makes every launch 501', async () => {
    writeFileSync(join(dir, name), FAKE_PEM);
    const cfg = config({ [KEY]: join(dir, name), JOB_ENV_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: 'inline' });
    const want = 'job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: both JOB_ENV_ and JOB_ENVFILE_ are set';
    expect(bootEnvFileStatusLines(cfg)).toEqual([want]);
    const { res } = await launch(cfg);
    expect(res.json().error).toBe(want); // the same phrase at boot and at launch
    // a JOB_ENV_ var for ANOTHER kind is not a conflict
    expect(bootEnvFileStatusLines(config({ [KEY]: join(dir, name), JOB_ENV_SCAN__GITHUB_APP_PRIVATE_KEY: 'x' }))).toEqual([
      'job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok',
    ]);
  });

  it('boot status lines: ok, or the named error; never the content; boot never throws', () => {
''')
BCF = 'apps/job-dispatcher/test/boot-check.test.ts'
edit(BCF, '''  it('no JOB_ENVFILE key at all is a non-zero exit (a trial must exercise the key)', () => {
''', '''  it('receipt 1377-v2 F3: JOB_ENV_ and JOB_ENVFILE_ for the same key is a non-zero exit, never the ok line', () => {
    const code = runBootCheck(
      { JOB_DISPATCH_TOKEN: 'fake-token', [KEY]: secret(), JOB_ENV_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: 'inline' },
      write,
      dir,
    );
    expect(code).toBe(1);
    expect(out).toEqual(['job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: both JOB_ENV_ and JOB_ENVFILE_ are set']);
  });

  it('no JOB_ENVFILE key at all is a non-zero exit (a trial must exercise the key)', () => {
''')

# ---------------------------------------------------------------- F2 + F3 + F4, whole script
JSG = RH + 'test_rw_ship_jobsecret_gate.py'
edit(JSG, '''@pytest.mark.parametrize('body,word', [('', '0'), ('{k}\\n{k}\\n', '2'), ('{k} \\n', '0'), ('#{k}\\n', '0'), ('symlink', 'unreadable')])''',
     '''@pytest.mark.parametrize('body,word', [
    ('', '0 (canonical 0)'), ('{k}\\n{k}\\n', '2 (canonical 2)'), ('{k} \\n', '1 (canonical 0)'), ('#{k}\\n', '0 (canonical 0)'),
    ('symlink', 'unreadable'),
    # receipt bugtracker-pr1377-gate-v2 F4: a second assignment to the key, even a different one, refuses
    ('{k}\\nJOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=/run/goodqa-secrets/other-key\\n', '2 (canonical 1)'),
    ('JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=/run/goodqa-secrets/other-key\\n', '1 (canonical 0)'),
    # F3 at gate (b): a JOB_ENV_ value for the same key refuses before any migration
    ('{k}\\nJOB_ENV_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=inline\\n', '2 (canonical 1)'),
])''')
edit(JSG, '''@pytest.mark.parametrize('line,word', [('', 'missing'), ('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: is a symlink', 'error:symlink')])''',
     '''@pytest.mark.parametrize('line,word', [('', 'missing'), ('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: is a symlink', 'error:symlink'),
    ('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: both JOB_ENV_ and JOB_ENVFILE_ are set', 'error:conflict')])''')
# the gate (c) re-hold failure without a migration now rolls back (lead ruling wa5b72dea2cf) instead of stopping
edit(JSG, '''def test_rehold_failure_is_exit_8_and_touches_nothing_else(R):
    R.put('disp-boot-line', ''); R.put('up-fail-disp-only', ''); sha = R.release('release/js-11'); rc, out = R.run('release/js-11', sha)
    assert rc == 8 and 'HOLD NOT RE-APPLIED' in out and 'JOB_IMAGE_INTELLIGENCE_WORKER' in out, out
    assert ups(R) == [FULL] and 'UPSVCS-FAILED ' + DISP_ONLY in R.dlog(), 'only the dispatcher pair was tried'
    assert 'ROLLED BACK' not in out and R.state_of('release/js-11')[0] == 'deploy-unverified' and os.path.exists(R.infl)
''', '''def test_rehold_failure_after_a_migration_is_exit_8_and_touches_nothing_else(R):
    R.put('mig-pending', '1'); R.put('disp-boot-line', ''); R.put('up-fail-disp-only', '')
    sha = R.release('release/js-11'); rc, out = R.run('release/js-11', sha)
    assert rc == 8 and 'HOLD NOT RE-APPLIED' in out and 'JOB_IMAGE_INTELLIGENCE_WORKER' in out, out
    assert ups(R) == [FULL] and 'UPSVCS-FAILED ' + DISP_ONLY in R.dlog(), 'only the dispatcher pair was tried'
    assert 'ROLLED BACK' not in out and R.state_of('release/js-11')[0] == 'deploy-unverified' and os.path.exists(R.infl)
''')
append(JSG, r'''
# ---------------------------------------------------------------- receipt bugtracker-pr1377-gate-v2 F2 (High)
# Once the switch's `up` has run, and until gate (c) passes, EVERY failure re-holds intelligence-worker first (dispatcher
# only), then: after a migration, the forward-only stop (exit 8); before any, the rollback (exit 5). When the re-hold itself
# fails: after a migration, exit 8 HOLD NOT RE-APPLIED; before any, roll back and exit 5 only when the restored release is
# the previous one AND its JOB_IMAGE_INTELLIGENCE_WORKER is held or byte-for-byte what it was before this run (lead ruling
# wa5b72dea2cf); otherwise exit 8.
def _pre_c_failure(R, how, sha):
    if how == 'unhealthy': R.put('unhealthy-ref', sha[:12]); return 'the new stack did not come up healthy'
    if how == 'guard':
        R.put('guard-log-missing', ''); return 'the running guard does not report the transcription hold'
    raise AssertionError(how)


def _setup(R, how):
    if how == 'guard': sh._guard_source(R, True); sh._conf(R, 'SELFHOST_JOB_HOLD', 'transcribe')


def _hold_base(R):
    p = os.path.join(R.vm, 'compose.yaml'); t = open(p).read()
    t2 = re.sub(r'^(      JOB_IMAGE_INTELLIGENCE_WORKER:).*$', r'\1 "" # held', t, flags=re.M)
    assert t2 != t; open(p, 'w').write(t2)


@pytest.mark.parametrize('how', ['unhealthy', 'guard'])
def test_pre_gate_c_failure_after_a_migration_reholds_before_the_forward_only_stop(R, how):
    """The receipt's case: intelligence-worker released, one migration applied, the new stack fails readiness."""
    _setup(R, how); R.put('mig-pending', '1'); sha = R.release('release/js-20'); why = _pre_c_failure(R, how, sha)
    rc, out = R.run('release/js-20', sha)
    assert rc == 8 and why in out and 'ROLLBACK REFUSED' in out and 'intelligence-worker was re-held' in out, out
    assert out.index('intelligence-worker re-held') < out.index('ROLLBACK REFUSED'), out
    assert ups(R) == [FULL, DISP_ONLY], 'the dispatcher-only re-hold, and no rollback across the migration'
    assert R.jobs()[INTEL] == HELD and R.jobs('job-dispatcher')[INTEL] == HELD
    assert 'gate (c)' not in out and R.state_of('release/js-20')[0] == 'deploy-unverified' and os.path.exists(R.infl)


@pytest.mark.parametrize('how', ['unhealthy', 'guard'])
def test_pre_gate_c_failure_without_a_migration_reholds_then_rolls_back(R, how):
    _setup(R, how); before = R.get('live'); sha = R.release('release/js-21'); why = _pre_c_failure(R, how, sha)
    rc, out = R.run('release/js-21', sha)
    assert rc == 5 and why in out and 'ROLLED BACK' in out, out
    assert out.index('intelligence-worker re-held') < out.index('ROLLED BACK'), out
    assert ups(R) == [FULL, DISP_ONLY, FULL], 're-hold (dispatcher only) BEFORE the rollback up'
    assert R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.get('live') == before


@pytest.mark.parametrize('base', ['held', 'released'])
def test_pre_gate_c_rehold_failure_without_a_migration_rolls_back_to_the_verified_previous_release(R, base):
    if base == 'held': _hold_base(R)
    pre = R.jobs()[INTEL]; before = R.get('live'); R.put('up-fail-disp-only', '')
    sha = R.release('release/js-22'); _pre_c_failure(R, 'unhealthy', sha); rc, out = R.run('release/js-22', sha)
    assert rc == 5 and 'the dispatcher-only re-hold failed' in out and 'ROLLED BACK' in out, out
    word = 'held' if base == 'held' else 'same-as-before'
    assert ('intelligence-worker on the restored release: ' + word) in out, out
    assert ('intelligence-worker before this run: ' + pre) in out, out
    assert ups(R) == [FULL, FULL] and 'UPSVCS-FAILED ' + DISP_ONLY in R.dlog()
    assert R.jobs()[INTEL] == pre and R.get('live') == before and 'HOLD NOT RE-APPLIED' not in out


def test_pre_gate_c_rehold_failure_when_the_restore_is_not_the_previous_value_is_exit_8(R):
    """The rollback "succeeds" but the restored intelligence-worker line is neither held nor what it was: exit 8."""
    R.put('up-fail-disp-only', ''); sha = R.release('release/js-23'); _pre_c_failure(R, 'unhealthy', sha)
    # a backup that restores a DIFFERENT intelligence-worker value (as if someone re-pinned it during the run)
    R.put('restore-intel-drift', 'goodqa-intelligence-worker@sha256:' + 'e' * 64)
    rc, out = R.run('release/js-23', sha)
    assert rc == 8 and 'HOLD NOT RE-APPLIED' in out and 'ROLLED BACK' not in out, out
    assert R.state_of('release/js-23')[0] == 'deploy-unverified' and os.path.exists(R.infl)


def test_pre_gate_c_rehold_failure_after_a_migration_stops_without_a_rollback(R):
    R.put('mig-pending', '1'); R.put('up-fail-disp-only', ''); sha = R.release('release/js-24'); _pre_c_failure(R, 'unhealthy', sha)
    rc, out = R.run('release/js-24', sha)
    assert rc == 8 and 'HOLD NOT RE-APPLIED' in out and 'ROLLED BACK' not in out and 'ROLLBACK REFUSED' not in out, out
    assert ups(R) == [FULL], 'no rollback across a migration'


def test_gate_c_rehold_failure_without_a_migration_rolls_back_to_the_previous_release(R):
    before = R.get('live'); R.put('disp-boot-line', ''); R.put('up-fail-disp-only', '')
    sha = R.release('release/js-25'); rc, out = R.run('release/js-25', sha)
    assert rc == 5 and 'ROLLED BACK' in out and 'intelligence-worker on the restored release: same-as-before' in out, out
    assert ups(R) == [FULL, FULL] and R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.get('live') == before


def test_job_ref_unresolved_before_gate_c_ends_on_the_previous_release(R):
    """Line 882: the re-hold pin names the same job refs, so it can refuse; the rollback still restores the previous release."""
    before = R.get('live'); sha = R.release('release/js-26'); R.put('untag-after-up', 'goodqa-scan: ' + sha)
    rc, out = R.run('release/js-26', sha)
    assert rc == 5 and 'job image refs' in out and 'ROLLED BACK' in out, out
    assert 're-holding intelligence-worker' in out, 'the re-hold is attempted first'
    assert R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.get('live') == before


def test_unreadable_pre_run_intelligence_worker_refuses_before_anything(R):
    """Lead ruling wa5b72dea2cf: the pre-run value is read at the start; unreadable or ambiguous refuses up front."""
    before = R.get('live'); R.put('state-jobs-error', '')
    sha = R.release('release/js-27'); rc, out = R.run('release/js-27', sha)
    assert rc == 2 and 'intelligence-worker before this run: unreadable' in out, out
    refused_before_anything(R, before, out)
''')

# the fake VM: two knobs for the F2 rollback verification (state with unreadable job lines; a restore that drifts)
edit(RH + 'test_rw_ship_selfhost.py', '''FAKE_SIDE=remote exec bash -c "$*"
\'\'\'
SUDO = ''', '''if [ -e "$FAKE_STATE/state-jobs-error" ] && [[ "$*" =~ \\ state$ ]]; then   # 1377 v3: no readable intelligence-worker value
  FAKE_SIDE=remote bash -c "$*" | python3 -c 'import json, sys
for l in sys.stdin:
    if l.startswith("{"): j = json.loads(l); j["jobs"] = {"error": "fake: unreadable job lines"}; l = json.dumps(j) + "\\n"
    sys.stdout.write(l)'; exit "${PIPESTATUS[0]}"
fi
if [ -e "$FAKE_STATE/restore-intel-drift" ] && [[ "$*" =~ \\ restore\\ --stamp\\ [0-9]{8}T[0-9]{6}Z$ ]]; then   # 1377 v3: the restore lands a different value
  FAKE_SIDE=remote bash -c "$*"; rc=$?; d=$(printf '%s' "$*" | sed -E 's/.*--dir ([^ ]+).*/\\1/'); v=$(cat "$FAKE_STATE/restore-intel-drift")
  sed -i -E "s|^(      JOB_IMAGE_INTELLIGENCE_WORKER:).*$|\\1 $v|" "$d/compose.yaml"; exit $rc
fi
FAKE_SIDE=remote exec bash -c "$*"
\'\'\'
SUDO = ''')

print('tests applied')
