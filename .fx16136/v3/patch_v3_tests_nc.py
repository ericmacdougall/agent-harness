#!/usr/bin/env python3
"""1377 v3: keep the forward-only negative control meaningful (F2 sends an unheld release through the re-hold first)."""
import sys
p = 'infra/release-harness/test_rw_ship_selfhost.py'; t = open(p).read()
old = """        if name == 'no-migration-hold':
            R.put('unhealthy-ref', sha[:12]); rc, out = R.run('release/wave-80', sha)"""
new = """        if name == 'no-migration-hold':
            # intelligence-worker held: the plain post-switch path (an unheld one re-holds first, receipt 1377-v2 F2)
            _conf(R, 'SELFHOST_JOB_HOLD', 'intelligence-worker')
            R.put('unhealthy-ref', sha[:12]); rc, out = R.run('release/wave-80', sha)"""
if old in t: t = t.replace(old, new)
elif new not in t: sys.exit('anchor missing')
anchor = "# ---------------------------------------------------------------- refusals before the switch\n"
add = '''def test_no_automatic_rollback_after_a_migration_with_intelligence_worker_held(R):
    """The plain forward-only path (no re-hold: intelligence-worker is held by this release)."""
    _conf(R, 'SELFHOST_JOB_HOLD', 'intelligence-worker'); R.put('mig-pending', '1'); sha = R.release('release/wave-68h')
    R.put('unhealthy-ref', sha[:12]); rc, out = R.run('release/wave-68h', sha)
    assert rc == 8 and 'ROLLBACK REFUSED' in out and 'forward-only' in out and 're-holding' not in out, out
    assert R.pins()['api'].startswith('goodqa-api:' + sha[:12]) and R.state_of('release/wave-68h')[0] == 'deploy-unverified'


'''
if add.split('\n')[0] not in t:
    assert t.count(anchor) == 1; t = t.replace(anchor, add + anchor)
open(p, 'w').write(t); print('nc applied')
