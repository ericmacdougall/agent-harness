"""goodqa#16136 AC-18 (lead NEG): the post-build id recheck skips transcode only under the whole-image hold.
python3 patch_tests_main2.py test_rw_ship_selfhost.py   (after patch_tests_f1f2.py)"""
import sys
p = sys.argv[1]; t = open(p).read()


def rep(old, new):
    global t
    assert t.count(old) == 1, (t.count(old), old[:90]); t = t.replace(old, new)


rep('''if a[:2] == ['image', 'inspect']:
    i = resolve(a[-1])''', '''if a[:2] == ['image', 'inspect'] and side == 'local' and mark('inspect-once') and markv('inspect-once') in a[-1]:
    # goodqa#16136: the image is there for the build receipt's own inspect, then gone (removed or re-tagged) by the recheck
    n = os.path.join(os.environ['FAKE_STATE'], 'inspect-count'); c = int(open(n).read()) if os.path.exists(n) else 0
    open(n, 'w').write(str(c + 1))
    if c >= 1: sys.exit(1)
if a[:2] == ['image', 'inspect']:
    i = resolve(a[-1])''')

t = t.rstrip('\n') + '''


# ---- goodqa#16136 AC-18: the id recheck skips transcode only when the whole-image hold removed it on purpose
def test_id_recheck_refuses_missing_transcode_without_a_hold(R):
    before = R.get('live'); R.put('inspect-once', 'goodqa-transcode:'); sha = R.release('release/wave-60r')
    rc, out = R.run('release/wave-60r', sha)
    assert rc == 3, out
    assert 'BUILD goodqa-transcode' in R.dlog() and 'LOAD' not in R.dlog(); unchanged(R, before)


def test_id_recheck_skips_transcode_removed_by_the_whole_image_hold(R):
    _guard_source(R, False); _conf(R, 'SELFHOST_JOB_HOLD', 'transcribe'); R.put('inspect-once', 'goodqa-transcode:')
    sha = R.release('release/wave-60s'); rc, out = R.run('release/wave-60s', sha)
    assert rc == 0 and 'the whole transcode image stays on its current pin' in out, out
    assert R.jobs()['JOB_IMAGE_TRANSCODE'] == BASE_JOBS['JOB_IMAGE_TRANSCODE'], R.jobs()
    assert 'goodqa-transcode' not in next(l for l in R.dlog().split('\\n') if l.startswith('local LOAD') or ' LOAD ' in l), R.dlog()
'''
open(p, 'w').write(t + '\n'); print('patched tests main2')
