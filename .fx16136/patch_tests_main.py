"""goodqa#16136 AC-18: re-target two rh tests at main's architecture (no assertion dropped; each still fails on main).
- AC-1/NEG (build failure): main reports build results in jobs.json receipts, not 'build <job>' lines. The test now reads
  the job-image receipt and requires transcode to be the failed job, plus rc 3 and nothing changed.
- AC-1 (build-disk floor, 'seven images'): on main rw-runtime.sh's resource preflight refuses first when the floor is
  impossible, so the existing test keeps main's assertion for that path and a new test reaches rw-ship's own floor
  (fake df reports 0G, floor 1G, so the preflight passes on any host)."""
import sys
p = sys.argv[1]; t = open(p).read()


def rep(old, new):
    global t
    assert t.count(old) == 1, (t.count(old), old[:90]); t = t.replace(old, new)


rep('''    rc, out = R.run('release/wave-60k', sha)
    assert rc == 3 and 'build transcode' in out, out
    unchanged(R, before)
''', '''    rc, out = R.run('release/wave-60k', sha)
    assert rc == 3 and 'job-images-' in out, out
    rd = os.path.join(R.F, 'biz/release-waves/deploys')
    receipts = [os.path.join(dp, f) for dp, _, fs in os.walk(rd) for f in fs if f == 'jobs.json' and 'job-images-' in dp]
    jobs = [j for r in receipts for j in json.load(open(r))['jobs']]
    assert [j['name'] for j in jobs if j['state'] == 'failed'] == ['transcode'], jobs
    unchanged(R, before)
''')
rep('''        assert rc == 11 and 'NO DISK' in out and 'seven images' in out, out
        assert 'BUILD' not in R.dlog() and R.pins() == BASE_PINS
    finally:
        R.cleanup()
''', '''        assert rc == 11 and 'NO DISK' in out, out
        assert 'BUILD' not in R.dlog() and R.pins() == BASE_PINS
    finally:
        R.cleanup()


def test_rw_ship_build_floor_counts_seven_images(tmp_path):
    # goodqa#16136 AC-1: rw-ship's own build-disk floor (after the runtime preflight) refuses before any image job.
    R = SRoot(str(tmp_path))
    try:
        conf = os.path.join(R.F, 'biz/release-waves/ship.conf')
        txt = open(conf).read(); open(conf, 'w').write(txt.replace('SELFHOST_BUILD_MIN_FREE_GB=0', 'SELFHOST_BUILD_MIN_FREE_GB=1'))
        df = os.path.join(R.F, 'stub', 'df')
        real = [d for d in os.environ['PATH'].split(':') if os.path.isfile(os.path.join(d, 'df'))][0]
        open(df, 'w').write('#!/bin/bash\\ncase "$*" in *--output=avail*) printf "Avail\\\\n0G\\\\n"; exit 0;; esac\\nexec %s/df "$@"\\n' % real)
        os.chmod(df, 0o755)
        sha = R.release('release/wave-75b'); rc, out = R.run('release/wave-75b', sha)
        assert rc == 11 and 'NO DISK (infrastructure, exit 11): 0G free' in out and 'seven images' in out, out
        assert 'BUILD' not in R.dlog() and R.pins() == BASE_PINS
        assert not any('job-images-' in dp for dp, _, _ in os.walk(os.path.join(R.F, 'biz/release-waves/deploys')))
    finally:
        R.cleanup()
''')
if 'import json' not in t.split('\n\n\n')[0] and '\nimport json' not in t:
    t = t.replace('\nimport os', '\nimport json\nimport os', 1)
open(p, 'w').write(t); print('patched tests main')
