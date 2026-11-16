"""Add the guard-old-timeout case (receipt bth-pr73-v5 F2) after the guard-log rollback test. Usage: patch_test_f2.py <file>"""
import sys

p = sys.argv[1]
t = open(p).read()
anchor = "    assert R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.get('live') == before\n\n\ndef test_guard_hold_line_written_and_recorded(tmp_path):"
assert t.count(anchor) == 1, t.count(anchor)
new = '''    assert R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.get('live') == before


def test_transcribe_hold_old_guard_that_just_listens_holds_transcode(R):
    """F2 (bth-pr73-v5): an older guard names GUARD_HELD_ENV in its source but ignores it and keeps listening, so the probe
    only ends at its timeout (rc 124). A timeout is not proof of support: the whole transcode image is held, its line
    emptied, no guard line written, and the other job images still ship pinned."""
    _guard_source(R, False, text=True); R.put('guard-old-timeout', ''); _conf(R, 'SELFHOST_JOB_HOLD', 'transcribe')
    sha = R.release('release/wave-61o'); rc, out = R.run('release/wave-61o', sha)
    assert rc == 0, out
    assert 'probe rc=124' in out and 'guard lacks GUARD_HELD_ENV' in out, out
    j = R.jobs(); assert j['JOB_IMAGE_TRANSCODE'] == HELD, j
    assert all(re.fullmatch(r'goodqa-[a-z-]+@sha256:[0-9a-f]{64}', v) for k, v in j.items() if k != 'JOB_IMAGE_TRANSCODE'), j
    assert _guard_line(R) == [] and 'GUARDPROBE' in R.dlog(), _guard_line(R)


def test_guard_hold_line_written_and_recorded(tmp_path):'''
t = t.replace(anchor, new)
open(p, 'w').write(t)
print('patched', p)
