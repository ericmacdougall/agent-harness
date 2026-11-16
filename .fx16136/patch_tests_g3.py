"""goodqa#16136 G3 tests. python3 patch_tests_g3.py test_rw_ship_selfhost.py"""
import sys
p = sys.argv[1]; t = open(p).read().rstrip('\n')
t += '''


# ---- goodqa#16136 G3: a job line is a digest-pinned ref or "" # held, nothing else (NEG-16)
@pytest.mark.parametrize('line', ['', '~', 'null', '${X:-}', '"${JOB_IMAGE_TRANSCODE_REF}"', 'goodqa-transcode:latest',
                                  '"goodqa-transcode@sha256:' + 'a' * 64 + "'"])
def test_job_line_value_must_be_a_pin_or_held(line):
    m = _ctl_mod()
    with pytest.raises(m.Refused) as e:
        m.Stack.job_lines(_real_compose_with(m, {'JOB_IMAGE_TRANSCODE': line}))
    assert 'must be a digest-pinned image ref or "" # held' in str(e.value), str(e.value)


@pytest.mark.parametrize('line', ['goodqa-transcode@sha256:' + 'c' * 64, '"goodqa-transcode@sha256:' + 'c' * 64 + '"',
                                  "'registry.digitalocean.com/goodqa-prod/bugtracker-transcode@sha256:" + 'c' * 64 + "'"])
def test_job_line_accepts_plain_or_quoted_pins(line):
    m = _ctl_mod()
    lines, res = m.Stack.job_lines(_real_compose_with(m, {'JOB_IMAGE_TRANSCODE': line}))
    assert 'JOB_IMAGE_TRANSCODE' in res
'''
open(p, 'w').write(t + '\n'); print('patched tests g3')
