"""goodqa#16136 E4 tests. python3 patch_tests_e4.py test_rw_ship_selfhost.py"""
import sys
p = sys.argv[1]; t = open(p).read().rstrip('\n')
t += '''


# ---- goodqa#16136 E4: "" is a held value only with the # held marker and only on a holdable key
def _ctl_mod():
    import importlib.util
    spec = importlib.util.spec_from_file_location('shctl_e4', CTL); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


def _real_compose_with(m, edits):
    text = open(os.path.join(HERE, '..', 'selfhost', 'app', 'compose.yaml')).read()
    lines, res = m.Stack.job_lines(text)
    for k, line in edits.items(): lines[res[k]] = '      %s: %s' % (k, line)
    return '\\n'.join(lines)


@pytest.mark.parametrize('key,line,err', [
    ('JOB_IMAGE_INTELLIGENCE_WORKER', '""', 'empty without the # held marker'),
    ('JOB_IMAGE_TRANSCODE', "''", 'empty without the # held marker'),
    ('JOB_IMAGE_SCAN', '"" # held', 'JOB_IMAGE_SCAN cannot be held'),
    ('JOB_IMAGE_SUGGEST_FIX_WORKER', '"" # held', 'JOB_IMAGE_SUGGEST_FIX_WORKER cannot be held'),
    ('JOB_IMAGE_SCAN', '""', 'JOB_IMAGE_SCAN cannot be held'),
    ('JOB_IMAGE_INTELLIGENCE_WORKER', 'goodqa-intelligence-worker@sha256:' + 'a' * 64 + ' # held', 'marked # held but its value is not ""'),
])
def test_empty_job_value_needs_marker_and_holdable_key(key, line, err):
    m = _ctl_mod()
    with pytest.raises(m.Refused) as e:
        m.Stack.job_lines(_real_compose_with(m, {key: line}))
    assert err in str(e.value), str(e.value)


def test_held_empty_lines_on_holdable_keys_are_accepted():
    m = _ctl_mod()
    text = _real_compose_with(m, {'JOB_IMAGE_INTELLIGENCE_WORKER': '"" # held', 'JOB_IMAGE_TRANSCODE': '"" # held'})
    stk = m.Stack('/nonexistent', '/nonexistent', 'rwtest')
    assert stk.held_keys(text) == ['JOB_IMAGE_INTELLIGENCE_WORKER', 'JOB_IMAGE_TRANSCODE']
    assert stk.jobs(text)['JOB_IMAGE_TRANSCODE'] == '""'


@pytest.mark.parametrize('key', ['JOB_IMAGE_SCAN', 'JOB_IMAGE_SUGGEST_FIX_WORKER'])
def test_job_hold_refuses_a_non_holdable_kind(key):
    m = _ctl_mod()
    imgs = ['%s=%s@sha256:%s' % (k, j, 'b' * 64) for k, j in m.JOB_KEYS.items() if k != key]
    with pytest.raises(m.Refused) as e:
        m.parse_job_args(imgs, [key])
    assert 'that kind cannot be held' in str(e.value), str(e.value)
'''
open(p, 'w').write(t + '\n'); print('patched tests e4')
