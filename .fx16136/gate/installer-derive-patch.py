"""goodqa#16148 (lead ruling, option 1): install-d2.sh records and validates one optional derive-blob line.
usage: python3 installer-derive-patch.py <release-harness dir> [--tests-only | --src-only]"""
import os, sys

d = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else ''


def edit(name, pairs):
    p = os.path.join(d, name); t = open(p).read()
    for old, new in pairs:
        assert t.count(old) == 1, (name, old[:90])
        t = t.replace(old, new)
    open(p, 'w').write(t)


SRC = [
    ("""source_path = 'infra/release-harness'
""", """source_path = 'infra/release-harness'
# goodqa#16148: rw-ship streams derive-job-secrets.py from the bound commit only when its blob is this recorded one.
derive_path = 'infra/selfhost/app/derive-job-secrets.py'
"""),
    ("""def validate_binding(data, files):""", """def derive_blob(commit):
    \"\"\"The blob id of derive-job-secrets.py at COMMIT (a regular blob), or None when the commit has no such file.\"\"\"
    entry = git('ls-tree', commit, '--', derive_path)
    if not entry:
        return None
    m = re.fullmatch(rb'(100644|100755) blob ([0-9a-f]{40})\\t' + re.escape(derive_path.encode()) + rb'\\n', entry)
    require(m is not None, 'derive-job-secrets.py at the commit is not a regular blob')
    return m.group(2).decode()

def validate_binding(data, files):"""),
    ("""    require(len(fields) == 7 and re.fullmatch(r'commit [0-9a-f]{40}', fields[0]), 'invalid binding grammar/completeness')
    require(fields[1] == 'path ' + source_path, 'invalid binding source path')
    recorded = {}
    for line in fields[2:]:""", """    require(len(fields) in (7, 8) and re.fullmatch(r'commit [0-9a-f]{40}', fields[0]), 'invalid binding grammar/completeness')
    require(fields[1] == 'path ' + source_path, 'invalid binding source path')
    if len(fields) == 8:  # goodqa#16148: exactly one optional last line, and nothing else new
        m = re.fullmatch(r'derive-blob ([0-9a-f]{40})', fields[7])
        require(m is not None, 'invalid binding derive-blob grammar')
        require(derive_blob(fields[0][7:]) == m.group(1), 'derive-blob is not the derive-job-secrets.py blob at the bound commit')
    recorded = {}
    for line in fields[2:7]:"""),
    ("""        data = ('# defensible-systems D2: exact reviewed runtime\\ncommit ' + commit + '\\npath ' + source_path + '\\n' +
                ''.join(digest(candidate[p]) + '  ' + p + '\\n' for p in paths)).encode()
""", """        blob_id = derive_blob(commit)  # goodqa#16148: absent = a 7-field binding (held releases only)
        data = ('# defensible-systems D2: exact reviewed runtime\\ncommit ' + commit + '\\npath ' + source_path + '\\n' +
                ''.join(digest(candidate[p]) + '  ' + p + '\\n' for p in paths) +
                ('derive-blob ' + blob_id + '\\n' if blob_id else '')).encode()
"""),
]

TESTS = r'''


# ---- goodqa#16148: one optional `derive-blob <40hex>` line, recorded from the candidate commit and checked against it
DERIVE = 'infra/selfhost/app/derive-job-secrets.py'


def with_derive(f, base, body=b'print("fake derive, not the real script")\n'):
    """A commit = BASE's tree + derive-job-secrets.py (commit-tree: HEAD, index and checkout untouched)."""
    env = dict(os.environ, GIT_INDEX_FILE=str(f.repo.parent / ('derive-index-' + base[:8])), GIT_AUTHOR_NAME='t',
               GIT_AUTHOR_EMAIL='t@example.com', GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@example.com')
    def run(*a, inp=None):
        return subprocess.run(['git', '-C', str(f.repo), *a], env=env, input=inp, capture_output=True, check=True).stdout.decode().strip()
    run('read-tree', base)
    h = run('hash-object', '-w', '--stdin', inp=body)
    run('update-index', '--add', '--cacheinfo', '100644,%s,%s' % (h, DERIVE))
    return run('commit-tree', run('write-tree'), '-p', base, '-m', 'add derive'), h


def fields(data):
    return [l for l in data.decode().splitlines() if not l.startswith('#')]


def test_install_records_the_derive_blob_of_the_candidate(f):
    c, h = with_derive(f, NEW)
    r = f.run('apply', '--commit', c, '--skip-until', '2000-01-01T00:00:00Z')
    assert r.returncode == 0, r.stdout + r.stderr
    b = fields(f.bf.read_bytes())
    assert len(b) == 8 and b[0] == 'commit ' + c and b[7] == 'derive-blob ' + h, b
    after = f.snapshot()
    r = f.run('apply', '--commit', c)
    assert r.returncode == 0 and 'identical reviewed runtime' in r.stdout, r.stdout + r.stderr
    assert f.snapshot() == after


def test_a_candidate_without_derive_installs_a_seven_field_binding(f):
    """Still installs; rw-ship then ships only held releases (test_rw_ship_jobsecret_gate: no-blob held ships, unheld refuses)."""
    r = f.apply('--skip-until', '2000-01-01T00:00:00Z')
    assert r.returncode == 0, r.stdout + r.stderr
    b = fields(f.bf.read_bytes())
    assert len(b) == 7 and not any(l.startswith('derive-blob') for l in b), b


@pytest.mark.parametrize('fault', ['file-missing', 'blob-mismatch', 'duplicate', 'unknown-8th', 'not-last'])
def test_a_bad_derive_blob_line_in_the_live_binding_refuses_read_only(f, fault):
    c, h = with_derive(f, OLD)
    base = fields(binding(OLD))
    if fault == 'file-missing': lines = base + ['derive-blob ' + h]              # OLD itself has no derive file
    else: lines = ['commit ' + c] + base[1:]
    if fault == 'blob-mismatch': lines.append('derive-blob ' + '0' * 40)
    if fault == 'duplicate': lines += ['derive-blob ' + h] * 2
    if fault == 'unknown-8th': lines.append('derive-path ' + DERIVE)
    if fault == 'not-last': lines.insert(2, 'derive-blob ' + h)
    f.bf.write_text('\n'.join(lines) + '\n')
    f.refuse('apply', '--commit', NEW)


def test_a_good_derive_blob_line_in_the_live_binding_is_accepted(f):
    """Control for the refusals above: the same live binding with its correct line validates."""
    c, h = with_derive(f, OLD)
    f.bf.write_text('\n'.join(['commit ' + c] + fields(binding(OLD))[1:] + ['derive-blob ' + h]) + '\n')
    r = f.run('check', '--commit', NEW)
    assert r.returncode == 0 and 'validated current binding and candidate' in r.stdout, r.stdout + r.stderr
'''

if mode != '--tests-only':
    edit('install-d2.sh', SRC)
if mode != '--src-only':
    open(os.path.join(d, 'test_install_d2_upgrade.py'), 'a').write(TESTS)
print('patched', mode or 'all')
