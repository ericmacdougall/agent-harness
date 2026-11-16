"""goodqa#16148 gate: regression fix-ups for suites that build their own release binding. usage: python3 gate-fixture-fixups.py <release-harness dir>"""
import os, sys

d = sys.argv[1]


def edit(name, pairs):
    p = os.path.join(d, name); t = open(p).read()
    for old, new in pairs:
        assert t.count(old) == 1, (name, old[:90])
        t = t.replace(old, new)
    open(p, 'w').write(t)


edit('test_rw_ship_selfhost.py', [(
    """        if self.autobind and 'RELEASE_BINDING=' not in open(os.path.join(self.F, 'biz/release-waves/ship.conf')).read():""",
    """        conf = os.path.join(self.F, 'biz/release-waves/ship.conf')    # a test may remove ship.conf on purpose
        if self.autobind and os.path.exists(conf) and 'RELEASE_BINDING=' not in open(conf).read():""")])

edit('test_rw_release_authority_d2.py', [
    ("""    for n in names: open(os.path.join(d, n), 'wb').write(open(os.path.join(R.F, 'bin', n), 'rb').read())
""", """    for n in names: open(os.path.join(d, n), 'wb').write(open(os.path.join(R.F, 'bin', n), 'rb').read())
    derive = open(sh.DERIVE_SRC, 'rb').read()          # goodqa#16148: the bound commit also carries derive-job-secrets.py
    os.makedirs(os.path.join(R.repo, os.path.dirname(sh.DERIVE_PATH)), exist_ok=True)
    open(os.path.join(R.repo, sh.DERIVE_PATH), 'wb').write(derive)
"""),
    ("""        lines.append('%s  bin/%s' % (hashlib.sha256(open(os.path.join(R.F, 'bin', n), 'rb').read()).hexdigest(), n))
""", """        lines.append('%s  bin/%s' % (hashlib.sha256(open(os.path.join(R.F, 'bin', n), 'rb').read()).hexdigest(), n))
    lines.append('derive-blob ' + sh.blob_sha(derive))
"""),
])

edit('test_runner_ship_adapter.py', [(
    """    sh.base.git('add', '.', cwd=r.repo); sh.base.git('commit', '-qm', 'reviewed five-file binding', cwd=r.repo)
    lines.insert(0, 'commit ' + sh.base.git('rev-parse', 'HEAD', cwd=r.repo))
""", """    derive = Path(sh.DERIVE_SRC).read_bytes()             # goodqa#16148: the bound commit also carries derive-job-secrets.py
    Path(r.repo, sh.DERIVE_PATH).parent.mkdir(parents=True, exist_ok=True); Path(r.repo, sh.DERIVE_PATH).write_bytes(derive)
    lines.append('derive-blob ' + sh.blob_sha(derive))
    sh.base.git('add', '.', cwd=r.repo); sh.base.git('commit', '-qm', 'reviewed five-file binding', cwd=r.repo)
    lines.insert(0, 'commit ' + sh.base.git('rev-parse', 'HEAD', cwd=r.repo))
""")])
print('fixed up')
