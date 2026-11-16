"""receipt pr1370-v1 F2: a failed DriverStatus discovery is not a classic store. usage: python3 f2-store-patch.py <release-harness dir>"""
import os, sys

d = sys.argv[1]


def edit(name, pairs):
    p = os.path.join(d, name); t = open(p).read()
    for old, new in pairs:
        assert t.count(old) == 1, (name, old[:80])
        t = t.replace(old, new)
    open(p, 'w').write(t)


edit('selfhost-ctl.py', [('''    def store_is_containerd(self):
        r = docker('info', '-f', '{{json .DriverStatus}}', timeout=60)
        return r.returncode == 0 and 'io.containerd.snapshotter' in r.stdout
''', '''    def store_is_containerd(self):
        """True for the containerd image store, False for a classic one, REFUSED when the store cannot be discovered
        (receipt pr1370-v1 F2): a failed or unreadable `docker info` DriverStatus is never read as classic."""
        try: r = docker('info', '-f', '{{json .DriverStatus}}', timeout=60)
        except (OSError, subprocess.SubprocessError) as e: raise Refused('cannot discover the docker image store (docker info DriverStatus: %s)' % type(e).__name__)
        try: ds = json.loads(r.stdout) if r.returncode == 0 else None
        except ValueError: ds = None
        if not (isinstance(ds, list) and ds and all(isinstance(x, list) and all(isinstance(y, str) for y in x) for x in ds)):
            raise Refused('cannot discover the docker image store (docker info DriverStatus %s)' % ('rc=%d' % r.returncode if r.returncode else 'unreadable'))
        return any('io.containerd.snapshotter' in y for x in ds for y in x)
''')])

edit('test_rw_ship_selfhost.py', [
    ('''if a[0] == 'info':
    print(''', '''if a[0] == 'info':
    if mark('driverstatus-fail'): print('Cannot connect to the Docker daemon', file=sys.stderr); sys.exit(1)
    if mark('driverstatus-out'): print(open(os.path.join(os.environ['FAKE_STATE'], 'driverstatus-out')).read()); sys.exit(0)
    print('''),
])

open(os.path.join(d, 'test_rw_ship_selfhost.py'), 'a').write('''

# ---- receipt pr1370-v1 F2: a failed DriverStatus discovery is not a classic store (fail closed, never DockerRootDir only)
DISCOVERY_FAILURES = [('rc', None), ('empty', ''), ('not-json', 'template: info: bad'), ('null', 'null'), ('object', '{}'),
                      ('empty-list', '[]'), ('not-pairs', '["driver-type"]')]


@pytest.mark.parametrize('name,body', DISCOVERY_FAILURES)
def test_vm_disk_refuses_when_the_store_cannot_be_discovered(R, name, body):
    """The containerd root is full; a discovery failure read as 'classic' would measure only DockerRootDir and ship."""
    if body is None: R.put('driverstatus-fail', '')
    else: R.put('driverstatus-out', body)
    R.put('vmdf-containerd', '0')
    out = _vm_disk_refused(R, 'release/wave-60d5', name)
    assert 'cannot discover the docker image store' in out, out


@pytest.mark.parametrize('name,body', DISCOVERY_FAILURES)
def test_ctl_pin_refuses_when_the_store_cannot_be_discovered(tmp_path, name, body):
    ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap()
    if body is None: (st / 'driverstatus-fail').write_text('')
    else: (st / 'driverstatus-out').write_text(body)
    rc, o = ctl(*PIN)
    assert rc == 3 and 'cannot discover the docker image store' in o, o
    assert snap() == before


def test_classic_store_is_still_told_apart(tmp_path):
    ctl, snap, st, vm, env = ctl_fixture(tmp_path); (st / 'driverstatus-out').write_text('[["Backing Filesystem","extfs"],["Supports d_type","true"]]')
    rc, o = ctl(*PIN)
    assert rc == 3 and 'is not containerd' in o and 'cannot discover' not in o, o
''')
print('patched')
