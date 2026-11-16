"""Apply the F1 (bth-pr73-v5) fixture and tests to a test_rw_ship_selfhost.py. Usage: patch_test.py <file>"""
import sys

p = sys.argv[1]
t = open(p).read()


def rep(old, new, n=1):
    global t
    assert t.count(old) == n, 'anchor count %d != %d: %r' % (t.count(old), n, old[:80])
    t = t.replace(old, new)


# 1. fake docker: .Containerd address and the API endpoint, before the DockerRootDir catch-all and the generic context answer
rep("""if a[0] == 'info' and 'DriverStatus' not in ' '.join(a): print(os.environ['FAKE_STATE']); sys.exit(0)""",
    """if a[0] == 'info' and '.Containerd' in ' '.join(a):         # F1: Docker 27+ names its containerd; older engines fail
    if mark('ctd-info-old'): print('template: :1:7: executing "" at <.Containerd>: can\\'t evaluate field Containerd', file=sys.stderr); sys.exit(1)
    print(json.dumps({'Address': markv('ctd-address') if mark('ctd-address') else '', 'Namespaces': {'Containers': 'moby'}})); sys.exit(0)
if a[0] == 'info' and 'DriverStatus' not in ' '.join(a): print(os.environ['FAKE_STATE']); sys.exit(0)""")
rep("""if a[0] == 'context':
    print('ssh://unaccounted-builder'""",
    """if a[:2] == ['context', 'inspect'] and side == 'remote' and mark('docker-api'): print('unix://' + markv('docker-api')); sys.exit(0)
if a[0] == 'context':
    print('ssh://unaccounted-builder'""")

# 2. the default `containerd config dump` names another root when asked (the store F1 must NOT measure)
rep("""printf "version = 2\\nroot = '%s'\\nstate = '/run/containerd'\\n" "$FAKE_STATE/containerd-root\"""",
    """r=containerd-root; [ -e "$FAKE_STATE/ctd-dump-alt" ] && r=alt-root     # F1: a default config naming another store
printf "version = 2\\nroot = '%s'\\nstate = '/run/containerd'\\n" "$FAKE_STATE/$r\"""")

# 3. fake VM df: compare real paths; alt-root is the default-config store
rep("""  case "$2" in "$FAKE_STATE") n=docker;; "$FAKE_STATE/containerd-root") n=containerd;; *) n="";; esac""",
    """  S=$(realpath -m "$FAKE_STATE"); case "$(realpath -m "$2")" in "$S") n=docker;; "$S/containerd-root") n=containerd;; "$S/alt-root") n=alt;; *) n="";; esac""")

# 4. a real process stands in for dockerd and containerd: it binds a unix socket and holds it, so the ctl's /proc
#    lookup runs unmodified (no test seam in the ctl)
rep("""class SRoot(base.Root):""",
    '''FAKEPROC = r"""import json, os, socket, sys, time
c = os.environ.get('FP_COMM', '')
if c: open('/proc/self/comm', 'w').write(c)
s = None
if os.environ.get('FP_LISTEN'):
    s = socket.socket(socket.AF_UNIX); s.bind(os.environ['FP_LISTEN']); s.listen(8)
elif os.environ.get('FP_FD'):
    s = socket.socket(fileno=int(os.environ['FP_FD']))
if os.environ.get('FP_CHILD_ARGS') and s is not None:      # a second process holding the same listening socket
    os.set_inheritable(s.fileno(), True)
    e = dict(os.environ, FP_FD=str(s.fileno()), FP_COMM=os.environ.get('FP_CHILD_COMM', c), FP_READY=os.environ['FP_READY'] + '.child')
    for k in ('FP_LISTEN', 'FP_CHILD_ARGS', 'FP_CHILD_COMM'): e.pop(k, None)
    if os.fork() == 0: os.execve(sys.executable, [sys.executable, sys.argv[0]] + json.loads(os.environ['FP_CHILD_ARGS']), e)
open(os.environ['FP_READY'], 'w').write(str(os.getpid()))
while True: time.sleep(60)
"""
_FAKEPROCS = []


def fakeproc(procs, sk, comm, sock, args, child_args=None, child_comm=None):
    """Start a process named COMM with command line ARGS that listens on SOCK (or holds nothing when SOCK is None);
    CHILD_ARGS adds a second process holding the same socket. Returns once each one is up."""
    import time as _t
    script = os.path.join(sk, 'fakeproc.py')
    if not os.path.exists(script): open(script, 'w').write(FAKEPROC)
    ready = os.path.join(sk, 'ready-%d' % len(procs))
    e = dict(os.environ, FP_COMM=comm, FP_READY=ready)
    if sock: e['FP_LISTEN'] = sock
    if child_args is not None: e['FP_CHILD_ARGS'] = json.dumps(child_args); e['FP_CHILD_COMM'] = child_comm or comm
    pr = subprocess.Popen([sys.executable, script] + list(args), env=e, start_new_session=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(pr); _FAKEPROCS.append(pr)
    want = [ready] + ([ready + '.child'] if child_args is not None else [])
    for _ in range(200):
        if all(os.path.exists(w) for w in want): return pr
        if pr.poll() is not None: break
        _t.sleep(0.05)
    raise AssertionError('fake %s did not start' % comm)


def _kill_fakeprocs(procs):
    import signal as _sig
    for pr in procs:
        try: os.killpg(pr.pid, _sig.SIGKILL)
        except (ProcessLookupError, PermissionError): pass
        try: pr.wait(timeout=5)
        except Exception: pass


import atexit as _atexit                                     # noqa: E402
_atexit.register(lambda: _kill_fakeprocs(_FAKEPROCS))


class SRoot(base.Root):''')

rep("""        for path, body in ((os.path.join(b, 'stub', 'containerd'), CONTAINERD), (os.path.join(b, 'stub', 'df'), VMDF)):
            open(path, 'w').write(body); os.chmod(path, 0o755)
""",
    """        for path, body in ((os.path.join(b, 'stub', 'containerd'), CONTAINERD), (os.path.join(b, 'stub', 'df'), VMDF)):
            open(path, 'w').write(body); os.chmod(path, 0o755)
        # F1: the VM's dockerd (holding docker's API socket) and the containerd docker reports, rooted in the fixture
        import tempfile as _tf
        self.sk = _tf.mkdtemp(prefix='f1-'); self.fprocs = []
        os.makedirs(os.path.join(self.st, 'containerd-root'), exist_ok=True); os.makedirs(os.path.join(self.st, 'alt-root'), exist_ok=True)
        fakeproc(self.fprocs, self.sk, 'dockerd', os.path.join(self.sk, 'docker.sock'), ['-H', 'fd://'])
        fakeproc(self.fprocs, self.sk, 'containerd', os.path.join(self.sk, 'ctd.sock'), ['--root', os.path.join(self.st, 'containerd-root')])
        self.put('docker-api', os.path.join(self.sk, 'docker.sock')); self.put('ctd-address', os.path.join(self.sk, 'ctd.sock'))
""")

rep("""    def env(self, smoke, **kw):
        kw.setdefault('DEPLOY_TARGET', 'selfhost'); return super().env(smoke, **kw)
""",
    """    def env(self, smoke, **kw):
        kw.setdefault('DEPLOY_TARGET', 'selfhost'); return super().env(smoke, **kw)

    def cleanup(self):
        _kill_fakeprocs(getattr(self, 'fprocs', []))
        import shutil as _sh; _sh.rmtree(getattr(self, 'sk', ''), ignore_errors=True) if getattr(self, 'sk', '') else None
        super().cleanup()
""")

# 5. retarget the two old "unresolved" cases (they drove the bare config dump F1 removes) to discovery failures, and add
#    the F1 regression at the release level
rep("""@pytest.mark.parametrize('mark', ['containerd-fail', 'containerd-noroot'])
def test_vm_disk_unresolved_containerd_root_refuses(R, mark):
    R.put(mark, ''); out = _vm_disk_refused(R, 'release/wave-60d3', mark)
    assert 'unresolved' in out, out
""",
    """@pytest.mark.parametrize('mark', ['no-listener', 'old-docker-no-dockerd'])
def test_vm_disk_unresolved_containerd_root_refuses(R, mark):
    # F1 retarget: these cases used to break the bare `containerd config dump` (containerd-fail / containerd-noroot),
    # which the ctl no longer runs. Now: docker names a socket nobody listens on; an old docker with no dockerd found.
    if mark == 'no-listener': R.put('ctd-address', os.path.join(R.sk, 'gone.sock')); why = 'nothing listens on'
    else: R.put('ctd-info-old', ''); R.put('docker-api', os.path.join(R.sk, 'gone.sock')); why = 'no dockerd'
    out = _vm_disk_refused(R, 'release/wave-60d3', mark)
    assert 'unresolved (REFUSED' in out and why in out, out


def test_vm_disk_measures_dockers_containerd_not_the_default_config(R):
    \"\"\"F1 (bth-pr73-v5): docker's own containerd keeps its store in a full root; a default `containerd config dump`
    names another root with ample space. The gate must measure docker's store, refuse and load nothing.\"\"\"
    R.put('vmdf-containerd', '0'); R.put('ctd-dump-alt', '')
    out = _vm_disk_refused(R, 'release/wave-60d8', 'active full, default has room')
    assert '"free_gb": 0' in out and 'containerd-root' in out and 'alt-root' not in out, out
""")

# 6. the discovery itself, case by case, on the real ctl code with real /proc (module constants for the two default
#    sockets, the default daemon.json and the default root are pointed into the fixture)
t = t.rstrip('\n') + '\n' + r'''


# ---- receipt bth-pr73-v5 F1: which containerd serves docker (each refusal has its own reason)
class _F1:
    pass


@pytest.fixture
def F1(tmp_path, monkeypatch):
    import importlib.util, shutil, tempfile as _tf
    h = _F1(); h.st = tmp_path / 'state'; h.st.mkdir(); stub = tmp_path / 'stub'; stub.mkdir()
    for name, body in (('docker', DOCKER), ('containerd', CONTAINERD)):
        (stub / name).write_text(body); os.chmod(stub / name, 0o755)
    h.sk = _tf.mkdtemp(prefix='f1-'); h.procs = []
    for d in ('containerd-root', 'alt-root', 'root-b', 'default-root'): (h.st / d).mkdir()
    (h.st / 'ctd-dump-alt').write_text('')                  # a bare `containerd config dump` would say alt-root
    monkeypatch.setenv('PATH', str(stub) + ':' + os.environ['PATH'])
    monkeypatch.setenv('FAKE_STATE', str(h.st)); monkeypatch.setenv('FAKE_SIDE', 'remote')
    spec = importlib.util.spec_from_file_location('selfhost_ctl_f1', CTL); M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
    h.M = M; h.sock = lambda n: os.path.join(h.sk, n); h.root = lambda n='containerd-root': os.path.realpath(str(h.st / n))
    if hasattr(M, 'CTD_DEFAULT_SOCKETS'):
        monkeypatch.setattr(M, 'CTD_DEFAULT_SOCKETS', (h.sock('system.sock'), h.sock('managed.sock')))
        monkeypatch.setattr(M, 'DOCKERD_DEFAULT_CONFIG', str(tmp_path / 'daemon.json'))
        monkeypatch.setattr(M, 'CTD_DEFAULT_CONFIG', str(tmp_path / 'no-default-containerd.toml'))
        monkeypatch.setattr(M, 'CTD_DEFAULT_ROOT', str(h.st / 'default-root'))
    h.put = lambda n, v='': (h.st / n).write_text(v)
    h.run = lambda *a, **k: fakeproc(h.procs, h.sk, *a, **k)
    h.dockerd = lambda args=(), **k: (h.run('dockerd', h.sock('docker.sock'), list(args), **k), h.put('docker-api', h.sock('docker.sock')))
    h.ctd = lambda sock, args, **k: h.run('containerd', h.sock(sock), list(args), **k)
    stk = M.Stack.__new__(M.Stack)

    def measured():
        roots = stk.store_roots()
        assert roots[0] == str(h.st) and len(roots) == 2, roots
        return roots[1]
    h.measured = measured
    yield h
    _kill_fakeprocs(h.procs); shutil.rmtree(h.sk, ignore_errors=True)


def _refused(h, why):
    with pytest.raises(h.M.Refused) as e: h.measured()
    assert why in str(e.value), str(e.value)


def test_f1_docker_info_address_names_the_store(F1):
    F1.ctd('ctd.sock', ['--root', str(F1.st / 'containerd-root')]); F1.put('ctd-address', F1.sock('ctd.sock'))
    assert F1.measured() == F1.root()


def test_f1_address_through_unix_scheme_and_config_file(F1):
    cfg = F1.st / 'ctd.toml'
    cfg.write_text("version = 2\nroot = '%s'   # the daemon root\nimports = []\n[plugins.'io.containerd.grpc.v1.cri']\n  root = '/elsewhere'\n"
                   "[plugins.'io.containerd.snapshotter.v1.overlayfs']\n  root_path = '/elsewhere2'\n" % (F1.st / 'containerd-root'))
    F1.ctd('ctd.sock', ['--config', str(cfg)]); F1.put('ctd-address', 'unix://' + F1.sock('ctd.sock'))
    assert F1.measured() == F1.root()


def test_f1_section_only_root_means_the_default_root(F1):
    cfg = F1.st / 'ctd.toml'; cfg.write_text("version = 2\n[plugins.x]\n  root = '%s'\n" % (F1.st / 'containerd-root'))
    F1.ctd('ctd.sock', ['-c', str(cfg)]); F1.put('ctd-address', F1.sock('ctd.sock'))
    assert F1.measured() == F1.root('default-root')


@pytest.mark.parametrize('body,why', [
    ("imports = ['/etc/containerd/conf.d/*.toml']\nroot = '%(r)s'\n", 'uses imports'),
    ("imports = [\n  '/x.toml',\n]\nroot = '%(r)s'\n", 'uses imports'),
    ("root = '%(r)s'\nroot = '/other'\n", 'sets root 2 times'),
    ("root = 'relative/root'\n", 'has an unreadable root'),
    ("root = '%(r)s/missing'\n", 'does not exist'),
])
def test_f1_containerd_config_refusals(F1, body, why):
    cfg = F1.st / 'ctd.toml'; cfg.write_text(body % {'r': F1.st / 'containerd-root'})
    F1.ctd('ctd.sock', ['--config', str(cfg)]); F1.put('ctd-address', F1.sock('ctd.sock'))
    _refused(F1, why)


def test_f1_named_config_missing_refuses(F1):
    F1.ctd('ctd.sock', ['--config', str(F1.st / 'nope.toml')]); F1.put('ctd-address', F1.sock('ctd.sock'))
    _refused(F1, 'does not exist')


def test_f1_relative_address_refuses(F1):
    F1.put('ctd-address', 'run/containerd.sock'); _refused(F1, 'not an absolute unix socket path')


def test_f1_nobody_listens_on_the_address(F1):
    F1.put('ctd-address', F1.sock('gone.sock')); _refused(F1, 'nothing listens on')


def test_f1_two_processes_hold_the_containerd_socket(F1):
    F1.ctd('ctd.sock', ['--root', str(F1.st / 'containerd-root')], child_args=['--root', str(F1.st / 'root-b')])
    F1.put('ctd-address', F1.sock('ctd.sock')); _refused(F1, '2 processes hold the containerd socket')


def test_f1_two_listening_sockets_at_one_path_refuse(F1):
    # a restarted containerd while the old one still listens: the path is unlinked and bound again
    F1.ctd('ctd.sock', ['--root', str(F1.st / 'root-b')]); os.unlink(F1.sock('ctd.sock'))
    F1.ctd('ctd.sock', ['--root', str(F1.st / 'containerd-root')])
    F1.put('ctd-address', F1.sock('ctd.sock')); _refused(F1, '2 sockets listen on')


# Docker < 27: no .Containerd in docker info; the one dockerd says where its containerd is
def test_f1_old_docker_dockerd_containerd_flag(F1):
    F1.put('ctd-info-old'); F1.dockerd(['--containerd', F1.sock('ctd.sock')])
    F1.ctd('ctd.sock', ['--root', str(F1.st / 'containerd-root')])
    assert F1.measured() == F1.root()


def test_f1_old_docker_daemon_json_containerd(F1):
    dj = F1.st / 'dj.json'; dj.write_text(json.dumps({'containerd': F1.sock('ctd.sock')}))
    F1.put('ctd-info-old'); F1.dockerd(['--config-file=%s' % dj]); F1.ctd('ctd.sock', ['--root', str(F1.st / 'containerd-root')])
    assert F1.measured() == F1.root()


def test_f1_old_docker_default_daemon_json_unparseable_refuses(F1):
    open(F1.M.DOCKERD_DEFAULT_CONFIG, 'w').write('{"containerd": ')
    F1.put('ctd-info-old'); F1.dockerd(); _refused(F1, 'cannot be parsed')


@pytest.mark.parametrize('live', ['managed', 'system'])
def test_f1_old_docker_default_uses_the_one_live_socket(F1, live):
    F1.put('ctd-info-old'); F1.dockerd(); F1.ctd(live + '.sock', ['--root', str(F1.st / 'containerd-root')])
    assert F1.measured() == F1.root()


def test_f1_old_docker_both_default_sockets_with_different_roots_refuse(F1):
    F1.put('ctd-info-old'); F1.dockerd()
    F1.ctd('system.sock', ['--root', str(F1.st / 'alt-root')]); F1.ctd('managed.sock', ['--root', str(F1.st / 'containerd-root')])
    _refused(F1, 'both default containerd sockets are live with different roots')


def test_f1_old_docker_both_default_sockets_with_one_root_agree(F1):
    F1.put('ctd-info-old'); F1.dockerd()
    F1.ctd('system.sock', ['--root', str(F1.st / 'containerd-root')]); F1.ctd('managed.sock', ['--root=%s' % (F1.st / 'containerd-root')])
    assert F1.measured() == F1.root()


def test_f1_old_docker_no_default_socket_refuses(F1):
    F1.put('ctd-info-old'); F1.dockerd(); _refused(F1, 'no containerd listens on either default socket')


def test_f1_old_docker_no_dockerd_refuses(F1):
    F1.put('ctd-info-old'); F1.put('docker-api', F1.sock('docker.sock')); _refused(F1, 'no dockerd')


def test_f1_old_docker_two_dockerd_refuse(F1):
    F1.put('ctd-info-old'); F1.dockerd(['--containerd', F1.sock('ctd.sock')], child_args=['--containerd', F1.sock('ctd.sock')])
    F1.ctd('ctd.sock', ['--root', str(F1.st / 'containerd-root')]); _refused(F1, '2 dockerd processes')


def test_f1_old_docker_socket_activation_holder_is_not_a_second_dockerd(F1):
    # systemd's docker.socket also holds the API socket; only processes named dockerd count
    F1.put('ctd-info-old'); F1.dockerd(['-H', 'fd://', '--containerd', F1.sock('ctd.sock')], child_args=['--system'], child_comm='systemd')
    F1.ctd('ctd.sock', ['--root', str(F1.st / 'containerd-root')])
    assert F1.measured() == F1.root()
'''
open(p, 'w').write(t)
print('patched', p)


def test_f1_unreadable_process_refuses_as_root(F1, monkeypatch):
    # on the VM the ctl is root: a process whose fds cannot be read might hold the socket, so the gate refuses
    F1.ctd('ctd.sock', ['--root', str(F1.st / 'containerd-root')]); F1.put('ctd-address', F1.sock('ctd.sock'))
    real = os.listdir

    def listdir(d):
        if str(d).endswith('/fd'): raise PermissionError(13, 'denied')
        return real(d)
    monkeypatch.setattr(F1.M.os, 'listdir', listdir); monkeypatch.setattr(F1.M.os, 'geteuid', lambda: 0)
    _refused(F1, 'cannot inspect process')
