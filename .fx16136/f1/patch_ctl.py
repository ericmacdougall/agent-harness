"""Apply the F1 (bth-pr73-v5) active-containerd-root fix to a selfhost-ctl.py. Usage: patch_ctl.py <selfhost-ctl.py>"""
import sys

p = sys.argv[1]
t = open(p).read()

OLD = """        if self.store_is_containerd():
            try: c = subprocess.run(['containerd', 'config', 'dump'], capture_output=True, text=True, timeout=60)
            except (OSError, subprocess.SubprocessError) as e: raise Refused('cannot run containerd config dump: %s' % type(e).__name__)
            m = re.search(r'^root\\s*=\\s*(["\\x27])([^"\\x27\\n]+)\\1\\s*$', c.stdout, re.M) if c.returncode == 0 else None
            if not m or not m.group(2).startswith('/'): raise Refused('cannot resolve the containerd root (containerd config dump)')
            roots.append(m.group(2))
        return roots
"""

NEW = """        if self.store_is_containerd(): roots.append(self.containerd_root())
        return roots

    def containerd_root(self):
        \"\"\"Receipt bth-pr73-v5 F1: the data root of the containerd that serves THIS docker, never a default `containerd
        config dump`. The endpoint comes from, in order: docker info .Containerd.Address (Docker Engine 27+); the one
        dockerd's --containerd flag; its daemon.json "containerd" key; else the two default sockets (system containerd
        and dockerd's own managed one), of which exactly one may be live, or both with the same root. The one process
        holding that endpoint's one listening socket is found through /proc (the ctl runs as root on the VM), and its own
        --root, or the top-level root of its own --config file, is the store. Every unresolved or ambiguous step refuses
        with its own message; rw-ship then reports the store unresolved and stops (NO DISK, exit 11) before any load.\"\"\"
        try: r = docker('info', '-f', '{{json .Containerd}}', timeout=60)
        except (OSError, subprocess.SubprocessError) as e: raise Refused('cannot run docker info for the containerd address: %s' % type(e).__name__)
        try: info = json.loads(r.stdout) if r.returncode == 0 else None
        except ValueError: info = None
        addr = info.get('Address') if isinstance(info, dict) else None
        if addr in (None, ''):                              # Docker < 27 has no .Containerd: ask the daemon itself
            dargs = proc_argv(self.dockerd_pid())
            opts = cli_flags(dargs, {'containerd': 'containerd', 'config-file': 'config-file'}, 'dockerd')
            if 'containerd' in opts: addr = opts['containerd']
            else:
                cfg = opts.get('config-file', DOCKERD_DEFAULT_CONFIG)
                try: d = json.loads(open(cfg).read())
                except FileNotFoundError:
                    if 'config-file' in opts: raise Refused('dockerd --config-file %s does not exist' % cfg)
                    d = {}
                except (OSError, ValueError, UnicodeDecodeError): raise Refused('dockerd daemon.json %s cannot be parsed' % cfg)
                if not isinstance(d, dict): raise Refused('dockerd daemon.json %s cannot be parsed' % cfg)
                addr = d.get('containerd') or None
        if addr is not None:
            if isinstance(addr, str) and addr.startswith('unix://'): addr = addr[len('unix://'):]
            if not isinstance(addr, str) or not addr.startswith('/') or '\\n' in addr:
                raise Refused('docker\\'s containerd address is not an absolute unix socket path')
            return containerd_root_at(addr)
        live = {}
        for s in CTD_DEFAULT_SOCKETS:
            try: live[s] = containerd_root_at(s)
            except NoListener: pass
        if not live: raise Refused('no containerd listens on either default socket (%s)' % ', '.join(CTD_DEFAULT_SOCKETS))
        if len(set(live.values())) > 1:
            raise Refused('both default containerd sockets are live with different roots (%s); docker\\'s store is ambiguous'
                          % ', '.join('%s=%s' % kv for kv in sorted(live.items())))
        return next(iter(live.values()))

    def dockerd_pid(self):
        \"\"\"The one dockerd holding docker's own API socket (the endpoint this docker CLI talks to).\"\"\"
        try: r = docker('context', 'inspect', '-f', '{{.Endpoints.docker.Host}}', timeout=60)
        except (OSError, subprocess.SubprocessError) as e: raise Refused('cannot read docker\\'s API endpoint: %s' % type(e).__name__)
        host = r.stdout.strip() if r.returncode == 0 else ''
        if not host.startswith('unix:///') or '\\n' in host: raise Refused('docker\\'s API endpoint is not a local unix socket; dockerd cannot be found')
        try: holders = socket_holders(host[len('unix://'):])
        except NoListener: raise Refused('no dockerd: nothing listens on docker\\'s API socket %s' % host[len('unix://'):])
        ds = [pid for pid in holders if proc_comm(pid) == 'dockerd']
        if len(ds) != 1: raise Refused('%d dockerd processes hold docker\\'s API socket, expected exactly one' % len(ds))
        return ds[0]
"""

assert t.count(OLD) == 1, 'store_roots anchor not found exactly once'
t = t.replace(OLD, NEW)

FUNC_ANCHOR = "def docker(*a, check=False, timeout=None, cwd=None):"
FUNC = '''# ---- receipt bth-pr73-v5 F1: which containerd serves docker, and where it keeps its data
CTD_DEFAULT_CONFIG = '/etc/containerd/config.toml'   # containerd's own defaults when its command line names neither
CTD_DEFAULT_ROOT = '/var/lib/containerd'
CTD_DEFAULT_SOCKETS = ('/run/containerd/containerd.sock', '/var/run/docker/containerd/containerd.sock')
DOCKERD_DEFAULT_CONFIG = '/etc/docker/daemon.json'


class NoListener(Refused):
    """Nothing listens on a socket path (the default-socket probe tolerates this for one of its two paths)."""


def proc_argv(pid):
    try: raw = open('/proc/%s/cmdline' % pid, 'rb').read()
    except OSError: raise Refused('process %s went away or cannot be read' % pid)
    args = raw.decode('utf-8', 'surrogateescape').split('\\0')
    if args and args[-1] == '': args.pop()
    if not args: raise Refused('process %s has no command line' % pid)
    return args


def proc_comm(pid):
    try: return open('/proc/%s/comm' % pid).read().strip()
    except OSError: return ''


def cli_flags(args, names, prog):
    """Values of the long flags NAMES ({spelling: key}) in ARGS[1:]: --x v, --x=v, -x v (Go flag forms). A repeated flag
    or one without a value refuses."""
    opts, i = {}, 1
    while i < len(args):
        a = args[i]; i += 1
        if not a.startswith('-') or a in ('-', '--'): continue
        name, eq, val = a.lstrip('-').partition('=')
        if name not in names: continue
        if not eq:
            if i >= len(args): raise Refused('%s --%s has no value' % (prog, name))
            val = args[i]; i += 1
        key = names[name]
        if key in opts: raise Refused('%s --%s is given twice' % (prog, key))
        if not val.startswith('/') and not val.startswith('unix:///') or '\\n' in val:
            raise Refused('%s --%s is not an absolute path' % (prog, key))
        opts[key] = val
    return opts


def socket_holders(path):
    """Pids holding the one listening unix socket bound at PATH. /proc/net/unix gives its inode; holders are looked for
    among the processes of the socket file's owner (only they can have bound it; the ctl runs as root on the VM), each in
    this pid namespace. NoListener when none listens; several listening inodes, an unreadable process of that owner,
    or a holder in another pid namespace refuse."""
    want = os.path.realpath(path)
    try: rows = open('/proc/net/unix').read().split('\\n')[1:]
    except OSError as e: raise Refused('cannot read /proc/net/unix: %s' % type(e).__name__)
    inodes = set()
    for row in rows:
        f = row.split(None, 7)                               # Num RefCount Protocol Flags Type St Inode Path
        if len(f) == 8 and f[3] == '00010000' and f[5] == '01' and f[7].startswith('/') and os.path.realpath(f[7]) == want:
            inodes.add(f[6])
    if not inodes: raise NoListener('nothing listens on %s' % path)
    if len(inodes) > 1: raise Refused('%d sockets listen on %s, expected exactly one' % (len(inodes), path))
    tag = 'socket:[%s]' % inodes.pop()
    try: uid = os.stat(want).st_uid
    except OSError as e: raise Refused('cannot stat the socket %s: %s' % (path, type(e).__name__))
    myns = os.readlink('/proc/self/ns/pid')
    holders, hidden = [], []

    def unreadable(pid):
        # as root (always so on the VM: `sudo python3 -`) every process can be read, so one that cannot is a refusal;
        # unprivileged (the test suite), processes of another security context are reported only if nothing holds PATH
        if os.geteuid() == 0: raise Refused('cannot inspect process %s (holder search for %s)' % (pid, path))
        hidden.append(pid)
    for pid in sorted((x for x in os.listdir('/proc') if x.isdigit()), key=int):
        try:
            if os.stat('/proc/' + pid).st_uid != uid: continue
            fds = os.listdir('/proc/%s/fd' % pid)
        except FileNotFoundError: continue                   # exited meanwhile
        except PermissionError: unreadable(pid); continue
        for fd in fds:
            try: hit = os.readlink('/proc/%s/fd/%s' % (pid, fd)) == tag
            except FileNotFoundError: hit = False
            except PermissionError: unreadable(pid); break
            if hit:
                try: ns = os.readlink('/proc/%s/ns/pid' % pid)
                except OSError: raise Refused('cannot inspect process %s (holder search for %s)' % (pid, path))
                if ns != myns: raise Refused('the holder of %s is in another pid namespace' % path)
                holders.append(pid); break
    if not holders and hidden: raise Refused('cannot inspect %d processes; no holder of %s found' % (len(hidden), path))
    return holders


def containerd_root_at(path):
    holders = socket_holders(path)
    if len(holders) != 1:
        raise Refused('%d processes hold the containerd socket %s, expected exactly one' % (len(holders), path))
    return containerd_root_of(proc_argv(holders[0]))


def containerd_root_of(args):
    """The existing data root (realpath) of the containerd process with command line ARGS: its --root, else the
    top-level root of its --config file (containerd's default config and root when unnamed). Keys inside [tables]
    (plugin root_path and the like) are not the daemon root. A non-empty imports, a repeated top-level root, an
    unreadable named config or a root that does not exist refuse."""
    opts = cli_flags(args, {'root': 'root', 'config': 'config', 'c': 'config'}, 'containerd')
    if 'root' in opts: root = opts['root']
    else:
        cfg = opts.get('config', CTD_DEFAULT_CONFIG)
        try: text = open(cfg).read()
        except FileNotFoundError:
            if 'config' in opts: raise Refused('containerd --config %s does not exist' % cfg)
            text = ''
        except (OSError, UnicodeDecodeError) as e: raise Refused('cannot read the containerd config %s: %s' % (cfg, type(e).__name__))
        top = []
        for line in text.split('\\n'):
            if re.match(r'^\\s*\\[', line): break
            top.append(line)
        body = '\\n'.join(top)
        im = re.search(r'^\\s*imports\\s*=\\s*\\[([^\\]]*)\\]', body, re.M)
        if (im and re.sub(r'(#[^\\n]*)|[\\s,]', '', im.group(1))) or (not im and re.search(r'^\\s*imports\\s*=', body, re.M)):
            raise Refused('the containerd config %s uses imports, which can override its root' % cfg)
        hits = [l for l in top if re.match(r'^\\s*root\\s*=', l)]
        if len(hits) > 1: raise Refused('the containerd config %s sets root %d times' % (cfg, len(hits)))
        if not hits: root = CTD_DEFAULT_ROOT
        else:
            m = re.match(r'^\\s*root\\s*=\\s*(["\\x27])([^"\\x27\\\\\\n]*)\\1\\s*(#.*)?$', hits[0])
            if not m or not m.group(2).startswith('/'): raise Refused('the containerd config %s has an unreadable root' % cfg)
            root = m.group(2)
    real = os.path.realpath(root)
    if not os.path.isdir(real): raise Refused('the containerd root %s does not exist' % root)
    return real


'''
assert t.count(FUNC_ANCHOR) == 1, 'docker() anchor not found exactly once'
REF_ANCHOR = 'class Refused('
assert t.index(REF_ANCHOR) < t.index(FUNC_ANCHOR), 'Refused must be defined before docker()'
t = t.replace(FUNC_ANCHOR, FUNC + FUNC_ANCHOR)
open(p, 'w').write(t)
print('patched', p)
