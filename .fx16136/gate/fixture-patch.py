"""goodqa#16148 gate: extend the fake VM in test_rw_ship_selfhost.py (fakes only; rw-ship.sh unchanged by this patch).
usage: python3 fixture-patch.py <path to test_rw_ship_selfhost.py>"""
import sys

p = sys.argv[1]
t = open(p).read()


def rep(old, new, count=1):
    global t
    n = t.count(old)
    assert n == count, (n, old[:80])
    t = t.replace(old, new)


rep('import json, os, re, subprocess, sys\n\nimport pytest', 'import hashlib, json, os, re, subprocess, sys\n\nimport pytest')

# A. ssh: the derive stream is answered here and never runs (on the real VM it writes under /etc)
rep('FAKE_SIDE=remote exec bash -c "$*"\n', r'''if [ "$*" = "sudo python3 -I -" ]; then   # goodqa#16148: the derive-job-secrets.py stream; record WHAT was streamed
  git hash-object --stdin > "$FAKE_STATE/derive-streamed"; echo x >> "$FAKE_STATE/derive-runs"
  [ -e "$FAKE_STATE/derive-ssh-fail" ] && exit 255
  if [ -e "$FAKE_STATE/derive-out" ]; then cat "$FAKE_STATE/derive-out"; else echo "job secret github-app-private-key: written"; fi
  exit "$(cat "$FAKE_STATE/derive-rc" 2>/dev/null || echo 0)"
fi
FAKE_SIDE=remote exec bash -c "$*"
''')

# B. sudo: the VM runs selfhost-ctl as root; here only trial-boot's chown to root:64910 becomes a no-op
rep('''SUDO = '#!/bin/sh\\nexec "$@"\\n'
''', r'''SUDO = r"""#!/bin/sh
# goodqa#16148: trial-boot chowns its fake marker to root:64910 (the VM runs this as root; the test does not). Only that
# call is neutralised; the streamed selfhost-ctl.py is otherwise run byte for byte.
if [ "$1" = python3 ] && [ "$2" = - ]; then case " $* " in *" trial-boot "*) shift 2
  exec python3 -c 'import os, sys; os.chown = lambda *a, **k: None; sys.argv[0] = "-"; exec(compile(sys.stdin.read(), "<stdin>", "exec"), {"__name__": "__main__"})' "$@";; esac; fi
exec "$@"
"""
''')

# C. docker: dispatcher containers get a hex id per generation, a start time and a boot line; the gate verbs' calls
rep("""        cons = [c for c in cons if c['service'] not in svcs]
""", """        gone = [c for c in cons if c['service'] in svcs]; W('gone.json', J('gone.json', []) + gone)
        cons = [c for c in cons if c['service'] not in svcs]
""")
rep("""        W('containers.json', cons); log('UP api=""", """        g = J('gen.json', 0) + 1; W('gen.json', g); prev = [c for c in gone if c['service'] == 'job-dispatcher' and 'hex' in c]
        for c in cons:                                        # goodqa#16148: what disp-boot reads
            if 'hex' in c: continue
            c['hex'] = hashlib.sha256(('%s/%d' % (c['id'], g)).encode()).hexdigest()
            c['started'] = '2026-11-15T01:%02d:%02d.123456789Z' % (g // 60 % 60, g % 60)
            if c['service'] == 'job-dispatcher':
                c['boot'] = markv('disp-boot-line') if mark('disp-boot-line') else DISP_OK
                if mark('disp-same-hex') and prev: c.update({k: prev[-1][k] for k in ('hex', 'started', 'boot')})
        log('UPSVCS ' + ','.join(svcs))
        W('containers.json', cons); log('UP api=""")
rep("""cons = J('containers.json', [])
if a[0] == 'ps':""", """cons = J('containers.json', [])
DISP_OK = 'job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok'
def hexid(c): return c.get('hex') or hashlib.sha256(c['id'].encode()).hexdigest()
if a[0] == 'ps' and 'label=com.docker.compose.service=job-dispatcher' in a:   # goodqa#16148 disp-boot
    log('DISPPS'); print('\\n'.join(hexid(c) for c in cons if c['service'] == 'job-dispatcher' and c['status'] == 'running')); sys.exit(0)
if a[0] == 'inspect' and a[1:3] == ['-f', '{{.State.StartedAt}}']:
    c = [c for c in cons + J('gone.json', []) if hexid(c) == a[3]]
    if not c: sys.exit(1)
    print(c[0].get('started', '2026-11-15T00:00:00.000000000Z')); sys.exit(0)
if a[0] == 'logs' and '--since' in a:
    c = [c for c in cons + J('gone.json', []) if hexid(c) == a[-1]]
    log('DISPLOGS %s since=%s tail=%s' % (a[-1][:12], a[a.index('--since') + 1], a[a.index('--tail') + 1] if '--tail' in a else '-'))
    if not c or mark('disp-logs-fail'): sys.exit(1)
    for n in range(5): print('{"level":30,"msg":"incoming request %d"}' % n)
    if c[0].get('boot'): print(json.dumps({'level': 30, 'msg': c[0]['boot']}))
    sys.exit(0)
if a[0] == 'run' and '--boot-check' in a:                     # goodqa#16148 trial-boot
    img = a[a.index('--boot-check') - 2]; log('TRIAL %s' % img)
    open(os.path.join(os.environ['FAKE_STATE'], 'trial-argv'), 'w').write(json.dumps(a))
    if not resolve(img): sys.exit(125)
    if (markv('trial') if mark('trial') else 'ok') == 'ok': print(DISP_OK); sys.exit(0)
    print('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: missing'); sys.exit(1)
if a[0] == 'rm':
    log('RM ' + ' '.join(a[1:])); sys.exit(0)
if a[0] == 'ps':""")

# D. the VM env dir holds dispatcher.env with the one key line (apply-job-secrets.sh writes it on the real VM)
rep("""            os.chmod(p, 0o600)
        with open(os.path.join(b, 'biz/release-waves/ship.conf'), 'a') as f:""", """            os.chmod(p, 0o600)
        p = os.path.join(self.envd, 'dispatcher.env')
        open(p, 'w').write('JOB_DISPATCH_TOKEN=fake-dispatch-token\\n' + JOBSECRET_KEY_LINE + '\\n'); os.chmod(p, 0o600)
        with open(os.path.join(b, 'biz/release-waves/ship.conf'), 'a') as f:""")

# E. lazy default binding: an unheld release needs derive-job-secrets.py from a bound commit (lead ruling Q1)
rep("""    def env(self, smoke, **kw):
        kw.setdefault('DEPLOY_TARGET', 'selfhost'); return super().env(smoke, **kw)
""", """    autobind = True                  # goodqa#16148: bind at the first run unless the test set RELEASE_BINDING or opted out

    def start(self, name, sha, smoke='auto', wrap=None, **kw):
        if self.autobind and 'RELEASE_BINDING=' not in open(os.path.join(self.F, 'biz/release-waves/ship.conf')).read():
            bind_release(self)
        return super().start(name, sha, smoke, wrap=wrap, **kw)

    def env(self, smoke, **kw):
        kw.setdefault('DEPLOY_TARGET', 'selfhost'); return super().env(smoke, **kw)
""")
rep("""class SRoot(base.Root):""", """JOBSECRET_KEY_LINE = 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=/run/goodqa-secrets/github-app-private-key'
DERIVE_SRC = os.path.join(HERE, '..', 'selfhost', 'app', 'derive-job-secrets.py')
DERIVE_PATH = 'infra/selfhost/app/derive-job-secrets.py'
BOUND = ('rw-ship.sh', 'selfhost-ctl.py', 'rw-rollback.sh', 'rw-runtime.sh')


def blob_sha(body): return subprocess.run(['git', 'hash-object', '--stdin'], input=body, capture_output=True, check=True).stdout.decode().strip()


def bind_release(R, derive=b'', blob=None):
    \"\"\"goodqa#16148: bind this root's installed release scripts AND infra/selfhost/app/derive-job-secrets.py to one commit
    (commit-tree: no branch, HEAD and main untouched), then write RELEASE_BINDING with its derive-blob line.
    derive=None leaves derive out of the commit; blob overrides the recorded derive-blob (None = the committed one).\"\"\"
    env = dict(os.environ, GIT_INDEX_FILE=os.path.join(R.F, 'tmp', 'bind.index'), GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@example.com',
               GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@example.com')
    def g(*a, body=None):
        return subprocess.run(['git', *a], cwd=R.repo, env=env, input=body, capture_output=True, check=True).stdout.decode().strip()
    entries = [('infra/release-harness/' + n, open(os.path.join(R.F, 'bin', n), 'rb').read()) for n in BOUND]
    if derive is not None: entries.append((DERIVE_PATH, derive or open(DERIVE_SRC, 'rb').read()))
    if os.path.exists(env['GIT_INDEX_FILE']): os.unlink(env['GIT_INDEX_FILE'])
    for path, body in entries: g('update-index', '--add', '--cacheinfo', '100644,%s,%s' % (g('hash-object', '-w', '--stdin', body=body), path))
    c = g('commit-tree', g('write-tree'), '-m', 'bind release scripts')
    g('push', '-q', 'origin', c + ':refs/heads/release-harness-bind')
    lines = ['commit ' + c, 'path infra/release-harness'] + ['%s  bin/%s' % (hashlib.sha256(b).hexdigest(), n) for n, (_, b) in zip(BOUND, entries)]
    if blob is None and derive is not None: blob = blob_sha(entries[-1][1])
    if blob: lines.append('derive-blob ' + blob)
    bf = os.path.join(R.F, 'bin', 'RELEASE_BINDING'); open(bf, 'w').write('\\n'.join(lines) + '\\n')
    _conf(R, 'RELEASE_BINDING', bf)
    return c


class SRoot(base.Root):""")

# F. failure injection for the re-hold paths
rep("""        svcs = [x for x in rest if not x.startswith('-')]; p = pins(text)
""", """        svcs = [x for x in rest if not x.startswith('-')]; p = pins(text)
        if mark('up-fail-disp-only') and sorted(svcs) == ['job-dispatcher', 'job-dispatcher-create-guard']:
            log('UPSVCS-FAILED ' + ','.join(svcs)); print('fake: dispatcher up failed', file=sys.stderr); sys.exit(1)
""")
rep('''FAKE_SIDE=remote exec bash -c "$*"
''', r'''if [ -e "$FAKE_STATE/restore-fail" ] && [[ "$*" =~ \ restore\ --stamp\ [0-9]{8}T[0-9]{6}Z$ ]]; then   # goodqa#16148: the run's own restore fails
  cat >/dev/null; echo "REFUSED fake restore failure"; exit 3
fi
FAKE_SIDE=remote exec bash -c "$*"
''')

open(p, 'w').write(t)
print('patched')
