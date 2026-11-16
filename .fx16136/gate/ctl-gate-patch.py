"""goodqa#16148 AC-8 (P3, P4, lead rulings): four selfhost-ctl verbs for the rw-ship unhold gate. Run in infra/release-harness."""
p = 'selfhost-ctl.py'
s = open(p).read()

USAGE_ANCHOR = "  pin --stamp S --sha SHA --deploy-id D --api REF --web REF --disp REF\n"
USAGE = '''  envfile-key                    goodqa#16148 AC-8 (b): one JSON line {"count": N}, how many lines of dispatcher.env are exactly
                                 the JOB_ENVFILE key line for the GitHub App key. A count only; no line is ever printed.
  disp-boot                      goodqa#16148 AC-8 (c): one JSON line {"id", "started", "status"} for the running job-dispatcher
                                 container. Its own log, bounded by --since <its StartedAt> and --tail, is read here and never
                                 printed or kept. status = ok (the exact boot line), missing (no line), error:<reason word>,
                                 no-container or ambiguous.
  trial-boot --image goodqa-job-dispatcher@sha256:<64 hex> --stamp S
                                 goodqa#16148 AC-8 / P3: runs that exact image once with --boot-check, isolated: --rm,
                                 --network none, --read-only, --cap-drop ALL, no-new-privileges, a non-root user, pids and
                                 memory limits, no socket, no env_file. A fresh 0711 dir holds a FIXED fake marker (never the
                                 real key) as root:64910 0440. 60 s timeout = timeout (and the container is removed). Prints
                                 {"status": ok|fail|timeout|refused, "rc": N}; the container's output is never printed.
  up-dispatcher [--timeout N]    goodqa#16148 AC-8 / P4: `docker compose up -d --no-deps` job-dispatcher and its guard ONLY,
                                 then waits as `up` does for those two. UP_OK / UP_FAIL.
'''
assert s.count(USAGE_ANCHOR) == 1
s = s.replace(USAGE_ANCHOR, USAGE + USAGE_ANCHOR)

FUNC_ANCHOR = "def cmd_up(stk, a):\n"
FUNCS = r'''# ---- goodqa#16148 AC-8: the job-secret unhold gate (names and status words only; no value, no log text leaves here)
JOBSECRET_KEY_LINE = 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=/run/goodqa-secrets/github-app-private-key'
DISP_OK_LINE = 'job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok'
DISP_ERR_PREFIX = 'job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: '
DISP_ERR_WORDS = {'missing': 'missing-file', 'is a symlink': 'symlink', 'unreadable': 'unreadable',
                  'not a regular file': 'not-regular', 'over 64 KiB': 'too-large', 'empty': 'empty',
                  'value holds CR, LF or NUL': 'bad-bytes', 'value is not valid UTF-8': 'bad-utf8',
                  'path outside the secrets directory': 'outside-dir', 'cannot read (error)': 'read-error'}
DISP_LOG_TAIL = 2000
TRIAL_IMAGE_RE = re.compile(r'^goodqa-job-dispatcher@sha256:[0-9a-f]{64}$')
TRIAL_STAMP_RE = re.compile(r'^[A-Za-z0-9._-]{1,80}$')
TRIAL_MARKER = 'goodqa-trial-boot-fixed-fake-marker-not-a-key'   # fixed; never derived from the real key
TRIAL_TIMEOUT = 60
TRIAL_GID = 64910
TRIAL_FLAGS = ('--rm', '--network', 'none', '--read-only', '--tmpfs', '/tmp', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges', '--user', 'node', '--group-add', str(TRIAL_GID),
               '--pids-limit', '64', '--memory', '256m')


def cmd_envfile_key(stk, a):
    path = os.path.join(stk.env_dir, 'dispatcher.env')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        n = sum(1 for l in f.read().split(b'\n') if l.rstrip(b'\r') == JOBSECRET_KEY_LINE.encode())
    out({'count': n}); return 0


def disp_status(log_text):
    """Status word of the GitHub App key boot line in a dispatcher log (pino JSON lines; `msg` compared exactly)."""
    err = None
    for l in log_text.split('\n'):
        try: msg = json.loads(l).get('msg')
        except Exception: continue
        if not isinstance(msg, str): continue
        if msg == DISP_OK_LINE: return 'ok'
        if msg.startswith(DISP_ERR_PREFIX) and err is None:
            err = 'error:' + DISP_ERR_WORDS.get(msg[len(DISP_ERR_PREFIX):], 'other')
    return err or 'missing'


def cmd_disp_boot(stk, a):
    ids = docker('ps', '-q', '--no-trunc', '--filter', 'label=com.docker.compose.project=' + stk.project,
                 '--filter', 'label=com.docker.compose.service=job-dispatcher', '--filter', 'status=running',
                 timeout=60).stdout.split()
    ids = [i for i in ids if re.match(r'^[0-9a-f]{12,64}$', i)]
    if len(ids) != 1:
        out({'id': None, 'started': None, 'status': 'no-container' if not ids else 'ambiguous'}); return 0
    cid = ids[0]
    started = docker('inspect', '-f', '{{.State.StartedAt}}', cid, timeout=60).stdout.strip()
    if not re.match(r'^\d{4}-\d\d-\d\dT[0-9:.]+Z$', started):
        out({'id': cid, 'started': None, 'status': 'unreadable'}); return 0
    r = docker('logs', '--since', started, '--tail', str(DISP_LOG_TAIL), cid, timeout=60)
    status = disp_status((r.stdout or '') + '\n' + (r.stderr or '')) if r.returncode == 0 else 'unreadable'
    del r
    out({'id': cid, 'started': started, 'status': status}); return 0


def trial_argv(name, image, secrets_dir):
    return ['run', *TRIAL_FLAGS, '--name', name,
            '-e', 'JOB_DISPATCH_TOKEN=trial-fake-token', '-e', JOBSECRET_KEY_LINE,
            '-v', secrets_dir + ':/run/goodqa-secrets:ro',
            '--entrypoint', 'node_modules/.bin/tsx', image, 'src/index.ts', '--boot-check']


def cmd_trial_boot(stk, a):
    if not TRIAL_IMAGE_RE.match(a.image) or not TRIAL_STAMP_RE.match(a.stamp):
        out({'status': 'refused', 'rc': None}); return 3
    if stk.image_ids([a.image]).get(a.image) != a.image.split('@', 1)[1]:
        out({'status': 'refused', 'rc': None}); return 3
    import tempfile
    name = 'goodqa-trial-' + a.stamp
    d = tempfile.mkdtemp(prefix='goodqa-trial-')
    try:
        os.chmod(d, 0o711)
        f = os.path.join(d, 'github-app-private-key')
        fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as fh: fh.write(TRIAL_MARKER + '\n')
        os.chown(f, 0, TRIAL_GID); os.chmod(f, 0o440)
        try:
            r = docker(*trial_argv(name, a.image, d), timeout=TRIAL_TIMEOUT)
        except subprocess.TimeoutExpired:
            out({'status': 'timeout', 'rc': None}); return 5
        ok = r.returncode == 0 and DISP_OK_LINE in r.stdout.split('\n')
        del r
        out({'status': 'ok' if ok else 'fail', 'rc': 0 if ok else 1}); return 0 if ok else 5
    finally:
        docker('rm', '-f', name, timeout=60)
        shutil.rmtree(d, ignore_errors=True)


'''
assert s.count(FUNC_ANCHOR) == 1
s = s.replace(FUNC_ANCHOR, FUNCS + FUNC_ANCHOR)

UP_OLD = """def cmd_up(stk, a):
    r = stk.dc('up', '-d', '--no-deps', '--pull', 'never', *SERVICES, timeout=a.timeout + 120)
"""
UP_NEW = """def cmd_up(stk, a, services=SERVICES):
    r = stk.dc('up', '-d', '--no-deps', '--pull', 'never', *services, timeout=a.timeout + 120)
"""
assert s.count(UP_OLD) == 1
s = s.replace(UP_OLD, UP_NEW)
for old, new in (("            out('UP_OK ' + json.dumps({s: want[s] for s in SERVICES}, sort_keys=True)); return 0\n",
                  "            out('UP_OK ' + json.dumps({s: want[s] for s in services}, sort_keys=True)); return 0\n"),
                 ("        for s in SERVICES:\n            mine = [c for c in cs if c['service'] == s",
                  "        for s in services:\n            mine = [c for c in cs if c['service'] == s")):
    assert s.count(old) == 1, old
    s = s.replace(old, new)
s = s.replace(FUNCS, FUNCS + '''def cmd_up_dispatcher(stk, a):
    return cmd_up(stk, a, services=('job-dispatcher', 'job-dispatcher-create-guard'))


''', 1)

ARG_ANCHOR = "    sub.add_parser('disk'); sub.add_parser('guard-log')\n"
ARGS = ARG_ANCHOR + """    sub.add_parser('envfile-key'); sub.add_parser('disp-boot')
    tb = sub.add_parser('trial-boot'); tb.add_argument('--image', required=True); tb.add_argument('--stamp', required=True)
    ud = sub.add_parser('up-dispatcher'); ud.add_argument('--timeout', type=int, default=300); ud.add_argument('--every', type=float, default=3)
"""
assert s.count(ARG_ANCHOR) == 1
s = s.replace(ARG_ANCHOR, ARGS)

DISP_OLD = "'pin': cmd_pin, 'restore': cmd_restore, 'up': cmd_up,"
DISP_NEW = ("'pin': cmd_pin, 'restore': cmd_restore, 'up': cmd_up, 'up-dispatcher': cmd_up_dispatcher, "
            "'envfile-key': cmd_envfile_key, 'disp-boot': cmd_disp_boot, 'trial-boot': cmd_trial_boot,")
assert s.count(DISP_OLD) == 1
s = s.replace(DISP_OLD, DISP_NEW)
open(p, 'w').write(s)
print('patched')
