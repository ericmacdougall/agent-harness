"""Patch infra/release-harness/selfhost-ctl.py for goodqa#16136 (job image pins). python3 patch_ctl.py FILE"""
import sys
p = sys.argv[1]; t = open(p).read()


def rep(old, new, count=1):
    global t
    n = t.count(old)
    assert n == count, (n, old[:90])
    t = t.replace(old, new)


rep('''  image-ids REF...               one JSON line {ref: image id or null}
''', '''  image-ids REF...               one JSON line {ref: image id or null}
  disk                           one JSON line {"free_gb": N}: free space where the docker store lives (before a load)
''')
rep('''                                 rides in the same backed-up, fenced env file, so `restore` (and every rollback) reverts it.
''', '''                                 rides in the same backed-up, fenced env file, so `restore` (and every rollback) reverts it.
                                 --job-image KEY=goodqa-<job>@sha256:<64 hex> / --job-hold KEY (goodqa#16136): every one of
                                 the four JOB_IMAGE_* keys must be named exactly once by one of the two. --job-image rewrites
                                 that key's line in the create-guard's &job-images anchor (the job-dispatcher inherits it, and
                                 each key must appear exactly once in the whole file, in that block); --job-hold keeps the
                                 current line. Refused unless the docker store is containerd (only there does a loaded,
                                 never-pushed image resolve as repo@<image id>). Before any file changes, every release-
                                 managed ref in the RESOLVED prepared compose (the four service images and every non-held
                                 JOB_IMAGE_* value, on both the guard and the dispatcher) must resolve on this host by its
                                 exact string, a job ref to its own digest; other (pulled, third-party) images only WARN.
''')
rep('''                                 --expect-fp equal to the live fingerprint the caller read.
''', '''                                 --expect-fp equal to the live fingerprint the caller read.
                                 Never runs the presence check: after restoring it prints WARN lines for job refs and core
                                 images that do not resolve (a rollback is never blocked; `up` never pulls).
''')

# ---- constants
rep('''class Refused(Exception):
    pass
''', '''# goodqa#16136: the four dispatcher job images. Each key's value is the guard allowlist entry for that job kind, so the
# repository is fixed per key and the value must be a content address (AUD-031) of an image loaded by the release.
JOB_KEYS = {'JOB_IMAGE_SCAN': 'goodqa-scan', 'JOB_IMAGE_TRANSCODE': 'goodqa-transcode',
            'JOB_IMAGE_INTELLIGENCE_WORKER': 'goodqa-intelligence-worker',
            'JOB_IMAGE_SUGGEST_FIX_WORKER': 'goodqa-suggest-fix-worker'}
JOB_BLOCK = 'job-dispatcher-create-guard'
JOB_LINE_RE = re.compile(r'^      (JOB_IMAGE_[A-Z0-9_]+):[ \\t]*(\\S+)(?:[ \\t]+#[ \\t]*(held))?[ \\t]*$')
# goodqa#16136 AC-16: the create-guard's mode hold; the only value a release may set.
GUARD_HOLD_ALLOWED = ('TRANSCODER_MODE=transcribe',)
GUARD_LINE_RE = re.compile(r'^      GUARD_HELD_ENV:[ \\t]*(\\S*)[ \\t]*$')


def job_ref_ok(key, ref):
    return re.fullmatch(re.escape(JOB_KEYS[key]) + r'@sha256:[0-9a-f]{64}', ref) is not None


class Refused(Exception):
    pass
''')

# ---- Stack: job lines, jobs(), rejob(), store check, resolved config
rep('''    # ---- env files (format: raw, KEY=VALUE per line)''', '''    # ---- the four JOB_IMAGE_* lines (goodqa#16136): exactly once each in the whole file, inside the create-guard block
    @staticmethod
    def job_lines(text):
        lines = text.split('\\n'); res = {}; cur = None; in_svc = False
        for i, l in enumerate(lines):
            if l.rstrip() == 'services:': in_svc = True; cur = None; continue
            if l and not l.startswith(' ') and not l.startswith('#'): in_svc = False; cur = None
            m = re.match(r'^  ([A-Za-z0-9_.-]+):\\s*(#.*)?$', l)
            if in_svc and m: cur = m.group(1); continue
            if 'JOB_IMAGE_' not in l.split('#', 1)[0]: continue
            m = JOB_LINE_RE.match(l)
            if not m or not in_svc or cur != JOB_BLOCK:
                raise Refused('compose.yaml line %d names a JOB_IMAGE_* key outside the %s &job-images block (the guard '
                              'allowlist and the dispatcher config could diverge)' % (i + 1, JOB_BLOCK))
            k = m.group(1)
            if k not in JOB_KEYS: raise Refused('compose.yaml line %d: unknown job image key %s' % (i + 1, k))
            if k in res: raise Refused('compose.yaml: %s appears more than once' % k)
            res[k] = i
        miss = sorted(set(JOB_KEYS) - set(res))
        if miss: raise Refused('compose.yaml: job image key(s) missing from the %s block: %s' % (JOB_BLOCK, ' '.join(miss)))
        return lines, res

    def jobs(self, text=None):
        text = open(self.compose).read() if text is None else text
        lines, res = self.job_lines(text)
        return {k: JOB_LINE_RE.match(lines[i]).group(2) for k, i in res.items()}

    def held_keys(self, text=None):
        text = open(self.compose).read() if text is None else text
        lines, res = self.job_lines(text)
        return sorted(k for k, i in res.items() if JOB_LINE_RE.match(lines[i]).group(3))

    def rejob(self, text, new, held=()):
        lines, res = self.job_lines(text)
        for k, ref in new.items():
            lines[res[k]] = '      %s: %s' % (k, ref)
        for k in held:
            m = JOB_LINE_RE.match(lines[res[k]])
            lines[res[k]] = '      %s: %s # held' % (k, m.group(2))
        return '\\n'.join(lines)

    def guard_hold(self, text=None):
        text = open(self.compose).read() if text is None else text
        hits = [l for l in text.split('\\n') if 'GUARD_HELD_ENV' in l.split('#', 1)[0]]
        if not hits: return None
        if len(hits) > 1 or not GUARD_LINE_RE.match(hits[0]): raise Refused('compose.yaml: GUARD_HELD_ENV must be one plain line')
        return GUARD_LINE_RE.match(hits[0]).group(1) or None

    def set_guard_hold(self, text, value):
        self.guard_hold(text)                                 # validates: at most one plain line
        lines = [l for l in text.split('\\n') if 'GUARD_HELD_ENV' not in l.split('#', 1)[0]]
        if value:
            _, res = self.job_lines('\\n'.join(lines))
            lines.insert(min(res.values()), '      GUARD_HELD_ENV: ' + value)
        return '\\n'.join(lines)

    def store_is_containerd(self):
        r = docker('info', '-f', '{{json .DriverStatus}}', timeout=60)
        return r.returncode == 0 and 'io.containerd.snapshotter' in r.stdout

    def resolved(self, text):
        """`docker compose config --format json` of TEXT (anchors and merge keys resolved by compose itself)."""
        tmp = os.path.join(self.dir, '.compose.rw-resolve.yaml')
        open(tmp, 'w').write(text)
        try:
            r = self.dc('config', '--format', 'json', files=[tmp], timeout=60)
            if r.returncode != 0: raise Refused('docker compose config --format json failed: ' + r.stderr.strip()[-300:])
            try: return json.loads(r.stdout)['services']
            except Exception: raise Refused('docker compose config --format json gave no services')
        finally:
            try: os.remove(tmp)
            except OSError: pass

    def job_ids_ok(self, refs):
        """Refs (job form) that do not resolve on this host to exactly their own digest."""
        ids = self.image_ids(sorted(set(refs)))
        return sorted(r for r in set(refs) if ids.get(r) != r.split('@', 1)[1])

    # ---- env files (format: raw, KEY=VALUE per line)''')

# ---- state: jobs + jobs_missing, outside the fp core
rep('''        return dict(core, fp=fp, running=run, missing=sorted(r for r, i in ids.items() if not i), allowed_env=self.allowed_env())''',
    '''        try:
            jobs = self.jobs(); jobs_held = self.held_keys(); guard_hold = self.guard_hold()
            jobs_missing = self.job_ids_ok([v for k, v in jobs.items() if k not in jobs_held])
        except Refused as e: jobs = {'error': str(e)}; jobs_held = []; jobs_missing = []; guard_hold = None
        # goodqa#16136: jobs and jobs_missing stay OUTSIDE the fp core (every fp recorded before them still matches) and
        # outside `missing` (rw-ship refuses a release while `missing` is non-empty: no rollback target).
        return dict(core, fp=fp, running=run, missing=sorted(r for r, i in ids.items() if not i), allowed_env=self.allowed_env(),
                    jobs=jobs, jobs_held=jobs_held, jobs_missing=jobs_missing, guard_hold=guard_hold)''')

# ---- pin: parse job args, store check, rejob, resolved presence check
rep('''def pin_prepare(stk, a):
    extra = parse_set_env(getattr(a, 'set_env', None))''', '''def parse_job_args(images, holds):
    """--job-image KEY=REF and --job-hold KEY -> ({key: ref}, {held keys}), or Refused. All four keys, each exactly once."""
    new, held = {}, set()
    for it in images or ():
        k, sep, v = it.partition('=')
        name = re.sub(r'[^A-Za-z0-9_]', '?', k)[:60]
        if not sep or k not in JOB_KEYS: raise Refused('--job-image %s is not a job image key (only %s)' % (name, ', '.join(sorted(JOB_KEYS))))
        if k in new: raise Refused('--job-image %s given more than once' % k)
        if not job_ref_ok(k, v): raise Refused('--job-image %s must be %s@sha256:<64 hex>' % (k, JOB_KEYS[k]))
        new[k] = v
    for k in holds or ():
        name = re.sub(r'[^A-Za-z0-9_]', '?', k)[:60]
        if k not in JOB_KEYS: raise Refused('--job-hold %s is not a job image key' % name)
        if k in held or k in new: raise Refused('--job-hold %s given more than once or also with --job-image' % k)
        held.add(k)
    left = sorted(set(JOB_KEYS) - set(new) - held)
    if left: raise Refused('every job image key needs --job-image or --job-hold; missing: ' + ' '.join(left))
    return new, held


def presence_check(stk, comp, held):
    """Every release-managed ref the RESOLVED prepared compose names must be on this host (exact string; a job ref by its
    own digest). Pulled third-party images only warn. Raises Refused; returns the warnings."""
    svcs = stk.resolved(comp)
    want_jobs = {k: v for k, v in stk.jobs(comp).items() if k not in held}
    for s in (JOB_BLOCK, 'job-dispatcher'):
        envs = (svcs.get(s) or {}).get('environment') or {}
        got = {k: envs.get(k) for k in want_jobs}
        if got != want_jobs: raise Refused('resolved compose: %s does not carry the pinned job images (%s)' % (s, got))
    managed = {(svcs.get(s) or {}).get('image') for s in SERVICES}
    bad = [r for r in managed if not r or not stk.image_ids([r])[r]]
    bad += stk.job_ids_ok(list(want_jobs.values()))
    if bad: raise Refused('image(s) not present on this host: ' + ' '.join(sorted(str(b) for b in bad)))
    warns = []
    for s, d in sorted(svcs.items()):
        r = (d or {}).get('image')
        if s not in SERVICES and r and not stk.image_ids([r])[r]: warns.append('WARN third-party image not present on this host: ' + r)
    return warns


def pin_prepare(stk, a):
    extra = parse_set_env(getattr(a, 'set_env', None))
    new_jobs, held = parse_job_args(getattr(a, 'job_image', None), getattr(a, 'job_hold', None))
    gh = list(getattr(a, 'guard_hold', None) or [])
    if len(gh) > 1 or (gh and gh[0] not in GUARD_HOLD_ALLOWED):
        raise Refused('--guard-hold may be given once, only as %s' % ' or '.join(GUARD_HOLD_ALLOWED))
    if new_jobs and not stk.store_is_containerd():
        raise Refused('the docker image store is not containerd: a loaded image would not resolve as repo@<image id> '
                      '(docker info DriverStatus has no io.containerd.snapshotter)')''')
rep('''    comp = stk.repin(old, new_pins, 'rw-ship %s %s' % (a.sha[:12], a.stamp))
    if stk.pins(comp) != new_pins: raise Refused('re-pin self-check failed')
    validate_compose(stk, comp)''', '''    comp = stk.repin(old, new_pins, 'rw-ship %s %s' % (a.sha[:12], a.stamp))
    if stk.pins(comp) != new_pins: raise Refused('re-pin self-check failed')
    before_jobs = stk.jobs(old)
    comp = stk.rejob(comp, new_jobs, held)
    comp = stk.set_guard_hold(comp, gh[0] if gh else None)
    want = dict(before_jobs, **new_jobs)
    if stk.jobs(comp) != want or stk.held_keys(comp) != sorted(held) or stk.guard_hold(comp) != (gh[0] if gh else None):
        raise Refused('job image re-pin self-check failed')
    validate_compose(stk, comp)
    for w in presence_check(stk, comp, held): out(w)''')

# ---- restore: warn, never check
rep('''    try:
        for f, b in zip(files, baks): write_like(f, open(b).read(), b)
    except Exception as e:
        raise RuntimeError('restore failed part way (%s)' % e)
    out(stk.state())''', '''    try:
        for f, b in zip(files, baks): write_like(f, open(b).read(), b)
    except Exception as e:
        raise RuntimeError('restore failed part way (%s)' % e)
    restore_warnings(stk)
    out(stk.state())


def restore_warnings(stk):
    """goodqa#16136: a rollback is never blocked, but it must say what it brought back that cannot run."""
    try:
        pins = stk.pins(); ids = stk.image_ids(sorted(set(pins.values())))
        core = sorted({r for r in pins.values() if not ids.get(r)})
        if core: out('WARN core image missing: ' + ' '.join(core) + ' (up runs with --pull never and will fail rather than pull)')
        try: hk = stk.held_keys(); down = stk.job_ids_ok([v for k, v in stk.jobs().items() if k not in hk])
        except Refused as e: down = ['(job image lines unreadable: %s)' % e]
        if down: out('WARN jobs down after rollback: ' + ' '.join(down))
    except Exception as e:
        out('WARN restore could not check images: %s: %s' % (type(e).__name__, e))''')

# ---- up never pulls
rep('''    r = stk.dc('up', '-d', '--no-deps', *SERVICES, timeout=a.timeout + 120)''',
    '''    r = stk.dc('up', '-d', '--no-deps', '--pull', 'never', *SERVICES, timeout=a.timeout + 120)''')

# ---- CLI
rep('''    pn.add_argument('--set-env', action='append', default=[], metavar='KEY=VALUE')''',
    '''    pn.add_argument('--set-env', action='append', default=[], metavar='KEY=VALUE')
    pn.add_argument('--job-image', action='append', default=[], metavar='KEY=REF')
    pn.add_argument('--job-hold', action='append', default=[], metavar='KEY')
    pn.add_argument('--guard-hold', action='append', default=[], metavar='KEY=VALUE')
    sub.add_parser('disk')''')
rep('''        if a.cmd == 'check-set-env': out({'set_env': parse_set_env(a.items)}); return 0''',
    '''        if a.cmd == 'check-set-env': out({'set_env': parse_set_env(a.items)}); return 0
        if a.cmd == 'disk':
            root = next((d for d in ('/var/lib/containerd', '/var/lib/docker') if os.path.isdir(d)), '/')
            out({'free_gb': shutil.disk_usage(root).free // (1 << 30), 'path': root}); return 0''')
rep("""  disk                           one JSON line {"free_gb": N}: free space where the docker store lives (before a load)
""", """  disk                           one JSON line {"free_gb": N}: free space where the docker store lives (before a load)
  guard-log                      one JSON line {"listening": bool, "held": VALUE|null}: what the running create-guard's own
                                 startup line says it enforces (goodqa#16136 D1: the hold is proven by the guard, not the file)
""")
rep("""        if a.cmd == 'disk':""", """        if a.cmd == 'guard-log':
            r = stk.dc('logs', '--no-color', '--no-log-prefix', '--tail', '200', JOB_BLOCK, timeout=60)
            ls = [l for l in r.stdout.split('\\n') if 'job-dispatcher-create-guard listening' in l]
            m = re.search(r'heldEnv=(\\S+)', ls[-1]) if ls else None
            held = m.group(1) if m and m.group(1) != 'none' else None
            out({'listening': bool(ls), 'held': held}); return 0
        if a.cmd == 'disk':""")
rep("""    sub.add_parser('disk')""", """    sub.add_parser('disk'); sub.add_parser('guard-log')""")
open(p, 'w').write(t)
print('patched ctl')
