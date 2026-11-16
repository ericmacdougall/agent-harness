#!/usr/bin/env python3
"""PR 1377 (goodqa#16148) runtime qualification kit: the release controller and the job-secret path on a REAL docker
daemon, at one exact bugtracker commit. Owned hosts only (t2-dev); never a production host. Dummy keys only.

    python3 -I qual.py --head <40-hex sha> --repo <bugtracker git checkout> [--work DIR] [--python PY] [--floor GB]

See README.md. Every check in CHECKS is run or counted as FAIL; exit 0 only when all pass and cleanup is complete.
"""
import argparse, hashlib, json, os, re, secrets, shlex, signal, subprocess, sys, time

KIT = os.path.dirname(os.path.abspath(__file__))
CHECKS = [
    ('q0', 'REAL', 'host layout recorded: t2-dev docker info; prod layout inferred from provisioning code (ASSUMPTION)'),
    ('q1', 'REAL', 'real `docker compose config` resolves the ctl re-pin of the product compose.yaml for guard and dispatcher'),
    ('q2', 'REAL', 'ctl disk gate resolves the containerd root that really holds the loaded image (content blob present)'),
    ('q3', 'REAL', 'ctl image-ids resolves loaded refs to their real ids, job refs to their own digest, an unknown ref to none'),
    ('q4', 'REAL', 'ctl trial-boot of the head dispatcher image with a dummy key: ok; control: a non-dispatcher image: not ok'),
    ('q5', 'REAL', 'gate (b) envfile-key 1/1 on the canonical file; controls: line removed 0, a twin line 2 (canonical 1)'),
    ('q6', 'REAL', 'ctl pin + up-dispatcher on the real daemon; gate (c) disp-boot ok; create-guard listening'),
    ('q7', 'STAND-IN', 'job launched through real dispatcher, guard, proxy, daemon; stand-in worker sees the key (hash match); '
                       'dummy key never in dispatcher logs; sampler PASS with >=1 run, --env-file only'),
    ('q8', 'REAL', 'sampler controls: no launch gives NO_SAMPLE exit 1; --seconds 0 --expect-runs 0 refused exit 2'),
    ('q9a', 'REAL (ctl)', 'gate (c) fails after a switch: re-hold pin + up-dispatcher holds the worker; restore re-hold then '
                          'switch; up; state fp byte-equal to before, worker line byte-equal, gate (c) ok again'),
    ('q9b', 'REAL (ctl)', 'switch fails (dispatcher never ready) and the re-hold fails too: restore both; up; state fp '
                          'byte-equal to before, worker line byte-equal'),
    ('q10', 'REAL (ctl)', 'migrated branch without a database: switch, gate (c) fails, re-hold pin + up; the worker is held, '
                          'the switched release stays (fp differs from before), nothing restored'),
    ('qF', 'FIXTURE', 'rw-ship.sh exit 5 / exit 8 decisions (re-hold, rollback, forward-only after a migration): the named '
                      'js_rehold / migration tests of test_rw_ship_jobsecret_gate.py at this head'),
]
INTEL = 'JOB_IMAGE_INTELLIGENCE_WORKER'
JOB_REPOS = {'JOB_IMAGE_SCAN': 'goodqa-scan', 'JOB_IMAGE_TRANSCODE': 'goodqa-transcode', INTEL: 'goodqa-intelligence-worker',
             'JOB_IMAGE_SUGGEST_FIX_WORKER': 'goodqa-suggest-fix-worker'}
CANON = 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=/run/goodqa-secrets/github-app-private-key'
FQ = '[A-Za-z0-9._-]'


class Stop(Exception):
    pass


class Kit:
    def __init__(self, a):
        self.a = a
        self.head = a.head
        stamp = time.strftime('%Y%m%dt%H%M%S', time.gmtime()).lower()
        self.run = 'qual-%s-%s' % (a.head[:8], stamp)
        self.work = os.path.join(os.path.abspath(os.path.expanduser(a.work)), self.run)
        os.makedirs(self.work, mode=0o700)
        self.logp = os.path.join(self.work, 'qual.log')
        self.logf = open(self.logp, 'a')
        self.src = os.path.join(self.work, 'src')
        self.app = os.path.join(self.src, 'infra', 'selfhost', 'app')
        self.ctlpy = os.path.join(self.src, 'infra', 'release-harness', 'selfhost-ctl.py')
        self.env = os.path.join(self.work, 'env')
        self.sec = os.path.join(self.work, 'job-secrets')
        self.keyf = os.path.join(self.sec, 'github-app-private-key')
        self.results = {}
        self.made_tags = []          # image tags this run created
        self.made_pulls = []         # image refs this run pulled that were absent before
        self.job_cids = []           # job / client containers this run caused
        self.token = 'qual-dummy-token-' + secrets.token_hex(12)
        self.key = '-----BEGIN QUAL DUMMY KEY-----\\nQUALDUMMY%s\\n-----END QUAL DUMMY KEY-----' % secrets.token_hex(12)
        self.keyhash = hashlib.sha256(self.key.encode()).hexdigest()
        self.secret_strings = (self.token, self.key, self.key.split('\\n')[1])
        self.root_env = []           # DOCKER_CONFIG for root when the compose plugin is per-user on this host

    # ------------------------------------------------------------------ plumbing
    def log(self, msg):
        for s in self.secret_strings:
            msg = msg.replace(s, '<dummy-redacted>')
        line = '%s %s' % (time.strftime('%H:%M:%SZ', time.gmtime()), msg)
        print(line, flush=True); self.logf.write(line + '\n'); self.logf.flush()

    def sh(self, argv, timeout=600, input=None, cwd=None, env=None, quiet=False):
        if not quiet: self.log('$ ' + ' '.join(shlex.quote(x) for x in argv)[:400])
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input, cwd=cwd, env=env)
        except subprocess.TimeoutExpired:
            self.log('  timeout after %ss' % timeout)
            return subprocess.CompletedProcess(argv, 124, '', 'timeout')
        return r

    def docker(self, *a, timeout=300, quiet=False):
        return self.sh(['docker', *a], timeout=timeout, quiet=quiet)

    def ctl(self, *a, env_dir=None, timeout=600):
        r = self.sh(['sudo', '-n', 'env', *self.root_env, 'python3', '-I', self.ctlpy, '--dir', self.app, '--env-dir', env_dir or self.env,
                     '--project', self.run, *a], timeout=timeout)
        lines = (r.stdout or '').split('\n')
        js = next((l for l in lines if l.startswith('{')), None)
        try: j = json.loads(js) if js else None
        except ValueError: j = None
        tags = [l[:300] for l in lines if re.match(r'^(UP_|REFUSED|FAILED|WARN)', l)]
        self.log('  ctl %s rc=%d %s %s' % (a[0], r.returncode, ' | '.join(tags), (json.dumps(j, sort_keys=True)[:600] if j else '')))
        if r.returncode not in (0, 3, 5) and r.stderr: self.log('  stderr: ' + r.stderr.strip()[-400:])
        return r.returncode, j, lines

    def free_gb(self):
        r = self.sh(['df', '-Pk', '/'], quiet=True)
        return int(r.stdout.strip().split('\n')[-1].split()[3]) // (1 << 20)

    def floor(self, phase):
        f = self.free_gb()
        self.log('df before %s: %dG free on / (floor %dG)' % (phase, f, self.a.floor))
        if f < self.a.floor: raise Stop('free space %dG is under the %dG floor before %s' % (f, self.a.floor, phase))

    def record(self, cid, ok, why):
        self.results[cid] = (bool(ok), why)
        label = next(c[1] for c in CHECKS if c[0] == cid)
        self.log('CHECK %s %s [%s] %s' % (cid, 'PASS' if ok else 'FAIL', label, why))

    def check(self, cid, fn):
        try:
            ok, why = fn()
        except Stop: raise
        except Exception as e:
            ok, why = False, 'error %s: %s' % (type(e).__name__, str(e)[:300])
        self.record(cid, ok, why)
        return ok

    def iid(self, ref):
        r = self.docker('image', 'inspect', '-f', '{{.Id}}', ref, quiet=True)
        v = r.stdout.strip()
        return v if r.returncode == 0 and re.match(r'^sha256:[0-9a-f]{64}$', v) else None

    def state(self):
        rc, j, _ = self.ctl('state')
        if rc != 0 or not j: raise RuntimeError('ctl state unreadable rc=%d' % rc)
        return j

    def disp_boot(self, want_ok=True, tries=10):
        j = None
        for _ in range(tries):
            rc, j, _ = self.ctl('disp-boot')
            st = (j or {}).get('status')
            if (st == 'ok') == want_ok and st not in (None, 'missing', 'no-container', 'unreadable'): return j
            if not want_ok and st and st.startswith('error:'): return j
            time.sleep(3)
        return j

    def up_disp(self, timeout=120):
        rc, _, lines = self.ctl('up-dispatcher', '--timeout', str(timeout), timeout=timeout + 300)
        return rc, next((l for l in lines if l.startswith('UP_')), '')

    def key_put(self):
        """The dummy key file as derive-job-secrets.py lays it out; the value goes on stdin, never argv."""
        r =subprocess.run(['sudo', '-n', 'python3', '-I', '-c',
                            'import os,sys\nd,f=sys.argv[1:3]\nv=sys.stdin.read()\nos.makedirs(d,exist_ok=True); os.chown(d,0,0); os.chmod(d,0o711)\n'
                            'p=f+".new"\nfd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)\nos.write(fd,(v+"\\n").encode()); os.close(fd)\n'
                            'os.chown(p,0,64910); os.chmod(p,0o440); os.replace(p,f)', self.sec, self.keyf],
                           input=self.key, capture_output=True, text=True, timeout=60)
        self.log('dummy key file written root:64910 0440 in a root 0711 dir (rc=%d)' % r.returncode)
        if r.returncode != 0: raise RuntimeError('could not write the dummy key file')

    def key_remove(self):
        r = self.sh(['sudo', '-n', 'rm', '-f', '--', self.keyf])
        if r.returncode != 0: raise RuntimeError('could not remove the dummy key file')

    def pin(self, stamp, disp, held=False):
        args = ['pin', '--stamp', stamp, '--sha', self.head, '--deploy-id', 'qual-' + stamp, '--api', self.api_ref,
                '--web', self.web_ref, '--disp', disp]
        for k in JOB_REPOS:
            args += (['--job-hold', k] if held and k == INTEL else ['--job-image', '%s=%s' % (k, self.job_refs[k])])
        return self.ctl(*args)

    # ------------------------------------------------------------------ setup
    def preflight(self):
        self.log('run %s  head %s  work %s' % (self.run, self.head, self.work))
        self.log('log %s' % self.logp)
        if self.sh(['sudo', '-n', 'true'], quiet=True).returncode != 0: raise Stop('passwordless sudo is required (the ctl runs as root, as on the VM)')
        self.compose_for_root()
        if self.sh(['git', '-C', self.a.repo, 'cat-file', '-e', self.head + '^{commit}']).returncode != 0:
            raise Stop('commit %s is not in %s (fetch it first)' % (self.head, self.a.repo))
        for k in ('kit qual.py', 'kit qualify.sh', 'kit README.md', 'kit worker/Dockerfile', 'kit worker/check.mjs'):
            p = os.path.join(KIT, k.split(' ', 1)[1])
            self.log('sha256 %s %s' % (hashlib.sha256(open(p, 'rb').read()).hexdigest() if os.path.exists(p) else 'MISSING', k))
        self.snap = self.snapshot()
        self.floor('archive')
        os.makedirs(self.src)
        p1 = subprocess.Popen(['git', '-C', self.a.repo, 'archive', '--format=tar', self.head], stdout=subprocess.PIPE)
        p2 = subprocess.run(['tar', '-x', '-C', self.src], stdin=p1.stdout, capture_output=True, timeout=600)
        p1.stdout.close()
        if p1.wait() != 0 or p2.returncode != 0: raise Stop('git archive of %s failed' % self.head)
        for rel in ('infra/release-harness/selfhost-ctl.py', 'infra/release-harness/rw-ship.sh', 'infra/selfhost/app/cmdline-sampler.py',
                    'infra/selfhost/app/compose.yaml', 'apps/job-dispatcher/Dockerfile'):
            self.log('sha256 %s head:%s' % (hashlib.sha256(open(os.path.join(self.src, rel), 'rb').read()).hexdigest(), rel))

    def compose_for_root(self):
        """The ctl runs as root (as on the VM, where install-docker.sh installs docker-compose-plugin system-wide). If root's
        docker has no compose plugin here, give root this run's own DOCKER_CONFIG holding a link to the invoking user's plugin."""
        if self.sh(['sudo', '-n', 'docker', 'compose', 'version'], quiet=True).returncode == 0:
            self.log('root docker compose: system plugin'); return
        out = self.docker('info', '--format', '{{range .ClientInfo.Plugins}}{{.Name}} {{.Path}}{{println}}{{end}}', quiet=True).stdout
        path = next((l.split(' ', 1)[1].strip() for l in out.split('\n') if l.startswith('compose ')), None)
        if not path or not os.path.isfile(path): raise Stop('no docker compose plugin for root or for this user')
        d = os.path.join(self.work, 'dockercfg', 'cli-plugins'); os.makedirs(d, mode=0o700)
        os.symlink(path, os.path.join(d, 'docker-compose'))
        self.root_env = ['DOCKER_CONFIG=' + os.path.dirname(d)]
        v = self.sh(['sudo', '-n', 'env', *self.root_env, 'docker', 'compose', 'version'], quiet=True)
        if v.returncode != 0: raise Stop('root cannot run the compose plugin via DOCKER_CONFIG')
        self.log('HOST DEVIATION: root has no system compose plugin on this host; the ctl gets %s (%s) via DOCKER_CONFIG=%s. '
                 'Prod installs docker-compose-plugin system-wide (install-docker.sh).' % (path, v.stdout.strip(), os.path.dirname(d)))

    def snapshot(self):
        def ls(*a): return set(self.docker(*a, quiet=True).stdout.split())
        return {'containers': ls('ps', '-aq', '--no-trunc'),
                'images': ls('image', 'ls', '-a', '--no-trunc', '--format', '{{.Repository}}:{{.Tag}}@{{.ID}}'),
                'volumes': ls('volume', 'ls', '-q'), 'networks': ls('network', 'ls', '-q', '--no-trunc')}

    def build(self):
        self.floor('image builds')
        r = self.docker('image', 'inspect', 'node:22-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5', quiet=True)
        self.base_was_present = r.returncode == 0
        self.disp_a = 'goodqa-job-dispatcher:%s-a' % self.run
        r = self.docker('build', '-q', '-f', os.path.join(self.src, 'apps/job-dispatcher/Dockerfile'), '-t', self.disp_a, self.src, timeout=2400)
        self.log('  dispatcher build rc=%d %s' % (r.returncode, (r.stderr or '').strip()[-600:] if r.returncode else ''))
        if r.returncode != 0: raise Stop('the head dispatcher image did not build')
        self.made_tags.append(self.disp_a)
        if not self.base_was_present: self.made_pulls.append('node:22-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5')
        wtag = 'goodqa-intelligence-worker:%s' % self.run
        r = self.docker('build', '-q', '-t', wtag, os.path.join(KIT, 'worker'), timeout=1200)
        if r.returncode != 0: raise Stop('the stand-in worker image did not build: ' + (r.stderr or '')[-300:])
        self.made_tags.append(wtag)
        for t in ['goodqa-job-dispatcher:%s-b' % self.run, 'goodqa-job-dispatcher:%s-c' % self.run]:
            if self.docker('tag', self.disp_a, t).returncode != 0: raise Stop('docker tag failed')
            self.made_tags.append(t)
        others = ['goodqa-scan:%s' % self.run, 'goodqa-transcode:%s' % self.run, 'goodqa-suggest-fix-worker:%s' % self.run,
                  'goodqa-api:%s' % self.run, 'goodqa-web:%s' % self.run, 'goodqa-job-dispatcher:%s-bad' % self.run]
        for t in others:
            if self.docker('tag', wtag, t).returncode != 0: raise Stop('docker tag failed')
            self.made_tags.append(t)
        self.disp_id = self.iid(self.disp_a); self.worker_id = self.iid(wtag)
        if not self.disp_id or not self.worker_id: raise Stop('built image ids unreadable')
        self.disp_b, self.disp_c = 'goodqa-job-dispatcher:%s-b' % self.run, 'goodqa-job-dispatcher:%s-c' % self.run
        self.disp_bad = 'goodqa-job-dispatcher:%s-bad' % self.run
        self.api_ref, self.web_ref = 'goodqa-api:%s' % self.run, 'goodqa-web:%s' % self.run
        self.job_refs = {k: '%s@%s' % (repo, self.worker_id) for k, repo in JOB_REPOS.items()}
        self.log('images: dispatcher %s (head build), stand-in worker %s (api/web/scan/transcode/suggest-fix/bad-dispatcher are '
                 'tags of the stand-in; api and web are never started)' % (self.disp_id[:19], self.worker_id[:19]))
        comp = open(os.path.join(self.app, 'compose.yaml')).read()
        proxy = re.search(r'image:\s*(tecnativa/docker-socket-proxy@sha256:[0-9a-f]{64})', comp).group(1)
        if not self.iid(proxy):
            if self.docker('pull', '-q', proxy, timeout=900).returncode != 0: raise Stop('could not pull ' + proxy)
            self.made_pulls.append(proxy)
        self.proxy = proxy

    def stage(self):
        """The product compose.yaml from the archive with only its host paths moved into this run's directory."""
        os.makedirs(self.env, mode=0o700)
        cp = os.path.join(self.app, 'compose.yaml'); t = open(cp).read()
        new = t.replace('/etc/goodqa/job-secrets', self.sec).replace('/etc/goodqa/', self.env + '/')
        for a, b in zip(t.split('\n'), new.split('\n')):
            if a != b: self.log('compose path moved: %s  ->  %s' % (a.strip()[:120], b.strip()[:160]))
        open(cp, 'w').write(new)
        open(os.path.join(self.app, '.env'), 'w').write('SITE_ADDRESS=qual.invalid\n')
        for s in ('api', 'web'):
            open(os.path.join(self.env, s + '.env'), 'w').write('RELEASE_SOURCE_SHA=%s\nRELEASE_DEPLOYMENT_ID=qual-base\n' % ('0' * 40))
        self.write_disp_env(self.env, [CANON])
        self.key_put()

    def write_disp_env(self, d, extra):
        os.makedirs(d, mode=0o700, exist_ok=True)
        p = os.path.join(d, 'dispatcher.env')
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f: f.write('\n'.join(['# qual dummy', 'JOB_DISPATCH_TOKEN=' + self.token] + extra) + '\n')

    # ------------------------------------------------------------------ checks
    def q0(self):
        f = '{{json .ServerVersion}} {{json .Driver}} {{json .DriverStatus}} {{json .DockerRootDir}} {{json .Containerd}} {{json .CgroupDriver}}'
        r = self.docker('info', '-f', f, quiet=True)
        self.log('t2-dev docker info: ' + r.stdout.strip()[:600])
        try: dj = json.load(open('/etc/docker/daemon.json'))
        except Exception as e: dj = {'_unreadable': type(e).__name__}
        self.log('t2-dev /etc/docker/daemon.json keys: %s' % sorted(dj))
        unit = self.sh(['systemctl', 'show', '-p', 'ExecStart', 'containerd'], quiet=True).stdout.strip()
        self.log('t2-dev containerd unit: ' + re.sub(r'\s+', ' ', unit)[:300])
        inst = open(os.path.join(self.app, 'install-docker.sh')).read()
        m = re.search(r"daemon\.json <<'J'\n(.*?)\nJ", inst, re.S)
        prod = json.loads(m.group(1)) if m else None
        pk = re.search(r'apt-get install -yq ([^\n]+)', inst)
        self.log('prod layout inferred from provisioning code (ASSUMPTION): packages [%s]; daemon.json %s; no containerd-snapshotter '
                 'feature key and no "containerd" key, so containerd.io is the external system containerd. Whether the image store is '
                 'containerd depends on the Engine version at install (fresh installs of Engine 29 default to it); the ctl refuses '
                 'job pins on a classic store, so a classic prod fails closed, never silently.' % (pk.group(1) if pk else '?', json.dumps(prod)))
        if prod: self.log('daemon.json differences prod vs t2-dev: only-prod %s, only-t2-dev %s' % (sorted(set(prod) - set(dj)), sorted(set(dj) - set(prod))))
        return (r.returncode == 0 and prod is not None and 'io.containerd.snapshotter' in r.stdout,
                'docker info read (containerd image store on t2-dev); prod side from install-docker.sh only, labelled ASSUMPTION')

    def q1(self):
        env = dict(os.environ, RW_REAL_COMPOSE='1', PYTHONDONTWRITEBYTECODE='1')
        r = self.sh([self.a.python, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'test_rw_ship_selfhost.py', '-k',
                     'test_real_compose_resolves_anchor_for_both_services'], cwd=os.path.join(self.src, 'infra/release-harness'), env=env, timeout=600)
        tail = (r.stdout or '').strip().split('\n')[-1]
        return r.returncode == 0 and re.match(r'^1 passed', tail) is not None, 'pytest: ' + tail

    def q2(self):
        rc, j, _ = self.ctl('disk')
        paths = (j or {}).get('paths') or {}
        info = json.loads(self.docker('info', '-f', '{{json .DockerRootDir}}', quiet=True).stdout or 'null')
        ctd = [p for p in paths if p != info]
        if rc != 0 or info not in paths or len(ctd) != 1: return False, 'disk gate did not report docker root + one containerd root: %s' % paths
        blob = os.path.join(ctd[0], 'io.containerd.content.v1.content', 'blobs', 'sha256', self.disp_id.split(':', 1)[1])
        has = self.sh(['sudo', '-n', 'test', '-f', blob], quiet=True).returncode == 0
        ctl_free = (j or {}).get('free_gb')
        return has and isinstance(ctl_free, int), ('containerd root %s holds the head dispatcher image content blob (oracle: the store '
                                                   'itself, not the ctl): %s; free_gb %s' % (ctd[0], has, ctl_free))

    def q3(self):
        bogus = 'goodqa-intelligence-worker@sha256:' + '0' * 64
        refs = [self.disp_a, self.api_ref] + sorted(set(self.job_refs.values())) + [bogus]
        rc, j, _ = self.ctl('image-ids', *refs)
        j = j or {}
        bad = [r for r in [self.disp_a, self.api_ref] if j.get(r) != self.iid(r)]
        bad += [r for r in set(self.job_refs.values()) if j.get(r) != r.split('@', 1)[1]]
        if j.get(bogus) is not None: bad.append('bogus resolved')
        return rc == 0 and not bad, 'refs resolved %d/%d, unknown ref none: %s' % (len(refs) - 1 - len(bad), len(refs) - 1, bad or 'ok')

    def q4(self):
        ref = 'goodqa-job-dispatcher@' + self.disp_id
        rc, j, _ = self.ctl('trial-boot', '--image', ref, '--stamp', self.run + '-q4', timeout=300)
        ok1 = rc == 0 and (j or {}).get('status') == 'ok'
        bad = 'goodqa-job-dispatcher@' + self.worker_id
        rc2, j2, _ = self.ctl('trial-boot', '--image', bad, '--stamp', self.run + '-q4c', timeout=300)
        ok2 = rc2 != 0 and (j2 or {}).get('status') in ('fail', 'timeout')
        return ok1 and ok2, 'head image: %s rc=%d; control (stand-in under the dispatcher name): %s rc=%d' % (
            (j or {}).get('status'), rc, (j2 or {}).get('status'), rc2)

    def q5(self):
        rc, j, _ = self.ctl('envfile-key')
        e2, e3 = os.path.join(self.work, 'env-noline'), os.path.join(self.work, 'env-twin')
        for d in (e2, e3):
            os.makedirs(d, mode=0o700, exist_ok=True)
            for s in ('api', 'web'): open(os.path.join(d, s + '.env'), 'w').write(open(os.path.join(self.env, s + '.env')).read())
        self.write_disp_env(e2, [])
        self.write_disp_env(e3, [CANON, 'JOB_ENV_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=/run/goodqa-secrets/other'])
        _, j2, _ = self.ctl('envfile-key', env_dir=e2)
        _, j3, _ = self.ctl('envfile-key', env_dir=e3)
        got = [(x or {}).get('count') for x in (j, j2, j3)], [(x or {}).get('canonical') for x in (j, j2, j3)]
        return rc == 0 and got == ([1, 0, 2], [1, 0, 1]), 'count [canonical, removed, twin] = %s, canonical = %s' % got

    def q6(self):
        rc, j, _ = self.pin(self.run + '-p0', self.disp_a)
        if rc != 0 or not j: return False, 'base pin refused rc=%d' % rc
        r = self.sh(['docker', 'compose', '-p', self.run, '-f', os.path.join(self.app, 'compose.yaml'), 'up', '-d', '--no-deps',
                     '--pull', 'never', 'job-dispatcher-docker-proxy'], cwd=self.app, timeout=300)
        if r.returncode != 0: return False, 'proxy did not start: ' + r.stderr.strip()[-300:]
        urc, line = self.up_disp()
        db = self.disp_boot(True)
        _, g, _ = self.ctl('guard-log')
        st = self.state()
        self.fp0, self.intel0, self.disp_cid = st.get('fp'), (st.get('jobs') or {}).get(INTEL), (db or {}).get('id')
        self.log('base state fp %s, %s=%s' % (self.fp0, INTEL, self.intel0))
        ok = urc == 0 and (db or {}).get('status') == 'ok' and (g or {}).get('listening') is True and self.intel0 == self.job_refs[INTEL]
        return ok, 'pin fp %s; %s; gate (c) disp-boot %s; guard listening %s' % (j.get('fp'), line[:120], (db or {}).get('status'), (g or {}).get('listening'))

    def q7(self):
        if not getattr(self, 'disp_cid', None): return False, 'no running dispatcher (q6 failed)'
        sp = subprocess.Popen(['python3', '-I', os.path.join(self.app, 'cmdline-sampler.py'), '--container', self.disp_cid,
                               '--seconds', '25', '--expect-runs', '1', '--interval', '0.05'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(2)
        js = ("const r=await fetch('http://job-dispatcher:8080/jobs/intelligence-worker/run',{method:'POST',headers:{'content-type':"
              "'application/json',authorization:'Bearer '+process.env.QUAL_TOKEN},body:JSON.stringify({env:{WORKER_LEASE_OWNER:process.env.QUAL_HASH}})});"
              "console.log(r.status+' '+(await r.text()));")
        name = self.run + '-client'
        r = subprocess.run(['docker', 'run', '--rm', '--name', name, '--network', self.run + '_edge', '-e', 'QUAL_TOKEN', '-e', 'QUAL_HASH',
                            '--entrypoint', 'node', self.job_refs[INTEL], '--input-type=module', '-e', js],
                           env=dict(os.environ, QUAL_TOKEN=self.token, QUAL_HASH=self.keyhash), capture_output=True, text=True, timeout=180)
        out = (r.stdout or '').strip()
        self.log('  client: rc=%d %s' % (r.returncode, out[:300]))
        m = re.match(r'^200 (\{.*\})$', out.split('\n')[-1] if out else '')
        cid = json.loads(m.group(1)).get('containerId') if m else None
        wl = ''
        if cid and re.match(r'^[0-9a-f]{12,64}$', cid):
            self.job_cids.append(cid)
            for _ in range(10):
                wl = self.docker('logs', cid, quiet=True).stdout
                if 'QUAL_WORKER' in wl: break
                time.sleep(0.5)
        try: so, _ = sp.communicate(timeout=60)
        except subprocess.TimeoutExpired: sp.kill(); so = ''
        try: sj = json.loads(so.strip().split('\n')[-1])
        except Exception: sj = {}
        dl = self.docker('logs', self.disp_cid, quiet=True)
        leaked = any(s in (dl.stdout or '') + (dl.stderr or '') for s in self.secret_strings[1:])
        self.log('  sampler: verdict %s runs_seen %s polls %s with_env_file %s with_env_flag %s' % tuple(sj.get(k) for k in (
            'verdict', 'runs_seen', 'polls', 'runs_with_env_file', 'runs_with_env_flag')))
        ok = (cid is not None and 'QUAL_WORKER key=present match=yes' in wl and not leaked and sp.returncode == 0
              and sj.get('verdict') == 'PASS' and sj.get('runs_seen', 0) >= 1 and sj.get('runs_with_env_file', 0) >= 1 and sj.get('runs_with_env_flag') == 0)
        return ok, 'launch %s; worker: %s; dummy key in dispatcher logs: %s; sampler %s runs %s' % (
            'ok ' + cid[:12] if cid else 'FAILED', (wl.strip() or 'no output')[:60], leaked, sj.get('verdict'), sj.get('runs_seen'))

    def q8(self):
        if not getattr(self, 'disp_cid', None): return False, 'no running dispatcher (q6 failed)'
        s = os.path.join(self.app, 'cmdline-sampler.py')
        r1 = self.sh(['python3', '-I', s, '--container', self.disp_cid, '--seconds', '3', '--expect-runs', '1'], timeout=60)
        r2 = self.sh(['python3', '-I', s, '--container', self.disp_cid, '--seconds', '0', '--expect-runs', '0'], timeout=60)
        v1 = json.loads(r1.stdout or '{}').get('verdict'); v2 = json.loads(r2.stdout or '{}').get('verdict')
        return (r1.returncode, v1, r2.returncode, v2) == (1, 'NO_SAMPLE', 2, 'FAIL'), 'no launch: %s rc=%d; zero args: %s rc=%d' % (v1, r1.returncode, v2, r2.returncode)

    def back_to_base(self, steps):
        st = self.state()
        intel = (st.get('jobs') or {}).get(INTEL)
        steps.append('state fp %s (before %s), worker %s' % (st.get('fp'), self.fp0, 'same' if intel == self.intel0 else intel))
        return st.get('fp') == self.fp0 and intel == self.intel0 and not st.get('jobs_held')

    def q9a(self):
        if not getattr(self, 'fp0', None): return False, 'no base state (q6 failed)'
        s, steps = self.run + '-s1', []
        rc, j, _ = self.pin(s, self.disp_b); steps.append('switch pin rc=%d' % rc)
        self.key_remove()
        urc, line = self.up_disp(); steps.append('up %s' % line[:40])
        db = self.disp_boot(False); steps.append('gate (c) %s' % (db or {}).get('status'))
        rc2, j2, _ = self.pin(s + 'h', self.disp_b, held=True); steps.append('re-hold pin rc=%d' % rc2)
        urc2, line2 = self.up_disp(); steps.append('re-hold up %s' % line2[:40])
        held = INTEL in ((self.state().get('jobs_held')) or [])
        steps.append('worker held %s' % held)
        r1, _, _ = self.ctl('restore', '--stamp', s + 'h'); r2, _, _ = self.ctl('restore', '--stamp', s)
        steps.append('restore re-hold rc=%d, switch rc=%d' % (r1, r2))
        self.key_put()
        urc3, line3 = self.up_disp(); db2 = self.disp_boot(True)
        base = self.back_to_base(steps); steps.append('gate (c) after %s' % (db2 or {}).get('status'))
        if db2 and db2.get('id'): self.disp_cid = db2['id']
        ok = (rc, urc, rc2, urc2, r1, r2, urc3) == (0, 0, 0, 0, 0, 0, 0) and (db or {}).get('status', '').startswith('error:') \
            and held and base and (db2 or {}).get('status') == 'ok'
        return ok, '; '.join(steps)

    def q9b(self):
        if not getattr(self, 'fp0', None): return False, 'no base state (q6 failed)'
        s, steps = self.run + '-s2', []
        rc, _, _ = self.pin(s, self.disp_bad); steps.append('switch pin (dispatcher that never starts) rc=%d' % rc)
        urc, line = self.up_disp(30); steps.append('up %s' % line[:60])
        rc2, _, _ = self.pin(s + 'h', self.disp_bad, held=True); steps.append('re-hold pin rc=%d' % rc2)
        urc2, line2 = self.up_disp(30); steps.append('re-hold up %s' % line2[:60])
        r1, _, _ = self.ctl('restore', '--stamp', s + 'h'); r2, _, _ = self.ctl('restore', '--stamp', s)
        steps.append('restore re-hold rc=%d, switch rc=%d' % (r1, r2))
        urc3, line3 = self.up_disp(); db2 = self.disp_boot(True)
        base = self.back_to_base(steps); steps.append('gate (c) after %s' % (db2 or {}).get('status'))
        if db2 and db2.get('id'): self.disp_cid = db2['id']
        ok = (rc, urc, rc2, urc2, r1, r2, urc3) == (0, 5, 0, 5, 0, 0, 0) and base and (db2 or {}).get('status') == 'ok'
        return ok, '; '.join(steps)

    def q10(self):
        if not getattr(self, 'fp0', None): return False, 'no base state (q6 failed)'
        s, steps = self.run + '-s3', []
        rc, _, _ = self.pin(s, self.disp_c); steps.append('switch pin rc=%d' % rc)
        self.key_remove()
        urc, line = self.up_disp(); steps.append('up %s' % line[:40])
        db = self.disp_boot(False); steps.append('gate (c) %s' % (db or {}).get('status'))
        rc2, _, _ = self.pin(s + 'h', self.disp_c, held=True); steps.append('re-hold pin rc=%d' % rc2)
        urc2, line2 = self.up_disp(); steps.append('re-hold up %s' % line2[:40])
        st = self.state()
        held = INTEL in (st.get('jobs_held') or [])
        stays = (st.get('pins') or {}).get('job-dispatcher') == self.disp_c and st.get('fp') != self.fp0
        cp = os.path.join(self.app, 'compose.yaml')
        not_restored = os.path.exists(cp + '.pre-rw-' + s) and open(cp).read() != open(cp + '.pre-rw-' + s).read()
        steps.append('worker held %s; switched release stays %s (fp %s vs before %s); not restored %s' % (held, stays, st.get('fp'), self.fp0, not_restored))
        ok = (rc, urc, rc2, urc2) == (0, 0, 0, 0) and (db or {}).get('status', '').startswith('error:') and held and stays and not_restored
        return ok, '; '.join(steps)

    def qF(self):
        k = ('gate_c_failure or rehold_failure or after_a_migration or rollback_restore_failure or reholds')
        r = self.sh([self.a.python, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'test_rw_ship_jobsecret_gate.py', '-k', k],
                    cwd=os.path.join(self.src, 'infra/release-harness'), env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), timeout=1800)
        tail = (r.stdout or '').strip().split('\n')[-1]
        m = re.match(r'^(\d+) passed', tail)
        return r.returncode == 0 and m is not None and int(m.group(1)) >= 9 and 'failed' not in tail, 'pytest -k "%s": %s' % (k, tail)

    # ------------------------------------------------------------------ cleanup
    def cleanup(self):
        left = []
        self.log('cleanup: only what this run created')
        cp = os.path.join(self.app, 'compose.yaml')
        if os.path.exists(cp):
            r = self.sh(['docker', 'compose', '-p', self.run, '-f', cp, 'down', '--volumes', '--remove-orphans', '--timeout', '10'], cwd=self.app, timeout=300)
            if r.returncode != 0: left.append('compose down rc=%d' % r.returncode)
        mine = set(self.docker('ps', '-aq', '--no-trunc', '--filter', 'label=com.docker.compose.project=' + self.run, quiet=True).stdout.split())
        ours_img = {self.iid(t) for t in self.made_tags} - {None}
        for c in set(self.docker('ps', '-aq', '--no-trunc', quiet=True).stdout.split()) - self.snap['containers']:
            r = self.docker('inspect', '-f', '{{.Image}} {{.Name}}', c, quiet=True).stdout.split()
            if c in mine or (r and (r[0] in ours_img or r[1].lstrip('/').startswith((self.run, 'goodqa-trial-' + self.run)))):
                mine.add(c)
        for c in sorted(mine | set(self.job_cids)):
            if self.docker('rm', '-f', c, quiet=True).returncode != 0 and self.docker('inspect', c, quiet=True).returncode == 0: left.append('container ' + c[:12])
        for n in self.docker('network', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + self.run, quiet=True).stdout.split():
            if self.docker('network', 'rm', n, quiet=True).returncode != 0: left.append('network ' + n)
        for v in self.docker('volume', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + self.run, quiet=True).stdout.split():
            if self.docker('volume', 'rm', v, quiet=True).returncode != 0: left.append('volume ' + v)
        for t in self.made_tags + self.made_pulls:
            if self.iid(t) and self.docker('image', 'rm', t, quiet=True).returncode != 0: left.append('image ' + t)
        real = os.path.realpath(self.work)
        for d in ('src', 'env', 'env-noline', 'env-twin', 'job-secrets', 'dockercfg'):
            p = os.path.realpath(os.path.join(self.work, d))
            if p.startswith(real + '/') and '/qual-' in p and os.path.lexists(p):
                if self.sh(['sudo', '-n', 'rm', '-rf', '--one-file-system', '--', p], quiet=True).returncode != 0 or os.path.lexists(p): left.append('dir ' + p)
        after = self.snapshot()
        self.log('docker objects added since the start and still present (other users of this host included): containers %d, '
                 'volumes %d, networks %d' % (len(after['containers'] - self.snap['containers']), len(after['volumes'] - self.snap['volumes']),
                                             len(after['networks'] - self.snap['networks'])))
        self.log('not removed by design: BuildKit build cache entries from the two builds (shared cache; no prune is run)')
        return left


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--head', required=True); p.add_argument('--repo', required=True)
    p.add_argument('--work', default='~/qual-runs'); p.add_argument('--python', default='python3')
    p.add_argument('--floor', type=int, default=28)
    a = p.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', a.head): sys.exit('--head must be a full 40-hex commit sha')
    k = Kit(a)
    stop = []
    def on_signal(sig, _f): raise Stop('signal %d' % sig)
    signal.signal(signal.SIGTERM, on_signal); signal.signal(signal.SIGINT, on_signal)
    left = None
    try:
        k.preflight(); k.build(); k.stage()
        for cid, _, _ in CHECKS:
            k.floor(cid)
            k.check(cid, getattr(k, cid))
    except Stop as e:
        stop.append(str(e)); k.log('STOP: %s' % e)
    except Exception as e:
        stop.append('%s: %s' % (type(e).__name__, e)); k.log('STOP (error): %s: %s' % (type(e).__name__, str(e)[:400]))
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN); signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try: left = k.cleanup()
        except Exception as e: left = ['cleanup error %s: %s' % (type(e).__name__, e)]
    for cid, label, what in CHECKS:
        if cid not in k.results: k.results[cid] = (False, 'not run' + (' (%s)' % stop[0] if stop else ''))
    passed = sum(1 for v in k.results.values() if v[0])
    k.log('SUMMARY')
    for cid, label, what in CHECKS:
        ok, why = k.results[cid]
        k.log('  %-4s %-4s %-10s %s' % (cid, 'PASS' if ok else 'FAIL', label, what))
    k.log('CLEANUP %s' % ('complete' if not left else 'INCOMPLETE: ' + '; '.join(left)))
    verdict = 'PASS' if passed == len(CHECKS) and not left and not stop else 'FAIL'
    k.log('QUAL RESULT %s %d/%d head=%s run=%s log=%s' % (verdict, passed, len(CHECKS), a.head, k.run, k.logp))
    json.dump({'verdict': verdict, 'passed': passed, 'total': len(CHECKS), 'head': a.head, 'run': k.run, 'stop': stop, 'cleanup_left': left,
               'checks': {c: {'pass': k.results[c][0], 'label': l, 'proves': w, 'detail': k.results[c][1]} for c, l, w in CHECKS}},
              open(os.path.join(k.work, 'summary.json'), 'w'), indent=1, sort_keys=True)
    return 0 if verdict == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
