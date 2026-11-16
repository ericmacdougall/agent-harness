#!/usr/bin/env python3
"""1377 v4 (receipt bugtracker-pr1377-gate-v3 F7, F8): failing-first tests. Run from the bugtracker repo root."""
import sys


def edit(path, old, new, count=1):
    t = open(path).read()
    n = t.count(old)
    if n != count:
        sys.exit('anchor %r in %s found %d times, want %d' % (old[:70], path, n, count))
    open(path, 'w').write(t.replace(old, new))


def append(path, text):
    t = open(path).read()
    if text.strip().split('\n')[0] in t: sys.exit('already applied: ' + path)
    open(path, 'w').write(t.rstrip('\n') + '\n\n\n' + text.lstrip('\n'))


# ---------------------------------------------------------------- F7: the sampler never passes on nothing
TS = 'infra/selfhost/app/test_cmdline_sampler.py'
edit(TS, '''    def test_runs_unprivileged_on_the_real_proc(self):
        r = subprocess.run([sys.executable, '-I', SCRIPT, '--container', CID, '--seconds', '0.2', '--expect-runs', '0'],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)['verdict'], 'PASS')
''', '''    def test_runs_unprivileged_on_the_real_proc(self):
        """Receipt bugtracker-pr1377-gate-v3 F7: the real /proc, a container nobody runs in, one run expected: never PASS."""
        r = subprocess.run([sys.executable, '-I', SCRIPT, '--container', CID, '--seconds', '0.2', '--expect-runs', '1'],
                           capture_output=True, text=True, timeout=30)
        out = json.loads(r.stdout)
        self.assertEqual((r.returncode, out['verdict'], out['runs_seen']), (1, 'NO_SAMPLE', 0), r.stderr)
        self.assertGreaterEqual(out['polls'], 1)

    def test_receipt_reproducer_zero_seconds_zero_runs_is_refused(self):
        """The receipt's case: --seconds 0 --expect-runs 0 with a valid id gave exit 0, PASS, polls 0, runs_seen 0."""
        r = subprocess.run([sys.executable, '-I', SCRIPT, '--container', CID, '--proc', self.proc, '--seconds', '0',
                            '--expect-runs', '0'], capture_output=True, text=True, timeout=30)
        out = json.loads(r.stdout)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotEqual(out['verdict'], 'PASS')

    def test_invalid_arguments_are_refused_before_sampling(self):
        self.add(['docker', 'run', '--env-file', '/x', 'img'])   # a run is there: only the arguments can refuse
        for args in (['--seconds', '0.3', '--expect-runs', '0'], ['--seconds', '0.3', '--expect-runs', '-1'],
                     ['--seconds', '0', '--expect-runs', '1'], ['--seconds', '-1', '--expect-runs', '1'],
                     ['--seconds', 'nan', '--expect-runs', '1'], ['--seconds', 'inf', '--expect-runs', '1'],
                     ['--seconds', '0.3', '--interval', '0', '--expect-runs', '1'],
                     ['--seconds', '0.3', '--interval', '-0.01', '--expect-runs', '1'],
                     ['--seconds', '0.3', '--interval', 'nan', '--expect-runs', '1'],
                     ['--seconds', '0.3', '--interval', '0.5', '--expect-runs', '1']):
            out, code = sampler.run(['--container', CID, '--proc', self.proc, *args])
            self.assertEqual((out['verdict'], code), ('FAIL', 2), args)
            self.assertIn('error', out, args)
            self.assertNotIn('runs', out, args)

    def test_pass_needs_every_expected_run_and_a_poll(self):
        self.add(['docker', 'run', '--env-file', '/x', 'img'])
        out, code = self.sample('--expect-runs', '2')
        self.assertEqual((out['verdict'], code, out['runs_seen']), ('NO_SAMPLE', 1, 1))
        out, code = self.sample('--expect-runs', '1')
        self.assertEqual((out['verdict'], code), ('PASS', 0))
        self.assertGreaterEqual(out['polls'], 1)
        self.assertGreaterEqual(out['runs_seen'], out['expect_runs'])

    def test_default_expect_runs_is_one(self):
        out, code = sampler.run(['--container', CID, '--proc', self.proc, '--seconds', '0.1', '--interval', '0.01'])
        self.assertEqual((out['verdict'], code, out['expect_runs']), ('NO_SAMPLE', 1, 1))
''')

# ---------------------------------------------------------------- F8: regenerating the env files keeps the key line
JSG = 'infra/release-harness/test_rw_ship_jobsecret_gate.py'
append(JSG, r'''
# ---------------------------------------------------------------- receipt bugtracker-pr1377-gate-v3 F8 (Medium)
# infra/selfhost/app/push-env.sh regenerates /etc/goodqa/dispatcher.env whole. It must emit the canonical JOB_ENVFILE
# line, or a regeneration silently removes the wiring and the next unholding release refuses at gate (b).
APP = os.path.join(sh.HERE, '..', 'selfhost', 'app')
PUSH_ENV = os.path.join(APP, 'push-env.sh')
FAKE_DOCTL = r"""#!/usr/bin/env python3
import json, sys
a = sys.argv[1:]
if a[:2] == ['apps', 'list']:
    print(json.dumps([{'id': 'api-1', 'spec': {'name': 'goodqa-phase-a-api'}}, {'id': 'web-1', 'spec': {'name': 'goodqa-phase-a-web'}}])); sys.exit(0)
if a[:2] == ['apps', 'get']:
    envs = [{'key': 'NODE_ENV', 'value': 'production', 'type': 'GENERAL'}, {'key': 'JWT_SECRET', 'type': 'SECRET'}]
    print(json.dumps([{'spec': {'services': [{'envs': envs}]}}])); sys.exit(0)
sys.exit(2)
"""
FAKE_GCLOUD = '#!/bin/sh\nfor a; do s=$a; case $a in --secret) n=1;; *) [ "${n:-}" = 1 ] && { v=$a; n=; };; esac; done\nprintf "fake-%s" "$v"\n'
FAKE_SSH = r"""#!/usr/bin/env python3
import os, sys
data = sys.stdin.buffer.read().split(b'\0')
out = os.environ['PUSH_OUT']
for name, body in zip(data[0::2], data[1::2]):
    open(os.path.join(out, name.decode()), 'wb').write(body)
print('fake ssh: %d file(s)' % (len(data) // 2))
"""


def push_env(tmp_path):
    b = tmp_path / 'push-bin'; o = tmp_path / 'push-out'; b.mkdir(); o.mkdir()
    for n, body in (('doctl', FAKE_DOCTL), ('gcloud', FAKE_GCLOUD), ('ssh', FAKE_SSH)):
        (b / n).write_text(body); os.chmod(b / n, 0o755)
    env = dict(os.environ, PATH='%s:%s' % (b, os.environ['PATH']), PUSH_OUT=str(o), ORIGIN='https://new-app.example.invalid',
               SSH_TARGET='fake-vm', DB_HOST='db.example.invalid', DEPLOY_ID='selfhost-test')
    r = subprocess.run(['bash', PUSH_ENV], env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    return {p.name: p.read_text() for p in o.iterdir()}


def test_regenerated_dispatcher_env_keeps_the_canonical_key_line_and_the_release_passes_gate_b(R, tmp_path):
    files = push_env(tmp_path)
    lines = files['dispatcher.env'].split('\n')
    assert lines.count(sh.JOBSECRET_KEY_LINE) == 1, 'push-env.sh must emit the canonical line exactly once'
    assert sum(1 for l in lines if 'INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY' in l) == 1
    # the installer replaces the whole file: the regenerated file is what the release reads
    p = os.path.join(R.envd, 'dispatcher.env'); open(p, 'w').write(files['dispatcher.env']); os.chmod(p, 0o600)
    sha = R.release('release/js-30'); rc, out = R.run('release/js-30', sha)
    assert 'gate (b) key lines in dispatcher.env: 1 (canonical 1)' in out, out
    assert rc == 0 and 'gate (c) dispatcher boot line: ok' in out, out


def test_the_canonical_key_line_has_one_source():
    """push-env.sh reads the line from apply-job-secrets-host.py; selfhost-ctl.py's gate (b) constant must equal it."""
    import ast
    tree = ast.parse(open(os.path.join(APP, 'apply-job-secrets-host.py')).read())
    consts = {}
    for n in tree.body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and getattr(n.targets[0], 'id', None) in ('ENV_KEY', 'ENV_LINE'):
            v = n.value
            consts[n.targets[0].id] = v.value if isinstance(v, ast.Constant) else consts['ENV_KEY'] + v.right.value
    ctl = open(sh.CTL).read()
    assert ("JOBSECRET_KEY_LINE = '%s'" % consts['ENV_LINE']) in ctl
    assert consts['ENV_LINE'] == sh.JOBSECRET_KEY_LINE
    assert 'apply-job-secrets-host.py' in open(PUSH_ENV).read(), 'push-env.sh takes the line from the host applier'


# Dispatcher keys the live VM carries (env-keys.json baseline) that push-env.sh does not produce: set by hand on the VM, so
# a regeneration drops them. Pinned here so a NEW gap fails; tracked as goodqa#16250.
PUSHENV_DISPATCHER_GAP = {'AI_DEFAULT_PROVIDER', 'AI_SPEND_GLOBAL_DAILY_MICROS', 'AI_SPEND_SDK_PRICES_JSON',
                          'GOOGLE_APPLICATION_CREDENTIALS_JSON', 'VERTEX_AI_LOCATION', 'VERTEX_AI_SUMMARY_MODEL'}


def test_dispatcher_env_keys_without_a_producer_are_exactly_the_known_gap(tmp_path):
    files = push_env(tmp_path)
    made = {l.split('=', 1)[0] for l in files['dispatcher.env'].split('\n') if l and not l.startswith('#') and '=' in l}
    want = set(json.load(open(os.path.join(APP, 'env-keys.json')))['dispatcher'])
    assert want - made == PUSHENV_DISPATCHER_GAP, sorted(want - made)
    assert made - want == set(), sorted(made - want)
''')
print('v4 tests applied')
