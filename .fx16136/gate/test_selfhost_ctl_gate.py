"""goodqa#16148 spec v4 AC-8 (P3, P4) and the lead's gate rulings: the selfhost-ctl verbs envfile-key, disp-boot,
trial-boot and up-dispatcher. A python fake docker on PATH; fake values only; no network, socket or containers.
Run: python3 -m pytest -q infra/release-harness/test_selfhost_ctl_gate.py
"""
import argparse
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
CTL = HERE / 'selfhost-ctl.py'
spec = importlib.util.spec_from_file_location('selfhost_ctl', CTL)
ctl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ctl)

KEYLINE = 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=/run/goodqa-secrets/github-app-private-key'
OK = 'job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok'
PLANT = 'FAKEgateLOGmarkerQWERTYuiopZXCVbnmXYZ'  # no digit runs (timestamps hold digits)
CID = 'c0ffee' * 10 + 'abcd'
IMG = 'goodqa-job-dispatcher@sha256:' + 'd' * 64
# The trial hardening flags, written out here (not imported), so dropping one in selfhost-ctl.py fails a test.
REQUIRED_TRIAL_FLAGS = [('--rm',), ('--network', 'none'), ('--read-only',), ('--cap-drop', 'ALL'),
                        ('--security-opt', 'no-new-privileges'), ('--user', 'node'), ('--pids-limit', '64'),
                        ('--memory', '256m'), ('--group-add', '64910'), ('--tmpfs', '/tmp')]

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys, time
F = os.environ['FAKE_D']; a = sys.argv[1:]
def rd(n, d=''):
    p = os.path.join(F, n); return open(p).read() if os.path.exists(p) else d
open(os.path.join(F, 'calls.jsonl'), 'a').write(json.dumps(a) + '\n')
if a[:2] == ['image', 'inspect']:
    r = a[-1]; print(r.split('@', 1)[1] if '@' in r else 'sha256:' + '0' * 64); sys.exit(0)
if a[:1] == ['ps']: print(rd('ps.txt')); sys.exit(0)
if a[:1] == ['inspect']: print(rd('started.txt', '2026-11-16T04:00:00.123456789Z')); sys.exit(0)
if a[:1] == ['logs']: sys.stdout.write(rd('logs.txt')); sys.exit(int(rd('logs-rc', '0') or 0))
if a[:1] == ['run']:
    name = a[a.index('--name') + 1]
    live = set(rd('live.txt').split()); live.add(name); open(os.path.join(F, 'live.txt'), 'w').write('\n'.join(live))
    d = [x.split(':')[0] for x in a if x.endswith(':/run/goodqa-secrets:ro')][0]
    open(os.path.join(F, 'seen-value'), 'w').write(open(os.path.join(d, 'github-app-private-key')).read())
    mode = rd('run-mode', 'ok').strip()
    if mode == 'hang': time.sleep(30)
    print('PLANT-' + os.environ.get('PLANT', '')); print('job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok' if mode == 'ok' else 'job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: missing')
    if '--rm' in a:
        live.discard(name); open(os.path.join(F, 'live.txt'), 'w').write('\n'.join(live))
    sys.exit(0 if mode == 'ok' else 1)
if a[:2] == ['rm', '-f']:
    live = set(rd('live.txt').split()); live.discard(a[2]); open(os.path.join(F, 'live.txt'), 'w').write('\n'.join(live)); sys.exit(0)
sys.exit(0)
'''


@pytest.fixture
def fake(tmp_path, monkeypatch):
    b, d, e = tmp_path / 'bin', tmp_path / 'app', tmp_path / 'etc'
    for p in (b, d, e):
        p.mkdir()
    (b / 'docker').write_text(FAKE_DOCKER)
    (b / 'docker').chmod(0o755)
    monkeypatch.setenv('PATH', '%s:%s' % (b, os.environ['PATH']))
    monkeypatch.setenv('FAKE_D', str(tmp_path))
    monkeypatch.setenv('PLANT', PLANT)
    return tmp_path


def calls(fake):
    p = fake / 'calls.jsonl'
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def cli(fake, *argv):
    r = subprocess.run([sys.executable, '-B', str(CTL), '--dir', str(fake / 'app'), '--env-dir', str(fake / 'etc'), *argv],
                       capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout, r.stderr


# ---- (b) envfile-key ----
def test_envfile_key_counts_only_the_exact_line(fake):
    (fake / 'etc/dispatcher.env').write_text('\n'.join([
        'JOB_DISPATCH_TOKEN=' + PLANT, KEYLINE, '# ' + KEYLINE, KEYLINE + ' ', KEYLINE.replace('goodqa-secrets', 'x'), '']))
    rc, out, err = cli(fake, 'envfile-key')
    assert (rc, json.loads(out)) == (0, {'count': 1})
    assert PLANT not in out + err
    (fake / 'etc/dispatcher.env').write_text('A=1\n')
    assert json.loads(cli(fake, 'envfile-key')[1]) == {'count': 0}


def test_envfile_key_refuses_a_symlink(fake):
    (fake / 'real.env').write_text(KEYLINE + '\n')
    os.symlink(fake / 'real.env', fake / 'etc/dispatcher.env')
    rc, out, _ = cli(fake, 'envfile-key')
    assert rc == 4 and out.startswith('FAILED OSError'), out


# ---- (c) disp-boot ----
def pino(msg):
    return json.dumps({'level': 30, 'time': 1, 'pid': 7, 'hostname': 'vm', 'msg': msg})


@pytest.mark.parametrize('lines,status', [
    ([pino('job-dispatcher: swept stale env-file dirs'), pino(OK)], 'ok'),
    ([pino('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: missing')], 'error:missing-file'),
    ([pino('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: is a symlink')], 'error:symlink'),
    ([pino('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ' + PLANT)], 'error:other'),
    ([pino('job env file key ignored (not allow-listed): JOB_ENVFILE_SCAN__X')], 'missing'),
    ([OK], 'missing'),                                           # a plain (non-pino) line is not the dispatcher's log line
    ([pino('x ' + OK)], 'missing'), ([pino(OK + ' ')], 'missing'),
    ([], 'missing'),
])
def test_disp_status_matches_the_exact_line_only(lines, status):
    assert ctl.disp_status('\n'.join(lines)) == status


def test_disp_boot_reads_only_this_container_bounded_and_leaks_nothing(fake):
    (fake / 'ps.txt').write_text(CID + '\n')
    (fake / 'logs.txt').write_text('\n'.join([pino('JOB_DISPATCH_TOKEN=' + PLANT), pino(PLANT), pino(OK), PLANT]) + '\n')
    rc, out, err = cli(fake, 'disp-boot')
    res = json.loads(out)
    assert rc == 0 and res == {'id': CID, 'started': '2026-11-16T04:00:00.123456789Z', 'status': 'ok'}
    for i in range(len(PLANT) - 7):
        assert PLANT[i:i + 8] not in out + err
    logs = [c for c in calls(fake) if c[:1] == ['logs']]
    assert logs == [['logs', '--since', '2026-11-16T04:00:00.123456789Z', '--tail', '2000', CID]]
    ps = [c for c in calls(fake) if c[:1] == ['ps']][0]
    assert 'label=com.docker.compose.service=job-dispatcher' in ps and 'status=running' in ps
    assert not list(fake.rglob('*.log')), 'no log copy is kept'


@pytest.mark.parametrize('ps,status', [('', 'no-container'), (CID + '\n' + 'ab' * 32 + '\n', 'ambiguous')])
def test_disp_boot_without_exactly_one_container(fake, ps, status):
    (fake / 'ps.txt').write_text(ps)
    assert json.loads(cli(fake, 'disp-boot')[1]) == {'id': None, 'started': None, 'status': status}
    assert not [c for c in calls(fake) if c[:1] == ['logs']]


def test_disp_boot_unreadable_log_is_not_ok(fake):
    (fake / 'ps.txt').write_text(CID)
    (fake / 'logs.txt').write_text(pino(OK))
    (fake / 'logs-rc').write_text('1')
    assert json.loads(cli(fake, 'disp-boot')[1])['status'] == 'unreadable'


# ---- P3 trial-boot ----
def trial(fake, monkeypatch, capsys, image=IMG, stamp='S1', timeout=None):
    monkeypatch.setattr(ctl.os, 'chown', lambda *a, **k: None)          # the VM runs this as root; the test does not
    if timeout is not None:
        monkeypatch.setattr(ctl, 'TRIAL_TIMEOUT', timeout)
    stk = ctl.Stack(str(fake / 'app'), str(fake / 'etc'), 'goodqa')
    code = ctl.cmd_trial_boot(stk, argparse.Namespace(image=image, stamp=stamp))
    text = capsys.readouterr().out
    return code, json.loads(text.strip().splitlines()[-1]), text


def run_argv(fake):
    return [c for c in calls(fake) if c[:1] == ['run']]


def test_trial_boot_ok_is_isolated_and_hardened(fake, monkeypatch, capsys):
    code, res, text = trial(fake, monkeypatch, capsys)
    assert (code, res) == (0, {'status': 'ok', 'rc': 0})
    [argv] = run_argv(fake)
    for flag in REQUIRED_TRIAL_FLAGS:
        i = argv.index(flag[0])
        assert tuple(argv[i:i + len(flag)]) == flag, flag
    assert argv[argv.index('--entrypoint') + 2:] == [IMG, 'src/index.ts', '--boot-check'], 'the exact digest, never a tag'
    joined = ' '.join(argv)
    assert 'docker.sock' not in joined and '--env-file' not in joined and '--privileged' not in joined
    assert '--network host' not in joined and not any(x.startswith('--env-file') for x in argv)
    assert (fake / 'seen-value').read_text() == ctl.TRIAL_MARKER + '\n', 'a fixed fake marker only'
    assert 'PLANT-' not in text and PLANT not in text, 'the container output is never printed'
    assert ['rm', '-f', 'goodqa-trial-S1'] in calls(fake)
    assert not [p for p in Path('/tmp').glob('goodqa-trial-*') if p.stat().st_uid == os.getuid() and (p / 'github-app-private-key').exists()]


def test_trial_boot_fail_line_is_fail(fake, monkeypatch, capsys):
    (fake / 'run-mode').write_text('fail')
    code, res, _ = trial(fake, monkeypatch, capsys)
    assert (code, res) == (5, {'status': 'fail', 'rc': 1})


def test_trial_boot_timeout_removes_the_container(fake, monkeypatch, capsys):
    (fake / 'run-mode').write_text('hang')
    code, res, _ = trial(fake, monkeypatch, capsys, timeout=1)
    assert (code, res) == (5, {'status': 'timeout', 'rc': None})
    assert ['rm', '-f', 'goodqa-trial-S1'] in calls(fake)
    assert (fake / 'live.txt').read_text().split() == [], 'no goodqa-trial-* container is left'


@pytest.mark.parametrize('image,stamp', [('goodqa-job-dispatcher:abc-1', 'S1'), ('evil@sha256:' + 'd' * 64, 'S1'),
                                         (IMG, 'bad stamp'), (IMG, '')])
def test_trial_boot_refuses_a_tag_or_bad_input(fake, monkeypatch, capsys, image, stamp):
    code, res, _ = trial(fake, monkeypatch, capsys, image=image, stamp=stamp)
    assert (code, res['status']) == (3, 'refused')
    assert not run_argv(fake)


# ---- P4 up-dispatcher ----
def test_up_dispatcher_recreates_only_the_dispatcher_and_guard(fake):
    (fake / 'app/compose.yaml').write_text('services:\n')
    cli(fake, 'up-dispatcher', '--timeout', '1', '--every', '0.1')
    ups = [c for c in calls(fake) if c[:1] == ['compose'] and 'up' in c]
    assert len(ups) == 1
    assert ups[0][ups[0].index('up'):] == ['up', '-d', '--no-deps', '--pull', 'never', 'job-dispatcher', 'job-dispatcher-create-guard']
