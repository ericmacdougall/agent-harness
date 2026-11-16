"""goodqa#16148 spec v4 AC-11 (Sonnet v4 condition): on a fake VM, the job-dispatcher secrets mount and group_add that
the host apply put in compose.yaml survive the real selfhost-ctl.py `pin` (the next release) and its `restore`
(that release's rollback). The fence refuses the rollback of a release pinned before the apply, so it can never remove them.
Fake docker on PATH; fake files only; no network, secrets or containers.
Run: python3 -m pytest -q infra/release-harness/test_selfhost_ctl_job_secrets.py
"""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CTL = HERE / 'selfhost-ctl.py'
APP = ROOT / 'infra/selfhost/app'

spec = importlib.util.spec_from_file_location('apply_host', APP / 'apply-job-secrets-host.py')
ah = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ah)

FAKE_DOCKER = '''#!/bin/sh
echo "$*" >> "$FAKE_VM/docker.log"
if [ "$1" = image ] && [ "$2" = inspect ]; then printf 'sha256:%s\\n' "$(printf %s "$5" | sha256sum | cut -c1-64)"; exit 0; fi
exit 0
'''
SHA_A, SHA_B = 'a' * 40, 'b' * 40


def env_text(sha, dep):
    return 'KEEP=x\nRELEASE_SOURCE_SHA=%s\nRELEASE_DEPLOYMENT_ID=%s\n' % (sha, dep)


@pytest.fixture
def vm(tmp_path, monkeypatch):
    d, e, b = tmp_path / 'app', tmp_path / 'etc', tmp_path / 'bin'
    for p in (d, e, b):
        p.mkdir()
    (b / 'docker').write_text(FAKE_DOCKER)
    (b / 'docker').chmod(0o755)
    for s in ('api', 'web'):
        (e / (s + '.env')).write_text(env_text('0' * 40, 'dep-0'))
    monkeypatch.setenv('PATH', '%s:%s' % (b, os.environ['PATH']))
    monkeypatch.setenv('FAKE_VM', str(tmp_path))
    return d, e


def ctl(vm, *argv):
    d, e = vm
    r = subprocess.run([sys.executable, '-B', str(CTL), '--dir', str(d), '--env-dir', str(e), *argv],
                       capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout


def pin(vm, stamp, sha, tag):
    return ctl(vm, 'pin', '--stamp', stamp, '--sha', sha, '--deploy-id', 'dep-' + stamp,
               '--api', 'goodqa-api:' + tag, '--web', 'goodqa-web:' + tag, '--disp', 'goodqa-job-dispatcher:' + tag)


def marked(text):
    """The marked AC-11 lines, each checked to sit in the job-dispatcher block and nowhere else."""
    lines = text.split('\n')
    start = lines.index('  job-dispatcher:')
    end = next(i for i in range(start + 1, len(lines)) if lines[i] and not lines[i].startswith('    '))
    block = lines[start:end]
    return [l for l in (ah.GROUP_LINE, ah.VOL_LINE) if l in block and lines.count(l) == 1]


def compose(vm):
    return (vm[0] / 'compose.yaml').read_text()


def test_mount_survives_the_next_release_pin_and_its_rollback(vm):
    applied = (APP / 'compose.yaml').read_text()          # the checked-in file is what the host apply leaves
    assert marked(applied) == [ah.GROUP_LINE, ah.VOL_LINE]
    (vm[0] / 'compose.yaml').write_text(applied)
    rc, out = pin(vm, 'S1', SHA_A, 'aaaa-1')
    assert rc == 0, out
    after_pin = compose(vm)
    assert 'goodqa-job-dispatcher:aaaa-1 # rw-ship' in after_pin
    assert marked(after_pin) == [ah.GROUP_LINE, ah.VOL_LINE], 'pin dropped the AC-11 lines'
    assert ah.compose_restore(after_pin) != after_pin
    rc, out = pin(vm, 'S2', SHA_B, 'bbbb-2')
    assert rc == 0, out
    assert marked(compose(vm)) == [ah.GROUP_LINE, ah.VOL_LINE]
    rc, out = ctl(vm, 'restore', '--stamp', 'S2')       # release S2 rolled back to S1
    assert rc == 0, out
    assert compose(vm) == after_pin
    assert marked(compose(vm)) == [ah.GROUP_LINE, ah.VOL_LINE], 'rollback dropped the AC-11 lines'


def test_rollback_of_a_release_pinned_before_the_apply_is_refused_and_keeps_the_mount(vm):
    before = ah.compose_restore((APP / 'compose.yaml').read_text())
    assert marked(before) == []
    (vm[0] / 'compose.yaml').write_text(before)
    rc, out = pin(vm, 'S1', SHA_A, 'aaaa-1')
    assert rc == 0, out
    applied = ah.compose_apply(compose(vm))                # the host apply runs after release S1
    (vm[0] / 'compose.yaml').write_text(applied)
    rc, out = ctl(vm, 'restore', '--stamp', 'S1')
    assert rc == 3, out
    assert out.startswith('REFUSED') and 'a stale rollback is refused' in out, out
    assert compose(vm) == applied
    assert marked(compose(vm)) == [ah.GROUP_LINE, ah.VOL_LINE]
