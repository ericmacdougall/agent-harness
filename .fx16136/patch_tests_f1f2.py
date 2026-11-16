"""goodqa#16136 review F1 + F2 tests. python3 patch_tests_f1f2.py test_rw_ship_selfhost.py
Fixture: a fake `containerd` (config dump root under FAKE_STATE), a fake `df` that answers for VM-side paths from
FAKE_STATE/vmdf-<name> (else the real df), and image sizes from the fake docker (FAKE_STATE/image-size, default 1 MiB)."""
import sys
p = sys.argv[1]; t = open(p).read()


def rep(old, new):
    global t
    assert t.count(old) == 1, (t.count(old), old[:90]); t = t.replace(old, new)


rep('''if a[:2] == ['image', 'inspect']:
    i = resolve(a[-1])''', '''if a[:2] == ['image', 'inspect'] and '{{.Size}}' in a:          # goodqa#16136 F2: bytes the run will load
    if not resolve(a[-1]) or mark('size-unreadable'): sys.exit(1)
    print(markv('image-size') if mark('image-size') else 1 << 20); sys.exit(0)
if a[:2] == ['image', 'inspect']:
    i = resolve(a[-1])''')

rep('''        open(os.path.join(b, 'bin', 'selfhost-ctl.py'), 'w').write(open(CTL).read())
''', '''        open(os.path.join(b, 'bin', 'selfhost-ctl.py'), 'w').write(open(CTL).read())
        for path, body in ((os.path.join(b, 'stub', 'containerd'), CONTAINERD), (os.path.join(b, 'stub', 'df'), VMDF)):
            open(path, 'w').write(body); os.chmod(path, 0o755)
''')

rep('''class SRoot(base.Root):''', '''CONTAINERD = r\'\'\'#!/usr/bin/env bash
# fake containerd: `config dump` reports a root under the fixture (goodqa#16136 F2)
[ "$*" = "config dump" ] || exit 2
[ -e "$FAKE_STATE/containerd-fail" ] && exit 1
[ -e "$FAKE_STATE/containerd-noroot" ] && { echo "version = 2"; exit 0; }
printf "version = 2\\nroot = '%s'\\nstate = '/run/containerd'\\n" "$FAKE_STATE/containerd-root"
\'\'\'

VMDF = r\'\'\'#!/usr/bin/env bash
# fake df for the VM side only: FAKE_STATE/vmdf-docker or vmdf-containerd = free KiB, or "fail"; otherwise the real df
if [ "${FAKE_SIDE:-}" = remote ] && [ "$1" = -Pk ]; then
  case "$2" in "$FAKE_STATE") n=docker;; "$FAKE_STATE/containerd-root") n=containerd;; *) n="";; esac
  if [ -n "$n" ]; then
    v=104857600; [ -e "$FAKE_STATE/vmdf-$n" ] && v=$(cat "$FAKE_STATE/vmdf-$n")
    [ "$v" = fail ] && exit 1
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\nfixture-%s 209715200 1 %s 1%% /%s\\n' "$n" "$v" "$n"; exit 0
  fi
fi
for d in $(printf '%s' "$PATH" | tr ':' ' '); do [ "$d/df" != "$0" ] && [ -x "$d/df" ] && [ "$(cd "$d" && pwd)" != "$(cd "$(dirname "$0")" && pwd)" ] && exec "$d/df" "$@"; done
exit 127
\'\'\'


class SRoot(base.Root):''')

t = t.rstrip('\n') + '''


# ---- goodqa#16136 review F1: one canonical SELFHOST_JOB_HOLD; an accepted value never releases a kind it names
@pytest.mark.parametrize('value', ['intelligence-worker, transcribe', 'intelligence-worker transcribe', 'intelligence-worker\\ttranscribe',
                                   'transcribe,', ',transcribe', 'transcribe,,intelligence-worker', ' none', 'none ', 'transcribe ', ','],
                         ids=['comma-space', 'space', 'tab', 'trailing-comma', 'leading-comma', 'empty-item', 'space-none', 'none-space',
                              'trailing-space', 'only-comma'])
def test_noncanonical_job_hold_refuses_before_building(R, value):
    before = R.get('live'); _conf(R, 'SELFHOST_JOB_HOLD', value); sha = R.release('release/wave-60f')
    rc, out = R.run('release/wave-60f', sha)
    assert rc == 2 and 'SELFHOST_JOB_HOLD' in out and 'nothing built or switched' in out, out
    assert 'BUILD' not in R.dlog() and 'GUARDPROBE' not in R.dlog(); unchanged(R, before)


def test_canonical_job_hold_holds_every_named_kind(R):
    _conf(R, 'SELFHOST_JOB_HOLD', 'transcribe,intelligence-worker'); sha = R.release('release/wave-60g')
    rc, out = R.run('release/wave-60g', sha)
    assert rc == 0, out
    j = R.jobs(); assert j[INTEL] == BASE_JOBS[INTEL] and j['JOB_IMAGE_TRANSCODE'] == BASE_JOBS['JOB_IMAGE_TRANSCODE'], j
    assert 'BUILD goodqa-intelligence-worker' not in R.dlog() and 'GUARDPROBE' in R.dlog(), R.dlog()


# ---- goodqa#16136 review F2: the VM disk gate measures the runtime's own data roots and fails closed
def _vm_disk_refused(R, name, sha_note):
    before = R.get('live'); _conf(R, 'SELFHOST_VM_MIN_FREE_GB', '1'); sha = R.release(name)
    rc, out = R.run(name, sha)
    assert rc == 11 and 'NO DISK on the VM' in out, out
    assert 'LOAD' not in R.dlog(); unchanged(R, before)
    return out


def test_vm_disk_containerd_root_full_refuses_while_docker_root_has_room(R):
    R.put('vmdf-containerd', '0')
    out = _vm_disk_refused(R, 'release/wave-60d1', 'containerd full')
    assert '"free_gb": 0' in out and 'containerd-root' in out, out


def test_vm_disk_docker_root_full_refuses_while_containerd_root_has_room(R):
    R.put('vmdf-docker', '0'); _vm_disk_refused(R, 'release/wave-60d2', 'docker full')


@pytest.mark.parametrize('mark', ['containerd-fail', 'containerd-noroot'])
def test_vm_disk_unresolved_containerd_root_refuses(R, mark):
    R.put(mark, ''); out = _vm_disk_refused(R, 'release/wave-60d3', mark)
    assert 'unresolved' in out, out


def test_vm_disk_stat_failure_refuses(R):
    R.put('vmdf-containerd', 'fail'); out = _vm_disk_refused(R, 'release/wave-60d4', 'stat fails')
    assert 'unresolved' in out, out


def test_vm_disk_needs_twice_the_incoming_image_bytes(R):
    # 7 images of 8 GiB need 112 GiB; the fixture VM has 100 GiB free on both roots, above the 1 GiB floor
    R.put('image-size', str(8 << 30)); out = _vm_disk_refused(R, 'release/wave-60d5', 'incoming bytes')
    assert '112G needed' in out, out


def test_vm_disk_unreadable_image_size_refuses(R):
    R.put('size-unreadable', ''); out = _vm_disk_refused(R, 'release/wave-60d6', 'size unknown')
    assert 'xG needed' in out, out


def test_vm_disk_reports_both_roots(R):
    _conf(R, 'SELFHOST_VM_MIN_FREE_GB', '1'); sha = R.release('release/wave-60d7'); rc, out = R.run('release/wave-60d7', sha)
    assert rc == 0, out
    line = next(l for l in out.split('\\n') if 'VM image store:' in l)
    assert '"free_gb": 100' in line and 'containerd-root' in line and '"paths"' in line, line
'''
if '\nimport pytest' not in t and 'import pytest' not in t.split('\n\n\n')[0]:
    t = t.replace('\nimport json', '\nimport pytest\nimport json', 1)
open(p, 'w').write(t + '\n'); print('patched tests F1 F2')
