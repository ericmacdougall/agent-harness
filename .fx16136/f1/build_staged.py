"""Build PR 73's staged test_rw_ship_selfhost.py from bugtracker's own file at the bound commit.
Usage: build_staged.py <upstream test file> <current staged test file> <out>

The staged runtime (config/goodqa-release/bin) is byte-equal to bugtracker infra/release-harness at the bound commit,
so bugtracker's tests apply to it unchanged, with two exceptions:
- SRoot copies rw-image-jobs.py, the image policy and the tzdata policy from the bugtracker tree into the fake repo.
  Those files are not staged, and the staged rw-ship.sh does not read them. The copy lines are left out.
- ThroughputProcess, install_real_promote and PromotionPhases drive the release-throughput scheduler, which lives in
  bugtracker's rw-image-jobs.py and promote.sh and is not part of the staged lane. That block is left out, by name.
The staged-only test_vm_disk_gate_refuses_when_the_image_store_is_unknown (the 52fed569 port) is kept, appended."""
import re
import sys

up = open(sys.argv[1]).read()
st = open(sys.argv[2]).read()

# 1. the three bugtracker-tree copies in SRoot
copy = re.search(r"\n        # Keep the scheduler and image policy in the immutable fixture source\.\n(?:        .*\n){5}", up)
assert copy and 'shutil.copyfile' in copy.group(0) and 'rw-image-jobs.py' in copy.group(0), 'copy block not found'
assert up.count('# Keep the scheduler and image policy') == 1
up = up.replace(copy.group(0), '\n')

# 2. the throughput-scheduler block, from its marker to the next section marker
a = up.index('# unittest entrypoint for the focused release-throughput process contract.')
b = up.index('# ---------------------------------------------------------------- goodqa#16136: job image pins')
block = up[a:b]
for name in ('class ThroughputProcess(', 'def install_real_promote(', 'class PromotionPhases('):
    assert block.count(name) == 1, name
assert not re.search(r'^def test_', block, re.M), 'a pytest test would be dropped with the scheduler block'
up = up[:a] + up[b:]

# 3. keep the staged-only disk-gate test
m = re.search(r"\n\n# -{64} the VM disk gate fails closed \(deliberate, was an accidental exit 11\)\n.*\Z", st, re.S)
assert m and 'def test_vm_disk_gate_refuses_when_the_image_store_is_unknown' in m.group(0), 'staged-only test not found'
assert 'def test_vm_disk_gate_refuses_when_the_image_store_is_unknown' not in up
keep = m.group(0)
# F1 retarget: `containerd-noroot` broke the removed `containerd config dump`; the unknown store is now a containerd
# address nobody listens on (same assertions)
old_p = "@pytest.mark.parametrize('how', ['driverstatus-fail', 'containerd-noroot'])"
old_b = "before = R.get('live'); R.put(how, ''); sha = R.release('release/wave-90')"
assert keep.count(old_p) == 1 and keep.count(old_b) == 1, 'staged-only test changed shape'
keep = keep.replace(old_p, "@pytest.mark.parametrize('how', ['driverstatus-fail', 'containerd-not-listening'])")
keep = keep.replace(old_b, "before = R.get('live')\n    if how == 'containerd-not-listening': R.put('ctd-address', os.path.join(R.sk, 'gone.sock'))\n"
                           "    else: R.put(how, '')\n    sha = R.release('release/wave-90')")
out = up.rstrip('\n') + keep.rstrip('\n') + '\n'

# 4. tests that read the bugtracker tree itself (its compose.yaml, the b3604eae ctl in its history) find it through the
#    same bugtracker checkout this suite already needs for tools/lane-harness (config/tools links into it)
h = "HERE = os.path.dirname(os.path.abspath(__file__))\n"
assert out.count(h) == 1
out = out.replace(h, h + "# the bugtracker checkout whose tools/ the lane links at config/tools (bugtracker-harness staged layout)\n"
                          "BT = os.path.realpath(os.path.join(HERE, '..', '..', 'tools', '..'))\n")
c = "os.path.join(HERE, '..', 'selfhost', 'app', 'compose.yaml')"
assert out.count(c) == 3, out.count(c)
out = out.replace(c, "os.path.join(BT, 'infra', 'selfhost', 'app', 'compose.yaml')")
g = "'b3604eaec1c6eac8a0f2558ca7f8ebd24cdc7254:infra/release-harness/selfhost-ctl.py'], cwd=HERE,"
assert out.count(g) == 1
out = out.replace(g, "'b3604eaec1c6eac8a0f2558ca7f8ebd24cdc7254:infra/release-harness/selfhost-ctl.py'], cwd=BT,")
open(sys.argv[3], 'w').write(out)
print('built', sys.argv[3], len(out.split('\n')), 'lines')
