"""goodqa#16148: broken variants of the selfhost-ctl gate verbs; each must fail test_selfhost_ctl_gate.py. Run in the gate root."""
import os
import shutil
import subprocess

F = 'infra/release-harness/selfhost-ctl.py'
PY = os.path.expanduser('~/repos/fx-16136/venv/bin/python')
FLAG_LINE_1 = "TRIAL_FLAGS = ('--rm', '--network', 'none', '--read-only', '--tmpfs', '/tmp', '--cap-drop', 'ALL',\n"
FLAG_LINE_2 = "               '--security-opt', 'no-new-privileges', '--user', 'node', '--group-add', str(TRIAL_GID),\n"
FLAG_LINE_3 = "               '--pids-limit', '64', '--memory', '256m')\n"
VARIANTS = [
    ('G1 no --rm', FLAG_LINE_1, FLAG_LINE_1.replace("'--rm', ", '')),
    ('G2 network bridge', FLAG_LINE_1, FLAG_LINE_1.replace("'none'", "'bridge'")),
    ('G3 no --read-only', FLAG_LINE_1, FLAG_LINE_1.replace("'--read-only', ", '')),
    ('G4 no cap-drop', FLAG_LINE_1, FLAG_LINE_1.replace(", '--cap-drop', 'ALL'", '')),
    ('G5 no no-new-privileges', FLAG_LINE_2, FLAG_LINE_2.replace("'--security-opt', 'no-new-privileges', ", '')),
    ('G6 root user', FLAG_LINE_2, FLAG_LINE_2.replace("'--user', 'node', ", '')),
    ('G7 no pids limit', FLAG_LINE_3, FLAG_LINE_3.replace("'--pids-limit', '64', ", '')),
    ('G8 no memory limit', FLAG_LINE_3, FLAG_LINE_3.replace(", '--memory', '256m'", '')),
    ('G9 no rm -f on timeout', "        docker('rm', '-f', name, timeout=60)\n", "        pass\n"),
    ('G10 prints container output', "        del r\n        out({'status': 'ok' if ok", "        print(r.stdout)\n        out({'status': 'ok' if ok"),
    ('G11 loose ok match', "        if msg == DISP_OK_LINE: return 'ok'\n", "        if DISP_OK_LINE in msg: return 'ok'\n"),
    ('G12 unbounded log read', "    r = docker('logs', '--since', started, '--tail', str(DISP_LOG_TAIL), cid, timeout=60)\n",
     "    r = docker('logs', cid, timeout=60)\n"),
    ('G13 up-dispatcher recreates all', "    return cmd_up(stk, a, services=('job-dispatcher', 'job-dispatcher-create-guard'))\n",
     "    return cmd_up(stk, a)\n"),
    ('G14 tag image allowed', "TRIAL_IMAGE_RE = re.compile(r'^goodqa-job-dispatcher@sha256:[0-9a-f]{64}$')",
     "TRIAL_IMAGE_RE = re.compile(r'^goodqa-job-dispatcher[@:]\\S+$')"),
    ('G15 envfile-key follows links', "    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)\n", "    fd = os.open(path, os.O_RDONLY)\n"),
]
orig = open(F).read()
shutil.copyfile(F, F + '.orig-variants')
try:
    for name, old, new in VARIANTS:
        assert orig.count(old) == 1, name
        open(F, 'w').write(orig.replace(old, new))
        r = subprocess.run([PY, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'infra/release-harness/test_selfhost_ctl_gate.py'],
                           capture_output=True, text=True, timeout=300)
        print(name + ': ' + r.stdout.strip().splitlines()[-1])
finally:
    shutil.copyfile(F + '.orig-variants', F)
    os.remove(F + '.orig-variants')
print('restored:', open(F).read() == orig)
