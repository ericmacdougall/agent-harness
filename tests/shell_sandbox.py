"""Gate for tests that hand shape, table, corpus or fuzz strings to real shells.

Such a test runs only inside the shell sandbox container: an unprivileged user, no sudo or doas and a disabled su,
no network interface but loopback, no credential files under HOME, and the marker the sandbox runner sets. Outside
it the test refuses to start (unittest.SkipTest naming every missing condition), so a row can never reach real
privilege, the network or a key on a developer or delivery host. Every condition is checked from the inside, so a
runner that forgets one is refused too. The runner is described in docs/operations.md ("Shell sandbox").
"""
import os
import shutil
import unittest

ENV = 'AGENT_HARNESS_SHELL_SANDBOX'
PRIVILEGE_PATHS = ('/usr/bin/sudo', '/bin/sudo', '/usr/local/bin/sudo', '/opt/homebrew/bin/sudo', '/usr/bin/doas', '/usr/local/bin/doas')
SU_PATHS = ('/usr/bin/su', '/bin/su')
CREDENTIAL_PATHS = ('.ssh', '.aws', '.config/gh', '.netrc', '.gnupg', '.docker/config.json', '.config/gcloud', '.azure', '.kube')
CONTAINER_MARKERS = ('/.dockerenv', '/run/.containerenv')
CGROUP_WORDS = ('docker', 'containerd', 'podman', 'libpod', 'lxc', 'kubepods')


def _read_cgroup(path='/proc/1/cgroup'):
    with open(path, encoding='utf-8', errors='replace') as handle:
        return handle.read(65536)


def reasons(env=None, geteuid=os.geteuid, which=shutil.which, exists=os.path.exists, access=os.access, listdir=os.listdir, read=_read_cgroup):
    """Every condition that is not met, one short reason each; an empty list means the gate is open."""
    env = os.environ if env is None else env
    out = []
    if env.get(ENV) != '1':
        out.append('%s is not 1 (not started by the sandbox runner)' % ENV)
    if geteuid() == 0:
        out.append('running as root')
    found = which('sudo') or which('doas') or next((p for p in PRIVILEGE_PATHS if exists(p)), None)
    if found:
        out.append('a privilege tool is present: %s' % found)
    runnable_su = next((p for p in SU_PATHS if access(p, os.X_OK)), None)
    if runnable_su:
        out.append('su is executable: %s' % runnable_su)
    try:
        cgroup = read()
    except OSError:
        cgroup = ''
    if not (any(exists(m) for m in CONTAINER_MARKERS) or env.get('container') or any(w in cgroup for w in CGROUP_WORDS)):
        out.append('no container marker (/.dockerenv, /run/.containerenv, $container or a container cgroup)')
    try:
        interfaces = sorted(name for name in listdir('/sys/class/net') if name != 'lo')
    except OSError:
        interfaces = None
    if interfaces is None:
        out.append('cannot prove the network is off (/sys/class/net is unreadable: not a Linux container)')
    elif interfaces:
        out.append('network interfaces besides lo: %s' % ', '.join(interfaces))
    home = env.get('HOME') or ''
    if not home:
        out.append('HOME is unset')
    for rel in CREDENTIAL_PATHS:
        if home and exists(os.path.join(home, rel)):
            out.append('credential path exists: %s' % os.path.join(home, rel))
    return out


# r9 F1: the spellings macOS's case-insensitive, Unicode-folding file system resolves to these programs (`ECHO` runs echo, `ba\u017fh`
# with a long s runs bash, `\u212a\u017fh` with a Kelvin sign runs ksh). Linux does not, so fold_links puts them in a PATH directory as
# symlinks: a stand-in for the Mac's lookup, so table and fuzz rows spelled this way run in the sandbox as they would on a Mac.
# Never a privilege tool: those never reach a shell in any spelling.
FOLDED_SPELLINGS = {'echo': ('ECHO', 'Echo'), 'nice': ('NICE',), 'env': ('ENV',), 'nohup': ('NOHUP',), 'timeout': ('TIMEOUT',),
                    'bash': ('BASH', 'ba\u017fh'), 'sh': ('SH', '\u017fh'), 'ksh': ('KSH', '\u212a\u017fh')}


def fold_links(directory, which=shutil.which):
    """Symlinks in directory for FOLDED_SPELLINGS whose program is on PATH; the spellings made. A spelling the directory's own
    file system already folds onto another (a case-insensitive host) is skipped."""
    made = []
    for program, spellings in FOLDED_SPELLINGS.items():
        target = which(program)
        if not target:
            continue
        for spelling in spellings:
            try:
                os.symlink(target, os.path.join(directory, spelling))
            except FileExistsError:
                continue
            made.append(spelling)
    return made


def require():
    """Raise SkipTest naming every missing condition; call it from setUpClass or a script entry point."""
    missing = reasons()
    if missing:
        raise unittest.SkipTest('real-shell tests run only in the shell sandbox container: ' + '; '.join(missing))
