"""Gate for tests that hand table, corpus or fuzz strings to real shells.

Such a test runs only inside a sandbox container: an unprivileged user, no sudo anywhere, no network interface
but loopback, no credential files under HOME, and the container marker the runner sets. Outside it the test
refuses to start (unittest.SkipTest naming every missing condition), so a table row can never reach real
privilege, the network or a key on a developer host or a delivery host. The runner that satisfies the gate is
documented in docs/operations.md ("Shell sandbox"); every condition is checked from the inside, so a runner that
forgets one is refused too.
"""
import os
import shutil
import unittest

ENV = 'AGENT_HARNESS_SHELL_SANDBOX'
SUDO_PATHS = ('/usr/bin/sudo', '/bin/sudo', '/usr/local/bin/sudo', '/opt/homebrew/bin/sudo', '/usr/bin/doas', '/usr/local/bin/doas')
CREDENTIAL_PATHS = ('.ssh', '.aws', '.config/gh', '.netrc', '.gnupg', '.docker/config.json', '.config/gcloud', '.azure', '.kube')
CONTAINER_MARKERS = ('/.dockerenv', '/run/.containerenv')


def _cgroup_names_a_container(read):
    try:
        text = read('/proc/1/cgroup')
    except OSError:
        return False
    return any(word in text for word in ('docker', 'containerd', 'podman', 'libpod', 'lxc', 'kubepods'))


def reasons(env=None, geteuid=os.geteuid, which=shutil.which, exists=os.path.exists, listdir=os.listdir, read=None):
    """Every condition that is not met, as a short reason each; an empty list means the gate is open."""
    env = os.environ if env is None else env
    if read is None:
        def read(path):
            with open(path, encoding='utf-8', errors='replace') as handle:
                return handle.read(65536)
    out = []
    if env.get(ENV) != '1':
        out.append('%s is not 1 (not started by the sandbox runner)' % ENV)
    if geteuid() == 0:
        out.append('running as root')
    found = which('sudo') or which('doas') or next((p for p in SUDO_PATHS if exists(p)), None)
    if found:
        out.append('a privilege tool is present: %s' % found)
    if not (any(exists(m) for m in CONTAINER_MARKERS) or env.get('container') or _cgroup_names_a_container(read)):
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
        path = os.path.join(home, rel) if home else rel
        if home and exists(path):
            out.append('credential path exists: %s' % path)
    return out


def require():
    """Raise SkipTest with every missing condition; the caller is a setUpClass or a script entry point."""
    missing = reasons()
    if missing:
        raise unittest.SkipTest('real-shell table tests run only in the shell sandbox container: ' + '; '.join(missing))
