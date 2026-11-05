"""Suite-wide hermeticity: keep tests off the operator's real HOME, usage store and state (GoodQA #14560).

`install()` runs when test_hermetic_guard is imported, which discovery does before any test executes, and when a
usage-touching module is run on its own. It points HOME and AGENT_HARNESS_USAGE_DIR at a private temp root for the
whole test process, so every child inherits them. A child that is started with an empty environment can still fall
back to the pwd database; the gates therefore also run the suite under a deny sandbox and snapshot the real dirs.
"""
import atexit
import os
import pwd
import shutil
import tempfile
from pathlib import Path

_ROOT = None


def real_home():
    return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()


def _inside(path, base):
    path = Path(os.path.realpath(path))
    return path == base or base in path.parents


def install():
    global _ROOT
    if _ROOT is None:
        _ROOT = Path(os.path.realpath(tempfile.mkdtemp(prefix='harness-suite-home-')))
        atexit.register(shutil.rmtree, _ROOT, True)
    home = real_home()
    if not _inside(os.environ.get('HOME', str(home)), _ROOT) and _inside(os.environ.get('HOME', str(home)), home):
        os.environ['HOME'] = str(_ROOT)
    usage = os.environ.get('AGENT_HARNESS_USAGE_DIR')
    if not usage or _inside(usage, home):
        os.environ['AGENT_HARNESS_USAGE_DIR'] = str(_ROOT / 'usage')
    return _ROOT


def violations():
    """Reasons the current process would still touch the real home; empty when hermetic."""
    home, found = real_home(), []
    for name, value in (('HOME', os.environ.get('HOME')), ('expanduser(~)', os.path.expanduser('~')),
                        ('AGENT_HARNESS_USAGE_DIR', os.environ.get('AGENT_HARNESS_USAGE_DIR')),
                        ('Path.home()', str(Path.home()))):
        if not value or _inside(value, home):
            found.append(f'{name}={value!r} is inside the real home {home}')
    return found
