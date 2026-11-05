"""Suite-wide hermeticity: keep tests off the operator's real state, usage store and logs (GoodQA #14560).

`install()` runs when test_hermetic_guard is imported (discovery imports every module before any test runs) and when
usage-touching modules are run on their own. It points HOME and AGENT_HARNESS_USAGE_DIR at a private temp root for
the process so every child inherits them. Limits, stated plainly:
- a child started with an empty environment still falls back to the pwd database (GoodQA #14561); the gate wrapper
  (hermetic_check.sh) therefore also runs the suite under a sandbox that DENIES writes to the real state dirs;
- modules that froze a real-home path at import time (before install ran) are reported by scan_frozen_paths(), which the
  suite asserts only when the gate pinned HOME first; under a bare discover those globals are protected by the tests'
  own patches (see the spec's Scope limits).
The protected set is the operator's real state directories, not "anything under HOME": a TMPDIR or worktree that
happens to live under HOME is fine.
"""
import atexit
import os
import pwd
import shutil
import sys
import tempfile
from pathlib import Path

_ROOT = None
PROTECTED_RELATIVE = ('.claude', '.codex', '.gitconfig', '.ssh', '.agent-harness/usage', '.agent-harness/state',
                      '.agent-harness/logs', '.agent-harness/commit-policy', '.agent-harness/wals')


def real_home():
    return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()


def protected():
    home = real_home()
    return [home / relative for relative in PROTECTED_RELATIVE]


def _inside(path, base):
    path = Path(os.path.realpath(path))
    return path == base or base in path.parents


def hits_protected(path):
    """True when `path` is, or is inside, one of the real state directories."""
    return bool(path) and any(_inside(path, base) for base in protected())


def install():
    global _ROOT
    if _ROOT is None:
        _ROOT = Path(os.path.realpath(tempfile.mkdtemp(prefix='harness-suite-home-')))
        atexit.register(shutil.rmtree, _ROOT, True)
    home = real_home()
    if os.path.realpath(os.environ.get('HOME') or str(home)) == str(home):
        os.environ['HOME'] = str(_ROOT)
    if not os.environ.get('AGENT_HARNESS_USAGE_DIR') or hits_protected(os.environ['AGENT_HARNESS_USAGE_DIR']):
        os.environ['AGENT_HARNESS_USAGE_DIR'] = str(_ROOT / 'usage')
    return _ROOT


def violations():
    """Reasons the current process would still write real state; empty when hermetic."""
    found = []
    home = real_home()
    for name, value in (('HOME', os.environ.get('HOME')), ('expanduser(~)', os.path.expanduser('~')),
                        ('Path.home()', str(Path.home()))):
        if not value or os.path.realpath(value) == str(home):
            found.append(f'{name}={value!r} is the real home {home}')
    if hits_protected(os.environ.get('HOME')):
        found.append(f"HOME={os.environ.get('HOME')!r} is inside a real state directory")
    usage = os.environ.get('AGENT_HARNESS_USAGE_DIR')
    if not usage or hits_protected(usage):
        found.append(f'AGENT_HARNESS_USAGE_DIR={usage!r} is unset or inside a real state directory')
    return found


def scan_frozen_paths(modules=None):
    """Module-level str/PathLike globals that point into the real state dirs (paths frozen at import time)."""
    found = []
    for name, module in list((modules if modules is not None else sys.modules).items()):
        for attribute, value in list(getattr(module, '__dict__', {}).items()):
            if attribute.startswith('__') or not isinstance(value, (str, os.PathLike)):
                continue
            text = os.fspath(value)
            if text.startswith('/') and hits_protected(text):
                found.append(f'{name}.{attribute}={text}')
    return found
