"""Audit hook for the hermeticity gate (GoodQA #14560): records any attempt, by this Python process or a child that
inherits PYTHONPATH, to write inside the operator's real state directories, whether or not the write was swallowed.
Enabled only when HC_AUDIT_LOG is set. HC_PROTECT (colon separated) overrides the protected set, HC_ALLOW exempts paths.
"""
import os
import sys

_LOG = os.environ.get('HC_AUDIT_LOG')


def _protected():
    if os.environ.get('HC_PROTECT'):
        return [p for p in os.environ['HC_PROTECT'].split(':') if p]
    try:
        import pwd
        home = os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)
    except Exception:
        return []
    return [os.path.join(home, rel) for rel in ('.claude', '.codex', '.gitconfig', '.ssh', '.agent-harness/usage',
            '.agent-harness/state', '.agent-harness/logs', '.agent-harness/commit-policy', '.agent-harness/wals')]


if _LOG:
    _PROT = [os.path.realpath(p) for p in _protected()]
    _ALLOW = [os.path.realpath(p) for p in os.environ.get('HC_ALLOW', '').split(':') if p]
    _WRITE = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
    _BUSY = []
    _PATH_EVENTS = {'os.mkdir': (0,), 'os.rmdir': (0,), 'os.remove': (0,), 'os.rename': (0, 1), 'os.symlink': (1,),
                    'os.link': (0, 1), 'shutil.rmtree': (0,), 'os.chmod': (0,), 'os.truncate': (0,)}

    def _inside(path, bases):
        return any(path == base or path.startswith(base.rstrip('/') + '/') for base in bases)

    def _record(event, path):
        _BUSY.append(1)
        try:
            real = os.path.realpath(os.fsdecode(path))
            if _inside(real, _PROT) and not _inside(real, _ALLOW):
                with open(_LOG, 'a') as handle:
                    handle.write(f'{os.getpid()} {event} {real} argv0={sys.argv[0] if sys.argv else ""}\n')
        except Exception:
            pass
        finally:
            _BUSY.pop()

    def _hook(event, args):
        if _BUSY:
            return
        if event == 'open':
            path, mode, flags = args
            if isinstance(path, (str, bytes, os.PathLike)) and (
                    (isinstance(flags, int) and flags & _WRITE) or (isinstance(mode, str) and any(c in mode for c in 'wax+'))):
                _record(event, path)
        elif event in _PATH_EVENTS:
            for index in _PATH_EVENTS[event]:
                if index < len(args) and isinstance(args[index], (str, bytes, os.PathLike)):
                    _record(event, args[index])

    sys.addaudithook(_hook)
