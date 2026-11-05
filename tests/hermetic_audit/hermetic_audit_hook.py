"""Audit hook for the hermeticity gate (GoodQA #14560).

Records every attempt, by any Python process that starts under the gate's virtualenv (a `.pth` file imports this
module), to write inside the operator's real state directories, whether or not the code swallowed the error.
Configuration comes from a JSON file, not from the environment, so children started with `env={}` or `python -I` are
covered too: the path is HC_AUDIT_CONFIG when set, otherwise `hermetic_audit_config.json` next to this module.
    {"log": "...", "loaded_log": "...", "protect": ["/abs/dir", ...], "allow": ["/abs/dir", ...]}
Limits: a child that execs another interpreter by absolute path (for example /usr/bin/python3) is not covered; sqlite
and other C-level writers, os.utime/chown/mkfifo and xattr calls are not hooked.
"""
import os
import sys


def _config():
    path = os.environ.get('HC_AUDIT_CONFIG') or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                             'hermetic_audit_config.json')
    try:
        import json
        with open(path) as handle:
            return json.load(handle)
    except Exception:
        return None


def _fd_path(fd):
    """Path of an open directory descriptor, or None."""
    try:
        if sys.platform == 'darwin':
            import fcntl
            return fcntl.fcntl(fd, 50, b'\0' * 1024).split(b'\0', 1)[0].decode()  # F_GETPATH
        return os.readlink('/proc/self/fd/%d' % fd)
    except Exception:
        return None


def install(config):
    log = config['log']
    protect = [os.path.realpath(p) for p in config.get('protect', [])]
    allow = [os.path.realpath(p) for p in config.get('allow', [])]
    busy = []
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
    # event -> (path argument indexes, (path index, dir_fd index) pairs for dir_fd-relative forms)
    events = {'os.mkdir': ((0,), ((0, 2),)), 'os.rmdir': ((0,), ((0, 1),)), 'os.remove': ((0,), ((0, 1),)),
              'os.rename': ((0, 1), ((0, 2), (1, 3))), 'os.symlink': ((1,), ((1, 2),)), 'os.link': ((0, 1), ((0, 2), (1, 3))),
              'shutil.rmtree': ((0,), ()), 'os.chmod': ((0,), ((0, 2),)), 'os.truncate': ((0,), ()),
              'os.utime': ((0,), ((0, 3),)), 'os.chown': ((0,), ((0, 3),)), 'os.mkfifo': ((0,), ((0, 2),)),
              'os.mknod': ((0,), ((0, 3),)), 'os.setxattr': ((0,), ()), 'os.removexattr': ((0,), ()),
              'shutil.copyfile': ((1,), ()), 'shutil.copymode': ((1,), ()), 'shutil.copystat': ((1,), ()),
              'shutil.move': ((1,), ()), 'shutil.chown': ((0,), ())}

    def inside(path, bases):
        return any(path == base or path.startswith(base.rstrip('/') + '/') for base in bases)

    def record(event, path, note=''):
        busy.append(1)
        try:
            real = os.path.realpath(os.fsdecode(path))
            if inside(real, protect) and not inside(real, allow):
                with open(log, 'a') as handle:
                    handle.write('%d %s %s%s argv0=%s\n' % (os.getpid(), event, real, note, sys.argv[0] if sys.argv else ''))
        except Exception:
            pass
        finally:
            busy.pop()

    def resolved(path, dir_fd):
        """Full path for a dir_fd-relative name, else the name as given."""
        if isinstance(path, (str, bytes, os.PathLike)) and isinstance(dir_fd, int) and not os.path.isabs(os.fsdecode(path)):
            base = _fd_path(dir_fd)
            return os.path.join(base, os.fsdecode(path)) if base else None
        return path

    def hook(event, args):
        if busy:
            return
        if event == 'open':
            path, mode, flags = args
            if not isinstance(path, (str, bytes, os.PathLike)):
                return
            if (isinstance(flags, int) and flags & write_flags) or (isinstance(mode, str) and any(c in mode for c in 'wax+')):
                record(event, path)
            else:
                # opening a protected directory is how dir_fd-relative writes start (usage_guard, report_file, workdir)
                try:
                    if os.path.isdir(path):
                        record('opendir', path)
                except Exception:
                    pass
        elif event in events:
            indexes, relative = events[event]
            done = set()
            for path_index, fd_index in relative:
                if path_index < len(args) and fd_index < len(args) and isinstance(args[fd_index], int) and args[fd_index] >= 0:
                    full = resolved(args[path_index], args[fd_index])
                    if full is not None:
                        record(event, full, ' (dir_fd)')
                        done.add(path_index)
            for index in indexes:
                if index not in done and index < len(args) and isinstance(args[index], (str, bytes, os.PathLike)):
                    record(event, args[index])

    try:
        with open(config.get('loaded_log') or log + '.loaded', 'a') as handle:
            handle.write('%d loaded protected=%d\n' % (os.getpid(), len(protect)))
    except Exception:
        pass
    sys.addaudithook(hook)


_CONFIG = _config()
if _CONFIG and _CONFIG.get('log'):
    install(_CONFIG)
