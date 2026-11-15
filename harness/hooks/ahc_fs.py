"""ahc_fs: the only way ahc writes under its state root (goodqa#16049, PR 258 v3 class fix).

PR 258 review rounds v1 and v3 each found an ahc write under the root steered through a planted link:
  - v1: a top-level name;
  - v3: `.git/config.ahc-tmp`.
The class fix is that ahc's code under the root never names a path to the kernel for a write. Every write goes
through this module, which:
  * opens the root by its own path with O_DIRECTORY|O_NOFOLLOW and checks the opened descriptor:
    - a directory;
    - owned by this uid;
    - mode exactly 0700;
  * reaches every directory below it one component at a time, relative to the parent's descriptor, with
    O_DIRECTORY|O_NOFOLLOW, applying the same owner and mode check to each one;
  * creates a temp file with O_CREAT|O_EXCL|O_NOFOLLOW under an unpredictable name `.<name>.<hex>.tmp`, then
    writes it, fchmods it and fsyncs it through that descriptor;
  * puts the file in place with rename or link relative to the directory descriptor, then fsyncs the directory.

A link planted at the target name is replaced as a name by rename, or refused by link when `exclusive`; it is never
followed. A link at any directory on the way makes the open fail with ELOOP or ENOTDIR. A directory owned by another
uid, or with group or other permission bits, is refused, so another user cannot have written anything below it.

tests/test_ahc_fs.py walks the ahc modules' syntax trees and fails on any path-based write outside this module,
except an allowlisted site that writes outside the root (each with its reason).

What remains (L10): a process with this uid can do anything this uid can. It could swap entries between calls, or
run git itself. Within this model that is not a separate attack.
"""
from __future__ import annotations

import os
import re
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path

NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
NONBLOCK = getattr(os, "O_NONBLOCK", 0)
DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | NOFOLLOW
DIR_MODE = 0o700
FILE_MODE = 0o600


class UnsafePath(OSError):
    """A path under the root is not safe to write: a link, a foreign owner, a loose mode, or outside the root."""


def _uid():
    return os.geteuid()


def dir_problem(info):
    """Why an fstat/lstat result is not an ahc-owned private directory, or None."""
    if not stat.S_ISDIR(info.st_mode):
        return "not a directory"
    if info.st_uid != _uid():
        return "owned by uid %d, not %d" % (info.st_uid, _uid())
    if stat.S_IMODE(info.st_mode) != DIR_MODE:
        return "mode %04o, not 0700" % stat.S_IMODE(info.st_mode)
    return None


def _check_dir(fd, what):
    """Raise UnsafePath, closing `fd`, if it is not a private ahc directory."""
    problem = dir_problem(os.fstat(fd))
    if problem:
        os.close(fd)
        raise UnsafePath("%s is %s" % (what, problem))


def parts_under(root, path):
    """The components of `path` below `root`, refusing anything that is not strictly inside it. Purely textual:
    nothing is resolved, so a link cannot move the path; the descriptor walk refuses links later."""
    root, path = Path(root), Path(path)
    try:
        rel = path.relative_to(root)
    except ValueError:
        raise UnsafePath("%s is not under the ahc root" % path) from None
    parts = rel.parts
    if any(p in ("", ".", "..") or os.sep in p for p in parts):
        raise UnsafePath("%s is not a plain path under the ahc root" % path)
    return parts


def open_root(root):
    """A descriptor for the root itself, never followed through a link, and checked to be owned by this uid with
    mode 0700."""
    try:
        fd = os.open(str(root), DIR_FLAGS)
    except OSError as error:
        raise UnsafePath("ahc root %s cannot be opened as a real directory (%s)"
                         % (root, type(error).__name__)) from None
    _check_dir(fd, "ahc root %s" % root)
    return fd


def _walk(root, parts, create):
    fd = open_root(root)
    for index, name in enumerate(parts):
        if create:
            try:
                os.mkdir(name, DIR_MODE, dir_fd=fd)
            except FileExistsError:
                pass
            except OSError:
                os.close(fd)
                raise
        try:
            nxt = os.open(name, DIR_FLAGS, dir_fd=fd)
        except OSError as error:
            os.close(fd)
            raise UnsafePath("%s under the ahc root is not a real directory (%s)"
                             % ("/".join(parts[:index + 1]), type(error).__name__)) from None
        os.close(fd)
        fd = nxt
        _check_dir(fd, "%s under the ahc root" % "/".join(parts[:index + 1]))
    return fd


@contextmanager
def directory(root, path, create=False):
    """Yield a checked descriptor for directory `path` (the root itself when path == root)."""
    fd = _walk(root, parts_under(root, path) if Path(path) != Path(root) else (), create)
    try:
        yield fd
    finally:
        os.close(fd)


def make_dirs(root, path):
    """Create `path` and any missing parents under the root at 0700, checking every component."""
    with directory(root, path, create=True):
        pass


def make_fresh_dir(root, path, reuse_empty=False):
    """Create `path` exclusively (FileExistsError if anything already holds the name) and return its (dev, ino).
    A caller can later reopen it and confirm it is the same directory. reuse_empty=True also accepts an existing
    EMPTY private directory, owned by this uid at 0700 and not a link. That is what a crash right after this call
    leaves, and inside the 0700 root nobody else can have made one."""
    parent, name = Path(path).parent, Path(path).name
    with directory(root, parent) as dfd:
        try:
            os.mkdir(name, DIR_MODE, dir_fd=dfd)
        except FileExistsError:
            if not reuse_empty:
                raise
            try:
                fd = os.open(name, DIR_FLAGS, dir_fd=dfd)
            except OSError:
                raise FileExistsError("%s exists and is not a real directory" % name) from None
            _check_dir(fd, "%s under the ahc root" % name)
            try:
                if os.listdir(fd):
                    raise FileExistsError("%s exists and is not empty" % name)
                info = os.fstat(fd)
                return info.st_dev, info.st_ino
            finally:
                os.close(fd)
        fd = os.open(name, DIR_FLAGS, dir_fd=dfd)
        _check_dir(fd, "%s under the ahc root" % name)
        try:
            info = os.fstat(fd)
            os.fsync(dfd)
            return info.st_dev, info.st_ino
        finally:
            os.close(fd)


def temp_name(name):
    """`.<name>.<hex>.tmp`, or `<name>.<hex>.tmp` for a dot name. Both match the root's tolerated temp patterns."""
    return "%s%s.%s.tmp" % ("" if name.startswith(".") else ".", name, secrets.token_hex(8))


def _create_temp(dfd, name, mode):
    tmp = temp_name(name)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW | NONBLOCK, mode, dir_fd=dfd)
    return tmp, fd


def write_file(root, path, data, mode=FILE_MODE, exclusive=False, create_dirs=False):
    """Write `data` (str or bytes) as the whole content of `path`, durably.
      exclusive=False: the result replaces whatever entry held the name; a link there is replaced, not followed.
      exclusive=True: FileExistsError if the name is taken (first writer wins; nothing is replaced).
    Returns (dev, ino) of the written file."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    parent, name = Path(path).parent, Path(path).name
    with directory(root, parent, create=create_dirs) as dfd:
        tmp, fd = _create_temp(dfd, name, mode)
        placed = False
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fchmod(handle.fileno(), mode)
                os.fsync(handle.fileno())
                info = os.fstat(handle.fileno())
            if exclusive:
                os.link(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
            else:
                os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
                placed = True
        finally:
            if not placed:
                try:
                    os.unlink(tmp, dir_fd=dfd)
                except FileNotFoundError:
                    pass
        os.fsync(dfd)
        return info.st_dev, info.st_ino


COPY_CHUNK = 1024 * 1024   # copy_to_temp holds at most one chunk in memory, whatever the file's size
TEMP_RE_TEMPLATE = r"^%s\.[0-9a-f]{16}\.tmp$"


class TooLarge(UnsafePath):
    """copy_to_temp refused a source over its byte cap. Nothing was published."""


def copy_to_temp(root, src, dst, max_bytes, mode=FILE_MODE, chunk=COPY_CHUNK):
    """Stream the regular file `src` into a new exclusive temp file beside `dst`, in `chunk`-sized pieces, and
    fsync it. It returns the temp's path, and the caller publishes it with rename(). Nothing at `dst` changes
    here. So a failure here (TooLarge, a link, a vanished or foreign source, ENOSPC) leaves every published name
    as it was. The temp is removed on failure.
      * src is opened relative to its checked directory with O_NOFOLLOW|O_NONBLOCK. The OPENED descriptor must
        be a regular file owned by this uid.
      * max_bytes is enforced on the descriptor's size before any byte is copied, and again while copying, in case
        the file grows."""
    sparent, sname = Path(src).parent, Path(src).name
    dparent, dname = Path(dst).parent, Path(dst).name
    with directory(root, sparent) as sfd, directory(root, dparent) as dfd:
        try:
            ifd = os.open(sname, os.O_RDONLY | NOFOLLOW | NONBLOCK, dir_fd=sfd)
        except OSError as error:
            raise UnsafePath("%s cannot be opened as a regular file (%s)" % (sname, type(error).__name__)) from None
        try:
            info = os.fstat(ifd)
            if not stat.S_ISREG(info.st_mode):
                raise UnsafePath("%s is not a regular file" % sname)
            if info.st_uid != _uid():
                raise UnsafePath("%s is owned by uid %d" % (sname, info.st_uid))
            if info.st_size > max_bytes:
                raise TooLarge("%s is %d bytes, over the %d-byte cap" % (sname, info.st_size, max_bytes))
            tmp, ofd = _create_temp(dfd, dname, mode)
            done = False
            try:
                total = 0
                while True:
                    block = os.read(ifd, chunk)
                    if not block:
                        break
                    total += len(block)
                    if total > max_bytes:
                        raise TooLarge("%s grew past the %d-byte cap while it was copied" % (sname, max_bytes))
                    view = memoryview(block)
                    while view:
                        view = view[os.write(ofd, view):]
                    del view, block
                os.fchmod(ofd, mode)
                os.fsync(ofd)
                done = True
            finally:
                os.close(ofd)
                if not done:
                    try:
                        os.unlink(tmp, dir_fd=dfd)
                    except FileNotFoundError:
                        pass
        finally:
            os.close(ifd)
        os.fsync(dfd)
        return Path(dparent) / tmp


def remove_temps(root, dst):
    """Remove every unpublished temp file of `dst` (`.<name>.<16 hex>.tmp`, the names write_file and copy_to_temp
    create), as names, never followed. A process that died between creating a temp and publishing it leaves one
    behind. Returns the removed names."""
    parent, name = Path(dst).parent, Path(dst).name
    pattern = re.compile(TEMP_RE_TEMPLATE % re.escape(("" if name.startswith(".") else ".") + name))
    removed = []
    with directory(root, parent) as dfd:
        for entry in sorted(os.listdir(dfd)):
            if pattern.match(entry):
                os.unlink(entry, dir_fd=dfd)
                removed.append(entry)
        if removed:
            os.fsync(dfd)
    return removed


def open_file(root, path, flags, mode=FILE_MODE, create_dirs=False):
    """A descriptor for the regular file `path`, opened relative to its checked directory with O_NOFOLLOW and
    O_NONBLOCK, so a FIFO cannot block it. The opened file must be a regular file owned by this uid. When the call
    creates the file, it fchmods it to `mode`. The caller closes the descriptor."""
    parent, name = Path(path).parent, Path(path).name
    with directory(root, parent, create=create_dirs) as dfd:
        fd = os.open(name, flags | NOFOLLOW | NONBLOCK, mode, dir_fd=dfd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise UnsafePath("%s is not a regular file" % name)
            if info.st_uid != _uid():
                raise UnsafePath("%s is owned by uid %d" % (name, info.st_uid))
            if flags & os.O_CREAT:
                os.fchmod(fd, mode)
        except BaseException:
            os.close(fd)
            raise
        return fd


def append_file(root, path, data, create_dirs=False):
    """Append `data` to `path` (created at 0600 if absent) and fsync it."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    fd = open_file(root, path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, create_dirs=create_dirs)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def touch(root, path):
    """Set the mtime of the regular file `path` to now, through its descriptor."""
    fd = open_file(root, path, os.O_RDONLY)
    try:
        os.utime(fd)
    finally:
        os.close(fd)


def rename(root, src, dst):
    """Rename the entry `src` (a link is moved as a link, never followed) to `dst`, both under the root. The
    rename may cross directories."""
    with directory(root, Path(src).parent) as sfd, directory(root, Path(dst).parent) as dfd:
        os.rename(Path(src).name, Path(dst).name, src_dir_fd=sfd, dst_dir_fd=dfd)
        os.fsync(dfd)
        if not os.path.samestat(os.fstat(sfd), os.fstat(dfd)):
            os.fsync(sfd)


def unlink(root, path, missing_ok=False):
    """Remove the name `path`. A link is removed as a link, never followed."""
    with directory(root, Path(path).parent) as dfd:
        try:
            os.unlink(Path(path).name, dir_fd=dfd)
        except FileNotFoundError:
            if not missing_ok:
                raise
            return
        os.fsync(dfd)


def link_exclusive(root, src, dst):
    """Hard-link the file `src` to the new name `dst` in the same tree. FileExistsError if `dst` is taken, which
    makes it the first-writer-wins primitive. A link at `src` is linked as itself, never followed."""
    with directory(root, Path(src).parent) as sfd, directory(root, Path(dst).parent) as dfd:
        os.link(Path(src).name, Path(dst).name, src_dir_fd=sfd, dst_dir_fd=dfd, follow_symlinks=False)
        os.fsync(dfd)


def ancestor_problems(root):
    """Directories above the root that another user could rewrite. Each ancestor, resolved because the home path
    may legitimately go through links such as /var -> /private/var, must be owned by this uid or by root. It must
    also not be group- or other-writable, unless it is sticky like /tmp. Another user able to write an ancestor
    could swap the root out from under ahc. ahc never changes an ancestor: it only refuses."""
    out = []
    here = Path(os.path.realpath(str(Path(root).parent)))
    while True:
        try:
            info = os.stat(str(here))
        except OSError as error:
            out.append("%s (%s)" % (here, type(error).__name__))
            break
        writable = stat.S_IMODE(info.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        if info.st_uid not in (0, _uid()):
            out.append("%s (owned by uid %d)" % (here, info.st_uid))
        elif writable and not info.st_mode & stat.S_ISVTX:
            out.append("%s (writable by group or others, not sticky)" % here)
        if here.parent == here:
            break
        here = here.parent
    return out
