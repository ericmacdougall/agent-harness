"""Private report target pinned to a validated directory inode."""

import os
import secrets
import stat
from pathlib import Path


def same_existing(left: Path, right: Path) -> bool:
    try:
        return left.samefile(right)
    except OSError:
        return False


def inside_worktree(parent: Path, repo: Path) -> bool:
    # samefile catches case aliases and hardlinked/symlinked directory names
    # that Path.resolve() leaves textually different on case-insensitive disks.
    return any(same_existing(candidate, repo) for candidate in (parent, *parent.parents))


class ReportTarget:
    def __init__(self, output: Path, repo: Path, packet: Path):
        self.fd = None
        self.report_fd = None
        if output.is_symlink():
            raise ValueError('output must not be a symlink')
        parent = output.parent.resolve()
        path = parent / output.name
        packet_path = packet.parent.resolve() / packet.name
        if inside_worktree(parent, repo) or same_existing(path, repo):
            raise ValueError('output must be outside the worktree')
        if path == packet_path or same_existing(path, packet):
            raise ValueError('output must differ from packet')
        parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.parent = parent
        self.path = path
        self.packet = packet
        # If a directory changed between resolution and open, refuse writes.
        if not self.directory_is_current() or inside_worktree(parent, repo):
            self.close()
            raise ValueError('output directory changed or is inside the worktree')

    def directory_is_current(self) -> bool:
        try:
            opened = os.fstat(self.fd)
            current = self.parent.stat()
        except OSError:
            return False
        return (opened.st_dev, opened.st_ino) == (current.st_dev, current.st_ino)

    def close(self):
        if self.report_fd is not None:
            os.close(self.report_fd)
            self.report_fd = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __del__(self):
        self.close()

    def require_fresh(self):
        """A report path is single-use; never remove an unrelated existing file."""
        if not self.directory_is_current():
            raise ValueError('output directory changed')
        try:
            os.stat(self.path.name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ValueError('output already exists; choose a fresh report path')

    def write_text(self, content: str):
        if self.report_fd is not None:
            raise OSError('report target is single-use')
        if not self.directory_is_current():
            raise OSError('output directory changed before report write')
        temporary = '.report-' + secrets.token_hex(12)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, 'w') as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
                written = os.fstat(handle.fileno())
                # Keep the inode alive through cleanup and caller WAL work so
                # an unlinked report inode cannot be recycled for a replacement.
                self.report_fd = os.dup(handle.fileno())
            if not self.directory_is_current():
                raise OSError('output directory changed before report publication')
            temporary_info = os.stat(temporary, dir_fd=self.fd, follow_symlinks=False)
            if (not stat.S_ISREG(temporary_info.st_mode) or temporary_info.st_nlink != 1
                    or (temporary_info.st_dev, temporary_info.st_ino) != (written.st_dev, written.st_ino)):
                raise OSError('temporary report changed before publication')
            # An independent file may appear after require_fresh(). Link is
            # atomic and refuses to replace it; unlink the temporary afterward.
            os.link(temporary, self.path.name, src_dir_fd=self.fd, dst_dir_fd=self.fd,
                    follow_symlinks=False)
            os.fsync(self.fd)
        finally:
            # Never remove the public destination: an inode check followed by
            # unlink is not atomic, so another writer's replacement could vanish.
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass
        self.verify_current()

    def verify_current(self):
        """Recheck after cleanup and any caller work, immediately before announcing."""
        if self.report_fd is None or self.fd is None or not self.directory_is_current():
            raise OSError('output directory changed or report was not published')
        visible = os.stat(self.path, follow_symlinks=False)
        published = os.stat(self.path.name, dir_fd=self.fd, follow_symlinks=False)
        written = os.fstat(self.report_fd)
        identity = (written.st_dev, written.st_ino)
        if ((visible.st_dev, visible.st_ino) != identity
                or (published.st_dev, published.st_ino) != identity):
            raise OSError('output path changed during report publication')
