"""Private report target pinned to a validated directory inode."""

import os
import secrets
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
        self.path = path
        self.packet = packet
        # If a directory changed between resolution and open, refuse writes.
        opened = os.fstat(self.fd)
        current = parent.stat()
        if ((opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                or inside_worktree(parent, repo)):
            self.close()
            raise ValueError('output directory changed or is inside the worktree')

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __del__(self):
        self.close()

    def require_fresh(self):
        """A report path is single-use; never remove an unrelated existing file."""
        try:
            os.stat(self.path.name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ValueError('output already exists; choose a fresh report path')

    def write_text(self, content: str):
        temporary = '.report-' + secrets.token_hex(12)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, 'w') as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            # An independent file may appear after require_fresh(). Link is
            # atomic and refuses to replace it; unlink the temporary afterward.
            os.link(temporary, self.path.name, src_dir_fd=self.fd, dst_dir_fd=self.fd,
                    follow_symlinks=False)
            os.fsync(self.fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass
