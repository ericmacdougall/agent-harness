"""Opt-in retirement of one copy or explicit artifact from a verified completed task."""

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

import command_guard
import copy_hygiene
import task_recovery
import workdir


GIT_HEAD = re.compile(r"[a-f0-9]{40}")
ARTIFACT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
B2_TARGET = re.compile(r"([A-Za-z0-9][A-Za-z0-9_-]{0,63}):([A-Za-z0-9][A-Za-z0-9._/-]{0,191})")
SENSITIVE = re.compile(r"(?:^|[._-])(log|logs|wal|wals|credential[s]?|secret[s]?|token[s]?|password[s]?|key[s]?|"
                       r"transcript[s]?|session[s]?|cookie[s]?|auth|env)(?:[._-]|$)", re.IGNORECASE)
PRIVATE_SUFFIXES = {".pem", ".key", ".der", ".pfx", ".p12", ".kdbx", ".sqlite", ".sqlite3", ".db", ".jsonl"}
DEFAULT_BYTES = 256 * 1024 * 1024
MAX_BYTES = 4 * 1024 * 1024 * 1024
ARCHIVE_OVERHEAD = 32 * 1024 * 1024
MAX_ENTRIES = 4096
TOOL_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/bin", "/opt/homebrew/bin")


class Retention(ValueError):
    """A candidate must be preserved."""


def require(condition, reason):
    if not condition:
        raise Retention(reason)


def trusted_tool(name):
    for directory in TOOL_DIRS:
        try:
            path = (Path(directory) / name).resolve(strict=True)
            if not any(base in path.parents for base in map(Path, ("/usr", "/bin", "/sbin", "/opt/homebrew"))):
                continue
            checked = [path, *path.parents]
            if any(info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022
                   for info in (item.stat() for item in checked)):
                continue
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
        except OSError:
            continue
    raise Retention("A trusted installed lsof, Git, mount, or rclone tool is unavailable.")


def tool_env(*, git_auth=False):
    values = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
              "HOME": pwd.getpwuid(os.geteuid()).pw_dir}
    if git_auth and "SSH_AUTH_SOCK" in os.environ:
        values["SSH_AUTH_SOCK"] = os.environ["SSH_AUTH_SOCK"]
    return values


def safe_git(repo, *args):
    result = subprocess.run([trusted_tool("git"), "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                             "-C", repo, *args], env=tool_env(), capture_output=True, timeout=30, text=True)
    return result.returncode, result.stdout.strip()


def guard(path, action, head=None):
    # Run the existing authoritative Git guard with only the trusted system tool directories.
    script = Path(command_guard.__file__).resolve(strict=True)
    argv = [sys.executable, "-I", str(script), action, "--path", str(path), "--remote-auth"]
    if head:
        argv.extend(("--expect-head", head))
    result = subprocess.run(argv, env=tool_env(git_auth=True), capture_output=True, timeout=1100)
    evidence = json.loads(result.stdout)
    require(type(evidence) is dict and evidence.get("verifier") == command_guard.VERIFIER_VERSION,
            "The Git guard outcome was not verified.")
    return evidence


@contextmanager
def completed_task(root):
    parent = workdir.work_root().resolve(strict=True)
    require(root.is_absolute() and root.resolve(strict=True) == root and parent in root.parents,
            "Expected one private enrolled task beneath the harness work root.")
    task_recovery.private(root, True)
    descriptor = os.open(root / "lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        require(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.geteuid()
                and opened.st_nlink == 1 and not opened.st_mode & 0o077, "Unsafe task lock.")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        manifest, state = task_recovery.load(root)
        require(task_recovery.completion_time(state), "Authoritative task completion is missing or uncertain.")
        yield manifest, state
    finally:
        os.close(descriptor)


def idle(path):
    require("HARNESS_COPY_HYGIENE_UNIT_DIRS" not in os.environ, "Service scan test override is active.")
    protected, errors = copy_hygiene.protected_scan()
    require(not errors and not copy_hygiene.protecting(str(path), protected),
            "A service uses this path or its dependencies could not be confirmed.")
    tool = trusted_tool("lsof")
    args = [tool, "-nP", "-t", "+D", str(path)] if path.is_dir() else [tool, "-nP", "-t", "--", str(path)]
    result = subprocess.run(args, env=tool_env(), capture_output=True, timeout=40)
    require(result.returncode == 1 and not result.stdout and not result.stderr,
            "A process is using the path or observations are uncertain.")


def audit_path(task, path):
    return task / ("cleanup-" + hashlib.sha256(str(path).encode()).hexdigest()[:20] + ".json")


def check_previous(audit):
    if os.path.lexists(audit):
        past = json.loads(task_recovery.read(audit))
        require(type(past) is dict and past.get("status") not in ("removing", "uncertain"),
                "A prior removal was not reconciled. Retain the candidate.")


def retire_copy(task, manifest, generation, repo, key, head, apply):
    require(GIT_HEAD.fullmatch(head), "Expected the exact 40-hex checkout commit.")
    code, source = safe_git(repo, "rev-parse", "--show-toplevel")
    require(code == 0 and source.strip(), "Source checkout could not be resolved.")
    source = source.strip()
    ident, _ = copy_hygiene.repo_identity(source, safe_git)
    path = Path(copy_hygiene.copies_root()) / ident / copy_hygiene.safe_key(key)
    require(path.resolve(strict=True) == path and Path(manifest["cwd"]).resolve(strict=True) == path,
            "Completed task does not own the exact reusable copy.")
    prompt = Path(manifest["prompt_file"]).resolve()
    require(prompt != path and path not in prompt.parents, "The task prompt is inside the reusable copy.")
    with copy_hygiene.copy_lock(str(path), create=False, wait=False) as lock:
        require(generation and copy_hygiene.copy_generation(lock) == generation,
                "Copy generation is unavailable or was reacquired after task enrollment.")
        row = copy_hygiene.load_index().get(str(path), {})
        require(row.get("repo") == source and row.get("key") == key, "The copy was not indexed for this key and source.")
        audit = audit_path(task, path)
        check_previous(audit)
        idle(path)
        if not apply:
            result = guard(path, "verify-worktree")
            require(result.get("removable") and result.get("head") == head,
                    "Exact Git origin verification refused; keep the checkout.")
            return {"status": "preview", "task": manifest["task_id"], "path": str(path), "head": head}
        context = {"task": manifest["task_id"], "path": str(path), "head": head, "reason": "verified origin"}
        task_recovery.atomic(audit, dict(context, status="removing"))
        result = guard(path, "remove-worktree", head)
        state = "removed" if result.get("removed") is True else (
            "retained" if result.get("removable") is False else "uncertain"
        )
        answer = dict(context, status=state)
        task_recovery.atomic(audit, answer)
        return answer


def artifact_name(name):
    return (ARTIFACT_NAME.fullmatch(name) and not SENSITIVE.search(name)
            and Path(name).suffix.lower() not in PRIVATE_SUFFIXES and not workdir.is_durable_state_name(name))


def item_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns)


@contextmanager
def directory_fd(path):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    require(path.is_absolute(), "Artifact directory must be absolute.")
    fd = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            opened = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = opened
        yield fd
    finally:
        os.close(fd)


def read_item(path, info):
    with directory_fd(path.parent) as directory:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    handle = os.fdopen(fd, "rb")
    try:
        require(item_identity(os.fstat(fd)) == item_identity(info), "Artifact changed while opening it.")
        return handle
    except BaseException:
        handle.close()
        raise


def digest(handle, bound):
    result = hashlib.sha256()
    size = 0
    for part in iter(lambda: handle.read(1024 * 1024), b""):
        size += len(part)
        require(size <= bound, "Hashed file exceeds the archive limit.")
        result.update(part)
    return result.hexdigest()


def linux_mounts(text):
    result = []
    for line in text.splitlines():
        fields = line.split()
        require(len(fields) >= 10 and "-" in fields[6:] and fields[4].startswith("/"), "Unknown mount table.")
        mount = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4])
        result.append(Path(mount))
    require(result, "Mount table is empty.")
    return result


def mounted_subtree(root):
    if sys.platform == "linux":
        with open("/proc/self/mountinfo", encoding="utf-8", errors="surrogateescape") as mounts:
            text = mounts.read(2 * 1024 * 1024 + 1)
        require(len(text) <= 2 * 1024 * 1024, "Mount table exceeds safe bounds.")
        mounted = linux_mounts(text)
    elif sys.platform == "darwin":
        output = subprocess.run([trusted_tool("mount")], env=tool_env(), capture_output=True,
                                timeout=10, check=True, text=True).stdout
        mounted = []
        for line in output.splitlines():
            _, match, path = line.rsplit(" (", 1)[0].partition(" on ")
            require(match and path.startswith("/"), "Unknown mount table.")
            mounted.append(Path(path))
        require(mounted, "Mount table is empty.")
    else:
        raise Retention("Mount observations are unavailable on this platform.")
    return any(path == root or root in path.parents for path in mounted)


def inventory(root, max_bytes=DEFAULT_BYTES):
    """Bounded per-member identity and digest. Reject the entire subtree on any unapproved member."""
    device = root.lstat().st_dev
    require(device == root.parent.stat().st_dev and not mounted_subtree(root),
            "Artifact contains or is a mounted filesystem.")
    work = [(Path("."), root)]
    items, size = {}, 0
    while work:
        require(len(items) + len(work) <= MAX_ENTRIES, "Artifact subtree has too many entries.")
        relative, path = work.pop()
        info = path.lstat()
        require(info.st_uid == os.geteuid() and info.st_dev == device and not info.st_mode & 0o022,
                "Artifact ownership, filesystem, or permissions differ.")
        if stat.S_ISDIR(info.st_mode):
            with directory_fd(path) as directory, os.scandir(directory) as children:
                require(item_identity(os.fstat(directory)) == item_identity(info), "Artifact directory changed.")
                for child in children:
                    require(artifact_name(child.name) and len(work) + len(items) < MAX_ENTRIES,
                            "Artifact subtree contains protected or excessive entries.")
                    work.append((relative / child.name, path / child.name))
            checksum = None
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "Artifact has a link or special file.")
            size += info.st_size
            require(size <= max_bytes, "Artifact archive size limit exceeded.")
            with read_item(path, info) as source:
                checksum = digest(source, info.st_size)
                require(item_identity(os.fstat(source.fileno())) == item_identity(info), "Artifact changed while hashing.")
        items[relative] = (item_identity(info), checksum)
    return items


class ArchiveMember:
    def __init__(self, file):
        self.file = file
        self.digest = hashlib.sha256()

    def read(self, size):
        data = self.file.read(size)
        self.digest.update(data)
        return data


def archive_tree(root, archive, expected):
    with tarfile.open(archive, "x", format=tarfile.PAX_FORMAT) as output:
        for relative, (identity, checksum) in sorted(expected.items()):
            source = root / relative
            info = source.lstat()
            require(item_identity(info) == identity, "Artifact changed before archive.")
            member = tarfile.TarInfo(str(Path(root.name) / relative))
            member.mode = stat.S_IMODE(info.st_mode) & 0o777
            member.mtime = info.st_mtime_ns // 1_000_000_000
            if checksum is None:
                member.type = tarfile.DIRTYPE
                output.addfile(member)
            else:
                member.size = info.st_size
                with read_item(source, info) as handle:
                    reader = ArchiveMember(handle)
                    output.addfile(member, reader)
                    require(reader.digest.hexdigest() == checksum
                            and item_identity(os.fstat(handle.fileno())) == identity,
                            "Artifact changed while writing the archive.")


def rclone(tool, *args, timeout):
    return subprocess.run([tool, "--tpslimit", "2", *args], env=tool_env(), timeout=timeout, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout


def store_archive(task, task_id, target, path, snapshot, max_bytes):
    require(target and B2_TARGET.fullmatch(target) and not any(part in (".", "..", "")
            for part in target.split(":", 1)[1].rstrip("/").split("/")),
            "Select an explicit configured B2 remote and bucket prefix.")
    tool = trusted_tool("rclone")
    remote = target.split(":", 1)[0]
    listed = rclone(tool, "listremotes", "--long", timeout=15).decode("utf-8").splitlines()
    require([remote + ":", "b2"] in [line.split() for line in listed], "Archive destination is not a configured B2 remote.")
    require(shutil.disk_usage(task).free > sum(item[0][3] for item in snapshot.values() if item[1] is not None)
            + ARCHIVE_OVERHEAD, "Insufficient scratch space to stage the bounded archive.")
    with tempfile.TemporaryDirectory(prefix="cleanup-stage-", dir=task) as folder:
        folder = Path(folder)
        initial = folder / "archive.tar"
        archive_tree(path, initial, snapshot)
        with initial.open("rb") as handle:
            checksum = digest(handle, max_bytes + ARCHIVE_OVERHEAD)
        name = checksum + ".tar"
        staged = initial.rename(folder / name)
        destination = target.rstrip("/") + "/harness-artifacts/" + task_id
        full = destination + "/" + name
        rclone(tool, "copyto", "--immutable", "--", str(staged), full, timeout=1800)
        observed = rclone(tool, "check", "--download", "--one-way", "--combined", "-",
                          "--include", "/" + name, "--", str(folder), destination, timeout=1800)
        require(observed.decode("utf-8").splitlines() == ["= " + name],
                "B2 download verification did not confirm the exact staged archive.")
    return full, checksum


def retire_artifact(task, manifest, name, target, apply, max_bytes=DEFAULT_BYTES):
    require(artifact_name(name), "Expected one explicitly selected artifact name.")
    require(type(max_bytes) is int and 0 < max_bytes <= MAX_BYTES, "Artifact byte limit must be 1 byte to 4 GiB.")
    base = task / "artifacts"
    task_recovery.private(base, True)
    path = base / name
    require(path.resolve(strict=True) == path, "Artifact path is not a regular unredirected subtree.")
    audit = audit_path(task, path)
    check_previous(audit)
    idle(path)
    before = inventory(path, max_bytes)
    context = {"task": manifest["task_id"], "path": str(path), "entries": len(before)}
    if not apply:
        return dict(context, status="preview")
    task_recovery.atomic(audit, dict(context, status="archiving"))
    try:
        remote, checksum = store_archive(task, manifest["task_id"], target, path, before, max_bytes)
        context.update(archive=remote, sha256=checksum)
        require(inventory(path, max_bytes) == before, "Artifact changed after backup. Keep the current source.")
        idle(path)
        require(item_identity(path.lstat()) == before[Path(".")][0], "Artifact changed before retirement.")
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError):
        task_recovery.atomic(audit, dict(context, status="retained"))
        raise
    if path.is_dir():
        require(shutil.rmtree.avoids_symlink_attacks, "This platform cannot safely remove a scoped artifact directory.")
    quarantine = Path(tempfile.mkdtemp(prefix="cleanup-quarantine-", dir=task)) / name
    task_recovery.atomic(audit, dict(context, status="removing", quarantine=str(quarantine)))
    try:
        with directory_fd(path.parent) as source, directory_fd(quarantine.parent) as target:
            require(item_identity(os.stat(path.name, dir_fd=source, follow_symlinks=False)) == before[Path(".")][0],
                    "Artifact identity changed before quarantine.")
            os.rename(path.name, quarantine.name, src_dir_fd=source, dst_dir_fd=target)
        require(inventory(quarantine, max_bytes) == before, "Artifact changed while being retired. Keep its quarantine.")
        idle(quarantine)
        require(not mounted_subtree(quarantine), "A mount appeared before retirement. Keep its quarantine.")
        if quarantine.is_dir():
            shutil.rmtree(quarantine)
        else:
            quarantine.unlink()
        quarantine.parent.rmdir()
    except (OSError, ValueError, subprocess.SubprocessError):
        task_recovery.atomic(audit, dict(context, status="uncertain", quarantine=str(quarantine)))
        raise
    result = dict(context, status="removed")
    task_recovery.atomic(audit, result)
    return result


def run(args):
    try:
        task = Path(args.task_dir)
        with completed_task(task) as (manifest, state):
            if args.cmd == "finish":
                result = retire_copy(task, manifest, state.get("copy_generation"), args.repo, args.key,
                                     args.expect_head, args.apply)
            else:
                limit = DEFAULT_BYTES if args.max_bytes is None else args.max_bytes
                result = retire_artifact(task, manifest, args.name, args.b2_remote, args.apply, limit)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        reason = str(error) if isinstance(error, Retention) else type(error).__name__
        result = {"status": "retained-or-uncertain", "reason": reason}
    print(json.dumps(result))
    return 0 if result["status"] in ("preview", "removed") else 2
