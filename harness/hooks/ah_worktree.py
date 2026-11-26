"""`ah worktree-remove`: free ONE dead linked git worktree on this machine or a configured remote host.

It hands a literal path to the fixed verifier `ah_worktree.py free-worktree` ON the target host (this file, run there),
which applies the user's rules of 2026-11-24 (see free_worktree below):
  * any agent: a worktree with no uncommitted changes whose HEAD is on a remote branch (or merged), or whose owning
    session has ended, is removed (a commit only it reaches is saved to refs/rescue/<name> first);
  * --rescue: uncommitted changes go to a patch under the caller's work dir and unpushed commits to
    refs/rescue/<name>, then it is removed --force (nothing is lost, so no role is asked; release 1001).
A process working inside the worktree still stops it. No ticket, WAL note or reason is required (--reason is logged
when given). `--remote-auth` is accepted for old callers and ignored: the new verifier reads no remote.

The caller's audit row is written before anything runs (fail closed) and again with the outcome; the verifier writes its
own row on the target host.
"""
from __future__ import annotations

import errno
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _remote_hosts():
    """~/.agent-harness/local.json `remote_worktree_hosts` (plain host names); none by default."""
    try:
        if str(HERE) not in sys.path:
            sys.path.insert(0, str(HERE))
        import ah_local  # noqa: PLC0415
        return tuple(h for h in ah_local.str_list("remote_worktree_hosts") if re.fullmatch(r"[A-Za-z0-9._-]{1,60}", h)
                     and h != "local")
    except Exception:  # noqa: BLE001
        return ()


REMOTE_HOSTS = _remote_hosts()
HOSTS = ("local",) + REMOTE_HOSTS
MAX_REASON = 500
VERIFIER_VERSION = 3
PATH_RE = re.compile(r"/[A-Za-z0-9_@+=:,.-]+(?:/[A-Za-z0-9_@+=:,.-]+)*")


class WorktreeError(Exception):
    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code, self.exit_code = code, exit_code


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _redact(text):
    return re.sub(r"(?i)(token|password|secret|key|authorization)[=: ]+\S+", r"\1=[redacted]", str(text))


def _skipped(result):
    """The verifier's list of unreadable processes it skipped (goodqa#15870), as at most 20 short printable strings, or None."""
    items = result.get("skipped_processes")
    if not isinstance(items, list):
        return None
    return [re.sub(r"[^\x20-\x7e]", "?", str(item))[:60] for item in items[:20]]


def audit(home, record):
    """Append one JSON row; raises when it cannot (the caller stops before acting)."""
    path = Path(home) / ".agent-harness" / "worktree-audit.jsonl"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    record = dict(record, at=_now(), by="ah")
    for key in ("reason", "why"):
        if record.get(key):
            record[key] = _redact(record[key])[:MAX_REASON]
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def check_path(path):
    if not isinstance(path, str) or not 2 <= len(path) <= 1024 or not PATH_RE.fullmatch(path) or ".." in path.split("/"):
        raise WorktreeError("bad_request", "--path must be one literal absolute path (letters, digits and _@+=:,.- only, "
                            "no dot segments, no trailing slash)")
    return path


def _argv(host, path, authenticated=False, rescue=False, session="", dry_run=False):
    tail = ["free-worktree", "--path", path] + (["--rescue"] if rescue else []) + (["--dry-run"] if dry_run else [])
    if session and re.fullmatch(r"[0-9A-Fa-f-]{8,64}", session):
        tail += ["--session", session]
    if host == "local":
        return [sys.executable, "-I", str(HERE / "ah_worktree.py"), *tail]
    cmd = "python3 -I .claude/hooks/ah_worktree.py " + " ".join(shlex.quote(t) for t in tail)
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", host, cmd]


# The longest a healthy call can take, from the verifier's own bounds: verification VERIFY_SECONDS (120), the process
# scan (lsof 20), git's removal REMOVE_SECONDS (900), the ssh connect (10) and slack for JSON and startup (50). A large
# removal is a long call: run it in the background, it is not meant for a foreground tool call.
VERIFY_SECONDS, SCAN_SECONDS, REMOVE_SECONDS, CONNECT_SECONDS, SLACK_SECONDS = 120, 20, 900, 10, 50
CALL_TIMEOUT = VERIFY_SECONDS + SCAN_SECONDS + REMOVE_SECONDS + CONNECT_SECONDS + SLACK_SECONDS


UNKNOWN = "the outcome is unknown: the removal may already have happened, check the host before retrying"


def _call(runner, host, path, authenticated, rescue=False, session="", dry_run=False):
    """Run the verifier. Once the runner has started, every failure here leaves the outcome UNKNOWN: the remote command
    keeps running after an ssh client dies and a garbled answer may still come from a verifier that removed the tree,
    so no message from here says that nothing was removed."""
    try:
        done = runner(_argv(host, path, authenticated, rescue, session, dry_run), capture_output=True, text=True,
                      timeout=CALL_TIMEOUT)
        data = json.loads(done.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        raise WorktreeError("host_unreachable", "could not run the verifier on %s (%s)" % (host, UNKNOWN), 3)
    if not isinstance(data, dict) or not isinstance(data.get("removable"), bool):
        raise WorktreeError("host_unreachable", "unexpected answer from the verifier on %s (%s)" % (host, UNKNOWN), 3)
    if data.get("verifier") != VERIFIER_VERSION:
        raise WorktreeError("verifier_outdated", "the verifier on %s is not version %d: install release 1001 there "
                            "(install.py --apply) (%s)" % (host, VERIFIER_VERSION, UNKNOWN), 3)
    if data.get("removed") not in (None, True, False):
        raise WorktreeError("host_unreachable", "malformed answer from %s (%s)" % (host, UNKNOWN), 3)
    if data["removable"] is False and data.get("removed") is True:
        # a verifier that refused cannot also have removed: the answer contradicts itself (receipt r5 N1)
        raise WorktreeError("host_unreachable", "contradictory answer from %s (%s)" % (host, UNKNOWN), 3)
    return data


def remove(host, path, reason=None, authenticated=False, session="", agent="", home=None, runner=subprocess.run,
           rescue=False, dry_run=False):
    if host not in HOSTS:
        raise WorktreeError("bad_request", "--host must be one of %s" % ", ".join(HOSTS))
    path = check_path(path)
    reason = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", (reason or "").strip())[:MAX_REASON] or "not given"
    if host == "local":
        cwd = os.path.realpath(os.getcwd())
        if cwd == path or cwd.startswith(path + os.sep):
            raise WorktreeError("bad_request", "the current directory is inside the worktree being removed")
    home = Path(home or Path.home())
    run_id = "wtr-" + uuid.uuid4().hex[:12]
    who = {"session": session or None, "agent": agent or None}
    try:
        audit(home, {"event": "start", "run": run_id, "host": host, "path": path, "reason": reason,
                     "rescue": bool(rescue), "dry_run": bool(dry_run), "caller": who})
    except OSError:
        raise WorktreeError("audit_failed", "could not write the audit row; nothing was run, nothing was removed", 3)
    # Once the runner has been started the outcome is UNKNOWN until the verifier answers: a killed ssh client does not stop
    # the remote command, so "no answer" is never recorded as "not removed" (removed: null).
    outcome = {"event": "result", "run": run_id, "host": host, "path": path, "removed": None,
               "why": "no answer from the verifier (outcome unknown)"}
    try:
        result = _call(runner, host, path, authenticated, rescue, session, dry_run)
        # A definite outcome needs a definite answer: `removable: false` is a refusal (nothing ran); `removable: true`
        # needs a real boolean `removed`, and a null or missing one is an unknown outcome (red-team r4 F2).
        partly = False
        if result.get("removable") is False:
            removed = False
        elif isinstance(result.get("removed"), bool):
            removed = result["removed"]
            if removed is False:
                # removable true and not removed: the removal STARTED and did not complete (a timeout, a git error after it
                # began deleting). The tree may be partly deleted, and the verifier cannot always tell a clean failure
                # from a partial one, so it is not recorded as a definite "not removed" (receipt r5 N2).
                removed, partly = None, True
        else:
            removed = None
        if partly:
            why = (result.get("reason") or "") + " (the removal started and did not complete: the worktree may be partly " \
                                                 "deleted, check the host before retrying)"
        else:
            why = result.get("reason") if removed is not None else (result.get("reason") or "") + " (" + UNKNOWN + ")"
        outcome.update(removed=removed, head=result.get("head"), freed_bytes=result.get("freed_bytes"),
                       directory_removed=result.get("directory_removed"),
                       registry_entry_left=result.get("registry_entry_left"), why=why,
                       skipped_processes=_skipped(result))
    except WorktreeError as error:
        outcome.update(why="%s: %s (outcome unknown, check the host)" % (error.code, error))
        raise
    finally:
        try:
            audit(home, outcome)
        except OSError:
            outcome["audit_warning"] = "the outcome row could not be written"
    answer = {"ok": removed is True, "run": run_id, "host": host, "path": path, "removed": removed,
              "head": result.get("head"), "freed_bytes": result.get("freed_bytes"),
              "reason": _redact(outcome["why"] or "") or None,
              "directory_removed": result.get("directory_removed"),
              "registry_entry_left": result.get("registry_entry_left"),
              "skipped_processes": outcome.get("skipped_processes"),
              "rescue_ref": result.get("rescue_ref"), "patch": result.get("patch")}
    if dry_run:
        answer.update(ok=bool(result.get("removable")), removed=False, would=result.get("would"))
    if "audit_warning" in outcome:
        answer["audit_warning"] = outcome["audit_warning"]
    step = next_step(result)
    if step:
        answer["next"] = step
    return answer


NEXT_STALE = ("run `git fetch --prune <the remote that holds the deleted branch>` in the registry repository (the checkout "
              "the worktree was added from) on the same host first, but only when every fetch refspec of that remote "
              "writes under refs/remotes/<that remote>/ and pruneTags is not set; prune deletes local branches or tags "
              "through any other destination (for example +refs/*:refs/* or +refs/heads/*:refs/heads/up/*). Then "
              "repeat the same ah worktree-remove call")


def next_step(result):
    """The fixed next step for a stale-tracking-ref refusal (goodqa#16943), or None. The verifier keeps that rule. The
    text names no path, host or remote: a value read from the repository can be wrong or harmful to run (#333 review
    rounds 1 and 2), so the caller fills in the remote it knows."""
    if result.get("removable") is not False or "stale or names a moved" not in str(result.get("reason") or ""):
        return None
    return NEXT_STALE


# ------------------------------------------------------------------ the verifier, run ON the target host
# Moved verbatim from command_guard.py (deleted in release 1001) with the helpers it calls: `ah_worktree.py
# free-worktree --path P [--rescue] [--session S] [--dry-run]` prints one JSON result. It reads the real worktree (git
# state, processes inside it, the owning session's end) and never a command line.

CLONE_ENV_KEEP = ('PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'SSH_AUTH_SOCK', 'USER', 'LOGNAME')


def _clone_env():
    env = {k: os.environ[k] for k in CLONE_ENV_KEEP if k in os.environ}
    env['PATH'] = os.pathsep.join(p for p in env.get('PATH', '').split(os.pathsep) if p.startswith('/')) or '/usr/bin:/bin'
    env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0', GIT_OPTIONAL_LOCKS='0',
               GIT_ATTR_NOSYSTEM='1', GIT_ASKPASS='/bin/true', GIT_CEILING_DIRECTORIES=os.path.dirname(os.sep))
    return env


def _git_out(repo, args, timeout, stdin=None):
    import subprocess
    done = subprocess.run(['git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
                           '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
                           '-c', 'protocol.ssh.allow=always', '-c', 'protocol.git.allow=always', '-C', repo] + list(args),
                          capture_output=True, timeout=max(0.2, timeout), env=_clone_env(),
                          input=stdin.encode() if stdin is not None else None)
    if done.returncode != 0 or len(done.stdout) > 8 * 1024 * 1024:
        raise ValueError('git %s failed' % (args[0] if args else ''))
    return done.stdout.decode('utf-8', 'surrogateescape')


WORKTREE_HOME_DENY = ('.claude', '.codex', '.ssh', '.config', '.gnupg', '.aws', '.kimi-code', 'library', '.trash')


def worktree_scope_refusal(path, *, _managed_copy=None):
    """Where `ah worktree-remove` may act: strictly under the caller's home, never the home itself, never the harness
    or credential state, and under ~/.agent-harness only inside work/. Names are compared case-folded (APFS is case
    insensitive)."""
    home = os.path.realpath(os.path.expanduser('~'))
    if not path.casefold().startswith(home.casefold() + os.sep):
        return 'the path is outside the home directory'
    parts = path[len(home) + 1:].split(os.sep)
    if parts[0].casefold() in WORKTREE_HOME_DENY:
        return 'the path is inside protected state (%s)' % parts[0][:30]
    if parts[0].casefold() == '.agent-harness' and (len(parts) < 3 or parts[1].casefold() != 'work'):
        # Only the isolated lifecycle worker supplies this internal exact scope after acquiring both named
        # locks and validating the completed task, allocation, repository and generation.
        if (_managed_copy == path and len(parts) == 4 and parts[:2] == ['.agent-harness', 'test-copies']
                and all(re.fullmatch(r'[A-Za-z0-9._-]+', part) and part not in ('.', '..') for part in parts[2:])):
            return None
        return 'under ~/.agent-harness only a worktree inside work/ is removable'
    return None


def _proc_status(pid):
    """{'name': Name, 'uid': real uid, 'ppid': parent pid} from /proc/PID/status, which any user can read whatever the process set about
    being inspected; 'gone' when the process has exited; None when it cannot be read or parsed. The real uid is used, not
    the owner of /proc/PID: a same-user process that made itself non-dumpable shows /proc/PID owned by root, and the
    owner would call it another user's (red-team F4)."""
    try:
        name = uid = ppid = None
        with open('/proc/%s/status' % pid) as handle:
            for line in handle:
                if line.startswith('Name:'):
                    name = line.partition(':')[2].strip()
                elif line.startswith('Uid:'):
                    uid = int(line.partition(':')[2].split()[0])
                elif line.startswith('PPid:'):
                    ppid = int(line.partition(':')[2].split()[0])
        return {'name': name, 'uid': uid, 'ppid': ppid} if uid is not None else None
    except (FileNotFoundError, ProcessLookupError):
        return 'gone'
    except (OSError, ValueError, IndexError):
        return None


def _proc_cmd0(pid):
    """The basename of argv[0] from /proc/PID/cmdline (world readable), or None when it cannot be read or is empty."""
    try:
        with open('/proc/%s/cmdline' % pid, 'rb') as handle:
            first = handle.read(4096).split(b'\x00')[0]
    except OSError:
        return None
    return os.path.basename(first.decode('utf-8', 'replace')) or None


def _proc_args(pid):
    """The command line of PID from /proc/PID/cmdline as one string (NULs read as spaces, bounded), '' when the process has
    an empty command line, None when it cannot be read."""
    try:
        with open('/proc/%s/cmdline' % pid, 'rb') as handle:
            return handle.read(8192).replace(b'\x00', b' ').decode('utf-8', 'replace')
    except OSError:
        return None


def _proc_start(pid):
    """When PID started, as seconds since the epoch (/proc/PID/stat field 22 and the boot time in /proc/stat), or None."""
    try:
        with open('/proc/%s/stat' % pid) as handle:
            fields = handle.read().rpartition(')')[2].split()
        ticks = int(fields[19])  # field 22 overall; the first two (pid, comm) are before the closing parenthesis
        with open('/proc/stat') as handle:
            boot = next(int(line.split()[1]) for line in handle if line.startswith('btime '))
        return boot + ticks / float(os.sysconf('SC_CLK_TCK'))
    except (OSError, ValueError, IndexError, StopIteration):
        return None


def _worktree_created(path):
    """When the linked worktree was created: the modification time of its `.git` file (written once by `git worktree add`),
    or None when it cannot be read."""
    try:
        return os.lstat(os.path.join(path, '.git')).st_mtime
    except OSError:
        return None


# What may sit in a working directory and was started by a person or an agent: a shell, an interpreter, an editor, a
# privilege wrapper or a build tool. An unreadable one of these always refuses (goodqa#15739: an interactive shell run
# through sg).
UNREADABLE_ALWAYS_REFUSES = {'sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'fish', 'csh', 'tcsh', 'busybox', 'mksh', 'pwsh',
                             'powershell', 'tmux', 'screen', 'vi', 'vim', 'nvim', 'nano', 'emacs', 'less', 'more', 'man',
                             'make', 'git', 'ssh', 'xargs', 'watch', 'python', 'python2', 'python3', 'node', 'nodejs',
                             'perl', 'ruby', 'php', 'deno', 'bun', 'lua', 'java', 'go', 'cargo', 'npm', 'pnpm', 'yarn',
                             'pip', 'uv'}


# Known long-lived helpers that never work in a project directory: an unreadable one is skipped whatever its start time
# (the user systemd manager and its sd-pam helper, the ssh and gpg agents, a tailscaled session helper). The name AND the command line must agree; both can be set by the process
# itself, which is a stated limit (accident prevention, not an access control).
UNREADABLE_KNOWN_HELPERS = (('(sd-pam)', ''), ('systemd', '--user'), ('ssh-agent', ''), ('gpg-agent', ''),
                            ('tailscaled', ' be-child '))


def unreadable_verdict(pid, name, path, created):
    """None when an unreadable same-user process may be skipped, else a short reason it still refuses. The process' own
    working directory cannot be read (a setgid or privilege-separation helper, an sd-pam or sg-docker wrapper), so this is
    judged from the worktree side, in this order: an unreadable command line refuses; a command line naming the worktree
    refuses; a shell, editor or interpreter always refuses; a known long-lived helper (name AND command line agree) is
    skipped whatever its start time; every other process is judged by time, because it cannot have been launched from the
    worktree before the worktree existed: it is skipped and REPORTED only when it started before the worktree was created,
    and refuses when it started after or when a start time is unknown. Stated limit: names and command lines can be set by the process itself, and a skipped process may still
    have the worktree as its working directory (its directory is then deleted under it, no data is lost: the worktree is
    clean and published); this protects against accident, not against a hostile same-user process."""
    base = (name or '').strip().lower()
    args = _proc_args(pid)
    if args is None:
        return 'its command line cannot be read'
    if path in args or os.path.realpath(path) in args:
        return 'its command line names the worktree'
    if base in UNREADABLE_ALWAYS_REFUSES:
        return 'it is a %s, which may sit in the worktree' % base
    for helper, marker in UNREADABLE_KNOWN_HELPERS:
        if base == helper and marker in (' ' + args + ' ' if marker.startswith(' ') else args):
            return None  # a known long-lived helper: skipped whatever its start time
    started = _proc_start(pid)
    if started is None or created is None or started >= created:
        return 'it started after the worktree was created, or a start time is unknown'
    return None


def busy_scan(path, skip_names=(), created=None):
    """Scan the processes for one whose working directory is the worktree or inside it. Returns {'busy': [(pid, command)],
    'unreadable': [(pid, name)], 'failed': bool}: `unreadable` lists processes of THIS user whose cwd link cannot be read
    and that are not on the service list (a shell run through sg or sudo, a setgid helper), `failed` is set when the scan
    could not be completed at all (fail closed). A process that has exited (ENOENT, ESRCH) is skipped, and so is one that
    cannot be read because its REAL uid (from the world-readable /proc/PID/status) is another user's (a Linux host has
    root daemons whose /proc/PID/cwd a normal user cannot read; goodqa#15739); a same-user unreadable process is skipped
    only by exact Name in `skip_names`. Limits, stated: other users' processes are invisible without root, and open files
    other than the working directory are not checked; plain `git worktree remove` also deletes ignored files."""
    result = {'busy': [], 'unreadable': [], 'skipped': [], 'failed': False}
    ancestors, walk = set(), os.getpid()
    for _ in range(64):  # the parent chain of this scanner, from /proc/PID/status (readable for every process)
        try:
            status = _proc_status(str(walk))
        except Exception:  # noqa: BLE001 - best effort: not learning the ancestors only means fewer skips (fail closed)
            break
        if not isinstance(status, dict) or not isinstance(status.get('ppid'), int) or status['ppid'] <= 1:
            break
        walk = status['ppid']
        ancestors.add(walk)
    try:
        if os.path.isdir('/proc/self'):
            for entry in os.listdir('/proc'):
                if entry.isdigit() and int(entry) != os.getpid():
                    try:
                        cwd = os.readlink('/proc/%s/cwd' % entry)
                    except OSError as error:
                        if error.errno in (errno.ENOENT, errno.ESRCH):
                            continue  # exited while we looked
                        if error.errno not in (errno.EACCES, errno.EPERM):
                            result['failed'] = True  # any other error: a process we could not see
                            return result
                        status = _proc_status(entry)
                        if status == 'gone':
                            continue  # exited between the two reads
                        if status is None:
                            result['failed'] = True  # an identity we cannot determine is a process we could not see
                            return result
                        if status['uid'] != os.getuid():
                            # Another user's process is invisible without root (the documented limit). A process whose real uid
                            # is 0 and whose parent is a process of THIS user (sudo -s, sudo -i run from the callers shell) is
                            # the caller's own work, not a daemon: it is listed and refuses. A boot-time root daemon (parent
                            # root or init) and a kernel thread (parent 0 or 2) are skipped; a parent that cannot be read
                            # does not make a root process skippable.
                            if status['uid'] == 0 and status.get('ppid') not in (0, 2):
                                parent = _proc_status(str(status.get('ppid')))
                                if not isinstance(parent, dict) or parent['uid'] == os.getuid():
                                    result['unreadable'].append((int(entry), status['name'] or '?'))
                            continue
                        # A same-user process whose cwd link is unreadable is skipped only for the few programs that are known
                        # to change to / when they start (the user systemd manager, ssh-agent): the process Name must be on the
                        # policy list AND the command line (argv[0] basename) must agree. comm can be set by the process itself
                        # (prctl PR_SET_NAME, exec -a) and so can argv[0]: this protects against accident, not against a
                        # hostile same-user process; it is a standing limit, not a control. Anything else (a shell run through
                        # sg, the docker client, a helper, any other name, an unreadable command line) is reported and refuses.
                        if skip_names and status['name'] in skip_names and _proc_cmd0(entry) == status['name']:
                            continue
                        # Judged from the worktree side (goodqa#15870): a setgid or sd-pam helper that cannot be read is
                        # skipped and reported unless something ties it to the worktree (see unreadable_verdict).
                        # the scanner's own ancestors are the caller's session (an ssh login can run under an unreadable
                        # `tailscaled be-child` whose command line carries the very command being run): never a reason to refuse
                        if int(entry) in ancestors or unreadable_verdict(entry, status['name'], path, created) is None:
                            result['skipped'].append((int(entry), status['name'] or '?'))
                            continue
                        result['unreadable'].append((int(entry), status['name'] or '?'))
                        continue
                    if cwd == path or cwd.startswith(path + os.sep):
                        result['busy'].append((int(entry), 'pid'))
            return result
        done = subprocess.run(['lsof', '-a', '-d', 'cwd', '-F', 'pcn'], capture_output=True, text=True, timeout=20,
                              env={'PATH': '/usr/sbin:/usr/bin:/bin', 'LC_ALL': 'C'}, cwd=os.sep)
        if done.returncode not in (0, 1) or (done.returncode == 1 and (done.stderr or '').strip()):
            result['failed'] = True  # exit 1 is "nothing found" only when lsof said nothing else
            return result
        pid = command = None
        for line in done.stdout.splitlines():
            if line.startswith('p') and line[1:].isdigit():
                pid, command = int(line[1:]), ''
            elif line.startswith('c'):
                command = line[1:40]
            elif line.startswith('n') and pid != os.getpid():
                name = os.path.realpath(line[1:]) if line[1:].startswith('/') else line[1:]
                if name == path or name.startswith(path + os.sep):
                    result['busy'].append((pid, command))
        return result
    except (OSError, subprocess.SubprocessError, ValueError):
        result['failed'] = True
        return result


def registry_lists(repo, path):
    """Whether `git worktree list --porcelain` run in `repo` names exactly `path` (compared line by line, not as a
    substring: /x/wt-1 is not /x/wt-10). Raises on a git failure."""
    listing = _git_out(repo, ['worktree', 'list', '--porcelain'], 10.0)
    return any(os.path.realpath(line[len('worktree '):]) == path for line in listing.splitlines()
               if line.startswith('worktree '))


def _worktree_audit(record):
    """One row in the target host's own ~/.agent-harness/worktree-audit.jsonl; never raises."""
    try:
        folder = os.path.join(os.path.expanduser('~'), '.agent-harness')
        os.makedirs(folder, mode=0o700, exist_ok=True)
        record = dict(record, at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), by='ah_worktree')
        fd = os.open(os.path.join(folder, 'worktree-audit.jsonl'),
                     os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, (json.dumps(record, separators=(',', ':')) + '\n').encode())
        finally:
            os.close(fd)
    except (OSError, TypeError, ValueError):
        pass


FREE_VERIFIER_VERSION = 3


SESSION_ENDED_SECONDS = 2 * 3600


_SESSION_ID = re.compile(r'^[0-9a-fA-F-]{8,64}$')


def worktree_owner_session(path, home=None):
    """The session id from a ~/.agent-harness/work/<session>/... path, or None."""
    home = os.path.realpath(home or os.path.expanduser('~'))
    base = os.path.join(home, '.agent-harness', 'work') + os.sep
    if not path.startswith(base):
        return None
    sid = path[len(base):].split(os.sep, 1)[0]
    return sid if _SESSION_ID.match(sid) else None


def session_ended(session, home=None, now=None, seconds=SESSION_ENDED_SECONDS):
    """True when nothing of `session` (its transcripts, its WAL directory) changed for `seconds`. Unknown: False."""
    if not session or not _SESSION_ID.match(session):
        return False
    home = home or os.path.expanduser('~')
    now = time.time() if now is None else now
    import glob
    places = glob.glob(os.path.join(home, '.claude', 'projects', '*', session + '.jsonl'))
    places += glob.glob(os.path.join(home, '.claude', 'projects', '*', session, 'subagents', '*.jsonl'))
    places += [os.path.join(home, '.claude', 'wals', session)]
    places += glob.glob(os.path.join(home, '.codex', 'sessions', '*', '*', '*', '*' + session + '*.jsonl'))
    newest = 0.0
    for place in places:
        try:
            newest = max(newest, os.stat(place).st_mtime)
        except OSError:
            continue
    return now - newest >= seconds


def _rescue_name(path, head):
    base = re.sub(r'[^A-Za-z0-9._-]', '-', os.path.basename(path.rstrip(os.sep)) or 'worktree')[:60].strip('.-') or 'wt'
    return '%s-%s' % (base, head[:12])


def free_worktree_state(path, home=None, now=None):
    """Facts for one linked worktree, or {'reason': why it is not one}. Never raises."""
    facts = {'path': path, 'reason': None}
    try:
        if not isinstance(path, str) or not os.path.isabs(path) or os.path.realpath(path) != path \
                or not os.path.isdir(path):
            return dict(facts, reason='not a literal absolute directory path without symlinks')
        reason = worktree_scope_refusal(path)
        if reason:
            return dict(facts, reason=reason)
        marker = os.path.join(path, '.git')
        if os.path.islink(marker) or not os.path.isfile(marker):
            return dict(facts, reason='.git is not a plain file (not a linked worktree)')
        top = os.path.realpath(_git_out(path, ['rev-parse', '--show-toplevel'], 10.0).strip())
        if top != path:
            return dict(facts, reason='the path is not the top of its worktree')
        listing = _git_out(path, ['worktree', 'list', '--porcelain'], 10.0)
        trees = [os.path.realpath(line[len('worktree '):]) for line in listing.splitlines() if line.startswith('worktree ')]
        if len(trees) < 2 or trees[0] == path or path not in trees:
            return dict(facts, reason='the path is not a non-primary entry in the worktree registry')
        if any(o != path and (o.startswith(path + os.sep)) for o in trees):
            return dict(facts, reason='another worktree is nested inside it')
        facts['repo'] = trees[0]
        try:
            facts['head'] = _git_out(path, ['rev-parse', '--verify', 'HEAD'], 10.0).strip()
        except ValueError:
            facts['head'] = None  # an unborn branch: nothing committed to lose
        status = _git_out(path, ['status', '--porcelain=v1', '-z', '--untracked-files=all'], 60.0)
        facts['dirty'] = [e[3:] for e in status.split('\x00') if len(e) > 3][:20]
        facts['dirty_count'] = len([e for e in status.split('\x00') if len(e) > 3])
        head = facts['head']
        published = False
        if head:
            published = bool(_git_out(path, ['for-each-ref', '--count=1', '--contains', head, 'refs/remotes'], 30.0).strip())
        facts['published'] = published
        facts['kept_by_ref'] = bool(head) and bool(_git_out(path, ['for-each-ref', '--count=1', '--contains', head,
                                                                    'refs/heads', 'refs/tags', 'refs/rescue'], 30.0).strip())
        facts['owner_session'] = worktree_owner_session(path, home)
        facts['session_ended'] = session_ended(facts['owner_session'], home, now)
        scan = busy_scan(path, ('systemd', 'ssh-agent'), _worktree_created(path))
        facts['busy'] = scan['busy'][:3]
        facts['scan_note'] = 'process scan incomplete' if scan['failed'] or scan['unreadable'] else None
    except Exception as error:  # noqa: BLE001
        return dict(facts, reason='could not read the worktree (%s)' % type(error).__name__)
    return facts


def free_worktree(path, rescue=False, patch_dir=None, dry_run=False, home=None, now=None):
    """Decide and (unless dry_run) remove one linked worktree. Returns the JSON report ah_worktree prints."""
    report = {'path': path, 'removable': False, 'removed': False, 'verifier': FREE_VERIFIER_VERSION, 'reason': None,
              'head': None, 'repo': None}
    facts = free_worktree_state(path, home, now)
    report.update({k: facts.get(k) for k in ('head', 'repo', 'dirty_count', 'published', 'owner_session',
                                             'session_ended', 'scan_note')})
    if facts.get('reason'):
        report['reason'] = facts['reason']
        return report
    if facts['busy']:
        report['reason'] = 'a process is using the worktree as its working directory (pid %d, %s)' % facts['busy'][0]
        return report
    dirty, head = facts['dirty_count'] > 0, facts['head']
    free = not dirty and (facts['published'] or facts['session_ended'] or not head)
    if not free and not rescue:
        why = ('it has %d uncommitted change(s)' % facts['dirty_count']) if dirty else (
            'its HEAD is not on a remote branch and its session %s is still active' % (facts['owner_session'] or '(unknown)'))
        report['reason'] = (why + '; a supervisor of the project or a Fable/Astra agent may run the same command with '
                            '--rescue (it saves the commits to refs/rescue/<name> and the changes to a patch first)')
        return report
    report['removable'] = True
    name = _rescue_name(path, head or 'unborn')
    if dry_run:
        report['would'] = {'rescue_ref': 'refs/rescue/' + name if head and not facts['published'] else None,
                           'patch': bool(dirty), 'force': bool(dirty)}
        return report
    try:
        if head and not facts['published']:
            _git_out(path, ['update-ref', 'refs/rescue/' + name, head], 30.0)  # shared refs: lives in the primary repo
            report['rescue_ref'] = 'refs/rescue/' + name
        if dirty:
            directory = patch_dir or os.path.join(os.path.expanduser('~'), '.agent-harness', 'rescue')
            os.makedirs(directory, mode=0o700, exist_ok=True)
            patch = os.path.join(directory, '%s-%s.patch' % (name, time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())))
            with tempfile_index(path) as env:
                _git_env_run(path, ['add', '-A'], env)
                diff = _git_env_run(path, ['diff', '--cached', '--binary'] + (['HEAD'] if head else []), env)
            fd = os.open(patch, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, diff)
                os.fsync(fd)
            finally:
                os.close(fd)
            if not diff:
                raise ValueError('the patch of the uncommitted changes came out empty')
            report['patch'] = patch
        _worktree_audit({'event': 'free', 'path': path, 'head': head, 'repo': facts['repo'],
                         'rescue_ref': report.get('rescue_ref'), 'patch': report.get('patch')})
        done = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-C', facts['repo'],
                               'worktree', 'remove'] + (['--force'] if dirty or rescue else []) + ['--', path],
                              capture_output=True, text=True, timeout=REMOVE_SECONDS, env=_clone_env())
        stderr = (done.stderr or '').strip()[:200]
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report.update(removable=False, reason='nothing removed: the rescue step failed (%s)' % _clean_reason(error))
        return report
    gone = not os.path.lexists(path)
    report.update(removed=done.returncode == 0 and gone, directory_removed=gone,
                  registry_entry_left=None if not os.path.isdir(facts['repo']) else registry_lists(facts['repo'], path))
    if not report['removed']:
        report['reason'] = 'git worktree remove did not complete: %s' % stderr
    _worktree_audit({'event': 'free-result', 'path': path, 'removed': report['removed']})
    return report


class tempfile_index:
    """A throwaway index file, so staging the changes for the patch never touches the worktree's own index."""

    def __init__(self, path):
        self.path = path

    def __enter__(self):
        import tempfile
        self.dir = tempfile.mkdtemp(prefix='wt-rescue-')
        return {'GIT_INDEX_FILE': os.path.join(self.dir, 'index')}

    def __exit__(self, *exc):
        shutil.rmtree(self.dir, ignore_errors=True)
        return False


def _git_env_run(repo, args, env):
    full = dict(_clone_env(), **env)
    if 'GIT_INDEX_FILE' in env:
        base = subprocess.run(['git', '-C', repo, 'rev-parse', '--git-path', 'index'], capture_output=True, text=True,
                              timeout=30, env=_clone_env())
        src = os.path.join(repo, base.stdout.strip()) if not os.path.isabs(base.stdout.strip()) else base.stdout.strip()
        if os.path.isfile(src) and not os.path.exists(env['GIT_INDEX_FILE']):
            shutil.copyfile(src, env['GIT_INDEX_FILE'])
    done = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', repo] + args, capture_output=True,
                          timeout=300, env=full)
    if done.returncode != 0:
        raise ValueError('git %s failed' % args[0])
    return done.stdout


def _clean_reason(reason):
    """A verifier reason made safe to print: printable ASCII only, 160 characters. Its text is the verifier's own, so it
    may name a remote or up to five ignored files of the worktree, as it did before goodqa#16943."""
    return re.sub(r'[^\x20-\x7e]', '?', str(reason))[:160]


def main(argv=None) -> int:
    import argparse  # noqa: PLC0415
    parser = argparse.ArgumentParser(prog="ah_worktree.py", description="the free-worktree verifier (ah worktree-remove)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    fw = sub.add_parser("free-worktree", help="remove one dead linked worktree under the 2026-11-24 rules")
    fw.add_argument("--path", required=True)
    fw.add_argument("--rescue", action="store_true", help="save commits and changes first, then remove")
    fw.add_argument("--session", help="caller session: the patch goes under ~/.agent-harness/work/<session>/rescue")
    fw.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    patch_dir = None
    if args.session and _SESSION_ID.match(args.session):
        patch_dir = os.path.join(os.path.expanduser("~"), ".agent-harness", "work", args.session, "rescue")
    result = free_worktree(args.path, args.rescue, patch_dir, args.dry_run)
    print(json.dumps(result))
    return 0 if result.get("removable") and (args.dry_run or result.get("removed")) else 1


if __name__ == "__main__":
    sys.exit(main())
