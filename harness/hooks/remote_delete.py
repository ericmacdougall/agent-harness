#!/usr/bin/env python3
"""Guarded delete of an archive-backed tree on another host (goodqa#15251), modelled on `ah kill --host`.

The approval is checked HERE, on the host that holds the user's transcript: the remote host's own guard refuses
local agents and never trusts relayed records, so it is not asked to. Then this helper performs the delete itself
over ssh, through `remote_delete_agent.py`, which re-checks the remote side.

  remote_delete.py --host t2-dev --path /home/eric/wt/X --archive-dir dropbox:Backups/.../worktree-archives \
      --user-source answer:<session>/<uuid> --wal <that session's WAL>

Checks here, all before anything runs remotely:
- the host is on the ah_kill allowlist; the path is a literal absolute path; the archive dir is an rclone remote;
- the answer resolves to a real, single-question AskUserQuestion turn (command_guard.resolve_user_source), at most
  no_backup_max_source_age_seconds old, a predefined option, and the WAL is that session's real WAL with a hook entry
  older than the answer;
- archive wording: the selected option says yes/remove/delete and holds no decline word; the question names the
  host, says the trees are backed up, and names this path (absolute, or `~/...` under the remote home);
- the cap: one answer approves at most `archive_remote_max_paths_per_source` (default 16) archive-backed deletions,
  counted from the command_guard audit log under a lock. A question may name several paths.

The remote side then (check) re-proves the path is a real directory under its home, a clean git tree when it is one,
that the Dropbox tar.gz streams to its recorded sha256, that the listing stays inside the tree, and that a tree with
unpushed commits has a verified bundle holding HEAD; (delete) repeats all of that, requires the same dev:inode, and
removes it. Both sides audit: the command_guard audit log and the WAL here, ~/.agent-harness/state on the host.
"""
import argparse
import fcntl
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import command_guard as cg  # noqa: E402
from ah_kill import HOSTS  # noqa: E402

ARCHIVE_KIND = "archive-remote"
DEFAULT_CAP = 16
# the selected option must say yes/remove/delete; "Delete, no backup" also matches, and is fine here because the
# remote side still requires the verified archive
# the whole option must approve every named path: "Yes, remove all 11 (Recommended)", "Delete them", "Remove it".
# "Delete only X", "Remove all except Y" and the like do not match.
APPROVE_ARCHIVE = re.compile(r"^(?:yes,? )?(?:remove|delete)(?: (?:it|them|both|all|these|all of them))?"
                             r"(?: (\d{1,2}))?(?: of them)?(?: \(recommended\))?\.?$", re.I)
BACKED_UP = re.compile(r"\bbacked up\b|\bbackups?\b", re.I)
TILDE_PATH_RE = re.compile(r'(?<![\w.~-])~/[^\s"\'`,;:()<>\[\]{}?!*|]+')
REMOTE_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}:[A-Za-z0-9 ._/-]{1,400}$")
AGENT = HERE / "remote_delete_agent.py"


class Refused(ValueError):
    pass


def _cap(policy):
    return int((policy.get("marker") or {}).get("archive_remote_max_paths_per_source", DEFAULT_CAP))


def named_count(question):
    """How many distinct paths (absolute or ~/) the question names."""
    named = {p.rstrip(".").rstrip("/") for p in cg.QUESTION_PATH_RE.findall(question or "")}
    named |= {p.rstrip(".").rstrip("/") for p in TILDE_PATH_RE.findall(question or "")}
    return len(named)


def question_names(question, path, remote_home):
    """True when the question names `path` as a whole path, absolute or as ~/ under remote_home."""
    named = {p.rstrip(".").rstrip("/") for p in cg.QUESTION_PATH_RE.findall(question or "")}
    for tilde in TILDE_PATH_RE.findall(question or ""):
        named.add((remote_home.rstrip("/") + tilde[1:]).rstrip(".").rstrip("/"))
    return path in named


def wording_refusal(turn, host):
    text, question = str(turn.get("text") or ""), str(turn.get("question") or "")
    if turn.get("predefined") is not True:
        return 'the answer is free text ("Other"), not a predefined option; ask the user again'
    approve = APPROVE_ARCHIVE.match(text.strip())
    if not approve or cg.DECLINE_WORDS.search(text):
        return ("the selected answer is not a plain approval of every named path (for example \"Yes, remove all 11\")"
                "; ask the user again")
    if cg.DECLINE_WORDS.search(question):
        return ("the question also says to keep or not remove something (%r); ask one question that lists only the "
                "paths to remove" % cg.DECLINE_WORDS.search(question).group(0))
    if named_count(question) > 1 and not approve.group(1):
        return ("the question names %d paths, so the answer must state that count (for example \"Yes, remove all "
                "%d\")" % (named_count(question), named_count(question)))
    if approve.group(1) and int(approve.group(1)) != named_count(question):
        return "the answer approves %s paths but the question names %d" % (approve.group(1), named_count(question))
    if not re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(host), question, re.I):
        return "the question does not name the host %s; ask the user again naming it" % host
    if not BACKED_UP.search(question):
        return "the question does not say the trees are backed up; an archive-backed approval needs that"
    return ""


def wal_refusal(wal, turn, user_home):
    wal_text = str(wal or "")
    if not wal_text:
        return "--wal is required: the approval is recorded there"
    wal_real = os.path.realpath(wal_text)
    wals_root = os.path.realpath(os.path.join(user_home, ".claude", "wals"))
    if os.path.dirname(wal_real) != os.path.join(wals_root, turn["session"]):
        return "the answer is from session %s, but --wal is not a WAL of that session" % turn["session"]
    if os.path.islink(wal_text) or wal_text != wal_real or not os.path.isfile(wal_real):
        return "--wal must be the existing, real WAL file of the session (no symlink, exact name)"
    if not cg._hook_wal_predates(wal_real, float(turn["at"])):
        return "--wal has no hook-written entry that predates the answer"
    return ""


def uses_of_source(canonical, home=None):
    path = cg.state_dir(home) / cg.AUDIT_NAME
    if not path.exists():
        return 0
    try:
        raw = cg._read_small(path, 64 << 20).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - unreadable audit log: fail closed
        return 1 << 30
    count = 0
    for line in raw.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("event") == "approved" and rec.get("kind") == ARCHIVE_KIND and \
                cg._canonical_source(rec.get("user_source")) == canonical:
            count += 1
    return count


def ssh_agent(host, args, runner, timeout):
    remote = "python3 -I - " + " ".join(shlex.quote(a) for a in args)
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", host, remote]
    try:
        done = runner(argv, input=AGENT.read_text(encoding="utf-8"), capture_output=True, text=True, timeout=timeout)
        lines = [line for line in (done.stdout or "").splitlines() if line.strip()]
        data = json.loads(lines[-1]) if lines else None
    except (OSError, subprocess.SubprocessError, ValueError):
        data = None
    if not isinstance(data, dict):
        raise Refused("no usable answer from %s (unreachable, or the remote check crashed)" % host)
    return data


def remote_delete(host, path, archive_dir, user_source, wal, home=None, now=None, resolver=None,
                  runner=subprocess.run, policy=None, timeout=3600):
    """Delete `path` on `host` after the checks above. Returns the remote result dict; raises Refused."""
    policy = policy or cg.load_policy()
    user_home = os.path.realpath(home) if home else cg._pinned_home()
    canonical = cg._canonical_source(user_source)
    name = os.path.basename(path or "")
    archive = "%s/%s.tar.gz" % (str(archive_dir or "").rstrip("/"), name)
    record = {"path": path, "kind": ARCHIVE_KIND, "user_source": canonical or "invalid", "remote": "host:%s" % host,
              "archive": archive}
    wal_ok = bool(wal) and os.path.isfile(str(wal)) and not os.path.islink(str(wal))
    try:
        if home is None:
            problem = cg._environment_refusal(user_home)
            if problem:
                raise Refused(problem)
        if host not in HOSTS:
            raise Refused("--host must be one of %s" % ", ".join(HOSTS))
        if not isinstance(path, str) or not os.path.isabs(path) or os.path.normpath(path) != path or \
                any(ch in path for ch in cg.GLOB_CHARS) or "$" in path or "`" in path or not name:
            raise Refused("give the literal absolute path (no globs, variables, '..' or trailing slash)")
        if not REMOTE_RE.match(str(archive_dir or "")) or ".." in str(archive_dir):
            raise Refused("--archive-dir must be an rclone remote path such as dropbox:Backups/x")
        if not canonical:
            raise Refused("--user-source must be exactly answer:<session>/<uuid>")
        try:
            turn = (resolver or cg.resolve_user_source)(user_source, now=now, max_age=int(
                (policy.get("marker") or {}).get("no_backup_max_source_age_seconds", 86400)), home=user_home)
        except ValueError as error:
            raise Refused(str(error))
        problem = wal_refusal(wal, turn, user_home) or wording_refusal(turn, host)
        if problem:
            raise Refused(problem)
        cap = min(_cap(policy), named_count(turn.get("question")))
        if uses_of_source(canonical, home) >= cap:
            raise Refused("this answer already approved %d archive-backed deletions; ask the user again" % cap)
        files = [archive, archive + ".sha256", archive + ".listing", archive[:-len(".tar.gz")] + ".bundle"]
        check = ssh_agent(host, ["check", path] + files, runner, timeout)
        if not check.get("ok"):
            raise Refused("the %s check refused: %s" % (host, str(check.get("error"))[:300]))
        remote_home = str(check.get("home") or "")
        if not remote_home.startswith("/") or not question_names(turn.get("question"), path, remote_home):
            raise Refused("the question does not name %s (absolute, or ~/ under the %s home)" % (path, host))
        identity = str(check.get("identity") or "")
        record.update({"archive_sha256": (check.get("archive") or {}).get("sha256", ""), "reason": identity})
        sd = cg.state_dir(home)
        sd.mkdir(parents=True, exist_ok=True)
        with open(sd / "remote-delete.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if uses_of_source(canonical, home) >= cap:  # re-counted under the lock
                raise Refused("this answer already approved %d archive-backed deletions; ask the user again" % cap)
            try:
                cg.audit("approved", record, home=home, strict=True)
            except ValueError as error:
                raise Refused(str(error))
        cg.audit("approved", record, home=home, wal=wal, to_file=False)
        result = ssh_agent(host, ["delete", path, files[0], files[1], files[2], identity, files[3]], runner, timeout)
    except Refused as error:
        cg.audit("refused", dict(record, reason=str(error)[:200]), home=home, wal=wal if wal_ok else None)
        raise
    cg.audit("deleted" if result.get("ok") else "remote-failed", dict(record, reason=str(result.get("error") or "")[:200]),
             home=home, wal=wal)
    if not result.get("ok"):
        raise Refused("the %s delete refused: %s" % (host, str(result.get("error"))[:300]))
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--host", required=True)
    ap.add_argument("--path", required=True)
    ap.add_argument("--archive-dir", required=True)
    ap.add_argument("--user-source", required=True)
    ap.add_argument("--wal", required=True)
    args = ap.parse_args(argv)
    try:
        result = remote_delete(args.host, args.path, args.archive_dir, args.user_source, args.wal)
    except Refused as error:
        print("remote-delete refused: %s" % error, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
