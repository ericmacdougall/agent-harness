"""`ah clone-remove`: remove ONE verified whole git clone inside an agent work dir, here or on t2-dev (goodqa#17119).

The guard's own exemption for deleting a reproducible clone runs inside a hook's few-second budget and reads the remote
without credentials, so a large or private clone is refused and the only way left was a raw rm. This command is the
audited route instead. It hands a literal path to the fixed verifier `command_guard.py remove-clone` (or `verify-clone`
with --check) ON the target host. That verifier keeps every rule of the exemption: a clean tree under the ignored-file
policy, no stash, no linked worktree, every commit reachable from a local ref, HEAD, a reflog or a stale remote-tracking
ref on a live remote. It adds a scope rule (strictly inside ~/.agent-harness/work/<session>/, never a WAL, log,
transcript, state or release location), the owning session's liveness on its own host, a mount check and a process
check (working directories and open files), and it moves the clone aside and re-checks it before deleting it.

This side adds what the target host cannot see: the owning session must not be live on any host (command_guard's
clone_liveness, the same rule the verifier applies on its own host), and a session no host knows refuses. It also checks
this host's release tooling. Nothing here relaxes a check: there is no --force, and the caller cannot supply refs.

The caller's audit row is written before anything runs (fail closed) and again with the outcome; the verifier writes its
own rows on the target host.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ah_worktree  # noqa: E402
import command_guard  # noqa: E402

HOSTS, REMOTE_HOSTS, MAX_REASON = ah_worktree.HOSTS, ah_worktree.REMOTE_HOSTS, ah_worktree.MAX_REASON
CLONE_VERIFIER_VERSION = 1
AUDIT_NAME = "clone-audit.jsonl"
# The verifier's own bounds: its liveness read (180 s), verification (120 s), the process scans (lsof up to 60 s,
# twice), the size walk (120 s), the deletion of a large tree and the ssh connect. Run a large removal in the background.
CALL_TIMEOUT = 180 + 120 + 2 * 60 + 120 + 900 + 10 + 50
UNKNOWN = ah_worktree.UNKNOWN
CloneError = ah_worktree.WorktreeError


def owning_session(path):
    """The <session> segment of ~/.agent-harness/work/<session>/<something>, or None."""
    return command_guard.clone_owning_session(path)


def liveness_refusal(host, session, home, runner, now):
    """(reason or None, summary): command_guard.clone_liveness over this host and, for a remote path, the target host,
    with a session no host knows refused."""
    hosts = ("local",) if host == "local" else ("local", host)
    return command_guard.clone_liveness(session, hosts, runner=runner, home=str(home), now=now, require_known=True)

def _argv(host, path, authenticated, check):
    tail = ["verify-clone" if check else "remove-clone", "--path", path] + (["--remote-auth"] if authenticated else [])
    if host == "local":
        return [sys.executable, "-I", str(HERE / "command_guard.py"), *tail]
    cmd = "python3 -I .claude/hooks/command_guard.py " + " ".join(shlex.quote(t) for t in tail)
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", host, cmd]


def _call(runner, host, path, authenticated, check):
    """Run the verifier. Once it has started, a failure leaves the outcome UNKNOWN (a remote command keeps running after
    an ssh client dies), so no message from here says that nothing was removed."""
    try:
        done = runner(_argv(host, path, authenticated, check), capture_output=True, text=True, timeout=CALL_TIMEOUT)
        data = json.loads(done.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        raise CloneError("host_unreachable", "could not run the verifier on %s (%s)" % (host, UNKNOWN), 3)
    if not isinstance(data, dict) or not isinstance(data.get("removable"), bool):
        raise CloneError("host_unreachable", "unexpected answer from the verifier on %s (%s)" % (host, UNKNOWN), 3)
    if data.get("clone_verifier") != CLONE_VERIFIER_VERSION:
        raise CloneError("verifier_outdated", "the clone verifier on %s is not version %d: install the merged "
                         "command_guard.py there (%s)" % (host, CLONE_VERIFIER_VERSION, UNKNOWN), 3)
    if data.get("removed") not in (None, True, False):
        raise CloneError("host_unreachable", "malformed answer from %s (%s)" % (host, UNKNOWN), 3)
    if data["removable"] is False and data.get("removed") is True:
        raise CloneError("host_unreachable", "contradictory answer from %s (%s)" % (host, UNKNOWN), 3)
    return data


VERIFIED_KEYS = ("head", "remotes", "commits_checked", "local_refs", "local_ref_names", "stale_tracking_refs",
                 "pull_proof_tips", "session_liveness", "process_check", "bytes", "freed_bytes", "directory_removed",
                 "quarantine")


def remove(host, path, reason, authenticated=False, session="", agent="", home=None, runner=subprocess.run,
           check=False, now=None):
    """Remove (or with check=True only verify) one clone. Returns the answer dict; raises CloneError on bad input or
    an unknown outcome."""
    if host not in HOSTS:
        raise CloneError("bad_request", "--host must be one of %s" % ", ".join(HOSTS))
    path = ah_worktree.check_path(path)
    reason = (reason or "").strip()
    if not reason or len(reason) > MAX_REASON or re.search(r"[\x00-\x08\x0b-\x1f\x7f]", reason):
        raise CloneError("reason_required", "--reason is mandatory, printable and at most %d characters" % MAX_REASON)
    owner = owning_session(path)
    if owner is None:
        raise CloneError("bad_request", "--path must be a clone inside an agent work dir "
                                        "(~/.agent-harness/work/<session>/...)")
    if host == "local":
        cwd = os.path.realpath(os.getcwd())
        if cwd == path or cwd.startswith(path + os.sep):
            raise CloneError("bad_request", "the current directory is inside the clone being removed")
    home = Path(home or Path.home())
    now = time.time() if now is None else now
    run_id = "clr-" + uuid.uuid4().hex[:12]
    who = {"session": session or None, "agent": agent or None}
    try:
        ah_worktree.audit(home, {"event": "start", "run": run_id, "host": host, "path": path, "reason": reason,
                                 "check": bool(check), "remote_auth": bool(authenticated), "caller": who}, AUDIT_NAME)
    except OSError:
        raise CloneError("audit_failed", "could not write the audit row; nothing was run, nothing was removed", 3)
    answer = {"ok": False, "run": run_id, "host": host, "path": path, "check": bool(check), "removed": False}
    refusal, live = liveness_refusal(host, owner, home, runner, now)
    answer["liveness"] = live
    if refusal is None and host != "local":
        refusal = command_guard.release_tooling_refusal(path, str(home))  # this host's tooling, home-relative
    if refusal:
        answer["reason"] = refusal
        _audit_result(home, {"event": "result", "run": run_id, "host": host, "path": path, "removed": False,
                             "why": refusal})
        return answer
    outcome = {"event": "result", "run": run_id, "host": host, "path": path, "removed": None,
               "why": "no answer from the verifier (outcome unknown)"}
    result = {}
    try:
        result = _call(runner, host, path, authenticated, check)
        if result["removable"] is False:
            removed = False
        elif check:
            removed = False
        elif isinstance(result.get("removed"), bool):
            # removable true and not removed: the deletion started and did not complete, so what is left is unknown
            removed = True if result["removed"] else None
        else:
            removed = None
        why = result.get("reason")
        if removed is None:
            why = (why or "") + " (" + UNKNOWN + ")"
        outcome.update(removed=removed, why=why, head=result.get("head"), freed_bytes=result.get("freed_bytes"),
                       quarantine=result.get("quarantine"))
    except CloneError as error:
        outcome.update(why="%s: %s (outcome unknown, check the host)" % (error.code, error))
        raise
    finally:
        _audit_result(home, outcome, answer)
    answer.update({key: result.get(key) for key in VERIFIED_KEYS if key in result})
    answer.update(removed=removed, reason=ah_worktree._redact(outcome["why"] or "") or None,
                  verified=bool(result.get("removable")),
                  ok=(removed is True) if not check else bool(result.get("removable")))
    return answer


def _audit_result(home, row, answer=None):
    try:
        ah_worktree.audit(home, row, AUDIT_NAME)
    except OSError:
        if answer is not None:
            answer["audit_warning"] = "the outcome row could not be written"


def cli_main(argv):
    """`ah clone-remove ...`: one JSON object on stdout, never a traceback. Exit 0 when removed (or, with --check,
    verified removable), 3 when refused, 2 on bad input, 3 on an unknown outcome."""
    parser = argparse.ArgumentParser(prog="ah clone-remove", allow_abbrev=False,
                                     description="remove ONE verified whole git clone inside an agent work dir here or "
                                                 "on t2-dev (audited; see ah_clone.py; no --force exists)")
    parser.add_argument("--host", required=True, help="local or t2-dev")
    parser.add_argument("--path", required=True, help="one literal absolute path")
    parser.add_argument("--reason", required=True, help="why (mandatory, logged)")
    parser.add_argument("--remote-auth", dest="remote_auth", action="store_true",
                        help="private repository: the verifier reads the remote with the TARGET host's own credentials")
    parser.add_argument("--check", action="store_true", help="verify only: print what would be checked, remove nothing")
    parser.add_argument("--session", help="calling session id for the audit row (not the owning session)")
    parser.add_argument("--agent", help="calling agent id for the audit row")
    args = parser.parse_args(argv)
    session = args.session or os.environ.get("CLAUDE_CODE_SESSION_ID") or os.environ.get("CLAUDE_SESSION_ID") or ""
    try:
        data = remove(args.host, args.path, args.reason, args.remote_auth, session,
                      args.agent or os.environ.get("AH_AGENT_ID", ""), check=args.check)
    except CloneError as error:
        json.dump({"ok": False, "code": error.code, "message": str(error)}, sys.stdout)
        sys.stdout.write("\n")
        return error.exit_code
    except Exception as error:  # noqa: BLE001 - a partial install or a bug: one JSON line, never a traceback
        json.dump({"ok": False, "code": "internal", "type": type(error).__name__}, sys.stdout)
        sys.stdout.write("\n")
        return 4
    sys.stdout.write(json.dumps(data, indent=2) + "\n")
    return 0 if data.get("ok") else 3


if __name__ == "__main__":
    sys.exit(cli_main(sys.argv[1:]))
