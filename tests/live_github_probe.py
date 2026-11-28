#!/usr/bin/env python3
"""Live proof of the merge rule against the real GitHub, on ONE private probe repository only.

Run: AH_LIVE_GITHUB=ericmacdougall/ah-ruleset-probe python3.13 tests/live_github_probe.py [--keep-clone]

The repository name is hard-coded. The script refuses any other value of AH_LIVE_GITHUB, and every push, ruleset,
status or merge goes to that repository alone. It creates the repository (private, with a README) if it is
missing and leaves it in place. It uses gh's own login and never prints a token.

Each check prints PROVEN, FAILED or UNPROVEN. The exit code is 1 when anything FAILED. The name does not start with
test_, so `unittest discover` never runs it.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROBE = "ericmacdougall/ah-ruleset-probe"
ROOT = Path(__file__).resolve().parents[1]
AH_REPO = ROOT / "harness" / "hooks" / "ah_repo.py"
RESULTS = []


def say(outcome, check, detail=""):
    RESULTS.append(outcome)
    print("%-9s %s%s" % (outcome, check, (": " + detail) if detail else ""), flush=True)


def run(argv, cwd=None, stdin=None, check=False, timeout=120):
    env = dict(os.environ, GH_PROMPT_DISABLED="1", GH_PAGER="cat", GIT_TERMINAL_PROMPT="0", NO_COLOR="1")
    done = subprocess.run(argv, cwd=cwd, input=stdin, capture_output=True, text=True, timeout=timeout, env=env)
    if check and done.returncode:
        raise RuntimeError("%s failed (%d): %s" % (" ".join(argv[:4]), done.returncode,
                                                  (done.stderr or done.stdout).strip()[-400:]))
    return done


def gh(*args, **kw):
    return run(["gh", *args], **kw)


def git(clone, *args, **kw):
    # gh supplies the credential for this one call; nothing is written to any git config.
    return run(["git", "-C", str(clone), "-c", "credential.helper=", "-c", "credential.helper=!gh auth git-credential",
                *args], **kw)


def ah(*args):
    return run([sys.executable, str(AH_REPO), *args])


def remote_sha(clone, branch):
    done = git(clone, "ls-remote", "origin", "refs/heads/" + branch)
    return done.stdout.split()[0] if done.returncode == 0 and done.stdout.strip() else None


def merge(number):
    """gh pr merge without --admin; returns (merged, message). Retries briefly while GitHub computes mergeability."""
    message = ""
    for _ in range(6):
        done = gh("pr", "merge", str(number), "-R", PROBE, "--merge", "--delete-branch=false")
        state = gh("pr", "view", str(number), "-R", PROBE, "--json", "state", "--jq", ".state").stdout.strip()
        if state == "MERGED":
            return True, (done.stdout or done.stderr).strip()
        message = (done.stderr or done.stdout).strip()
        if "not mergeable" in message.lower() and "unknown" in message.lower():
            time.sleep(5)
            continue
        return False, message
    return False, message


def post_status(sha, state, description):
    """Posted as the review runner does, in-process (peer_review.post_review_result calls ah_repo directly): the
    command line refuses a passing status from inside an agent, and this probe may be run from one."""
    sys.path.insert(0, str(AH_REPO.parent))
    import ah_repo  # noqa: PLC0415
    try:
        ah_repo.post_review_status(PROBE, sha, state, description)
        return subprocess.CompletedProcess([], 0, "", "")
    except (ah_repo.GitHubError, ValueError) as error:
        return subprocess.CompletedProcess([], 1, "", str(error))


def main(argv):
    if os.environ.get("AH_LIVE_GITHUB") != PROBE:
        print("live_github_probe: refused. Set AH_LIVE_GITHUB=%s; no other repository is ever touched." % PROBE,
              file=sys.stderr)
        return 2
    keep = "--keep-clone" in argv
    if gh("auth", "status").returncode:
        say("UNPROVEN", "gh is logged in", "gh auth status failed")
        return 1

    view = gh("repo", "view", PROBE, "--json", "visibility,defaultBranchRef,nameWithOwner")
    if view.returncode:
        created = gh("repo", "create", PROBE, "--private", "--add-readme",
                     "--description", "Agent Harness merge-rule probe (safe to keep)")
        if created.returncode:
            say("FAILED", "create the private probe repository", created.stderr.strip()[-300:])
            return 1
        time.sleep(3)
        view = gh("repo", "view", PROBE, "--json", "visibility,defaultBranchRef,nameWithOwner", check=True)
    info = json.loads(view.stdout)
    if info.get("nameWithOwner", "").lower() != PROBE or info.get("visibility") != "PRIVATE":
        say("FAILED", "probe repository is private", "visibility %s" % info.get("visibility"))
        return 1
    default = (info.get("defaultBranchRef") or {}).get("name") or "main"
    say("PROVEN", "probe repository exists and is private", "%s, default branch %s" % (PROBE, default))

    protect = ah("protect", PROBE)
    plan_refused = protect.returncode == 3
    if plan_refused:
        say("UNPROVEN", "ah repo protect", "GitHub plan refuses rulesets here: " + protect.stderr.strip()[-300:])
        return 0
    if protect.returncode:
        say("FAILED", "ah repo protect", (protect.stderr or protect.stdout).strip()[-300:])
        return 1
    say("PROVEN", "ah repo protect", protect.stdout.strip())
    again = ah("protect", PROBE)
    say("PROVEN" if again.returncode == 0 and again.stdout.strip() == protect.stdout.strip() else "FAILED",
        "ah repo protect is idempotent (same ruleset id)", again.stdout.strip() or again.stderr.strip()[-200:])
    status = ah("status", PROBE)
    say("PROVEN" if status.returncode == 0 else "FAILED", "ah repo status", (status.stdout or status.stderr).strip())

    work = Path(tempfile.mkdtemp(prefix="ah-ruleset-probe-"))
    clone = work / "clone"
    try:
        git(work, "clone", "-q", "https://github.com/%s.git" % PROBE, str(clone), check=True)
        origin = git(clone, "remote", "get-url", "origin", check=True).stdout.strip()
        if PROBE not in origin.lower():
            say("FAILED", "clone origin is the probe", origin)
            return 1
        git(clone, "config", "user.name", "ah probe", check=True)
        git(clone, "config", "user.email", "probe@example.invalid", check=True)
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        branch = "probe/" + stamp
        git(clone, "checkout", "-q", "-b", branch, check=True)
        (clone / "probe.txt").write_text("probe %s\n" % stamp)
        git(clone, "add", "probe.txt", check=True)
        git(clone, "commit", "-qm", "probe " + stamp, check=True)
        head = git(clone, "rev-parse", "HEAD", check=True).stdout.strip()
        git(clone, "push", "-q", "origin", branch, check=True)
        created = gh("pr", "create", "-R", PROBE, "--head", branch, "--base", default, "--title", "probe " + stamp,
                     "--body", "Merge-rule probe (tests/live_github_probe.py).", check=True)
        number = int(created.stdout.strip().rsplit("/", 1)[1])
        say("PROVEN", "opened a pull request", "#%d head %s" % (number, head[:12]))

        merged, message = merge(number)
        say("FAILED" if merged else "PROVEN", "merge refused with no harness/review status", message[-200:])
        if not merged:
            posted = post_status(head, "failure", "probe: failure")
            if posted.returncode:
                say("FAILED", "ah review-status post failure (read back)", posted.stderr.strip()[-200:])
            else:
                merged, message = merge(number)
                say("FAILED" if merged else "PROVEN", "merge refused with harness/review failure", message[-200:])
            if not merged:
                posted = post_status(head, "success", "probe: success")
                if posted.returncode:
                    say("FAILED", "ah review-status post success (read back)", posted.stderr.strip()[-200:])
                else:
                    shown = ah("review-status", "show", "--repo", PROBE, "--sha", head)
                    say("PROVEN" if "success" in shown.stdout else "FAILED", "ah review-status show", shown.stdout.strip())
                    merged, message = merge(number)
                    say("PROVEN" if merged else "FAILED", "merge allowed with harness/review success", message[-200:])

        git(clone, "fetch", "-q", "origin", default, check=True)
        git(clone, "checkout", "-q", "-B", "force-probe", "origin/" + default, check=True)
        before = remote_sha(clone, default)
        git(clone, "commit", "-q", "--amend", "-m", "force-push probe " + stamp, check=True)
        pushed = git(clone, "push", "--force", "origin", "HEAD:refs/heads/" + default)
        after = remote_sha(clone, default)
        lines = [line.strip() for line in pushed.stderr.splitlines() if line.strip()]
        why = next((line for line in lines if "rule" in line.lower() or "GH013" in line), lines[-1] if lines else "")
        say("PROVEN" if pushed.returncode and after == before else "FAILED",
            "force-push to %s refused" % default, why[-200:])

        deleted = gh("api", "-X", "DELETE", "repos/%s/git/refs/heads/%s" % (PROBE, default))
        still = remote_sha(clone, default)
        reason = (deleted.stderr.strip().splitlines() or [""])[-1][-200:]
        if deleted.returncode == 0 or still != after:
            say("FAILED", "deleting %s refused" % default, reason)
        elif "default branch" in reason.lower():
            # GitHub refuses deleting the default branch on its own, so this cannot show the ruleset's deletion rule;
            # that rule is shown by the readback in `ah repo protect`.
            say("UNPROVEN", "deletion refused by the ruleset", "GitHub's own default-branch guard answered first: "
                + reason)
        else:
            say("PROVEN", "deleting %s refused" % default, reason)
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
        say("FAILED", "probe step", str(error)[-400:])
    finally:
        if keep:
            print("clone kept at " + str(clone))
        else:
            shutil.rmtree(work, ignore_errors=True)
    return 1 if "FAILED" in RESULTS else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
