"""Is this commit the merge of a reviewed PR on canonical main? The check main's guard-file install route runs.

goodqa#16944, PR 326a, main's ruling: a guard file may be installed by main without the user only from a commit that is
on canonical main and is the merge of a PR with an exact-HEAD review receipt of record, or an audited waiver.

verify(ref) returns {"pr", "head", "waiver", "source"} or raises ReceiptError. It holds when:
  1. GitHub (the `gh` CLI, run with a scrubbed environment) lists exactly one merged PR of CANONICAL_REPO into `main`
     whose merge_commit_sha is REF, with a full-sha head;
  2. merge_gate's waiver log (hash chain and head record verified by merge_gate._read_waivers) holds a `waive` row for
     that repo, PR number and head whose approval_source is `settled-review` (bound to a settled independent PR PASS
     FINAL) or `hook` (main's own stamped `merge_gate waive`, which cites the review in its reason). An `asserted` row
     (typed --approved-by text) is not enough.
The caller separately proves REF is an ancestor of canonical main in a fresh fetch (ah_install.fetch_source).

Residual, stated rather than controlled (goodqa#17019): the waiver log is a same-user file. Its hash chain catches an
edit or truncation, not an agent that appends a well-formed row through its own code; and a `hook` row is main's
assertion that the review passed. Hard rule 3 forbids forging either. Stdlib only, Python 3.9+, no side effects on
import.
"""
from __future__ import annotations

import json
import os
import pwd
import re
import subprocess
from pathlib import Path

CANONICAL_REPO = "ericmacdougall/agent-harness"
SOURCES = ("settled-review", "hook")
SHA = re.compile(r"^[0-9a-f]{40}$")
GH_TIMEOUT = 60


class ReceiptError(Exception):
    pass


def real_home() -> Path:
    """The account's home from the password database: HOME and AH_HOME are not consulted."""
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def gh_env() -> dict:
    home = str(real_home())
    env = {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin", "HOME": home, "LC_ALL": "C", "GH_PROMPT_DISABLED": "1",
           "GH_NO_UPDATE_NOTIFIER": "1"}
    return env


def merged_pr(ref, runner=subprocess.run, gh="gh"):
    """(number, head sha) of the one merged PR into main whose merge commit is REF."""
    if not isinstance(ref, str) or not SHA.fullmatch(ref):
        raise ReceiptError("the ref is not a full 40-hex commit sha")
    try:
        done = runner([gh, "api", "repos/%s/commits/%s/pulls" % (CANONICAL_REPO, ref)], capture_output=True, text=True,
                      timeout=GH_TIMEOUT, env=gh_env())
    except (OSError, subprocess.SubprocessError) as error:
        raise ReceiptError("could not ask GitHub which PR merged %s (%s)" % (ref[:12], type(error).__name__)) from None
    if done.returncode != 0:
        raise ReceiptError("GitHub did not answer which PR merged %s (gh exit %s)" % (ref[:12], done.returncode))
    try:
        pulls = json.loads(done.stdout)
    except ValueError:
        raise ReceiptError("GitHub's answer for %s is not JSON" % ref[:12]) from None
    if not isinstance(pulls, list):
        raise ReceiptError("GitHub's answer for %s is not a list of PRs" % ref[:12])
    found = []
    for pr in pulls:
        if not isinstance(pr, dict):
            continue
        base = pr.get("base") if isinstance(pr.get("base"), dict) else {}
        repo = (base.get("repo") or {}) if isinstance(base.get("repo"), dict) else {}
        head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
        if (pr.get("merged_at") and pr.get("merge_commit_sha") == ref and base.get("ref") == "main"
                and str(repo.get("full_name", "")).lower() == CANONICAL_REPO
                and type(pr.get("number")) is int and isinstance(head.get("sha"), str) and SHA.fullmatch(head["sha"])):
            found.append((pr["number"], head["sha"]))
    if len(found) != 1:
        raise ReceiptError("%s is not the merge commit of exactly one merged PR into main of %s (found %d)"
                           % (ref[:12], CANONICAL_REPO, len(found)))
    return found[0]


def waiver_of_record(number, head, state_dir=None):
    """The merge_gate waive row that authorized merging PR NUMBER at HEAD, or ReceiptError."""
    import merge_gate  # noqa: PLC0415 - a guard file beside this one
    state_dir = Path(state_dir) if state_dir is not None else real_home() / ".agent-harness" / "state"
    try:
        records = merge_gate._read_waivers(state_dir)
    except Exception as error:  # noqa: BLE001 - Corrupt, OSError, anything: no receipt
        raise ReceiptError("the merge-gate waiver log cannot be verified (%s)" % error) from None
    want = merge_gate.repo_key(CANONICAL_REPO)
    rows = [r for r in records if isinstance(r, dict) and r.get("event") == "waive"
            and merge_gate.repo_key(r.get("repo")) == want and str(r.get("pr")) == str(number) and r.get("head") == head]
    good = [r for r in rows if r.get("approval_source") in SOURCES]
    if not good:
        raise ReceiptError("PR #%s at head %s has no review receipt of record in the merge-gate log (%s)"
                           % (number, head[:12], "only %s rows" % sorted({str(r.get('approval_source')) for r in rows})
                              if rows else "no row"))
    return good[-1]


def verify(ref, runner=subprocess.run, state_dir=None, gh="gh") -> dict:
    number, head = merged_pr(ref, runner, gh)
    row = waiver_of_record(number, head, state_dir)
    return {"pr": number, "head": head, "waiver": row.get("id"), "source": row.get("approval_source")}
