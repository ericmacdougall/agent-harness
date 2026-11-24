"""The one list of guard files: hooks that check agent commands, the files they read or trust, and the code they load.

goodqa#16944, PR 326a. `ah install-files` (ah_install.guard_gate) asks this module whether a file is a guard file; a
guard file then needs the not-agent-launched branch (launch_check.py, a speed bump, not a boundary) or main's
reviewed-release branch (release_receipt.py and a stamp mission_gate puts for main's own call, INSTALL_STAMP). The installers and repair_harness.py --apply do not ask
yet: goodqa#17032, after the local target goodqa#17031.

A file is a guard file when any of these holds:
  * its name is listed in GUARD_NAMES, or starts with a GUARD_PREFIXES entry, or is a policy JSON (`*_policy.json`);
  * with a hooks directory given, it is in guard_closure() of that directory: the PreToolUse and Stop hooks
    hooks_manifest.json registers and every listed or prefix-matched guard file present there (both are starting
    points), every harness module they import there, and every file in that directory a closure module names anywhere
    in its text ("run_probe.py", "ahc_release.json", "dropbox_budget.conf", a by-path load), followed the same way. It
    is a text scan, not a parse, so a name in a comment or a dead string counts too.
An unreadable manifest, a manifest of an unexpected shape (not an object with a "hooks" list holding at least one
PreToolUse or Stop row) or an unreadable closure module counts every name as a guard file (fail closed).
The install route checks two trees: the hooks directory of the machine running it, before the fetch, and the
`harness/hooks` tree of the ref being installed, after the fetch and before any remote write (guard_subset_trees), so a
file that is a guard file only at the ref (version skew between the Mac and the target) is still gated.

Over-inclusion is the intended failure: a file wrongly counted as a guard file costs one gated install; a guard file
wrongly left out lets an agent change what checks it. tests/test_guard_install_gate.py fails when a registered PreToolUse or
Stop hook, or a file a guard names, is missing from the set. Stdlib only, Python 3.9+, no side effects on import.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

GUARD_NAMES = frozenset({
    # hooks that decide whether an agent's command, spawn, merge or stop goes ahead
    "agent_gate.py", "bg_lint.py", "commit_policy.py", "dropped_gate.py", "heavy_job_guard.py", "idle_guard.py",
    "mc_inbox.py", "mission_gate.py", "owner_inbox.py", "prod_delete_guard.py", "spec_flow.py", "status_truth.py",
    "tier_gate.py", "wal.py", "wal_cadence.py", "work_assignments.py", "worktree_hygiene.py",
    "usage_guard.py", "peer_review.py", "escalation.py", "caller_identity.py", "model_tiers.py", "native_context.py",
    # files a guard reads as data or trusts by name (acceptance review F-A4)
    "hooks_manifest.json", "rules.json", "model_tiers.json", "resource_limits.json", "ahc_release.json",
    "dropbox_budget.conf", "domain_checklists.json",
    "run_probe.py", "run_capped.py", "bg_job.py", "deliver.py", "remote_delete.py", "remote_delete_agent.py",
    "installer_scan.py",
    # what command_guard loads by name inside functions (PR 345 review F9): listed so a closure failure cannot drop them
    "safe_input.py", "redact.py", "shell_words.py", "shellwords.py",
    # the install routes and the checks they run: replacing them changes what every later install checks
    "ah.py", "ah_install.py", "guard_files.py", "launch_check.py", "release_receipt.py",
    # reserved for the supervisor lanes (PR 326b), so they are guard files the day they land
    "ah_ops.py", "supervisor_grant.py", "transcript_guard.py",
})
GUARD_PREFIXES = ("command_guard", "kill_guard", "copy_hygiene", "merge_gate", "provenance", "self_serve", "settings")
POLICY_JSON = re.compile(r"^[A-Za-z0-9_]+_policy(\.local)?\.json(\.example)?$")
GUARD_EVENTS = ("PreToolUse", "Stop")

INSTALL_STAMP = "install-files-guard"


def install_stamp_parts(host, ref, files, ticket) -> list:
    """The stamp key parts for one `ah install-files` new install: mission_gate (main's Bash call) and ah_install (the
    process) both compute them from the parsed command, so the stamp covers that exact host, ref, file set and ticket."""
    return [str(host), str(ref), ",".join(sorted(str(f) for f in (files or ()))), str(ticket)]


def is_guard_file(name: str) -> bool:
    base = Path(str(name)).name
    return base in GUARD_NAMES or base.startswith(GUARD_PREFIXES) or bool(POLICY_JSON.match(base))


class Unreadable(Exception):
    pass


def guard_closure(hooks_dir):
    """The registered PreToolUse/Stop hooks in HOOKS_DIR and every file there they import or name; None when the
    manifest or a closure module cannot be read (the caller then treats every name as a guard file)."""
    try:
        hooks_dir = Path(hooks_dir)
        present = {p.name for p in hooks_dir.iterdir() if p.is_file()}
        roots = set(registered_guard_hooks(hooks_dir / "hooks_manifest.json"))
        roots |= {name for name in present if is_guard_file(name)}  # the static names are starting points too (F2)
        return roots | set(local_closure(hooks_dir, sorted(roots)))
    except Exception:  # noqa: BLE001 - unreadable or malformed: fail closed
        return None


def guard_subset(names, hooks_dir=None) -> list:
    """The guard files among NAMES. With HOOKS_DIR (the installed hooks), the closure there counts too, and an
    unreadable manifest or module makes every name a guard file."""
    bases = {Path(str(n)).name for n in names}
    if hooks_dir is None:
        return sorted(b for b in bases if is_guard_file(b))
    closure = guard_closure(hooks_dir)
    if closure is None:
        return sorted(bases)
    return sorted(b for b in bases if is_guard_file(b) or b in closure)


def guard_subset_trees(names, hooks_dirs) -> list:
    """The guard files among NAMES counted against every directory in HOOKS_DIRS (the union of their closures); an
    unreadable directory makes every name a guard file."""
    out = set()
    for hooks_dir in hooks_dirs:
        out |= set(guard_subset(names, hooks_dir))
    return sorted(out)


def registered_guard_hooks(manifest: Path) -> list:
    """Scripts that hooks_manifest.json registers for a PreToolUse or Stop event. Raises Unreadable for an unexpected
    shape: a parsed manifest with no such row would otherwise give an empty closure (PR 345 review F9)."""
    data = json.loads(Path(manifest).read_text())
    if not isinstance(data, dict) or not isinstance(data.get("hooks"), list):
        raise Unreadable("hooks_manifest.json is not an object with a hooks list")
    found = sorted({h["script"] for h in data["hooks"]
                    if isinstance(h, dict) and h.get("event") in GUARD_EVENTS and isinstance(h.get("script"), str)})
    if not found:
        raise Unreadable("hooks_manifest.json registers no PreToolUse or Stop hook")
    return found


WORD = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
IMPORT = re.compile(r"^[ \t]*(?:from[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t.]|import[ \t]+([A-Za-z_][A-Za-z0-9_., \t]*))", re.M)


def referenced(text, present, modules) -> set:
    """Files in PRESENT that TEXT imports (`import x`, `from x import`) or names anywhere, as a bare name or a path's last
    part. A text scan, not a parse: a name in a comment counts too, which only ever adds guard files."""
    out = {w for w in WORD.findall(text) if w in present}
    for match in IMPORT.finditer(text):
        for mod in re.split(r"[\s,]+", match.group(1) or match.group(2) or ""):
            mod = mod.split(".")[0]
            if mod in modules:
                out.add(mod + ".py")
    return out


def local_closure(hooks_dir: Path, roots) -> list:
    """Every file in HOOKS_DIR that the ROOTS import or name, directly or through each other. Raises Unreadable when a
    Python file in the closure cannot be read (it might load anything)."""
    hooks_dir = Path(hooks_dir)
    present = {p.name for p in hooks_dir.iterdir() if p.is_file()}
    modules = {p[:-3] for p in present if p.endswith(".py")}
    seen, stack = set(), [Path(r).name for r in roots]
    while stack:
        name = stack.pop()
        if name in seen or name not in present:
            continue
        seen.add(name)
        if not name.endswith(".py"):
            continue
        try:
            text = (hooks_dir / name).read_text(errors="replace")
        except (ValueError, OSError) as error:
            raise Unreadable("%s: %s" % (name, type(error).__name__)) from None
        stack.extend(referenced(text, present, modules))
    return sorted(seen)
