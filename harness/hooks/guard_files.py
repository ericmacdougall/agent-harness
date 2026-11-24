"""The one list of guard files: hooks that check agent commands, the policy files they read, and the code they import.

Guard installs stay a user-run command pinned to a reviewed, merged commit (GoodQA goodqa#16944, coordinator ruling on
the self-serve enabler). Both agent install routes read this module and refuse a ref that would change a guard file:
`ah ops repair` (harness_repair and the central-decisions recipe) and `ah install-files --manifest`
(install_files_manifest). Everything else stays agent-installable under the signed grant.

A file is a guard file when any of these holds:
  * its name is listed;
  * its name starts with a listed prefix;
  * it is a policy JSON (`*_policy.json`);
  * the routes pass the installed hooks directory, and it is a harness module that a registered PreToolUse or Stop hook
    imports there, directly or through other modules (guard_closure). Changing shellwords.py changes how mission_gate
    reads a command, so it is guard code too.
An unreadable hooks_manifest.json counts every name as a guard file (fail closed).
tests/test_guard_files.py fails when a registered PreToolUse or Stop hook is missing from the static list. Stdlib only,
Python 3.9+, and importing this module has no side effects.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

GUARD_NAMES = frozenset({
    # the hooks that decide whether an agent's command, spawn, merge or stop goes ahead
    "agent_gate.py", "bg_lint.py", "commit_policy.py", "dropped_gate.py", "heavy_job_guard.py", "idle_guard.py",
    "mc_inbox.py", "mission_gate.py", "owner_inbox.py", "prod_delete_guard.py", "spec_flow.py", "status_truth.py",
    "tier_gate.py", "wal.py", "wal_cadence.py", "work_assignments.py", "worktree_hygiene.py",
    "usage_guard.py", "peer_review.py", "escalation.py", "caller_identity.py", "model_tiers.py", "native_context.py",
    # the registrations and rules those hooks load
    "hooks_manifest.json", "rules.json", "model_tiers.json", "resource_limits.json", "commit_policy.json",
    "spec_policy.json", "review_policy.json", "provenance_policy.json", "kill_guard_policy.json", "domain_checklists.json",
    "codex_pool_policy.json", "ahd_policy.json",
    # the installers themselves: replacing them changes what every later install checks
    "ah_install.py", "ah_ops.py", "guard_files.py", "supervisor_grant.py",
    # keeps the record supervisor power reads the model from client-written (goodqa#16944)
    "transcript_guard.py",
})
GUARD_PREFIXES = ("command_guard", "kill_guard", "copy_hygiene", "merge_gate", "provenance", "self_serve", "settings")
POLICY_JSON = re.compile(r"^[A-Za-z0-9_]+_policy(\.local)?\.json(\.example)?$")
GUARD_EVENTS = ("PreToolUse", "Stop")

USER_INSTALL = ("python3 -I ~/.claude/hooks/ah.py install-files --host {host} --from-ref {ref} --file {files} "
                "--ticket \"GoodQA <project>#<n>\"   (run by the user in his own terminal)")


def is_guard_file(name: str) -> bool:
    base = Path(str(name)).name
    return base in GUARD_NAMES or base.startswith(GUARD_PREFIXES) or bool(POLICY_JSON.match(base))


def guard_closure(hooks_dir) -> set | None:
    """The registered PreToolUse/Stop hooks in HOOKS_DIR and every harness module they import there; None when the manifest
    cannot be read (the caller then treats every name as a guard file)."""
    try:
        hooks_dir = Path(hooks_dir)
        roots = registered_guard_hooks(hooks_dir / "hooks_manifest.json")
        return set(roots) | set(local_import_closure(hooks_dir, roots))
    except Exception:  # noqa: BLE001 - unreadable or malformed: fail closed
        return None


def guard_subset(names, hooks_dir=None) -> list:
    """The guard files among NAMES. With HOOKS_DIR (the installed hooks), the import closure of the registered guard hooks
    there counts too, and an unreadable manifest makes every name a guard file."""
    bases = {Path(str(n)).name for n in names}
    if hooks_dir is None:
        return sorted(b for b in bases if is_guard_file(b))
    closure = guard_closure(hooks_dir)
    if closure is None:
        return sorted(bases)
    return sorted(b for b in bases if is_guard_file(b) or b in closure)


def refusal(host: str, ref: str, names) -> str:
    """The refusal text both routes print: which guard files differ, and the one line the user runs instead. NAMES are the
    guard files already chosen by guard_subset."""
    files = sorted({Path(str(n)).name for n in names})
    return ("ref %s would change guard file(s) %s on %s. Agents install only non-guard tooling under the self-serve "
            "grant; a guard install stays yours. Run: %s" % (ref[:12], ", ".join(files), host,
                                                              USER_INSTALL.format(host=host, ref=ref, files=" --file ".join(files))))


def registered_guard_hooks(manifest: Path) -> list:
    """Scripts that hooks_manifest.json registers for a PreToolUse or Stop event."""
    data = json.loads(Path(manifest).read_text())
    return sorted({h["script"] for h in data.get("hooks", [])
                   if isinstance(h, dict) and h.get("event") in GUARD_EVENTS and isinstance(h.get("script"), str)})


def local_import_closure(hooks_dir: Path, roots) -> list:
    """Every harness module in HOOKS_DIR that the ROOTS import, directly or through each other (static, by name)."""
    hooks_dir = Path(hooks_dir)
    local = {p.stem for p in hooks_dir.glob("*.py")}
    seen, stack = set(), [Path(r).name for r in roots]
    while stack:
        name = stack.pop()
        path = hooks_dir / name
        if name in seen or not path.is_file():
            continue
        seen.add(name)
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                mods = [node.module.split(".")[0]]
            stack.extend(m + ".py" for m in mods if m in local)
    return sorted(seen)
