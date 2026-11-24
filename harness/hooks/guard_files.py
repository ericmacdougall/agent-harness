"""The one list of guard files: hooks that check agent commands, the policy files they read, and the code they import.

Guard installs stay a user-run command pinned to a reviewed, merged commit (GoodQA goodqa#16944, coordinator ruling on
the self-serve enabler). Both agent install routes read this module and refuse a ref that would change a guard file:
`ah ops repair` (harness_repair and the central-decisions recipe) and `ah install-files --manifest`
(install_files_manifest). Everything else stays agent-installable under the signed grant.

A file is a guard file when its name is listed, starts with a listed prefix, or is a policy JSON (`*_policy.json`).
tests/test_guard_files.py fails when a hook registered for PreToolUse or Stop, or a harness module such a hook imports,
is missing here, so a new guard cannot be left out by accident. Stdlib only; Python 3.9+; no side effects on import.
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
})
GUARD_PREFIXES = ("command_guard", "kill_guard", "copy_hygiene", "merge_gate", "provenance", "self_serve", "settings")
POLICY_JSON = re.compile(r"^[A-Za-z0-9_]+_policy(\.local)?\.json(\.example)?$")
GUARD_EVENTS = ("PreToolUse", "Stop")

USER_INSTALL = ("python3 -I ~/.claude/hooks/ah.py install-files --host {host} --from-ref {ref} --file {files} "
                "--ticket \"GoodQA <project>#<n>\"   (run by the user in his own terminal)")


def is_guard_file(name: str) -> bool:
    base = Path(str(name)).name
    return base in GUARD_NAMES or base.startswith(GUARD_PREFIXES) or bool(POLICY_JSON.match(base))


def guard_subset(names) -> list:
    return sorted({Path(str(n)).name for n in names if is_guard_file(n)})


def refusal(host: str, ref: str, names) -> str:
    """The refusal text both routes print: which guard files differ, and the one line the user runs instead."""
    files = guard_subset(names)
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
