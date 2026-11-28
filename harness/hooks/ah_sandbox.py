#!/usr/bin/env python3
"""`ah sandbox`: the per-role boundary as native settings for Claude Code and Codex (docs/sandbox.md).

    ah sandbox show  [--role R] [--flavor F] [--json] [--project DIR]     print
    ah sandbox write [--role R] [--flavor F] --out PATH                   atomic write, mode 0600, never via a symlink
    ah sandbox write --flavor managed --managed-dir DIR                   DIR/managed-settings.d/50-agent-harness.json
    ah sandbox roles                                                      the three roles, one line each

Flavors: claude (the file for `claude --settings`), managed (the same plus managed-only locks, for
managed-settings.d), codex (three `[permissions.ah-<role>]` tables), codex-launch (the `-c` arguments that select a
profile), codex-requirements (an /etc/codex/requirements.toml body). Nothing here installs anything, writes a real
settings file, registers a hook or reads command text: the operating-system sandbox and the vendor's permission rules
enforce what this module only describes. The role data is sandbox_base.json beside this file; ~/.agent-harness/
local.json adds sandbox_allowed_domains, sandbox_extra_deny_read, sandbox_extra_write, sandbox_excluded_commands
(worker and supervisor), sandbox_role, and every host
named under hosts, remote_worktree_hosts and trusted_git_hosts joins the network allow-list. A key of the wrong type
falls back to its default (the ah_local rule). Standard library only, Python 3.9.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shlex
import sys
from pathlib import Path

ROLES = ("worker", "reviewer", "supervisor")
FLAVORS = ("claude", "managed", "codex", "codex-launch", "codex-requirements")
BASE_FILE = Path(__file__).resolve().parent / "sandbox_base.json"
MANAGED_NAME = "50-agent-harness.json"
MANAGED_DIRS = {"darwin": "/Library/Application Support/ClaudeCode", "linux": "/etc/claude-code"}
LOCAL_MAX = 256 * 1024
HOST_RE = re.compile(r"^(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9-]{1,63})*$")
REVIEWER_TOOLS = ("Edit", "NotebookEdit", "Write")
# Inside workspace roots .git is writable for git commit, merge, stash and gc, except hooks/, config and
# config.worktree, which stay read-only (as Claude Code keeps them): a planted hook or a program-valued config key
# would run later, unsandboxed, in the owner's own git. The more specific path wins; the codex sandbox run proved
# commit, merge, stash and gc work and that writing or renaming hooks/ and config is refused.
GIT_READ_ONLY = (".git/hooks", ".git/config", ".git/config.worktree")
DESCRIPTIONS = {
    "worker": "Agent Harness worker: project and session folder writable, secrets unreadable, records read-only",
    "reviewer": "Agent Harness reviewer: read-only, secrets unreadable",
    "supervisor": "Agent Harness supervisor: worker plus the approvals log, secrets unreadable",
}
SUMMARIES = {
    "worker": "writes the project, its session folder, temp and caches; reads all but secrets; records read-only",
    "reviewer": "read-only: Bash writes only $TMPDIR, the Edit/Write/NotebookEdit tools are removed",
    "supervisor": "worker plus append to approvals.jsonl; `harness` runs outside the sandbox for the owner's switch",
}


class Refused(Exception):
    """A request this module will not carry out; the message says why and how to proceed."""


# ----------------------------------------------------------------------------- data
def base() -> dict:
    """sandbox_base.json (shipped beside this file)."""
    with open(BASE_FILE, "rb") as handle:
        return json.loads(handle.read(1 << 20).decode("utf-8"))  # the shipped data file is a few KB


def _home(home=None) -> Path:
    return Path(home).expanduser() if home is not None else Path(os.environ.get("HOME") or os.path.expanduser("~"))


def load_local(home=None) -> dict:
    """local.json as a dict ({} when missing, unreadable, oversized or not an object). With no home, AH_LOCAL_CONFIG
    names the file when set (the ah_local rule); with a home, that home's ~/.agent-harness/local.json."""
    override = os.environ.get("AH_LOCAL_CONFIG") if home is None else None
    path = Path(override).expanduser() if override else _home(home) / ".agent-harness" / "local.json"
    try:
        with open(path, "rb") as handle:
            raw = handle.read(LOCAL_MAX + 1)
        data = json.loads(raw.decode("utf-8")) if len(raw) <= LOCAL_MAX else {}
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _local(home, local) -> dict:
    return local if isinstance(local, dict) else load_local(home)


def _get(local: dict, key, default):
    """The ah_local.get rule: a value of another JSON type than the default is the default."""
    value = local.get(key, default)
    if value is None or isinstance(value, bool) != isinstance(default, bool):
        return default
    if isinstance(default, (list, tuple)):
        return value if isinstance(value, (list, tuple)) else default
    return value if isinstance(value, type(default)) else default


def _strings(local, key) -> list:
    return [x for x in _get(local, key, []) if isinstance(x, str) and x and "\n" not in x and "\0" not in x]


def _unique(items) -> list:
    out = []
    for item in items:
        if item not in out:
            out.append(item)
    return out


def sandbox_role(home=None, local=None) -> str:
    """The role a managed drop-in carries on this machine: local.json `sandbox_role`, else worker."""
    role = _get(_local(home, local), "sandbox_role", "worker")
    return role if role in ROLES else "worker"


def _check_role(role) -> str:
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}: one of {', '.join(ROLES)} (the owner's own terminal has no role file)")
    return role


def domains(role, home=None, local=None) -> list:
    """The network allow-list: the role's base list, then (worker, supervisor) every local host name and
    sandbox_allowed_domains, in that order, without duplicates. Names that are not host names are dropped."""
    data, local = base(), _local(home, local)
    if role == "reviewer":
        return _unique(data["reviewer_network_allow"])
    extra = []
    hosts = _get(local, "hosts", {})
    extra += [k for k in hosts if isinstance(k, str)] if isinstance(hosts, dict) else []
    extra += _strings(local, "remote_worktree_hosts") + _strings(local, "trusted_git_hosts")
    extra += _strings(local, "sandbox_allowed_domains")
    return _unique(list(data["network_allow"]) + [h for h in extra if HOST_RE.match(h) and len(h) <= 253])


def tool_spellings(command, home=None) -> list:
    """One harness tool's exclusion under the spellings an agent uses: ~/, $HOME/ and the absolute home. The absolute
    form is the resolved home, so the installer (which resolves) and doctor or `ah sandbox show` render one file."""
    if " ~/" not in command:
        return [command]
    absolute = os.path.realpath(str(_home(home))).rstrip("/") + "/"   # resolved: one file whoever renders it
    return _unique([command, command.replace(" ~/", " $HOME/", 1), command.replace(" ~/", " " + absolute, 1)])


def lists(role, home=None, local=None) -> dict:
    """The role's lists in ~/ form: deny_read, deny_write, allow_write, excluded, domains, network_open,
    project_read_only, secret_globs."""
    _check_role(role)
    data, local = base(), _local(home, local)
    deny_read = _unique(list(data["secret_paths"]) + _strings(local, "sandbox_extra_deny_read"))
    deny_write = list(data["record_paths"])
    allow_write = []
    if role in ("worker", "supervisor"):
        allow_write = list(data["worker_write"]) + _strings(local, "sandbox_extra_write")
    if role == "supervisor":
        extra = list(data["supervisor_write_extra"])
        allow_write += extra
        deny_write = [p for p in deny_write if p not in extra]
    excluded = list(data["excluded_commands"].get(role, []))
    if role in ("worker", "supervisor"):
        for command in data["harness_tools"]:
            excluded += tool_spellings(command, home)
        excluded += _strings(local, "sandbox_excluded_commands")
    return {"deny_read": deny_read, "deny_write": _unique(deny_write), "allow_write": _unique(allow_write),
            "excluded": _unique(excluded), "domains": domains(role, home, local),
            "network_open": role in data["open_network"], "project_read_only": role == "reviewer",
            "secret_globs": list(data["secret_globs"])}


def expand(path, home) -> str:
    """A ~/ path against `home` (the doctor's view of the same list)."""
    return str(_home(home) / path[2:]) if path.startswith("~/") else path


def role_lists(role, home=None, local=None) -> dict:
    """lists() with every ~/ path made absolute against home: what `ah doctor` builds its probe profiles from."""
    found = lists(role, home, local)
    for key in ("deny_read", "deny_write", "allow_write"):
        found[key] = [expand(p, home) for p in found[key]]
    return found


# ----------------------------------------------------------------------------- Claude Code
def claude_settings(role, home=None, local=None, project=None) -> dict:
    """The settings object for `claude --settings FILE` (Claude Code 2.1.332 keys).

    `project` is the reviewer's checkout as an absolute path, put in denyWrite so the reviewer's Bash cannot write
    its working directory. It has to be the absolute path: the e2e run showed that `.` and `./` in a --settings file
    do not mean the working directory. Without `project` (the generic installed reviewer file) the Edit, Write and
    NotebookEdit tools are still removed, but Bash can write the working directory; a reviewer launch passes the
    checkout (`ah sandbox show --role reviewer --project DIR`, or this function's JSON as the --settings string)."""
    if project is not None and (role != "reviewer" or not os.path.isabs(str(project))):
        raise ValueError("project is the reviewer's checkout as an absolute path")
    found = lists(role, home, local)
    deny = []
    for path in found["deny_read"]:
        deny += [f"Read({path})", f"Read({path}/**)"]     # a Read deny also blocks Edit and Write there
    deny += [f"Read({pattern})" for pattern in found["secret_globs"]]   # project .env files, wherever they are
    for path in found["deny_write"]:
        deny += [f"Edit({path})", f"Edit({path}/**)"]     # Edit rules cover every built-in file-editing tool
    deny_write = list(found["deny_write"])
    if found["project_read_only"]:
        deny += list(REVIEWER_TOOLS)
        if project:
            deny_write.append(os.path.normpath(str(project)))
    filesystem = {"denyRead": found["deny_read"], "denyWrite": deny_write}
    if found["allow_write"]:
        filesystem["allowWrite"] = found["allow_write"]
    # Local ports (dev servers, test servers, a browser's debugging port) always bind. Outbound network stays open
    # for workers and supervisors in the first version (docs/direction.md): with no allowedDomains the proxy filters
    # nothing. A reviewer keeps a strict GitHub-only list.
    network = {"allowLocalBinding": True, "allowMachLookup": list(base()["mach_lookup"])}
    if not found["network_open"]:
        network.update(allowedDomains=found["domains"], strictAllowlist=True)
    box = {"enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False,
           "autoAllowBashIfSandboxed": True, "filesystem": filesystem, "network": network}
    if found["excluded"]:
        box["excludedCommands"] = found["excluded"]
    permissions = {"deny": _unique(deny)}
    if role == "reviewer":
        # Only the reviewer refuses bypass mode. Workers and supervisors keep the owner's normal launch
        # (--dangerously-skip-permissions): the sandbox and the deny rules are the boundary, and deny rules hold in
        # bypass mode too. Disabling it silently dropped every Edit, Write and MCP call back to a prompt.
        permissions["disableBypassPermissionsMode"] = "disable"
    return {"env": {"AH_ROLE": role, "AH_ROLE_SOURCE": f"ah-sandbox:{role}"}, "sandbox": box,
            "permissions": permissions}


def managed_settings(role, home=None, local=None) -> dict:
    """claude_settings plus the managed-only sandbox locks. Never sets allowManagedHooksOnly (it would silence the
    harness's own user hooks) or allowManagedPermissionRulesOnly (it would drop a reviewer's --settings denies)."""
    data = copy.deepcopy(claude_settings(role, home, local))
    data["sandbox"]["enableWeakerNestedSandbox"] = False
    data["sandbox"]["enableWeakerNetworkIsolation"] = False
    return data


def render_claude(data: dict) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def installed_path(home, role, flavor="claude") -> Path:
    """Where the installer puts a role's generated file: ~/.agent-harness/sandbox/<role>.<flavor>.json."""
    return _home(home) / ".agent-harness" / "sandbox" / f"{_check_role(role)}.{flavor}.json"


def managed_target(system=None) -> Path:
    system = system or sys.platform
    root = MANAGED_DIRS["darwin" if system == "darwin" else "linux"]
    return Path(root) / "managed-settings.d" / MANAGED_NAME


# ----------------------------------------------------------------------------- Codex
def _q(text) -> str:
    """A TOML basic string (JSON escapes are valid TOML escapes)."""
    return json.dumps(str(text), ensure_ascii=True)


def codex_profile(role, home=None, local=None) -> str:
    found = lists(role, home, local)
    name = f"permissions.ah-{role}"
    entries = {}
    for path in found["deny_write"]:
        entries[path] = "read"          # read-only even when a workspace root holds it
    for path in found["allow_write"]:
        entries[path] = "write"
    for path in found["deny_read"]:
        entries[path] = "deny"          # deny wins over write and read
    out = [f"[{name}]", f"description = {_q(DESCRIPTIONS[role])}",
           f"extends = {_q(':read-only' if role == 'reviewer' else ':workspace')}", "", f"[{name}.filesystem]"]
    out += [f"{_q(path)} = {_q(mode)}" for path, mode in entries.items()]
    if role != "reviewer":
        out += ["", f'[{name}.filesystem.":workspace_roots"]', '".git" = "write"']
        out += [f'{_q(path)} = "read"' for path in GIT_READ_ONLY]
    out += ["", f"[{name}.network]", "enabled = true"]
    if not found["network_open"]:
        out += ["", f"[{name}.network.domains]"] + [f"{_q(host)} = \"allow\"" for host in found["domains"]]
    return "\n".join(out) + "\n"


def codex_profiles(home=None, local=None) -> str:
    """TOML text of the three [permissions.ah-<role>] tables, no markers (the Codex installer places them)."""
    local = _local(home, local)
    return "\n".join(codex_profile(role, home, local) for role in ROLES)


def codex_launch_args(role) -> list:
    """The `codex -c` arguments that select the role's profile and export AH_ROLE to its commands."""
    _check_role(role)
    return ["-c", f'default_permissions="ah-{role}"', "-c", f'shell_environment_policy.set.AH_ROLE="{role}"']


def codex_requirements(home=None, local=None) -> str:
    """An /etc/codex/requirements.toml body: only the three profiles, the machine's default, secrets unreadable."""
    local = _local(home, local)
    deny = lists("worker", home, local)["deny_read"]
    out = ["# /etc/codex/requirements.toml (generated by `ah sandbox show --flavor codex-requirements`;",
           "# install it as root by hand, after a clean shadow day: nothing writes it for you)",
           f"default_permissions = {_q('ah-' + sandbox_role(home, local))}", "", "[allowed_permission_profiles]"]
    out += [f"{_q('ah-' + role)} = true" for role in sorted(ROLES)]
    out += ["", "[permissions.filesystem]", "deny_read = [" + ", ".join(_q(p) for p in deny) + "]"]
    return "\n".join(out) + "\n"


# ----------------------------------------------------------------------------- output
def render(flavor, role, home=None, local=None, project=None, as_json=False) -> str:
    if flavor == "claude":
        return render_claude(claude_settings(role, home, local, project))
    if flavor == "managed":
        return render_claude(managed_settings(role, home, local))
    if flavor == "codex-launch":
        args = codex_launch_args(role)
        return json.dumps(args) + "\n" if as_json else " ".join(shlex.quote(a) for a in args) + "\n"
    text = codex_profiles(home, local) if flavor == "codex" else codex_requirements(home, local)
    return json.dumps({"flavor": flavor, "text": text}, indent=2, sort_keys=True) + "\n" if as_json else text


def write_private(path, text: str) -> Path:
    """Write text to path in one rename, mode 0600. A symlink at the path, or as its parent, is refused."""
    path = Path(path).expanduser().absolute()
    if path.is_symlink():
        raise Refused(f"{path} is a symlink; refusing to write through it (remove it or pick another --out)")
    if path.parent.is_symlink():
        raise Refused(f"{path.parent} is a symlink; refusing to write through it")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{os.getpid()}.tmp"
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            os.write(fd, text.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def install_line(source: Path, system=None) -> str:
    target = managed_target(system)
    return (f"sudo install -d -m 755 {shlex.quote(str(target.parent))} && "
            f"sudo install -m 644 {shlex.quote(str(source))} {shlex.quote(str(target))}")


# ----------------------------------------------------------------------------- CLI
def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ah sandbox", description="Per-role sandbox settings (docs/sandbox.md).")
    sub = parser.add_subparsers(dest="cmd")
    for name in ("show", "write"):
        p = sub.add_parser(name)
        p.add_argument("--role", choices=ROLES)
        p.add_argument("--flavor", choices=FLAVORS, default="claude")
        p.add_argument("--home", help="the home whose local.json is read (tests; default $HOME)")
        p.add_argument("--project", help="reviewer: the checkout to make read-only by absolute path")
        if name == "show":
            p.add_argument("--json", action="store_true")
        else:
            p.add_argument("--out", help="the file to write")
            p.add_argument("--managed-dir", help="managed flavor: write DIR/managed-settings.d/" + MANAGED_NAME)
    sub.add_parser("roles")
    return parser


def main(argv=None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    except SystemExit as stop:
        return int(stop.code or 0)
    if args.cmd == "roles":
        for role in ROLES:
            print(f"{role:<11} {SUMMARIES[role]}")
        return 0
    if args.cmd not in ("show", "write"):
        parser.print_help(sys.stderr)
        return 2
    home = Path(args.home).expanduser() if args.home else None
    local = load_local(home)
    role = args.role
    if role is None and args.flavor == "managed":
        role = sandbox_role(home, local)
    if role is None and args.flavor in ("claude", "codex-launch"):
        print(f"ah sandbox {args.cmd}: --role is required for --flavor {args.flavor} ({', '.join(ROLES)})",
              file=sys.stderr)
        return 2
    if args.project and (role != "reviewer" or args.flavor != "claude"):
        print("ah sandbox: --project names the reviewer's checkout (--role reviewer, --flavor claude)", file=sys.stderr)
        return 2
    try:
        text = render(args.flavor, role, home, local, args.project, getattr(args, "json", False))
    except ValueError as error:
        print(f"ah sandbox {args.cmd}: {error}", file=sys.stderr)
        return 2
    if args.cmd == "show":
        sys.stdout.write(text)
        return 0
    if args.flavor == "managed":
        if not args.managed_dir:
            print("ah sandbox write --flavor managed: give --managed-dir DIR (a directory of yours); nothing is "
                  "written to the real managed directory. Then install it with:\n  "
                  + install_line(Path("DIR") / "managed-settings.d" / MANAGED_NAME), file=sys.stderr)
            return 2
        out = Path(args.managed_dir).expanduser() / "managed-settings.d" / MANAGED_NAME
    elif not args.out:
        print(f"ah sandbox write: --out PATH is required for --flavor {args.flavor}", file=sys.stderr)
        return 2
    else:
        out = Path(args.out)
    try:
        written = write_private(out, text)
    except (Refused, OSError) as error:
        print(f"ah sandbox write: {error}", file=sys.stderr)
        return 3
    print(f"wrote {written} ({args.flavor}{', role ' + role if role else ''}, mode 0600)")
    if args.flavor == "managed":
        print("to enforce it on this host (the owner's step, after a clean shadow day):\n  " + install_line(written))
    return 0


if __name__ == "__main__":
    sys.exit(main())
