#!/usr/bin/env python3
"""User-run enabler for agent self-serve (GoodQA goodqa#16757, lane L5 of the self-serve spec).

    python3 ~/.agent-harness/bin/ah_enable_self_serve.py            dry run: print the diff and the capability list
    python3 ~/.agent-harness/bin/ah_enable_self_serve.py --apply --ref <40-hex canonical-main SHA>
    ... --status | --undo | --disable <capability|all> | --resume RUN
    ... --bootstrap --ref <SHA>      scan, repair-harness --apply on both hosts, then --apply (one command)

This command is the human step. Every mutating mode refuses unless stdin and stdout are a terminal, no agent
process (claude, codex) is an ancestor of this process and no agent environment marker is set, and the person types
the nonce shown over the diff. There is no flag, environment variable or file that skips those checks. An agent that
runs it gets a refusal and writes nothing. It never creates accounts, never types or reads a password, never writes
Codex `trusted_hash` (it lists the hooks you must trust in `/hooks`), and it never falls back to a local copy when
the remote host step fails (the journal records the failure; use --resume or --undo).

What --apply does, in this order (each step is journaled under ~/.agent-harness/work/self-serve/<run>/):
  preflight  the pinned SHA is on canonical main and every installed hook equals its git blob (Mac and the worker)
  backup     existing managed files are copied to ~/.claude/agent-harness-backups/self-serve-<run>/
  key        create ~/.agent-harness/private/self-serve/ed25519.key (0600) or reuse it
  pin_local  pin the public key in ~/.agent-harness/policy/self-serve-pubkeys.json
  pin_remote pin it on the worker through a regular temp file (never /dev/stdin)
  claude_md / agents_md  marker block self-serve:begin..end
  settings   exact-prefix allow rules merged into ~/.claude/settings.json, tracked, user rules untouched
  codex_hook the self_serve check appended last to ~/.codex/hooks.json PreToolUse
  policy     the signed policy file is written last, so a partial run never leaves a grant behind
  audit      one row in ~/.agent-harness/policy/audit.jsonl
Rollback: --undo (restores or surgically strips each managed file and removes both key pins), or create
~/.agent-harness/policy/disabled. The private key is kept so a later apply reuses it.
"""
from __future__ import annotations

import argparse
import ast
import base64
import difflib
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import stat
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA = "self-serve/1"
PURPOSE = "self-serve"
KEYS_SCHEMA = "self-serve-keys/1"
STATE_SCHEMA = "self-serve-enabler/1"
REPO = "ericmacdougall/agent-harness"
ORIGIN = "https://github.com/%s.git" % REPO
DEFAULT_HOST = "t2-dev"
CAPABILITIES = ("same_harness_fallback_review", "merge_reviewed_pr", "harness_repair", "pool_cleanup",
                "install_files_manifest", "central_decisions_agent_steps")
CAPABILITY_TEXT = {
    "same_harness_fallback_review": "accept a settled same-harness exact-HEAD PASS when the other harness is out of quota (receipt, rung and denylist limits)",
    "merge_reviewed_pr": "merge one reviewed PR through `ah ops merge`",
    "harness_repair": "run the journaled `ah ops repair` recipe on both hosts",
    "pool_cleanup": "reap this session's own dead pool reservations",
    "install_files_manifest": "run `ah install-files` in manifest mode",
    "central_decisions_agent_steps": "run the merge, repair, enable and adapter steps of the central-decisions recipe (never approve, keygen, pin or publish)",
}
TTL_SECONDS = {"same_harness_fallback_review": 900, "merge_reviewed_pr": 900, "harness_repair": 3600,
               "pool_cleanup": 3600, "install_files_manifest": 3600, "central_decisions_agent_steps": 3600}
MARK_BEGIN = "<!-- self-serve:begin -->"
MARK_END = "<!-- self-serve:end -->"
# id -> exact allow rule. `waive`, `approve-top`, `decision keygen|pin|publish`, raw `gh pr merge`, secrets and shell
# wrappers are deliberately absent (spec section 2).
ALLOW_RULES = {
    "ops": "Bash(python3 ~/.claude/hooks/ah.py ops *)",
    "install-files": "Bash(python3 ~/.claude/hooks/ah.py install-files *)",
    "decision-verify": "Bash(python3 ~/.claude/hooks/ah.py decision verify *)",
    "decision-status": "Bash(python3 ~/.claude/hooks/ah.py decision status *)",
    "repair-harness": "Bash(~/.agent-harness/bin/repair-harness *)",
}
CODEX_HOOK_NAME = "self_serve.py"
AGENT_NAME = re.compile(r"^(claude|codex)([-_.].*)?$|claude-code|codex-", re.I)
AGENT_ENV = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CODEX_THREAD_ID", "CODEX_SESSION_ID", "CODEX_SANDBOX")
REF = re.compile(r"^[0-9a-f]{40}$")
HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$")
RUN = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$")
KEY_ID = re.compile(r"^[0-9a-f]{16}$")
# The bootstrap surface: the files that run before any trust exists. Only the agent-rules category is expected (they
# write the user's CLAUDE.md, settings.json and AGENTS.md); any other category refuses the bootstrap.
BOOTSTRAP_SURFACE = ("install.py", "install_codex.py", "scripts/repair-harness.sh", "scripts/repair_harness.py",
                     "scripts/enable-agent-ops.py", "templates/self-serve-block.md")
BOOTSTRAP_OK_CATEGORIES = {"agent-rules"}
REMOTE_HASH_CODE = (
    "import hashlib,json,os,sys\n"
    "out={}\n"
    "for n in json.load(sys.stdin):\n"
    "    try:\n"
    "        with open(os.path.expanduser('~/.claude/hooks/'+n),'rb') as f:\n"
    "            d=f.read()\n"
    "        out[n]=hashlib.sha1(b'blob %d\\0'%len(d)+d).hexdigest()\n"
    "    except OSError:\n"
    "        out[n]=None\n"
    "print(json.dumps(out))\n")


class Refused(Exception):
    """A refusal; nothing further is written."""


# ----------------------------------------------------------------------------------------------- small helpers
def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical(obj) -> bytes:
    """Canonical JSON for signing: sorted keys, compact separators, ASCII."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def key_id_of(public_raw: bytes) -> str:
    return hashlib.sha256(b"agent-harness-self-serve-key\x00" + public_raw).hexdigest()[:16]


def now_iso(now=None) -> str:
    return datetime.fromtimestamp(time.time() if now is None else now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        raise Refused("the cryptography package is required (use /usr/bin/python3 or a Python that has it)") from None
    return ed25519, serialization


class Layout:
    def __init__(self, home):
        self.home = Path(home)
        self.claude = self.home / ".claude"
        self.codex = self.home / ".codex"
        self.ah = self.home / ".agent-harness"
        self.policy_dir = self.ah / "policy"
        self.policy = self.policy_dir / "self-serve.json"
        self.kill = self.policy_dir / "disabled"
        self.pubkeys = self.policy_dir / "self-serve-pubkeys.json"
        self.state = self.policy_dir / "enabler-state.json"
        self.audit = self.policy_dir / "audit.jsonl"
        self.keyfile = self.ah / "private" / "self-serve" / "ed25519.key"
        self.claude_md = self.claude / "CLAUDE.md"
        self.settings = self.claude / "settings.json"
        self.agents_md = self.codex / "AGENTS.md"
        self.hooks_json = self.codex / "hooks.json"
        self.backups = self.claude / "agent-harness-backups"
        self.work = self.ah / "work" / "self-serve"
        self.codex_hook_script = self.codex / "agent-harness" / CODEX_HOOK_NAME

    def managed(self):
        return {"policy": self.policy, "pubkeys": self.pubkeys, "claude_md": self.claude_md, "settings": self.settings,
                "agents_md": self.agents_md, "hooks_json": self.hooks_json}


def _check_no_symlink(path: Path, stop: Path):
    probe = path
    while True:
        if probe.is_symlink():
            raise Refused("refusing a symlinked path: %s" % probe)
        if probe == stop or probe.parent == probe:
            return
        probe = probe.parent


def read_file(path: Path):
    """(bytes, mode) of a regular file, or None when absent. Symlinks and non-regular files are refused."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise Refused("not a regular file: %s" % path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        return os.read(fd, info.st_size + 1) if info.st_size else b"", stat.S_IMODE(info.st_mode)
    finally:
        os.close(fd)


def ensure_dir(path: Path, mode=0o700):
    _check_no_symlink(path, path.parent.parent)
    created = not path.exists()
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    if created:
        os.chmod(path, mode)


def write_atomic(path: Path, data: bytes, mode=0o600):
    ensure_dir(path.parent)
    if path.is_symlink():
        raise Refused("refusing to write through a symlink: %s" % path)
    tmp = path.parent / (".enable-%s.tmp" % secrets.token_hex(8))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def remove_file(path: Path):
    try:
        path.unlink()
    except FileNotFoundError:
        pass


# ----------------------------------------------------------------------------------------- pure transformations
def render_block(template: str, capabilities, policy_id: str, key_id: str) -> str:
    lines = "\n".join("- `%s`: %s" % (cap, CAPABILITY_TEXT[cap]) for cap in capabilities)
    block = template.replace("{{CAPABILITIES}}", lines).replace("{{POLICY_ID}}", policy_id).replace("{{KEY_ID}}", key_id)
    if "{{" in block or MARK_BEGIN not in block or MARK_END not in block:
        raise Refused("the self-serve block template is malformed")
    return block if block.endswith("\n") else block + "\n"


def _marker_span(text: str):
    begins, ends = text.count(MARK_BEGIN), text.count(MARK_END)
    if begins == 0 and ends == 0:
        return None
    if begins != 1 or ends != 1 or text.index(MARK_BEGIN) > text.index(MARK_END):
        raise Refused("malformed self-serve markers; resolve the file by hand")
    start = text.index(MARK_BEGIN)
    end = text.index(MARK_END) + len(MARK_END)
    if text[end:end + 1] == "\n":
        end += 1
    return start, end


def add_block(text: str, block: str) -> str:
    span = _marker_span(text)
    if span:
        return text[:span[0]] + block + text[span[1]:]
    if not text:
        return block
    separator = "\n" if text.endswith("\n") else "\n\n"  # always one blank line before the block (remove_block undoes it)
    return text + separator + block


def remove_block(text: str) -> str:
    span = _marker_span(text)
    if not span:
        return text
    start, end = span
    if text[:start].endswith("\n\n") and start >= 2:
        start -= 1  # the single blank line add_block put before the block
    return text[:start] + text[end:]


def merge_allow(settings: dict, rule_ids=None):
    """Add the exact rules that are missing; return (settings, ids this call added). User rules are never removed."""
    if not isinstance(settings, dict):
        raise Refused("settings.json must contain an object")
    result = json.loads(json.dumps(settings))
    permissions = result.setdefault("permissions", {})
    if not isinstance(permissions, dict):
        raise Refused("settings.json permissions must be an object")
    allow = permissions.setdefault("allow", [])
    if not isinstance(allow, list):
        raise Refused("settings.json permissions.allow must be a list")
    added = []
    for rule_id in (rule_ids or ALLOW_RULES):
        if ALLOW_RULES[rule_id] not in allow:
            allow.append(ALLOW_RULES[rule_id])
            added.append(rule_id)
    return result, added


def strip_allow(settings: dict, rule_ids):
    result = json.loads(json.dumps(settings))
    allow = result.get("permissions", {}).get("allow") if isinstance(result.get("permissions"), dict) else None
    if isinstance(allow, list):
        drop = {ALLOW_RULES[i] for i in rule_ids if i in ALLOW_RULES}
        allow[:] = [rule for rule in allow if rule not in drop]
    return result


def codex_hook_command(layout: Layout) -> str:
    # Fail open: the check must never block a Codex tool call by itself, and a missing verb or file exits 0.
    return "python3 %s hook || exit 0" % shlex.quote(str(layout.codex_hook_script))


def append_codex_hook(hooks: dict, command: str):
    """Append the check as the last PreToolUse group so every trusted position above it stays valid."""
    if not isinstance(hooks, dict):
        raise Refused("hooks.json must contain an object")
    result = json.loads(json.dumps(hooks))
    section = result.setdefault("hooks", {})
    groups = section.setdefault("PreToolUse", [])
    if not isinstance(section, dict) or not isinstance(groups, list):
        raise Refused("hooks.json PreToolUse must be a list")
    for group in groups:
        for handler in (group.get("hooks") or []) if isinstance(group, dict) else []:
            if isinstance(handler, dict) and handler.get("command") == command:
                return result, False
    groups.append({"hooks": [{"type": "command", "command": command, "timeout": 10}]})
    return result, True


def remove_codex_hook(hooks: dict, command: str):
    result = json.loads(json.dumps(hooks))
    groups = result.get("hooks", {}).get("PreToolUse") if isinstance(result.get("hooks"), dict) else None
    if isinstance(groups, list):
        kept = []
        for group in groups:
            handlers = [h for h in group.get("hooks", []) if not (isinstance(h, dict) and h.get("command") == command)]
            if handlers or not isinstance(group, dict) or "hooks" not in group:
                kept.append({**group, "hooks": handlers} if isinstance(group, dict) and "hooks" in group else group)
        groups[:] = kept
    return result


def build_policy(key_id: str, *, repos, hosts, disabled=(), expires_days=None, now=None, policy_id=None) -> dict:
    capabilities = {}
    for cap in CAPABILITIES:
        scope = {"repos": sorted(repos)} if cap in ("same_harness_fallback_review", "merge_reviewed_pr") \
            else {"hosts": sorted(hosts)}
        capabilities[cap] = {"scope": scope, "ttl_seconds": TTL_SECONDS[cap]}
    when = time.time() if now is None else now
    return {"schema": SCHEMA, "purpose": PURPOSE, "policy_id": policy_id or secrets.token_hex(16), "key_id": key_id,
            "issued_at": now_iso(when),
            "expires_at": now_iso(when + expires_days * 86400) if expires_days else None,
            "capabilities": capabilities, "disabled": sorted(set(disabled))}


def sign_policy(policy: dict, private_key) -> dict:
    body = {k: v for k, v in policy.items() if k != "signature"}
    return {**body, "signature": b64url(private_key.sign(canonical(body)))}


def verify_policy(policy, pinned_keys: dict) -> str | None:
    """None when valid, else the reason. Purpose-bound: only a key pinned for self-serve verifies."""
    ed25519, _ = crypto()
    try:
        if policy.get("schema") != SCHEMA or policy.get("purpose") != PURPOSE:
            return "wrong schema or purpose"
        public = pinned_keys.get(policy.get("key_id"))
        if not public:
            return "key id is not pinned"
        body = {k: v for k, v in policy.items() if k != "signature"}
        ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(public)).verify(
            b64url_decode(policy["signature"]), canonical(body))
        return None
    except Exception:  # noqa: BLE001 - any failure is "not valid"
        return "signature does not verify"


def load_pinned(layout: Layout) -> dict:
    try:
        raw = read_file(layout.pubkeys)
        record = json.loads(raw[0]) if raw else {}
        return {k["key_id"]: k["public_key"] for k in record.get("keys", [])
                if isinstance(k, dict) and KEY_ID.match(str(k.get("key_id", "")))}
    except (Refused, ValueError, OSError, TypeError):
        return {}


# --------------------------------------------------------------------------------------------- environment seams
class Env:
    """Who is running this. The real implementation reads the terminal, the process table and the environment."""

    def is_tty(self) -> bool:
        return sys.stdin.isatty() and sys.stdout.isatty()

    def environ(self) -> dict:
        return dict(os.environ)

    def process_table(self) -> dict:
        out = subprocess.run(["/bin/ps", "-axo", "pid=,ppid=,command="], capture_output=True, text=True, timeout=20).stdout
        table = {}
        for line in out.splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
                table[int(parts[0])] = (int(parts[1]), parts[2])
        return table

    def pid(self) -> int:
        return os.getpid()

    def read_nonce(self, prompt: str) -> str:
        return input(prompt)


def agent_ancestor(table: dict, pid: int):
    seen = set()
    while pid in table and pid not in seen and len(seen) < 64:
        seen.add(pid)
        ppid, command = table[pid]
        words = command.split()
        names = [os.path.basename(w) for w in words[:3]]
        if any(AGENT_NAME.search(n) for n in names):
            return pid, os.path.basename(words[0])
        pid = ppid
    return None


def require_human(env: Env):
    if not env.is_tty():
        raise Refused("this command is the human step: it needs an interactive terminal on stdin and stdout "
                      "(an agent, a pipe or a script cannot run it)")
    marker = [name for name in AGENT_ENV if env.environ().get(name)]
    if marker:
        raise Refused("an agent session environment is present (%s); run this from your own terminal" % marker[0])
    try:
        table = env.process_table()
    except (OSError, subprocess.SubprocessError):
        raise Refused("could not read the process table to prove no agent is an ancestor; refusing") from None
    found = agent_ancestor(table, env.pid())
    if found:
        raise Refused("an agent process (%s, pid %d) is an ancestor of this command; run it from your own terminal"
                      % (found[1], found[0]))


def confirm(env: Env, label: str):
    nonce = "%s-%s" % (label, secrets.token_hex(3))
    answer = env.read_nonce("Type %s to continue (anything else cancels): " % nonce)
    if not hmac.compare_digest(answer.strip().encode(), nonce.encode()):
        raise Refused("the nonce did not match; nothing was changed")


class Upstream:
    """Canonical-main facts through the GitHub CLI (read only)."""

    def __init__(self, repo=REPO, gh="gh"):
        self.repo, self.gh = repo, gh

    def _gh(self, *args):
        done = subprocess.run([self.gh, "api", *args], capture_output=True, text=True, timeout=60)
        if done.returncode != 0:
            raise Refused("could not read canonical main from GitHub (gh api exit %d)" % done.returncode)
        return done.stdout

    def is_canonical(self, ref: str) -> bool:
        status = self._gh("repos/%s/compare/main...%s" % (self.repo, ref), "--jq", ".status").strip()
        return status in ("identical", "behind")

    def hook_blobs(self, ref: str) -> dict:
        """{hook name: git blob sha} for every file the installer at `ref` lists in HOOKS."""
        source = self._gh("-H", "Accept: application/vnd.github.raw", "repos/%s/contents/install.py?ref=%s" % (self.repo, ref))
        names = hook_names_from_installer(source)
        listing = self._gh("repos/%s/git/trees/%s:harness/hooks" % (self.repo, ref), "--jq", '.tree[]|"\\(.path) \\(.sha)"')
        shas = dict(line.split(" ", 1) for line in listing.splitlines() if " " in line)
        missing = [n for n in names if n not in shas]
        if missing:
            raise Refused("canonical main at the pinned SHA lacks hooks the installer lists: %s" % ", ".join(missing[:5]))
        return {n: shas[n] for n in names}


def hook_names_from_installer(source: str) -> list:
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "HOOKS" for t in node.targets):
            names = [n.value for n in ast.walk(node.value) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
            if names:
                return names
    raise Refused("could not read the HOOKS manifest from the pinned installer")


class Remote:
    def __init__(self, ssh="/usr/bin/ssh"):
        self.ssh = ssh

    def run(self, host: str, command: str, stdin: bytes | None = None, timeout=90):
        if not HOST.match(host):
            raise Refused("not a plain SSH host name")
        done = subprocess.run([self.ssh, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", host, command],
                              input=stdin, capture_output=True, timeout=timeout)
        return done.returncode, done.stdout.decode("utf-8", "replace")


def remote_pin_command() -> str:
    script = ('umask 077; d="$HOME/.agent-harness/policy"; mkdir -p "$d" && t=$(mktemp "$d/.pin.XXXXXX") '
              '&& cat > "$t" && mv -f "$t" "$d/self-serve-pubkeys.json"')
    return "sh -c " + shlex.quote(script)


def remote_unpin_command(key_id: str) -> str:
    if not KEY_ID.match(key_id):
        raise Refused("bad key id")
    script = ('f="$HOME/.agent-harness/policy/self-serve-pubkeys.json"; '
              'if grep -q %s "$f" 2>/dev/null; then rm -f "$f"; fi' % key_id)
    return "sh -c " + shlex.quote(script)


def remote_hash_command() -> str:
    return "python3 -c " + shlex.quote(REMOTE_HASH_CODE)


class Runner:
    def run(self, argv, **kwargs) -> int:
        return subprocess.run(argv, **kwargs).returncode

    def capture(self, argv, **kwargs):
        done = subprocess.run(argv, capture_output=True, text=True, **kwargs)
        return done.returncode, done.stdout


# --------------------------------------------------------------------------------------------------- the engine
STEPS = ("preflight", "backup", "key", "pin_local", "pin_remote", "claude_md", "agents_md", "settings", "codex_hook",
         "policy", "audit")


class Enabler:
    def __init__(self, layout: Layout, *, env=None, upstream=None, remote=None, template=None, out=print,
                 on_step=None, now=None):
        self.layout = layout
        self.env = env or Env()
        self.upstream = upstream or Upstream()
        self.remote = remote or Remote()
        self.out = out
        self.on_step = on_step or (lambda step: None)  # tests inject a failure here
        self.clock = now
        self.template = template if template is not None else load_template()

    # ----- planning (pure reads)
    def plan(self, params: dict) -> dict:
        """The exact bytes each managed file would hold after --apply. Reads only."""
        layout = self.layout
        raw_key = self._public_raw_if_present()
        key_id = key_id_of(raw_key) if raw_key else "(created on apply)"
        policy_id = params.get("policy_id") or "(new on apply)"
        block = render_block(self.template, CAPABILITIES, policy_id, key_id)
        files = {}
        existing = read_file(layout.claude_md)
        files["claude_md"] = (existing[0] if existing else None,
                              add_block(existing[0].decode() if existing else "", block).encode())
        existing = read_file(layout.agents_md)
        files["agents_md"] = (existing[0] if existing else None,
                              add_block(existing[0].decode() if existing else "", block).encode())
        existing = read_file(layout.settings)
        settings, added = merge_allow(json.loads(existing[0]) if existing and existing[0].strip() else {})
        files["settings"] = (existing[0] if existing else None, (json.dumps(settings, indent=2) + "\n").encode())
        existing = read_file(layout.hooks_json)
        hooks, _ = append_codex_hook(json.loads(existing[0]) if existing and existing[0].strip() else {},
                                     codex_hook_command(layout))
        files["hooks_json"] = (existing[0] if existing else None, (json.dumps(hooks, indent=2) + "\n").encode())
        return files

    def _public_raw_if_present(self):
        try:
            raw = read_file(self.layout.keyfile)
        except Refused:
            return None
        if not raw:
            return None
        ed25519, serialization = crypto()
        try:
            key = serialization.load_pem_private_key(raw[0], password=None)
            return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        except (ValueError, TypeError):
            raise Refused("the self-serve signing key exists but cannot be loaded; inspect it by hand") from None

    def preflight(self, ref: str, host, skip_remote: bool):
        """NEG-3: the pinned SHA is on canonical main and every installed hook equals its blob there."""
        if not REF.match(ref or ""):
            raise Refused("--ref must be a full 40-hex commit SHA that is on canonical main")
        if not self.upstream.is_canonical(ref):
            raise Refused("the pinned SHA %s is not on canonical main" % ref[:12])
        expected = self.upstream.hook_blobs(ref)
        drift = []
        hooks_dir = self.layout.claude / "hooks"
        for name, want in expected.items():
            try:
                raw = read_file(hooks_dir / name)
            except Refused:
                raw = None
            if raw is None or blob_sha(raw[0]) != want:
                drift.append(name)
        if drift:
            raise Refused("installed hooks differ from the pinned SHA on this Mac (%d, first: %s); run repair-harness "
                          "at that SHA first" % (len(drift), ", ".join(drift[:5])))
        if skip_remote or not host:
            return
        code, output = self.remote.run(host, remote_hash_command(), json.dumps(sorted(expected)).encode())
        if code != 0:
            raise Refused("could not read the installed hooks on %s (exit %d); not continuing" % (host, code))
        try:
            installed = json.loads(output.strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise Refused("unreadable hook inventory from %s" % host) from None
        drift = [n for n, want in expected.items() if installed.get(n) != want]
        if drift:
            raise Refused("installed hooks differ from the pinned SHA on %s (%d, first: %s)"
                          % (host, len(drift), ", ".join(drift[:5])))

    def show_plan(self, params: dict):
        for label, (old, new) in self.plan(params).items():
            path = self.layout.managed()[label]
            diff = difflib.unified_diff((old or b"").decode("utf-8", "replace").splitlines(True),
                                        new.decode("utf-8", "replace").splitlines(True),
                                        "a/%s" % path, "b/%s" % path)
            self.out("".join(diff) or "(no change to %s)" % path)
        self.out("signing key: %s" % ("reused" if self._public_raw_if_present() else "would be created (0600)"))
        self.out("policy file: %s (signed, written last)" % self.layout.policy)
        self.out("remote key pin: %s" % ("skipped" if params["skip_remote"] else "%s via a regular temp file" % params["host"]))
        self.out("capabilities:")
        for cap in CAPABILITIES:
            self.out("  %s: %s" % (cap, CAPABILITY_TEXT[cap]))

    def dry_run(self, params: dict) -> int:
        before = self._managed_digest()
        self.out("DRY RUN: nothing will be changed. Use --apply (in your own terminal) to apply.")
        notes = []
        if params.get("ref"):
            try:
                self.preflight(params["ref"], params["host"], params["skip_remote"])
                notes.append("preflight ok: the pinned SHA is on canonical main and installed hooks equal it")
            except Refused as error:
                notes.append("preflight would refuse: %s" % error)
        else:
            notes.append("no --ref given: --apply will refuse until it names a canonical-main SHA")
        self.show_plan(params)
        for note in notes:
            self.out("NOTE: %s" % note)
        if self._managed_digest() != before:  # self-check: a dry run must be read-only
            raise RuntimeError("dry run changed a managed file")
        return 0

    def _managed_digest(self) -> dict:
        digest = {}
        for label, path in self.layout.managed().items():
            raw = read_file(path) if not path.is_symlink() else None
            digest[label] = sha256(raw[0]) if raw else None
        digest["key"] = sha256(read_file(self.layout.keyfile)[0]) if read_file(self.layout.keyfile) else None
        return digest

    # ----- apply
    def new_run_id(self) -> str:
        return datetime.fromtimestamp(time.time() if self.clock is None else self.clock, timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)

    def apply(self, params: dict, run_id: str | None = None, journal: dict | None = None) -> int:
        layout = self.layout
        resuming = journal is not None
        run_id = run_id or self.new_run_id()
        if not resuming:
            if layout.state.exists():
                raise Refused("an earlier run is recorded in %s; use --status, then --resume RUN or --undo" % layout.state)
            self.preflight(params["ref"], params["host"], params["skip_remote"])  # before asking for the nonce
            journal = {"schema": STATE_SCHEMA, "run": run_id, "params": params, "steps": {s: "pending" for s in STEPS},
                       "started_at": now_iso(self.clock), "files": {}, "rules_added": [], "codex_hook_added": False,
                       "key_created": False, "remote_pinned": False}
            self.show_plan(params)
            confirm(self.env, "enable")
        for step in STEPS:
            if journal["steps"].get(step) == "done":
                continue
            journal["steps"][step] = "running"
            self._save_journal(journal)
            try:
                self.on_step(step)
                getattr(self, "step_" + step)(journal)
            except BaseException as error:
                journal["steps"][step] = "failed: %s" % type(error).__name__
                self._save_journal(journal)
                self.out("STOPPED at step '%s' (%s). Nothing falls back to a local copy. Run --resume %s to continue "
                         "or --undo to roll back." % (step, error, run_id))
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise
                return 1
            journal["steps"][step] = "done"
            self._save_journal(journal)
        self.out("Applied run %s. Policy %s, key %s." % (run_id, journal.get("policy_id"), journal.get("key_id")))
        hooks = self.codex_untrusted(journal)
        if hooks:
            self.out("Codex will skip these hooks until you trust them in /hooks (this command never writes trust):")
            for line in hooks:
                self.out("  " + line)
        return 0

    def codex_untrusted(self, journal) -> list:
        if not journal.get("codex_hook_added"):
            return []
        raw = read_file(self.layout.hooks_json)
        try:
            groups = json.loads(raw[0])["hooks"]["PreToolUse"]
        except (TypeError, ValueError, KeyError):
            return []
        command = codex_hook_command(self.layout)
        return ["pre_tool_use group %d: %s" % (i, command) for i, g in enumerate(groups)
                if any(h.get("command") == command for h in g.get("hooks", []) if isinstance(h, dict))]

    def _journal_path(self, run_id) -> Path:
        return self.layout.work / run_id / "journal.json"

    def _save_journal(self, journal: dict):
        write_atomic(self._journal_path(journal["run"]), (json.dumps(journal, indent=2, sort_keys=True) + "\n").encode())
        write_atomic(self.layout.state, (json.dumps(journal, indent=2, sort_keys=True) + "\n").encode())

    def _record_file(self, journal, label):
        path = self.layout.managed()[label]
        raw = read_file(path)
        journal["files"].setdefault(label, {})["sha_after"] = sha256(raw[0]) if raw else None

    # ----- steps
    def step_preflight(self, journal):
        p = journal["params"]
        self.preflight(p["ref"], p["host"], p["skip_remote"])

    def step_backup(self, journal):
        layout = self.layout
        target = layout.backups / ("self-serve-" + journal["run"])
        ensure_dir(layout.backups)
        ensure_dir(target)
        manifest = {}
        for label, path in layout.managed().items():
            raw = read_file(path)
            entry = {"path": str(path), "existed": raw is not None, "sha256": sha256(raw[0]) if raw else None,
                     "mode": raw[1] if raw else None}
            if raw is not None:
                write_atomic(target / label, raw[0], 0o600)
            manifest[label] = entry
        write_atomic(target / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
        journal["backup"] = str(target)
        for label, entry in manifest.items():
            journal["files"].setdefault(label, {}).update(entry)

    def _private_key(self):
        ed25519, serialization = crypto()
        raw = read_file(self.layout.keyfile)
        if raw is None:
            return None
        if raw[1] & 0o077:
            raise Refused("the signing key must be mode 0600")
        try:
            return serialization.load_pem_private_key(raw[0], password=None)
        except (ValueError, TypeError):
            raise Refused("the signing key could not be loaded") from None

    def step_key(self, journal):
        ed25519, serialization = crypto()
        key = self._private_key()
        if key is None:
            key = ed25519.Ed25519PrivateKey.generate()
            ensure_dir(self.layout.keyfile.parent)
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
            fd = os.open(self.layout.keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, pem)
                os.fsync(fd)
            finally:
                os.close(fd)
            journal["key_created"] = True
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        journal["key_id"], journal["public_key"] = key_id_of(raw), b64url(raw)

    def _pin_record(self, journal) -> bytes:
        return (json.dumps({"schema": KEYS_SCHEMA, "keys": [{"key_id": journal["key_id"],
                                                             "public_key": journal["public_key"]}]},
                           sort_keys=True, indent=1) + "\n").encode()

    def step_pin_local(self, journal):
        write_atomic(self.layout.pubkeys, self._pin_record(journal), 0o600)
        self._record_file(journal, "pubkeys")

    def step_pin_remote(self, journal):
        p = journal["params"]
        if p["skip_remote"]:
            journal["remote_pinned"] = False
            return
        code, _ = self.remote.run(p["host"], remote_pin_command(), self._pin_record(journal))
        if code != 0:
            raise Refused("pinning the key on %s failed (exit %d); REMOTE state may be uncertain, inspect it before "
                          "retrying" % (p["host"], code))
        journal["remote_pinned"] = True

    def _block(self, journal) -> str:
        policy_id = journal.setdefault("policy_id", secrets.token_hex(16))
        return render_block(self.template, CAPABILITIES, policy_id, journal["key_id"])

    def _write_block(self, journal, label):
        path = self.layout.managed()[label]
        raw = read_file(path)
        text = add_block(raw[0].decode() if raw else "", self._block(journal))
        write_atomic(path, text.encode(), raw[1] if raw else 0o600)
        self._record_file(journal, label)

    def step_claude_md(self, journal):
        self._write_block(journal, "claude_md")

    def step_agents_md(self, journal):
        self._write_block(journal, "agents_md")

    def step_settings(self, journal):
        raw = read_file(self.layout.settings)
        settings, added = merge_allow(json.loads(raw[0]) if raw and raw[0].strip() else {})
        journal["rules_added"] = sorted(set(journal["rules_added"]) | set(added))
        write_atomic(self.layout.settings, (json.dumps(settings, indent=2) + "\n").encode(), raw[1] if raw else 0o600)
        self._record_file(journal, "settings")

    def step_codex_hook(self, journal):
        raw = read_file(self.layout.hooks_json)
        hooks, added = append_codex_hook(json.loads(raw[0]) if raw and raw[0].strip() else {},
                                         codex_hook_command(self.layout))
        journal["codex_hook_added"] = bool(journal["codex_hook_added"] or added)
        write_atomic(self.layout.hooks_json, (json.dumps(hooks, indent=2) + "\n").encode(), raw[1] if raw else 0o600)
        self._record_file(journal, "hooks_json")

    def step_policy(self, journal):
        key = self._private_key()
        p = journal["params"]
        policy = build_policy(journal["key_id"], repos=p["repos"], hosts=["mac"] + ([p["host"]] if not p["skip_remote"] else []),
                              expires_days=p.get("expires_days"), now=self.clock, policy_id=journal.get("policy_id"))
        write_atomic(self.layout.policy, (json.dumps(sign_policy(policy, key), indent=2, sort_keys=True) + "\n").encode(), 0o600)
        journal["policy_id"] = policy["policy_id"]
        self._record_file(journal, "policy")

    def step_audit(self, journal):
        self.audit("apply", journal, files={k: v.get("sha_after") for k, v in journal["files"].items()})

    def audit(self, event, journal, **extra):
        row = {"ts": now_iso(self.clock), "event": event, "run": journal.get("run"), "policy_id": journal.get("policy_id"),
               "key_id": journal.get("key_id"), "ref": journal.get("params", {}).get("ref"), **extra}
        path = self.layout.audit
        existing = read_file(path)
        write_atomic(path, (existing[0] if existing else b"") + (json.dumps(row, sort_keys=True) + "\n").encode(), 0o600)

    # ----- undo, disable, status
    def undo(self) -> int:
        layout = self.layout
        raw = read_file(layout.state)
        if raw is None:
            raise Refused("nothing to undo: no enabler state under %s" % layout.policy_dir)
        journal = json.loads(raw[0])
        confirm(self.env, "undo")
        backup = Path(journal.get("backup", "")) if journal.get("backup") else None
        files = journal.get("files", {})
        for label, path in layout.managed().items():
            entry = files.get(label)
            if not entry:
                continue
            current = read_file(path)
            current_sha = sha256(current[0]) if current else None
            saved = read_file(backup / label) if backup and entry.get("existed") else None
            if label in ("policy", "pubkeys"):
                if entry.get("existed") and saved:
                    write_atomic(path, saved[0], entry.get("mode") or 0o600)
                else:
                    remove_file(path)
            elif current_sha is not None and current_sha == entry.get("sha_after"):
                if saved:
                    write_atomic(path, saved[0], entry.get("mode") or 0o600)  # byte-exact original
                else:
                    remove_file(path)
            elif current:
                text = current[0].decode("utf-8", "replace")
                if label in ("claude_md", "agents_md"):
                    new = remove_block(text)
                elif label == "settings":
                    new = json.dumps(strip_allow(json.loads(text), journal.get("rules_added", [])), indent=2) + "\n"
                else:
                    new = json.dumps(remove_codex_hook(json.loads(text), codex_hook_command(layout)), indent=2) + "\n"
                write_atomic(path, new.encode(), current[1])
        result = 0
        if journal.get("remote_pinned") and journal.get("params", {}).get("host"):
            code, _ = self.remote.run(journal["params"]["host"], remote_unpin_command(journal["key_id"]))
            if code != 0:
                self.out("WARNING: could not remove the key pin on %s (exit %d); remove it by hand" % (journal["params"]["host"], code))
                result = 1
        self.audit("undo", journal)
        remove_file(layout.state)
        self.out("Undone run %s. The signing key was kept for reuse. %s" % (journal["run"], "Backup: %s" % backup if backup else ""))
        return result

    def disable(self, what: str) -> int:
        layout = self.layout
        if what != "all" and what not in CAPABILITIES:
            raise Refused("unknown capability %r (known: %s, or 'all')" % (what, ", ".join(CAPABILITIES)))
        confirm(self.env, "disable")
        if what == "all":
            write_atomic(layout.kill, b"disabled by ah_enable_self_serve.py --disable all\n", 0o600)
            self.out("Kill switch written: %s (every capability refuses)" % layout.kill)
            self.audit("disable", {}, capability="all")
            return 0
        raw = read_file(layout.policy)
        key = self._private_key()
        if raw is None or key is None:
            raise Refused("no policy or no signing key to re-sign")
        policy = json.loads(raw[0])
        policy["disabled"] = sorted(set(policy.get("disabled", [])) | {what})
        write_atomic(layout.policy, (json.dumps(sign_policy(policy, key), indent=2, sort_keys=True) + "\n").encode(), 0o600)
        self.audit("disable", {"policy_id": policy.get("policy_id"), "key_id": policy.get("key_id")}, capability=what)
        self.out("Disabled %s in policy %s" % (what, policy.get("policy_id")))
        return 0

    def status(self) -> dict:
        layout = self.layout
        raw = read_file(layout.policy)
        policy = json.loads(raw[0]) if raw else None
        pinned = load_pinned(layout)
        settings = read_file(layout.settings)
        allow = []
        if settings and settings[0].strip():
            allow = (json.loads(settings[0]).get("permissions") or {}).get("allow") or []
        has_block = lambda p: bool((lambda r: r and MARK_BEGIN in r[0].decode("utf-8", "replace"))(read_file(p)))  # noqa: E731
        hooks = read_file(layout.hooks_json)
        state = read_file(layout.state)
        return {"policy_file": raw is not None,
                "policy_id": policy.get("policy_id") if policy else None,
                "signature": (verify_policy(policy, pinned) or "valid") if policy else None,
                "key_id": policy.get("key_id") if policy else None,
                "capabilities": sorted(policy.get("capabilities", {})) if policy else [],
                "disabled": policy.get("disabled", []) if policy else [],
                "kill_switch": layout.kill.exists(),
                "key_present": read_file(layout.keyfile) is not None,
                "pinned_key_ids": sorted(pinned),
                "claude_md_block": has_block(layout.claude_md), "agents_md_block": has_block(layout.agents_md),
                "allow_rules": {i: r in allow for i, r in ALLOW_RULES.items()},
                "codex_hook": bool(hooks and codex_hook_command(layout) in hooks[0].decode("utf-8", "replace")),
                "run": json.loads(state[0]).get("run") if state else None,
                "steps": json.loads(state[0]).get("steps") if state else None}


def load_template() -> str:
    here = Path(__file__).resolve().parent
    for candidate in (here / "self-serve-block.md", here.parent / "templates" / "self-serve-block.md"):
        if candidate.is_file():
            return candidate.read_text()
    raise Refused("self-serve-block.md template not found next to this script")


# ------------------------------------------------------------------------------------------------- bootstrap
def fetch_checkout(ref: str, dest: Path, runner: Runner) -> Path:
    ensure_dir(dest)
    src = dest / "src"
    steps = (["/usr/bin/git", "init", "-q", str(src)],
             ["/usr/bin/git", "-C", str(src), "fetch", "-q", "--depth", "1", ORIGIN, ref],
             ["/usr/bin/git", "-C", str(src), "checkout", "-q", "FETCH_HEAD"])
    for argv in steps:
        if runner.run(argv, stdin=subprocess.DEVNULL) != 0:
            raise Refused("could not fetch the pinned SHA from the canonical repository")
    code, head = runner.capture(["/usr/bin/git", "-C", str(src), "rev-parse", "HEAD"])
    if code != 0 or head.strip() != ref:
        raise Refused("the fetched checkout is not the pinned SHA")
    return src


def scan_surface(src: Path, work: Path, runner: Runner, python=sys.executable) -> dict:
    """Scan the files that run before trust exists. Only the agent-rules category is expected."""
    surface = work / "surface"
    ensure_dir(surface)
    for name in BOOTSTRAP_SURFACE:
        source = src / name
        if not source.is_file():
            raise Refused("the pinned checkout lacks %s" % name)
        write_atomic(surface / name.replace("/", "__"), source.read_bytes(), 0o600)
    scanner = src / "harness" / "hooks" / "installer_scan.py"
    code, output = runner.capture([python, "-I", str(scanner), str(surface), "--json"])
    try:
        report = json.loads(output)
    except ValueError:
        raise Refused("installer_scan produced no report (exit %d)" % code) from None
    write_atomic(work / "installer-scan.json", (json.dumps(report, indent=2) + "\n").encode())
    categories = sorted({f.get("category") for f in report.get("findings", [])})
    unexpected = [c for c in categories if c not in BOOTSTRAP_OK_CATEGORIES]
    if report.get("files_scanned", 0) < len(BOOTSTRAP_SURFACE) - 1 or report.get("skipped") or report.get("truncated"):
        raise Refused("installer_scan did not cover the whole bootstrap surface (report: %s)" % (work / "installer-scan.json"))
    if unexpected:
        raise Refused("installer_scan found unexpected side effects (%s); report: %s"
                      % (", ".join(unexpected), work / "installer-scan.json"))
    return {"findings": len(report.get("findings", [])), "categories": categories, "report": str(work / "installer-scan.json")}


def bootstrap(layout: Layout, params: dict, *, env=None, upstream=None, runner=None, out=print, fetch=None, python=sys.executable) -> int:
    env, upstream, runner = env or Env(), upstream or Upstream(), runner or Runner()
    ref = params.get("ref")
    if not REF.match(ref or ""):
        raise Refused("--bootstrap needs --ref <40-hex SHA on canonical main>")
    require_human(env)
    if not upstream.is_canonical(ref):
        raise Refused("the pinned SHA %s is not on canonical main" % ref[:12])
    work = layout.work / ("bootstrap-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3))
    ensure_dir(layout.work)
    src = (fetch or fetch_checkout)(ref, work, runner)
    scan = scan_surface(src, work, runner, python)
    out("installer_scan on the bootstrap surface: %d expected agent-rules findings (installers write your agent rule "
        "files); report %s. Read it." % (scan["findings"], scan["report"]))
    out("Plan: repair-harness --apply %s on this Mac and %s, then the enabler --apply (which shows its own diff and "
        "asks again)." % (ref[:12], params["host"]))
    confirm(env, "bootstrap")
    repair = ["/bin/bash", str(src / "scripts" / "repair-harness.sh"), "--ref", ref, "--host", params["host"]]
    for mode in ("--check", "--apply"):
        if runner.run(repair + [mode]) != 0:
            raise Refused("repair-harness %s failed; stopping before the enabler (inspect its log, then rerun)" % mode)
    enable = [python, str(src / "scripts" / "enable-agent-ops.py"), "--apply", "--ref", ref, "--host", params["host"]]
    if params["skip_remote"]:
        enable.append("--skip-remote")
    for repo in params["repos"]:
        enable += ["--repo", repo]
    if params.get("expires_days"):
        enable += ["--expires-days", str(params["expires_days"])]
    if layout.home != Path.home():
        enable += ["--home", str(layout.home)]
    return runner.run(enable)


# ------------------------------------------------------------------------------------------------------- CLI
def parse(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply", action="store_true", help="apply (default is a dry run); needs a terminal and a typed nonce")
    parser.add_argument("--ref", help="full SHA of the pinned canonical-main commit the installed hooks must equal")
    parser.add_argument("--host", default=DEFAULT_HOST, help="worker host that also pins the key (default %(default)s)")
    parser.add_argument("--skip-remote", action="store_true", help="do not pin on the worker (recorded as a limitation)")
    parser.add_argument("--repo", action="append", help="repository a merge capability covers (default %s)" % REPO)
    parser.add_argument("--expires-days", type=int, help="policy lifetime (default: no expiry)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--status", action="store_true")
    mode.add_argument("--undo", action="store_true")
    mode.add_argument("--disable", metavar="CAPABILITY|all")
    mode.add_argument("--resume", metavar="RUN")
    mode.add_argument("--bootstrap", action="store_true", help="scan the pinned SHA, repair both hosts, then --apply")
    parser.add_argument("--home", type=Path, default=Path.home(), help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv=None, *, env=None, upstream=None, remote=None, runner=None, out=print, on_step=None) -> int:
    options = parse(sys.argv[1:] if argv is None else argv)
    layout = Layout(options.home)
    if options.host and not HOST.match(options.host):
        out("refused: --host must be a plain SSH host name")
        return 3
    params = {"ref": options.ref, "host": options.host, "skip_remote": options.skip_remote,
              "repos": sorted(set(options.repo or [REPO])), "expires_days": options.expires_days}
    enabler = Enabler(layout, env=env, upstream=upstream, remote=remote, out=out, on_step=on_step)
    try:
        if options.status:
            out(json.dumps(enabler.status(), indent=2, sort_keys=True))
            return 0
        if options.bootstrap:
            return bootstrap(layout, params, env=enabler.env, upstream=enabler.upstream, runner=runner, out=out)
        if options.undo or options.disable or options.resume or options.apply:
            require_human(enabler.env)  # before any read or write
            if options.undo:
                return enabler.undo()
            if options.disable:
                return enabler.disable(options.disable)
            if options.resume:
                if not RUN.match(options.resume):
                    raise Refused("--resume needs a run id like 20261123T101500Z-ab12cd")
                raw = read_file(layout.work / options.resume / "journal.json")
                if raw is None:
                    raise Refused("no journal for run %s" % options.resume)
                journal = json.loads(raw[0])
                confirm(enabler.env, "resume")
                return enabler.apply(journal["params"], options.resume, journal)
            if not options.ref:
                raise Refused("--apply needs --ref <SHA of canonical main>")
            return enabler.apply(params)
        return enabler.dry_run(params)
    except Refused as error:
        out("refused: %s" % error)
        return 3
    except ValueError as error:  # malformed JSON in a managed file
        out("refused: a managed file is not valid JSON (%s); nothing was changed by this step" % error)
        return 3


if __name__ == "__main__":
    sys.exit(main())
