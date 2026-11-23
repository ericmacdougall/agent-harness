#!/usr/bin/env python3
"""One-shot, user-run installer of the takeover cleanup (goodqa#16441). Started through enable-takeover-cleanup.sh.

What it does, in order, on this Mac and on t2-dev (both unless --host says otherwise):

  1. preflight   the ref is an ancestor of canonical main, the kit bytes equal the ref's blobs, there is room for the bytes
                 it will write plus the backups plus 64 MiB, ssh works, no unfinished ah install run, the policy block in
                 each rule file is well formed, and `repair-harness.sh --check` passes
  2. snapshot    the rule files, the tuned model_tiers.json and resource_limits.json, and every hook file the installers
                 write, into ~/.agent-harness/backups/takeover-cleanup/<UTC>/ (0700), with the state file that --undo reads
  3. install     `repair-harness.sh --ref REF --host t2-dev --apply` (remote first; it refreshes hooks, never CLAUDE.md,
                 AGENTS.md, settings.json, hooks.json or config.toml)
  4. tuned JSON  kept as it was when the repo file did not change between the installed and the new ref; otherwise the new
                 file is kept, both hashes are printed and the run exits 3 (re-run enable-parallel-build.sh)
  5. policy      scripts/takeover-cleanup-policy.md, read from the ref, appended outside the managed markers of
                 ~/.claude/CLAUDE.md on each host, and of ~/.codex/AGENTS.md only where Codex guard hooks are shown active
  6. verify      one PASS/FAIL/SKIP table (also `--verify` alone, which an agent may run)

--apply and --undo are the user's: they refuse when an agent environment variable is set or there is no terminal, and they
need a typed nonce. The command guards also refuse an agent that runs them. Both are accident prevention, and bypassable
outside guarded sessions: the user is the control here. Stdlib only, Python 3.11 or later. Never reads or prints a secret.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path

BEGIN = "<!-- takeover-cleanup:begin v1 -->"
END = "<!-- takeover-cleanup:end -->"
MANAGED_END = {".claude/CLAUDE.md": "<!-- agent-harness:end -->", ".codex/AGENTS.md": "<!-- agent-harness-codex:end -->"}
RULE_FILES = tuple(MANAGED_END)
TUNED = tuple("%s/%s.json" % (d, n) for d in (".claude/hooks", ".codex/agent-harness") for n in ("model_tiers", "resource_limits"))
KIT = ("scripts/enable-takeover-cleanup.sh", "scripts/enable_takeover_cleanup.py", "scripts/takeover-cleanup-policy.md")
POLICY = "scripts/takeover-cleanup-policy.md"
HOOKS_COMMON = ("ah.py", "ah_kill.py", "takeover.py", "takeover_rules.py", "ah_worktree.py", "command_guard.py", "kill_guard.py")
DIRS = {"claude": ".claude/hooks", "codex": ".codex/agent-harness"}
SLACK = 64 << 20
AGENT_ENV = ("CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID", "CLAUDECODE")
SHA = re.compile(r"[0-9a-f]{40}")
HOSTS = ("local", "t2-dev")
STATE_REL = ".agent-harness/state/takeover-cleanup.json"
BACKUP_REL = ".agent-harness/backups/takeover-cleanup"
EXIT_AGENT, EXIT_TUNED = 4, 3


class ScriptError(Exception):
    def __init__(self, message, code=2):
        super().__init__(message)
        self.code = code


def agent_environment(environ):
    return any(environ.get(k) for k in AGENT_ENV) or any(k.startswith("CODEX_") for k in environ)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------------------------------- hosts

class Host:
    """A home directory this script reads and writes by relative path. LocalHost uses the file system, SshHost one ssh
    command per operation (paths are matched against a strict pattern first, so nothing needs shell quoting)."""
    REL = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._/@+=-]{0,200}$")

    def __init__(self, name):
        self.name = name

    def check(self, rel):
        if not self.REL.fullmatch(rel) or ".." in rel.split("/"):
            raise ScriptError("refused path %r" % rel)
        return rel


class LocalHost(Host):
    def __init__(self, home, name="local"):
        super().__init__(name)
        self.home = Path(home)

    def read(self, rel):
        try:
            return (self.home / self.check(rel)).read_bytes()
        except FileNotFoundError:
            return None

    def write(self, rel, data, mode=0o600):
        path = self.home / self.check(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name(path.name + ".tc-tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temp, path)

    def remove(self, rel):
        try:
            (self.home / self.check(rel)).unlink()
        except FileNotFoundError:
            pass

    def mode(self, rel):
        try:
            return stat.S_IMODE((self.home / self.check(rel)).stat().st_mode)
        except FileNotFoundError:
            return None

    def free_bytes(self):
        usage = shutil.disk_usage(self.home)
        return usage.free

    def mkdir_private(self, rel):
        path = self.home / self.check(rel)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path, 0o700)

    def run(self, argv, timeout=300):
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=str(self.home),
                              env={"HOME": str(self.home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"})
        return done.returncode, done.stdout, done.stderr

    def alive(self):
        return True


class SshHost(Host):
    def __init__(self, name, runner=subprocess.run):
        super().__init__(name)
        self.runner = runner

    def _ssh(self, command, data=None, timeout=180):
        done = self.runner(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", self.name, command],
                           input=data, capture_output=True, timeout=timeout)
        return done.returncode, done.stdout, done.stderr

    def read(self, rel):
        code, out, _err = self._ssh('test -e "$HOME/%s" && cat "$HOME/%s"' % (self.check(rel), rel))
        if code == 0:
            return out
        code, _out, _err = self._ssh('test -e "$HOME/%s"' % rel)
        if code == 0:
            raise ScriptError("could not read %s on %s" % (rel, self.name))
        return None

    def write(self, rel, data, mode=0o600):
        self.check(rel)
        code, _o, _e = self._ssh('umask 077 && mkdir -p "$(dirname "$HOME/%s")" && cat > "$HOME/%s.tc-tmp" && chmod %o '
                                 '"$HOME/%s.tc-tmp" && mv "$HOME/%s.tc-tmp" "$HOME/%s"' % (rel, rel, mode, rel, rel, rel), data)
        if code:
            raise ScriptError("could not write %s on %s" % (rel, self.name))

    def remove(self, rel):
        self._ssh('rm -f "$HOME/%s"' % self.check(rel))

    def mode(self, rel):
        code, out, _e = self._ssh('stat -c %%a "$HOME/%s" 2>/dev/null || stat -f %%Lp "$HOME/%s"' % (self.check(rel), rel))
        text = out.decode("ascii", "replace").strip()
        return int(text, 8) if code == 0 and re.fullmatch(r"[0-7]{3,4}", text) else None

    def free_bytes(self):
        code, out, _e = self._ssh('df -Pk "$HOME" | tail -1 | tr -s " " | cut -d" " -f4')
        if code or not out.strip().isdigit():
            raise ScriptError("could not read free space on %s" % self.name)
        return int(out.strip()) * 1024

    def mkdir_private(self, rel):
        self._ssh('mkdir -p -m 700 "$HOME/%s"' % self.check(rel))

    def run(self, argv, timeout=300):
        code, out, err = self._ssh(" ".join(shlex.quote(a) for a in argv), timeout=timeout)
        return code, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")

    def alive(self):
        return self._ssh("true", timeout=30)[0] == 0


# ------------------------------------------------------------------------------------------------ the repository

class Repo:
    """Reads blobs of one ref with `git cat-file`, never checking anything out (another agent may own the checkout)."""

    def __init__(self, path, ref, git=("git",)):
        self.path, self.ref, self.git = str(path), ref, tuple(git)

    def _run(self, *args, check=True):
        done = subprocess.run([*self.git, "-C", self.path, *args], capture_output=True, timeout=120)
        if check and done.returncode:
            raise ScriptError("git %s failed" % " ".join(args[:2]))
        return done

    def blob(self, rel):
        return self._run("cat-file", "blob", "%s:%s" % (self.ref, rel)).stdout

    def blob_id(self, rel):
        return self._run("rev-parse", "%s:%s" % (self.ref, rel)).stdout.decode().strip()

    def ancestor_of_main(self):
        return self._run("merge-base", "--is-ancestor", self.ref, "origin/main", check=False).returncode == 0


def git_hash_object(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


# ------------------------------------------------------------------------------------------- the policy block

def block_state(text):
    """('none'|'one'|'bad', start, end): where the single well-formed block sits."""
    begins, ends = text.count(BEGIN), text.count(END)
    if begins == 0 and ends == 0:
        return "none", -1, -1
    if begins != 1 or ends != 1:
        return "bad", -1, -1
    start, end = text.index(BEGIN), text.index(END)
    if end < start:
        return "bad", -1, -1
    managed = [m for m in ("<!-- agent-harness:start -->", "<!-- agent-harness-codex:start -->") if m in text]
    for marker in managed:  # a block inside a managed block would be overwritten by the installer
        other = marker.replace("start", "end")
        if text.find(marker) < start < text.find(other, text.find(marker)) if other in text else False:
            return "bad", -1, -1
    return "one", start, end + len(END)


def with_block(text, block):
    """The text with `block` appended, or its own block replaced inside its markers; None when it is already there."""
    state, start, end = block_state(text)
    if state == "bad":
        raise ScriptError("the takeover-cleanup markers in the rule file are malformed (unpaired, duplicated or inside a managed block)")
    block = block.strip("\n")
    if state == "one":
        if text[start:end] == block:
            return None
        return text[:start] + block + text[end:]
    return text.rstrip("\n") + "\n\n" + block + "\n"


# -------------------------------------------------------------------------------------------------- the run

class Run:
    def __init__(self, options, hosts, repo, environ, stdin_tty, stdout_tty, nonce_in, out, repair, now, kit_dir, mac=None):
        self.o, self.hosts, self.repo, self.environ = options, hosts, repo, environ
        self.mac = mac or hosts[0]  # the machine this script runs on: ah install keeps its audit there
        self.stdin_tty, self.stdout_tty, self.nonce_in, self.out, self.repair, self.now = stdin_tty, stdout_tty, nonce_in, out, repair, now
        self.kit_dir = Path(kit_dir)

    def say(self, text):
        print(text, file=self.out)

    # ---- guards
    def require_user(self):
        if agent_environment(self.environ):
            raise ScriptError("refused: an agent environment variable is set; --apply and --undo are run by the user in a terminal", EXIT_AGENT)
        if not (self.stdin_tty and self.stdout_tty):
            raise ScriptError("refused: --apply and --undo need a terminal on stdin and stdout", EXIT_AGENT)
        nonce = secrets.token_hex(3)
        self.say("Type this code to confirm: %s" % nonce)
        if (self.nonce_in() or "").strip() != nonce:
            raise ScriptError("refused: the confirmation code did not match", EXIT_AGENT)

    # ---- preflight
    def policy_block(self):
        text = self.repo.blob(POLICY).decode("utf-8")
        if text.count(BEGIN) != 1 or text.count(END) != 1:
            raise ScriptError("the policy file in the ref has no single v1 block")
        return text[text.index(BEGIN):text.index(END) + len(END)]

    def preflight(self, block):
        if not SHA.fullmatch(self.o.ref):
            raise ScriptError("--ref must be a full 40-hex commit")
        if not self.repo.ancestor_of_main():
            raise ScriptError("the ref is not an ancestor of origin/main: nothing was changed")
        for rel in KIT:
            theirs = self.repo.blob_id(rel)
            ours = self.kit_dir / rel
            if not ours.exists() or git_hash_object(ours.read_bytes()) != theirs:
                raise ScriptError("kit file %s differs from the blob at the ref: get the kit with `git archive`" % rel)
        need = self.estimate()
        for host in self.hosts:
            if not host.alive():
                raise ScriptError("ssh to %s does not work: nothing was changed" % host.name)
            free = host.free_bytes()
            if free < need + SLACK:
                raise ScriptError("%s has %d bytes free; this run needs %d plus %d slack" % (host.name, free, need, SLACK))
            for rel in RULE_FILES:
                data = host.read(rel)
                if data is not None and block_state(data.decode("utf-8", "replace"))[0] == "bad":
                    raise ScriptError("%s on %s has malformed takeover-cleanup markers" % (rel, host.name))
        audit = self.mac.read(".agent-harness/install-audit.jsonl")
        for target in ("t2-dev", "ah-mac-mini"):
            if audit and self.unfinished(audit.decode("utf-8", "replace"), target):
                raise ScriptError("%s has an unfinished ah install run: resume or roll it back first" % target)
        code = self.repair("check")
        if code:
            raise ScriptError("repair-harness.sh --check failed (exit %d): nothing was changed" % code)

    @staticmethod
    def unfinished(audit_text, host):
        opened = {}
        for line in audit_text.splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if not isinstance(row, dict) or row.get("host") != host or not row.get("run"):
                continue
            if row.get("event") == "start" and row.get("kind") in ("install", "resume", "rollback"):
                opened[row["run"]] = True
            elif row.get("event") == "result" and row.get("result") in ("installed", "rolled_back", "restored", "already_current", "refused"):
                opened[row["run"]] = False
        return [run for run, is_open in opened.items() if is_open]

    def estimate(self):
        total = 2 * len(self.repo.blob(POLICY)) * len(RULE_FILES)
        for host in self.hosts:
            for rel in RULE_FILES + TUNED:
                data = host.read(rel)
                total += 2 * len(data or b"")
        for name in HOOKS_COMMON:
            total += 2 * len(self.repo.blob("harness/hooks/" + name)) * len(self.hosts) * 2
        return total

    # ---- eligibility of the Codex rule file
    def codex_guard_active(self, host):
        """(ok, why): hooks.json names the installed command_guard, and a codex-wals main WAL has a hook-written PreToolUse
        row from the last 7 days (T9: if Codex trust is per entry this evidence is replaced by a guard-specific trace)."""
        hooks = host.read(".codex/hooks.json")
        if not hooks or ".codex/agent-harness/command_guard" not in hooks.decode("utf-8", "replace"):
            return False, "hooks.json has no command_guard entry"
        return (True, "ok") if self.recent_pretooluse(host) else (False, "no hook-written PreToolUse row in the last 7 days")

    def recent_pretooluse(self, host):
        listing = host.run(["bash", "-c", "ls -1t \"$HOME\"/.agent-harness/codex-wals/*/main.jsonl 2>/dev/null | head -20"])[1].split()
        cutoff = self.now() - 7 * 86400
        for path in listing:
            code, out, _e = host.run(["bash", "-c", "tail -n 200 %s | grep -c '\"event\": *\"PreToolUse\"'" % shlex.quote(path)])
            code2, mtime, _e2 = host.run(["bash", "-c", "stat -c %%Y %s 2>/dev/null || stat -f %%m %s" % (shlex.quote(path), shlex.quote(path))])
            if out.strip().isdigit() and int(out.strip()) > 0 and mtime.strip().isdigit() and int(mtime.strip()) > cutoff:
                return True
        return False

    # ---- apply
    def apply(self):
        self.require_user()
        block = self.policy_block()
        self.preflight(block)
        stamp = dt.datetime.fromtimestamp(self.now(), dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        state = {"ref": self.o.ref, "ts": stamp, "files": {}, "hosts": [h.name for h in self.hosts]}
        done = []
        try:
            for host in self.hosts:
                state["files"][host.name] = self.snapshot(host, stamp)
            self.save_state(state)  # an interrupted apply must leave --undo a record to read
            before_tuned = {h.name: {rel: h.read(rel) for rel in TUNED} for h in self.hosts}
            code = self.repair("apply")
            if code:
                raise ScriptError("repair-harness.sh --apply failed (exit %d); the completed steps were restored" % code)
            done.append("install")
            tuned_changed = []
            for host in self.hosts:
                for rel, before in before_tuned[host.name].items():
                    now_bytes = host.read(rel)
                    if before is not None and now_bytes != before:
                        state["_post"] = {rel: now_bytes}
                        if self.repo_tuned_unchanged(rel, state):
                            host.write(rel, before, state["files"][host.name][rel].get("mode", 0o644))
                        else:
                            tuned_changed.append((host.name, rel, sha256(before), sha256(now_bytes or b"")))
            for host in self.hosts:
                for rel in RULE_FILES:
                    text = host.read(rel)
                    if text is None:
                        self.say("SKIP %s on %s: the file does not exist" % (rel, host.name))
                        continue
                    if rel.endswith("AGENTS.md"):
                        ok, why = self.codex_guard_active(host)
                        if not ok:
                            self.say("TARGET_MISMATCH %s on %s not written: Codex guard hooks not shown active (%s)" % (rel, host.name, why))
                            continue
                    updated = with_block(text.decode("utf-8"), block)
                    if updated is None:
                        self.say("PASS %s on %s: block already present" % (rel, host.name))
                        continue
                    host.write(rel, updated.encode("utf-8"), state["files"][host.name][rel].get("mode", 0o644))
                    state["files"][host.name].setdefault(rel, {})["after"] = sha256(updated.encode("utf-8"))
            for host in self.hosts:
                for rel in self.parity_paths():
                    data = host.read(rel[0])
                    if data is not None:
                        state["files"][host.name].setdefault(rel[0], {})["after"] = sha256(data)
            state.pop("_post", None)
            self.save_state(state)
            self.say("Applied %s. Backups: ~/%s/%s" % (self.o.ref[:12], BACKUP_REL, stamp))
            if tuned_changed:
                for name, rel, old, new in tuned_changed:
                    self.say("TUNED %s on %s changed in the repo between the installed ref and %s (was %s, now %s)" % (rel, name, self.o.ref[:12], old[:12], new[:12]))
                self.say("Re-run ~/timbar/.claude/enable-parallel-build.sh --apply --permanent to restore your tuned values.")
                return EXIT_TUNED
            return 0
        except Exception:
            self.restore_all(state, hooks=False)
            raise

    def repo_tuned_unchanged(self, rel, state):
        """True when the installer only reset the user's tuned file: what it wrote is exactly the ref's own blob, so the
        user's earlier bytes can be put back. The script does not know the previously installed ref, so this is the proof
        it has; any other bytes after the install (a merge, a changed default) are kept and the run exits 3."""
        try:
            return self.repo.blob("harness/hooks/" + rel.rsplit("/", 1)[1]) == state["_post"][rel]
        except (ScriptError, KeyError):
            return False

    def snapshot(self, host, stamp):
        base = "%s/%s" % (BACKUP_REL, stamp)
        host.mkdir_private(BACKUP_REL)
        host.mkdir_private(base)
        record = {}
        for rel in RULE_FILES + TUNED + tuple(p for p, _s in self.parity_paths()):
            data = host.read(rel)
            if data is None:
                record[rel] = {"before": None}
                continue
            host.write("%s/%s" % (base, rel.replace("/", "__")), data, 0o600)
            record[rel] = {"before": sha256(data), "backup": "%s/%s" % (base, rel.replace("/", "__")),
                           "mode": host.mode(rel) or 0o644}
        return record

    def parity_paths(self):
        """[(host-relative destination, repo path)] for every file the parity check covers."""
        out = []
        for name in HOOKS_COMMON:
            for flavor in ("claude", "codex"):
                out.append(("%s/%s" % (DIRS[flavor], name), "harness/hooks/" + name))
        out.append((".claude/hooks/wal.py", "harness/hooks/wal.py"))
        out.append((".codex/agent-harness/wal.py", "codex/hooks/wal.py"))
        out.append((".claude/hooks/ahc_release.json", "harness/hooks/ahc_release.json"))
        return out

    def save_state(self, state):
        data = (json.dumps(state, indent=1, sort_keys=True) + "\n").encode()
        self.hosts[0].write(STATE_REL, data, 0o600)

    # ---- undo
    def load_state(self):
        raw = self.hosts[0].read(STATE_REL)
        if raw is None:
            raise ScriptError("--undo refused: no recorded apply (%s)" % STATE_REL)
        return json.loads(raw)

    def restore_all(self, state, hooks, force_files=()):
        for host in self.hosts:
            files = state.get("files", {}).get(host.name, {})
            for rel, record in files.items():
                is_hook = rel in dict(self.parity_paths())
                if is_hook and not hooks:
                    continue
                current = host.read(rel)
                after = record.get("after")
                if is_hook and after and current is not None and sha256(current) != after:
                    self.say("SKIP %s on %s: changed since the apply (current sha is not the post-apply sha)" % (rel, host.name))
                    continue
                if not is_hook and after and current is not None and sha256(current) != after and rel not in force_files:
                    raise ScriptError("%s on %s changed after the apply; use --force-file %s to restore it anyway" % (rel, host.name, rel))
                backup = record.get("backup")
                if record.get("before") is None:
                    if rel in RULE_FILES + TUNED:
                        continue
                    if current is not None and after:
                        host.remove(rel)
                elif backup:
                    data = host.read(backup)
                    if data is not None and sha256(data) == record["before"]:
                        host.write(rel, data, record.get("mode", 0o644))

    def undo(self):
        self.require_user()
        state = self.load_state()
        self.restore_all(state, hooks=self.o.hooks, force_files=tuple(self.o.force_file or ()))
        self.say("Restored the rule files and tuned JSON from the backup of %s." % state["ts"])
        self.say("To put the previous hook files back run: scripts/repair-harness.sh --ref <previous ref> --host t2-dev --apply "
                 "(a downgrade: check the release notes first)")
        return 0

    # ---- verify
    def verify(self):
        rows, failed = [], False

        def row(status, what, detail=""):
            nonlocal failed
            failed = failed or status == "FAIL"
            rows.append("%-4s %s%s" % (status, what, (": " + detail) if detail else ""))

        for host in self.hosts:
            for rel, repo_rel in self.parity_paths():
                data = host.read(rel)
                if data is None:
                    row("SKIP", "%s on %s" % (rel, host.name), "not installed there")
                    continue
                want = sha256(self.repo.blob(repo_rel))
                row("PASS" if sha256(data) == want else "FAIL", "parity %s on %s" % (rel, host.name))
            code, out, _e = host.run(["python3", "-I", ".claude/hooks/command_guard.py", "doctor"])
            bad = [json.loads(l)["check"] for l in out.splitlines() if l.startswith("{") and '"ok": false' in l]
            # the doctor's check ids are not named by this change: an unhealthy id is reported, never failed on
            row("PASS" if code == 0 and "HEALTHY" in out else ("WARN" if out.strip() else "FAIL"),
                "command_guard doctor on %s" % host.name, "unhealthy checks: %s" % ", ".join(bad) if bad else "")
            self.guard_probes(host, row)
            for text in (RULE_FILES):
                data = host.read(text)
                if data is None:
                    row("SKIP", "block count in %s on %s" % (text, host.name))
                    continue
                count = data.decode("utf-8", "replace").count(BEGIN)
                if text.endswith("AGENTS.md") and count == 0:
                    ok, why = self.codex_guard_active(host)
                    row("SKIP" if not ok else "FAIL", "block in %s on %s" % (text, host.name),
                        "TARGET_MISMATCH: Codex guard hooks not shown active (%s)" % why if not ok else "missing")
                else:
                    row("PASS" if count == 1 else "FAIL", "block in %s on %s" % (text, host.name), "%d" % count)
            for flavor in ("claude", "codex"):
                ah = "%s/ah.py" % DIRS[flavor]
                # `status` needs a caller; the evidence read does not, and reports no WAL for an id nobody has
                code, out, _e = host.run(["python3", "-I", ah, "takeover", "status", "--from", "00000000-none", "--evidence-only", "--json"])
                try:
                    ok = code == 0 and json.loads(out).get("flavors") == [] and json.loads(out).get("version") == 1
                except ValueError:
                    ok = False
                row("PASS" if ok else "FAIL", "takeover evidence (%s) on %s" % (flavor, host.name),
                    "no session" if ok else out[:80].strip())
                self.dry_run_probe(host, flavor, ah, row)
        return rows, failed

    PROBE = "verifyself01"  # a session id nobody has; the probes only ever analyse command text

    def guard_probes(self, host, row):
        """command_guard `check` (it runs nothing) on the commands this change is about, as the hook would judge them."""
        guard = ".claude/hooks/command_guard.py"
        path = "~/.agent-harness/work/%s/x" % self.PROBE
        owner = self.recorded_session(host)
        if owner is None:
            row("SKIP", "guard check on %s: foreign session, lone form blocks with the takeover route" % host.name,
                "no session WAL recorded on this host to probe with")
        probes = (
            ("own session, forced remove blocks with the ah route", self.PROBE, "git worktree remove --force %s" % path, "block", "ah.py worktree-remove"),
        ) + ((
            # since review F2 a work directory is a session's only when this host records a WAL of that name
            ("foreign session, lone form blocks with the takeover route", "othersession1",
             "git worktree remove ~/.agent-harness/work/%s/x" % owner, "block", "takeover status --from %s" % owner),
        ) if owner else ()) + (
            ("an assigned session id blocks", "othersession1",
             "CLAUDE_CODE_SESSION_ID=abc python3 -I ~/.claude/hooks/ah.py worktree-remove --host local --path %s --reason r" % path, "block", "identity"),
            ("ah worktree-remove is allowed", self.PROBE,
             "python3 -I ~/.claude/hooks/ah.py worktree-remove --host local --path %s --reason r" % path, "allow", ""),
            ("ah takeover status is allowed on the Codex path", self.PROBE,
             "python3 -I ~/.codex/agent-harness/ah.py takeover status --from %s" % self.PROBE, "allow", ""),
            ("the user's script cannot be applied by an agent", self.PROBE, "bash scripts/enable-takeover-cleanup.sh --apply", "block", "user only"),
        )
        for label, session, command, want, part in probes:
            code, out, _e = host.run(["python3", "-I", guard, "check", "--session", session, command])
            try:
                verdict = json.loads(out)
            except ValueError:
                verdict = {}
            good = verdict.get("verdict") == want and part in verdict.get("message", "")
            row("PASS" if good else "FAIL", "guard check on %s: %s" % (host.name, label), "" if good else (out[:100].strip() or "no answer"))

    SESSION_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{7,127}$")

    def recorded_session(self, host):
        """The first session WAL directory name this host records (Claude, then Codex), or None. Names only: nothing
        inside a WAL is read. The probe only analyses command text that names that session's work directory."""
        code, out, _e = host.run(["bash", "-c", "ls -1 .claude/wals .agent-harness/codex-wals 2>/dev/null"])
        names = [line.strip() for line in (out or "").splitlines()]
        names = [n for n in names if self.SESSION_NAME.fullmatch(n) and n not in ("othersession1", self.PROBE)]
        return names[0] if names else None

    def dry_run_probe(self, host, flavor, ah, row):
        """ah kill --dry-run on a sleep this script starts: would-stop, and the process is still there afterwards."""
        code, out, _e = host.run(["bash", "-c", "nohup sleep 20 >/dev/null 2>&1 & echo $!"])
        pid = out.strip()
        if code or not pid.isdigit():
            row("FAIL", "dry-run probe (%s) on %s" % (flavor, host.name), "could not start the probe process")
            return
        code, out, _e = host.run(["python3", "-I", ah, "kill", "--dry-run", "--foreign", "--pid", pid, "--reason", "verify"])
        try:
            status = json.loads(out)["results"][0]["status"]
        except (ValueError, KeyError, IndexError, TypeError):
            status = "no answer"
        alive = host.run(["bash", "-c", "kill -0 %s" % pid])[0] == 0
        row("PASS" if status == "would-stop" and alive else "FAIL", "dry-run probe (%s) on %s" % (flavor, host.name),
            "would-stop, nothing signalled" if status == "would-stop" and alive else "%s, alive=%s" % (status, alive))

    def run(self):
        mode = self.o.mode
        if mode == "apply":
            return self.apply()
        if mode == "undo":
            return self.undo()
        block = self.policy_block()
        if mode == "verify":
            rows, failed = self.verify()
            for line in rows:
                self.say(line)
            return 1 if failed else 0
        # dry run: report what would change, write nothing
        self.preflight(block)
        for host in self.hosts:
            for rel in RULE_FILES:
                text = host.read(rel)
                if text is None:
                    self.say("SKIP %s on %s: missing" % (rel, host.name))
                    continue
                try:
                    changed = with_block(text.decode("utf-8"), block) is not None
                except ScriptError as error:
                    self.say("FAIL %s on %s: %s" % (rel, host.name, error))
                    return 2
                if rel.endswith("AGENTS.md"):
                    ok, why = self.codex_guard_active(host)
                    if not ok:
                        self.say("TARGET_MISMATCH %s on %s would be skipped: %s" % (rel, host.name, why))
                        continue
                self.say("%s %s on %s" % ("WOULD WRITE" if changed else "PASS (already current)", rel, host.name))
        self.say("Dry run: nothing was written.")
        return 0


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ref", required=True, help="a full 40-hex commit on origin/main")
    parser.add_argument("--repo", required=True, help="a checkout whose objects hold the ref (read with git cat-file only)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", dest="mode", action="store_const", const="dry", help="default: report, write nothing")
    mode.add_argument("--apply", dest="mode", action="store_const", const="apply")
    mode.add_argument("--undo", dest="mode", action="store_const", const="undo")
    mode.add_argument("--verify", dest="mode", action="store_const", const="verify")
    parser.add_argument("--hooks", action="store_true", help="with --undo: also restore hook bytes that are still the post-apply bytes")
    parser.add_argument("--force-file", action="append", help="with --undo: restore this rule file although it changed after the apply")
    parser.add_argument("--host", choices=("all",) + HOSTS, default="all")
    parser.set_defaults(mode="dry")
    return parser


def main(argv=None, deps=None):
    """deps (tests only, in process): home, ssh_runner, repair, environ, stdin_tty, stdout_tty, nonce_in, out, now."""
    deps = deps or {}
    options = build_parser().parse_args(argv)
    environ = deps.get("environ", os.environ)
    out = deps.get("out", sys.stdout)
    try:
        if options.mode in ("apply", "undo") and agent_environment(environ):
            raise ScriptError("refused: an agent environment variable is set; --apply and --undo are run by the user in a terminal", EXIT_AGENT)
        home = deps.get("home", Path.home())
        hosts = []
        if options.host in ("all", "local"):
            hosts.append(LocalHost(home))
        if options.host in ("all", "t2-dev"):
            hosts.append(deps.get("remote") or SshHost("t2-dev", deps.get("ssh_runner", subprocess.run)))
        repo = Repo(options.repo, options.ref)
        script_dir = Path(deps.get("kit_dir", Path(__file__).resolve().parents[1]))

        def repair(phase):
            if "repair" in deps:
                return deps["repair"](phase)
            tool = script_dir / "scripts" / "repair-harness.sh"
            return subprocess.run(["bash", str(tool), "--ref", options.ref, "--host", "t2-dev", "--" + ("apply" if phase == "apply" else "check")]).returncode

        run = Run(options, hosts, repo, environ, deps.get("stdin_tty", sys.stdin.isatty()), deps.get("stdout_tty", sys.stdout.isatty()),
                  deps.get("nonce_in", input), out, repair, deps.get("now", lambda: dt.datetime.now(dt.timezone.utc).timestamp()), script_dir,
                  mac=LocalHost(home))
        return run.run()
    except ScriptError as error:
        print("enable-takeover-cleanup: %s" % error, file=out)
        return error.code


if __name__ == "__main__":
    sys.exit(main())
