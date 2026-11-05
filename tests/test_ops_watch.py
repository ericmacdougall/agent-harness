"""ops_watch.py: one failing-control fixture per check, the ring, dedup and sinks. Stdlib only, no network."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ops_watch as ow  # noqa: E402

SECRET = "sk-live-OPSWATCHSECRET123"
GIB = 1024 ** 3


class FakeRunner:
    """Maps an argv prefix (tuple) to (rc, stdout) or a callable; records every call."""

    def __init__(self, table=None):
        self.table = table or {}
        self.calls = []

    def __call__(self, argv, timeout, stdin=None, env=None, cwd=None):
        self.calls.append(list(argv))
        for prefix, result in sorted(self.table.items(), key=lambda kv: -len(kv[0])):
            if tuple(argv[:len(prefix)]) == prefix:
                if callable(result):
                    return result(argv, timeout, stdin)
                return result
        return (127, "")


def keys(alerts):
    return {a["key"]: a for a in alerts}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.cfg = ow.load_config(self.home, host="testhost", overrides={})


class DiskTests(Base):
    def vol(self, used_pct, total=1000 * GIB):
        free = int(total * (100 - used_pct) / 100)
        return {"fsid": "1", "path": "/", "total": total, "free": free}

    def test_thresholds(self):
        for pct, sev in ((80, None), (86, "warning"), (93, "high"), (98, "critical")):
            alerts = keys(ow.volume_alerts([self.vol(pct)], self.cfg["disk"]))
            got = alerts.get("disk:volume:/", {}).get("severity")
            self.assertEqual(got, sev, pct)

    def test_free_floor_is_critical(self):
        a = keys(ow.volume_alerts([self.vol(50, total=12 * GIB)], dict(self.cfg["disk"], free_floor_gib=10)))
        self.assertEqual(a["disk:volume:/"]["severity"], "critical")

    def test_growth_names_top_three(self):
        state = {}
        now = 1_000_000.0
        dirs = {f"/h/d{i}": i for i in range(5)}
        runner = FakeRunner({("du",): lambda argv, t, s: (0, f"{dirs[argv[-1]] * 1024 * 1024}\t{argv[-1]}\n")})
        ow.measure_dirs(list(dirs), state, runner, now, budget_s=100, per_dir_s=50)
        for i, d in enumerate(dirs):
            dirs[d] = i + (20 * i)  # d4 grows 80 GiB, d3 60, d2 40, d1 20, d0 0 (GiB, in 1 h)
        ow.measure_dirs(list(dirs), state, runner, now + 3600, budget_s=100, per_dir_s=50)
        alerts = keys(ow.growth_alerts(state, [], self.cfg["disk"], now + 3600))
        g = alerts["disk:growth"]
        self.assertEqual(g["severity"], "high")
        self.assertEqual([x["path"] for x in g["detail"]["top"]], ["/h/d4", "/h/d3", "/h/d2"])
        # failing control: under 10 GiB/h is no alert
        state2 = {}
        dirs2 = {"/h/a": 1}
        r2 = FakeRunner({("du",): lambda argv, t, s: (0, f"{dirs2[argv[-1]] * 1024 * 1024}\t{argv[-1]}\n")})
        ow.measure_dirs(["/h/a"], state2, r2, now, 100, 50)
        dirs2["/h/a"] = 9
        ow.measure_dirs(["/h/a"], state2, r2, now + 3600, 100, 50)
        self.assertNotIn("disk:growth", keys(ow.growth_alerts(state2, [], self.cfg["disk"], now + 3600)))

    def test_du_timeout_splits_and_flags_unmeasured(self):
        state = {}
        big = self.home / "big"
        (big / "a").mkdir(parents=True)
        (big / "b").mkdir()

        def du(argv, t, s):
            if argv[-1] == str(big):
                raise subprocess.TimeoutExpired(argv, t)
            return (0, f"10\t{argv[-1]}\n")
        runner = FakeRunner({("du",): du})
        t0 = time.monotonic()
        ow.measure_dirs([str(big)], state, runner, 1000.0, budget_s=5, per_dir_s=1)
        self.assertLess(time.monotonic() - t0, 5)
        self.assertTrue(state["dirs"][str(big)]["split"])
        roots = ow.expand_split(state, [str(big)])
        self.assertEqual(sorted(roots), sorted([str(big / "a"), str(big / "b")]))
        alerts = keys(ow.growth_alerts(state, [], self.cfg["disk"], 1000.0))
        self.assertIn("disk:unmeasured", alerts)

    def test_volume_growth_unattributed(self):
        state = {"volumes": {"1": {"used": 100 * GIB, "at": 0.0}}}
        vols = [{"fsid": "1", "path": "/", "total": 1000 * GIB, "free": 1000 * GIB - 130 * GIB}]
        ow.record_volumes(vols, state, 3600.0)
        alerts = keys(ow.growth_alerts(state, vols, self.cfg["disk"], 3600.0))
        self.assertTrue(alerts["disk:growth"]["detail"]["volume_rate_gib_h"] >= 29)


class UnitsTests(Base):
    def table(self, failed_lines, show, journal):
        def show_fn(argv, t, s):
            return (0, show.get(argv[-1], "LoadState=not-found\n"))
        return FakeRunner({
            ("systemctl", "--user", "list-units"): (0, failed_lines),
            ("systemctl", "--user", "show"): show_fn,
            ("journalctl",): (0, journal),
        })

    def test_failed_and_reclaim(self):
        failed = ("● box-janitor.service loaded failed failed box janitor\n"
                  "run-u1082316.scope loaded failed failed ramp\n"
                  "ship-sample-watch.service loaded failed failed ship\n")
        show = {
            "ship-sample-watch.service": "LoadState=loaded\nActiveState=failed\nResult=exit-code\nInvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nExecMainExitTimestampMonotonic=1\n",
            "ship-sample-watch.timer": "LoadState=loaded\nActiveState=active\n",
            "runner-worktree-retire.service": "LoadState=loaded\nActiveState=inactive\nResult=success\nInvocationID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
            "runner-worktree-retire.timer": "LoadState=loaded\nActiveState=active\n",
            "inventory-hygiene.service": "LoadState=loaded\nActiveState=inactive\nResult=success\nInvocationID=\n",
            "inventory-hygiene.timer": "LoadState=loaded\nActiveState=inactive\n",
        }
        journal = "task-worktree    failed     /srv/lanes      3 dirs " + SECRET + "\nplan ok\n"
        runner = self.table(failed, show, journal)
        a = keys(ow.check_units(self.cfg, {}, runner, 0.0))
        self.assertEqual(a["units:failed"]["detail"]["units"], ["box-janitor.service"])
        self.assertIn("reclaim:ship-sample-watch", a)
        self.assertEqual(a["reclaim:runner-worktree-retire"]["detail"]["failed_lines"], 1)
        self.assertIn("timer inactive", a["reclaim:inventory-hygiene"]["message"])
        self.assertNotIn(SECRET, json.dumps(list(a.values())))

    def test_healthy_is_silent(self):
        show = {"runner-worktree-retire.service": "LoadState=loaded\nActiveState=inactive\nResult=success\nInvocationID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
                "runner-worktree-retire.timer": "LoadState=loaded\nActiveState=active\n"}
        self.assertEqual(ow.check_units(self.cfg, {}, self.table("", show, "all good\n"), 0.0), [])


class CrashTests(Base):
    def write_ips(self, name, proc, signal, namespace, mtime):
        d = self.home / "Library/Logs/DiagnosticReports"
        d.mkdir(parents=True, exist_ok=True)
        p = d / name
        header = {"app_name": proc, "timestamp": "2026-11-04 11:00:29.00 -0700", "bug_type": "309", "name": proc}
        body = {"pid": 4242, "parentPid": 4200, "parentProc": "zsh", "procName": proc,
                "captureTime": "2026-11-04 11:00:24.3676 -0700", "procPath": "/x/" + SECRET,
                "exception": {"type": "EXC_CRASH", "signal": signal},
                "termination": {"namespace": namespace, "indicator": SECRET}}
        p.write_text(json.dumps(header) + "\n" + json.dumps(body))
        os.utime(p, (mtime, mtime))
        return p

    def test_python_sandbox_sigkill_high_and_redacted(self):
        now = time.time()
        self.write_ips("Python-2026-11-04-1.ips", "Python", "SIGKILL", "SANDBOX", now - 60)
        state = {"crashes": {"last_scan": now - 600}}
        a = keys(ow.check_crashes(self.cfg, state, now))
        c = a["crashes"]
        self.assertEqual(c["severity"], "high")
        item = c["detail"]["reports"][0]
        self.assertEqual(set(item), {"proc", "pid", "ppid", "parent", "time", "kind"})
        self.assertEqual(item["kind"], "sandbox-sigkill")
        self.assertNotIn(SECRET, json.dumps(a))

    def test_old_reports_ignored(self):
        now = time.time()
        self.write_ips("swift-1.ips", "swift-frontend", "SIGTRAP", "SIGNAL", now - 86400 * 3)
        self.assertEqual(ow.check_crashes(self.cfg, {"crashes": {"last_scan": now - 600}}, now), [])

    def test_other_crash_is_warning(self):
        now = time.time()
        self.write_ips("swift-2.ips", "swift-frontend", "SIGTRAP", "SIGNAL", now - 30)
        a = keys(ow.check_crashes(self.cfg, {"crashes": {"last_scan": now - 600}}, now))
        self.assertEqual(a["crashes"]["severity"], "warning")


class ProcessTests(Base):
    def test_orphans_runaway_and_counts(self):
        orphans = {"orphans": [{"pid": i, "ppid": 1, "age_s": 100, "cpu": 0, "rss_mb": 9, "name": "node",
                                "cmd": "node x --token=" + SECRET} for i in range(6)]
                   + [{"pid": 99, "ppid": 1, "age_s": 5, "cpu": 95, "rss_mb": 9000, "name": "chrome", "cmd": SECRET}]}
        ps = "".join(f"{i} 1 /Applications/Google Chrome.app/Contents/Google Chrome Helper (Renderer)\n" for i in range(300))
        ps += "".join(f"{i} 1 -zsh\n" for i in range(1000, 1010))
        cfg = dict(self.cfg)
        cfg["processes"] = dict(cfg["processes"], netwatch=str(self.home / "netwatch"))
        (self.home / "netwatch").write_text("")
        runner = FakeRunner({(str(self.home / "netwatch"), "orphans", "--json"): (0, json.dumps(orphans)),
                             ("ps",): (0, ps)})
        a = keys(ow.check_processes(cfg, runner))
        self.assertEqual(a["procs:orphans"]["detail"]["count"], 7)
        self.assertEqual(a["procs:runaway"]["severity"], "high")
        self.assertEqual(a["procs:chrome-helpers"]["detail"]["count"], 300)
        self.assertNotIn("procs:shells", a)
        self.assertNotIn(SECRET, json.dumps(a))
        self.assertNotIn("cmd", json.dumps(a))

    def test_quiet_host(self):
        runner = FakeRunner({("ps",): (0, "1 0 /sbin/launchd\n2 1 -zsh\n")})
        cfg = dict(self.cfg)
        cfg["processes"] = dict(cfg["processes"], netwatch=str(self.home / "missing"))
        self.assertEqual(ow.check_processes(cfg, runner), [])


def git(*args, cwd):
    env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null",
               GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout


class GitFixture(Base):
    def make_repo(self, files):
        repo = self.home / "repo"
        repo.mkdir()
        git("init", "-q", "-b", "main", cwd=repo)
        for rel, text in files.items():
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        git("add", "-A", cwd=repo)
        git("commit", "-qm", "init", cwd=repo)
        git("update-ref", "refs/remotes/origin/main", "HEAD", cwd=repo)
        return repo


class DeliveryTests(GitFixture):
    def test_dirty_and_off_main(self):
        repo = self.make_repo({"a.txt": "a\n"})
        cfg = dict(self.cfg, delivery=[str(repo)])
        self.assertEqual(ow.check_delivery(cfg, ow.run), [])
        (repo / "a.txt").write_text("changed\n")
        a = keys(ow.check_delivery(cfg, ow.run))
        self.assertEqual(a[f"delivery:{repo}"]["detail"]["dirty"], 1)
        git("checkout", "-q", "-b", "side", cwd=repo)
        a = keys(ow.check_delivery(cfg, ow.run))
        self.assertEqual(a[f"delivery:{repo}"]["detail"]["branch"], "side")
        self.assertFalse((repo / ".git" / "index.lock").exists())

    def test_missing_checkout(self):
        cfg = dict(self.cfg, delivery=[str(self.home / "nope")])
        self.assertIn(f"delivery:{self.home / 'nope'}", keys(ow.check_delivery(cfg, ow.run)))


class DriftTests(GitFixture):
    def test_claude_block_and_hooks(self):
        harness = "# Agent Harness engineering workflow\n\nrule one\n"
        repo = self.make_repo({"HARNESS.md": harness, "harness/hooks/wal.py": "print(1)\n",
                               "harness/hooks/deliver.py": "print(2)\n"})
        claude = self.home / ".claude"
        (claude / "hooks").mkdir(parents=True)
        (claude / "hooks" / "wal.py").write_text("print(1)\n")
        (claude / "hooks" / "deliver.py").write_text("print(2)\n")
        (claude / "CLAUDE.md").write_text(f"mine\n<!-- agent-harness:start -->\n{harness}<!-- agent-harness:end -->\n")
        cfg = dict(self.cfg, drift={"repo": str(repo), "ref": "origin/main", "claude_dir": str(claude)})
        self.assertEqual(ow.check_drift(cfg, ow.run), [])
        (claude / "hooks" / "deliver.py").write_text("print('old')\n")
        (claude / "CLAUDE.md").write_text(f"<!-- agent-harness:start -->\n{harness}stale\n<!-- agent-harness:end -->\n")
        a = keys(ow.check_drift(cfg, ow.run))
        self.assertIn("drift:claude-md", a)
        self.assertEqual(a["drift:hooks"]["detail"]["differ"], ["deliver.py"])

    def test_no_repo_skips(self):
        cfg = dict(self.cfg, drift={"repo": str(self.home / "none"), "ref": "origin/main", "claude_dir": str(self.home)})
        self.assertEqual(ow.check_drift(cfg, ow.run), [])


class CodexTrustTests(Base):
    def write(self, trust_all=True, tamper=False):
        codex = self.home / ".codex"
        codex.mkdir()
        hooks_path = codex / "hooks.json"
        hooks = {"hooks": {
            "SessionStart": [{"hooks": [{"type": "command", "command": "python3 /x/wal.py hook", "timeout": 10}]}],
            "PreToolUse": [{"hooks": [{"type": "command", "command": "python3 /x/guard.py hook", "timeout": 30}]},
                           {"hooks": [{"type": "command", "command": "python3 /x/wal.py hook", "timeout": 10}]}]}}
        hooks_path.write_text(json.dumps(hooks))
        lines = ["model = \"x\"\n", "[hooks.state]\n"]
        entries = ow.codex_expected_trust(hooks_path)
        for i, (key, digest) in enumerate(sorted(entries.items())):
            if not trust_all and "session_start" in key:
                continue
            if tamper and "pre_tool_use:0:0" in key:
                digest = "sha256:" + "0" * 64
            lines.append(f'\n[hooks.state."{key}"]\ntrusted_hash = "{digest}"\n')
        (codex / "config.toml").write_text("".join(lines))
        return codex

    def test_hash_matches_live_verified_algorithm(self):
        # golden: the live Mac session_start:0:0 entry (verified 2026-11-05 against ~/.codex/config.toml)
        handler = {"type": "command", "command": "python3 /Users/eric/.codex/agent-harness/wal.py hook", "timeout": 10}
        self.assertEqual(ow.codex_hook_hash("session_start", None, handler),
                         "sha256:0fe68cebd7f434c0dd1111d4474115d9fd8ca44c8e4393fd9ea102af9969907a")

    def test_trusted_is_silent(self):
        codex = self.write()
        cfg = dict(self.cfg, codex_dir=str(codex))
        before = (codex / "config.toml").read_bytes()
        self.assertEqual(ow.check_codex_trust(cfg), [])
        self.assertEqual((codex / "config.toml").read_bytes(), before)

    def test_missing_and_tampered(self):
        codex = self.write(trust_all=False, tamper=True)
        a = keys(ow.check_codex_trust(dict(self.cfg, codex_dir=str(codex))))
        t = a["codex:trust"]
        self.assertIn("Codex is skipping harness hooks", t["message"])
        self.assertEqual(len(t["detail"]["untrusted"]), 1)
        self.assertEqual(len(t["detail"]["changed"]), 1)


class RingTests(Base):
    def test_preallocated_fixed_size_and_wrap(self):
        ring = self.home / "alerts.jsonl"
        for i in range(ow.RING_SLOTS + 5):
            ow.emit({"host": "h", "source": "t", "event": "raise", "severity": "info", "key": f"k{i}",
                     "message": "m", "detail": {"big": "x" * 5000}}, path=ring)
        self.assertEqual(ring.stat().st_size, ow.RING_SLOTS * ow.SLOT_BYTES)
        events = ow.read_ring(ring)
        self.assertEqual(len(events), ow.RING_SLOTS)
        self.assertEqual(max(e["seq"] for e in events), ow.RING_SLOTS + 5)
        for line in ring.read_bytes().split(b"\n")[:-1]:
            self.assertEqual(len(line), ow.SLOT_BYTES - 1)
            json.loads(line)

    def test_corrupt_slot_tolerated(self):
        ring = self.home / "alerts.jsonl"
        ow.emit({"host": "h", "source": "t", "event": "raise", "severity": "info", "key": "a", "message": "m"}, path=ring)
        with open(ring, "r+b") as f:
            f.seek(ow.SLOT_BYTES * 7)
            f.write(b"{garbage")
        self.assertEqual(len(ow.read_ring(ring)), 1)

    def test_required_fields(self):
        with self.assertRaises(ValueError):
            ow.emit({"host": "h"}, path=self.home / "r.jsonl")


class ReconcileAndRunTests(Base):
    def run_with(self, alerts_by_run, comment_ok=True, deadman_ok=True):
        posted, dead = [], []

        def comment(argv, t, stdin):
            posted.append(stdin)
            return (0 if comment_ok else 1, "")

        def deadman(argv, t, stdin):
            dead.append(argv)
            return (0 if deadman_ok else 1, "")
        cfg = dict(self.cfg)
        cfg["sinks"] = {"comment": {"mode": "cmd", "argv": ["fake-comment"]},
                        "deadman": [["fake-deadman", "{SUBJECT}"]]}
        runner = FakeRunner({("fake-comment",): comment, ("fake-deadman",): deadman})
        rcs = []
        for alerts in alerts_by_run:
            checks = {"disk": lambda *a, _al=alerts: list(_al)}
            rcs.append(ow.run_once(cfg, self.home, runner=runner, checks=checks, now=time.time()))
        return rcs, posted, dead

    def test_dedup_clear_reraise(self):
        a = {"check": "disk", "key": "disk:volume:/", "severity": "high", "message": "93% used", "detail": {}}
        rcs, posted, dead = self.run_with([[a], [a], [], [a]])
        self.assertEqual(rcs, [0, 0, 0, 0])
        events = [(e["event"], e["key"]) for e in ow.read_ring(ow.ring_path(self.home)) if e["source"] == "ops-watch"]
        self.assertEqual(events, [("raise", "disk:volume:/"), ("clear", "disk:volume:/"), ("raise", "disk:volume:/")])
        self.assertEqual(len(posted), 3)
        self.assertEqual(dead, [])

    def test_escalation_and_critical_deadman(self):
        a = {"check": "disk", "key": "disk:volume:/", "severity": "high", "message": "93%", "detail": {}}
        b = dict(a, severity="critical", message="98%")
        rcs, posted, dead = self.run_with([[a], [b], [b]])
        self.assertEqual(len(dead), 1)
        self.assertTrue(dead[0][1].startswith("[ops-watch] testhost critical disk:volume:/"))  # one argv element

    def test_sink_failure_exit2_and_retry(self):
        a = {"check": "disk", "key": "disk:volume:/", "severity": "high", "message": "93%", "detail": {}}
        rcs, posted, _ = self.run_with([[a], [a]], comment_ok=False)
        self.assertEqual(rcs, [2, 2])
        self.assertEqual(len(posted), 2)  # retried on the second run
        st = ow.load_state(self.home)
        self.assertTrue(st["pending_comment"])
        self.assertFalse((self.home / ".agent-harness/logs/ops-watch.last-ok").exists())

    def test_check_error_does_not_clear_and_alerts(self):
        a = {"check": "disk", "key": "disk:volume:/", "severity": "high", "message": "93%", "detail": {}}
        cfg = dict(self.cfg)
        cfg["sinks"] = {"comment": {"mode": "none"}, "deadman": []}
        ow.run_once(cfg, self.home, runner=FakeRunner(), checks={"disk": lambda *x: [a]}, now=time.time())

        def boom(*x):
            raise RuntimeError("boom " + SECRET)
        rc = ow.run_once(cfg, self.home, runner=FakeRunner(), checks={"disk": boom}, now=time.time())
        self.assertEqual(rc, 0)
        active = ow.active_alerts(self.home)
        ks = {x["key"] for x in active}
        self.assertIn("disk:volume:/", ks)
        self.assertIn("ops-watch:check-error:disk", ks)
        self.assertNotIn(SECRET, ow.ring_path(self.home).read_text())

    def test_injection_text(self):
        self.assertEqual(ow.injection_text(self.home), "")
        a = {"check": "codex", "key": "codex:trust", "severity": "high",
             "message": "Codex is skipping harness hooks (3 untrusted)", "detail": {}}
        cfg = dict(self.cfg)
        cfg["sinks"] = {"comment": {"mode": "none"}, "deadman": []}
        ow.run_once(cfg, self.home, runner=FakeRunner(), checks={"codex": lambda *x: [a]}, now=time.time())
        text = ow.injection_text(self.home)
        self.assertIn("Codex is skipping harness hooks", text)
        self.assertLess(len(text), 900)

    def test_injection_never_raises_on_garbage(self):
        p = ow.ring_path(self.home)
        p.parent.mkdir(parents=True)
        p.write_bytes(b"\x00\xff garbage")
        (p.parent / "ops-watch").mkdir()
        (p.parent / "ops-watch" / "state.json").write_bytes(b"{nope")
        self.assertIsInstance(ow.injection_text(self.home), str)


class WalInjectionTests(Base):
    def invoke(self, event, data):
        return subprocess.run([sys.executable, str(HOOKS / "wal.py"), event], input=json.dumps(data), text=True,
                              capture_output=True, env={**os.environ, "HOME": str(self.home),
                                                        "HARNESS_PROVENANCE_OFFLINE": "1"})

    def test_prompt_and_subagent_carry_active_alerts(self):
        r = self.invoke("prompt", {"session_id": "s1", "prompt": "hi"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("OPS ALERTS", r.stdout)
        ow.emit({"host": "dev2", "source": "ops-watch", "event": "raise", "severity": "critical",
                 "key": "disk:volume:/", "message": "/ 97% used"}, home=self.home)
        for event, data in (("prompt", {"session_id": "s1", "prompt": "hi"}),
                            ("subagent", {"session_id": "s1", "agent_id": "a1", "agent_type": "task-owner"}),
                            ("session", {"session_id": "s1", "source": "startup"})):
            r = self.invoke(event, data)
            self.assertEqual(r.returncode, 0, r.stderr)
            ctx = json.loads(r.stdout)["hookSpecificOutput"]["additionalContext"]
            self.assertIn("[critical] dev2 disk:volume:/: / 97% used", ctx, event)

    def test_corrupt_ring_never_blocks_prompt(self):
        p = ow.ring_path(self.home)
        p.parent.mkdir(parents=True)
        p.write_bytes(b"\xff" * 4096)
        r = self.invoke("prompt", {"session_id": "s1", "prompt": "hi"})
        self.assertEqual(r.returncode, 0, r.stderr)


class ReadOnlyTests(unittest.TestCase):
    def test_command_allowlist(self):
        src = (HOOKS / "ops_watch.py").read_text()
        for bad in ("os.remove", "os.unlink", "shutil.rmtree", "os.kill", "killpg", ".unlink(", "rmdir"):
            self.assertNotIn(bad, src, bad)


if __name__ == "__main__":
    unittest.main()
