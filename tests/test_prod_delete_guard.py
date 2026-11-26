"""goodqa#14908: prod_delete_guard.

The detection cases are Hawkeye's own (tests/test-prod-delete-guard.py: H-1, H-1b, H-1c, the H-2
accepted limitations and the BLOCKER 1-3 regression pins). Release 1001 registers the guard on the database tools only,
never on Bash, and lifts a refusal with a live `ah approve delete --host <target>` approval. The shell-shaped cases run
through a local `db_tool_patterns` tool (`mcp__shell__run`, field `command`), the only way such text reaches the guard
now. Every test uses its own temporary HOME. Commands are judged by evaluate() or by the hook run as a child process,
and are never executed.
PDG_HOOKS_DIR points the suite at another implementation; the mutants in the review packet use it
to show the suite failing first.
"""

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get("PDG_HOOKS_DIR") or ROOT / "harness/hooks")
sys.path.insert(0, str(HOOKS))

import prod_delete_guard as pdg  # noqa: E402

SID = "0f4c2b6e-8d1a-4e5b-9c3d-7a2e1f6b5c4d"  # Claude Code session ids are UUIDs (provenance answer: form)


SHELL_TOOL = "mcp__shell__run"  # a db_tool_patterns tool whose `command` field is read as a command


def bash(command):
    return {"hook_event_name": "PreToolUse", "tool_name": SHELL_TOOL, "tool_input": {"command": command}}


def approve(home, target, expires=None, kind="delete", granted_by="user"):
    """Record what `ah approve delete --host <target>` records, in the approvals store under `home`."""
    import ah_approvals  # noqa: PLC0415
    return ah_approvals.grant(kind, {"host": target}, granted_by, "test: approved production delete", expires=expires,
                              home=home)


class Case(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="pdg-")
        self.home = Path(os.path.realpath(self._tmp.name))
        self._env = {k: os.environ.get(k) for k in ("HOME", "CLAUDE_CONFIG_DIR", "AH_LOCAL_CONFIG")}
        os.environ["HOME"] = str(self.home)
        os.environ.pop("CLAUDE_CONFIG_DIR", None)
        local = self.home / "local.json"
        local.write_text(json.dumps({"db_tool_patterns": [{"tool": SHELL_TOOL, "fields": ["command"]}]}))
        os.environ["AH_LOCAL_CONFIG"] = str(local)
        import ah_local  # noqa: PLC0415
        ah_local.reset()
        self.addCleanup(ah_local.reset)
        self.wal = self.home / ".claude/wals/s/agent-pdg.jsonl"
        self.wal.parent.mkdir(parents=True)

    def tearDown(self):
        for key, value in self._env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._tmp.cleanup()

    def verdict(self, ev, **kw):
        kw.setdefault("home", str(self.home))
        result = pdg.evaluate(ev, **kw)
        return result[0] if result else "allow"

    def assertDenied(self, command, **kw):
        self.assertEqual(self.verdict(bash(command), **kw), "deny", command)

    def assertAllowed(self, command, **kw):
        self.assertEqual(self.verdict(bash(command), **kw), "allow", command)

class Detection(Case):
    """Hawkeye's cases, as end-to-end verdicts with no grant recorded."""

    def test_h1_at_sign_before_prod(self):
        self.assertDenied("psql 'postgresql://u:p@prod-db.example.com/main' -c 'DROP TABLE users'")
        self.assertDenied("psql 'postgresql://u:p@prod.example.com/main' -c 'DROP TABLE users'")

    def test_h1b_colon_after_prod(self):
        self.assertDenied("psql 'postgresql://u:p@prod:5432/main' -c 'DROP TABLE users'")

    def test_h1c_query_and_fragment_after_prod(self):
        self.assertDenied("psql 'postgresql://u:p@prod?sslmode=require' -c 'DROP TABLE users'")
        self.assertDenied("psql 'postgresql://u:p@prod#frag' -c 'DROP TABLE users'")

    def test_controls_flag_targets(self):
        self.assertDenied("psql 'postgresql://u:p@db-prod.example.com/main' -c 'DROP TABLE users'")
        self.assertDenied("psql --host=prod-db.example.com -c 'TRUNCATE sessions'")
        self.assertDenied("mysql -h prod.internal -e 'DROP DATABASE app'")
        self.assertDenied("mysqldump --host=prod.example.com --all-databases | mysql --host=other && "
                          "mysql -h prod-shard-1 -e 'DROP DATABASE app'")
        self.assertDenied("mongosh --host production.cluster --eval 'db.x.drop()' ; psql -d production -c 'DELETE FROM t'")

    def test_d1_remote_and_file_payload(self):
        self.assertDenied('wrangler d1 execute mydb --remote --command="DELETE FROM users"')
        self.assertDenied('python3 -c "import subprocess" && wrangler d1 execute mydb --remote --command="DELETE FROM users"')
        sql = self.home / "payload.sql"
        sql.write_text("DELETE FROM users;\n")
        self.assertDenied("wrangler d1 execute mydb --remote --file=%s" % sql)
        self.assertAllowed("wrangler d1 execute mydb --file=%s" % sql)  # local D1 is a throwaway file
        sql.write_text("SELECT 1;\n")
        self.assertAllowed("wrangler d1 execute mydb --remote --file=%s" % sql)

    def test_accepted_limitations_and_blocker_pins_still_deny(self):
        for command in (
                "python3 -c \"print('example: wrangler d1 execute mydb --remote --command=\\\"DELETE FROM users\\\"')\"",
                "cat >> notes.md <<'EOF'\n## finding\nDROP TABLE against postgresql://u:p@prod-db.example.com/main\nEOF\n",
                "python3 -c \"import subprocess; subprocess.run(['psql', '--host=prod-db.example.com', '-c', 'DROP TABLE users'])\"",
                "cat >> notes.md <<EOF\n$(psql 'postgresql://u:p@prod-db.example.com/main' -c 'DROP TABLE users')\nEOF\n",
                "cat >>script.sh <<'EOF'\npsql 'postgresql://u:p@prod-db.example.com/main' -c 'DROP TABLE users'\nEOF\nbash script.sh\n",
                "psql 'postgresql://u:p@prod-db.example.com/main' <<'EOF'\nDELETE FROM users WHERE 1=1;\nEOF\n",
                "bash <<'EOF'\nwrangler d1 execute mydb --remote --command=\"DELETE FROM users\"\nEOF\n"):
            with self.subTest(command=command[:60]):
                self.assertDenied(command)

    def test_non_production_and_non_destructive_are_allowed(self):
        for command in (
                "psql 'postgresql://u:p@localhost:5432/dev' -c 'DROP TABLE scratch'",
                "psql --host=prod-db.example.com -c 'SELECT count(*) FROM users'",
                "psql -h staging.example.com -c 'TRUNCATE sessions'",
                "grep -n 'DELETE FROM' notes/production-incident.md",
                "docker run -d prod-image sh -c 'echo DROP TABLE'",
                "psql -h reproduction.example.com -c 'DROP TABLE t'",  # 'prod' inside a word is not a segment
                "ls -la", ""):
            with self.subTest(command=command):
                self.assertAllowed(command)

    def test_mcp_tool_paths(self):
        d1 = {"tool_name": "mcp__cloudflare__d1_database_query", "tool_input": {"sql": "DELETE FROM devices"}}
        self.assertEqual(self.verdict(d1), "deny")
        d1["tool_input"] = {"sql": "SELECT * FROM devices"}
        self.assertEqual(self.verdict(d1), "allow")
        run = {"tool_name": "mcp__mydb__run",
               "tool_input": {"command": "ls", "payload": ["wrangler d1 execute db --remote --command='DROP TABLE x'"]}}
        self.assertEqual(self.verdict(run), "allow")  # not a database tool unless local.json db_tool_patterns names it
        sql = {"tool_name": "mcp__pg__execute_sql", "tool_input": {"statement": "psql -h prod-1 -c 'TRUNCATE t'"}}
        self.assertEqual(self.verdict(sql), "deny")
        sql["tool_input"] = {"sql": "DROP TABLE t"}  # no named target and not production by construction
        self.assertEqual(self.verdict(sql), "allow")
        hyper = {"tool_name": "mcp__cloudflare__hyperdrive_query", "tool_input": {}}
        self.assertEqual(self.verdict(hyper), "allow")  # no field it reads: nothing to judge
        self.assertEqual(self.verdict({"tool_name": "Write", "tool_input": {"content": "DROP TABLE x --host=prod"}}),
                         "allow")

    def test_malformed_events_allow(self):
        for ev in (None, [], {"tool_name": "Bash"}, {"tool_name": "Bash", "tool_input": "x"}, {"tool_input": {}}):
            with self.subTest(ev=ev):
                self.assertEqual(self.verdict(ev), "allow")

    def test_matcher_covers_every_judged_tool_shape_and_never_bash(self):
        for name in ("mcp__cloudflare__d1_database_query", "mcp__pg__execute_sql",
                     "mcp__x__run_sql", "mcp__x__query", "mcp__x__sql", "mcp__cloudflare__hyperdrive_configs_list"):
            with self.subTest(name=name):
                self.assertTrue(re.fullmatch(pdg.MATCHER, name))
        for name in ("Bash", "PowerShell", "Write", "Edit", "Read", "Agent"):
            self.assertFalse(re.fullmatch(pdg.MATCHER, name), name)
        self.assertFalse(re.fullmatch(pdg.matcher(), "Bash"))

    def test_a_bash_payload_is_not_judged_even_when_a_local_pattern_names_bash(self):
        cmd = "psql --host=prod-db.example.com -c 'TRUNCATE sessions'"
        event = {"tool_name": "Bash", "tool_input": {"command": cmd}}
        self.assertEqual(self.verdict(event), "allow")
        (self.home / "local.json").write_text(json.dumps({"db_tool_patterns": [{"tool": "Bash", "fields": ["command"]},
                                                                              {"tool": ".*", "fields": ["command"]}]}))
        import ah_local  # noqa: PLC0415
        ah_local.reset()
        self.assertEqual(self.verdict(event), "allow")
        self.assertFalse(re.fullmatch(pdg.matcher(), "Bash"))


class LocalDbTools(unittest.TestCase):
    """~/.agent-harness/local.json `db_tool_patterns` adds a tool to the judged set and to the installed matcher."""

    def setUp(self):
        import ah_local
        self.ah_local = ah_local
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "local.json"
        path.write_text(json.dumps({"db_tool_patterns": [
            {"tool": "mcp__mydb__run", "fields": ["payload", "command"]}, {"tool": "bad[regex"}, "junk"]}))
        old = os.environ.get("AH_LOCAL_CONFIG")
        os.environ["AH_LOCAL_CONFIG"] = str(path)
        ah_local.reset()

        def restore():
            if old is None:
                os.environ.pop("AH_LOCAL_CONFIG", None)
            else:
                os.environ["AH_LOCAL_CONFIG"] = old
            ah_local.reset()
        self.addCleanup(restore)

    def test_a_configured_tool_is_judged_and_matched(self):
        run = {"tool_name": "mcp__mydb__run",
               "tool_input": {"command": "ls", "payload": ["wrangler d1 execute db --remote --command='DROP TABLE x'"]}}
        self.assertIn("DROP TABLE", pdg.command_text_for_event(run))
        self.assertTrue(re.fullmatch(pdg.matcher(), "mcp__mydb__run"))
        self.assertFalse(re.fullmatch(pdg.matcher(), "mcp__other__run"))
        self.assertEqual(pdg.matcher(), pdg.MATCHER + "|mcp__mydb__run")  # invalid entries are skipped

    def test_the_installer_registers_the_configured_matcher(self):
        sys.path.insert(0, str(ROOT))
        import install
        self.assertEqual(install.prod_delete_matcher(), pdg.matcher())


class Bypasses(Case):
    """native review F3: each of these used to be allowed with no grant."""

    def sql_file(self, name="drop.sql", text="DROP TABLE users;\n"):
        path = self.home / name
        path.write_text(text)
        return path

    def test_file_and_redirect_inputs(self):
        self.sql_file()
        for command in ("psql -h prod-db -f %s" % (self.home / "drop.sql"), "psql -h prod-db < %s" % (self.home / "drop.sql"),
                        "psql -h prod-db -f drop.sql"):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(dict(bash(command), cwd=str(self.home))), "deny")
        self.assertAllowed("psql -h prod-db -f %s" % self.sql_file("ok.sql", "SELECT 1;\n"))

    def test_unreadable_sql_file_on_a_prod_target_denies(self):
        # a file the guard cannot read (missing at hook time, e.g. written earlier in the same command,
        # or unreadable) cannot be judged, so a prod-targeted run of it fails closed
        made = "printf 'DROP TABLE users;' > /tmp/pdg-x.sql && psql -h prod-db -f /tmp/pdg-nonexistent-x.sql"
        for command in (made, "wrangler d1 execute appdb --remote --file=~/pdg-nonexistent.sql",
                        "psql -h prod-db < %s" % (self.home / "missing.sql")):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(dict(bash(command), cwd=str(self.home))), "deny")
        self.assertAllowed("psql -h localhost -f %s" % (self.home / "missing.sql"))  # not production

    def test_wrangler_relative_file_resolves_against_event_cwd(self):
        self.sql_file()
        ev = dict(bash("wrangler d1 execute appdb --remote --file=drop.sql"), cwd=str(self.home))
        self.assertEqual(self.verdict(ev), "deny")

    def test_attached_flags_env_and_positional_targets(self):
        for command in ("psql -hprod-db -c 'DELETE FROM users'", "mysql -hprod.internal -e 'DROP DATABASE app'",
                        "PGHOST=prod-db psql -c 'DELETE FROM users'",
                        "DATABASE_URL=postgres://u@prod-db/app psql \"$DATABASE_URL\" -c 'DELETE FROM t'",
                        "psql -U app prod -c 'DELETE FROM users'", "psql -U app app_production -c 'TRUNCATE t'"):
            with self.subTest(command=command):
                self.assertDenied(command)

    def test_hook_environment_variables(self):
        self.assertDenied("psql \"$DATABASE_URL\" -c 'DELETE FROM t'", env={"DATABASE_URL": "postgres://u@prod-db/app"})
        self.assertDenied("psql -c 'DELETE FROM t'", env={"PGHOST": "prod-db"})
        self.assertAllowed("psql -h localhost -c 'DELETE FROM t'", env={"PGHOST": "prod-db"})
        self.assertAllowed("psql -c 'DELETE FROM t'", env={"PGHOST": "localhost"})

    def test_ssh_and_docker_exec(self):
        self.assertDenied("ssh prod-db.internal \"psql -c 'DELETE FROM users'\"")
        self.assertDenied("ssh -i k -p 22 deploy@prod-db \"psql -c 'TRUNCATE t'\"")
        self.assertDenied("docker exec -it prod-postgres psql -U app -c 'DELETE FROM users'")
        self.assertAllowed("ssh prod-web.internal 'ls /var/log'")
        self.assertAllowed("docker exec dev-postgres psql -c 'DELETE FROM users'")

    def test_disguised_and_extra_statements(self):
        for command in ("psql -h prod-db -c \"DEL\"\"ETE FROM users\"", "psql -h prod-db -c 'DELETE/**/FROM users'",
                        "psql -h prod-db -c 'DROP SCHEMA public CASCADE'", "psql -h prod-db -c 'UPDATE users SET email=null'"):
            with self.subTest(command=command):
                self.assertDenied(command)
        self.assertAllowed("psql -h prod-db -c 'UPDATE users SET email=null WHERE id=4'")

class HookProcess(Case):
    """The installed shape: python3 -I <script>, payload on stdin, like doctor's canary."""

    def hook(self, payload):
        return subprocess.run([sys.executable, "-I", str(HOOKS / "prod_delete_guard.py")], input=json.dumps(payload),
                              capture_output=True, text=True, env=dict(os.environ), timeout=60, check=False)

    def test_deny_and_allow_on_stdout_exit_zero(self):
        denied = self.hook(bash("psql --host=prod-db.example.com -c 'TRUNCATE sessions'"))
        self.assertEqual(denied.returncode, 0, denied.stderr)
        self.assertEqual(json.loads(denied.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        allowed = self.hook(bash("ls"))
        self.assertEqual((allowed.returncode, allowed.stdout, allowed.stderr), (0, "", ""))

    def test_garbage_stdin_allows(self):
        r = subprocess.run([sys.executable, "-I", str(HOOKS / "prod_delete_guard.py")], input="{nope",
                           capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual((r.returncode, r.stdout), (0, ""))

class Install(unittest.TestCase):
    def test_installer_registers_guard_fail_open_with_matcher(self):
        sys.path.insert(0, str(ROOT))
        import install
        claude = Path("/h/.claude")
        groups = [g for g in install.managed_hooks(claude)["PreToolUse"]
                  if any(str(claude / "hooks" / "prod_delete_guard.py") in install.hook_argv(h) for h in g["hooks"])]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["matcher"], pdg.matcher())
        self.assertFalse(re.fullmatch(groups[0]["matcher"], "Bash"))
        self.assertNotIn("onFailure", groups[0]["hooks"][0])
        self.assertIn("prod_delete_guard.py", install.HOOKS)
        self.assertIn(str(claude / "hooks" / "prod_delete_guard.py"), install.managed_scripts(claude))


class Round3(Case):
    """Native re-review of 71d7e78 (hk-wave1-r2-71d7e78.md): R1-R6."""
    TARGET = "prod-db"

    def sql(self, name, text):
        (self.home / name).write_text(text)
        return self.home / name

    def ev(self, command):
        return dict(bash(command), cwd=str(self.home))

    def test_r1_huge_destructive_command_decides_fast(self):
        body = "DELETE FROM a; " * 200000  # about 3 MB in one quoted token
        for command, want in (("psql -h prod-db -c '%s'" % body, "deny"), ("psql -h localhost -c '%s'" % body, "allow")):
            with self.subTest(want=want):
                start = time.monotonic()
                self.assertEqual(self.verdict(bash(command)), want)
                self.assertLess(time.monotonic() - start, 5.0)  # measured 1.3 s on the Mac; hook timeout is 30 s

    def test_r2_fifo_sql_file_denies_without_hanging(self):
        import threading
        fifo = self.home / "q.sql"
        os.mkfifo(fifo)
        got = []
        worker = threading.Thread(target=lambda: got.append(self.verdict(self.ev("psql -h prod-db -f %s" % fifo))),
                                  daemon=True)
        worker.start()
        worker.join(3)
        try:
            self.assertFalse(worker.is_alive(), "the hook blocked on a FIFO")
            self.assertEqual(got, ["deny"])
        finally:
            if worker.is_alive():  # release the blocked reader so the thread can end
                os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))

    def test_r3_other_ways_of_feeding_a_file(self):
        self.sql("evil.sql", "DROP TABLE users;\n")
        self.sql("q.sql", "SELECT 1;\n")
        for command in ("cat evil.sql | psql -h prod-db", "psql -h prod-db -c '\\i evil.sql'",
                        "psql -h prod-db -c '\\ir evil.sql'", 'psql -h prod-db <<< "$(cat evil.sql)"',
                        'psql -h prod-db <<< "$(< evil.sql)"', "mysql -h prod-db -e 'source evil.sql'",
                        "sqlite3 /srv/prod.db '.read evil.sql'",
                        "cp evil.sql q.sql && psql -h prod-db -f q.sql",
                        "base64 -d enc.b64 > q.sql; psql -h prod-db -f q.sql",
                        "sed -i 's/SELECT 1/SELECT 2/' q.sql && psql -h prod-db < q.sql"):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(self.ev(command)), "deny")
        for command in ("cat q.sql | psql -h prod-db", "psql -h prod-db -f q.sql", "cat evil.sql | psql -h localhost"):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(self.ev(command)), "allow")

    def test_r5_d1_target_skips_flags_and_flag_targets_refused(self):
        desc, groups = pdg.targets_production("wrangler d1 execute --remote mydb --command 'DELETE FROM t'")
        self.assertEqual(groups, [("mydb",)])
        self.assertTrue(pdg.valid_target("--remote"))  # a flag is never an approvable target

class Round4(Case):
    """Native delta re-review of ca56501 (hk-wave1-r3-ca56501.md): B1-B7 and N1."""

    def test_b4_database_past_the_option_scan_bound_fails_closed(self):
        # past AFTER_SCAN option words the guard cannot tell which database psql uses: a delete denies (M49)
        many = "psql " + "-v a=b " * 200 + "devdb -c 'DELETE FROM users'"
        self.assertDenied(many)
        self.assertIn("too long to judge its database", pdg.evaluate(bash(many), home=str(self.home))[1])
        self.assertAllowed("psql " + "-v a=b " * 5 + "devdb -c 'DELETE FROM users'")  # control: within the bound

    def test_source_compiles_without_warnings(self):
        # dev2 (Python 3.12) printed "SyntaxWarning: invalid escape sequence" on every hook run
        import warnings
        source = (HOOKS / "prod_delete_guard.py").read_text()
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            compile(source, "prod_delete_guard.py", "exec")

    def sql(self, name, text):
        (self.home / name).write_text(text)
        return self.home / name

    def ev(self, command):
        return dict(bash(command), cwd=str(self.home))

    def test_b2_oversized_command_keeps_a_positional_prod_database(self):
        filler = "SELECT 1; " * 7000  # about 70 KB inside the quoted -c
        self.assertDenied("psql -c '%s DELETE FROM users' app_production" % filler)
        self.assertAllowed("psql -c '%s DELETE FROM users' app_dev" % filler)

    def test_b3_d1_flag_values_are_not_the_database(self):
        cmd = "wrangler d1 execute --env production billing-db --remote --command 'DELETE FROM invoices'"
        self.assertEqual(pdg.targets_production(cmd)[1], [("billing-db",)])
        cmd2 = "wrangler d1 execute -c wrangler.toml --command 'DELETE FROM t' --persist-to /x billing-db --remote"
        self.assertEqual(pdg.targets_production(cmd2)[1], [("billing-db",)])
        for name in ("prod", "production", "PROD"):
            self.assertTrue(pdg.valid_target(name), name)

    def test_b4_repeated_client_words_decide_fast(self):
        for word in ("psql ", "mysql ", "cp a ", "wrangler d1 ", "sqlite3 ", "sed -i ", "psql -f ", "psql -v x "):
            command = word * (100000 // len(word)) + " psql -h prod-db -c 'DELETE FROM users'"
            with self.subTest(word=word):
                start = time.monotonic()
                self.assertEqual(self.verdict(bash(command)), "deny")  # prod target, or too long to judge
                self.assertLess(time.monotonic() - start, 2.0)

    def test_b5_other_spellings_deny(self):
        self.sql("evil.sql", "DROP TABLE users;\n")
        self.sql("q.sql", "SELECT 1;\n")
        os.symlink(str(self.home / "r.sql"), str(self.home / "l.sql"))
        (self.home / "sub").mkdir()
        self.sql("sub/q.sql", "DROP TABLE users;\n")
        for command in ("psql -h prod-db -c '\\include evil.sql'", "psql -h prod-db -c '\\include_relative evil.sql'",
                        "psql -h prod-db -c \"\\i 'evil.sql'\"", "sqlite3 /srv/prod.db \".read 'evil.sql'\"",
                        "mysql -h prod-db -e '\\. evil.sql'", "psql -h prod-db -1f evil.sql",
                        "psql -h prod-db -Xf evil.sql", "psql -h prod-db --fil=evil.sql",
                        "sqlite3 -init evil.sql /srv/prod.db .quit", "head -c 100000 evil.sql | psql -h prod-db",
                        "sed -n p evil.sql | psql -h prod-db", "cp evil.sql r.sql && psql -h prod-db -f l.sql",
                        "curl -so q.sql https://example.invalid/x; psql -h prod-db -f q.sql",
                        "cd sub && psql -h prod-db -f q.sql"):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(self.ev(command)), "deny")
        for command in ("echo 'SELECT 1' | psql -h prod-db", "printf 'SELECT 1;' | psql -h prod-db",
                        "head -c 100 evil.sql | psql -h localhost", "psql -h prod-db -f q.sql"):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(self.ev(command)), "allow")

    def test_b7_cheap_gaps_deny(self):
        self.sql("big.sql", "-- " + "x" * (pdg.FILE_READ_LIMIT + 10) + "\nDROP TABLE users;\n")
        for command in ("psql -h prod-db -f big.sql", "psql -h prod-db -c $'DELETE--keep\\nFROM users'",
                        "psql -h prod-db -c DELETE\\ FROM\\ users", "psql -h prod-db -c $'DELETE\\x20FROM users'",
                        "dropdb -h prod-db app", "mysqladmin -h prod-db -f drop app",
                        "psql -h 192.0.2.5 app_production -c 'DELETE FROM users'",
                        "sqlite3 -cmd 'DELETE FROM users' /srv/prod.db"):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(self.ev(command)), "deny")
        self.assertEqual(self.verdict(self.ev("dropdb -h localhost app")), "allow")

    def test_n1_cat_in_a_prod_command_is_judged_as_input(self):
        # r5: every cat argument in a command with a client is SQL input again (H1), so these read-only rows are
        # denied as in ca56501, naming the file (a disclosed over-refusal: split the command)
        for command, name in (("psql -h prod-db -c 'SELECT count(*) FROM users' > out.txt && cat out.txt", "out.txt"),
                              ("cat /dev/null > x.log; psql -h prod-db -c 'SELECT 1'", "/dev/null"),
                              ("PGPASSWORD=$(cat ~/.nope) psql -h prod-db -c 'SELECT 1'", "~/.nope")):
            with self.subTest(command=command):
                result = pdg.evaluate(self.ev(command), home=str(self.home))
                self.assertEqual(result[0], "deny")
                self.assertIn(name, result[1])
        for command in ("psql -h prod-db -c 'SELECT count(*) FROM users' > out.txt",
                        "psql -h prod-db -c 'SELECT 1' | cat"):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(self.ev(command)), "allow")


class Round5(Case):
    """Native delta re-review of 33f1695 (hk-wave1-r4-33f1695.md): H1-H4 and L1 A8, through the real hook."""

    def setUp(self):
        super().setUp()
        self.cwd = self.home / "cwd"
        self.cwd.mkdir()
        for name, body in {"evil.sql": "DROP TABLE users;\n", "ok.sql": "SELECT 1;\n", "q.sql": "SELECT 1;\n",
                           "migration.sql": "DELETE FROM sessions;\n"}.items():
            (self.cwd / name).write_text(body)

    def hook(self, command):
        payload = {"hook_event_name": "PreToolUse", "tool_name": SHELL_TOOL, "tool_input": {"command": command},
                   "cwd": str(self.cwd)}
        env = dict(os.environ, HOME=str(self.home))
        env.pop("CLAUDE_CONFIG_DIR", None)
        r = subprocess.run([sys.executable, "-I", str(HOOKS / "prod_delete_guard.py")], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60, check=False)
        self.assertEqual((r.returncode, r.stderr), (0, ""), command)
        return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] if r.stdout.strip() else "allow"

    def check(self, rows, want):
        for command in rows:
            with self.subTest(command=command):
                self.assertEqual(self.hook(command), want, command)

    def test_h1_cat_into_a_wrapped_or_remote_client_denies(self):
        self.check(("cat evil.sql | ssh prod-db-1 psql app", "cat evil.sql | ssh prod-db-1 'psql app'",
                    "cat evil.sql | docker exec -i prod-pg psql -U postgres app",
                    "cat evil.sql | sudo -u postgres psql -h prod-db", "cat evil.sql | env PGPASSWORD=x psql -h prod-db",
                    "cat evil.sql | timeout 60 psql -h prod-db", "cat migration.sql | ssh prod-db-1 psql app; true"),
                   "deny")

    def test_h1_cat_substitution_anywhere_denies(self):
        self.check(('psql -h prod-db -c "$(cat ok.sql evil.sql)"', 'psql -h prod-db --command="$(cat evil.sql)"',
                    'psql -h prod-db -c "SELECT 1; $(cat evil.sql)"', 'mysql -h prod-db --execute="$(cat evil.sql)"',
                    'psql -h prod-db -c "$(cat evil.sql)"', "psql -h prod-db -c `cat evil.sql`"), "deny")

    def test_h2_flags_that_do_not_replace_stdin_still_deny(self):
        self.check(("head -c 999 evil.sql | psql -h prod-db -e", "head -c 999 evil.sql | mysql -h prod-db -f",
                    "head -c 999 evil.sql | mysql -h prod-db -c",
                    "head -c 999 evil.sql | sqlite3 -cmd '.mode list' /srv/prod.db",
                    "head -c 999 evil.sql | sqlite3 -init ok.sql /srv/prod.db",
                    "sed -n p evil.sql | psql -h prod-db --echo-errors -e",
                    "head -c 999 evil.sql | sudo -u postgres psql -h prod-db",
                    'psql -h prod-db -c "$(head -c 999 evil.sql)"'), "deny")

    def test_h3_same_step_writers_deny(self):
        self.check(("dd if=evil.sql of=q.sql 2>/dev/null | xargs psql -h prod-db -f q.sql",
                    "psql -h prod-db -f q.sql -v x=$(dd if=evil.sql of=q.sql 2>/dev/null)",
                    "psql -h prod-db -f q.sql -v x=`dd if=evil.sql of=q.sql`",
                    "curl -so q.sql http://127.0.0.1:9/x | xargs psql -h prod-db -f q.sql",
                    "psql -h prod-db -f q.sql <(dd if=evil.sql of=q.sql)",
                    "PGOPTIONS=$(dd if=evil.sql of=q.sql) psql -h prod-db -f q.sql"), "deny")

    def test_read_only_and_non_prod_controls_allow(self):
        self.check(("cat ok.sql | ssh prod-db-1 psql app", "head ok.sql | psql -h localhost",
                    "cd /srv && psql -h localhost -f ok.sql", "psql -h prod-db -c 'SELECT 1' 2>&1 | tee log.txt",
                    "psql -h prod-db -f ok.sql 2>&1", "psql -h prod-db -f ok.sql &> log.txt",
                    "head -c 999 ok.sql | psql -h prod-db -c 'SELECT 2'", "head -c 99 ok.sql | psql -h prod-db -f q.sql",
                    "head -c 99 evil.sql | mysql -h prod-db -e 'SELECT 1'", "psql -h prod-db -c \"$(cat ok.sql)\"",
                    "PGPASSWORD=$(cat ok.sql) psql -h localhost -c 'SELECT 1'",
                    "git commit -m 'note: psql DELETE FROM users on prod' "), "allow")

    def test_h5_attached_option_values_do_not_replace_stdin(self):
        (self.cwd / "dump.sql.gz").write_bytes(b"\x1f\x8b")
        self.check(("zcat dump.sql.gz | mysql -h prod-db -uroot -pchangeme app",
                    "gunzip -c dump.sql.gz | mysql -h prod-db -Dstore", "head -c 999 evil.sql | mysql -h prod-db -pe app",
                    "head -c 999 evil.sql | mysql -h prod-db --init-command='SET x=1' -De",
                    "head -c 999 evil.sql | psql -h prod-db -Usvc app", "head -c 999 evil.sql | psql -h prod-db -v x=-f",
                    "head -c 999 evil.sql | psql -h prod-db -v 'x= -c'", "head -c 999 evil.sql | psql -h prod-db -v '<x'",
                    "head -c 999 evil.sql | psql -h prod-db -v 'x=< ok.sql '",
                    "head -c 999 evil.sql | mariadb -h prod-db -pse app"), "deny")
        self.check(("head -c 99 evil.sql | mysql -h prod-db -Be 'SELECT 1'",
                    "head -c 99 evil.sql | mysql -h prod-db --execute='SELECT 1'",
                    "head -c 99 evil.sql | psql -h prod-db -Xc 'SELECT 1'",
                    "head -c 99 evil.sql | psql -h prod-db --command='SELECT 1'",
                    "head -c 99 evil.sql | psql -h prod-db -U svc -c 'SELECT 1'",
                    "head -c 99 evil.sql | psql -h prod-db app < ok.sql"), "allow")


class Approvals(Case):
    """Release 1001: the approvals store is the one record (docs/approvals.md); the signed grant file is gone."""
    CMD = "psql --host=prod-db.example.com -c 'TRUNCATE sessions'"
    TARGET = "prod-db.example.com"

    def test_a_live_delete_approval_for_the_exact_target_allows(self):
        self.assertDenied(self.CMD)
        approve(self.home, self.TARGET)
        self.assertAllowed(self.CMD)
        self.assertAllowed(self.CMD.replace(self.TARGET, self.TARGET.upper()))  # case-folded

    def test_the_target_is_an_exact_name_never_a_substring(self):
        approve(self.home, "prod-db")
        self.assertDenied(self.CMD)
        approve(self.home, "example.com")
        self.assertDenied(self.CMD)

    def test_every_prod_target_needs_its_own_approval(self):
        both = "psql -h prod-a -c 'DELETE FROM t' | psql -h prod-b -c 'DELETE FROM u'"
        approve(self.home, "prod-a")
        self.assertDenied(both)
        approve(self.home, "prod-b")
        self.assertAllowed(both)

    def test_an_approval_without_a_host_or_of_another_kind_covers_nothing(self):
        import ah_approvals  # noqa: PLC0415
        ah_approvals.grant("delete", {"project": str(self.home)}, "user", "test: project-wide delete", home=self.home)
        approve(self.home, self.TARGET, kind="kill")
        self.assertDenied(self.CMD)

    def test_an_expired_or_revoked_approval_denies(self):
        import ah_approvals  # noqa: PLC0415
        record = approve(self.home, self.TARGET)
        self.assertAllowed(self.CMD)
        ah_approvals.revoke(record["id"], "user", home=self.home)
        self.assertDenied(self.CMD)
        later = time.time() + 7200
        approve(self.home, self.TARGET, expires="1h")
        self.assertAllowed(self.CMD)
        self.assertEqual(self.verdict(bash(self.CMD), now=later), "deny")

    def test_keyword_and_flag_names_never_count_as_targets(self):
        for word in ("prod", "production", "delete", "psql", "--remote", "a b", "x*"):
            with self.subTest(word=word):
                self.assertTrue(pdg.valid_target(word))
        self.assertEqual(pdg.valid_target(self.TARGET), "")

    def test_the_refusal_names_the_approve_command_and_an_unreadable_store_denies(self):
        reason = pdg.evaluate(bash(self.CMD), home=str(self.home))[1]
        self.assertIn("ah approve delete --host prod-db.example.com", reason)
        with mock.patch("ah_approvals.records", side_effect=OSError("disk")):
            self.assertEqual(self.verdict(bash(self.CMD)), "deny")

    def test_the_grant_cli_was_removed(self):
        for verb in ("grant", "list"):
            r = subprocess.run([sys.executable, str(HOOKS / "prod_delete_guard.py"), verb, "--target", "x"],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 2)
            self.assertEqual(json.loads(r.stderr)["status"], "REMOVED")
            self.assertIn("ah approve delete", r.stderr)


if __name__ == "__main__":
    unittest.main()
