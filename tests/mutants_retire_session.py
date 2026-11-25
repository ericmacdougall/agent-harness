"""goodqa#17148 failing-first evidence for `ah task retire-session`: tests.test_retire_session must fail against each
controlled broken variant of ah.py or dropped_gate.py (each variant removes one control) and pass against the real files.

Run: python3 -B tests/mutants_retire_session.py   (copies harness/hooks into a temporary tree; changes nothing here).
Exit 0 only when the real files pass and every variant is killed."""
import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# name: (file, [(old, new), ...])
MUTANTS = {
    # R1 liveness: the registry, the process list and quiet time
    "an unreadable process list reads as nothing running": ("ah.py", [("    if r.returncode != 0 or not lines or len(lines) > RETIRE_PS_MAX:", "    if False:")]),
    "a session named in a command line is not running": ("ah.py", [("{pid for pid, _pp, _u, cmd in table if pid not in mine and named.search(cmd)}", "set()")]),
    "any path that holds the id counts as the session": ("ah.py", [('named = re.compile(r"(?<![\\w/.-])" + re.escape(session) + r"(?![\\w/.-])")', "named = re.compile(re.escape(session))")]),
    "the shell that typed the command counts as the session": ("ah.py", [("    while p and p not in mine:", "    while False:")]),
    "the registry is not read": ("ah.py", [("    live = _retire_registry_live(home, session)\n    table", "    live = []\n    table")]),
    "the registry host session id is ignored": ("ah.py", [('if session not in (entry.get("sessionId"), entry.get("hostSessionId")):', 'if session != entry.get("sessionId"):')]),
    "a dead pid in the registry counts as running": ("ah.py", [("        if not _retire_pid_alive(pid):\n            continue", "        if False:\n            continue")]),
    "a reused pid counts as the session": ("ah.py", [("        if started is not None and recorded is not None and abs(started - recorded) > RETIRE_START_SLACK_S:\n            continue", "        if False:\n            continue")]),
    "an incomparable start time reads as not running": ("ah.py", [("        if started is not None and recorded is not None and abs(started - recorded) > RETIRE_START_SLACK_S:", "        if recorded is None or started is None or abs(started - recorded) > RETIRE_START_SLACK_S:")]),
    "a missing registry is accepted": ("ah.py", [('    except OSError as e:\n        raise AhError("retire_unreadable", f"task.retire-session: the Claude Code session registry', '    except OSError as e:\n        return []\n        raise AhError("retire_unreadable", f"task.retire-session: the Claude Code session registry')]),
    "a corrupt registry entry is skipped": ("ah.py", [('        except (OSError, ValueError) as e:\n            raise AhError("retire_unreadable", f"task.retire-session: registry entry {name} cannot be read "', '        except (OSError, ValueError) as e:\n            continue\n            raise AhError("retire_unreadable", f"task.retire-session: registry entry {name} cannot be read "')]),
    "the registry side files are opened": ("ah.py", [('REGISTRY_FILE_RE = re.compile(r"^\\d{1,10}\\.json$")', 'REGISTRY_FILE_RE = re.compile(r"^\\d{1,10}\\..*$")')]),
    "a registry entry with no pid is accepted": ("ah.py", [("        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:", "        if False:")]),
    "the quiet time is 2 h": ("ah.py", [("RETIRE_QUIET_S = 6 * 3600", "RETIRE_QUIET_S = 2 * 3600")]),
    "the quiet time is 7 h": ("ah.py", [("RETIRE_QUIET_S = 6 * 3600", "RETIRE_QUIET_S = 7 * 3600")]),
    "recent transcripts are not checked": ("ah.py", [("    if now - tr[\"newest_at\"] < RETIRE_QUIET_S:", "    if False:")]),
    "recent owner activity is not checked": ("ah.py", [("        if now - max(last, transcript_mtime(home, session, r[\"agent_id\"])) < RETIRE_QUIET_S:", "        if False:")]),
    "a missing transcript is accepted": ("ah.py", [("    if not main_at:\n        raise AhError(\"retire_unreadable\"", "    if False:\n        raise AhError(\"retire_unreadable\"")]),
    "unread owner sources are accepted": ("ah.py", [(" or (data.get(\"read\") or {}).get(\"unread_total\"):", ":")]),
    "a live owner does not stop the retire": ("ah.py", [("raise AhError(\"retire_live_owner\"", "print(\"ignored\") or AhError(\"retire_live_owner\"")]),
    # R2 authority
    "no hook stamp is needed": ("ah.py", [("    if caller_identity.take_stamp(purpose, retire_stamp_parts(fields, mode), home=home, bound=True) is None:", "    if False:")]),
    "the stamp is taken before the checks": ("ah.py", [("    _retire_stamp(home, args)  # last: a refusal above leaves the stamp to die with main's call\n", ""), ("    session = args[\"session\"]\n    if caller_session and caller_session == session:", "    session = args[\"session\"]\n    _retire_stamp(home, args)\n    if caller_session and caller_session == session:")]),
    "the stamp hook mints for --dry-run": ("dropped_gate.py", [('"retire-session" \\\n                or getattr(args, "dry_run", False):', '"retire-session":')]),
    "a sub-agent may run it": ("dropped_gate.py", [("    if words[:2] == [\"task\", \"retire-session\"]:\n        return True", "    if False:\n        return True"),
                                                    ("    return \"retire-session\" in text or (\"dispose\" in text", "    return (\"dispose\" in text")]),
    "a loop of retires is not limited": ("ah.py", [("    if n < RETIRE_BURST_MAX:\n        return", "    if True:\n        return")]),
    "a dropped retire needs no ticket": ("ah.py", [('        if dropped and not TICKET_RE.match(args.get("ticket") or ""):', "        if False:")]),
    "a ticket that does not exist is accepted": ("ah.py", [("        if found is False:\n            raise AhError(\"evidence\", f\"task.retire-session: {args['ticket']} does not exist\", 3)", "        if False:\n            raise AhError(\"evidence\", f\"task.retire-session: {args['ticket']} does not exist\", 3)")]),
    "the source is not checked": ("ah.py", [("    if not res[\"ok\"]:\n        first = res[\"problems\"][0] if res[\"problems\"] else {\"code\": \"rejected\", \"message\": \"rejected\"}\n        raise AhError(\"provenance\", f\"source rejected ({first['code']}): {first['message']}\"[:300], 3)\n    rb = args.get(\"replaced_by\")", "    rb = args.get(\"replaced_by\")")]),
    "a missing source is accepted": ("ah.py", [("        need(\"session\", \"ended\", \"at\", \"source\")", "        need(\"session\", \"ended\", \"at\")")]),
    "replaced-by may name the same session": ("ah.py", [("(not SESSION_RE.match(rb) or rb == args[\"session\"])", "(not SESSION_RE.match(rb))")]),
    "replaced-by may be unknown": ("ah.py", [("        if not _wal_path(home, rb, \"main\").is_file():", "        if False:")]),
    "replaced-by may hold no work": ("ah.py", [("        if not (_retire_registry_live(home, rb) or now - main_transcript_at(home, rb, strict=True) < RETIRE_REPLACER_S):", "        if False:")]),
    "replaced-by and dropped may both be given": ("ah.py", [("if bool(rb) == bool(dropped) or dropped not in (None, True):", "if not (rb or dropped):")]),
    "a session may retire itself": ("ah.py", [("    if caller_session and caller_session == session:", "    if False:"),
                                              ("        if retiring and session and session == args.get(\"session\"):", "        if False:")]),
    "an owner may retire its own session": ("ah.py", [("        if actor_id() in pinned:", "        if False:")]),
    # R3 state and overrides
    "a live wait or resume is overridden": ("ah.py", [("        if held or ASK_ID_RE.match(str(r.get(\"wait_on\") or \"\")):", "        if False:")]),
    "a wait on an open user ask is overridden": ("ah.py", [("        if held or ASK_ID_RE.match(str(r.get(\"wait_on\") or \"\")):", "        if held:")]),
    "the owner list is taken before the lock": ("ah.py", [("        _retire_pin(home, args)  # under the store lock: the owner list is what the ledger says now", "        pass"),
                                                         ("    return dict(args, ended_utc=ended)", "    out = dict(args, ended_utc=ended)\n    _retire_pin(home, out)\n    return out")]),
    "the preview is not enforced": ("ah.py", [("    if args[\"expect\"] != ev[\"owners_sha\"]:", "    if False:")]),
    "--expect is optional": ("ah.py", [("        if not re.fullmatch(r\"[0-9a-f]{16}\", str(args.get(\"expect\") or \"\")):", "        if False:")]),
    "ah's own bookkeeping counts as session activity": ("ah.py", [("    return rec.get(\"event\") not in AH_WRITTEN_EVENTS and rec.get(\"by\") not in AH_WRITERS", "    return True")]),
    "ah's bookkeeping events are only partly excluded": ("ah.py", [("AH_WRITTEN_EVENTS = frozenset({\"disposition\", \"deadline\", \"deadline_done\", \"pending_stop\"})", "AH_WRITTEN_EVENTS = frozenset({\"disposition\"})")]),
    "a revoke resolver crash is a traceback": ("ah.py", [("    except Exception as e:  # a resolver crash is a rejection, never a traceback\n        raise AhError(\"provenance\", f\"source check failed ({type(e).__name__})\", 3)\n    if not res[\"ok\"]:\n        first = res[\"problems\"][0] if res[\"problems\"] else {\"code\": \"rejected\", \"message\": \"rejected\"}\n        raise AhError(\"provenance\", f\"source rejected ({first['code']}): {first['message']}\"[:300], 3)\n    rows = _ledger(home)", "    except ZeroDivisionError as e:\n        raise AhError(\"provenance\", f\"source check failed ({type(e).__name__})\", 3)\n    if not res[\"ok\"]:\n        first = res[\"problems\"][0] if res[\"problems\"] else {\"code\": \"rejected\", \"message\": \"rejected\"}\n        raise AhError(\"provenance\", f\"source rejected ({first['code']}): {first['message']}\"[:300], 3)\n    rows = _ledger(home)")]),
    "a session may revoke its own retire": ("ah.py", [("    if caller_session and caller_session == args[\"session\"]:", "    if False:"), ("        if retiring and session and session == args.get(\"session\"):", "        if False:")]),
    "an unreadable replacement transcript reads as inactive": ("ah.py", [("                except OSError as e:\n                    if strict:", "                except OSError as e:\n                    if False:")]),
    "unacked handoffs are not named": ("ah.py", [("\"unacked_handoffs\": sorted(handoffs)}", "\"unacked_handoffs\": []}")]),
    # R4 reopen
    "a retired owner is excused for ever": ("ah.py", [("        if seen > float(d.get(\"at\") or 0.0):", "        if False:")]),
    "session activity does not reopen": ("ah.py", [("        seen = max(parse_ts(r[\"last_activity\"]) or 0.0, sub_dirs.get(r[\"agent_id\"], 0.0), session_seen)", "        seen = max(parse_ts(r[\"last_activity\"]) or 0.0, sub_dirs.get(r[\"agent_id\"], 0.0))")]),
    "a reopened silent owner gets no attention": ("ah.py", [("            if str(r[\"state\"]).startswith(\"SILENT\") and not r[\"attention\"]:", "            if False:")]),
    "a subagent transcript write does not reopen": ("ah.py", [("        seen = max(parse_ts(r[\"last_activity\"]) or 0.0, sub_dirs.get(r[\"agent_id\"], 0.0), session_seen)", "        seen = max(parse_ts(r[\"last_activity\"]) or 0.0, session_seen)")]),
    "a retired owner keeps its attention flags": ("ah.py", [("        r[\"decision_required\"], r[\"attention\"], r[\"wait_on\"] = False, [], None", "        r[\"decision_required\"], r[\"wait_on\"] = False, None")]),
    "a retired owner still needs a decision": ("ah.py", [("        r[\"decision_required\"], r[\"attention\"], r[\"wait_on\"] = False, [], None", "        r[\"attention\"], r[\"wait_on\"] = [], None")]),
    # R5 evidence, ended, preview, undo
    "--ended may have no offset": ("ah.py", [("    if not RETIRE_ENDED_RE.match(text):", "    if False:")]),
    "--ended may be earlier than the last write": ("ah.py", [("    if at < newest_at - RETIRE_ENDED_SLACK_S:", "    if False:")]),
    "--ended is stored as typed": ("ah.py", [("    return dict(args, ended_utc=ended)", "    return dict(args, ended_utc=args[\"ended\"])")]),
    "a revoke is ignored": ("ah.py", [("    revoked = {(r.get(\"args\") or {}).get(\"decision\") for r in rows if r.get(\"op\") == \"task.retire_revoke\"}", "    revoked = set()")]),
    "a revoke needs no stamp": ("ah.py", [("    _retire_stamp(home, args, \"revoke\")\n    return args", "    return args")]),
    "a decision may be revoked twice": ("ah.py", [("    if any(r.get(\"op\") == \"task.retire_revoke\" and (r.get(\"args\") or {}).get(\"decision\") == args[\"decision\"] for r in rows):", "    if False:")]),
    # N1, N2 and the delta red-team
    "the ps start time is read in the host zone": ("ah.py", [('env=dict(os.environ, LC_ALL="C", LANG="C", TZ="UTC"))\n    except (OSError, subprocess.SubprocessError):\n        return None\n    return _retire_parse_start', 'env=dict(os.environ, LC_ALL="C", LANG="C"))\n    except (OSError, subprocess.SubprocessError):\n        return None\n    return _retire_parse_start')]),
    "an unparseable recorded start time reads as reused": ("ah.py", [("        if started is not None and recorded is not None and abs(started - recorded) > RETIRE_START_SLACK_S:", "        if started is not None and abs(started - (recorded or 0.0)) > RETIRE_START_SLACK_S:")]),
    "a matching start time reads as reused": ("ah.py", [("RETIRE_START_SLACK_S = 2 ", "RETIRE_START_SLACK_S = -1 ")]),
    "the stamp is not bound to main's call": ("ah.py", [("take_stamp(purpose, retire_stamp_parts(fields, mode), home=home, bound=True)", "take_stamp(purpose, retire_stamp_parts(fields, mode), home=home, bound=False)")]),
    "the hook mints an unbound stamp": ("dropped_gate.py", [('transcript=str(payload.get("transcript_path") or ""), require_bound=True)', 'transcript=str(payload.get("transcript_path") or ""), require_bound=False)')]),
    "the stamp is not bound to the arguments": ("ah.py", [("hashlib.sha256(canonical(body).encode()).hexdigest()[:24]]", "\"x\"]")]),
    "a revoke shares the retire purpose": ("ah.py", [('    purpose = "retire-revoke" if mode == "revoke" else "retire-session"\n    if caller_identity.take_stamp', '    purpose = "retire-session"\n    if caller_identity.take_stamp')]),
    "the feature ticket stands for the dropped work": ("ah.py", [('        if dropped and canonical_ref(args["ticket"]) == RETIRE_OWN_TICKET:', "        if False:")]),
    "a cite that names no session is not warned about": ("ah.py", [('        if args["session"][:8] not in args["source"] and', "        if False and")]),
    # shape
    "a retry is not a duplicate": ("ah.py", [("            if row.get(\"key\") == k0 and row.get(\"sha\") == sha0:", "            if False:")]),
    "a reused key with another body is not a conflict": ("ah.py", [("            if row.get(\"key\") == k0:\n                raise AhError(\"key_conflict\"", "            if False:\n                raise AhError(\"key_conflict\"")]),
    "the dry run writes the decision": ("ah.py", [("            if args.dry_run:\n                return retire_dry_run(home, args.session)\n", "")]),
    "owners get no per-owner disposition": ("ah.py", [("            for who in ((a.get(\"retire\") or {}).get(\"owners\") or []):", "            for who in []:")]),
    "the per-owner audit lines are not written": ("ah.py", [("            for who_id in args[\"retire\"][\"owners\"]:", "            for who_id in []:")]),
}


def run(tree):
    env = dict(os.environ, RETIRE_HOOKS=str(tree / "hooks"), PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-B", "-m", "unittest", "-f", "test_retire_session"], cwd=str(tree / "tests"),
                          capture_output=True, text=True, timeout=900, env=env)


def one(job):
    tmp, number, name, (fname, edits) = job
    tree = Path(tmp) / f"m{number}"
    shutil.copytree(ROOT / "harness" / "hooks", tree / "hooks", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (tree / "tests").mkdir()
    shutil.copy(ROOT / "tests" / "test_retire_session.py", tree / "tests")
    path = tree / "hooks" / fname
    text = path.read_text()
    for old, new in edits:
        if text.count(old) != 1:
            return name, f"BAD VARIANT: pattern found {text.count(old)} times: {old[:60]!r}"
        text = text.replace(old, new)
    path.write_text(text)
    out = run(tree)
    return name, "killed" if out.returncode != 0 else "SURVIVED"


def main():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base"
        shutil.copytree(ROOT / "harness" / "hooks", base / "hooks", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (base / "tests").mkdir()
        shutil.copy(ROOT / "tests" / "test_retire_session.py", base / "tests")
        real = run(base)
        print("real files:", "pass" if real.returncode == 0 else "FAIL\n" + real.stderr[-2000:])
        jobs = [(tmp, i, n, m) for i, (n, m) in enumerate(MUTANTS.items())]
        with ThreadPoolExecutor(4) as pool:
            results = list(pool.map(one, jobs))
    bad = [r for r in results if r[1] != "killed"]
    for name, verdict in results:
        print(f"{verdict:9} {name}" if not verdict.startswith("BAD") else f"{verdict} {name}")
    print(f"{len(results) - len(bad)}/{len(results)} variants killed")
    return 0 if real.returncode == 0 and not bad else 1


if __name__ == "__main__":
    sys.exit(main())
