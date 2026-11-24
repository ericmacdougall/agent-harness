"""goodqa#16399 failing-first evidence for `ah chat send`: tests/test_ah_chat_send.py must fail against each controlled broken
variant (each removes one control) and pass against the real files.

Run: python3 -B tests/mutants_ah_chat_send.py   (copies the hooks and the tests into a temporary tree; changes nothing here).
Variants run three at a time and stop at the first failing test."""
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILE = "ah_chat_send.py"

MUTANTS = {
    "no main-agent stamp is needed": ("    if stamp is None:\n        raise ChatError(\"main_only\", \"only the main agent sends",
                                      "    if False:\n        raise ChatError(\"main_only\", \"only the main agent sends"),
    "the allow-list is not checked": ('    if peer not in allowed:\n        raise ChatError("not_allowed"',
                                      '    if False:\n        raise ChatError("not_allowed"'),
    "the send does not check the member name": ("    if not any(_names(member, name) for name in names):", "    if False:"),
    "a failed member lookup is ignored": ("        member = _member_name(base, org, peer)\n    except Exception:",
                                          "        member = \" \".join(names)\n    except Exception:"),
    "the words are found under HOME": ('provenance.resolve(source, {"home": os.path.join(str(home), ".claude")})',
                                       "provenance.resolve(source, {})"),
    "an unproved entry is reported as not listed": ('        raise ChatError("entry_unproved", "that person\'s allow-list line',
                                                    '        raise ChatError("not_allowed", "that person\'s allow-list line'),
    "the hint omits --org and --name": ("--with USER_ID --org ORG --name \"\n              \"NAME --source", "--with USER_ID --source"),
    "a damaged allow-list line is skipped": ('            raise _allow_damaged("holds a line that is not `<user id> wal:<session>/<row id>`")',
                                             "            continue"),
    "an entry needs no decision row": ("    names = []\n    for session, wal_id in refs:",
                                       "    return [\"Pat\", \"Sam\"]\n    names = []\n    for session, wal_id in refs:"),
    "the decision row's person is not checked": (' and row.get("peer") == peer', ""),
    "the decision row's org is not checked": ('\n                    and row.get("org") == org and', "\n                    and"),
    "the decision row's source is not rechecked": ('                _users_words(row["source"], row["name"], home)', "                pass"),
    "the words need not name the person": ("    if not _names(excerpt, name):", "    if False:"),
    "the member name is not checked": ("    if not _names(member, name):", "    if False:"),
    "a name inside a word counts": ('r"(?<!\\w)" + re.escape(name.casefold()) + r"(?!\\w)"', "re.escape(name.casefold())"),
    "the allow stamp ignores the source": ('name.casefold(), hashlib.sha256(source.encode("utf-8")).hexdigest()]', "name.casefold()]"),
    "the allow stamp ignores the person": ('    return ["allow", with_.lower(), org.lower(),', '    return ["allow", org.lower(),'),
    "any source adds a recipient": ("    kind = _users_words(source, name, home)\n", "    kind = \"user\"\n"),
    "no WAL decision for an added recipient": ("            ah._wal_append(home, wal, record)", "            pass"),
    "the decision claims the user confirmed it": ('"source_kind": kind,', '"source_kind": kind, "confirmed_by_user": True,'),
    "the allow-list lives under a second root": ('    return os.path.join(str(home), ".config"', '    return os.path.join(chat.gq.home(), ".config"'),
    "an allow-list others can write is used": ("info.st_uid != os.getuid() or info.st_mode & 0o022", "info.st_uid != os.getuid()"),
    "a symlinked allow-list is followed": ('        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))',
                                           '        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))'),
    "adding a recipient needs no stamp": ("    if stamp is None:\n        raise ChatError(\"main_only\", \"only the main agent adds",
                                          "    if False:\n        raise ChatError(\"main_only\", \"only the main agent adds"),
    "a source not of the user's words adds a recipient": (
        '    if (not result.get("ok") or result.get("kind") != "user" or result.get("origin") != "user"\n'
        '            or provenance.weak_problem(result)',
        '    if (not result.get("ok")\n            or False'),
    "a name is added as a recipient": ('    if not chat._is_uuid(with_):\n        raise ChatError("bad_request", "--with is the person\'s user id (a UUID), never a name", fixed=True)',
                                       '    if False:\n        raise ChatError("bad_request", "--with is the person\'s user id (a UUID), never a name", fixed=True)'),
    "the stamp ignores the text's content": ('    return ["send", target, org.lower(), os.path.realpath(text_file), digest, (approval or "").lower()]',
                                             '    return ["send", target, org.lower(), os.path.realpath(text_file), (approval or "").lower()]'),
    "the stamp ignores the approval id": ('    return ["send", target, org.lower(), os.path.realpath(text_file), digest, (approval or "").lower()]',
                                          '    return ["send", target, org.lower(), os.path.realpath(text_file), digest]'),
    "the stamp is matched against a second read": ("    stamp = caller_identity.take_stamp(STAMP, _parts(conversation, with_, org, text_file, digest, approval), home=home,",
                                                   "    stamp = caller_identity.take_stamp(STAMP, stamp_parts(conversation, with_, org, text_file, approval) or [\"refused\"], home=home,"),
    "the hook stamps a sub-agent": ("mission_gate.py", "    import caller_identity  # noqa: PLC0415\n    if not caller_identity.is_main(payload):\n        return {}\n    session = str(payload.get(\"session_id\") or \"\")\n",
                                    "    import caller_identity  # noqa: PLC0415\n    if False:\n        return {}\n    session = str(payload.get(\"session_id\") or \"\")\n"),
    "the hook stamps a dry run": ("mission_gate.py", '        if getattr(args, "dry_run", True):\n            continue', "        pass"),
    "the stamp is not bound to the call": ("                                       bound=True)", "                                       bound=False)"),
    "the prefix is dropped": ("    return PREFIX + text", "    return text"),
    "the ledger keys on the raw file bytes": ("    peer, body_sha = _identity(peer, body)", "    peer, body_sha = peer, digest"),
    "the ledger keeps the id's letter case": ("    return (peer.lower() if isinstance(peer, str) else peer), hashlib",
                                              "    return peer, hashlib"),
    "an inner CRLF is sent as is": ('        text = raw.decode("utf-8").replace("\\r\\n", "\\n").rstrip("\\n")',
                                    '        text = raw.decode("utf-8").rstrip("\\r\\n")'),
    "a name is accepted for --with": ("    if with_ is not None and not chat._is_uuid(with_):", "    if False:"),
    "the defaults-file org is used": ("    if not chat._is_uuid(org):\n        raise ChatError(\"bad_request\", \"send needs --org",
                                      "    if org is not None and not chat._is_uuid(org):\n        raise ChatError(\"bad_request\", \"send needs --org"),
    "a bot persona is a person": ("                    or any(p.get(\"isBot\") for p in people)):", "                    or False):"),
    "three participants are accepted": ("            if (len(ids) != 2 or len(others) != 1", "            if (False or len(others) != 1"),
    "the caller need not be in the DM": ("            if (len(ids) != 2 or len(others) != 1", "            if (len(ids) != 2 or len(others) > 2"),
    "conversation ids compare by case": ('            if not isinstance(row, dict) or not isinstance(row.get("id"), str) or row["id"].lower() != want:',
                                         '            if not isinstance(row, dict) or not isinstance(row.get("id"), str) or row["id"] != conversation:'),
    "a non-ChatError escapes the outcome": ("        except Exception as error:  # noqa: BLE001 - PR 337 F2", "        except ZeroDivisionError as error:  # PR 337 F2"),
    "no WAL warning": ('        result["wal_warning"] = "the WAL row could not be written; the chat-send ledger still records this attempt"',
                       "        pass"),
    "no ledger lock": ("    with _Lock(path):\n        rows = _rows(path)", "    if True:\n        rows = _rows(path)"),
    "the pending row is not in the ledger at request time": (
        "            _append(path, {\"id\": attempt, \"kind\": \"pending\"",
        "            _append(str(path) + \".elsewhere\", {\"id\": attempt, \"kind\": \"pending\""),
    "a pending row without its time is accepted": ("        return (isinstance(row.get(\"peer\"), str) and isinstance(row.get(\"sha\"), str) and isinstance(at, (int, float))\n                and not isinstance(at, bool))",
                                                   "        return isinstance(row.get(\"peer\"), str) and isinstance(row.get(\"sha\"), str)"),
    "an unknown row kind is accepted": ("        return isinstance(row.get(\"ref\"), str) and isinstance(row.get(\"status\"), str)\n    return False",
                                        "        return isinstance(row.get(\"ref\"), str) and isinstance(row.get(\"status\"), str)\n    return True"),
    "format characters are sent": ('REFUSED_CATEGORIES = frozenset(("Cc", "Cf", "Zl", "Zp", "Cs", "Co"))',
                                   'REFUSED_CATEGORIES = frozenset(("Cc", "Zl", "Zp", "Cs", "Co"))'),
    "no overall hourly cap": ("    if len([a for a in attempts if now - a[\"at\"] < RATE_WINDOW]) >= GLOBAL_LIMIT:", "    if False:"),
    "the refusal does not name the same-call trap": ("earlier, separate call", "earlier call"),
    "the length cap is 601": ("MAX_CHARS = 600", "MAX_CHARS = 601"),
    "a secret shape is sent": ("    if chat._secret_spans(text):\n", "    if False:\n"),
    "a token piece is sent": ("        if chat._holds_token(body):", "        if False:"),
    "the same text may go again": ('    if same and any(a["status"] not in FREE_STATUSES for a in same):', "    if False:"),
    "an uncertain outcome frees the text": ('    if same and any(a["status"] not in FREE_STATUSES for a in same):',
                                            '    if same and any(a["status"] == "sent" for a in same):'),
    "approval_required blocks the text forever": ('    if same and any(a["status"] not in FREE_STATUSES for a in same):', "    if same:"),
    "any server refusal frees the text": ('    status = "uncertain"\n    if error.code in', '    status = "refused"\n    if error.code in'),
    "an approval refusal holds the text back": ('              "approval_mismatch": "approval_refused"}', '              "approval_mismatch": "uncertain"}'),
    "the approval id is not sent": ('            arguments["approvalId"] = approval', "            pass"),
    "the approval id is not printed": ('        result["approval_id"] = approval_id', "        pass"),
    "a malformed approval id is accepted": ("    if approval is not None and not chat._is_uuid(approval):", "    if False:"),
    "no rate limit": ("    if len([a for a in mine if now - a[\"at\"] < RATE_WINDOW]) >= RATE_LIMIT:", "    if False:"),
    "an unfinished ledger record is ignored": ("    if data and not data.endswith(b\"\\n\"):", "    if False:"),
    "a malformed ledger record is skipped": ("            raise ChatError(\"ledger_damaged\", \"the chat-send ledger holds a malformed record",
                                             "            continue\n            raise ChatError(\"ledger_damaged\", \"the chat-send ledger holds a malformed record"),
    "the DM token sends": ('        client = chat.Client(base, source="user")', '        client = chat.Client(base, source="dm")'),
    "a group DM is accepted": ('            if row.get("kind") != "dm":', "            if False:"),
    "a symlinked text file is followed": ('        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))',
                                          '        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))'),
    "a relative text path is accepted": ("    if not isinstance(path, str) or not os.path.isabs(path) or \"\\x00\" in path:",
                                         "    if not isinstance(path, str) or \"\\x00\" in path:"),
    "control characters are sent": ("    if refused_char(text):", "    if False:"),
    "no WAL row": ("            wal_id = _wal(home, session, dict(record, status=status, message=message_id, attempt=attempt, **why))",
                   "            wal_id = None"),
    "the WAL row holds the text": ('        record = {"peer": peer, "org": org, "conversation": conversation, "text_sha256": body_sha, "chars": len(body)}',
                                   '        record = {"peer": peer, "org": org, "conversation": conversation, "text_sha256": body_sha, "chars": len(body), "text": body}'),
    "the base is not pinned": ("    chat._pinned_base(base)  # first: a refused base reads nothing", "    pass"),
    "a dry run reads the token": ("    if dry_run:  # no token", "    chat.Client(base, source=\"user\")\n    if dry_run:  # no token"),
    # goodqa#16399, the uncertain live send: why a send was not sent is recorded, and a definite refusal frees the text
    "not_found loses its server code": ("ah_chat.py", "                missing.server_code = code  #", "                pass  #"),
    "an HTTP error loses its code": ("ah_chat.py", "            refused.server_code = code if isinstance(code, str) else None\n",
                                     "            refused.server_code = None\n"),
    "an HTTP error loses its status": ("ah_chat.py", "            refused.http_status = error.code if", "            refused.http_status = None if"),
    "the outcome row records no reason": ('                        "at": time.time()}, **why)', '                        "at": time.time()})'),
    "the WAL row records no reason": ("message=message_id, attempt=attempt, **why))", "message=message_id, attempt=attempt))"),
    "the result prints no reason": ("    result.update((k, v) for k, v in why.items() if v is not None)", "    pass"),
    "a refused code stays uncertain": ('        status = "refused"\n    return status, error.code, code, http',
                                       '        status = "uncertain"\n    return status, error.code, code, http'),
    "refused does not free the text": ('FREE_STATUSES = APPROVAL_STATUSES | {"refused"}', "FREE_STATUSES = APPROVAL_STATUSES"),
    "every server code counts as refused": ('elif error.code == "not_found" and code in REFUSED_CODES:',
                                            'elif error.code in ("tool_error", "not_found") and code is not None:'),
    "an HTTP-level code counts as refused": ('elif error.code == "not_found" and code in REFUSED_CODES:',
                                             'elif code in REFUSED_CODES:'),
    "a tool error counts as refused": ('elif error.code == "not_found" and code in REFUSED_CODES:',
                                       'elif error.code in ("tool_error", "not_found") and code in REFUSED_CODES | {"forbidden"}:'),
    "the table grows without a citation": ('REFUSED_CODES = frozenset(REFUSED_SOURCES)',
                                           'REFUSED_CODES = frozenset(REFUSED_SOURCES) | {"forbidden"}'),
    "the server commit is not pinned": ('REFUSAL_CHECKED_AT = "a70289c740da"', 'REFUSAL_CHECKED_AT = "main"'),
    "a non-approval refusal prints a permit": ('if status in APPROVAL_STATUSES else None', 'if status in FREE_STATUSES else None'),
    "an approval refusal prints no permit": ('if status in APPROVAL_STATUSES else None', 'if False else None'),
    "a code is recorded as given": ("    if not (isinstance(code, str) and SERVER_CODE_RE.fullmatch(code)) or chat._holds_token(code):",
                                    "    if not isinstance(code, str):"),
    "a token-piece code is recorded": ("SERVER_CODE_RE.fullmatch(code)) or chat._holds_token(code):", "SERVER_CODE_RE.fullmatch(code)):"),
    "no_message_id is not recorded": ('            failure = None if message_id else "no_message_id"', "            failure = None"),
    "the exception type is not recorded": ('"exception:" + (name if EXCEPTION_RE.fullmatch(name) else "unnamed")', '"exception"'),
    "the goodqa#17013 hint is missing": ('        if code == "not_found":\n            result["next"] +=',
                                         '        if False:\n            result["next"] +='),
}


def run(tree):
    return subprocess.run([sys.executable, "-I", "tests/test_ah_chat_send.py", "-f"], cwd=str(tree), capture_output=True,
                          text=True, timeout=900)


def one(job):
    tmp, number, name, change = job
    tree = Path(tmp) / ("t%d" % number)
    (tree / "tests").mkdir(parents=True)
    shutil.copytree(ROOT / "harness" / "hooks", tree / "harness" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
    for test in ("test_ah_chat.py", "test_ah_chat_send.py"):
        shutil.copy(ROOT / "tests" / test, tree / "tests" / test)
    if change:
        name_of_file, old, new = change if len(change) == 3 else (FILE, *change)
        path = tree / "harness" / "hooks" / name_of_file
        text = path.read_text()
        if text.count(old) != 1:
            return name, "BROKEN MUTANT: pattern found %d times" % text.count(old), True
        path.write_text(text.replace(old, new))
    proc = run(tree)
    failed = proc.returncode != 0
    shutil.rmtree(tree, ignore_errors=True)
    if failed and change is None:
        tail = [line for line in proc.stderr.splitlines() if line.startswith(("FAIL:", "ERROR:", "Ran ", "FAILED"))]
        return name, "tests FAIL (RUN INVALID): %s" % " | ".join(tail[:6]), True
    return name, "tests FAIL (killed)" if failed else "tests PASS", failed != (change is not None)


def main():
    survived = []
    with tempfile.TemporaryDirectory() as tmp:
        jobs = [(tmp, n, name, change) for n, (name, change) in enumerate([("(the real file)", None)] + list(MUTANTS.items()))]
        with ThreadPoolExecutor(max_workers=3) as pool:
            for name, verdict, bad in pool.map(one, jobs):
                print("%-48s %s" % (name, verdict), flush=True)
                if bad:
                    survived.append(name)
    print("survivors: %s" % (survived or "none"))
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
