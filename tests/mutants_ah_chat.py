"""goodqa#16396 failing-first evidence for `ah chat`: tests.test_ah_chat must fail against each controlled broken variant of
harness/hooks/ah_chat.py, or of ah.py where a variant names it (each variant removes one control), and pass against the
real files. ah chat is read only (PR 277 r6); the send variants left with send and are kept in the goodqa#16399 patch.

Run: python3 -B tests/mutants_ah_chat.py   (copies the hooks and the test into a temporary tree; changes nothing here).
Variants run four at a time and stop at the first failing test (a killed variant is a failure, so this is quick)."""
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILE = "ah_chat.py"

MUTANTS = {
    "redirects are followed": ("gq._OPENER.open(req, timeout=self.timeout)", "urllib.request.urlopen(req, timeout=self.timeout)"),
    "the credential backstop is off": ("    if gq.holds_credential(json.dumps(result, ensure_ascii=False)):", "    if False:"),
    "server error codes are printed raw": ('    shown = gq.shown_code(code) if isinstance(code, str) else None\n    return shown or "unrecognized_error"',
                                           "    return str(code)"),
    "not_found is a traceback": ('raise ChatError("not_found", "GoodQA says not_found', 'raise KeyError("not_found", "GoodQA says not_found'),
    "the membership id is used as the user id": ('uid = row.get("userId") or user.get("userId") or (user.get("id") if user is not row else None)',
                                                 'uid = user.get("id") or user.get("userId")'),
    "a paged member list is trusted for a name": ('    if isinstance(data, dict) and (data.get("nextCursor") or data.get("hasMore")):', "    if False:"),
    "a read is not audited": ("    _audit(home, {\"op\": \"chat.read\"", "    None and _audit(home, {\"op\": \"chat.read\""),
    "a missing dm token falls back to the user token": (
        "            self._token = getattr(gq, SOURCES[source][0])()",
        "            try:\n                self._token = getattr(gq, SOURCES[source][0])()\n            except gq.Refused:\n"
        "                self._token = gq.read_token()"),
    "a private read uses the user token": ('    client = Client(base, source="dm")\n    if conversation:\n        _need(client, "get_direct_conversation_messages")',
                                           '    client = Client(base, source="user")\n    if conversation:\n        _need(client, "get_direct_conversation_messages")'),
    "an absent conversation tool is not an error": ("    if tool not in _offered(client):", "    if False:"),
    # PR 277 r4 source-to-sink sweep, re-run for the read-only build (r6): one variant per check
    "uuids are prefix-matched": ("UUID_RE.fullmatch(value) is not None", 're.match(UUID_RE.pattern + "$", value) is not None'),
    "names are prefix-matched": ("NAME_RE.fullmatch(who)", 're.match(NAME_RE.pattern + "$", who)'),
    "metadata values are prefix-matched": ("META_VALUE.fullmatch(str(v))", 're.match("(?:" + META_VALUE.pattern + ")$", str(v))'),
    "the token-file screen is off for ids and error text": ("(gq.holds_credential(value) or any(", "(False or any("),
    "the secret-shape screen is off for ids and error text": ("or any(p.search(value) for p in gq.SECRET_SHAPES))", "or False)"),
    "target ids are not screened": ("        if _credential_like(value):\n            raise ChatError(\"secret_refused\", \"an id",
                                    "        if False:\n            raise ChatError(\"secret_refused\", \"an id"),
    "error text is not screened": ("        if _credential_like(message):  # the one choke point", "        if False:  # the one choke point"),
    # PR 277 r6: `ah chat send` is deferred to goodqa#16399; ah.py refuses it before anything is parsed, imported or read
    "send reaches the parser": ("ah.py", '        if _first_word(given[given.index("chat") + 1:]) == "send":', "        if False:"),
    "the send refusal exits zero": ("ah.py", '    sys.stdout.write("\\n")\n    return 2\n\n\ndef _parse_chat',
                                    '    sys.stdout.write("\\n")\n    return 0\n\n\ndef _parse_chat'),
    "the send refusal names no follow-up": ("ah.py", "deferred to goodqa#16399, which", "deferred to a follow-up, which"),
    "send imports the chat module first": ("ah.py", '== "send":  # goodqa#16396', '== "send" and __import__("ah_chat"):  # goodqa#16396'),
    # PR 277 r7 F1: a chat parse failure is one fixed refusal on stdout; nothing reaches stderr
    "chat parse errors reach stderr": ("ah.py", "        with contextlib.redirect_stderr(io.StringIO()):  # the usage",
                                       "        if True:  # the usage"),
    "chat arguments use the plain parser": ("ah.py", '    if _first_word(given) == "chat":', "    if False:"),
    "a global option before chat skips the chat path": ("ah.py", 'return next((t for t in tokens if not t.startswith("-")), None)',
                                                        "return tokens[0] if tokens else None"),
    "help counts as a refusal": ("ah.py", "        if stop.code in (0, None):", "        if False:"),
    # PR 277 r7 F2: every read output is an allow-list of fields
    "issue and personal file rows are passed whole": (
        "    listed = [_file_meta(f) for f in rows[:200]]  # the same",
        '    listed = [_file_meta(f) if surface == "chat" else f for f in rows[:200]]  # the same'),
    "a file key outside the list is passed": ("    return _pick(row, FILE_KEYS)", "    return dict(row) if isinstance(row, dict) else {}"),
    "link-shaped values pass under an allowed key": ("        if key not in TEXT_KEYS and LINKISH.search(value):", "        if False:"),
    "a relative signed path is not link-shaped": (r"|blob:)|^\s*/\S*[?#]", r"|blob:)"),
    "message text is treated as a link": ("        if key not in TEXT_KEYS and LINKISH.search(value):",
                                          "        if LINKISH.search(value):"),
    "nested values pass under a scalar key": ("    return _DROP  # a dict, a list, a float", "    return value  # a dict, a list, a float"),
    "message rows are passed whole": ("else [_message(m) for m in rows]", "else [m for m in rows]"),
    "the author object is passed whole": ('kept["author"] = _pick(row["author"], AUTHOR_KEYS)', 'kept["author"] = row["author"]'),
    "an author label is passed whole": ('            kept["authorLabel"] = _pick(row["authorLabel"], AUTHOR_LABEL_KEYS)\n        if isinstance(row.get("attachments")',
                                        '            kept["authorLabel"] = row["authorLabel"]\n        if isinstance(row.get("attachments")'),
    "message attachments are passed whole": ('[_file_meta(a) for a in row["attachments"][:50]]', 'row["attachments"][:50]'),
    "conversation rows are passed whole": ("    listed = [_conversation(r) for r in rows]", "    listed = list(rows)"),
    "participants keep every field": ("[_pick(p, PARTICIPANT_KEYS) for p in", "[p for p in"),
    # PR 277 r8 (the findings of the 9d0706a review): one mutant per new control
    "M2: --with skips the tools-offered check": ('        _need(client, "get_direct_conversation_messages")\n        peer, name = _user(client, org, with_)',
                                                 '        peer, name = _user(client, org, with_)'),
    "M3: a base other than goodqa.app is accepted": ('    raise ChatError("refused", "ah chat sends a token only to', '    return base\n    raise ChatError("refused", "ah chat sends a token only to'),
    "M3: browser-defaults.json base is trusted": ("self.base = _pinned_base(base)  # before", "self.base = _pinned_base(base or gq.load_defaults().get('base'))  # before"),
    "M3: loopback needs no test switch": ('        if loopback and os.environ.get("GQ_BROWSER_TEST_LOOPBACK") == "1":', "        if loopback:"),
    "M3: any host counts as loopback": ('loopback = (u.hostname in ("127.0.0.1", "localhost", "::1") and u.scheme', "loopback = (True and u.scheme"),
    "M3: test mode takes the real token path": ("            if real is None or os.path.realpath(os.path.dirname(getattr(gq, SOURCES[source][2])())) == real:", "            if False:"),
    "M3: the token is read before the base is checked": ("self.base = _pinned_base(base)  # before", "self.base = _pinned_base(base) if getattr(gq, SOURCES[source][0])() else None  # before"),
    "m3: probe defaults to the user token": ("ah.py", 'c.add_argument("--token", choices=("user", "dm"), default="dm",', 'c.add_argument("--token", choices=("user", "dm"), default="user",'),
    "M4: text is not redacted": ("                raw = redact.redact(scanned) + raw[MAX_SCAN:]", "                raw = scanned + raw[MAX_SCAN:]"),
    "M4: the redacted flag is not set": ('                    kept["redacted"] = True', "                    pass"),
    "m7: names are not bounded": ("        cap = MAX_TEXT_FIELD if key in TEXT_KEYS else MAX_NAME_FIELD", "        cap = MAX_TEXT_FIELD"),
    "m7: the notice omits the names": ("previews, participant and author names and file names are untrusted", "file names are untrusted"),
    "paging: conversations drop the cursor argument": ('        arguments["cursor"] = cursor', "        pass"),
    "paging: conversations drop the page envelope": ('**_paging(data, ("hasMore", "has_more", "bool"), ("nextCursor", "next_cursor", "cursor"))', "**{}"),
    "paging: history drops found_oldest and head_seq": ('paging = _paging(data, ("foundOldest", "found_oldest", "bool"), ("foundNewest", "found_newest", "bool"),\n                         ("headSeq", "head_seq", "int"))', "paging = {}"),
    "paging: files drop the offset argument": ('            arguments["offset"] = offset', "            pass"),
    "paging: an offset is accepted off the chat surface": ('    if offset is not None and (surface != "chat" or not isinstance(offset, int)', '    if offset is not None and (False or not isinstance(offset, int)'),
    "cursor: a malformed cursor is sent": ("    if value is not None and not (isinstance(value, str) and CURSOR_RE.fullmatch(value)):", "    if False:"),
    "cursor: a cursor holding a token piece is sent": ("    _refuse_credential_ids(value)\n    return value", "    return value"),
    "cursor: the cap is 512": ("{1,500}", "{1,512}"),
    "last message: the full body is kept": ('"attachmentCount", "preview")', '"attachmentCount", "preview", "body")'),
    "last message: the author label is passed whole": ('    kept = _pick(row, LAST_MESSAGE_KEYS)\n    if isinstance(row, dict) and isinstance(row.get("authorLabel"), dict):\n        kept["authorLabel"] = _pick(row["authorLabel"], AUTHOR_LABEL_KEYS)', '    kept = _pick(row, LAST_MESSAGE_KEYS)\n    if isinstance(row, dict) and isinstance(row.get("authorLabel"), dict):\n        kept["authorLabel"] = row["authorLabel"]'),
    "last message: passed whole": ('kept["lastMessage"] = _last_message(row["lastMessage"])', 'kept["lastMessage"] = row["lastMessage"]'),
    "participants keep the avatar": ('PARTICIPANT_KEYS = ("id", "name")', 'PARTICIPANT_KEYS = ("id", "name", "avatarUrl")'),
    "m4: --no-text drops seq": ('META_KEYS = re.compile(r"id|seq|', 'META_KEYS = re.compile(r"id|'),
    "m6: --with does not say it cannot page": ('        paging["paging_note"] = (', '        paging["x"] = ('),
    "m9: a bare tool result is not understood": ('inner = data.get("data") if isinstance(data, dict) and isinstance(data.get("data"), dict) else data', 'inner = data.get("data")'),
    "m1: a token file is opened following symlinks": ("gq_browser.py", '        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))', "        fd = os.open(path, os.O_RDONLY)"),
    "m1: a token file is read without a bound": ("gq_browser.py", "chunk = os.read(fd, 4097 - len(raw))", "chunk = os.read(fd, 1 << 26)"),
}


def run(tree):
    return subprocess.run([sys.executable, "-I", "tests/test_ah_chat.py", "-f"], cwd=str(tree), capture_output=True,
                          text=True, timeout=900)


def one(job):
    tmp, number, name, change = job
    tree = Path(tmp) / ("t%d" % number)
    (tree / "tests").mkdir(parents=True)
    (tree / "tests" / "__init__.py").write_text("")
    shutil.copytree(ROOT / "harness" / "hooks", tree / "harness" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(ROOT / "tests" / "test_ah_chat.py", tree / "tests" / "test_ah_chat.py")
    if change:
        name_of_file, old, new = change if len(change) == 3 else (FILE, *change)
        path = tree / "harness" / "hooks" / name_of_file
        text = path.read_text()
        if text.count(old) != 1:
            return name, "BROKEN MUTANT: pattern found %d times" % text.count(old), True
        path.write_text(text.replace(old, new))
    failed = run(tree).returncode != 0
    shutil.rmtree(tree, ignore_errors=True)  # the disk is tight: one copy of the hooks at a time per worker
    return name, "tests FAIL (killed)" if failed else "tests PASS", failed != (change is not None)


def main():
    survived = []
    with tempfile.TemporaryDirectory() as tmp:
        jobs = [(tmp, n, name, change) for n, (name, change) in enumerate([("(the real file)", None)] + list(MUTANTS.items()))]
        with ThreadPoolExecutor(max_workers=4) as pool:
            for name, verdict, bad in pool.map(one, jobs):
                print("%-52s %s" % (name, verdict), flush=True)
                if bad:
                    survived.append(name)
    print("survivors: %s" % (survived or "none"))
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
