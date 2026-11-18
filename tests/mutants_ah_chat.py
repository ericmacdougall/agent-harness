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
    "an unlisted base is accepted": ("self.base = gq.check_base(base or self.defaults.get(\"base\") or first, self.defaults)",
                                     "self.base = (base or first).rstrip('/')"),
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
    "an unreadable token file leaves its token unscreened": ("        _screenable()\n", "        pass\n"),
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
    "an author label is passed whole": ('kept["authorLabel"] = _pick(row["authorLabel"], AUTHOR_LABEL_KEYS)',
                                        'kept["authorLabel"] = row["authorLabel"]'),
    "message attachments are passed whole": ('[_file_meta(a) for a in row["attachments"][:50]]', 'row["attachments"][:50]'),
    "conversation rows are passed whole": ("    listed = [_conversation(r) for r in rows]", "    listed = list(rows)"),
    "participants keep every field": ("[_pick(p, PARTICIPANT_KEYS) for p in", "[p for p in"),
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
