"""goodqa#16396 failing-first evidence for `ah chat`: tests.test_ah_chat must fail against each controlled broken variant of
harness/hooks/ah_chat.py (each variant removes one control) and pass against the real file.

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
    "a client id is not required": ("    if not client_msg_id:\n        raise ChatError(\"client_msg_id_required\"",
                                    "    if False:\n        raise ChatError(\"client_msg_id_required\""),
    "secret shapes are not refused": ("        gq._refuse_secret_text(body, client._token)", "        pass"),
    "a body holding the other token is sent": ("    if gq.holds_credential(body):", "    if False:"),
    "the ledger keeps the message text": ("body_len=len(body),", "body_len=len(body), text=body,"),
    "a repeated id sends again": ("        if sent:  # no second post", "        if False:  # no second post"),
    "an unknown outcome is resent blindly": ("and not conversation and not confirm_not_delivered:", "and False:"),
    "a different body under one id is accepted": ("        if rows and rows[0].get(\"request\") != request_sha:", "        if False:"),
    "not_found is a traceback": ('            if code == "not_found":\n                raise ChatError("not_found"', '            if code == "not_found":\n                raise KeyError("not_found"'),
    "the token file can be the body": ("def _read_body(path):", "def _read_body(path):\n    return open(path).read()  # mutant"),
    "any tool error counts as not delivered": ('(error.code == "tool_error" and getattr(error, "server_code", None) in PRE_EFFECT)',
                                               'error.code == "tool_error"'),
    "an rpc error counts as not delivered": ('definite = error.code == "not_found" or', 'definite = error.code in ("not_found", "rpc_error") or'),
    "a 5xx counts as not delivered": ('status.group(1)[0] == "4"', 'status.group(1)[0] in "45"'),
    "approval_required counts as not delivered": ('"forbidden", "unauthorized",', '"forbidden", "unauthorized", "approval_required",'),
    "dot files can be the body": ("    real = _plain_path(path) if isinstance(path, str) else None", "    real = path if isinstance(path, str) else None"),
    "a symlinked directory is not resolved": ("    real = os.path.join(os.path.realpath(parent), name)", "    real = os.path.join(parent, name)"),
    "a hard link is accepted": ("        if st.st_nlink != 1:", "        if False:"),
    "a file swapped after the check is accepted": ("(again.st_dev, again.st_ino) != (st.st_dev, st.st_ino)", "False"),
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
    "a send uses the dm token": ('client = Client(base, source="user")  # a send is a write', 'client = Client(base, source="dm")  # a send is a write'),
    "a private read uses the user token": ('    client = Client(base, source="dm")\n    if conversation:\n        _need(client, "get_direct_conversation_messages")',
                                           '    client = Client(base, source="user")\n    if conversation:\n        _need(client, "get_direct_conversation_messages")'),
    "a file's link is passed on": ("    return {k: _scrub(v) for k, v in row.items() if k in FILE_KEYS", "    return {k: _scrub(v) for k, v in row.items() if k"),
    "a server message id is not checked before it is stored": (
        'mid = _usable_message_id(message.get("id") if isinstance(message, dict) else None)',
        'mid = message.get("id") if isinstance(message, dict) else None'),
    # PR 277 r4 source-to-sink sweep: one variant per new check
    "a newline-terminated client id passes (match, not fullmatch)": ("not CLIENT_ID_RE.fullmatch(client_msg_id)",
                                                                      'not re.match(CLIENT_ID_RE.pattern + "$", client_msg_id)'),
    "uuids are prefix-matched": ("UUID_RE.fullmatch(value) is not None", 're.match(UUID_RE.pattern + "$", value) is not None'),
    "names are prefix-matched": ("NAME_RE.fullmatch(who)", 're.match(NAME_RE.pattern + "$", who)'),
    "metadata values are prefix-matched": ("META_VALUE.fullmatch(str(v))", 're.match("(?:" + META_VALUE.pattern + ")$", str(v))'),
    "the send file is prefiltered on raw key bytes": ("                if len(line) > 4096:",
                                                      "                if len(line) > 4096 or key.encode() not in line:"),
    "the token-file screen is off for ids and error text": ("(gq.holds_credential(value) or any(", "(False or any("),
    "the secret-shape screen is off for ids and error text": ("or any(p.search(value) for p in gq.SECRET_SHAPES))", "or False)"),
    "the client id is not screened": ("    if _credential_like(client_msg_id):", "    if False:"),
    "target ids are not screened": ("        if _credential_like(value):\n            raise ChatError(\"secret_refused\", \"an id",
                                    "        if False:\n            raise ChatError(\"secret_refused\", \"an id"),
    "a replayed message id is not checked again": ('_usable_message_id(sent[-1].get("message_id"))', 'sent[-1].get("message_id")'),
    "error text is not screened": ("        if _credential_like(message):  # the one choke point", "        if False:  # the one choke point"),
    "an unreadable token file leaves its token unscreened": ("        _screenable()\n", "        pass\n"),
    "a channel send without a message id counts as sent": ("            if mid is None:  # a 2xx with no usable", "            if mid is None and not conversation:  # a 2xx with no usable"),
    "an absent conversation tool is not an error": ("    if tool not in _offered(client):", "    if False:"),
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
        path = tree / "harness" / "hooks" / FILE
        text = path.read_text()
        old, new = change
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
