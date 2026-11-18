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
    "not_found is a traceback": ('                refused = ChatError("not_found"', '                refused = KeyError("not_found"'),
    "the token file can be the body": ("def _read_body(path):", "def _read_body(path):\n    return open(path).read()  # mutant"),
    # PR 277 r5: the send outcome table in docs/ah-chat.md, one variant per row (the number is the table row)
    "r2 a DM 2xx without a message id counts as sent": (
        "            if mid is None:  # a 2xx with no usable", "            if mid is None and conversation:  # a 2xx with no usable"),
    "r3 a pre-effect tool code counts as uncertain": (
        '    if error.code in ("tool_error", "not_found"):\n        return "failed" if code in PRE_EFFECT else "uncertain"',
        '    if error.code in ("tool_error", "not_found"):\n        return "uncertain"'),
    "r4 a tool not_found counts as uncertain": ('    if error.code in ("tool_error", "not_found"):', '    if error.code in ("tool_error",):'),
    "r5 any tool error counts as not delivered": (
        '    if error.code in ("tool_error", "not_found"):\n        return "failed" if code in PRE_EFFECT else "uncertain"',
        '    if error.code in ("tool_error", "not_found"):\n        return "failed"'),
    "r5 approval_required counts as not delivered": ('"forbidden", "unauthorized",', '"forbidden", "unauthorized", "approval_required",'),
    "r5/r11 an unrecognised code counts as no code": ('else "unrecognized_error"\n', 'else None\n'),
    "r6 a tool error without a code counts as not delivered": (
        '    if error.code in ("tool_error", "not_found"):\n        return "failed" if code in PRE_EFFECT else "uncertain"',
        '    if error.code in ("tool_error", "not_found"):\n        return "failed" if code in PRE_EFFECT or code is None else "uncertain"'),
    "r7 an rpc error counts as not delivered": ('    return "uncertain"\n\n\ndef _destination',
                                               '    return "failed" if error.code == "rpc_error" else "uncertain"\n\n\ndef _destination'),
    "r8 an unexpected 2xx counts as not delivered": ('    return "uncertain"\n\n\ndef _destination',
                                                     '    return "failed" if error.code == "unexpected_response" else "uncertain"\n\n\ndef _destination'),
    "r9 an oversized 2xx counts as not delivered": ('    return "uncertain"\n\n\ndef _destination',
                                                    '    return "failed" if error.code == "response_too_large" else "uncertain"\n\n\ndef _destination'),
    "r10 a pre-effect code in an HTTP body counts as uncertain": (
        '        if code is not None:\n            return "failed" if code in PRE_EFFECT else "uncertain"',
        '        if code is not None:\n            return "uncertain"'),
    "r11 the 9a9f152 rule: any 4xx but 408 and 429 is not delivered": (
        '        if code is not None:\n            return "failed" if code in PRE_EFFECT else "uncertain"\n'
        '        return "failed" if status in PRE_EFFECT_STATUS else "uncertain"',
        '        return "uncertain" if status in (408, 429) else "failed"'),
    "r11 an HTTP body code is ignored": ("        if code is not None:", "        if False:"),
    "r11 an HTTP error keeps no structured code": ("            refused.server_code = _known_or_unrecognized(code)\n            raise refused from None",
                                                   "            raise refused from None"),
    "r12 a bare pre-effect 4xx counts as uncertain": ('        return "failed" if status in PRE_EFFECT_STATUS else "uncertain"',
                                                      '        return "uncertain"'),
    "r12 an HTTP error keeps no status": ("refused.http_status = error.code if", "refused.http_status = None if"),
    "r13 a bare 409 counts as not delivered": ("frozenset({400, 401, 403, 404, 405, 411,", "frozenset({400, 401, 403, 404, 405, 409, 411,"),
    "r13 a bare 408, 410 or 429 counts as not delivered": ("414, 415, 422})", "414, 415, 422, 408, 410, 429})"),
    "r14 a 5xx counts as not delivered": ("400 <= status <= 499", "400 <= status <= 599"),
    "r15 a redirect counts as not delivered": ('    return "uncertain"\n\n\ndef _destination',
                                               '    return "failed" if error.code == "redirect_refused" else "uncertain"\n\n\ndef _destination'),
    "r16 no answer counts as not delivered": ('    return "uncertain"\n\n\ndef _destination',
                                              '    return "failed" if error.code == "unreachable" else "uncertain"\n\n\ndef _destination'),
    "r17 a pending attempt is posted again": ('in ("pending", "uncertain")', 'in ("uncertain",)'),
    "r18 the API base is not part of the send identity": ('json.dumps({"base": destination, "target": target, "body": digest},',
                                                         'json.dumps({"target": target, "body": digest},'),
    "r18 the API base is not normalised": ('    return urllib.parse.urlunsplit((u.scheme.lower(), netloc, u.path.rstrip("/"), "", ""))',
                                           "    return base"),
    "r19 a row without an API base is trusted": ('        if rows and not isinstance(rows[0].get("base"), str):', "        if False:"),
    "channel: an uncertain channel post is blocked": ("and not conversation and not confirm_not_delivered:", "and not confirm_not_delivered:"),
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
