"""goodqa#16396 failing-first evidence for `ah chat`: tests.test_ah_chat must fail against each controlled broken variant of
harness/hooks/ah_chat.py (each variant removes one control) and pass against the real file.

Run: python3 -B tests/mutants_ah_chat.py   (copies the hooks and the test into a temporary tree; changes nothing here)."""
import shutil
import subprocess
import sys
import tempfile
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
    "the ledger keeps the message text": ("body_len=len(body),", "body_len=len(body), text=body,"),
    "a repeated id sends again": ("        if sent:\n            return _checked", "        if False:\n            return _checked"),
    "an unknown outcome is resent blindly": ("and not conversation and not confirm_not_delivered:", "and False:"),
    "a different body under one id is accepted": ("        if rows and rows[0].get(\"request\") != request_sha:", "        if False:"),
    "not_found is a traceback": ('            if code == "not_found":\n                raise ChatError("not_found"', '            if code == "not_found":\n                raise KeyError("not_found"'),
    "the token file can be the body": ("def _read_body(path):", "def _read_body(path):\n    return open(path).read()  # mutant"),
    "an unlisted base is accepted": ("self.base = gq.check_base(base or self.defaults.get(\"base\") or first, self.defaults)",
                                     "self.base = (base or first).rstrip('/')"),
    "a read is not audited": ("    _audit(home, {\"op\": \"chat.read\"", "    None and _audit(home, {\"op\": \"chat.read\""),
}


def run(tree):
    return subprocess.run([sys.executable, "-I", str(tree / "tests" / "test_ah_chat.py")], capture_output=True, text=True, timeout=600)


def main():
    survived = []
    with tempfile.TemporaryDirectory() as tmp:
        for name, change in [("(the real file)", None)] + list(MUTANTS.items()):
            tree = Path(tmp) / "t"
            if tree.exists():
                shutil.rmtree(tree)
            (tree / "tests").mkdir(parents=True)
            shutil.copytree(ROOT / "harness" / "hooks", tree / "harness" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copy(ROOT / "tests" / "test_ah_chat.py", tree / "tests" / "test_ah_chat.py")
            if change:
                path = tree / "harness" / "hooks" / FILE
                text = path.read_text()
                old, new = change
                if text.count(old) != 1:
                    print("BROKEN MUTANT %-48s pattern found %d times" % (name, text.count(old)))
                    survived.append(name)
                    continue
                path.write_text(text.replace(old, new))
            p = run(tree)
            failed = p.returncode != 0
            expected = change is not None
            print("%-52s %s" % (name, "tests FAIL (killed)" if failed else "tests PASS"))
            if failed != expected:
                survived.append(name)
    print("survivors: %s" % (survived or "none"))
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
