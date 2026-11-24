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
    "no main-agent stamp is needed": ("    if stamp is None:\n        raise ChatError(\"main_only\"", "    if False:\n        raise ChatError(\"main_only\""),
    "the stamp ignores the text's content": ('    return ["send", target, org or "", os.path.realpath(text_file), digest]',
                                             '    return ["send", target, org or "", os.path.realpath(text_file)]'),
    "the hook stamps a sub-agent": ("mission_gate.py", "    if not caller_identity.is_main(payload):\n        return {}", "    if False:\n        return {}"),
    "the hook stamps a dry run": ("mission_gate.py", '        if getattr(args, "dry_run", True):\n            continue', "        pass"),
    "the stamp is not bound to the call": ("                                       bound=True)", "                                       bound=False)"),
    "the prefix is dropped": ("    body = PREFIX + text", "    body = text"),
    "the length cap is 601": ("MAX_CHARS = 600", "MAX_CHARS = 601"),
    "a secret shape is sent": ("    if chat._secret_spans(text):\n", "    if False:\n"),
    "a token piece is sent": ("        if chat._holds_token(body):", "        if False:"),
    "the same text may go again": ('    if same and any(a["status"] != "approval_required" for a in same):', "    if False:"),
    "an uncertain outcome frees the text": ('    if same and any(a["status"] != "approval_required" for a in same):',
                                            '    if same and any(a["status"] == "sent" for a in same):'),
    "approval_required blocks the text forever": ('    if same and any(a["status"] != "approval_required" for a in same):', "    if same:"),
    "no rate limit": ("    if len(recent) >= RATE_LIMIT:", "    if False:"),
    "an unfinished ledger record is ignored": ("    if data and not data.endswith(b\"\\n\"):", "    if False:"),
    "a malformed ledger record is skipped": ("            raise ChatError(\"ledger_damaged\", \"the chat-send ledger holds a malformed record",
                                             "            continue\n            raise ChatError(\"ledger_damaged\", \"the chat-send ledger holds a malformed record"),
    "the DM token sends": ('        client = chat.Client(base, source="user")', '        client = chat.Client(base, source="dm")'),
    "a group DM is accepted": ('            if row.get("kind") != "dm":', "            if False:"),
    "a symlinked text file is followed": ('        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))',
                                          '        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))'),
    "a relative text path is accepted": ("    if not isinstance(path, str) or not os.path.isabs(path) or \"\\x00\" in path:",
                                         "    if not isinstance(path, str) or \"\\x00\" in path:"),
    "control characters are sent": ("    if CONTROL.search(text.replace(\"\\r\\n\", \"\\n\")):", "    if False:"),
    "no WAL row": ("        wal_id = _wal(home, session, dict(record, status=status, message=message_id, attempt=attempt))",
                   "        wal_id = None"),
    "the WAL row holds the text": ('        record = {"peer": peer, "org": org, "conversation": conversation, "text_sha256": digest, "chars": len(body)}',
                                   '        record = {"peer": peer, "org": org, "conversation": conversation, "text_sha256": digest, "chars": len(body), "text": body}'),
    "the base is not pinned": ("    chat._pinned_base(base)  # first: a refused base reads nothing", "    pass"),
    "a dry run reads the token": ("    if dry_run:  # no token", "    chat.Client(base, source=\"user\")\n    if dry_run:  # no token"),
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
