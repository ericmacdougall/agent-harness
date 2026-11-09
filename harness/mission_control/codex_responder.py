"""Codex answers dashboard chat (GoodQA #15585 AC-6): one headless `codex exec --json` run per message, resuming
a single dashboard thread, read-only sandbox, approval never, scrubbed environment, empty cwd, concurrency 1,
300 s timeout, subscription login only. Replies stream into the outbox through a holdback redactor."""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path

import events as ev
import mc_chat
from safeio import scrubbed_env

HOLDBACK = 4096
THREAD_RE = re.compile(r"^[0-9a-fA-F-]{8,64}$")
PREAMBLE = ("You are Codex answering the user's chat in their local Mission Control dashboard (the agent "
            "harness fleet view). You run read-only: do not attempt to modify files, run deployments or contact "
            "services. Never print secrets, tokens, keys or the contents of credential, auth or Keychain files. "
            "Answer briefly and concretely. The user's message follows, framed as untrusted dashboard text.\n\n")


class StreamRedactor:
    """Redact over the accumulated reply and release only a prefix that ends at whitespace and leaves at least
    the last HOLDBACK characters (or everything after the last newline) unreleased, so a secret arriving split
    across chunks is never shown in part. Agent messages are kept per item id (their text is cumulative)."""

    def __init__(self):
        self.parts: dict[str, str] = {}

    @property
    def text(self) -> str:
        return "\n\n".join(self.parts.values())

    def update(self, item_id, text: str) -> None:
        self.parts[str(item_id)] = text

    def safe(self, final: bool = False) -> str:
        import redact
        text = self.text
        if final:
            return redact.redact(text)
        cut = len(text) - HOLDBACK
        newline = text.rfind("\n")
        if newline > cut:
            cut = newline
        if cut <= 0:
            return ""
        while cut > 0 and not text[cut - 1].isspace():
            cut -= 1  # never cut inside a token
        return redact.redact(text[:cut])


class CodexResponder:
    TIMEOUT_S = 300
    RATE_PER_MIN = 6
    AVAIL_TTL_S = 120

    def __init__(self, hub, health, runner, codex_bin: str | None, root: Path, disabled: str = ""):
        self.hub, self.health, self.runner = hub, health, runner
        self.disabled = disabled
        self.codex = codex_bin
        self.root = root
        self.cwd = root / "codex" / "cwd"
        self.thread_file = root / "codex" / "thread.json"
        self.recent: list[float] = []
        self.available = (False, "not checked yet")
        self.checked = 0.0
        self.busy = False
        self.stop = threading.Event()

    # ------------------------------------------------------------ availability
    def availability(self, now: float | None = None) -> tuple[bool, str]:
        now = time.time() if now is None else now
        if now - self.checked < self.AVAIL_TTL_S:
            return self.available
        self.checked = now
        self.available = self._check()
        self.hub.snapshot("codex", {"available": self.available[0], "reason": self.available[1], "busy": self.busy})
        return self.available

    def _check(self) -> tuple[bool, str]:
        if self.disabled:
            return False, self.disabled
        if not self.codex or not os.access(self.codex, os.X_OK):
            return False, "codex CLI not found"
        code, out = self.runner.run("codex-login-status", timeout=20)
        if code != 0 or "chatgpt" not in out.lower():
            return False, "Codex is not logged in with the ChatGPT subscription (API-key login is not used for chat)"
        code, out = self.runner.run("codex-pool-status", timeout=20)
        blocked = re.search(r"subscription:\s*BLOCKED until (\S+)", out or "")
        if blocked and ev.parse_ts(blocked.group(1), 0) > time.time():
            return False, f"Codex subscription quota is blocked until {blocked.group(1)}"
        return True, "ready"

    # ------------------------------------------------------------ loop
    def loop(self) -> None:
        while not self.stop.wait(2.0):
            try:
                self.step()
            except Exception as exc:  # noqa: BLE001 - shown as health, never fatal
                self.health.error("codex", f"{type(exc).__name__}: {str(exc)[:160]}")

    def step(self) -> None:
        ok, reason = self.availability()  # cached for AVAIL_TTL_S, so the dock always shows a current reason
        queued = mc_chat.pending("codex", root=self.root)
        if not queued:
            return
        record = queued[0]
        if not ok:
            mc_chat.set_state(record["id"], "unavailable", reason=reason, root=self.root)
            self.hub.snapshot("chat_state", {"id": record["id"], "status": "unavailable", "reason": reason})
            return
        now = time.time()
        self.recent = [t for t in self.recent if now - t < 60]
        if len(self.recent) >= self.RATE_PER_MIN:
            return  # waits its turn; stays queued
        self.recent.append(now)
        self.answer(record)

    def _argv(self, thread: str | None) -> list[str]:
        base = [self.codex, "exec", "--json", "--skip-git-repo-check", "-c", 'sandbox_mode="read-only"',
                "-c", 'approval_policy="never"']
        if thread:
            return base + ["resume", thread, "-"]
        return base + ["-s", "read-only", "-"]

    def _thread(self) -> str | None:
        data = mc_chat.read_json(self.thread_file)
        value = data.get("thread") if isinstance(data, dict) else None
        return value if isinstance(value, str) and THREAD_RE.match(value) else None

    def answer(self, record: dict) -> None:
        self.busy = True
        mc_chat.set_state(record["id"], "delivered", root=self.root)
        self.hub.snapshot("chat_state", {"id": record["id"], "status": "answering"})
        self.cwd.mkdir(mode=0o700, parents=True, exist_ok=True)
        reply_id = "reply-" + mc_chat.ulid()
        stream = StreamRedactor()
        last_sent = ""
        thread = self._thread()
        try:
            proc = subprocess.Popen(self._argv(thread), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, cwd=str(self.cwd), env=scrubbed_env(),
                                    start_new_session=True)
        except OSError as exc:
            self._fail(record, f"codex did not start: {exc}")
            return
        timer = threading.Timer(self.TIMEOUT_S, self._kill, args=(proc,))
        timer.start()
        failure = ""
        try:
            proc.stdin.write((PREAMBLE + mc_chat.frame(record)).encode("utf-8"))
            proc.stdin.close()
            for raw in proc.stdout:
                if len(raw) > 1024 * 1024:
                    continue
                try:
                    item = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                kind = item.get("type") if isinstance(item, dict) else None
                if kind == "thread.started" and isinstance(item.get("thread_id"), str) and not thread:
                    if THREAD_RE.match(item["thread_id"]):
                        mc_chat.write_json(self.thread_file, {"thread": item["thread_id"]})
                elif kind in ("item.updated", "item.completed"):
                    body = item.get("item") if isinstance(item.get("item"), dict) else {}
                    if body.get("type") == "agent_message" and isinstance(body.get("text"), str):
                        # agent_message text is cumulative per item; keep the latest per item id
                        stream.update(body.get("id"), body["text"])
                        shown = stream.safe()
                        if shown != last_sent and shown.strip():
                            mc_chat.write_reply(record["id"], "codex", shown, final=False, reply_id=reply_id,
                                                root=self.root)
                            self.hub.snapshot("chat_reply", {"id": reply_id, "reply_to": record["id"],
                                                             "final": False})
                            last_sent = shown
                elif kind in ("turn.failed", "error"):
                    err = item.get("error") if isinstance(item.get("error"), dict) else item
                    failure = ev.short(str(err.get("message") or "codex reported an error"), 200)
            proc.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired) as exc:
            failure = failure or f"codex stream error: {exc}"
            self._kill(proc)
        finally:
            timer.cancel()
            self.busy = False
        final_text = stream.safe(final=True)
        if proc.returncode not in (0, None) and not final_text.strip():
            failure = failure or ("codex timed out after 300 s" if proc.returncode in (-9, -15)
                                  else f"codex exited {proc.returncode}")
        if failure and not final_text.strip():
            self._fail(record, failure)
            return
        mc_chat.write_reply(record["id"], "codex", final_text or "(no answer)", final=True, reply_id=reply_id,
                            root=self.root)
        self.hub.snapshot("chat_reply", {"id": reply_id, "reply_to": record["id"], "final": True})

    def _fail(self, record: dict, reason: str) -> None:
        mc_chat.set_state(record["id"], "failed", reason=reason, root=self.root)
        self.hub.snapshot("chat_state", {"id": record["id"], "status": "failed", "reason": reason})

    @staticmethod
    def _kill(proc) -> None:
        try:
            os.killpg(proc.pid, 9)
        except (OSError, ProcessLookupError):
            pass
