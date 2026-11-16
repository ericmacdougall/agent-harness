#!/usr/bin/env python3
"""AC-7: W21's update-branch send behind AHC_W21_SEND (goodqa#16049 slice 1 (b), spec r9).

Contracts.wi_move W21 writes the keyed record: one w21_sends row in state intent and its authority line, whose
event id, request id and content are functions of (item, B, seq) alone. This module moves that record:

- intent -> cancelled, only while it is still intent with no attempted timestamp, when a blocking control holds at
  the send decision: the flag is off, the kill switch is on or its reading is stale or not taken under the shared
  T9 lock, or the repo's policy no longer allows W21. The slot is released; the item keeps the queue head.
- intent -> attempted, committed immediately before the call (the sender acts only on committed rows), then the
  one-shot AC-13 expectation is armed and the PUT is sent once. A failed or lost response leaves the row attempted
  (never cancelled); it goes to read-back, and W23 ends it as lost after 10 min.
- attempted or readback-pending -> resolved, only when H' is ahc's update: parent1 is H, parent2 is an ancestor of
  or equal to the tip, the tree of H' equals a locally computed `git merge-tree --write-tree H parent2`, and the
  attempted record predates the read-back. Otherwise the row waits for W23.
- restart reconciliation cancels intent rows and reads back attempted ones; it never sends again.

Named crash points (ahc_crash.POINTS): w21.before_send (after attempted commits, before the call) and w21.after_send
(after the call, before the read-back record).
"""
from __future__ import annotations

import os
import re

import ahc_contracts as C
from ahc_crash import crash_at

FLAG = "AHC_W21_SEND"
KILL_MAX_AGE = 5.0                   # the kill reading is at most 5 s old at the send decision
SHA = re.compile(r"[0-9a-f]{40}")


def enabled():
    """AHC_W21_SEND: only the exact value 1, read at each send decision."""
    return os.environ.get(FLAG) == "1"


def put_args(repo, pr, head):
    """The one non-GET gh form (AC-13): W21's update-branch with the expected head."""
    return ["api", "--method", "PUT", "repos/%s/pulls/%d/update-branch" % (repo, int(pr)), "-f",
            "expected_head_sha=%s" % head]


class Sender:
    """`gh(args, timeout)` -> (rc, out, err) runs gh in its AC-13 form; `arm(argv_args)` arms the guard's one-shot
    W21 expectation (production: Policy.arm_w21 with the resolved gh path); `kill()` returns
    {"on": bool, "epoch": int, "mono": float, "shared": bool} read under the shared T9 flock, or None when unknown;
    `allows(repo)` says whether the repo's policy at its current revision allows W21; `git(args, cwd)` -> (rc, out)
    and `clone(repo, head, base)` give the daemon clone for the read-back."""

    def __init__(self, contracts, gh, arm, kill, allows, git, clone):
        self.c = contracts
        self.gh, self.arm, self.kill, self.allows, self.git, self.clone = gh, arm, kill, allows, git, clone
        self.sent = []

    enabled = staticmethod(enabled)

    # ------------------------------------------------------------ the send decision

    def blocked(self, row):
        """The blocking control at the send decision, or None."""
        if not enabled():
            return "AHC_W21_SEND is not exactly 1"
        k = self.kill()
        if not isinstance(k, dict):
            return "the kill reading is unknown"
        if k.get("shared") is not True:
            return "the kill reading was not taken under the shared T9 lock"
        mono = k.get("mono")
        if not isinstance(mono, (int, float)) or isinstance(mono, bool) or \
                not 0 <= float(self.c._mono()) - float(mono) <= KILL_MAX_AGE:
            return "the kill reading is more than 5 s old"
        if k.get("on") is not False:
            return "the kill switch is on"
        if self.allows(row["repo"]) is not True:
            return "the repo policy revision no longer allows W21"
        return None

    def pump(self):
        """One pass: decide each committed intent (cancel or send), then read back each sent row."""
        out = {"cancelled": [], "sent": [], "resolved": [], "failed": []}
        for (rid,) in self.c.db.execute("SELECT request_id FROM w21_sends WHERE state='intent' ORDER BY created, "
                                        "request_id").fetchall():
            result = self.send(rid)
            if result in ("sent", "cancelled"):
                out[result].append(rid)
        out["resolved"] = self.readback_all()
        return out

    def send(self, rid):
        """The send decision for one committed intent row, for any caller: the blocking controls are re-read here
        (a blocked row is cancelled, never sent), then attempted is committed, and only the process whose CAS
        moved the row makes the one call. Returns "sent", "cancelled" or None (another process took the row)."""
        row = self.c._row("w21_sends", "request_id", rid)
        if row is None or row["state"] != "intent":
            return None
        why = self.blocked(row)
        if why:
            return "cancelled" if self.c.w21_cancel(rid, why) else None
        if not self.c.w21_attempt(rid):
            return None                                    # another process or tick took it, or it is not intent
        row = self.c._row("w21_sends", "request_id", rid)
        crash_at("w21.before_send")
        args = put_args(row["repo"], row["pr"], row["head"])
        self.arm(args)
        rc, out, err = self.gh(args, 30)
        self.sent.append(rid)
        crash_at("w21.after_send")
        if rc == 0:
            self.c.w21_sent(rid, _request_id(out))
        return "sent"

    # ------------------------------------------------------------ read-back

    def readback_all(self):
        resolved = []
        for (rid,) in self.c.db.execute("SELECT request_id FROM w21_sends WHERE state IN ('attempted', "
                                        "'readback-pending') ORDER BY created, request_id").fetchall():
            if self.readback(rid):
                resolved.append(rid)
        return resolved

    def readback(self, rid):
        """Read the PR head; record H' as ahc's update only under the four rules. Anything else leaves the row for
        W23 (lost after its 10 min), never cancelled and never re-sent."""
        row = self.c._row("w21_sends", "request_id", rid)
        rc, out, _err = self.gh(["api", "--method", "GET", "repos/%s/pulls/%d" % (row["repo"], row["pr"])], 30)
        if rc != 0:
            return False
        try:
            import json  # noqa: PLC0415
            new = (json.loads(out).get("head") or {}).get("sha")
        except (ValueError, AttributeError):
            return False
        if not (isinstance(new, str) and SHA.fullmatch(new)) or new == row["head"]:
            return False                                   # still at H: readback-pending until W23
        return self.c.w21_resolve(rid, new) if self.is_ours(row, new) else False

    def is_ours(self, row, new):
        try:
            clone = self.clone(row["repo"], new, row["base"])
        except Exception:  # noqa: BLE001 - a clone failure is an inconclusive read-back
            return False

        def one(args):
            rc, out = self.git(args, clone)
            return out.strip() if rc == 0 else None
        p1, p2 = one(["rev-parse", new + "^1"]), one(["rev-parse", new + "^2"])
        if p1 != row["head"] or not (p2 and SHA.fullmatch(p2)):
            return False
        if p2 != row["base"] and self.git(["merge-base", "--is-ancestor", p2, row["base"]], clone)[0] != 0:
            return False
        tree = one(["rev-parse", new + "^{tree}"])
        merged = one(["merge-tree", "--write-tree", row["head"], p2])
        merged = merged.splitlines()[0] if merged else None
        if not tree or tree != merged:
            return False                                   # NEG-20: an evil merge is not ahc's update
        return row["attempted_at"] is not None

    # ------------------------------------------------------------ restart

    def reconcile(self):
        """At startup, before any send: an intent row is cancelled (nothing was sent); an attempted row is read
        back, never cancelled and never sent again."""
        rows = self.c.db.execute("SELECT request_id FROM w21_sends WHERE state='intent'").fetchall()
        cancelled = [rid for (rid,) in rows if self.c.w21_cancel(rid, "restart reconciliation found an intent row")]
        return {"cancelled": cancelled, "resolved": self.readback_all()}


def _request_id(out):
    """GitHub's response request id when the response carries one (an X-GitHub-Request-Id header line)."""
    m = re.search(r"(?im)^x-github-request-id:\s*([A-Za-z0-9:._-]{1,80})\s*$", str(out or ""))
    return m.group(1) if m else None


__all__ = ["Sender", "enabled", "put_args", "C"]
