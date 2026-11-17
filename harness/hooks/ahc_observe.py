#!/usr/bin/env python3
"""AC-1 / AC-2 observation producer (goodqa#16049 slice 1 (b), spec r9).

One read session per observation. Each field has one named source:
- GitHub by PR number (gh api, READ_TEMPLATES "pull"): pr, pr_head, pr_state, draft, mergeable, mergeable_state,
  the PR body (its digest and updated_at) and changed_files. The pull is read first and again at the end; a head
  that moved in between refuses the observation.
- GitHub by ref (READ_TEMPLATES "ref"): tip, the default branch's sha.
- local git over the fetched shas: compare, b_r_ancestors, fast_forward, paths (`diff --name-status --find-renames`
  of M..H, M = merge-base(B, H)) and the commit messages of M..H. No 3000-file or 250-commit API list is read.
- GitHub by sha (READ_TEMPLATES "check_runs" and "statuses"): the AC-2 checks evidence.
- GoodQA (injected reader): attached_core, open_findings, mirror_ok and the W12 check facts, and the attached spec
  core's text (`spec_core_text`, PR 273 receipt F3). The text must hash to attached_core or the observation is
  refused; it is handed to R2 on the returned observation only and never persisted (the digest is).
- local config and the recorded canary (AC-10): policy, kill_switch, kill_epoch, chk_cas, canary_age.

Fail closed: a missing, truncated, oversized, foreign or malformed read refuses the whole observation
(ObservationRefused) and nothing moves. A tick has a gh call budget and a byte cap per call; the build has a deadline
under 120 s on the boot clock; a 403 or 429 starts a backoff (AC-10 timer GH_BACKOFF) during which the producer
refuses without calling gh.

The observation is stamped at its first read with (boot id, boot clock, sequence), which is its id, and persisted
append-only in the observations table (Contracts.record_observation). Guards load it by id.
"""
from __future__ import annotations

import hashlib
import json
import re

import ahc_contracts as C
import ahc_guard

SHA = re.compile(r"[0-9a-f]{40}")
BODY_MAX_BYTES = 262_144           # the PR body cap (GitHub allows 65536 characters, at most 4 bytes each)
CALL_BUDGET = 16                   # gh calls per observation build (two pulls, the ref, and check pages)
TICK_CALL_BUDGET = 200             # gh calls per tick across every observation
DEADLINE_SECONDS = 110.0           # the build's deadline, under the spec's 120 s, on the boot clock
GH_TIMEOUT = 30
BACKOFF_SECONDS = 300              # a 403 or 429 backs off this long (both clocks: a wait before acting)
RATE = re.compile(r"\b(HTTP 403|HTTP 429|rate limit|secondary rate)", re.I)
# A closing keyword naming another repository (L9): "fixes owner/repo#12" or a URL to another repo's issue.
CLOSING = re.compile(r"\b(close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b[:\s]+(?:(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#"
                     r"(?P<n>\d+)|https?://github\.com/(?P<urepo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/(?:issues|pull)/"
                     r"(?P<un>\d+))", re.I)
API_HEADERS = ["-H", ahc_guard.GH_HEADERS[0], "-H", ahc_guard.GH_HEADERS[1]]


class ObservationRefused(RuntimeError):
    """The observation is refused, fail closed. `rate_limited` marks a 403/429 (the producer backs off)."""

    def __init__(self, why, rate_limited=False):
        super().__init__(why)
        self.rate_limited = rate_limited


# goodqa#16262 d5: the commit form of a ticket, matched in full against one line; project goodqa
REFS_LINE = re.compile(r"Refs: GoodQA #([1-9][0-9]{0,8})")


def parse_refs(messages, shas=None):
    """RULED-4 check 1 at W1: every M..H commit body has exactly one line matching REFS_LINE in full (lines split
    on \\n only, so a trailing \\r or space does not match), and all name the same number. Returns
    (("goodqa", N), None) or (None, "refs: <which>")."""
    messages = list(messages)
    if not messages:
        return None, "refs: no commits in M..H"
    numbers = set()
    for i, msg in enumerate(messages):
        found = [m for m in (REFS_LINE.fullmatch(line) for line in str(msg).split("\n")) if m]
        if len(found) != 1:
            who = (shas[i][:12] if shas and i < len(shas) and shas[i] else "#%d" % (i + 1))
            return None, "refs: commit %s has %d canonical Refs lines (needs exactly one `Refs: GoodQA #N`)" % (
                who, len(found))
        numbers.add(int(found[0].group(1)))
    if len(numbers) != 1:
        return None, "refs: the commits name %s" % ", ".join("goodqa#%d" % n for n in sorted(numbers))
    return ("goodqa", numbers.pop()), None


def foreign_closing_keyword(text, repo):
    """True when `text` carries a closing keyword that names a repository other than `repo` (L9)."""
    for m in CLOSING.finditer(text or ""):
        other = (m.group("repo") or m.group("urepo") or "").lower()
        if other and other != str(repo).lower():
            return True
    return False


def parse_name_status(out):
    """(paths, count) of `git diff --name-status --find-renames -z`: every path, both paths of a rename or copy,
    and the number of entries (a rename counts once, as GitHub's changed_files does). Malformed output raises."""
    toks = out.split("\0")
    if toks and toks[-1] == "":
        toks.pop()
    paths, count, i = [], 0, 0
    while i < len(toks):
        status = toks[i]
        if not re.fullmatch(r"[ACDMRTUX][0-9]{0,3}", status):
            raise ObservationRefused("git diff --name-status: unexpected status %r" % status[:20])
        n = 2 if status[0] in "RC" else 1
        names = toks[i + 1:i + 1 + n]
        if len(names) != n or not all(names):
            raise ObservationRefused("git diff --name-status: truncated entry")
        paths.extend(names)
        count += 1
        i += 1 + n
    return paths, count


def parse_pages(out):
    """[(headers dict, body text)] of `gh api --include --paginate`: each page is an HTTP status line, its headers,
    a blank line and its JSON body (ASSUMPTION, PENDING_REAL_TEST obs-pages: confirmed on fixtures only)."""
    pages = []
    for chunk in re.split(r"(?m)^(?=HTTP/[0-9.]+ \d{3})", out):
        if not chunk.strip():
            continue
        head, sep, body = chunk.replace("\r\n", "\n").partition("\n\n")
        if not sep:
            raise ObservationRefused("gh api: a page has no header terminator")
        lines = head.split("\n")
        status = re.match(r"HTTP/[0-9.]+ (\d{3})", lines[0])
        if not status or status.group(1) != "200":
            raise ObservationRefused("gh api: a page answered %s" % lines[0][:40])
        headers = {}
        for line in lines[1:]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        pages.append((headers, body.strip()))
    return pages


def _next_page(headers):
    m = re.search(r'<[^>]*[?&]page=(\d+)[^>]*>;\s*rel="next"', headers.get("link", ""))
    return int(m.group(1)) if m else None


def complete_pages(pages):
    """The page bodies, in order, only when the Link headers chain 1, 2, ... n with no gap and the last page has no
    next link. A missing page refuses."""
    if not pages:
        raise ObservationRefused("gh api: no page")
    for idx, (headers, _body) in enumerate(pages):
        nxt = _next_page(headers)
        last = idx == len(pages) - 1
        if last and nxt is not None:
            raise ObservationRefused("gh api: the last page read still links a next page (truncated)")
        if not last and nxt != idx + 2:
            raise ObservationRefused("gh api: page %d links page %s, not %d (a page is missing)" % (idx + 1, nxt,
                                                                                                   idx + 2))
    return [b for _h, b in pages]


# ---------------------------------------------------------------- AC-2 checks evidence

def checks_evidence(repo, base, head, revision, policy, run_pages, status_pages):
    """AC-2: the checks evidence for (repo, B, H, policy revision), or a refusal reason.

    Returns {"green": bool, "reason": str, "binding": {...}, "contexts": {...}}. green is True only when the policy
    names GitHub required contexts and one app, and for every required context: every check run of it for H (all
    attempts, `filter=all`) was posted by that app and concluded success, it is not also posted as a commit status
    (a duplicate context), and the check-run pages are complete (total_count equals the runs read). A policy that
    requires ahc-local checks is never green in this slice (that producer is out of scope)."""
    binding = {"repo": str(repo).lower(), "base": base, "head": head, "policy_revision": revision}
    out = {"green": False, "reason": "", "binding": binding, "contexts": {}}
    req = policy.get("required_checks") if isinstance(policy, dict) else None
    if not isinstance(req, dict):
        out["reason"] = "the policy names no required checks"
        return out
    if req.get("ahc_local"):
        out["reason"] = "ahc-local checks are required and that producer is out of scope (AC-2)"
        return out
    contexts, app = req.get("contexts"), req.get("app")
    if not (isinstance(contexts, list) and contexts and all(isinstance(c, str) and c for c in contexts)
            and isinstance(app, str) and app):
        out["reason"] = "the policy's required checks name no contexts or no app"
        return out
    runs, total = [], None
    for body in run_pages:
        try:
            page = json.loads(body)
        except ValueError:
            out["reason"] = "a check-runs page is not JSON"
            return out
        if not isinstance(page, dict) or not isinstance(page.get("check_runs"), list):
            out["reason"] = "a check-runs page has no check_runs list"
            return out
        if total is None:
            total = page.get("total_count")
        runs.extend(page["check_runs"])
    if type(total) is not int or total != len(runs):
        out["reason"] = "check runs incomplete: total_count %r, read %d" % (total, len(runs))
        return out
    status_contexts = set()
    for body in status_pages:
        try:
            page = json.loads(body)
        except ValueError:
            out["reason"] = "a statuses page is not JSON"
            return out
        if not isinstance(page, list):
            out["reason"] = "a statuses page is not a list"
            return out
        status_contexts |= {s.get("context") for s in page if isinstance(s, dict)}
    for ctx in contexts:
        mine = [r for r in runs if isinstance(r, dict) and r.get("name") == ctx]
        if not mine:
            out["reason"] = "required context %s has no check run for H" % ctx
            return out
        if ctx in status_contexts:
            out["reason"] = "required context %s is also posted as a commit status (duplicate)" % ctx
            return out
        for r in mine:
            slug = (r.get("app") or {}).get("slug") if isinstance(r.get("app"), dict) else None
            if slug != app:
                out["reason"] = "required context %s was posted by app %r, not %s" % (ctx, slug, app)
                return out
            if r.get("head_sha") != head:
                out["reason"] = "a run of %s is for another sha" % ctx
                return out
            if r.get("status") != "completed" or r.get("conclusion") != "success":
                out["reason"] = "an attempt of %s is %s/%s" % (ctx, r.get("status"), r.get("conclusion"))
                return out
        out["contexts"][ctx] = len(mine)
    out["green"] = True
    out["reason"] = "every required context passed on every attempt for H"
    return out


def bound_green(evidence, repo, base, head, revision):
    """checks_green: True only for green evidence bound to exactly (repo, B, H, policy revision) (AC-2, NEG-6)."""
    if not isinstance(evidence, dict) or evidence.get("green") is not True:
        return False
    want = {"repo": str(repo).lower(), "base": base, "head": head, "policy_revision": revision}
    return evidence.get("binding") == want


# ---------------------------------------------------------------- the producer

class Producer:
    """Builds observations. `gh(args, timeout)` and `git(args, cwd, timeout)` return (rc, stdout, stderr) and are
    the AC-13 production forms (`for_live`) or injected fakes in tests; `goodqa(repo, pr, head, ticket)` returns a dict of
    GoodQA facts; `local(repo)` returns the local config facts for the repo: {"policy": record, "kill_switch",
    "kill_epoch", "chk_cas", "canary"} (canary is the recorded (boot, mono) canary result)."""

    def __init__(self, contracts, gh, git, goodqa, local, tick_budget=TICK_CALL_BUDGET):
        self.c = contracts
        self._gh, self._git, self._goodqa, self._local = gh, git, goodqa, local
        self.tick_left = int(tick_budget)
        self.incidents = []

    @classmethod
    def for_live(cls, contracts, policy, goodqa, local, run=None):
        """The production producer: gh and git through the AC-13 forms of `policy` (cwd under the root)."""
        import ahc_clone  # noqa: PLC0415

        def gh(args, timeout):
            return ahc_guard.run(policy, "gh", list(args), timeout)

        def git(args, cwd, timeout):
            r = ahc_clone._git(list(args), cwd=str(cwd), timeout=timeout, check=False)
            return r.returncode, r.stdout, r.stderr
        return cls(contracts, gh, git, goodqa, local)

    # -------------------------------------------------------------- reads

    def _budget(self, s):
        if s["calls"] >= CALL_BUDGET or self.tick_left <= 0:
            raise ObservationRefused("the gh call budget is spent")
        if float(self.c._mono()) - s["start"] >= DEADLINE_SECONDS:
            raise ObservationRefused("the observation build passed its deadline")
        s["calls"] += 1
        self.tick_left -= 1

    def _api(self, s, endpoint, paginate=False):
        name, m = ahc_guard.template_of(endpoint)
        if name is None:
            raise ObservationRefused("no read template for %s" % endpoint[:80])
        self._budget(s)
        args = ["api", "--method", "GET"] + API_HEADERS + (["--include", "--paginate"] if paginate else []) + [
            endpoint]
        rc, out, err = self._gh(args, GH_TIMEOUT)
        if rc != 0:
            raise ObservationRefused("gh api %s failed (exit %s): %s" % (name, rc, str(err).strip()[-200:]),
                                     rate_limited=bool(RATE.search(str(err) + str(out))))
        if len(out.encode("utf-8", "replace")) > ahc_guard.READ_TEMPLATES[name]["max_bytes"]:
            raise ObservationRefused("gh api %s: output over its byte cap" % name)
        s["refs"].append(endpoint)
        if paginate:
            return complete_pages(parse_pages(out))
        try:
            return json.loads(out)
        except ValueError:
            raise ObservationRefused("gh api %s: output is not JSON (truncated?)" % name) from None

    def _gitrun(self, s, args, clone, ok=(0,)):
        if float(self.c._mono()) - s["start"] >= DEADLINE_SECONDS:
            raise ObservationRefused("the observation build passed its deadline")
        rc, out, err = self._git(list(args), clone, GH_TIMEOUT)
        if rc not in ok:
            raise ObservationRefused("git %s failed (exit %s): %s" % (args[0], rc, str(err).strip()[-200:]))
        return rc, out

    def _ancestor(self, s, clone, a, b):
        rc, _out = self._gitrun(s, ["merge-base", "--is-ancestor", a, b], clone, ok=(0, 1))
        return rc == 0

    def _pull(self, s, repo, pr):
        p = self._api(s, "repos/%s/pulls/%d" % (repo, pr))
        if not isinstance(p, dict):
            raise ObservationRefused("the PR read is not an object")
        base_repo = ((p.get("base") or {}).get("repo") or {}).get("full_name") if isinstance(p.get("base"),
                                                                                              dict) else None
        if str(base_repo or "").lower() != repo or p.get("number") != pr:
            raise ObservationRefused("gh returned another repo's PR or another number (NEG-2)")
        head = (p.get("head") or {}).get("sha") if isinstance(p.get("head"), dict) else None
        if not (isinstance(head, str) and SHA.fullmatch(head)):
            raise ObservationRefused("the PR head is not a full sha (NEG-2)")
        return p, head

    def _backing_off(self, repo):
        return self.c.clock._row("gh:" + repo, "GH_BACKOFF") is not None and \
            not self.c.clock.due("gh:" + repo, "GH_BACKOFF", BACKOFF_SECONDS)

    # -------------------------------------------------------------- the session

    def observe(self, repo, pr, *, item=None, clone=None, snapshot_bases=(), base=None):
        """One read session for (repo, pr). Returns the persisted observation, loaded by its id. `item` (an id) and
        `snapshot_bases` (the B_r of the item's code review rows) and `base` (the item's B, for W18's fast_forward)
        are recorded for the guards; `clone` is the daemon
        clone holding H and the tip (ahc_clone.prepare). Raises ObservationRefused."""
        repo = str(repo).lower()
        if self._backing_off(repo):
            raise ObservationRefused("gh rate limited: backing off (AC-1)", rate_limited=True)
        stamp = self.c.first_read_stamp()
        s = {"calls": 0, "start": float(stamp["mono"]), "refs": []}
        try:
            fields = self._build(s, repo, int(pr), clone, list(snapshot_bases), item, base)
        except ObservationRefused as error:
            if error.rate_limited:
                with self.c.tx():
                    self.c.clock.start("gh:" + repo, "GH_BACKOFF", BACKOFF_SECONDS)
            raise
        source = {"github": ["pull", "ref", "check_runs", "statuses"], "git": "clone by sha",
                  "goodqa": "reader", "local": "config and canary"}
        rows = self.c.record_observation(stamp, repo, pr, item, source, s["refs"], fields)
        if rows > self.c.OBSERVATION_ROW_CAP:
            self.incidents.append("observations table holds %d rows, over its cap %d" % (rows,
                                                                                         self.c.OBSERVATION_ROW_CAP))
        return dict(self.c.load_observation(stamp["id"]), **s.get("attach", {}))

    @staticmethod
    def _spec_core_text(gq):
        """PR 273 receipt F3: the attached spec core's raw bytes, verified against attached_core, for R2 only: kept
        on the returned observation, never in the persisted fields. Absent: R2 holds; foreign: refused here."""
        data = _spec_core_bytes(gq)
        if data is None:
            return {}
        try:
            return {"spec_core_text": data.decode("utf-8")}
        except UnicodeDecodeError:
            raise ObservationRefused("the GoodQA spec core text is not UTF-8") from None

    def _build(self, s, repo, pr, clone, bases, item, base=None):
        local = self._local(repo)
        policy = dict(local.get("policy") or {}) if isinstance(local, dict) else {}
        branch = policy.get("default_branch")
        if not (isinstance(branch, str) and branch):
            raise ObservationRefused("the policy record names no default branch")
        p, head = self._pull(s, repo, pr)
        if "body" not in p:
            raise ObservationRefused("the PR read has no body field (NEG-34)")
        body = p["body"] if p["body"] is not None else ""
        if not isinstance(body, str) or len(body.encode("utf-8", "replace")) > BODY_MAX_BYTES:
            raise ObservationRefused("the PR body is not text or is over its byte cap (NEG-34)")
        ref = self._api(s, "repos/%s/git/ref/heads/%s" % (repo, branch))
        tip = ((ref or {}).get("object") or {}).get("sha") if isinstance(ref, dict) else None
        if not (isinstance(tip, str) and SHA.fullmatch(tip)):
            raise ObservationRefused("the default-branch ref is not a full sha")
        if clone is None:
            raise ObservationRefused("no daemon clone holds H and the tip")
        for sha in (head, tip):
            self._gitrun(s, ["cat-file", "-e", sha + "^{commit}"], clone)
        _rc, mb = self._gitrun(s, ["merge-base", tip, head], clone)
        merge_base = mb.strip()
        if not SHA.fullmatch(merge_base):
            raise ObservationRefused("no merge base of B and H")
        if tip == head:
            compare = "identical"
        elif self._ancestor(s, clone, tip, head):
            compare = "ahead"
        elif self._ancestor(s, clone, head, tip):
            compare = "behind"
        else:
            compare = "diverged"
        _rc, ns = self._gitrun(s, ["diff", "--name-status", "--find-renames", "-z", merge_base, head], clone)
        paths, count = parse_name_status(ns)
        changed = p.get("changed_files")
        if type(changed) is not int or changed != count:
            raise ObservationRefused("changed_files %r disagrees with the local M..H list (%d) (NEG-3)"
                                     % (changed, count))
        _rc, log = self._gitrun(s, ["log", "--format=%H%x00%B%x00", "%s..%s" % (merge_base, head)], clone)
        parts = log.split("\0")
        messages = [m for m in parts[1::2]]
        shas = [x.strip() for x in parts[0::2]][:len(messages)]
        anc = {b: self._ancestor(s, clone, b, tip) for b in bases if SHA.fullmatch(str(b))}
        ff = None
        if isinstance(base, str) and SHA.fullmatch(base) and base != tip:
            ff = self._ancestor(s, clone, base, tip)
        revision = policy.get("revision")
        runs = self._api(s, "repos/%s/commits/%s/check-runs?per_page=100&filter=all" % (repo, head), paginate=True)
        statuses = self._api(s, "repos/%s/commits/%s/statuses?per_page=100" % (repo, head), paginate=True)
        evidence = checks_evidence(repo, tip, head, revision, policy, runs, statuses)
        policy["checks_green"] = bound_green(evidence, repo, tip, head, revision)
        p2, head2 = self._pull(s, repo, pr)                    # the head is re-read at the end
        if head2 != head:
            raise ObservationRefused("the PR head moved during the read (NEG-4)")
        state = "MERGED" if p2.get("merged") is True else {"open": "OPEN", "closed": "CLOSED"}.get(p2.get("state"))
        if state is None:
            raise ObservationRefused("unknown PR state %r" % p2.get("state"))
        # goodqa#16262 d5: the reader is called with the Refs ticket at W1 (check 1 here: a problem skips the call
        # and does not refuse the observation) and with the lineage's binding for a live item (unbound: no call).
        # The request's own ticket is never passed.
        refs_ticket = refs_problem = None
        if item is None:
            refs_ticket, refs_problem = parse_refs(messages, shas)
            ticket = refs_ticket
        else:
            ticket = self.c.lineage_ticket(item)
        if ticket is None:
            gq = {}
        else:
            gq = self._goodqa(repo, pr, head, ticket)
            if not isinstance(gq, dict):
                raise ObservationRefused("the GoodQA reader returned nothing")
        s["attach"] = self._spec_core_text(gq)
        spec_ticket = C.parse_ticket_text(gq.get("spec_ticket")) if gq.get("attached_core") is not None else None
        canary_age = self.c.clock.canary_age(local.get("canary"))
        fields = {
            "repo": repo, "pr": pr, "pr_head": head, "pr_state": state, "draft": p2.get("draft"),
            "mergeable": p2.get("mergeable"), "mergeable_state": p2.get("mergeable_state"),
            "tip": tip, "merge_base": merge_base, "compare": compare, "b_r_ancestors": anc,
            "fast_forward": ff, "paths": paths, "changed_files": changed,
            "foreign_closing_keyword": any(foreign_closing_keyword(t, repo) for t in messages + [body]),
            "body_sha256": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest(),
            "body_updated_at": p2.get("updated_at"),
            "checks_evidence": evidence, "policy": policy,
            "kill_switch": local.get("kill_switch"), "kill_epoch": local.get("kill_epoch"),
            "chk_cas": local.get("chk_cas"), "canary_age": canary_age,
            "attached_core": gq.get("attached_core"), "open_findings": gq.get("open_findings"),
            "mirror_ok": gq.get("mirror_ok"),
            "refs_ticket": C.ticket_text(refs_ticket) if refs_ticket else None, "refs_problem": refs_problem,
            "spec_ticket": C.ticket_text(spec_ticket) if spec_ticket else None,
        }
        for k in ("check_record", "author", "owner", "spec_reviewers", "evidence_posters"):
            if k in gq:
                fields[k] = gq[k]
        return fields


SPEC_CORE_MAX = 1 << 20      # bytes; the same cap as ahc_review.SPEC_CORE_MAX


def _spec_core_bytes(gq):
    text = gq.get("spec_core_text")
    if text is None:
        return None
    if isinstance(text, str):
        text = text.encode("utf-8")
    if not isinstance(text, bytes):
        raise ObservationRefused("the GoodQA spec core text is not text")
    if len(text) > SPEC_CORE_MAX:
        raise ObservationRefused("the GoodQA spec core text is larger than %d bytes" % SPEC_CORE_MAX)
    if hashlib.sha256(text).hexdigest() != gq.get("attached_core"):
        raise ObservationRefused("the GoodQA spec core text is not the attached core (a foreign read)")
    return text


def stale_or_bad(contracts, obs):
    """NEG-1 helper for callers: the clause an observation fails T2 on, or None."""
    try:
        contracts._fresh(obs)
    except C.ContractError as error:
        return str(error)
    return None
