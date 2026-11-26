# The merge rule

GitHub decides merges. No hook reads a merge command. A protected branch takes a change only through a pull request
whose head commit has a passing `harness/review` status (plus any checks the repository requires). The independent
review posts that status.

## The ruleset: `ah repo protect`

```
ah repo protect owner/repo [--check NAME]... [--admin-bypass] [--dry-run] [--json]
ah repo status  owner/repo [--check NAME]... [--admin-bypass] [--json]
```

`protect` writes one ruleset named `harness-merge-rule` on the default branch (`~DEFAULT_BRANCH`). It goes through
`gh api` and `gh`'s own login, and never holds a token. It runs the same way every time:

1. It reads the repository. If you do not have admin permission there, it stops and writes nothing.
2. It lists the repository's own rulesets and looks for `harness-merge-rule`.
3. If the ruleset is missing, it creates it (`POST`). If it exists, it replaces it in place (`PUT`) and keeps the same
   id. Other rulesets are left alone.
4. It reads the ruleset back and compares every rule. It prints
   `protected owner/repo: pr, no-force-push, no-delete, status harness/review (ruleset <id>)` only when they all match.

The rules:

| Rule | Setting |
|---|---|
| `pull_request` | required, with 0 approving reviews: the owner cannot approve his own pull request, and the independent review is the status instead |
| `non_fast_forward` | no force-push |
| `deletion` | the branch cannot be deleted |
| `required_status_checks` | `harness/review`, plus each `--check NAME` (the repository's own CI). The merge rule does not read CI itself; GitHub does |
| bypass | none. `--admin-bypass` lets repository admins bypass through a pull request only |

`status` runs the same comparison and writes nothing. `--dry-run` prints the body and calls nothing.

Exit codes: 0 when protected; 1 when a GitHub call failed or the ruleset differs; 2 for bad input; 3 when GitHub's
plan does not allow rulesets on this private repository. Exit 3 prints `not protected: <GitHub's message>` and is
never reported as success.

## The status: `ah review-status`

```
ah review-status post --repo owner/repo --sha <40 hex> --state success|failure|error|pending --description TEXT
                      [--target-url https://...] [--owner-override --approval ID --pr N]
ah review-status show --repo owner/repo --sha <40 hex> [--json]
```

`post` sends `harness/review` for that exact commit. It then reads the commit's statuses back and checks that the
newest `harness/review` entry is the one it sent, with the same state and description. A readback that differs, or a
newer entry from someone else, fails with exit 1. A description longer than GitHub's 140 characters is cut before
it is sent. `show` prints the newest entry.

`--owner-override --approval ID --pr N` is the owner's path for a pull request the reviewer blocked. It runs only
outside an agent, in the owner's own terminal. It needs a live `ah approve merge --project owner/repo --pr N` record
with that id, and the description names the approval. Approvals bind to the pull request; reviews bind to the commit.

## The review runner posts it

`peer_review.py pr ... --github-repo owner/repo --pr N` first reads the pull request from GitHub (`ah_repo.pr_head`).
The repository, number, head and open state must all match the reviewed HEAD, or the review does not start. After
the receipt is settled, it posts for the exact HEAD it reviewed:

| Review outcome | Status |
|---|---|
| `VERDICT: PASS` | `success`, description `PASS by <reviewer>; receipt <run id>` |
| `VERDICT: BLOCK` | `failure`, description `BLOCK by <reviewer>; receipt <run id>` |
| A ticketed form (`VERDICT: PASS-WITH-TICKETS`, or `TICKETED:` lines) | `failure`, `ticketed findings: owner decides; receipt <run id>` |
| No result (provider failure, timeout, quota, nothing launched), or a Kimi advisory | nothing is posted |

There are two verdicts, PASS and BLOCK. A finding the reviewer would defer to a ticket blocks, and the pull request
goes to the owner's queue. When nothing is posted the head stays unmergeable, and the failure is never counted.

If the post or the readback fails, the review result stands, the exit code is 4, and stderr prints the one
`ah review-status post ...` command that finishes the job.

A fix pushed after the review is a new commit with no status, so GitHub refuses the merge until the new head is
reviewed. This replaces the old 150-line allowance. Re-review happens automatically; nobody files a new card for it.

The reviewer runs inside its own boundary when the owner has installed one. Claude gets
`--settings ~/.agent-harness/sandbox/reviewer.claude.json` when that file exists. Codex gets the `ah-reviewer`
permission profile when `config.toml` declares it; otherwise it keeps `--sandbox read-only`. Profiles and
`--sandbox` do not combine. The child process carries `AH_ROLE=reviewer`.

## What this does not cover

- Workers can read `gh`'s credentials so they can push and open pull requests. With them, a determined agent could
  post `harness/review` itself. This is settled when the reviewer posts through an identity that workers cannot
  read (direction, "never" list).
- A repository the owner never ran `ah repo protect` on has no merge rule.
- `--no-main-stamp` is accepted and ignored for one release.

## Proof against the real GitHub

`tests/live_github_probe.py` runs only with `AH_LIVE_GITHUB=ericmacdougall/ah-ruleset-probe` and touches only that
private repository. It creates the repository if it is missing and leaves it in place. It then protects it, opens a
pull request, and checks each refusal: a merge with no status, a merge with `failure`, a force-push to the default
branch, and deleting the default branch. It also checks that a `success` merge goes through. Each line prints PROVEN,
FAILED or UNPROVEN.
