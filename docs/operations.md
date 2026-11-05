# Operations and safety boundaries

## Components

| Component | Role |
| --- | --- |
| `HARNESS.md` | User-wide workflow instructions installed as a marked block in `CLAUDE.md`. |
| `harness/agents/*.md` | Task owner, click tester, fixer and red-team roles. |
| `wal.py`, `wal_note.py` | Private metadata and human-readable WAL entries. |
| `peer_review.py`, `report_file.py` | Read-only plan/code-inspection/PR review with bounded provider fallback and inode-checked private reports. |
| `usage_guard.py` | Opt-in finite command receipts, declared input identities, full-run gates, duplicate protection and private provider-pool state. |
| `git_safety.py` | Bounded Git source preflight and controlled subprocess environment shared by review, rescue, publication, and integration. |
| `rescue.py` | Main-approved Astra rescue with Fable fallback on a clean worktree. |
| `deliver.py` | Durable prepare/finish workflow for a draft PR and checked original checkout. |
| `publish_feature.py` | Guarded feature branch push to `origin`. |
| `integrate_local.py` | Checked scratch merge and protected fast-forward into the starting checkout. |
| `watch-tests.py` | Polling test runner for source edits. |
| `commit_policy.py`, `commit_policy.json`, `ticket_adapters.py` | Commit message policy: PreToolUse hook, git `commit-msg` backstop, range and GitHub checks, GoodQA ticket verification and delivery comments, waivers. |
| `spec_flow.py`, `spec_policy.json`, `spec_template.md` | Spec-driven tickets: spec documents, spec reviews, per-criterion evidence, click-test records, sign-off and the done gate (CLI, plan-review ticket gate, PreToolUse hook on GoodQA status changes). |

No background process is installed. Claude Code runs hooks, and the main agent invokes the other helpers when appropriate. The installer refuses symlinked managed files and directories, including its backup directory, before reading settings or writing files. Reinstallation preserves unrelated hooks even when they share an entry with a managed hook. The installer rejects non-regular managed files (including FIFOs) and files occupying managed directory paths. It reads all source payloads before writing, then backs up the captured original bytes in private files before replacing managed files. It keeps original directory and managed-file inodes open through installation and rollback. A missing directory is created under a random staging name, opened and checked while empty, then published under its final name; the installer does not infer that a newly opened final name is the directory it created. Each file write compares the captured parent and file identity; a replacement is refused before mutation. The published file inode is recorded before the directory `fsync`, so a later write error can still roll back that file. A descriptor for each published managed file remains open through rollback so its inode number cannot be recycled while the guard relies on it. Reads, replacements, and rollback traverse parents without following symlinks, and each replacement rechecks the visible parent after publication. A parent that moves during installation produces an error rather than a success report. On a caught write failure it attempts to restore the original bytes and permission bits of existing files and remove newly installed files. Restoration continues after an individual failure; an incomplete rollback reports affected paths and the backup directory. Backups and newly created empty directories remain. This is per-file atomic replacement with best-effort rollback, not a crash-safe transaction: power loss, process termination, or a second failure during recovery can still require manual restoration. In an eight-process disposable contention test, some installers may refuse an intervening directory creation and succeed on retry; the final installation remains coherent. Concurrent settings editors can still race over read-modify-write settings, so do not run them together.

Before replacing a managed file, both installers also compare its current bytes and permission mode with the original snapshot. If either differs, they refuse the write and leave that path untouched. Rollback acts only on files this run published and refuses to replace or remove one whose published bytes or mode were edited in place. The backup contains the preflight snapshot, not a later external edit. A noncooperating editor can still write in the narrow interval between the final comparison and atomic replacement; filesystem rename has no portable compare-and-swap guard for file contents. Coordinate installers and editors if that race matters.

## WAL behavior

The `SessionStart` hook creates a private session log. Session and agent identifiers are reduced to `[A-Za-z0-9._-]` with a reserved escaped namespace and hash suffix for cleaned, truncated, uppercase, or reserved-prefix IDs so distinct values remain distinct on case-insensitive filesystems; the names `.` and `..` stay under `~/.claude/wals`. `UserPromptSubmit` logs prompt length, and `PreToolUse` logs tool metadata and target length. Neither logs the text or an unkeyed digest that could reveal a short input by guessing. `SubagentStart` creates a separate `agent-` log so an agent named `main` cannot alias the main WAL. The Claude hook and semantic-note writer omit the working directory from new records. Existing WALs are not rewritten; inspect older private logs if directory names need removal. Caller-authored notes and other helper records may still contain paths. Concurrent writers lock the file before appending a record. Prompt and pretool hooks use `onFailure: block`; a broken hook can stop those actions. Agents add semantic entries with:

```sh
python3 ~/.claude/hooks/wal_note.py --wal ~/.claude/wals/SESSION_ID/main.jsonl --event intent --note 'Brief intent without secrets'
```

Claude Code's `--safe-mode` disables customizations, including these hooks and `CLAUDE.md`. A safe-mode session therefore has no automatic WAL gate. A fresh normal headless session was smoke-tested after installation: it created `session` and `prompt` entries in a mode `0600` WAL.

Both WAL writers refuse symlinks from `.claude` down to the log, hardlinked logs, and non-regular files such as FIFOs. They open directories without following links, enforce mode `0700` on the WAL root and session directory, and mode `0600` on new and existing log files. If a concurrent first write gets `ENOENT` while creating the log, the writer retries at most three times with short delays. It verifies the pinned `.claude`, `wals`, and session directory components through their parent descriptors before retrying, then checks those components and the log file identity before writing and after `fsync`. Under the file lock, an append removes an unterminated final suffix left by an interrupted writer, then adds the next complete JSONL record. Recovery scans at most 64 KiB; a longer suffix fails closed for manual inspection without truncating the file. A removed or replaced path fails the hook. If a path moves during a write, a record may remain in the moved file even though the hook returns an error; inspect it before retrying. Mutation after the final identity check is outside this protection. Semantic note commands reject common credential-shaped values and assignments, including compound environment variable names, before writing. This guard cannot recognize every secret. Record redacted summaries, keep `~/.claude/wals` and `~/.agent-harness/codex-wals` private, review them before sharing, and do not commit them.

For behavior changes, use matching `PENDING_REAL_TEST <id>:` and `REALLY_TESTED <id>:` notes through `wal_note.py` before editing and after observation. Use `status` for the pending note and `check` for the verified note. The latter names the command or live steps, result, and applicable commit; any unmatched pending ID stays visible in the handoff. This is a concise audit trail, not an automated Stop gate. A disposable live slug-fix trial recorded `V1` before the edit, observed the baseline test fail, reran it successfully after the edit, and recorded the matched proof. A separate Stop-hook probe showed why the global gate was rejected: it ran on a simple arithmetic answer and forced an unnecessary second turn when configured to demand a test.

## Usage guard

Both editions install the same standard-library helper: `~/.claude/hooks/usage_guard.py` or `~/.codex/agent-harness/usage_guard.py`. It guards commands routed through it. Direct shell commands and native agents remain workflow-governed; no daemon, global Stop gate, permission reduction or distributed account enforcement is installed. Tiny fixes need no new receipt or model call.

State defaults to `~/.agent-harness/usage`; set `AGENT_HARNESS_USAGE_DIR` or global `--state-dir` to an owned private directory outside the worktree. Directories are `0700`, records `0600`. START precedes command execution; its metadata reference is emitted on stderr before the child starts. Stdout carries one final JSON result. FINAL records the observed execution/result/reason and a separately held digest reference. Inspecting a START reference is historical/UNKNOWN, not a claim that a process is still running. A missing FINAL is unknown, including after supervisor death. A session ID, PID, log text or exit zero is not completion proof. The main agent keeps foreground ownership through completion and hands off receipt paths and the actual responsible owner.

An input manifest is a mode-`0600` private JSON file, at most 32 KiB. Declare relevant public runtime instruction/config/schema/fixture/expected-record files and opaque revisions for secret-dependent configuration. Do not include credentials or hash secret inputs. For example, replace the paths and executable digest with verified values:

```json
{
  "schema": 1,
  "complete": true,
  "deterministic": true,
  "public_arguments": true,
  "files": [{"label": "instructions", "path": "/private/runtime-instructions.md", "public": true}],
  "revisions": {"config": "reviewed-config-revision-1"},
  "toolchain": {"python": {"executable": "python3", "public": true, "sha256": "REPLACE_WITH_VERIFIED_EXECUTABLE_SHA256"}},
  "environment": {"CI": "1", "LANG": "C"},
  "target": "local"
}
```

Toolchain entries identify an absolute `path` or an `executable` resolved through PATH, with an expected SHA-256 and explicit public declaration. A bare version string cannot verify executable identity. Relevant environment declarations are bounded nonsecret values from `CI`, `LANG`, `LC_ALL`, `TZ`, `PYTHONHASHSEED` and `NODE_ENV`; never dump the environment. Known helper files are included as runtime inputs. A missing/incomplete manifest, dirty or unknown input, unverified toolchain or secret-dependent input without a safe revision prevents reuse. Fingerprints cover declared dependencies, not universal discovery. HEAD changes invalidate conservatively even when tree bytes match.

Run focused test evidence with a finite timeout:

```sh
python3 ~/.codex/agent-harness/usage_guard.py check --repo /absolute/worktree --manifest /private/inputs.json --purpose feature-focused --owner owner-a --label focused --timeout 300 --kind focused --adapter unittest -- python3 -m unittest discover -s tests -p 'test_feature.py' -v
```

Replace `test_feature.py` with the actual module for the focused change.

Adapters require a recognized terminal result and nonzero observed executed count; zero cases or ambiguous output are NO_RESULT. The supported test formats are unittest summaries, pytest summaries and Go JSON test events. A non-test command needs `--kind command --adapter command --success-exit 0`, an explicit exit predicate rather than a claim about test coverage. Assertion findings, compile/process failures, provider errors and unknown results remain distinct. Receipts omit raw argv, prompts, source/log tails and credential values.

The helper retains typed outcomes/counts and receipt references only; it does not automatically retain raw child output or offer a log-file option. Arrange repository-native reports or a separate caller-owned logging/supervision path before a run when diagnostic output is needed. Capturing only the helper's stdout/stderr captures its final JSON and START metadata, not the child's raw test logs. Inspection/reuse commands can succeed administratively while evidence is unknown or ineligible: read the typed execution/result and reuse eligibility rather than treating their exit zero as check success.

A review FINAL records its historical provider outcome and remains provisional until the review's publication and final input checks settle it. Gate and reuse checks require that settlement. A later detected finalization failure appends an immutable invalidation; the historical FINAL is preserved and cannot authorize validation or cached acceptance. Missing or inconsistent START/history references and damaged pool state require diagnosis; ordinary reconciliation does not repair corrupted evidence.

A guarded `--kind full` run additionally needs `--gate RUN_ID:final:SHA256` naming accepted current subject-matching CODE_INSPECTION evidence with no open material findings. Review and test argv differ, so this gate matches the subject; reuse requires the exact invocation. If using verified native evidence or a bounded pre-review investigation, supply an explicit `--ungated-reason` that names the evidence/reason. It remains recorded as ungated and never becomes a helper approval. This does not waive required full validation. Freeze runtime files/docs before full execution; record late results in private/PR receipts.

```sh
python3 ~/.codex/agent-harness/usage_guard.py inspect --reference RUN_ID:final:SHA256
python3 ~/.codex/agent-harness/usage_guard.py gate --repo /absolute/worktree --manifest /private/inputs.json --reference RUN_ID:final:SHA256
python3 ~/.codex/agent-harness/usage_guard.py reuse --repo /absolute/worktree --manifest /private/inputs.json --purpose feature-focused --reference RUN_ID:final:SHA256 -- python3 -m unittest discover -s tests -v
```

CLI references use the printed receipt fields as `run_id:record:sha256`. REUSED references original scope, timestamp and result. It does not execute a command, create CHECK_OK, sign off a PR, substitute a prior-head approval or replace mandatory fresh validation. Failed evidence remains historical failure. An identical completed/reserved invocation is refused before another launch. One explicit `--repeat-reason` can spend the remaining declared aggregate budget; it cannot clear an unknown active reservation.

Missing FINAL, interrupted/unknown execution and stale pool ownership require diagnosis and an explicit append-only acknowledgement:

```sh
python3 ~/.codex/agent-harness/usage_guard.py reconcile --run RUN_ID --actor owner-a --reason 'Owned process and logs reconciled' --evidence 'private-evidence-reference'
python3 ~/.codex/agent-harness/usage_guard.py ack-pool --provider codex --pool default --actor owner-a --reason 'Availability change verified' --evidence 'private-evidence-reference'
```

These actions retain history and record actor/reason/evidence; they never manufacture successful execution. Acknowledging availability is separate from reconciling an active owner. Quota/auth cooldowns apply only to cooperating callers sharing this state directory and the configured opaque provider/auth-pool alias. Aliases do not derive from credentials. Trusted account errors can set a cooldown; vague credit messages, model-specific availability and tool content cannot disable the whole pool. A reliable reset hint can permit a later call after its reset; otherwise availability needs recorded evidence, with no polling, purchase or automatic model-switch loop.

Before expensive commands, disk probes cover work/build, temp and receipt filesystems. Default floors are 2 GiB for compile/test work and 256 MiB otherwise, with `--minimum-free-bytes` for a declared override or known higher peak. Missing data or low space prevents launch. Floors are not predictions and are subject to concurrent consumption. No automatic cache deletion or broad process killing occurs. Process-group cleanup retains its existing detached-descendant limitations. Hashes/permissions catch accidental staleness or mutation; same-user receipts are cooperative evidence, not signed attestations.

## Review and rescue

```sh
python3 ~/.claude/hooks/peer_review.py plan --repo /absolute/worktree --packet ~/.agent-harness/work/SESSION_ID/TASK/plan.md --output ~/.agent-harness/work/SESSION_ID/TASK/plan-review.md
python3 ~/.claude/hooks/peer_review.py code-inspection --repo /absolute/worktree --packet ~/.agent-harness/work/SESSION_ID/TASK/code-packet.md --output ~/.agent-harness/work/SESSION_ID/TASK/code-review.md --expected-head FULL_COMMITTED_SHA
python3 ~/.claude/hooks/peer_review.py pr --repo /absolute/worktree --packet ~/.agent-harness/work/SESSION_ID/TASK/pr-packet.md --output ~/.agent-harness/work/SESSION_ID/TASK/pr-review.md --expected-head FULL_COMMITTED_SHA --snapshot-base FULL_MERGE_BASE_SHA
```

All three review stages require a clean worktree; code inspection and PR review bind the expected HEAD. PLAN_RESULT and CODE_INSPECTION_RESULT use ACCEPT/BLOCK, while only a fresh PR can emit its pass marker. Code inspection examines implementation with full validation explicitly pending; final PR review checks the fresh full evidence and every delta. The external packet is untrusted evidence, not executable instructions. Both Sol and the blind Opus fallback run from the same private, detached Git checkout of the observed commit. The checkout holds only that commit and one base commit (depth 1), so its size follows the reviewed trees rather than the repository's history. The base defaults to HEAD's first parent so reviewers can check the packet's diff with `git diff BASE HEAD`; pass `--snapshot-base FULL_SHA` (an ancestor of HEAD, usually the merge base) to diff a whole branch instead. Other history is absent, `HEAD^` does not resolve, and the reviewer prompt names the base. The source checkout's ignored files and vendor directories, local configuration, refs, hooks, history, and unrelated objects are not copied into that checkout. Tracked vendor files and other committed files of the reviewed commit and base are review inputs: do not commit credentials or private material to them.

Snapshot preparation uses a fresh Git repository and a local depth-1 fetch of the exact commit (and base). Fetch verifies every received object ID; the helper then requires the snapshot commit and tree IDs to equal the source's, requires every named commit that has parents to be a shallow boundary, and allows no other boundary. Inherited Git routing variables and global/system configuration are disabled for preparation, verification, and reviewer processes; templates, hooks, replace objects, and lazy fetching are disabled. Source-local Git configuration is inspected before source status: executable local/worktree filters (including conditional includes), hidden index flags, and gitlinks are refused. Source status also forces ordinary stat, executable-bit and symlink-type checks and includes all untracked files. This is a bounded guard against known execution and concealment paths, not an OS sandbox or a guarantee against source configuration changing after preflight. Shallow/partial repositories, alternate object stores, grafts, and a reviewed tree containing gitlinks are refused. Committed symlinks are checked out in the snapshot as regular files whose content is the link-target text (`core.symlinks=false` for the snapshot and the reviewer processes only), so a reviewer reads the target path but cannot follow it outside the snapshot; the snapshot state check refuses any real symlink in the snapshot worktree, including inside ignored directories, and the reviewer prompt says how symlinks are shown. Disabling global ignore rules can reveal previously ignored files as untracked and require cleanup before review.

The helper compares source HEAD, Git status, and tracked diff before preparation, before review, and after snapshot cleanup. It rejects index flags such as `assume-unchanged` and `skip-worktree` that can hide tracked edits from Git status and diff; the NUL-delimited index listing has a five-second, 40 MB, 250,000-entry budget and does not read tracked file contents. It also checks snapshot HEAD and cleanliness before and after review. Special-file metadata scanning skips ignored directories without opening their contents and retains limits of 250,000 entries, 64 levels, five seconds, and 1 MB of ignored-directory names. The base ancestry check, snapshot fetch, tree listing and checkout share one `--snapshot-timeout` deadline (default 1800 seconds, at most 7200); metadata commands keep short fixed deadlines. The snapshot is prepared before the usage reservation, so a slow or failed snapshot launches no provider and leaves no reservation to reconcile. A very large reviewed tree still costs its full checkout size, with no byte or disk quota, and the post-checkout snapshot state check keeps the fixed status and metadata-scan limits described below. Cleanup must succeed before report publication, and reports identify the reviewed SHA and isolated input. These checks are not an OS isolation boundary: a process able to mutate the snapshot or access arbitrary external paths is outside this guarantee. Changes made and reverted between guards and changes after the final check remain outside the gate.

Report finalization reopens the published path without following symlinks, then compares its inode, bytes, size, mode, and link count with the private written report before either caller announces success. The comparison has a narrow final-check-to-announcement window; a later external edit can invalidate a previously successful report, so consumers still verify the exact reviewed SHA and report contents when using it.

Peer-review reports also name `Reviewed packet SHA-256`, calculated from the raw packet file bytes before text decoding for the reviewer. The helper keeps the original packet inode open and rechecks its identity, metadata, and bytes after review, immediately before the public report link, and before announcing success. To rely on stage acceptance, require helper exit 0, verify the stage and reviewed HEAD, and compare the header with the **current packet file's raw-byte SHA-256**. Only PR acceptance is PR signoff. A report without this header predates packet binding and cannot establish which packet bytes were reviewed. There is no atomic operation joining a packet check to the report link: a packet mutation immediately after that check can leave a historical digest-bound PASS file while the helper returns 2. Preserve that file, treat the attempt as failed, and retry with a fresh output path. A transient change entirely between checks may also escape detection; coordinate other packet writers while reviewing.

Exit 0 means acceptance for the named stage, 3 means a material block, and 2 means no valid review. PLAN_RESULT/CODE_INSPECTION_RESULT acceptance never becomes a PR PASS. Set `CODEX_REVIEW_MODEL` to override the Codex model used for review; the rescue model is fixed. The reviewer and rescue helper require one regular, unlinked packet file of at most 150 KB and put private reports outside the Git worktree, preferably in a private directory owned by the user. Give each attempt a fresh output path; an existing file or directory is preserved and rejected before any model call. The report writer pins its output directory, rechecks its identity before and after publication, and creates the final file atomically without replacement. It refuses a file created while a model runs or a directory moved during that run, with a nonzero exit; a rescue may already have edited or committed its worktree when report creation fails, so inspect it. If a directory moves after publication, a report may remain in the relocated directory; the helper never unlinks the public destination on failure because another writer could replace it. An old PASS report is historical evidence and must never be treated as the result of a failed new attempt; check the helper exit code and the fresh path together. Temporary-file cleanup and rescue result WAL append complete before the final directory/file identity check immediately preceding the success announcement; pinned directory and report descriptors remain open through that check. A WAL append failure also returns nonzero and directs worktree inspection. A result WAL entry describes model/worktree results, not proof that report finalization succeeded. The reviewer requires a worktree root; the rescue helper also requires a clean named branch. The reviewer reads the packet and repository. Do not include secrets or personal data in either. A PASS is advisory evidence, not proof that checks were run or that every defect was found. Reviewer and rescue model subprocesses use process-group cleanup after their deadlines; a deliberately detached child can still escape it. The rescue helper reads Astra's optional handoff only from a regular, singly linked file of at most 1 MB, opened without following symlinks or blocking on pipes. An unsafe or oversized handoff blocks report readiness and leaves the worktree for main inspection.

The review helper normalizes supported Codex JSONL and Claude JSON/JSONL terminal envelopes before extracting a verdict; structured errors, unsuccessful completion, malformed output and nonzero exit cannot sign off despite embedded pass text. Legacy plaintext uses strict stage/verdict markers. A wrong-stage marker is invalid output. It launches at most one primary and one authorized independent-provider fallback, with `--timeout` between 1 and 720 seconds per call and at most 1,440 seconds of provider execution; a fallback receives only the remaining budget. Invalid output and code findings do not spend a fallback call. Codex `Reconnecting... N/M` error records are treated as progress, and a plain `error` record repeated verbatim by the final `turn.failed` is classified by that final record. The final Codex error record of a transcript with no completion or agent message, carrying no structured code, type, subtype or scope, counts as an auth failure, which may use the fallback, only when its own message carries an explicit `401`, `unauthorized` or `revoked` signal (for example a revoked refresh token); that prose-derived classification never places an account-pool cooldown, and model or tool output is never inspected for it. Without a cooldown, later runs on a revoked token still spend Codex's reconnect attempts from the shared provider budget before falling back. Use `--input-manifest` for declared runtime identity and `--pool`/`--fallback-pool` for opaque auth-pool aliases; a model override cannot bypass same-pool cooldown. One explicit `--repeat-reason` may spend the remaining immutable-purpose budget. Token/money usage is recorded only if reported by the provider; no dollar/token cap or zero charge on early cancellation is promised. `--packet-budget-bytes` can tighten the 150,000-byte ceiling; 32 KiB and exact duplicate fenced-block warnings are advisory and never rewrite signed bytes.

The main agent can invoke `rescue.py` after repeated material findings, only in a clean rescue worktree and with a self-contained packet. A successful rescue still needs main-agent verification and final review.

The rescue wrapper does not stage or commit leftover model edits. It always exits 3 after a valid model attempt, including a clean committed descendant reported as `needs-main-verification`; exit 0 is never a rescue success signal. The isolated worktree and its existing Git index remain in place. Main must independently inspect the preserved worktree, branch, commit ancestry, file types and contents, and test evidence, then obtain final review before integration. If the model leaves a dirty worktree, the report says `needs-main-commit`; main must test and commit the preserved work. Any failed Astra invocation preserves the worktree for main inspection instead of triggering Fable. Fable is used only when the Astra executable is unavailable and the worktree remains unchanged under Git inspection; the main agent must give this worktree exclusive ownership. The wrapper compares `.git/info/attributes`, `.git/info/exclude`, and repository-local configuration values for their alternate paths while selecting fallback and reporting status. It does not pin the alternate files' contents or worktree-scoped configuration, nor attest to raw file bytes under every pre-existing attribute or stat-cache combination; a `needs-main-verification` report is only a handoff. Keep the report's `exit` field distinct from the helper exit: it records the model's exit code.

## Delivery workflow

Both editions install the same delivery implementation and dependencies. Claude uses `~/.claude/hooks/deliver.py`; Codex uses `~/.codex/agent-harness/deliver.py` and needs no Claude installation. Remote delivery also needs an authenticated Git transport and GitHub CLI (`gh`). The helper never merges a remote PR. Repository review, authorization and scope checks remain the main agent's responsibility.

Create private mode-0600 input files outside the worktree, in the durable session work directory the hooks announce (`~/.agent-harness/work/SESSION_ID/`) rather than `/tmp` or the scratchpad, so a reboot cannot destroy a run kit that a later `finish --resume` must reproduce byte for byte. A run kit records real commands; its text is validated but never executed by this helper. For example, replace these with the repository's actual verified instructions:

```json
{"run":"python3 -m app","test":"python3 -m unittest discover -s tests -v","watch":"python3 ~/.codex/agent-harness/watch-tests.py --root /absolute/original -- python3 -m unittest discover -s tests -v","logs":"Read the terminal test output","stop":"Ctrl-C"}
```

After final source review and tests, prepare the feature and draft PR:

```sh
python3 ~/.codex/agent-harness/deliver.py prepare --task OWNER_TASK --source /absolute/feature --original /absolute/original --original-branch main --expected-source-head FULL_REVIEWED_SHA --expected-original-head FULL_CAPTURED_SHA --kit-file ~/.agent-harness/work/SESSION_ID/TASK/kit.json --pr-title 'Reviewed scope' --pr-body-file ~/.agent-harness/work/SESSION_ID/TASK/pr-body.md
```

The effective fetch and push identities of both checkouts must be the same supported GitHub repository. Publication binds that identity inside the publisher before network effects; a policy refusal cannot become local fallback. `PR_READY` records the reviewed source, run-kit digest, PR number, generation and state path. It leaves the original checkout unchanged. Once the normal repository process has merged the PR:

```sh
python3 ~/.codex/agent-harness/deliver.py finish --task OWNER_TASK --generation GENERATION --original /absolute/original --original-branch main --mode remote --check 'python3 -m unittest discover -s tests -v'
```

Finish checks get their own deadline: `--check-timeout` (default 1800 seconds, at most 7200) bounds each preparation and check command, while `--timeout` (default 120) keeps bounding Git and GitHub commands. A bare `python` or `python3` check resolves through `PATH` to an absolute interpreter that must be Python 3.10 or newer. Finish checks this before any checkout effect and refuses an older or missing interpreter with `BLOCKED_POLICY`, naming the version found and asking for a supported `python3` first on `PATH`; each check run resolves and verifies the interpreter again. Remote finish, resume and `--resolve-baseline` stream check output to an owner-only log of at most 32 MiB under the generation's `checks/` directory, keeping the newest five logs (an older `check_log` path reported by an earlier attempt can therefore disappear). A failed or timed-out check there reports `check_log`, `check_status`, `check_log_truncated` and a 2000-character `check_tail`, with best-effort redaction of URL credentials, authorization headers, bearer and provider tokens, private-key blocks, cookies, and `KEY=value`, quoted JSON and `--flag value` secrets, and omits lines over 4000 characters; recovery responses carry the same fields. `integrate_local.py --resolve-journal` logs its checks under the journal's `checks/` directory the same way. Local-mode scratch and delivered checks still discard output. `integrate_local.py` accepts `--check-timeout` (default: its `--timeout`), which finish passes for local delivery. The full log is not redacted; treat it as private.

Remote finish verifies the PR's repository, branch, source SHA and merge commit. It fetches the exact advertised target through private bare transport, using the original object store without reading source-local routing configuration. The borrowed-store context explicitly disables automatic maintenance/GC and fetch commit-graph writing, and advertises available original/baseline/source negotiation tips. A real-Git regression uses aggressive maintenance and split packs to verify all prior objects survive; another verifies incremental object transfer, including cached feature history. It accepts only clean original history between the captured baseline and pinned target, reserves a shared recovery barrier and target ref, then uses hook-disabled `--ff-only --no-overwrite-ignore --no-autostash`. After exact merged-PR proof, the feature worktree may be removed or reused. Checks run in the actual original checkout. Concurrent remote advancement is accepted only after fetching the observed tip and proving the pinned target is its ancestor. The checkout and receipt stay at the pinned tested target; `remote_observed_head` identifies the later observation without claiming its code was delivered. Failed commands report observed HEAD even if Git advanced before returning an error; recovery evidence remains and blocks other tools on that original scope.

A saved `REMOTE_BLOCKED` generation permits `finish --mode local`; not every network-error response settles the generation. Explicit local-only work uses `prepare --local-only` (PR title/body are then optional) before local finish. Local delivery requires worktrees of the same repository, uses the scratch helper below, and leaves remote publication outstanding. `REMOTE_UNCERTAIN`, unsupported origins and policy refusals cannot silently unlock fallback. Missing origin is a definite remote blocker. Continue independent local work when remote access is unavailable.

Publication/create intents survive process loss. Query-only `prepare --reconcile-only --task OWNER_TASK --original /absolute/original --original-branch main` verifies an exact remote outcome without push, PR creation or checkout mutation, even when the source checkout has moved. Known PR numbers are queried exactly; inaccessible/ambiguous outcomes stay uncertain. A possible create is never disproved by a temporary empty list, malformed response or missing feature ref: it needs positive matching PR evidence. Durable `PUBLISHING` and `PR_LOOKUP` phases distinguish a push from a not-yet-attempted PR create. Explicit preflight failure before any push can settle `REMOTE_BLOCKED`; a definite push rejection or pre-create policy refusal settles `POLICY_BLOCKED`, permitting a new reviewed generation without local fallback. Fork/foreign PRs with the same branch name are excluded from owned matches. PR enumeration is capped at 101 records, rejecting more than 100, with bounded output and API deadlines. Publisher parent time is bounded to cover its fixed sequential per-command budgets; its deadline test uses a synthetic two-stage elapsed-time model, separate from real Git behavior tests. New reviewed source/run-kit inputs use `--new-generation` only after the prior generation is settled; older generations are stale and cannot mutate the current task.

Workflow state is private metadata beneath `<git-common-dir>/agent-harness/delivery-workflows`, separated from scratch journals and independent of HOME/session. One task lock serializes workflow receipt changes; the existing original-checkout lock serializes actual applies across tools. The local child owns that original lock itself so parent/child do not deadlock. A fresh local generation can retry a previously resolved identical baseline/source tuple; the child preserves the prior attempt in archive history. Only the guard API's explicit `reservation_started is False` proof permits returning a failed pre-reservation attempt to `PR_READY`; unknown or partially written own attempts retain recovery. A remote target remains reachable through an owned ref. Successful receipts are immutable and written only after checks; `ALREADY_DELIVERED` validates the historical delivered commit in a clean current original without silently syncing newer remote work. Full run-kit/body text and check-command text are not persisted in workflow receipts.

A moved, copied or restored checkout can have a different filesystem identity even when its path or files look unchanged. A saved generation/guard from another identity is not permission to rewrite scope identifiers or reset state. Stop, preserve the original records and diagnose the mismatch. A fresh owned checkout and fresh reviewed transaction may be appropriate; the helper does not migrate safety journals automatically.

An interrupted remote finish can be resumed explicitly when its known pending guard belongs to the exact current generation and the original is already clean at that guard's pinned target:

```sh
python3 ~/.codex/agent-harness/deliver.py finish --task OWNER_TASK --generation GENERATION --original /absolute/original --original-branch main --mode remote --resume --resume-reason 'Checks interrupted after sync' --kit-file ~/.agent-harness/work/SESSION_ID/TASK/kit.json --check 'python3 -m unittest discover -s tests -v'
```

Supply the same run kit and ordered preparation/check commands. Verify the project's interpreter and dependency prerequisites first and stop on a failed prerequisite; an unchanged command digest does not prove toolchain readiness. Declared `--prepare` commands run before checks, and a failing preparation prevents the test child from starting. Resume holds one original-checkout lock throughout read-only guard validation, fresh merged-PR/remote proof, fresh checks and durable completion. It never moves the checkout, selects a newer target, creates another guard or treats an earlier check as fresh success. Other recovery barriers, dirty/non-target state, changed bindings and resolved guards are refused before checks. Ordinary pending refusal remains unchanged.

Private per-attempt records beneath the workflow generation's `resumes` directory identify the followup executor revision/helper digests separately from the historical reviewed source and kit. Keep the reason free of secrets. A start without a final result, or a guard resolved before its workflow receipt completed, requires diagnosis; it is not delivery evidence. A reviewed followup helper can be invoked from its checkout before a global installation.

A failed apply that is not eligible for explicit resume requires inspection. Resolve actual shared journals using the lower-level helper's explicit `--resolve-journal KEY` below, at a full confirmed clean HEAD with real passing checks. `RESOLVED` accepts a baseline while retaining artifacts and actual pin-state facts; it proves no delivery. If the workflow stopped before binding its child/guard result, after all actual barriers are resolved use:

```sh
python3 ~/.codex/agent-harness/deliver.py finish --task OWNER_TASK --original /absolute/original --original-branch main --resolve-baseline FULL_CONFIRMED_SHA --check 'python3 -m unittest discover -s tests -v'
```

Only known interrupted apply phases can make this transition. Exact clean HEAD, passing nonvacuous checks, unchanged generation/state and no shared unresolved barriers are required. `RESOLVED_BASELINE` preserves every record/ref and writes no delivery receipt; start a new reviewed generation and finish with fresh proof. It cannot settle unknown push/PR outcomes.

No global Stop hook claims these steps occurred or blocks ordinary questions/background work. The main agent must call the helper and inspect the actual result. The run kit also needs useful user-facing instructions: verify a repository-native watcher or the installed dependency-free watcher (`~/.codex/agent-harness/watch-tests.py` or `~/.claude/tools/watch-tests.py`). Use `--once` to verify setup, omit it for continuous testing and Ctrl-C to stop. The helper cannot judge whether those commands are useful. Local scratch and remote checks execute repository code and are not an OS sandbox; same-user external mutations and changes reverted entirely between guards remain outside the guarantee.

## Commit message policy

Every agent commit uses one structured format, and the commits in ticket-tracked repositories must reference a ticket that was updated after the commit. The rules live in one file, `commit_policy.json`, installed beside the hooks: `~/.claude/hooks` for Claude Code and `~/.codex/agent-harness` for Codex. Edit that file to change the types, the sections, the boilerplate lists, the tracked repositories or the ticket systems.

```text
fix(deliver): refuse non-compliant commit ranges before publication

Why: an agent reverted two production auth fixes with no recorded reason.
What: prepare checks the owner's commit range and blocks violations.
Testing: `python3 -m unittest tests.test_commit_policy` -> 42 passed
Refs: GoodQA #14151
Risk: optional; migrations, rollback

Co-Authored-By: ...
```

### Message rules

- **Subject.** Write `<type>(<scope>): <imperative summary>`, at most 72 characters, with no trailing period.
  - Allowed types: `feat fix refactor perf test docs build ci chore revert security`.
  - Summaries in the boilerplate list are rejected, such as `wip`, `update` and `various fixes`.
- **Body sections.** After a blank line, write `Why:`, `What:`, `Testing:` and `Refs:` in that order. `Risk:` is optional.
  - A section is rejected if it is empty, holds a placeholder, or is too short.
- **Testing.** Name the exact command and its result. Bare text like "tests pass" is rejected. If you didn't test, write `not run: <reason>`.
- **Refs.** Reference a GoodQA ticket as `GoodQA #N` (project `goodqa`) or `GoodQA <project-slug>#N`.
  - PR references and `R-NNNNNN` coordinator records are recognized. They do not count as a ticket, because they cannot be verified.
  - In tracked repositories (origin matches `ticket_systems.*.repos`), only `chore` and `docs` may write `Refs: none (<reason>)`. Every other type needs a GoodQA ticket.
  - Other repositories accept `none (<reason>)` for any type.
- **Reverts.** A revert uses type `revert` and includes `Reason:` and `Authorized-by:` lines. In tracked repositories, `Authorized-by:` must cite the GoodQA ticket that records the authorization.
  - A commit is treated as a revert if its body says "This reverts commit", even when its subject uses another type.
  - The policy enforces a recorded and verifiable citation. It cannot prove that a human approved the revert.
- **Trailers** such as Co-Authored-By and Signed-off-by come last, after a blank line.
- **Repeats.** A message identical to the previous commit's message is rejected.
- **Exemptions.**
  - Only real merges are exempt: a merge in progress (`MERGE_HEAD`), or a commit with more than one parent in a range. A single-parent commit whose subject starts with "Merge" is judged like any other, and so is a `gh pr merge --squash` message.
  - `fixup!`, `squash!` and `amend!` commits are allowed only on an unpublished branch. The publication check always rejects them.

### Enforcement points

1. **PreToolUse hook** (`commit_policy.py hook`). It runs before each Claude Code Bash call and each Codex tool call.
   - It reads the message from the forms it can check without running anything:
     - `-m` (repeated) and `-am`;
     - `--message=`;
     - `-F <file>` and `-F -` with a quoted heredoc;
     - `-m "$(cat <<'EOF' ... EOF)"`;
     - `--amend --no-edit`, which checks HEAD's message;
     - `-C <commit>`;
     - `--fixup` and `--squash`;
     - `gh pr merge --squash --subject --body`.
   - It fails closed with an explanation when it cannot know the message:
     - the message comes from `$VAR`, another `$()`, or an unquoted heredoc containing `$`;
     - the commit would open an editor;
     - `-F` names a file that does not exist yet;
     - the command is a bare `git revert`, `git commit-tree`, `eval`, or `gh pr merge --squash` without a subject and body;
     - git commit runs through another program (`xargs`, `find -exec`, `parallel`, `watch`, `sudo`, `env -S`), through a pipe into a shell (`echo ... | bash`), or under a command name computed at run time (`$G commit`);
     - a command that commits also runs a git subcommand that is not built in. That subcommand may be an alias, and the same command can define one (`git config alias...`, `GIT_CONFIG_*`);
     - another program in the same command touches the `-F` message file (`sed -i`, `python3 -c`, `truncate`, `>|`; reading with `cat`, `grep` or `git add` is fine);
     - the message could change after the check: `-e`/`--edit`, `--cleanup=strip|scissors`, or a `-F` file that the same command writes (redirect, `tee`, `cp`/`mv`/`install`, or a write to an unknown path);
     - git commit runs inside `$(...)` or backticks (for example `OUT=$(git commit ...)`), or `git history` rewrites messages;
     - an unknown git subcommand (possibly an alias) runs where the repository configuration is not visible: an unknown working directory, or over ssh.

   Shell keywords (`if`/`then`/`else`/`for`/`do`/`while`/`{ }`/`!`) and the wrappers `timeout`, `nice`, `ionice`, `stdbuf` and `caffeinate` (including their value flags) are unwrapped and checked. Shell options that take a value (`bash -o pipefail -c`, `--rcfile`, `-O`, `+o`) are understood. An alias call in a command that never contains the word `commit` (for example `git ci -m x`, locally or over ssh) is not analyzed. The git backstop catches it in tracked repositories on Git 2.54+, and the publication checks catch it everywhere. The same applies to deliberately obfuscated command names (for example `gi''t` inside a substitution). The hook guards against careless commits, not adversarial ones. A script file (`bash deploy.sh`) or a program such as `python3 -c` that commits is not visible to the hook. Outside dev2/T2 the git backstop covers those cases, and the publication checks cover them everywhere.

   It also analyzes `ssh <host> '<remote command>'`, `ssh <host> bash -s <<'EOF'` and nested `bash -lc` strings, which is where most dev2/T2 commits run. A remote host's files, HEAD and repository are not visible, so a remote `-F <file>`, `--amend --no-edit` or `-C` fails closed. Pass the message inline instead: `ssh host 'cd repo && git commit -F - <<"EOF" ... EOF'`. Remote commits are held to the ticket rule (`remote_tickets_required`).

   When it blocks, it lists the problems and prints a template that starts from your subject line.
2. **Git `commit-msg` backstop** (`commit_policy.py git-hook`). It is a Git 2.54+ config-based hook registered as `hook.agent-harness-commit-policy` (Claude) and `hook.agent-harness-commit-policy-codex` (Codex) in `~/.gitconfig`.
   - It runs alongside each repository's own hooks and never changes `core.hooksPath`.
   - It enforces only when both of these hold:
     - an agent marker is present (`CLAUDECODE`, `CODEX_THREAD_ID`, `CODEX_TOOL_CALL_ID`, `CODEX_SANDBOX` or `AI_AGENT`);
     - the repository's origin matches `backstop_repos`.
   - Everywhere else it stays silent: human commits, test fixtures, and other repositories that agents run.
   - The installer reports "backstop inactive" when Git is older than 2.54.
   - If the script is removed, the hook command exits 0.
   - Not verified live: that Codex shells carry a `CODEX_*` marker (Codex quota was exhausted while this was built). For Codex, the PreToolUse hook is the primary gate.
   - dev2 and T2 run git 2.43, which has no backstop. A user-local git was not installed there, because the hosts are shared and a source-built git on agent PATHs risks breaking https push, LFS and credential helpers. On those hosts the protection is the ssh-aware PreToolUse hook plus the publication checks (`deliver.py prepare`, `gh pr create`, `peer_review.py pr`).
3. **Publication check in `deliver.py prepare`.** It runs only when prepare is about to create a new generation. Re-entering an existing generation never repeats it.
   - **Range checked:** commits reachable from the reviewed head, excluding the baseline and `refs/remotes/origin/<branch>`, so upstream commits written by others are never judged. If upstream moved, run `git fetch origin` first.
   - **Ticket check:** each referenced GoodQA ticket must exist and must have a comment that names one of these:
     - The commit SHA (7+ hex characters). Such a comment necessarily postdates the commit.
     - The branch. This comment must be newer than the commit time minus `clock_skew_seconds`.
   - **PR text:** prepare also checks the PR title (at most 64 characters, so `title (#N)` fits) and the PR body (the same sections), because GitHub squash uses them as the final message.
   - **Results.** Neither failure creates delivery state.
     - `BLOCKED_COMMIT_POLICY` (exit 2) lists each failing commit and stale ticket, with the fix.
     - `TICKETS_UNVERIFIED` (exit 6) means GoodQA was unreachable or answered unexpectedly. The check fails closed.
   - **Projects the credential cannot see.** The member key reaches the FrameBright org only (`org_id` is pinned to it), so GoodQA answers `project_not_found` for Eric-org refs such as `GoodQA solve#7`.
     - Only projects listed in `ticket_systems.goodqa.unreachable_projects` (shipped: `solve`, `ai-course`, `harness`) are reported as `OUT_OF_SCOPE`. The ref still has to be well formed. The range passes with a warning naming `unreachable_reason`. `deliver.py prepare` and the PR-review gate print it; the `gh pr create` hook passes silently. Each warning is recorded once per ticket and head in `~/.agent-harness/commit-policy/warnings.jsonl`. finish skips the ticket's comment and lists it as not verified on the other tickets' comments.
     - Any other `project_not_found` fails closed as `TICKETS_UNVERIFIED`. That covers a typo, an invented slug, an Eric-org project not yet listed, and the default project `goodqa`, which is never treated as out of scope. A missing ticket in a project the key can see is still `MISSING` and blocks.
     - Adding a confirmed slug is a config change. Empty the list once durable cross-org access lands.
   - Local-only delivery verifies tickets too.
   - **Credentials.** The member key file `~/.claude/goodqa-hive/member.key` (mode 600) is used first and keeps full access: verification, plus the finish and `notify` comments. Never copy it to another host.
     - A host without that file (dev2) reads `key_secret` (Secret Manager `goodqa-api-key-framebright` in project `goodqa-28dd3`) in-process through `gcloud secrets versions access`. The value is never passed in argv or the environment, and never written to disk.
     - That credential is **read-only** in code: only `list_orgs`, `list_projects`, `get_issue_by_number` and `get_issue_comments` are allowed. Any write (a comment, a status change) is refused before a request is sent. On dev2, `prepare` and PR review therefore verify tickets, but finish's ticket comment stays pending (exit 5). Post it from the Mac with the printed `notify` command.
     - If gcloud cannot read the secret, verification fails closed (`TICKETS_UNVERIFIED`).
   - **Project-qualified refs.** `GoodQA #N` means the default project `goodqa`. Tickets in another project need its slug, for example `GoodQA work-tracker-automatic#35633`. A `MISSING` result says so.
   - **Legacy commits:** commits authored before `enforce_after` are reported as legacy and do not block.
4. **Delivery comments in `deliver.py finish`.**
   - After `DELIVERED`, `LOCAL_DELIVERED` or a repeat `ALREADY_DELIVERED`, finish comments on each referenced ticket once, with an idempotent operation id.
   - The comment opens with the stage, "Merged (not yet deployed or live)" or "Delivered to the local checkout only". It then lists the delivered SHA, the PR, the checks that passed, and any waivers used.
   - Exit 5 means the delivery succeeded but a ticket comment is still pending. Do not start recovery; re-run the same finish command or the printed `notify` command.
   - Deployment happens outside `deliver.py`. After a deploy, post the evidence:

     ```sh
     python3 ~/.claude/hooks/commit_policy.py notify --repo <checkout> --base <baseline> --head <source-head> \
       --seed <generation> --stage deployed --evidence '<where and how it was verified live>'
     ```

   - Status changes are off by default (`on_delivered_status` / `on_deployed_status`), because GoodQA's done states need independent acceptance.

### Checks, waivers and audit

- **Check a draft:** `python3 ~/.claude/hooks/commit_policy.py check-message --file msg.txt`
- **Check a range:** `python3 ~/.claude/hooks/commit_policy.py check-range --repo . --base origin/main --head HEAD --branch <branch> --verify-tickets` (exit 0 pass, 2 blocked, 4 tickets unverified; `deliver.py prepare` reports the last case as exit 6 `TICKETS_UNVERIFIED`)
- **Waivers.** A waiver is the only exception path. There is no environment-variable bypass.

  ```sh
  python3 ~/.claude/hooks/commit_policy.py waive --wal <your WAL> --kind message|commit|tickets --subject <digest-or-sha> --reason '<why and who authorized it>'
  ```

  - The waiver is appended to your WAL and indexed in `~/.agent-harness/commit-policy/waivers.jsonl`. A waiver counts only when both records exist. It expires after `max_age_hours`.
  - A `message` waiver applies only in the session that recorded it. A `tickets` waiver applies to one range head, which is the offline delivery path.
  - Waivers are self-attested. The threat model is careless or hurried agents, not adversarial ones: an agent can edit the installed hooks anyway. The `waive` command is not on the permission allow list, but Codex with `approval_policy = "never"` and Claude in bypass or broad-allow modes will not prompt.
  - Every waiver that gets used is listed in the reports and in the delivery ticket comment.
- **Audit:** `commit_policy.py report --since 2026-11-04` lists the waivers and flags any whose WAL record is missing. It also lists out-of-scope ticket warnings (`warnings`, `warning_count`).

### Rollout and rollback

- A malformed `commit_policy.json` blocks only commit-like commands, with an explanation. Every other tool call runs before the file is read. The PreToolUse handler's timeout is 60 seconds, because `gh pr create` consults GitHub and GoodQA (internal budget: 10 + 15 + 25 seconds).
- `enforcement` in `commit_policy.json` takes three values:
  - `enforce` (the default) blocks.
  - `warn` prints the problems and allows.
  - `off` turns every enforcement point off.
- **Remove the git backstop:** `python3 ~/.claude/hooks/commit_policy.py uninstall-git-hook`. For the Codex key, use `git config --global --remove-section hook.agent-harness-commit-policy-codex`.
- **Remove the PreToolUse hook:**
  - Claude Code: delete the `commit_policy.py hook` handler from `~/.claude/settings.json`.
  - Codex: delete it from `~/.codex/hooks.json`.

## Spec-driven tickets

Every want, need, finding or bug is a GoodQA ticket. When an agent picks one up, it writes a spec, gets the spec reviewed and attaches it to the ticket. As it works, it attaches proof for each acceptance criterion. After deploy, it attaches the click-test record. Once signed off, the ticket can be marked done.

The ticket is the record of truth. Each step posts one comment containing a readable summary and a fenced `harness-spec-record` JSON block, with its files attached. Attaching costs four calls: `file_upload_start` (project surface), a presigned `PUT`, `file_upload_complete` with the sha256, then `comment_on_issue` with `attachmentIds`. The done gate trusts a file only when `issue_attachments_list` shows it completed, on that comment, with the server-computed sha256 that the record names. Retries are idempotent: a record whose content key is already on the ticket is reported `ALREADY_RECORDED`, and the comment `operationId` is derived from that key.

```sh
S=~/.claude/hooks/spec_flow.py
python3 $S new --ticket 'GoodQA harness#168' --out ~/specs/168.md --author 'agent:<id> (<model>)'
python3 $S lint ~/specs/168.md
python3 $S packet ~/specs/168.md --out ~/specs/168.packet.md      # exact bytes a helper review must see
python3 ~/.claude/hooks/peer_review.py plan --repo <clean worktree> --packet ~/specs/168.packet.md --output ~/specs/168.adv.md
python3 $S review ~/specs/168.md --role adversarial --report ~/specs/168.adv.md
python3 $S review ~/specs/168.md --role acceptance --agent <red-team|task-owner|fixer id> --wal <main WAL> --verdict ACCEPT --report-file <its report>
python3 $S attach ~/specs/168.md --actor 'agent:<id>'
python3 $S evidence --ticket 'GoodQA harness#168' --actor 'agent:<id>' --ac AC-1 --really-tested RT1 --wal <WAL> [--commit <sha> --repo <checkout> --target origin/main] [--log run.log]
python3 $S click-test --ticket 'GoodQA harness#168' --actor 'agent:<id>' --agent-id <click-tester id> --wal-dir ~/.claude/wals/<session> --url <url> --deployed-commit <sha> --repo <checkout> --result pass --report <its report> [--log f] [--screenshot f.png]
python3 $S signoff --ticket 'GoodQA harness#168' --actor 'agent:<main id>' --by <main id> --kind agent --source '<where it was given>'
python3 $S done --ticket 'GoodQA harness#168' [--apply]          # status: same report, never writes
```

### Spec document

- **Header lines:**
  - `Ticket: GoodQA <project>#<n>`. The project slug is required; a bare `GoodQA #N` is rejected.
  - `Author: agent:<id> (<model>)`, `human:<name>` or `model:<name>`.
  - `Click-test: required` or `not-applicable (<reason>)`.
  - `Sign-off: main` or `human`.
- **Sections:** `## Outcome`, `## Scope`, `## Acceptance criteria`, `## Negative cases` and `## Risks`.
  - Each criterion is written `- AC-n: <observable result>. Verify by: <check>.`
  - Each negative case is written `- NEG-n (AC-n): ...`.
  - `lint` rejects a spec that has no criteria, duplicate ids, a criterion without `Verify by:`, a negative case that names an unknown criterion, an unedited `<placeholder>`, or an unrecognized bullet.
- **Reviews section:** `## Reviews` is generated from the sidecar `<spec>.reviews.json`. The *spec core* is everything above it, normalized to NFC and LF with trailing spaces trimmed. Reviews bind to the core's sha256. Editing the spec after review therefore makes its reviews stale, while regenerating the reviews table does not. Keep `## Reviews` last: `attach` refuses a spec with a section after it, since that section would be lost.

### Reviews

- **Two roles, distinct reviewers.** The `adversarial` and `acceptance` roles each need an `ACCEPT` on the current core.
  - The two reviewers must differ in model, agent or person. Two runs of the same helper model count as one reviewer.
  - Neither reviewer may be the spec author.
  - A later `BLOCK` for a role replaces an earlier `ACCEPT`.
- **Review sources:**
  - **Helper report.** A `peer_review.py plan` report. It must have `Stage: plan`, a body verdict `PLAN_RESULT: ...`, and `Reviewed packet SHA-256` equal to the core sha.
  - **Native agent.** A native agent id recorded by SubagentStart in the main WAL, plus its report file. Only `task-owner`, `click-tester`, `fixer` and `red-team` agents are logged. An adversarial review from a native agent requires `red-team`.
  - **Human.** A human name with `--source`. This is self-attested.
- **What `attach` uploads:** the spec, the reviews JSON and each review report. A report that changed since its review is refused.

### Evidence, click-tests and sign-off

- **Evidence** must name criteria of the attached spec. Proof is any of these; a note alone is not proof:
  - a `REALLY_TESTED <id>:` WAL note newer than its `PENDING_REAL_TEST`;
  - a log;
  - a commit plus a note naming the check.
- **Commits** must exist. With `--target`, they must also be reachable from that ref.
- **Logs:**
  - They are regular files; symlinks are refused.
  - A log longer than `max_log_bytes` (2 MB) is cut to its tail.
  - The text is redacted with `integrate_local.redact_output` (tokens, cookies, bearer, URL userinfo, keys).
  - A log is refused if private-key material remains, or if the cut lands in what looks like a key.
  - Screenshots and recordings (`png jpg gif webm mp4`, up to 15 MB) are checked by magic number and are not redacted.
- **Click-tests:**
  - Logs or a report are mandatory.
  - `--deployed-commit` names the commit that was deployed and tested. Every commit cited by evidence on the current spec must be reachable from it, or the record is refused. Evidence commits added later make `done` NOT READY until a new click-test covers them. This is a membership check, so it also applies when the later commit was already inside the deployed commit; rerun the click-test. The deployed commit is declared by whoever records the click-test and is not read back from the deployment, so `done` lists it under Self-attested.
  - The tester must be independent: a click-test whose tester is the spec author, a spec reviewer or anyone who posted evidence does not count toward READY.
  - **Agent click-tester:**
    - The agent must be recorded as `click-tester` in the session's `main.jsonl`.
    - The start time is its SubagentStart record. The end time is its first `subagent_stop` record (from the SubagentStop hook). If there is none, `ended_at` is null and `last_activity_at` is recorded.
    - A pass counts only if it comes from the click-tester: its report (first line `CLICK_TEST_RESULT: PASS|FAIL`, matching `--result`) has its sha256 noted in the agent's own WAL, or `--really-tested <id>` is found there.
  - **Human click-tests** are self-attested.
- **Sign-off:**
  - It must come from someone other than the spec author, either spec reviewer, a click-tester, or anyone who posted spec, evidence or click-test records. By default this is the main agent. When the main agent directed the work, its independence is nominal; ask for `Sign-off: human` when that matters.
  - It must be `--kind human` when the spec says `Sign-off: human` or the ticket text says "human sign-off".
  - The sign-off identity is self-declared.
  - GoodQA labels agent comments made through a user token as human, so comment authorship never proves a human.

### Done gate

`done` reports READY only when all of the following hold:

- a verified spec is attached: its record carries the spec file (matching `spec_file_sha`), the reviews file and at least one criterion;
- both reviews `ACCEPT` that spec's core;
- every criterion has evidence on that core;
- the evidence on that core cites at least one commit and attaches at least one execution log (this applies to every ticket, including documentation-only work: cite the docs commit and a check log);
- the latest click-test on that core passed with logs, by an independent tester, at a deployed commit containing every evidence commit (unless the spec says not-applicable); a click-test of an older spec version is stale;
- a valid sign-off exists on that core.

Otherwise it lists each missing item with the command that fixes it. Under "Self-attested" it lists every check that rests on a name the helper cannot verify.

**Exit codes:**

| Code | Meaning |
|---|---|
| 0 | READY, or `--apply` on a ticket that is already done (`ALREADY_DONE`, safe to retry) |
| 2 | Missing items, a refused record, a `lint` failure, or a command-line error from the argument parser |
| 3 | Spec or input error found after parsing (for example a stale review, a refused log file, an unknown criterion) |
| 4 | GoodQA unreachable, or the page budget ran out (fail closed) |
| 5 | `--apply` was refused by GoodQA (`TRACKER_REFUSED`); the ticket is left unchanged |

GoodQA's own independent-acceptance rule for done transitions still applies.

### Gates

1. **Ticket at plan review.** In tracked repositories (origin matches `ticket_systems.*.repos`), `peer_review.py plan` needs a `Ticket: GoodQA <project>#<n>` line naming a ticket that exists. The check is controlled by `plan_ticket_gate` in `spec_policy.json`:
   - `warn` (the shipped default) prints the problem and continues.
   - `enforce` stops before any reviewer launches, with exit 2.
   - An unreachable GoodQA gives `TICKETS_UNVERIFIED` (exit 6 in enforce mode). A commit-policy `tickets` waiver for subject `plan-<packet sha256[:20]>` covers that case.
   - Commits are already held to `Refs:` by the commit policy.
2. **Done at the tracker call (Claude Code).** A PreToolUse hook (`spec_flow.py hook`, timeout 60 s, `onFailure: block`, internal budget `hook_deadline_seconds` = 40) watches `close_issue_done`, `close_issue_wont_fix`, `update_issue`, `bulk_update_issues`, `archive_issue`, `reassign_issue` and `call_api`.
   - **Allowed without a network call:** open statuses (triage through `on_production`, which GoodQA documents as nonterminal) and `update_issue` without a status.
   - **Gated by the spec:** `done`.
   - **Need a reason:** `wont_fix` and `duplicate` need one of at least 20 characters.
   - **Warn mode:** the hook allows the call and returns its findings as `additionalContext`, which Claude Code shows the agent next to the tool result (plain stderr from an allowing hook is never shown to the agent). It makes no permission decision, so normal permission rules still apply.
   - **Blocked:** an unknown status, archiving an open ticket, a project, pipeline or stage move (`reassign_issue`, or `projectId`, `pipelineId` or `stageId` in an `update_issue` patch), and a `call_api` DELETE on an issue.
   - **`call_api` writes:** every non-GET `call_api` call is unchecked unless the hook recognises it, and an unchecked call warns, or blocks while any project is enforced. The path is lowercased first, so a mixed-case path is gated like the canonical one; a path without a leading `/`, or with a query, fragment, `%` escape, backslash, or empty or dot segment, is unchecked. Recognised shapes: an exact `/issues/<uuid>` path with an object body whose fields are all known (`status` and `patch.status` are gated like `update_issue`, and two different values or an explicit null are an unknown status, `projectId`/`pipelineId`/`stageId` as a move, and descriptive fields such as `title`, `priority` and `labels` pass; any other field, such as `archivedAt` or `action`, is unchecked); the exact `/comments`, `/attachments` and `/time-entries` sub-paths (allowed unless the body carries a status); a collection write with an `items` list (checked like `bulk_update_issues`); and a plain create (`POST /v1/issues` or `/v1/projects/<uuid>/issues` with no status, patch, items, id or filter keys), which blocks only when the path names an enforced project. Routes that do not name issues (projects, stages, other resources) are unchecked too, because the hook cannot tell whether they move or close issues.
   - **Bulk calls:** every item in a bulk call is checked, and one failing item blocks the call.
   - **Where it blocks:** only in `mode: enforce`, and only for `enforced_projects`. Everywhere else it prints what is missing and allows the call.
   - **Unreachable GoodQA:** a transport failure blocks only in enforce mode when enforced projects are configured. The status write goes to the same service, so blocking it costs little.
   - **Refused key:** if any routed key gets `forbidden` reading the issue (a revoked or rotated key, or lost membership), the hook blocks in enforce mode while any project is enforced, and names `doctor`. Re-run `doctor` for each enforced project after any key or membership change.
   - **Non-uuid issue id:** a missing or non-uuid `issueId` blocks while any project is enforced. Only `update_issue` and `reassign_issue` declare `issueId` as a uuid; the other tools only describe it as one.
   - **Issue not found:** GoodQA also answers `not_found` to a key without membership. So when every routed key reports `not_found`, the hook first checks that each enforced project's key can still read its own project (`get_project`). If any cannot, it blocks and names `doctor`. If all can, the issue is outside every enforced project and the hook only warns.
   - **Bulk calls while enforced:** one unresolvable item (a non-uuid id, or a not-found id while an enforced key is dead) blocks the whole call, including items in projects that are not enforced.
   - **Out of reach:** the GoodQA UI, REST calls made with curl or scripts, Codex and Cursor. Codex has no SubagentStop or MCP PreToolUse hook here, and Cursor is not wired, so on Codex and Cursor the commands are run by hand and `done` is advisory. Parity is tracked in GoodQA work-tracker-automatic#35670, to be absorbed by the harness Go port.

### Credentials and rollout

- **Keys and routing.** A GoodQA key is bound to one organization. `spec_policy.json` `projects` maps a project slug to its `project_id` and `org_id`, and to `key_file` when it needs a different key. `doctor --project <slug>` checks that the routed key can create attachments, comment and transition in that project.
  - `member.key` reaches FrameBright, including the `work-tracker-automatic` tracker.
  - The Harness project lives in org Eric, and no key file reaches it yet.
- **Shipped mode:** `mode: warn`, `plan_ticket_gate: warn`, `enforced_projects: []`. No project is enforced in this release.
- **Before enforcing any project:** resolve the remaining items in GoodQA work-tracker-automatic#35672 (per-project plan ticket gate, a policy for tickets opened before enforcement, bulk timing with several routed keys). `doctor` reports the permissions GoodQA lists for the key; it does not try a write. Re-run it after any key or membership change.
- **Enforcing on `harness`:** once #35672 is resolved, add `{"key_file": ...}` to its route, run `doctor --project harness`, then set `"enforced_projects": ["harness"]` and `"mode": "enforce"`.
- **Rollback:** set the modes to `off`, or delete the `spec_flow.py hook` handler from `~/.claude/settings.json`.

## PR review map

`review_map.py` builds one self-contained HTML page for pair-programming a pull request:

```sh
python3 ~/.claude/hooks/review_map.py generate --repo <checkout> --pr <N>      # or --branch <name> --no-gh
python3 ~/.claude/hooks/review_map.py attach --map <file.html> --yes           # tickets come from the PR's commits
python3 ~/.claude/hooks/review_map.py list --repo <checkout> --state open
```

The page has a grouped change map (tile area follows changed lines), reasoning per commit (Why, What, Testing, Risk), known edges with diff snippets (spec NEG cases, spec risks, commit Risk lines and review findings), the refinements reviews caught (finding, fix commit, test file), suggested next steps and prompts to run next. It loads nothing from the network, escapes every string, pins its single script with a CSP hash and is written with mode 0600 to `~/.agent-harness/work/review-maps/` (override with `HARNESS_REVIEW_WORK`).

Sources are matched to the PR only by commit SHA (at least 8 hex characters), exact branch name or a project-qualified ticket reference; each attribution shows its basis, and a report that reviewed an older head is marked stale. Specs and reports are found under `~/.agent-harness/work`, WAL notes under `~/.claude/wals`. Refinement links (finding to fix commit) are inferred and labeled so. Text is redacted with the harness redactor plus e-mail, JWT and home-directory patterns before it is truncated, and generation refuses to write a page that an independent detector still finds token-shaped text in. Ticket references come only from the PR's commit messages, never from PR comments, and `attach` needs `--yes`. It uploads the page and comments with its sha256 once per ticket (a rerun reports `ALREADY_ATTACHED`); projects the member key cannot reach are reported `UNREACHABLE`.

The console lists the selected session repository's pull requests; selecting one and pressing **Open review map** builds the page and shows it in a sandboxed frame (no access to the console token or API). **Attach to GoodQA tickets** asks you to confirm the ticket list first. The console runs `~/.claude/hooks/review_map.py` (override with `HARNESS_REVIEW_MAP`).

## Lower-level publication and local integration

```sh
python3 ~/.claude/hooks/publish_feature.py --repo /absolute/feature-worktree --branch feat/example --original-branch main --expected-head FULL_FEATURE_SHA
```

If publication succeeds, create a draft PR for that exact feature commit and treat it as `PR_READY`. Keep the original checkout unchanged until the repository's review and merge authorization are complete. After GitHub merges it, verify the PR and pin the remote branch target before a hook-disabled, protected fast-forward into a clean original checkout; run checks there before reporting delivery. The remote-phase command is still coordinated by the main agent; this local helper does not merge a GitHub PR.

Use the local helper when publication is genuinely blocked or the user chose local-only delivery:

```sh
python3 ~/.claude/hooks/integrate_local.py --repo /absolute/original-checkout --original-branch main --expected-head FULL_ORIGINAL_SHA --source feat/example --expected-source-head FULL_FEATURE_SHA --check 'python3 -m unittest discover -s tests -v'
```

Local-only delivery leaves publication outstanding. A later GitHub merge may have different history even if its file tree matches, so reconcile deliberately instead of assuming it will fast-forward onto the local merge.

The publication helper requires `--repo` to resolve to the feature worktree root before inspecting the branch or remote; a nested directory returns `BLOCKED_POLICY` (exit 2), because a directory-scoped index scan could miss hidden root entries. It resolves `origin`’s effective push URL (including `pushurl` and `pushInsteadOf`) and asks that destination for its advertised default branch and refuses to push that branch, including nonstandard names such as `trunk`. If the default is unknown (for example, an empty remote) or the query fails, it returns `BLOCKED_REMOTE` (exit 4) and local integration continues. Multiple push destinations, or an effective URL that would be rewritten again during inspection, are rejected with `BLOCKED_POLICY` before any push; they cannot be checked or updated atomically across repositories. This follows Git’s [push URL semantics](https://git-scm.com/docs/git-push#REMOTES). It canonicalizes source-relative local push URLs, including paths with a colon after a slash, and preserves the source object format, then exposes the reviewed commit to a temporary bare repository through Git object alternates (without copying the project's history), then pushes that object to the inspected feature ref using a temporary remote pinned in command environment. This prevents a moving source branch, source-local URL rewrite, or source `pre-push` hook from changing the delivered object or destination. Because the isolated transport bypasses source `pre-push` hooks, publication scans the commits the push can add for [Git LFS pointer blobs](https://github.com/git-lfs/git-lfs/blob/main/docs/spec.md) and returns `BLOCKED_POLICY` if any are found; use an LFS-aware push path or make an explicit local-only delivery decision; a policy refusal is not a remote outage. The LFS scan runs in that prepared transport immediately before pushing, using the same original object graph as the transfer. It asks the pinned destination for its `refs/heads/*` and `refs/tags/*` tips, peels those present locally to commits, and scans every commit reachable from the feature head but not from those tips. Local remote-tracking refs are never trusted to shrink the range. Each such commit is diffed against every parent (or as a root), so the scan covers new blobs and older blobs a new commit adds at a changed path, as the Git LFS pre-push hook does. Pointers only in history the destination already advertises do not block publication. If a destination ref disappears between this listing and the push, Git may send objects that already existed on the destination without this scan; those objects were not introduced by the feature commits. Source shallow boundaries and grafts cannot hide retained ancestor objects from inspection. A shallow source can publish when the unpublished range is complete locally and adds no pointer; missing objects inside the unpublished range make verification fail closed with `BLOCKED_REMOTE`, even if the destination might already have them. All publication Git commands disable replacement objects. The scan conservatively rejects small blobs containing a recognized LFS version line, including CRLF, surrounding Unicode whitespace, extension records and legacy version aliases; malformed pointer-like text can therefore also require manual publication. Enumeration streams commit IDs and raw diff records without retaining paths and refuses more than 200,000 destination refs or 64,000,000 ref-listing bytes, 100,000 unpublished commits, 300,000 candidate blobs, 19,500,000 commit-list bytes, 256,000,000 diff bytes, or malformed/oversized records before buffering the complete enumeration. Candidate blob content is limited to 30,000,000 bytes. The whole scan shares one `--timeout` deadline. If the scan cannot complete within these budgets or that deadline, it returns `BLOCKED_REMOTE` with a fixed `reason` (for example `LFS scan commit budget exceeded`) without pushing; the read-only enumeration process group is killed immediately on refusal or timeout. It does not create a PR; the main agent does that separately when available. A concurrent change to global Git URL rewrites or external DNS/transport routing remains outside this protection. Git terminal credential prompts are disabled during the push. Credential helpers and SSH can still stall; `--timeout` (default 600 seconds) bounds each Git command, including local inspection, temporary transport setup, and the push. Local inspection timeouts return `BLOCKED_REMOTE` before any push; the default-branch query has the smaller of this deadline and 30 seconds. For other Git commands, on timeout the helper terminates Git and descendants in its process group with SIGTERM, then kills anything still running after a two-second grace, before reporting. A timeout does not prove that the remote ref was unchanged: verify it before retrying.

The integration helper accepts a small fixed set of test/build commands and lockfile installs, parsed as argv without a shell. An unparseable or unapproved command returns `BLOCKED_POLICY` (exit 2) before integration. `--repo` must be the root of the original worktree, and the named original branch and HEAD and reviewed source branch and commit must still match. The original checkout must be clean. The helper refuses inherited `GIT_*` routing, index, and configuration overrides before Git inspection; identity variables, `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_NOSYSTEM`, `GIT_TERMINAL_PROMPT`, and `GIT_PAGER` are allowed. Helper-owned Git commands strip `GIT_PAGER`. A blocked or changed original checkout is preserved; do not reset it to make delivery pass.

Before the scratch merge can run merge drivers, hooks, or checks, the helper reserves an owner-only journal under the repository Git common directory at `agent-harness/delivery-scratch`. This state is independent of `HOME` and shared by linked worktrees. A private lock serializes integration for one original checkout inode and branch. Each original checkout and branch has its own `scopes/<scope>/active` namespace. A scan of at most 4096 active or legacy journals shares a deadline of the smaller of `--timeout` and 30 seconds; an unsafe or over-budget set requires recovery before new merge/check effects. Unresolved attempts block across changed baseline or feature inputs. Completed and explicitly resolved metadata moves to `scopes/<scope>/archive`; a new feature never rescans archived history or depends on old candidate ancestry. An exact completed repeat checks that candidate, current clean checkout, and remaining artifacts before returning `ALREADY_INTEGRATED`; natural completion of retained-artifact cleanup is accepted. An unfinished reservation in another linked worktree does not block this scope. The scratch worktree is created in a separate owner-only temporary container outside `.git`, `.hg`, and `.sl` path components so VCS-ignoring test tools can see its files. The journal binds its absolute path and container device/inode; changing `HOME` does not move recovery state. The scratch worktree shares the repository's objects, refs, and local Git configuration. It lets the helper validate the candidate before deliberately changing the original HEAD, **not** sandbox repository code: merge drivers, hooks, package lifecycle scripts, and tests can execute and can affect external paths or shared Git metadata. Use trusted repositories and inspect a retained scratch worktree before recovery.

In scratch, the helper runs `git merge --no-ff --no-commit` against the exact reviewed feature commit. It records the actual merge tree, runs approved preparations and checks there, and rejects a changed index tree, unstaged edit, or untracked test output before committing. It then verifies the candidate merge commit's two exact parents and tree and pins it under a private `refs/agent-harness/delivery/<tuple-key>-<attempt>` ref. The attempt identity is recorded before repository code runs, so a resolved retry can preserve the old pin and create a distinct new pin, including when a legacy flat tuple-key ref exists. A custom merge driver may produce a tree different from a default Git merge prediction; the checked and pinned candidate is the one offered to the original checkout. The helper rechecks original branch, HEAD, cleanliness, source ref, candidate ref, and scratch identity before applying it. It uses `git merge --ff-only --no-overwrite-ignore --no-autostash <candidate>` with hooks disabled in the original checkout, then reruns approved preparations and checks **in that checkout** and verifies the final HEAD and cleanliness. Scratch merge and commit hooks still run; original fast-forward hooks are suppressed because a post-merge hook can delete ignored user data after Git's overwrite guard. A green scratch run alone is not `INTEGRATED`. With `merge.autostash=true`, the explicit no-autostash flag prevents this step from silently stashing a concurrent user edit. The ignored-file overwrite guard covers tested flat, nested, and relocated destinations, but external filesystem or Git configuration changes after a check remain a race.

On a failed scratch merge or check, the helper has not intentionally applied the candidate to the original checkout. Inspect the original anyway: repository code can change its files or shared refs before the protected fast-forward. The helper attempts `git merge --abort` **in scratch** only after rechecking scratch Git state. If that state cannot be verified, it leaves the merge for inspection. A failure at or after candidate application can leave the original checkout at the candidate commit even when the helper returns a failure; delivered-check failures report `DELIVERED_CHECK_FAILED` with the observed HEAD. Once a journal exists, failed or interrupted attempts retain it, plus any scratch worktree and candidate ref already created. Recovery state and retained payload paths are reported separately; the journal directory is not the scratch worktree. Inspect the reported journal, scratch worktree if present, original HEAD/status, merge state, candidate ref if present, and any ignored artifacts before manual recovery. Never infer success from a changed HEAD, delete an uncertain worktree, or automatically retry the same inputs. The helper does not hard-reset the original checkout or delete Git lock files. After the protected fast-forward and original checks, it marks the journal as finalizing, attempts cleanup with hooks disabled for its own candidate-ref operations, rechecks the original, then marks the journal delivered. Cleanup removes scratch only if its identity still matches and it has no hidden, untracked, or ignored data. `cleanup_pending` means a scratch worktree, candidate ref, or both remain; inspect which artifact remains. Terminal journal metadata remains in the archive. Archive growth does not add work to a new feature scan. The fixed schema-1 legacy namespace is inspected fail-closed and can be explicitly resolved without moving its nested worktree.

## Explicit recovery resolution

First inspect the reported journal, actual original `HEAD` and status, scratch data, and candidate ref. Preserve anything uncertain. Choose the current clean original commit as the baseline you intend to keep, then run:

```sh
python3 ~/.claude/hooks/integrate_local.py --repo /absolute/original-checkout --original-branch main --expected-head <confirmed-current-SHA> --resolve-journal <64-character-journal-key> --check 'python3 -m unittest discover -s tests'
```

Resolution takes the same per-checkout lock, verifies the selected journal belongs to this checkout and branch, and runs the approved nonempty checks in the original checkout. It rechecks the exact confirmed HEAD, cleanliness, and repository identity afterward. Only then does it emit `RESOLVED` and archive the metadata. This accepts the tested current checkout as a new baseline; it does not assert that the failed candidate was delivered. It deletes no scratch files or refs, including ignored output or dependencies. A failed check, changed checkout, symlinked/hardlinked journal, or journal from another scope remains blocked. A scoped reservation interrupted before its first journal write can be resolved explicitly, with `artifacts_unknown: true`; a legacy reservation whose scope cannot be established stays blocked for manual inspection.

After `RESOLVED`, a corrected feature can be attempted as a new delivery. If the source and baseline are unchanged because an external failure was fixed, the helper preserves the prior resolution under `archive/history/<attempt>/<key>` before reusing that tuple; it never overwrites the earlier record. Retained worktrees and candidate refs still need deliberate inspection and cleanup; use a normal non-forced `git worktree remove` only after preserving all needed ignored/untracked data, and use an exact compare-and-swap ref deletion for the recorded candidate. The resolver intentionally does not automate that deletion.

Git cleanliness inspections disable fsmonitor and untracked caches, force normal stat, executable-bit, and symlink-type checks, include untracked files and dirty submodules despite user configuration, and reject gitlinks and hidden `assume-unchanged` or `skip-worktree` index entries. The NUL-delimited index scan reads no file contents or paths into reports and refuses more than 40 MB, 250,000 entries, a 1 MB path record, or 30 seconds. Sparse checkouts with skip-worktree entries and submodule gitlinks need a separate delivery path; do not clear flags automatically. These checks are not byte-for-byte filesystem attestation: forged stat metadata, concurrent edits, and changes after final verification remain limits. A repository's `.gitattributes` may select a user-global clean filter during status, and scratch integration retains merge drivers and Git hooks for its merge and commit. Source checks constrain known execution and concealment paths but cannot isolate or pin all repository code and shared configuration.

Each Git command, preparation, check, and abort attempt has a positive `--timeout` in seconds (default 600 **per command**, not for the whole workflow). The helper terminates a timed-out command's process group with SIGTERM, then SIGKILL after a bounded grace. Detached descendants remain outside that cleanup. Failure reports give a phase, status, and available exit code without child stdout or stderr, which might contain secrets; `merge_aborted` describes the scratch merge only. Approved `unittest discover` checks require at least one non-skipped test invocation, but a test can still lack meaningful assertions; other allowlisted runners retain their own exit-status semantics. The main agent must judge test sufficiency and review evidence. The helper does not publish the original branch.

## Integration command output

Approved preparation and check commands merge stdout and stderr into one pipe and drain it in fixed 64 KiB chunks without retaining the bytes. The helper keeps their exit status, not their output, and prints only its structured status report. It waits for pipe EOF, including same-group children that inherited the descriptors, and then waits for the command leader within the original deadline. On timeout, it continues bounded draining during the two-second TERM grace, kills the process group, then bounds final pipe cleanup before attempting a safe scratch merge abort. If cleanup itself fails, it reports `BLOCKED_LOCAL` with `merge_aborted: false` and retains the scratch worktree and journal because a child might still be active. A child that closes or redirects both descriptors, or detaches from the process group, can still outlive this check; do not rely on the helper to supervise detached services. Inspect the reported phase and scratch worktree before rerunning a command for diagnostics. If the phase reached original checkout checks, first inspect the actual original HEAD and user files. Merge, commit, and fast-forward hook output is discarded. Metadata Git inspections still capture output needed to verify branch, tree, and checkout state without a hard overall memory bound; an unusually large untracked set can stress memory or time.

## Test watcher

```sh
python3 ~/.claude/tools/watch-tests.py --root /absolute/checkout --once -- python3 -m unittest discover -s tests -v
python3 ~/.claude/tools/watch-tests.py --root /absolute/checkout -- python3 -m unittest discover -s tests -v
```

The watcher polls common source extensions plus exact dependency filenames: `pyproject.toml`, `requirements.txt`, `poetry.lock`, `uv.lock`, `go.mod`, `go.sum`, `go.work`, `go.work.sum`, `pnpm-lock.yaml`, and `yarn.lock`. These names remain watched when `--extensions` changes the suffix list. It skips common vendor/build directories, generated-output directories (`coverage`, `test-results`, `playwright-report`, `.next`), and symlinked files/directories. Other generated files with watched suffixes can still retrigger a run; move them into a skipped directory or choose a narrower `--extensions` list. It compares file metadata (device, inode, mode, size, modification time, and status-change time), without reading source contents; on macOS/Linux this detects ordinary same-size edits with restored modification times and atomic replacements. Coarse timestamps and concurrent filesystem changes remain possible, so the watcher is a best-effort local convenience, not a security boundary or CI gate.

Watcher-authored status shows run number, elapsed time, exit status, and watched-file count without printing the checkout path or command arguments. Child test output is streamed verbatim and remains the test command's responsibility. Root-resolution and scan errors stop the watcher with exit 2 and generic messages; a missing command executable returns 127 without echoing its path. A child directory removed during scanning is skipped, while a missing root fails. A stalled test process group is terminated after `--timeout` (600 seconds by default), with `--once` returning 124 on timeout. Stop a continuous watch with Ctrl-C. After changing this helper, run `python3 install.py --apply` from the harness checkout to update the user-wide copy; the installer retains private backups of replaced files for manual recovery.

## netwatch monitor

`install.py --apply` and `install_codex.py --apply` also install [netwatch](https://github.com/ericmacdougall/netwatch), a small public Go binary that records gateway and internet latency, apps that start using the network, and orphaned or runaway developer processes. `harness/netwatch.json` pins the version, the SHA-256 of each platform archive and the SHA-256 of the binary inside it. The installer:

1. hashes any existing `~/.agent-harness/bin/netwatch` (`netwatch.exe` on Windows) and, if it matches the pinned binary, downloads nothing;
2. otherwise downloads only `https://github.com/ericmacdougall/netwatch/releases/download/<version>/...`, refuses an archive or binary whose digest differs, reads only the expected binary member, places it atomically and checks that it reports the pinned version. Any binary that differs from the pin is replaced without being run, so a hand-installed build there is overwritten; keep custom builds elsewhere;
3. runs `netwatch install` to register a per-user service (a LaunchAgent on macOS, a `systemd --user` unit on Linux, a logon Scheduled Task on Windows; no root or administrator rights) unless the binary is unchanged and `netwatch status` already reports it running. That check does not compare the registered program path, so a same-label service started from another binary is left until the next upgrade or a manual `netwatch install`. On Windows the shortcut recognises only an English `Running` Scheduled Task status, so with the Run-key fallback or a localized Task Scheduler every `--apply` re-registers and restarts netwatch.

- The service belongs to whoever runs the installer, so it is registered only when the target is your real home. With a non-default `--home`, as in tests, netwatch is skipped; `--netwatch` places the binary but still leaves the service alone.
- A download, digest or service failure is reported as one `netwatch:` status line and never fails the harness install.
- `--no-netwatch` skips netwatch and is remembered in `~/.agent-harness/netwatch-state.json`; `--netwatch` turns it back on. `AGENT_HARNESS_NETWATCH=0` skips it for one run. Opting out does not remove an installed service; run `~/.agent-harness/bin/netwatch uninstall` for that, and pass `--no-netwatch` to later installs or they register it again.
- An upgrade re-registers the service, which keeps a custom config or log directory only when it is set through `NETWATCH_CONFIG` / `NETWATCH_LOG_DIR` in the installer's environment.
- To upgrade the pin, copy the version and digests from the release's `SHA256SUMS` and the extracted binaries into `harness/netwatch.json`, then rerun the installer.

Agents read it with `netwatch orphans --json` and `netwatch report --since 1h --json`. `orphans --kill` is opt-in, needs `--pid`, `--match` or `--all`, re-checks each process immediately before signalling and sends only `SIGTERM` on macOS and Linux. Logs stay on the machine (`~/Library/Logs/netwatch`, `~/.local/state/netwatch` or `%LOCALAPPDATA%\netwatch\logs`), are owner-only, and have secrets in command lines masked.

## Agent log backup

`install.py --apply` installs a scheduled, copy-only backup of agent logs to Dropbox (GoodQA #14471). Files: `~/.agent-harness/bin/log-backup.sh` and `log-backup.excludes`, plus a LaunchAgent `com.ericmacdougall.log-backup` (macOS, every 15 min) or the systemd user units `log-backup.service` and `log-backup.timer` (Linux). A second install changes nothing and reloads nothing; a differing hand-installed file is first saved as `NAME.bak-STAMP`; the scheduler is reloaded only when a unit changed, never while a run holds the lock, and never with a non-default `--home`. On Linux the timer needs systemd user linger (`loginctl enable-linger $USER`) to run without a login.

What it copies: `.claude/{projects,wals,history.jsonl}`, `.codex/{sessions,archived_sessions,history.jsonl}`, `.agent-harness/work` and the work-ledger files, to `<remote>/<host>/...`. It runs only `rclone copy` (and `listremotes`): a local deletion never reaches the remote, and an overwritten file is kept under `versions/STAMP/` (`LOG_BACKUP_VERSIONS=0` turns that off and logs a warning; versions of actively appended transcripts grow without bound until a pruning follow-up exists). Live sources (`.claude/*`, `.codex/sessions`, history and ledger files) are first snapshotted with rsync into `~/.agent-harness/backup-stage` (mode 0700, not deleted by the script, so it grows with the sources; credential-named files are excluded from the snapshot as well as the upload) and uploaded from the snapshot, because transcripts change mid-upload and Dropbox then rejects the hash; static sources (`.codex/archived_sessions`, `.agent-harness/work`) upload in place and skip files younger than 2 minutes. Credential-named files are excluded by `log-backup.excludes` (a filter file, never shell globs). Secrets pasted into transcripts cannot be found by name: **the remote copy is plaintext at rest until encryption is added** (open decision). Selecting a crypt overlay later needs only `LOG_BACKUP_REMOTE`.

Encryption at rest is deliberately not part of this component; it is tracked as follow-up GoodQA #14522. Until it lands, treat everything under `Backups/agent-logs/` as readable by anyone with access to the Dropbox account. The dev2 host retires on 2026-11-09 and its work moves to T2: reinstall the component there with `install.py --apply` (the remote there may be named `dropbox:` or `lessons-dropbox:`; selection is automatic) and keep the old dev2 backup path, because the remote copy outlives the host.

Remote selection: `LOG_BACKUP_REMOTE=NAME:path` (NAME must be a configured dropbox or crypt remote), else the first of `lessons-dropbox`, `dropbox`. The name is pinned in `~/.agent-harness/logs/log-backup.remote`; a change fails the run (exit 4) until you remove the pin. Exit codes: 0 ok or skipped, 1 a source failed or no primary source copied, 2 bad excludes or host, 3 remote problem, 4 pin mismatch, 127 rclone or rsync missing, 1 the stage directory could not be created. rclone runs in Dropbox batch mode with 2 transfers, tpslimit 2 and its own 10 retries (30 s apart), and the script retries a failed source twice more, because Dropbox rate-limits (too_many_write_operations); a source that still fails keeps the run non-fresh. Build outputs, VM and disk images are excluded; the build, dist, target and .cache exclusions match at any depth, including inside durable task folders under `.agent-harness/work`. The stage must be an absolute, private directory that is not a symlink and not inside or around any source; a stage that still holds deleted files never makes an empty live tree count as a backup. `last-ok` means every source copied without error, not that every file was uploaded: files younger than 2 minutes in static sources wait for the next run. A partial snapshot (rsync exit 23) uploads what was staged but withholds `last-ok`.

Freshness: `~/.agent-harness/logs/log-backup.last-ok` holds the run start time and is written, atomically, only after every source copied and at least one primary source (`.claude/projects` or `.codex/sessions`) was copied. A run skipped because another holds the lock writes `log-backup.last-skip` and never counts as success. `python3 ~/.claude/hooks/log_backup.py check` exits 0 fresh (1 hour or less), 1 stale, 2 missing or invalid (garbage or future); `status` prints the success, run, skip and lock state; a SessionStart hook prints a visible alert when the backup is not fresh (a very long session will not see staleness arrive).

Restore test: `python3 ~/.claude/hooks/log_backup.py restore --src .claude/wals --into /an/empty/scratch/dir` copies the source from the remote, verifies it against the remote with `rclone check --download`, and compares it with the live files (identical, grown = restored is a byte prefix of the longer live file, differing, or no-live). It exits non-zero on zero files, a differing file or a failed check, and refuses relative, `..`, symlinked or non-empty targets and anything inside `~/.claude`, `~/.codex` or `~/.agent-harness`. A real disaster restore copies from the remote into the new home by hand with `rclone copy`.

Work tree and run budget: `.agent-harness/work` can hold hundreds of GB of git worktrees, checkouts, screenshots and mutation trees, which no 15-minute run can upload under Dropbox rate limits. The component therefore backs up only small durable state from it: every directory that has a `.git` entry is excluded (found on each run; paths with glob characters cannot be excluded safely and are still uploaded), media and archive files (`log-backup.work-excludes`) are skipped, files over 25M are skipped (`LOG_BACKUP_WORK_MAX_SIZE`) and a 5G transfer cap applies (`LOG_BACKUP_WORK_MAX_TRANSFER`). Each run has a 13 minute budget (`LOG_BACKUP_BUDGET_SECONDS`) passed to rclone as `--max-duration`; when the budget or transfer cap stops a source, progress is kept, `last-ok` is withheld and the next run continues, so a large backlog shows as a stale backup rather than a hung job. The freshness alert does not depend on the lock: a run that has been going for over an hour still alerts, and the alert says that a run holds the lock.

Behaviour changes from the hand-installed script: lock takeover by rename (and only for a dead or non-log-backup holder or a lock over 24 h old), skip marker, primary-source rule, anchored excludes check, remote type check and pin, extended excludes, retries, rclone timeouts, `RCLONE_*` environment stripped except `RCLONE_CONFIG`.

## Design limits

The policy is intentionally risk-scaled. The small fix path skips worktrees and review loops. A normal code task gets only relevant tests and documents. The agents must not infer that the presence of a test or a reviewer PASS proves quality. Independent checks, reviewer availability, UI tool access and remote permissions vary by environment; handoffs must say exactly what ran and what did not.

Claude Code settings can change between versions. The hook structure follows the [Claude Code hooks reference](https://code.claude.com/docs/en/hooks), and worktree agents follow the [subagent](https://code.claude.com/docs/en/sub-agents) and [worktree](https://code.claude.com/docs/en/worktrees) guides. Check these references when upgrading Claude Code.
