# Spec: Preserve explicitly inventoried untracked files during original-checkout delivery

Ticket: GoodQA goodqa#16647
Author: agent:01a205a2-964b-7bb3-93b0-35dbf8075325
Owners: agent:01a205a2-964b-7bb3-93b0-35dbf8075325
Click-test: required
Sign-off: main
Review-policy: standard

## Outcome

An explicitly opted-in remote delivery advances the original checkout to its verified target while retaining its reviewed, noncolliding untracked and ignored entries. Ordinary delivery remains strict. Unsupported or changed state refuses before effects instead of hiding, moving or overwriting user files.

This formal spec promotes independently reviewed plan SHA2569007fb8cd35e50a916959afe32b6d68d8fe3365fcb1b763a15526fc239614512 with main's required sibling and empty-directory positives. PLAN acceptance is not formal registration or implementation admission. Source: inferred: from ticket:GoodQA goodqa#16647 -- original DeepTap refusal recorded by GoodQA16565 checkpoint ah93adff8104 and main scoped preservation assignment.

## Scope

- In: metadata-only immutable inventory; strict source/original tracked cleanliness; collision and drift checks; prepare/remote finish and typed lower external-apply reservation/completion/recovery; focused real Git controls, docs and normal merged-source installation.
- Out: generic dirty overrides; ignoring, stashing, moving, copying or deleting original user entries; unknown leaf contents or link targets; local fallback from uncertain outcomes; local integration relaxation; frozen bootstrap feature changes or a new self-install route.

## Contract

Strict mode remains the default and rejects any untracked file. Add an explicit read-only inventory operation and a prepare argument naming the resulting private manifest plus its exact SHA256. No environment variable, run-kit field or generic dirty-check override can activate preservation. The captured manifest binds checkout path/device/inode, expected branch/baseline, source identity/reviewed HEAD, layout proof, inventory policy version and exact metadata inventory. Preparing with a stale or differently bound manifest refuses. Finish uses the immutable generation-bound copy; it cannot replace the inventory or silently recapture it. A new inventory requires a fresh settled generation under existing recovery rules.

Inventory includes Git's untracked listing **without exclusion rules**, so ignored files count, plus bounded descriptor-based expansion of opaque directories returned by Git. It also records empty directories and the required ancestry identities. Initial proposed limits:4096 total preserved entries,24 directory levels,2MB canonical path listing,8MB private manifest,15second monotonic scan budget; no unlimited fallback. Paths use a closed portable ASCII relative-path policy for this first version; non-ASCII, undecodable names and unsupported platform semantics refuse rather than relying on normcase. Target trees must satisfy the same supported collision-policy constraints for opt-in mode. Review may refine these limits before implementation; they are not tunable bypasses.

Never open untracked regular-file contents, read link targets, derive content hashes or export filenames/metadata in ordinary output. Use nofollow descriptor traversal and before/after descriptor stat checks. Regular leaves require current UID, ordinary safe mode and nlink1. Reject symlinks, special files, unowned or writable-by-others ancestry, cross-device traversal and ambiguous path components. Capture leaf device/inode/type/UID/mode/nlink/size/mtime_ns/ctime_ns. Preserve directory entries and distinguish an entire untracked subtree from shared tracked ancestors: subtree metadata must remain unchanged; shared ancestor identity/ownership/mode remains bound while Git may legitimately change its directory timestamps by updating tracked siblings.

Before publication and again before any checkout effect, independently enumerate and compare the exact set and metadata. Reject additions, removal, replacement, edits or unsupported entries. Collision checks cover exact paths, either ancestor direction and conservative ASCII case-insensitive component equality against both the candidate tree and the eventual fetched merged target tree. Do not trust core.ignorecase or Python normcase. Any untracked hardlink, including an alias of a tracked target, refuses before Git runs. Keep Git's real --no-overwrite-ignore and --no-autostash protection in the actual pinned fast-forward.

Persist the binding in a new explicit delivery journal schema while retaining strict schema1/2 compatibility. The external-apply guard must carry the same validated inventory identity in its durable key/record and revalidate it at reservation, completion, interrupted-apply resume and final evidence. A generic callback returning clean or a bool allowing dirty state is not acceptable. Shared local-integration CLI and unrelated external guards remain strict. Preserve all pending outcome/recovery barriers; inventory mismatch cannot settle an uncertain remote operation or authorize local fallback.

Opt-in is initially remote-delivery only. Reject incompatible local finish or baseline-resolution operations before effects unless their preservation semantics are separately reviewed. Remote source and original tracked files must remain clean, exact branch/HEAD/layout checks remain, and final delivered checks still execute in the actual original checkout. Checks that create or mutate preserved/untracked files cause refusal; there is no automatic whitelist for generated artifacts.

Threat model follows current operations.md: cooperative local account and no concurrent nonparticipating editor during the guarded delivery window. The workflow lock serializes participating deliveries; repeated metadata checks detect inspected drift. Metadata-only observation cannot cryptographically attest content or atomically exclude a malicious same-UID writer, inode/clock forgery or a mutation fully reverted between guards. Do not claim that guarantee. Use actual Git collision safeguards in addition to pre/post inspection, refuse detected drift, and retain uncertain effect state without destructive rollback.

## Required positive distinctions

A shared already tracked parent is valid: preserve untracked dir/foo while delivering tracked dir/bar. A target blob/symlink at dir, target dir/foo, or a descendant entering an entirely untracked preserved subtree is a collision. Do not treat every shared directory ancestor as a collision.

An untracked empty directory is preserved as empty with unchanged metadata. Git does not list all empty directories, so bounded nofollow filesystem enumeration must discover them, including ignored ones. In addition to4096 preserved entries and other fixed bounds, allow at most20000 total visited filesystem entries; exceeding either bound refuses. This does not permit unknown regular-file content reads.

## Actual planning evidence

Only nofollow metadata was read from the original. Git visible listing:19 entries; including ignored:21 entries, comprising18 regular files and3 opaque directories. Expanding those directories found1193 more entries (1007 regular,186 directories). All observed entries owned by current UID; no symlink, special file or multiply-linked regular file observed. Private inventories remain mode0600; stdout emitted counts/digests only. This inspection is not a final preservation manifest or a stable-state promise. The bootstrap and other cooperating work can legitimately change these paths before a later inventory capture.

## Acceptance criteria

- AC-1: Strict default and tracked cleanliness are preserved. Verify by: actual prior strict prepare refusal, unchanged strict tests, tracked staged/unstaged edit denials and wrong branch/HEAD controls. Source: inferred: from ticket:GoodQA goodqa#16647 -- actual installed refusal and user keep-gates requirement.
- AC-2: Explicit opt-in preserves a bounded noncolliding ordinary/ignored/opaque-directory inventory through actual remote prepare and finish. Verify by: real local bare-remote/Git fixtures, immutable generation record/digest and before/after metadata equality; exact tracked target arrives and all preserved files remain. Fixtures may independently compare their own known synthetic bytes; product never reads unknown contents. Source: inferred: from ticket:GoodQA goodqa#16647 -- main proposed preservation contract.
- AC-3: Unsafe path/type/collision state refuses before publication or local overwrite. Verify by: same path, ancestor both directions, case-only and Unicode/unsupported spelling, symlink ancestor/leaf, special file, cross-device/unowned paths, hardlink alias of a tracked target, ignored target collision and source/merged-target changes. Real Git controls demonstrate the hazardous cases rather than only mocking names. Source: inferred: from ticket:GoodQA goodqa#16647 -- main adversarial requirements and real Git behavior.
- AC-4: Inventory drift cannot be recaptured or ignored. Verify by: additions, removal, replacement, chmod, size, timestamp/inode drift, stale/wrong manifest binding, malformed/private-file checks, timeout/entry/depth bounds and an unknown ignored file; zero publication/checkout effects on pre-effect denials. Source: inferred: from ticket:GoodQA goodqa#16647 -- main exact-inventory requirement.
- AC-5: The same binding protects external guard and recovery. Verify by: interruption before apply, after actual protected fast-forward and before completion, re-entry with unchanged inventory, changed manifest/inventory refusal, existing unresolved journal collision, legacy strict journals and no local fallback. Source: inferred: from ticket:GoodQA goodqa#16647 -- existing external-apply journal behavior and user gates.
- AC-6: Delivery remains reviewable and installed through normal gates. Verify by: independent plan/spec and code review, final exact-HEAD review, focused frozen validation, documented non-UI staged CLI checks, normal remote merge/delivery and merged-source installation/readback before original PR10 retry. Source: inferred: from ticket:GoodQA goodqa#16647 -- agent-harness workflow and main scope.

- AC-7: Shared tracked ancestry and empty directories work through the real remote delivery route: preserve untracked dir/foo while tracked dir/bar is delivered, and retain a noncolliding untracked empty directory without adding contents. Verify by: real bare-remote/Git fixture positives and synthetic before/after metadata/byte checks; pair exact blob/symlink/subtree/case collisions and an unknown empty-directory drift refusal. Source: inferred: from ticket:GoodQA goodqa#16647 -- main explicit required implementation positives.

## Negative cases

- NEG-1 (AC-1): Omit explicit opt-in with the same untracked fixture; strict prepare must refuse. Source: inferred: from ticket:GoodQA goodqa#16647 -- actual refusal.
- NEG-2 (AC-2, AC-3): Remove target collision check while keeping an independently hazardous real-Git fixture; only actual forbidden overwritten/removed synthetic state satisfies the control, not a setup error. Keep --no-overwrite-ignore guard as a distinct protection and attribute any downstream refusal honestly. Source: inferred: from ticket:GoodQA goodqa#16647 -- main nonvacuous proof requirement.
- NEG-3 (AC-3): Remove hardlink rejection; use an actual untracked alias of a tracked target, record real Git behavior and metadata. Do not presume Git truncates versus unlinks; if the lower layer prevents damage, attribute that control and use exact missing-preservation rejection as the schema contract, not invented data loss. Source: inferred: from ticket:GoodQA goodqa#16647 -- main explicit hardlink angle.
- NEG-4 (AC-4): Omit inventory equality at one declared boundary; mutate one known synthetic entry there and require the exact drift oracle, with a clean positive. Distinct pre-publication and pre-apply controls. Source: inferred: from ticket:GoodQA goodqa#16647 -- main drift requirement.
- NEG-5 (AC-5): Remove durable preservation binding or substitute another generation manifest; recovery must refuse exact context mismatch while valid resume works. Source: inferred: from ticket:GoodQA goodqa#16647 -- current durable recovery contract.

- NEG-6 (AC-6): Missing matching staging-exists evidence must refuse the existing release gate; source-only checks cannot claim installed or product-live behavior. Preserve the normal independently tested source and installed-runtime gates. Source: inferred: from ticket:GoodQA goodqa#16647 -- main instruction to retain all release gates.
- NEG-7 (AC-4, AC-7): Exact target blob/symlink/ancestor/case/ignored/subtree collisions refuse, while dir/foo and dir/bar under the same tracked parent pass. Source: inferred: from ticket:GoodQA goodqa#16647 -- distinguish collision from shared ancestry.
- NEG-8 (AC-4, AC-7): A new unknown ignored empty directory after capture refuses; an unchanged preserved empty directory passes and remains empty. Source: inferred: from ticket:GoodQA goodqa#16647 -- exact entry-set preservation.

No fixture count establishes population precision/recall, a Wilson interval or pass^k reliability. Release threshold: zero unsafe admissions and no unexplained valid-case failure across the finite accepted contract. Any privacy/content read, lost preserved state, bypassed collision, false success, unbound recovery or unexpected remote write is a hard failure. Generic exceptions, timeout and a downstream guard do not establish the intended mutant failure.

## Resource budget

Host: mac
Fan-out: agents=1 jobs=1 processes=4 browser_pages=0 test_workers=1
Peak memory: 0.5 GB (method: estimated bounded local Git fixtures and metadata records, no build/model inference).
CPU: 1 core (method: serial focused Python/Git controls).
Disk: 0.2 GB (method: small isolated fixture repositories and redacted receipts).
Network: 10 MB (method: Git metadata and GoodQA requests; no provider calls).
Wall time: 10 min per focused validation job.
Cap and kill: test timeout and supported harness process supervision; no unrelated process action.
Checkpoint: exact commit/fixture/manifest/log digests in private owner WAL and GoodQA; heavy or broad jobs use physical t2-dev broker and current admission floors.

## Rollback and delivery

No original user files are moved or backed up by this feature. Reverting the new opt-in route restores strict refusal; previously strict generations retain their semantics. A preserved generation cannot be resumed by an older executable that lacks its schema; retain pending state and install the reviewed compatible version rather than deleting journals. Detected post-effect drift remains a recovery condition, never an automatic rollback over user data. Separate feature review/merge/install follows the already frozen PR295 bootstrap. Original PR10 publication remains blocked until that supported installation is verified.

## Risks

- Lost original state: nofollow exact inventory, source and merged-target collision checks, real Git overwrite safeguards and no destructive rollback.
- Private-data disclosure: no unknown leaf-content or link-target reads; private bounded manifests and output counts/digests only.
- Recovery bypass: typed immutable binding across workflow and lower guard, strict legacy compatibility, no recapture or uncertainty fallback.
- Concurrent metadata changes: cooperative-account limit is explicit and detected drift remains a recovery condition; no atomic malicious-writer guarantee.

## Domain checklist

Domains: auth, delete, devices, money, release

Domain-gate: pre-account-hijack waived (no registration, account linking or recovery changes)
Domain-gate: lookalike-identifier waived (account identifiers unchanged; filesystem ASCII and case policy is explicitly covered)
Domain-gate: request-device-binding waived (no approval-link or device-code authentication introduced)
Domain-gate: link-expiry-single-use waived (no login token, email link or credential mechanism introduced)
Domain-gate: session-fixation waived (account session creation, rotation and revocation unchanged)
Domain-gate: rate-limit-enumeration waived (no account endpoint or authentication timing change)
Domain-gate: store-billing-exposure waived (no purchases, entitlement, billing or account merges)
Domain-gate: backup-before-delete waived (feature never deletes or backs up user files and refuses target collisions)
Domain-gate: unpushed-work-detection waived (no checkout, worktree, branch or ref deletion; cleanup gates unchanged)
Domain-gate: dry-run-diff waived (no deletion operation; exact inventory and drift admission are explicit acceptance criteria)
Domain-gate: scope-pinning waived (no deletion operation; preservation scope and nofollow binding are explicitly tested)
Domain-gate: cross-host-approval-portability waived (no destructive approval; inventory binds exact local checkout identity)
Domain-gate: idempotent-retry waived (no deletion operation; durable remote delivery and recovery are explicitly tested)
Domain-gate: device-identity-binding waived (no enrollment, device identity or remote-control authentication changes)
Domain-gate: unattended-recovery waived (device daemon lifecycle unchanged; CLI interrupted delivery recovery explicitly tested)
Domain-gate: grant-durability waived (no new authorization grant or expiry mechanism introduced)
Domain-gate: remote-exec-audit waived (existing command audit unchanged; only redacted local preservation evidence added)
Domain-gate: factory-reset-guard waived (no wipe, reset, unenrollment or bulk device operation)
Domain-gate: idempotency-key waived (no money movement; delivery generation identity explicitly tested)
Domain-gate: double-submit waived (no charge or payout; participating delivery serialization unchanged)
Domain-gate: currency-precision waived (no amounts, currencies or rounding in scope)
Domain-gate: refund-reversal-path waived (no capture, refund, payout or entitlement changes)
Domain-gate: ledger-reconciliation waived (no processor or financial ledger integration)
Domain-gate: authorization-vs-capture waived (no payment authorization, capture or funds lifecycle)
Domain-gate: derived-gate-floor-with-ratchet waived (no release-quality count or coverage floor changes; existing gates remain required)
Domain-gate: artifact-inventory-mirrored waived (signed artifact distribution and mirror inventory unchanged)
Domain-gate: self-update-e2e waived (no updater or feed changes; normal merged-source install and installed checks remain required)
Domain-gate: transport-proof waived (GitHub auth and publication transport unchanged; changed filesystem semantics use real Git controls)
Domain-gate: rollback-not-blocked waived (emergency release rollback unchanged; no user-data rollback introduced and recovery is explicit)

## Reviews

Spec core sha256: `6357b309a426b30fc0c2d512353d17d8df14f3c3c07e0d3b3c808d3e0c62a93c`

| Role | Verdict | Reviewer | Kind | Source | Bound to |
|---|---|---|---|---|---|
| acceptance | ACCEPT | 01a2059e-af0d-7881-aaf7-4ff2098b0f6e | agent | Codex native reviewer metadata; parent bound to native WAL session | current |
| adversarial | ACCEPT | 01a2059e-da64-7693-851f-2dec80571f63 | agent | Codex native reviewer metadata; parent bound to native WAL session | current |
