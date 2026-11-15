# Spec amendment 1c: goodqa#15771 proxmox_pool inventory, status rule, bounded capture, rollout and rollback

Supersedes: notes-15771/spec-amend-1b.md (plan review BLOCK, notes-15771/spec-amend-1b-review.md, F1 to F3) and spec-amend-1.md.
Amends: notes-15771/spec.md (spec core sha256 e987343d09a5ad81984e88d990e2fd2a56bd626c349495e2e68826c2779beba5). spec.md is not edited, because its reviews are bound to its hash. Where the two disagree, this amendment replaces the Scope bullet "qm config of every VM" and the matching Risks text.
Ticket: GoodQA goodqa#15771
Author: agent:af20f2612d1e40016 (Opus rescue owner, PR 240)
Code: the PR 240 head named on line 1 of notes-15771/pr-packet.md. The PR review r4 passed at 7bb3aa29; the F3 fix and the source-built fixtures in this amendment come after it.
Source: ticket:GoodQA goodqa#15771; file:receipts/r2-pr240.md; file:receipts/r3-pr240.md; file:notes-15771/spec-amend-1b-review.md

## Inventory (replaces "qm config of every VM")
- **Volume sizes:** `timeout 8 pvesm list STORAGE`. Each row gives the volume's size in bytes and, for guest volumes, its VMID. `images` and `rootdir` rows count toward provisioned. `iso`, `vztmpl`, `snippets`, `backup` and `import` rows never count, even a backup that carries a VMID.
- **Cross-check:** `timeout 3 find MOUNT/images -mindepth 2 -maxdepth 2`, names only. Any image file or directory without a listed row makes allocation incomplete.
- **Watched VMs:** `allocated_gib` is the sum of that VMID's listed volumes on this storage.
- **Removed:** `qm list` and `qm config`. No VM config is read any more.

## What is proven from source and what is proven live
Source was read on <pve-host>, read-only, on 2026-11-13. Versions: pve-manager 9.2.20, libpve-storage-perl 9.1.10, pve-container 6.1.14. No container was created.

Proven from source:
- **S1 Row format.** `/usr/share/perl5/PVE/CLI/pvesm.pm`, `$print_content` (lines 197-241):
  - Header `Volid Format Type Size VMID`, then rows printed with `"%-<maxname>s %-7s %-9s %<sizedigits>s"`.
  - Rows with a VMID come first, with ` %d` VMID appended, in the order `PVE::Storage::volume_list` returns (sorted by lowercase volid).
  - Rows without a VMID come after, sorted by format.
  - An undefined size prints `-`; an approximate size prints `~N`.
- **S2 Content types.** `/usr/share/perl5/PVE/Storage.pm` `volume_list` asks the plugin only for the content types enabled on the storage (from `rootdir images vztmpl iso backup snippets import`).
- **S3 Container classification.** `/usr/share/perl5/PVE/Storage/Plugin.pm` `list_volumes`:
  - A guest volume's content is `rootdir` when its owner is an LXC guest in the cluster vmlist, and `images` otherwise, including a volume whose owner no longer exists.
  - A volume whose content type was not requested is dropped.
  - Each volume lands in exactly one content type, so no row appears twice.
- **S4 What `list_images` skips or sizes as zero.** `Plugin.pm` `list_images`:
  - It globs `images/[0-9][0-9]*/*`.
  - It skips names that don't match a valid format extension, and `snap-*.qcow2` files (`parse_name_dir` dies on them, caught by `eval`).
  - It skips any file whose size is undefined (`qemu-img` failure: a stderr `warn`, exit 0).
  - It sizes a directory (a subvol) as 0 (`file_size_info`, `S_ISDIR`).
- **S5 How containers are allocated on dir storage.** `/usr/share/perl5/PVE/LXC.pm` (around line 2610) and `Plugin.pm` `alloc_image` / `get_next_vm_diskname`:
  - A container rootfs with a size is allocated as raw `vm-<ct>-disk-N.raw` under `images/<ct>/`.
  - A size-less one is a `subvol-<ct>-disk-N.subvol` directory; `alloc_image` refuses a subvol with a nonzero size on dir storage.

Proven live:
- **L1 Renderer fidelity.** The test fixture renderer `pvesm_list()` reproduces the live `pvesm list local` output byte for byte: 25 rows, 19 with a VMID, 2299 bytes, `byte_identical=True`. Evidence: agent-af20f2612d1e40016/renderer_fidelity.py and renderer-fidelity.txt.
- **L2 Live inventory.** On the live pool, 19 image files match 19 listed `images` rows. There are no containers and no `rootdir` rows. `local` has content `snippets,images,backup,rootdir,vztmpl,iso`.
- **L3 Probe through the real runner.** Read-only, about 3 s per call. Every status line is 0; `allocation_complete` is true with overcommit 1.8. Run at c887363983f5d1f4af7f81bc37114cd1a67ec0f5 from the clean receipt worktree clean-15771-r5: 2.91 s (live-probe-4.txt); rehearsal runs 2.58, 1.46 and 2.70 s (rehearsal-3.txt).

Not proven live: a real container row, a subvol, or a storage with `rootdir` disabled. Those fixtures are built from S1-S5 and rendered with the L1-verified renderer.

Unsupported layouts (restricted; they read as allocation unknown, never as a low total):
- qcow2 snapshot chains (`snap-*.qcow2`), because of S4.
- Size-less subvol container volumes on dir storage (size 0), because of S4 and S5.
- Stray files or directories under `images/<id>/` that pvesm does not list.
- Storages other than dir type (lvm, zfs, rbd and others): the check's `find` and `du` assume a directory layout under MOUNT.

## Acceptance criteria
Unchanged from spec.md and restated for traceability:
- AC-1: Pool used % alerts: warning at >=85, high at >=92, critical at >=97 or under 20 GiB free, under key `disk:volume:<pve-host>:/var/lib/vz`. Verify by: ThresholdTests. Source: ticket:GoodQA goodqa#15771
- AC-2: Growth alert from stored samples (more than 10 GiB/day over a window of 6 h to 48 h). Verify by: GrowthTests. Source: inferred: from ticket:GoodQA goodqa#15771 -- the ticket asks for a growth rule, the windows are the owner's choice
- AC-3: Alert detail carries overcommit_ratio and, for each watched VM, allocated_gib, actual_gib and growth_gib_day. Verify by: ThresholdTests, GrowthTests. Source: ticket:GoodQA goodqa#15771
- AC-4: An unreachable host, timeout, nonzero exit or unusable output yields UNKNOWN (warning, then high after 30 min), and the last good alerts are carried forward. Verify by: UnknownTests; rehearsal run 2 (AC-14). Source: ticket:GoodQA goodqa#15771
- AC-5: Registered in DEFAULT_CHECKS and runs through run_once, producing a ring alert. Verify by: RunOnceTests; rehearsal run 1. Source: ticket:GoodQA goodqa#15771
- AC-6: The remote command is one fixed read-only script built from a validated alias, storage name and integer VM ids. Verify by: CommandAndConfigTests. Source: ticket:GoodQA goodqa#15771
- AC-7: A watched VM whose sizes or disk usage are missing from an otherwise valid probe raises disk:vmunknown. Verify by: RedTeamRound1Tests, DuStatusTests. Source: ticket:GoodQA goodqa#15771
- AC-8: Live and deployed: the installed ops-watch carries the proxmox_pools entry, and a real run shows disk:volume at the live percentage with overcommit and VM 102/103 fields. Verify by: after merge and install, `python3 ~/.claude/hooks/ops_watch.py run` then `status`, recorded as REALLY_TESTED with the commit. Source: ticket:GoodQA goodqa#15771

New in this amendment:
- AC-9 (RC-1): every command in the remote script is followed immediately by its own `##RC <NAME> $?` line: PVESM, VOLS, FILES, and `DU <vm>` for each watched VM. Only the `echo` marker lines don't get one. Verify by: `DuStatusTests.test_every_remote_command_reports_its_own_status`. Source: file:receipts/r3-pr240.md
- AC-10 (RC-2): data from a command is used only when its status line is present and 0. Source: ticket:GoodQA goodqa#15771
  - PVESM not 0: the whole probe is UNKNOWN.
  - VOLS or FILES not 0: allocation is incomplete and every VM subtotal is unknown.
  - DU not 0, missing, or with zero or several matching lines: that VM's usage is unknown, disk:vmunknown is raised, and no growth sample is stored for that VM.
  Verify by: CompletionStatusTests, AllVolumesTests, DuStatusTests.
- AC-11 (RC-3): data that is independently valid is kept. Pool capacity alerts and the pool sample survive a VOLS, FILES or DU failure, and one VM's valid du survives another VM's failure. Verify by: DuStatusTests, `CompletionStatusTests.test_failure_after_one_sized_disk_does_not_pass_as_a_complete_subtotal`. Source: ticket:GoodQA goodqa#15771
- AC-12 (bounded capture): the default runner reads stdout and stderr incrementally, each capped at max_bytes while reading (64 MiB by default, 1 MiB for the pool probe). On overflow it kills and reaps the child and returns `RUN_OVERFLOW_RC`, which the pool reports as `disk:unknown` "output over the size limit". A timeout also kills and reaps the child. Verify by: BoundedRunTests (failing-first on 7bb3aa29: 5 of 5), agent-af20f2612d1e40016/f3_memory_demo.py (8 MiB output: 7bb3aa29 peak 24.0 MiB allocated; new code 1.4 MiB, overflow). Source: file:notes-15771/spec-amend-1b-review.md
- AC-13 (container coverage): fixtures follow S1-S5 and are rendered by the L1-verified renderer. Source: file:notes-15771/spec-amend-1b-review.md
  - A raw container volume counts toward provisioned.
  - An orphan volume counts.
  - A size-less subvol container volume makes allocation incomplete.
  - A container on a storage without `rootdir` content (row missing, file present) makes allocation incomplete.
  - A snapshot-chain file makes allocation incomplete.
  Verify by: AllVolumesTests; renderer-fidelity.txt.
- AC-14 (rehearsal): one pool, through the actual runner on the Mac against <login>@<pve-host> local, via run_once with a throwaway home. Source: file:notes-15771/spec-amend-1b-review.md
  - Run 1 (good) raises disk:volume high and stores one sample with VMs 102 and 103.
  - Run 2 (deliberately failed: storage `nosuchpool` in a throwaway config copy) raises disk:unknown, keeps disk:volume active, and stores no sample.
  - Run 3 (good) clears disk:unknown, and disk:volume stays active.
  Verify by: agent-af20f2612d1e40016/rehearsal.py and rehearsal-3.txt (at c887363983f5d1f4af7f81bc37114cd1a67ec0f5, from clean-15771-r5). Result: 2.58 s, 1.46 s and 2.70 s, all as stated (an earlier run at the pre-commit tree, rehearsal-2.txt, matched).
- AC-15 (rollback): setting `proxmox_pools` to `[]` makes the next run do no ssh call and clear the pool alerts. Stored samples stay in state. Re-enabling raises the alerts again from a fresh read and reuses samples younger than 48 h. Verify by: agent-af20f2612d1e40016/rollback_rehearsal.py and rehearsal-3.txt at c887363983f5d1f4af7f81bc37114cd1a67ec0f5 (disabled: 0 ssh calls, clear disk:volume, 1 sample kept; re-enabled: 1 ssh call, raise disk:volume, 1 sample). Source: file:notes-15771/spec-amend-1b-review.md

## Negative cases
Unchanged from spec.md:
- NEG-1 (AC-6): the command has no qm/pvesm write verb, fstrim, resize, shell metacharacter from config, or option-like host. Verify by: CommandAndConfigTests. Source: ticket:GoodQA goodqa#15771
- NEG-2 (AC-4, AC-8): host unreachable means UNKNOWN; a deployed host without a proxmox_pools entry is detected by AC-8. Verify by: UnknownTests. Source: ticket:GoodQA goodqa#15771
- NEG-3 (AC-1): malformed, truncated or oversized pvesm status output fails closed as UNKNOWN. Verify by: UnknownTests. Source: inferred: from ticket:GoodQA goodqa#15771 -- unusable probe output is the same unknown state as an unreachable host
- NEG-4 (AC-4): no secret, banner text or raw host address appears in alert text. Verify by: `UnknownTests.test_no_remote_text_secret_or_address_reaches_the_alert`. Source: inferred: from ticket:GoodQA goodqa#15771 -- alerts must not carry remote text or addresses
- NEG-5 (AC-3): a VM with missing or garbled data is reported unknown inside detail without breaking the pool alert. Verify by: VmDetailTests. Source: inferred: from ticket:GoodQA goodqa#15771 -- a partial read must not hide the pool alert
- NEG-6 (AC-2): a counter reset, a pool shrink or a too-fresh sample raises no growth alert. Verify by: GrowthTests. Source: inferred: from ticket:GoodQA goodqa#15771 -- a partial read must not hide the pool alert

New:
- NEG-7 (AC-10): a du that prints a plausible subtotal and exits nonzero, a du with no status line, and a du that times out after a valid prefix all give unknown usage, disk:vmunknown, and no growth sample for that VM. Verify by: DuStatusTests (failing-first on 2e8d6f29: 6 of 6). Source: file:receipts/r3-pr240.md
- NEG-8 (AC-13): container, detached unused and orphan volumes are counted; an unsizable, size-less or unlisted image makes allocation incomplete and never gives a low total. Verify by: AllVolumesTests and failing_first_f1.py (db2f6b11 under-reported in 2 of 2 cases). Source: file:receipts/r2-pr240.md
- NEG-9 (AC-10): a listing that is cut, malformed, error-only, or has rows that can't be tied to one VM marks allocation incomplete, and every subtotal is unknown. Verify by: VolumeListFormatTests, CompletionStatusTests. Source: file:receipts/r2-pr240.md
- NEG-10 (AC-12): a probe that floods stdout or stderr past the cap is stopped and reaped, with no child left behind, and reads as UNKNOWN; this process's memory stays bounded. Verify by: BoundedRunTests (stdout overflow, stderr overflow, timeout reap, pool overflow is UNKNOWN). Source: file:notes-15771/spec-amend-1b-review.md
- NEG-11 (AC-14): a deliberately failed read through the actual runner never clears disk:volume and never stores a sample. Verify by: rehearsal-3.txt run 2. Source: file:notes-15771/spec-amend-1b-review.md

## Rollout
1. Merge PR 240 after main's final review. The one-pool rehearsal (AC-14) and the rollback rehearsal (AC-15) were run at c887363983f5d1f4af7f81bc37114cd1a67ec0f5, with the actual runner and a throwaway home (rehearsal-3.txt).
2. Install, then add exactly one entry to `~/.agent-harness/ops-watch.json`: `{"host": "<login>@<pve-host>", "storage": "local", "mount": "/var/lib/vz", "watch_vms": [102, 103]}`. Run `python3 ~/.claude/hooks/ops_watch.py run` and `status` once by hand (AC-8).
3. Observe for 24 h (about 144 ticks at 10 min), against these criteria:
   - **Duration:** every pool probe under 10 s (measured about 3 s); no `disk:unknown` with reason "unreachable or timed out" while ssh to the host works.
   - **Alert continuity:**
     - disk:volume stays raised at its live severity (high at about 93.5%) on every tick, and is never cleared while the pool is at or above 85%.
     - Any disk:unknown is transient, and disk:volume is carried forward through it.
     - No disk:allocunknown or disk:vmunknown on the healthy host.
   - **Growth samples:**
     - one stored per 30 min (about 48 per day), each carrying VM 102 and 103 usage;
     - none from failed reads;
     - after 6 h to 24 h, growth_gib_day is filled for 102 and 103, and no disk:growth alert fires unless the pool really grows more than 10 GiB/day.
   - **Correctness spot check, once:** used % and provisioned_gib match a manual read-only `pvesm status --storage local` and `pvesm list local` to within 1%.

## Rollback
Triggers (any one):
- (a) a false disk:unknown, disk:allocunknown or disk:vmunknown on 3 consecutive ticks while the host is healthy;
- (b) probe duration over 20 s on 3 ticks, or any visible load impact on the hypervisor;
- (c) an ops-watch run failure (rc 2, traceback) attributable to the check;
- (d) a number off by more than 1% against the manual read.

Procedure:
1. Set `proxmox_pools` to `[]` in `~/.agent-harness/ops-watch.json`. No restart is needed: the next tick makes no ssh call and clears the pool alerts (AC-15).
2. That clear means the check is off, not that the pool is fine, so post a GoodQA goodqa#15771 comment saying so with the trigger.
3. Until the check is re-enabled, main reads `pvesm status --storage local` read-only once a day. Alternatively, revert PR 240. That leaves main's earlier PR 217 parser, which reads UNKNOWN on the real header: loud, never green.

Stored samples:
- They stay in the ops-watch state file under the pool's key and are not read while the entry is absent.
- On re-enable, samples older than 48 h are dropped (POOL_SAMPLE_KEEP_S), so a stale baseline cannot raise a growth alert. Younger samples are reused; their format `[ts, used_bytes, {vm: bytes}]` is unchanged by this PR.
- A revert of PR 240 leaves the same samples readable by the earlier code, which uses the same format.

## Changed read load
- One ssh call per tick, as before. It is still a fixed read-only script, still has a 25 s local bound, and still uses BatchMode, StrictHostKeyChecking=yes, ConnectTimeout=5 and no ControlMaster.
- Commands:
  - `pvesm status --storage S` (timeout 8)
  - `pvesm list S` (timeout 8; one `qemu-img info` per image, as the PVE storage view does)
  - `find MOUNT/images -mindepth 2 -maxdepth 2` (timeout 3; names only)
  - one `du -sk MOUNT/images/<vm>` per watched VM (timeout 5 each)
- Output is capped at 1 MiB per stream while reading (AC-12).

## Resource budget

Scope: one proxmox_pool tick of ops-watch (every 10 min) on the Mac, plus its single read-only ssh call to <pve-host>.

Host: mac
Fan-out: agents=0 jobs=1 processes=1 browser_pages=0 test_workers=0
Peak memory: 0.05 GB (method: one ssh client (about 10 MB RSS) inside the running ops-watch process; capture is capped at 1 MiB per stream while reading (AC-12), 3489 bytes measured live; tracemalloc peak 1.4 MiB on an 8 MiB flood)
CPU: 0.1 cores (method: the ssh client is mostly idle during the 2.82 s call measured live at 7bb3aa29, once per 600 s tick; parsing a few KB is negligible)
Disk: 0.01 GB (method: ops-watch state holds at most 120 pool samples of a few dozen bytes each; nothing else is written)
Network: 0.05 MB (method: 3489 bytes of script output measured live at 7bb3aa29, plus the ssh handshake and a 0.5 KB script, per tick)
Remote CPU: 1 cores (method: upper bound of one core for the about 3 s measured wall time; two pvesm perl start-ups plus one qemu-img info per image (19 images live) in pvesm list; find and du touch metadata only)
Remote IO: 2 MB (method: qemu-img info reads each image header (KB-scale, 19 images); find is a readdir of the image dirs, names only; du stats only the watched VMs' directories (2 today); no image data is read)
Remote network: 0.05 MB (method: the same bytes as the local Network line, in the other direction)
Wall time: 29 s (method: worst case if every remote timeout runs out: pvesm status 8 s + pvesm list 8 s + find 3 s + du 5 s per watched VM x 2; the local 25 s subprocess bound ends it first and the result is UNKNOWN; measured 2.91 s live and 1.46 to 2.70 s in the rehearsal at c8873639)
Cap and kill: every remote command runs under coreutils timeout (8, 8, 3 and 5 s per du); ssh uses ConnectTimeout=5 and BatchMode=yes; the local runner ends and reaps the ssh client at 25 s (TimeoutExpired, reported as UNKNOWN) or as soon as stdout or stderr passes 1 MiB (RUN_OVERFLOW_RC, reported as UNKNOWN); one call per tick, no retries inside a tick
Checkpoint: not required (under 10 min and 4 GB); each tick is idempotent and read-only, and its only state (pool samples and last good alerts) lives in the ops-watch state file in its durable home, so a missed or stopped tick resumes on the next run
