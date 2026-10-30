# Cross-boundary chaos proof

This pass starts from merged `main` at `75f2c03`. All fixtures use disposable homes, reports, worktrees, and local bare Git remotes. No user settings or credentials are fixtures. The fixed publication seed is `0x5EED` so the same branch names and payload sizes run in CI.

## Failure-first observations

| Boundary | Controlled baseline observation | Corrected invariant |
| --- | --- | --- |
| Installer managed directory | Swapping `agents` to an outside symlink after preflight let the old path-based writer complete without an error. | Parent traversal refuses symlinks and rollback does not unlink outside files. |
| Installer backup | Swapping `agents` before `copy2` copied an outside fixture into a private backup. | Backups use the already captured regular-file snapshot; no second read follows the changed path. |
| Installer final replacement | A first descriptor-relative repair reported success after `.claude` moved during the final `settings.json` replacement. | Descriptor-relative replacement checks the visible parent before and after publication and fails if it moved. |
| WAL restart | An existing complete JSONL record followed by an unterminated crash suffix became one malformed line after the next append. | The locked writer removes only the incomplete final suffix before appending; a suffix beyond 64 KiB is left untouched for inspection. |

## Chaos matrix

| Scenario | What the test asserts |
| --- | --- |
| Every managed write position | Each of 15 injected write interruptions restores the original settings and instruction bytes and modes, removes newly installed files, and leaves no temporary files. |
| Ancestor swaps | `agents`, `hooks`, `tools`, `.claude`, and the backup directory are replaced after preflight or creation; outside sentinels remain the only files outside the installation. |
| Installer contention | Eight real processes install into the same disposable home; the result has one policy marker, one managed hook group per event, valid preserved user settings, exact installed agent bytes, and no temporary files. |
| Report contention | Twelve real processes compete for one report path; exactly one publishes, eleven refuse, the winner's content and mode `0600` are verified, and no temporary report remains. |
| Publication variation | Eight seeded, distinct binary payload commits on nested feature branches publish to a bare remote whose path contains spaces. Each remote feature ref equals the reviewed SHA and remote `main` remains at its starting SHA. |
| WAL crash tail | One truncated suffix is removed under the file lock; a larger-than-budget suffix is refused without modifying the file. |

Four focused cases were replayed with the new tests copied into an archive of `75f2c03`: exit **1**, two failures and one error in 0.125 seconds. The directory swap and backup snapshot cases failed, and the crash-tail case raised `JSONDecodeError`; the final-replacement case passed because the original path-based writer failed earlier when its temporary source moved. The false-success final-replacement case was observed against the intermediate descriptor-relative repair before the post-replacement check was added. These are distinct implementation states, not four failures attributed to the original baseline.

These tests cover specific schedules and invariants. They do not prove safety against a process that can modify files after the final identity check, power loss during installation, concurrent settings editors with different content, or external Git routing changes. The installer remains a best-effort rollback, not a filesystem transaction. This pass does not measure autonomous reviewer quality or browser click accuracy; those require separate live exercises.
