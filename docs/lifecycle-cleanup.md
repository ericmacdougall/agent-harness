# Clean up one completed task

Use a reusable copy per repository and PR or lane. Enroll the native task after acquiring its copy so the task can pin that acquisition's generation. Reacquiring the same key reuses the checkout when it is safe to do so and invalidates retirement for the earlier generation. Use the enrolled native task's read-only completion verifier to prove the intended outcome. A process exit, timer expiry, or manually written completion claim is insufficient.

Run the following commands from a different working directory after delivery and live verification. Substitute the path to the installed `copy_hygiene.py` for your Claude or Codex harness. The default previews the one selected item.

```sh
python3 /path/to/copy_hygiene.py finish \
  --task-dir /absolute/enrolled/task --repo /absolute/source/checkout \
  --key pr-123 --expect-head FULL_COMMIT_SHA
```

Add `--apply` to retire the same checkout after reviewing the preview. The copy must still match the enrolled task's working directory and exact commit, belong to the reused key, and have no later acquisition. The isolated lifecycle worker holds the task and copy locks throughout guard verification and removal. The guarded remover checks live Git origin, uncommitted work, the worktree registry, open processes, and current protected service paths. It uses ordinary Git worktree removal. Keep a checkout that fails these checks.

For an explicitly selected, non-secret build or report artifact, put the regular file or subtree under the enrolled task's private `artifacts` directory. Use only data authorized to be archived to the configured private bucket. The operation refuses the enrolled prompt, hidden paths, links, foreign filesystems, logs, WALs, credentials by common names or extensions, and recognized durable harness state. These name checks cannot classify arbitrary artifact content. Keep sensitive files outside this directory.

```sh
python3 /path/to/copy_hygiene.py archive-artifact \
  --task-dir /absolute/enrolled/task --name report-output \
  --b2-remote configured-b2:private-bucket/prefix --apply
```

The archive uses a SHA-256 object name and immutable upload. A download comparison must match the exact staged archive before retirement. The helper then rechecks source contents, service references, and open processes. It preserves changed or uncertain data and never retries an uncertain deletion. The default input limit is 256 MiB. Operators who know the expected size can pass an exact `--max-bytes` limit up to 4 GiB. The host must have enough free scratch space for the archive. Larger or unsupported items stay local.

The task directory retains a cleanup result with the archive object and SHA-256 or original Git commit. After an interrupted artifact retirement, inspect the result and any named private quarantine before touching the path. To restore a verified artifact, download the exact object to a private directory, verify its full SHA-256, and extract into an empty destination. Upload or verification failures leave the local source intact. Leave logs and WALs to the existing Dropbox-verified retention workflow. This cleanup command does not schedule a sweep or retire unrelated tasks.
