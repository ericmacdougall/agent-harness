# Repair an existing harness installation

Use the repair command to refresh existing Claude and Codex harness files on a workstation and its SSH worker. Both hosts need Python 3.11 or later and existing installations. Run it from an inspected checkout of Agent Harness.

```sh
scripts/repair-harness.sh --ref REVIEWED_MERGED_COMMIT --host <worker host> --check
scripts/repair-harness.sh --ref REVIEWED_MERGED_COMMIT --host <worker host> --apply
```

Replace `REVIEWED_MERGED_COMMIT` with the full commit SHA from the reviewed release. Preview is the default. Use `--python /absolute/path/to/python3` when interpreter discovery needs an explicit choice. The SSH target must already have a trusted host key and working account access.

The shell entry point rejects an older default Python and searches installed
3.11+ executables, including Homebrew paths. It never installs an interpreter.
Each host's private `check-runtime.json` and `apply-runtime.json` record its
selected interpreter version, available space and archive size.

The command fetches the canonical repository into private storage and verifies that the requested commit belongs to the fetched main history. A later commit on main keeps earlier reviewed commits usable. The same source archive supplies both hosts. Both installers preview on both hosts before either installation changes. Apply runs on the worker first and then locally. It uses the installers' hooks-only path and backup handling, checks installed files, and checks preservation of the existing instruction and settings files.

The workstation reuses one private blob-filtered canonical Git object store
under `~/.agent-harness/work/repair-source.git`; it does not create a full Git
clone per attempt. A kernel lock serializes cache fetch/archive operations.
Archive creation has a hard 64 MiB child-process file limit. Local source staging
and both host phases require at least 512 MiB free before proceeding. These
limits bound repair staging; they do not free disk or establish staging capacity
for another product. Every check and apply extracts a separate fresh verified
source tree, so extra files left in the preview tree cannot become apply-time
imports. Per-run archives, source trees and logs remain private recovery evidence.

A host-wide kernel lock spans each check or apply phase, including both
installers and final readback. Another attempt refuses while a worker remains
alive, including after a lost SSH connection. Lock files must be private regular
files owned by the current account, with no symlink or hardlink aliases. Applying
an already-used stage refuses rather than silently replaying a partial operation.
The tool snapshots installed files and settings during preview and requires the
same state before apply; a concurrent edit requires reconciliation.

Successful output reports agent hook registration as **unchanged** separately
from file repair. Hooks-only does not enroll new hooks, change permission
defaults, or grant Codex trust. The existing installers can migrate a missing
local policy profile and install the Git commit-msg backstop; existing local
profiles are checked for preservation. New registration needs the ordinary
installer workflow and its own review.

Progress and diagnostics remain in private work directories. An error after apply begins can leave a host partially updated. Keep its logs and installer backups and inspect the reported phase before deciding how to recover. A lost SSH response leaves the remote outcome uncertain. The command requires explicit investigation before another attempt.

The tool repairs installation drift. Codex hook review uses the native `/hooks` command or Settings > Hooks. An audit's model approval still requires its supported consent source, and a verified model result still requires provider execution evidence. Keep application-specific approvals, deployment gates, and enabled or disabled integrations in their established configuration.

For a release that updates the remote hook-file deployment guard itself, use this normal repair flow with the reviewed merged commit. After the refreshed guard is active, the installed `ah.py install-files` command accepts a proven Claude Code main or Codex Desktop root. It checks the existing command form and applies the same remote host, merged source, allowlist, backup, and audit requirements. A Desktop root qualifies through the actual signed runtime and supported GUI ancestry plus the current root metadata. Children and standalone CLI sessions do not inherit that authority.

Git versions below 2.54 cannot activate the installer's global commit-msg backstop. The host's installer reports that limitation. Review it alongside the other install results.
