# Repair an existing harness installation

Use the repair command to refresh existing Claude and Codex harness files on a workstation and its SSH worker. Both hosts need Python 3.11 or later and existing installations. Run it from an inspected checkout of Agent Harness.

```sh
scripts/repair-harness.sh --ref REVIEWED_MERGED_COMMIT --host t2-dev --check
scripts/repair-harness.sh --ref REVIEWED_MERGED_COMMIT --host t2-dev --apply
```

Replace `REVIEWED_MERGED_COMMIT` with the full commit SHA from the reviewed release. Preview is the default. Use `--python /absolute/path/to/python3` when interpreter discovery needs an explicit choice. The SSH target must already have a trusted host key and working account access.

The command fetches the canonical repository into private storage and verifies that the requested commit belongs to the fetched main history. A later commit on main keeps earlier reviewed commits usable. The same source archive supplies both hosts. Both installers preview on both hosts before either installation changes. Apply runs on the worker first and then locally. It uses the installers' hooks-only path and backup handling, checks installed files, and checks preservation of the existing instruction and settings files.

Progress and diagnostics remain in private work directories. An error after apply begins can leave a host partially updated. Keep its logs and installer backups and inspect the reported phase before deciding how to recover. A lost SSH response leaves the remote outcome uncertain. The command requires explicit investigation before another attempt.

The tool repairs installation drift. Codex hook review uses the native `/hooks` command or Settings > Hooks. An audit's model approval still requires its supported consent source, and a verified model result still requires provider execution evidence. Keep application-specific approvals, deployment gates, and enabled or disabled integrations in their established configuration.

Git versions below 2.54 cannot activate the installer's global commit-msg backstop. The host's installer reports that limitation. Review it alongside the other install results.
