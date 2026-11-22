# Build one native Codex receipt proof

The **Codex receipt proof build** workflow runs by manual dispatch from `main`. It fetches the reviewed source capsule and official Codex source at fixed Git revisions. The driver verifies both revisions and the patch digest before building. The build receives no native account session or customer audit inputs.

After review and delivery of the workflow, use the GitHub Actions page to dispatch it once from `main`.

The job uses a standard public Ubuntu runner and stops after 60 minutes. It runs the focused transport, compaction, App Server and schema checks before retaining the compressed proof binary and its build manifest. Download the short-lived artifact, verify `artifacts.sha256`, and verify `binary.sha256` against the decompressed `codex` file. The manifest records the build workflow revision, the capsule revision and the patched upstream tree.

This artifact is for side-by-side testing. Live validation needs a separately reviewed consumer and authorization for a scoped native run.
