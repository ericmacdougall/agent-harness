# Build one native Codex receipt proof

The **Codex receipt proof build** workflow runs by manual dispatch from `main`. It fetches the reviewed source capsule and official Codex source at fixed Git revisions. The driver verifies both revisions and the patch digest before building. The build receives no native account session or customer audit inputs.

The upstream `rust-v0.169.0` tag sets `[workspace.package].version` to `0.169.0` while its checked-in `Cargo.lock` still lists 173 local packages at `0.0.0`. Before building, the driver checks both lockfile digests and the matching inherited-version manifests. It changes only those 173 workspace versions and records the effective lockfile in the patched tree. The receipt source patch stays separate. Dependencies, external source pins and checksums stay byte-identical. Every Cargo test and build uses `--locked`.

The release guard refuses to create helper aliases when `CODEX_HOME` is under the system temporary directory. The pinned test overlay puts the WebSocket integration launcher and the eight selected App Server cases in disposable homes beneath a fresh private runner directory outside that system root. The selected App Server release fixtures use the supported `features.plugins=false` override to prevent startup plugin work. Debug fixtures keep their existing builder defaults. The driver supplies the private base only to Cargo test commands. It verifies the overlay separately from the receipt capsule, records its digest with build provenance, and keeps the release guard and release profile active.

After review and delivery of the workflow, use the GitHub Actions page to dispatch it once from `main`.

The job uses a standard public Ubuntu runner and stops after 90 minutes. A previous run took about 55 minutes to reach the App Server fixtures. The larger budget allows time for schema verification and the final CLI build with the same test scope. The driver checks the exact fixture names and pass totals for transport, compaction, App Server and schema before retaining the compressed proof binary and its build manifest. The run retains test output in its GitHub Actions log even if compilation or a fixture fails. Download the short-lived artifact, verify `artifacts.sha256`, and verify `binary.sha256` against the decompressed `codex` file. The manifest records the build workflow revision, the capsule revision, the patched upstream tree, and the original and effective Cargo lockfile digests.

This artifact is for side-by-side testing. Live validation needs a separately reviewed consumer and authorization for a scoped native run.

Run `python3 -B native/codex/test_verify_focused.py` to check the proof parser against independent literal logs. [Fixture sources](FOCUSED_FIXTURES.md) identifies the pinned Rust declarations and macro case names.

Run `python3 -B native/codex/test_build_proof.py` to verify that source, test fixture home, and provenance failures stop the driver before the Rust toolchain step. The test exercises the real driver with local stand-ins and an explicit build sentinel.

Run `python3 -B native/codex/test_lock_normalization.py` to check version-only lockfile repair and rejection of unverified lockfiles.
