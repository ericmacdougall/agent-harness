#!/usr/bin/env bash
# One public-source Linux build. GitHub credentials are not inherited by this process.
set -Eeuo pipefail
umask 077

readonly harness_root="$PWD"
readonly upstream="$harness_root/codex-upstream"
readonly capsule="$harness_root/codex-receipt-capsule"
readonly manifest="$capsule/native/codex/source.json"
readonly patch="$capsule/native/codex/model-receipt.patch"
readonly test_home_patch="$harness_root/native/codex/test-arg0-home.patch"
readonly run_root="${1:?expected runner temp directory}/codex-receipt-work"
readonly output="${1:?expected runner temp directory}/codex-receipt-output"
readonly test_home_base="$run_root/fixture-homes"
readonly upstream_commit=d32063f96c2dff1dc96af839b3952abb6acfeda4
readonly capsule_commit=8d688c1c9a548f14de0a1c4b9475ef42e607684b
readonly patch_sha=90141e64b41ec86c31c5a320535c4cb9300aab29894117544a44a746386d9c1f
readonly test_home_patch_sha=628279287a3510edaa65a3a585f7e9979f261a30487fb3b894f67d4377d78ffc
readonly toolchain=1.95.0
readonly target=x86_64-unknown-linux-gnu
unset CODEX_TEST_ARG0_HOME_BASE

[[ "$(uname -m)" == x86_64 ]]
actual_upstream="$(git -C "$upstream" rev-parse --verify HEAD)"
actual_capsule="$(git -C "$capsule" rev-parse --verify HEAD)"
upstream_status="$(git -C "$upstream" status --porcelain=v1)"
capsule_status="$(git -C "$capsule" status --porcelain=v1)"
if [[ "$actual_upstream" != "$upstream_commit" || "$actual_capsule" != "$capsule_commit" ||
      -n "$upstream_status" || -n "$capsule_status" ]]; then
  printf '%s\n' "The pinned source checkouts could not be verified." >&2
  exit 1
fi
printf '%s  %s\n' "$patch_sha" "$patch" | sha256sum --check --strict -
printf '%s  %s\n' "$test_home_patch_sha" "$test_home_patch" | sha256sum --check --strict -
python3 - "$manifest" "$upstream_commit" "$patch_sha" "$toolchain" "$target" <<'PY'
import json
import sys
from pathlib import Path

doc = json.loads(Path(sys.argv[1]).read_bytes())
assert doc == {
    "upstreamRepository": "https://github.com/openai/codex.git",
    "upstreamTag": "rust-v0.169.0",
    "upstreamCommit": sys.argv[2],
    "patchSha256": sys.argv[3],
    "toolchain": sys.argv[4],
    "target": sys.argv[5],
    "receiptProtocol": "codex-response-model-observation-v1",
}
PY
mkdir -m 700 "$run_root" "$output"
mkdir -m 700 "$test_home_base"
python3 - "$test_home_base" <<'PY'
import os
from pathlib import Path
import stat
import sys

base = Path(sys.argv[1])
temp = Path(os.environ.get("TMPDIR") or "/tmp")
info = base.lstat()
if (not base.is_absolute() or base.resolve(strict=True) != base
        or base.is_relative_to(temp) or base.is_relative_to(temp.resolve(strict=True))
        or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != os.geteuid() or any(base.iterdir())):
    raise SystemExit("The isolated fixture home must be fresh, private and outside the system temp root.")
PY
git -C "$upstream" apply --check --index --whitespace=error "$patch"
git -C "$upstream" apply --index --whitespace=error "$patch"
git -C "$upstream" apply --check --index --whitespace=error "$test_home_patch"
git -C "$upstream" apply --index --whitespace=error "$test_home_patch"
python3 "$harness_root/native/codex/normalize-lock.py" "$upstream/codex-rs" > "$run_root/lock-provenance.txt"
git -C "$upstream" add -- codex-rs/Cargo.lock
patched_tree="$(git -C "$upstream" write-tree)"
harness_commit="$(git -C "$harness_root" rev-parse --verify HEAD)"
if ! [[ "$patched_tree" =~ ^[0-9a-f]{40}$ && "$harness_commit" =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' "Complete source provenance identifiers are required." >&2
  exit 1
fi
readonly patched_tree harness_commit

# The isolated Cargo home has no Rustup installation to self-update.
rustup toolchain install "$toolchain" --profile minimal --target "$target" --no-self-update
rustup run "$toolchain" rustc --version --verbose > "$run_root/rustc.txt"
grep -Fx "host: $target" "$run_root/rustc.txt"

# The pinned upstream checkout provides the trust anchor for these prebuilt GNU V8 files.
readonly v8_version=152.2.0
test "$(python3 "$upstream/.github/scripts/rusty_v8_bazel.py" resolved-v8-crate-version)" = "$v8_version"
readonly v8_profile="ptrcomp_sandbox_release_$target"
readonly v8_manifest="rusty_v8_$v8_profile.sha256"
readonly v8_archive="librusty_v8_$v8_profile.a.gz"
readonly v8_binding="src_binding_$v8_profile.rs"
readonly v8_dir="$run_root/v8"
mkdir -m 700 "$v8_dir"
for item in "$v8_manifest" "$v8_archive" "$v8_binding"; do
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 180 \
    "https://github.com/openai/codex/releases/download/rusty-v8-v$v8_version/$item" \
    --output "$v8_dir/$item"
done
(
  cd "$v8_dir"
  awk -v file="$v8_manifest" '$2 == file { print }' \
    "$upstream/third_party/v8/rusty_v8_152_2_0_release_manifests.sha256" | sha256sum --check --strict -
  test "$(wc -l < "$v8_manifest")" -eq 2
  tr -d '\r' < "$v8_manifest" | sha256sum --check --strict -
)
export RUSTY_V8_ARCHIVE="$v8_dir/$v8_archive"
export RUSTY_V8_SRC_BINDING_PATH="$v8_dir/$v8_binding"

# Use one compatible profile for both the narrow fixtures and the proof binary.
export CARGO_TARGET_DIR="$run_root/target"
export CARGO_BUILD_JOBS=3 CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_OPT_LEVEL=1 CARGO_PROFILE_RELEASE_LTO=false
export CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_PROFILE_RELEASE_STRIP=symbols
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
export STABLE_GIT_COMMIT="$capsule_commit"
cd "$upstream/codex-rs"

df -h "$run_root"
readonly -a cargo_cmd=(rustup run "$toolchain" cargo)
run_focused() {
  local label="$1"
  shift
  CODEX_TEST_ARG0_HOME_BASE="$test_home_base" \
    "${cargo_cmd[@]}" test --locked --release --target "$target" "$@" 2>&1 | tee -a "$run_root/$label.log"
  python3 "$harness_root/native/codex/verify-focused.py" "$label" "$run_root/$label.log"
}
run_focused tracker -p codex-api --lib response_model_observation
run_focused sse -p codex-api --test sse_end_to_end responses_sse_binds_http_model_header_to_its_one_response
run_focused websocket -p codex-core --test all responses_websocket_model_observation_does_not_cross_response_boundaries
run_focused compaction -p codex-core --lib collect_compaction_output_accepts_additional_output_items
run_focused app-server -p codex-app-server --test all turn_start_emits_raw_response_completed_with_upstream_usage
for kind in 0 1; do
  CODEX_APP_SERVER_SCHEMA_ROOT="$PWD/app-server-protocol/schema" CODEX_APP_SERVER_SCHEMA_EXPERIMENTAL="$kind" \
    run_focused "schema-export-$kind" -p codex-app-server-protocol --lib \
      schema_fixtures_tests::write_schema_fixtures_from_env -- --exact --ignored
done
run_focused schema-verify -p codex-app-server-protocol --lib schema_fixtures_tests

"${cargo_cmd[@]}" build --locked --release --target "$target" -p codex-cli --bin codex
git -C "$upstream" diff --exit-code -- codex-rs/Cargo.lock
readonly binary="$CARGO_TARGET_DIR/$target/release/codex"
test -x "$binary"
test "$("$binary" --version)" = "codex-cli 0.169.0"
install -m 0755 "$binary" "$run_root/codex"
(
  cd "$run_root"
  sha256sum codex > "$output/binary.sha256"
  gzip -n -1 -c codex > "$output/codex-linux-x64.gz"
)
cp "$manifest" "$output/source.json"
cp "$run_root/rustc.txt" "$output/rustc.txt"
cp app-server-protocol/schema/precomputed/app-server-exports-stable.json.zst "$output/"
cp app-server-protocol/schema/precomputed/app-server-exports-experimental.json.zst "$output/"
printf 'harness_commit=%s\ncapsule_commit=%s\npatched_tree=%s\nprofile=release-opt1-no-lto\n' \
  "$harness_commit" "$capsule_commit" "$patched_tree" > "$output/build-provenance.txt"
printf 'fixture_home_patch_sha256=%s\n' "$test_home_patch_sha" >> "$output/build-provenance.txt"
cat "$run_root/lock-provenance.txt" >> "$output/build-provenance.txt"
(
  cd "$output"
  sha256sum binary.sha256 codex-linux-x64.gz source.json rustc.txt build-provenance.txt \
    app-server-exports-stable.json.zst app-server-exports-experimental.json.zst > artifacts.sha256
  test "$(du --apparent-size --bytes --summarize . | cut -f1)" -le 134217728
)
df -h "$run_root"
