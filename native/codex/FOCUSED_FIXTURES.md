# Sources for the focused Codex fixture names

The [literal log fixtures](focused-log-fixtures.json) use Rust libtest output with synthetic durations and filtered counts. Their test names come from the declarations below. The build checks a single successful summary and every expected completed name for each command.

The source base is [OpenAI Codex d32063f9](https://github.com/openai/codex/tree/d32063f96c2dff1dc96af839b3952abb6acfeda4). The [patch capsule 8d688c1](https://github.com/ericmacdougall/agent-harness/tree/8d688c1c9a548f14de0a1c4b9475ef42e607684b/native/codex) pins patch SHA-256 `90141e64b41ec86c31c5a320535c4cb9300aab29894117544a44a746386d9c1f`. All paths below are relative to the patched upstream `codex-rs` directory. The table records the Git blob IDs of the files that declare the selected Rust tests.

| Build group | Rust module evidence | Declaration file and blob |
| --- | --- | --- |
| tracker | `codex-api/src/lib.rs`: `pub(crate) mod sse;`, `sse/mod.rs`: `pub(crate) mod responses;`, `responses.rs`: `mod tests {` | `codex-api/src/sse/responses.rs` `f9620e52083ec4495d164e63ce845ea4658f421a` |
| sse | Cargo integration test root `sse_end_to_end.rs` | `codex-api/tests/sse_end_to_end.rs` `521790377e1337cf5c6c7fd792247baf5992743d` |
| websocket | `core/tests/all.rs`: `mod suite;`, `suite/mod.rs`: `mod client_websockets;` | `core/tests/suite/client_websockets.rs` `18468066a2aa92cc51be6a043d901c550d6dc2bf` |
| compaction | `core/src/lib.rs`: `mod compact_remote_v2;`, `compact_remote_v2.rs`: `mod tests {` | `core/src/compact_remote_v2.rs` `2dea07bd7ba0a9bbf279206630dcfee9e945c6f7` |
| app-server | `app-server/tests/all.rs`: `mod suite;`, `suite/mod.rs`: `mod v2;`, `v2/mod.rs`: `mod turn_start;` | `app-server/tests/suite/v2/turn_start.rs` `11a69d1b5bc35a86328bb558e22f0ecf6248b2da` |
| schema-export-0, schema-export-1, schema-verify | `app-server-protocol/src/lib.rs`: `mod schema_fixtures_tests;` | `app-server-protocol/src/schema_fixtures_tests.rs` `8186255ae7e28fbd117d5a33686815575e061a2e` |

## Tracker, transport and compaction declarations

```rust
// codex-api/src/sse/responses.rs, inside tests
#[test]
fn response_model_observation_requires_bound_unambiguous_provider_metadata()
#[test]
fn response_model_observation_is_consumed_by_its_terminal_event()
// codex-api/tests/sse_end_to_end.rs
async fn responses_sse_binds_http_model_header_to_its_one_response() -> Result<()>
// core/tests/suite/client_websockets.rs
async fn responses_websocket_model_observation_does_not_cross_response_boundaries()
// core/src/compact_remote_v2.rs, inside tests
async fn collect_compaction_output_accepts_additional_output_items()
```

## App Server case expansion

`app-server/tests/suite/v2/turn_start.rs` declares `async fn turn_start_emits_raw_response_completed_with_upstream_usage(...)` with these `#[test_case(...; "description")]` descriptions in source order:

```text
without_usage_metadata
without_amount
null_amount
zero_amount
exact_amount
null_extra
zero_extra
nested_extra
```

`Cargo.lock` selects version `3.3.1` of both macro crates. The digests below were checked against the published crate bytes.

| Crate | Cargo.lock SHA-256 | Source excerpt |
| --- | --- | --- |
| [test-case-macros](https://static.crates.io/crates/test-case-macros/test-case-macros-3.3.1.crate) | `5c89e72a01ed4c579669add59014b9a524d609c0c88c6a585ce37485879f6ffb` | `src/lib.rs:127` sets `let mod_name = item.sig.ident.clone();`. Line 142 emits `mod #mod_name {` containing the rendered cases. |
| [test-case-core](https://static.crates.io/crates/test-case-core/test-case-core-3.3.1.crate) | `adcb7fd841cd518e279be3d5a3eb0636409487998a4aff22f3de87b81e88384f` | `src/test_case.rs:121` emits `fn #test_case_name() -> #typ`. Lines 138–145 apply `escape_test_name(desc)`; lines 159–166 take the declared description. |

`test-case-core/src/utils.rs` lowercases alphanumeric runs and replaces separators with a single underscore. Each chosen description already has that form. Combining the test module, the original function identifier, and each case identifier produces the eight qualified App Server fixture names.

## Schema declarations

```rust
#[test]
fn typescript_schema_fixtures_match_generated() -> Result<()>
#[test]
fn json_schema_fixtures_match_generated() -> Result<()>
#[test]
fn stable_precomputed_exports_match_schema_fixtures() -> Result<()>
#[test]
fn experimental_precomputed_exports_match_generated() -> Result<()>
#[test]
#[ignore = "invoked by `just write-app-server-schema`"]
fn write_schema_fixtures_from_env() -> Result<()>
```

The stable and experimental export commands each select the ignored writer explicitly. The schema verification command executes the other four cases and leaves the writer ignored.
