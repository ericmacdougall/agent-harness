# Codex response model observation

This source patch propagates bounded, provider-returned model metadata to the Codex App Server's existing experimental `rawResponse/completed` notification. The notification identifies the thread, turn and upstream response. Each observation identifies the model and its source. The pinned upstream commit, patch digest, toolchain and Linux target are in [source.json](source.json).

The HTTP transport can bind a model header to its one Responses stream. On a persistent WebSocket, a model observation needs the matching response ID. Conflicting, malformed or unbound metadata leaves the observation absent. A completion-body field is tracked separately so a caller can distinguish it from a provider header. In a native ChatGPT audit, only matching, bound provider-header evidence can establish the served model under the current receipt policy.

The patch adds transport and App Server fixture cases without requiring a provider account. A source check can confirm the patch applies to the pinned release. A focused isolated Linux build must separately run the fixture tests, regenerate the schema from the patched Rust types, and record the binary's hash. The resulting binary has a distinct build manifest and is intended for side-by-side validation. A build cannot establish which metadata a live signed-in service sends.

The patch applies to the Apache-2.0-licensed OpenAI Codex source. The upstream [license](LICENSE.upstream) and [notice](NOTICE.upstream) accompany it.
