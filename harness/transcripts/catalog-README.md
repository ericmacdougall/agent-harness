# agent-transcripts (catalog)

This private repo is the catalog of the agent transcripts archive (agent-harness, GoodQA #16650). It
maps hosts, sessions, projects, tickets and PRs to compressed transcript chunks. The chunks themselves
live in the private per-host monthly shard repos `agent-transcripts-<host>-<YYYY>-<MM>-p<N>`.

## This archive is NOT secret-free

Every record passed a two-pass redaction gate before it was pushed. A record that still tripped the
verifier was replaced by an omitted marker. Redaction has known gaps, and the owner accepted them
explicitly when choosing redacted plaintext with no encryption ("Scrub only, plaintext", answer
8d9ac187-f758-4aac-b3ea-8e54ebf74057/fce7446f-9b52-42df-902f-2856da6dd1d8):

- Free-text passwords, and short secrets with no keyword or vendor prefix. Raw 64-hex keys are not
  redacted because sha256 digests appear everywhere.
- Third-party personal data beyond email addresses and North American phone numbers. That includes
  ParentProof parents.
- Git history is permanent. A leaked value cannot be scrubbed without deleting and recreating the repo.
- GitHub secret scanning is not available on these repos.

Treat every file here as sensitive. Never make this repo or a shard public, fork it or add
collaborators. The archiver checks all four before every push and refuses on any failure.

## Layout

- `shards/<host>.json`: that host's shard ledger (repo, month, part, compressed bytes, chunk count).
- `index/<host>.jsonl`: one row per pushed chunk (schema 1).
- `manifests/<host>/<source>/<relpath>.json`: one manifest per source file, listing every generation's
  ordered chunk list, hashes, `fully_archived` and omissions.

The format is specified in `docs/transcripts-index.schema.json` and `docs/transcripts-archive.md`
in the agent-harness repo.

## Recovery truth

- Recovery from git is byte-identical to the redacted archive, never to the source.
- Exact-source recovery comes from the local source file or the Dropbox log backup.

Use `ah transcripts find|cat|recover|verify|reindex`; never edit these files by hand.
