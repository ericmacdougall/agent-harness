# Importing a local ledger into GoodQA (proposed contract)

**Status: proposal.** The harness side is built (`harness tickets export --format goodqa-import`, `bind`,
`sync-state`; see `docs/ledger.md`). The GoodQA server side is **not built**: this document is what a GoodQA owner
needs to build it, with a fixture pair (`testdata/ledger-import/`) that the harness tests keep consistent with the
CLI. Until the server exists, "continued live in GoodQA" is not delivered; the filed GoodQA ticket (linked from
#35695) tracks it. Source of the ask: ledger A235, GoodQA ticket #35695.

## Goals and non-goals

- Take the whole history of a local ledger (tickets, every status movement, comments, label and field changes) into a
  GoodQA project, keeping original times, and be safe to run again.
- Let the same ledger be imported once and then kept in step by deltas (`--since-bound`) until work continues in
  GoodQA.
- Not goals: live two-way sync, mapping claimed actors to GoodQA users, importing attachments, or trusting anything the
  ledger says about who did what.

Inspected on dev2 (read-only, `~/repos/bugtracker`): the reviewed-plan flow of `/orgs/:orgId/imports`
(`apps/api/src/modules/imports`, table `import_jobs` with an immutable `report` and per-row `results`), the
per-issue `issue_events` table (original `created_at` is writable by the importer), `issue_comments`, the
`issue_operations` idempotency table (`unique(project_id, operation_id)` with a `request_hash`), `api_idempotency_keys`,
and `issues.source`/`external_fingerprint`. Nothing was changed.

## Documents

### Import document (`goodqa-ledger-import/v1`, produced by the harness)

Canonical JSON, one object, no generation timestamp. Fields in order: `format`, `project` (`id` = ledger project id,
`slug`, `name`, `statuses[{key,name,category}]`), `frontier` (per writer: `writer`, `ops`, `wall_ms`, `ctr`, `last_op`),
`base_digest` (empty for a full export, the previous receipt's `export_digest` for a delta), `redacted`, `tickets[]`,
then `ops` (canonical op lines in fold order) or `ops_omitted: "redacted"`, then `digest` and `excluded`.

`digest` is the sha256 of the canonical document without `digest` and `excluded`; it is a pure function of the folded
state. `excluded` (counts of unverified, blocked, rejected, ignored and held-back ops) is informational and outside
the digest.

Each ticket carries `id` (`tk_...`), `handle`, `title`, `body`, `type`, `priority`, `status`, `category`, `labels`,
`created_ms`, `updated_ms`, `created_by`, `comments[]` and `history[]`. A history event has `op` (op id), `writer`,
`claimed_actor`, `kind` (`ticket.create`, `ticket.status_set`, `ticket.field_set`, `ticket.label_add`,
`ticket.label_remove`, `ticket.comment`), `wall_ms`, `ctr`, `field`, `from`, `to` and, for status moves, `to_category`.
Events are in fold order (`wall_ms`, `ctr`, writer, op id).

### Receipt (`goodqa-ledger-receipt/v1`, returned by GoodQA, accepted by `bind`)

```json
{"format":"goodqa-ledger-receipt/v1","goodqa_project":"<uuid>","import_id":"<opaque, at most 64 chars>",
 "ledger_project":"proj_...","export_digest":"<64 hex>","base_digest":"","redacted":false,
 "frontier":[{"writer":"w_...","ops":8,"wall_ms":0,"ctr":0,"last_op":"op_..."}],
 "tickets":[{"handle":"d974ebba","number":1}],"imported_at_ms":0}
```

Exactly these fields, no others. `export_digest`, `base_digest`, `frontier` and `redacted` echo the document that was
imported. `tickets` maps each ledger handle to the GoodQA issue number. The receipt is **advisory and
unauthenticated**: its digest is public, so it proves that harness and GoodQA agree on content, not that GoodQA stored
it, unless it arrives in the signed envelope below and the user pinned GoodQA's key.

### Signed receipts

GoodQA should sign what it returns. The envelope is
`{"format":"goodqa-ledger-receipt-signed/v1","receipt":{...},"alg":"ed25519","key_id":"<first 16 hex of sha256(raw 32-byte public key)>","sig":"<base64url, no padding, 64 bytes>"}`.
The signature covers the ASCII tag `goodqa-ledger-receipt/v1` plus a newline, then the canonical receipt: compact JSON,
keys sorted at every level, separators `,` and `:`, ASCII only, integers as plain digits, no trailing newline (Python:
`json.dumps(receipt, sort_keys=True, separators=(',', ':'), ensure_ascii=True)`). `import_id` must match
`[A-Za-z0-9._:-]{1,64}` so Go and Python give identical bytes. The receipt inside keeps exactly the fields above.
The user pins GoodQA's public key (32 raw bytes as hex, base64 or PEM SPKI) with `harness tickets bind --goodqa-key FILE`.
Once pinned, a bare receipt, a different `key_id` or a bad signature is refused and `sync-state --json` reports
`authenticated: true`; an unpinned ledger stays advisory. Fixture: `testdata/ledger-import/receipt.signed.json` with the
test-only key `goodqa-test.pub` (a fixed public seed, never a real key). The signing key is a GoodQA server secret and the
public key is published by GoodQA; rotation publishes a new key and the user runs `harness tickets unbind --confirm SLUG` and pins it with a new full import. The envelope carries no instance or expiry: one pinned key means one GoodQA.

## Endpoints

Modelled on the existing reviewed-plan import (`plan`, then `commit`). Both calls take an `Idempotency-Key` header.

1. `POST /projects/:projectId/ledger-imports` with the import document (up to 8 MiB, gzip allowed) creates a **plan**
   and writes nothing but the job row. Response: `{id, state: "planned", plan_sha256, plan}` where `plan` holds
   `tickets: {create, update, skip}`, `events: {create, skip}`, `number_map` (preview), `status_map` (ledger status key
   to GoodQA status, with unmapped keys listed), `conflicts[]` and `warnings[]`. The new-project variant is
   `POST /orgs/:orgId/ledger-imports` with `create_project: {name, slug}` in the body.
2. `GET /projects/:projectId/ledger-imports/:id` returns the plan and, after commit, the results.
3. `POST /projects/:projectId/ledger-imports/:id/commit` with `{plan_sha256, resolutions: [{ticket, field, choose}]}`
   (`choose` is `goodqa` or `ledger`; the default for an unlisted conflict is `goodqa`) applies the plan in batches of
   at most 500 events, resumable, and returns the receipt above. A commit whose `plan_sha256` is not the stored plan's
   is refused.

MCP tools mirror the two POSTs (`import_ledger_plan`, `import_ledger_commit`). Permission: project write plus an
`import` scope for agent keys; every commit writes one `audit_events` row (`ledger.import.commit`, metadata only).

## Mapping

| Ledger | GoodQA |
|---|---|
| `project.statuses[].category` | project workflow status through `status_map` (category `backlog`, `unstarted`, `started`, `completed`, `canceled`); an unmapped key is a plan warning and needs a `status_map` entry in the plan request |
| `ticket.create` | one `issues` row; the number is assigned in `created_ms` order from the project's next number; `source` is a new enum value `ledger_import`; `external_fingerprint` is the ledger ticket id, which is the per-ticket idempotency key |
| `type`, `priority` | the project's issue types and priorities by name (`task`, `bug`, `feature`, `chore`; `none` to `urgent`) |
| history events | `issue_events` rows keeping their original `created_at` (the event's `wall_ms`), `actor_id` null, and `data` holding `{ledger: {op, writer, claimed_actor, ctr}, field, from, to}`; status moves use the existing status-change event type, the rest a new `ledger_event` type |
| comments | `issue_comments` with the original time, no author, `body`, and `{ledger: {op, claimed_actor}}` metadata |
| labels | matched or created by normalised name |

Claimed actors are shown as "imported, claimed: NAME" and are never turned into a user or an agent persona.
`via_api_key_id` and `via_persona_id` stay null: they would assert something the ledger cannot prove.

## Idempotency

Per event: `issue_operations` with `operation_id = "ledger:" + <op id>` and `request_hash` = sha256 of the op's raw
canonical line. The same op id with the same hash is skipped; the same op id with a different hash refuses the whole
plan with `409 op_conflict`. Per ticket: `external_fingerprint` finds the existing issue. Re-importing the same document,
a document that overlaps an earlier one, or a retry after a lost response therefore changes nothing. The job itself is
keyed by the `Idempotency-Key` plus `plan_sha256`.

## Conflicts and resolutions

Nothing is merged silently. A plan lists a conflict when a ticket already exists and:

- GoodQA changed a field (or moved status) after the last receipt for this ledger, and the ledger also changed it, or
- a delta event's `from` does not match GoodQA's current value at that point, or
- the ordering of a touched ticket's history changed (a late-trusted writer's backdated ops reorder it).

Each conflict names the ticket, field, ledger value, GoodQA value and GoodQA's `updated_at`. The commit applies only what
`resolutions` chooses and defaults to **GoodQA wins**. Applied ledger values are written as ordinary events, so the
ticket history shows them.

## Freeze and delta sync

After a successful commit the project is the system of record and the ledger is `bound` locally. Further local writes
are allowed offline; `sync-state` shows them as `pending` and `export --since-bound` emits only those ops plus the
full history of each ticket they touch, with `base_digest` set to the last receipt's `export_digest`. GoodQA refuses
a delta whose `base_digest` is not the last committed `export_digest` for that ledger project (`409 base_mismatch`);
the remedy is a full export. A delta is planned and committed exactly like the first import.

## Redacted imports

`export --redact-secrets` masks secret-shaped text with `[REDACTED:type]`, sets `redacted: true`, and omits the raw
`ops`. GoodQA then keys idempotency on the history event op ids (hash of the event JSON), marks every ticket whose text
was masked as lossy, and does not continue such a ticket live without an explicit resolution. The receipt echoes
`redacted: true`; `bind` rebuilds in that same mode.

## Limits and errors

Document at most 8 MiB (gzip allowed), 5,000 tickets, 50,000 events, 64 KiB per op, 1 plan per project per minute,
commit batches of 500 events. Errors use GoodQA's error envelope:

| Status | Code | Meaning |
|---|---|---|
| 400 | `invalid_document` | not `goodqa-ledger-import/v1`, malformed, or a digest that does not recompute |
| 403 | `forbidden` | no project write or `import` scope |
| 409 | `op_conflict` | an op id already imported with different bytes |
| 409 | `base_mismatch` | a delta whose base is not the last committed export |
| 409 | `plan_stale` | `plan_sha256` is not the stored plan, or the project changed since planning |
| 413 | `too_large` | over a limit above |
| 422 | `unmapped_status` | a ledger status key with no `status_map` entry |
| 429 | `rate_limited` | plan rate limit |

The server recomputes `digest` (sha256 of the canonical document without `digest` and `excluded`) and refuses a
mismatch, so a hand-edited document cannot be imported under another digest.

## Trust and privacy

The document is user content from a machine GoodQA cannot verify: titles, bodies and comments pass the same
sanitisation and secret scan as ordinary issue text, and a finding refuses the plan rather than storing the secret.
`claimed_actor` and `writer` are metadata. The import never grants anyone access to a project.

## As implemented by GoodQA (#35824, bugtracker draft PR #1215)

The server was built from this contract by a separate owner (branch `claude/ledger-import-35824-20261105-r2`). Where it
differs from or adds to the text above, the implementation is what runs:

- **Endpoints (all under `/v1`):** `POST /projects/:projectId/ledger-imports` (plan), `GET /projects/:projectId/ledger-imports[/:id]`,
  `POST .../:id/commit`, `POST .../:id/cancel`, and `GET /ledger-imports/signing-key` (authenticated; returns
  `{alg: "ed25519", key_id, public_key_hex}`, 404 when the server has no key). The new-project variant is
  `POST /orgs/:orgId/ledger-imports?create_project={"name":..,"slug"?:..,"description"?:..}` with GET, commit and cancel under
  `/orgs/:orgId/ledger-imports/:id`; a delta is refused there (`409 base_mismatch`). Options travel in the query (`status_map`
  and `create_project`, both JSON); the `Idempotency-Key` header is required on plan. Response bodies carry `project_id`, `plan`,
  `progress`, `results`, `receipt` and `signed_receipt` (the signed envelope, null when the server has no key). Commit returns
  202 while batches remain: post the same request again.
- **Idempotency** is stored per project in `ledger_import_ops`, not in `issue_operations` (whose `kind` check admits only
  `issue_create`, `issue_update` and `comment_create`).
- **Access:** the API-key family is `ledger_import` and is explicit-only (a key naming no family, or only `issues`, is refused;
  over MCP the key must name both `mcp` and `ledger_import`). Permission is project role pm or better; the org variant also needs
  `project:create`.
- **Attribution:** imported issues list the importing user as reporter; events and comments have no actor and carry
  `data.ledger {op, writer, claimed_actor, ctr}`.
- **Re-committing** an older full export makes it the last committed export again, so a later delta must use that receipt's
  `export_digest`. The harness rebinds to the receipt it is given, so this stays consistent.
- **Limits:** one plan per project (per org for the new-project variant) per minute, 8 MiB, 5,000 tickets, 50,000 events, 64 KiB per
  op. The 8 MiB cap binds first (roughly 10 to 20 thousand events fit).
- **Validation beyond the digest:** members in canonical order; op lines canonical and agreeing with the history events that cite
  them; history in fold order with exactly one `ticket.create` (an op ordered before the create is allowed); field limits equal to
  the snapshot's (title 1 to 1024 characters on one line, label 1 to 128, priority and type 1 to 32); `ctr` at most 2^31-1; times at
  most 8.64e15 ms; and, for a full unredacted export, the frontier must equal its own op lines per writer (count and last op). A
  secret-shaped string anywhere, ids and writers included, is refused `422 secret_detected`. A redacted export carries no ops, so
  its frontier is echoed unchecked.
- **Status mapping:** a `status_map` entry, else the identical GoodQA status key, else the category default with a plan warning;
  an unmapped target with no stage is `422 unmapped_status`.
- **Error codes added:** `idempotency_conflict`, `invalid_resolution`, `invalid_status_map`, `secret_detected` (422),
  `import_failed` (422, a batch failed: the job is failed and a re-plan of the same document resumes), `already_committed`,
  `plan_stale`.

## What GoodQA has to build

A `ledger_imports` table (id, project, ledger project, export digest, base digest, plan, state, results, receipt), the
`issue_source` value `ledger_import`, the `ledger_event` event type, the two endpoints and tools above, and the
status-map step. No existing table changes meaning. Open questions for the GoodQA owner: whether a new project can be
created by the same call, which role may import, and whether receipts should be signed.
