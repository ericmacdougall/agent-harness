# Native context diagnostics and inert admission proposals

OpenAI runtime origin, a user-message candidate and authority to act as main are
separate facts. This increment provides read-only origin diagnostics, weak native
citations and an inert bootstrap preview. It does not enable native main-agent
stamps, change commit attribution, authorize protected stops or install hooks.
Both installer copy manifests include the three modules, since `caller_identity`
imports `native_context`. The Codex copy set also includes the existing
`wal_note.py`, required by `ah` writes and its doctor import contract. This is
packaging only; no installed files or hook configuration are changed by the source
commit.

## Runtime origin

Run `python3 harness/hooks/native_context.py probe` in the source checkout.
On macOS the probe walks a bounded kernel-observed ancestry chain and checks the
running Codex identity using Security.framework's **running guest** validation
against the pinned OpenAI team and executable identifier at each bounded ancestor,
independent of its filename. A basename is only a deny hint. It rechecks
kernel PID/start/parent/executable facts and running code identity/CDHash around
the attestation. A changed process, same-PID exec swap, invalid signature,
inaccessible guest or ambiguous ancestry returns unknown. A nearer recognized
Claude/Kimi runtime prevents attribution to an outer Codex ancestor. An ordinary
process does not acquire OpenAI origin from environment variables or a pathname
in JSON. No attestation is cached for later use.

Even a verified result has `role: unknown`, `main_authority: false` and
`strong_user_source: false`. A desktop runtime may serve multiple chats, and a
standalone CLI owner's signed process is not the desktop main chat. Process
ancestry does not authenticate a hook event or select a thread.

`caller_identity.is_main` denies known or ambiguous native context **before**
checking a legacy Claude transcript. A valid Claude root transcript supplied by
an ordinary native tool therefore cannot confer Claude-main authority. Native
environment/transcript hints can only deny; they never authenticate. Existing
genuinely Claude checks and the `take_stamp` API are retained. Unsupported hosts
provide no new origin evidence; the existing legacy Claude path remains there.
The probe is a bounded guardrail, not an isolation boundary against an agent
that can replace installed code. Concurrent undetectable exec-away-and-back and
unrecognized wrapper runtimes are outside the assurance provided by snapshots.

### Operational requirement: restart sessions after a runtime self-update

The probe fails closed. A long-running session whose runtime binary was deleted or replaced by a
self-update (the kernel then reports no executable path and the Security framework refuses a guest
lookup) has no verifiable identity. Such a session is denied main authority and, with commit
attribution active, its commits are refused as "native runtime attribution uncertain". This is
intended and is deliberately not relaxed for deleted binaries (user decision, goodqa#15565). After
installing, and after any runtime self-update, restart the affected sessions (resume with the same
session id) so they run the current binary. A stale session shows a runtime process whose
`lsof -p <pid>` text file no longer exists.

A Terminal-launched session has root-owned `/usr/bin/login` above its shell, and the kernel withholds
its BSD info from the user. Only that exact kernel path ends the walk as a non-native chain; any other
unreadable ancestor, and the caller itself, stay uncertain.

## Weak native user-message discovery

Pass a bounded app `read_thread` snapshot on stdin:

```sh
python3 harness/hooks/native_user_source.py list < private-native-snapshot.json
```

The snapshot requires `thread.id`, `thread.hostId`, and `turns` containing actual
turn/item IDs and text `userMessage` items. The listing preserves those opaque
identities in `codex:<host>/<thread>/<turn>/<item>` citations. The entire bounded
source is checked for credential shapes before any excerpt selection or display
cutoff. If any are found, discovery returns metadata and a fixed redacted marker;
excerpt resolution rejects for that source, including value-only selections and
apparently safe aliases elsewhere in the message. This deliberately favors
privacy over excerpt availability. Identifiers are not converted into Claude UUIDs. The literal
excerpt resolver requires the exact host/thread/turn/item and matching source
text. Assistant, tool, hook, compaction and explicitly automated messages are
excluded. Duplicate keys/identities and oversized or malformed inputs reject.

Every first-increment result is weak. There is no production strong-provider
registry, CLI flag or configuration that upgrades imported JSON or an injected
adapter. Claimed human origin, message time and root status do not authenticate
the import. Event time remains null rather than being inferred from an ID or
capture time. The listing is not wired into protected-stop approval resolution.
Store snapshots privately; do not publish raw chat content in this repository.

## Inert bootstrap preview

`python3 harness/hooks/native_admission.py preview < private-proposal.json`
accepts only schema 1 proposals in `PROPOSED_NOT_ADMITTED` state. A proposal has
the exact fields below; actual runtime/chat identities belong outside Git:

```json
{
  "schema": 1,
  "state": "PROPOSED_NOT_ADMITTED",
  "generation": null,
  "activation_profile": "operator_exact_operation_only",
  "automatic_native_main": false,
  "operation_grants": [],
  "runtime_observation": {},
  "proposed_roles": [
    {"host": "local", "thread": "example-thread", "role": "orchestrator", "admitted": false}
  ],
  "user_source_evidence": {
    "platform": "codex", "host": "local", "thread": "example-thread",
    "turn": "example-turn", "item": "example-item", "evidence_only": true,
    "individual_message_time": null, "native_human_origin_attestation": null
  },
  "bootstrap_status": "Proposed only; no active registry exists."
}
```

The output binds the canonical candidate digest and proposed roles, with null
active generation, empty grants, no installed changes and authority `none`.
The validator rejects active generations, self-admitted roles, grants, automatic
mode, unexpected policy/path fields and strong-source claims. It consumes only
stdin, never a registry file or symlink. It cannot apply, enroll, activate, invoke
elevation, write a stamp or launch an operation. A digest binds candidate bytes;
it is not an approval receipt or a source/diff authenticity claim.

## Remaining activation boundary

Automatic native-main admission stays disabled until a separately reviewed
app-owned adapter authenticates event/thread/root-versus-child/generation in a
way that ordinary tool subprocesses cannot replay. The observed native snapshot
shape supplies neither authenticated human origin nor actual per-item event time.
The first increment has no strong adapter, including for injected test providers.

A future operator-approved exact-operation helper needs its own reviewed diff,
two security plan reviews and human/native-policy approval. Its protected registry
must resist model writes; mode 0700 under the same user is insufficient. It must
bind the full command, cwd, repo/PR, reviewed HEAD/packet, generation, expiry and
one-use consuming PID/start. Children/project owners, mismatches, replay and stale
generations must fail closed. This helper is **not implemented or activated here**.
Native Review hooks approval remains a separate required trust step for changed
hooks/plugins. Existing exact-PID, freshness, same-session and interactive-process
stop controls remain unchanged. Weak citations cannot satisfy those controls.

The original commit-hook marker-loss diagnosis remains unverified until an
existing affected hook is observed with metadata-only diagnostics. Do not enable
attribution from this probe or suppress markers to work around that gap.
