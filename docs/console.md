# Interactive console guide

The console runs locally as one Go executable with embedded HTML, JavaScript,
and CSS. A browser supplies the interface; locally installed Codex and Claude
Code provide the models and tools. No Node runtime, Electron runtime, hosted
console account, or separate frontend server is required.

Build and start instructions are in [console/README.md](../console/README.md).
The optional [conversation launcher](tui-plugin.md) passes supplied context
into a clearly labeled new session. It does not take over an existing desktop
chat or claim to have imported history that the provider cannot return.

## Sessions and work

Use the top tabs to switch sessions or create a new one. Each session has its
own provider identity, cwd, transcript, and work state. The composer sends to
the selected session. The file picker snapshots selected file contents; a
changed original does not silently replace the selected snapshot.

The sidebar shows agent information supplied by the provider and the console's
independent review sessions. Select a node to read its available transcript.
Unsupported controls remain disabled with a reason. An embedded Claude child
does not have an independent host control channel; interrupting its parent
controls the process tree. An application-managed reviewer has a separate
provider session. Missing model, write, or activity telemetry is unknown.

Direct resume of a native Codex child is unavailable until the provider exposes
a bounded child-context probe for the authentication, network, browser, and
filesystem boundaries the task requires. Thread metadata is not capability
proof after a parent account or permission change, so the console does not send
a resume turn to the old child. Reconcile its WAL, messages, branch/worktree,
processes, and possible in-flight effects; confirm the old writer is quiescent;
then dispatch one fresh owner through a supported native mechanism in the
current authenticated parent context. That replacement remains pending until
performed; the console does not claim to create it automatically.

Substantive work uses bounded checkpoints and independent review. A structured
review is tied to its actual subject and evidence. Unknown transport outcomes,
subject drift, user pause, and exhausted repair budgets stop automatic
advancement and explain why. Review does not make arbitrary repository code
safe to run. All provider processes run as the same local OS user.

Native finality requires an exact request binding and a durable final receipt
before the follow-up queue can advance. For Codex, only the correlated
`turn/start` RPC reply binds a request to its turn ID; `turn/started` is not
authority. Up to sixteen distinct early completions, limited to 256 KiB of
retained identity/status/error strings, can wait for that reply. A missing or
ambiguous binding, failed reply with early completion, or completion overflow
leaves ambiguous work unknown with no replay, even if the provider finished.
Matching early completions are finalized after the reply, including for managed
reviews. Root content and telemetry require the same exact active binding;
identified pre-reply frames stay private in a separate 128-frame/256-KiB buffer.
Content-buffer overflow drops diagnostic content without establishing finality.
Questions without exact active turn identity are rejected before entering the
waiting state; checkpoint updates recheck binding at their mutation points.
See the [console README](../console/README.md#workflow-and-history) for identity
shapes, deduplication limits, buffering behavior and local-test limitations.

Claude stream-json results do not identify the input request. Each process
therefore admits only one user turn, and its request identity never changes.
Before another turn, the console closes stdin and waits up to five seconds for
exit, then starts a fresh process with `--resume` and the same conversation ID.
The task/checkpoint and follow-up revision bindings still accompany each turn.
Failure to confirm exit refuses replacement; failure to resume does not fall
back to a new conversation. This adds process startup overhead and relies on
the CLI's conversation persistence and resume behavior. Late output from the
retired process cannot finalize the next request. An unknown or final request
cannot be reopened by a late acknowledgment, error, or duplicate completion.

### Follow-up queue and review authority

While tracked work is active, **Queue follow-up** records the new request
without replacing the current objective. The queue is private, durable, FIFO,
and bounded: at most eight inputs can be pending; each message is at most
128 KiB; retained text and the expanded objective each have a 256 KiB bound;
and all retained attachment snapshots together are limited to 16 MiB and 16
files. Up to 256 queue receipts may remain while delivered or discarded entries
await cleanup. The same request ID is idempotent only while its text and
attachment bytes match. A held or unknown head blocks later entries rather than
allowing them to overtake uncertain work.

Queue acceptance alone does not invalidate an in-flight review. At the actual
provider-write boundary, the console first binds the queued payload to the
same task generation, advances `inputRevision`, extends the objective, and
clears all earlier review passes. A verdict for an older objective is rejected
even when its source or artifact digest matches. Dispatch is also refused if
the cwd, account/model/tools policy, runtime, immutable attachment snapshots,
task generation, or pause epoch changed after acceptance.

Queued follow-ups remain as read-only recovery records until the user explicitly
discards the local payload. Ordinary sends transfer attachment ownership out of
the composer while the provider turn can still have delayed readers, then
release those snapshots automatically after a native final outcome. If finality
or cleanup durability is unknown, the receipt and files remain for explicit
reconciliation. Discard releases retained snapshot files, but it does not
cancel provider work or alter whether delivery occurred. Starting a new
objective is refused while retained payloads still need reconciliation.

On macOS and Linux, cleanup pins the private data and attachment directories,
unlinks by basename relative to the open directory, and syncs that same handle.
If an ancestor or attachment directory changes identity, cleanup fails closed
with its receipt intact. Windows builds reject attachment selection before
copying bytes or starting provider work because this release has no equivalent
descriptor-confined deletion primitive there; text-only chat remains available.

Repository controls expose local tracking and worktree state. Sync preserves
local work if a remote is unavailable. Removal refuses dirty, locked, current,
or unpushed work and requires exact-path confirmation. A new terminal request
means the OS accepted the launch; it does not establish that the CLI signed in
or became ready.

## Settings and account storage

Settings are revisioned. Conflicting edits are refused rather than silently
overwriting a newer configuration. Changes affect new stages; a running request
retains its admitted account and policy.

| Setting | Behavior and boundary |
| --- | --- |
| Provider profiles | Separate global, API-key, and supported managed sign-in profiles. Allowed profiles can be selected for new work. |
| Usage | Displays actual supported provider measurements and reset times. An unavailable balance or quota stays unavailable; sign-in is not quota proof. |
| Rotation | Reserved until actual profile harness readiness and safe dispatch are verified. It cannot silently switch accounts after an accepted or uncertain request. |
| Defaults | Provider, profile, model, effort, service tier, permission mode, approval policy, and harness for new stages. |
| Cascade and review ladders | Ordered routes. Uncertain, authenticated, quota-limited, or already accepted work must not be replayed on another provider. Empty custom review ladders retain the default independent review. |
| Instructions and memory | Supported files use read, preview, digest-checked apply, and private backup. The editor does not execute file contents. |
| Hooks | Shows discovered descriptors and trust state. Toggle, preview, and apply are separate actions; native trust requirements still apply. |
| Agent environment | Profile-scoped variables. Sensitive is the default; credential-like names require vault storage. Reserved runtime/auth variables are refused. |
| GoodQA | Explicit discovery and capability selection through a scoped local MCP helper. Enabling it does not restart the disabled Codex bridge or old Hive work. |

Application-managed API keys and sensitive variables use the OS credential
store: macOS Keychain, Windows Credential Manager, or Linux Secret Service.
There is no plaintext fallback when the vault is unavailable. Values are
write-only in Settings; normal configuration stores opaque references.
Deliberately public environment values can be stored as non-sensitive.

On Linux, saving secrets requires `secret-tool` and an active, unlocked Secret
Service in the user's desktop session. A headless shell with no service will
refuse saves. On Windows, Credential Manager also requires a usable credential
set for the current logon session; a network/SSH logon can lack one even when
the DLL is available. Microsoft documents this limitation for
[CredWrite](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credwritew).
Run the app in the signed-in desktop session to qualify native storage; do not
interpret a successful build or DLL lookup as a successful secret round-trip.

Provider-managed sign-in uses the official CLI's supported flow and storage.
It is not a promise that every provider OAuth token is held in the OS vault.
Managed profile authentication and harness readiness are separate states.
Creating a profile does not prove that hooks, roles, and account isolation have
executed successfully. Complete required native login and trust steps when the
interface reports them; never paste login credentials into chat.

Full access controls local provider permissions. Browser availability, saved
site denials, managed policies, native app controls, and external services retain
their own authority. The console preserves native tools; it cannot grant a
capability that the host or provider disables.

## Data and recovery

The server binds only loopback. A fresh per-launch capability authenticates
API requests, with exact Host and Origin checks. Treat bootstrap URLs printed
by `--no-open` as secrets. Do not publish or forward the console port as a
public service.

Private console data includes settings metadata, selected file snapshots,
instruction backups, a metadata journal, and queued follow-up text. Queue
payloads and their immutable snapshots are stored separately because delayed
and uncertain consumers must retain ownership. Provider CLIs may retain their
normal conversation history. Redaction reduces accidental disclosure; it does
not isolate hostile same-user processes or make unrestricted tools safe.

A browser reload reconnects to the current process. A server restart restores
durable identities but quarantines previous writers. Queued or held inputs
become held; dispatching or uncertain inputs remain unknown. If a crash leaves
both the primary queue file and its beforeimage, recovery validates both,
preserves every non-conflicting payload and snapshot owner, promotes the merged
state durably, and marks it unknown. Missing, conflicting, corrupt, foreign, or
over-limit recovery data fails closed for manual preservation rather than
guessing which candidate won. Unresolved sends stay unknown and are not
replayed. Use an explicit new session with available context when continuing;
old native sessions may still need reconciliation.

Closing a browser tab does not stop the server. Use **Quit console** and confirm
the shutdown, or Ctrl-C in the process's terminal. Stopping a selected turn is
different from shutting down the whole console. If cancellation lacks a native
terminal confirmation, its state remains unknown and its Stop control stays
available.

## Verification

### Build standalone archives

The package helper uses the `go` executable on `PATH` and builds offline from
the module cache. Use a security-patched Go executable, then prefetch the pinned
module in the same user environment before packaging:

```sh
go version
cd console
go mod download
go mod verify
cd ..
python3 tools/package_console.py --output-dir /absolute/new-directory --version 0.2.0
```

The package helper disables Go's automatic toolchain switching; setting only
`GOTOOLCHAIN` does not change the executable it chooses from `PATH`. The output
directory must not exist. A missing dependency fails the offline build;
`go mod download` is the explicit network step. `SHA256SUMS` appears only
after all selected target archives are complete. The six archives are unsigned
compile checks, not proof that the GUI or native vault works on every target.

The preregistered [ordinary, deep, and negative scenarios](../plans/CONSOLE-SCENARIOS.md)
define flow acceptance. Deterministic subprocess and HTTP fixtures exercise
protocol, concurrency, failure, redaction, and recovery controls without paid
model loops. CI also runs focused Node tests for composer routing and uncertain
retry identity, but those tests do not replace real browser interaction. Real
CLI requests, real browser interactions, and native platform checks are
separate evidence. Exact commits, commands, counts, failures, repairs, and
remaining limits belong in each release's PR receipts.

The console requires a desktop browser for visual use. A headless host can
exercise its authenticated HTTP and provider contracts, but that does not prove
desktop browser opening. Builds are unsigned unless a release explicitly says
otherwise; OS signing and notarization must not be inferred from an archive or
checksum.

Provider discovery validates executables on the launcher's PATH and in known
installation locations. The conversation launcher uses a minimal PATH, so a
custom shell-only installation may require launching the console directly from
that shell. There is no executable picker in Settings in this version. Install
the official CLI in a supported location and restart if setup reports it missing.
