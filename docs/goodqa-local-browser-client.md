# GoodQA local browser client launcher

This source-only launcher delegates to the reviewed native GoodQA browser client.
It does not install or register an MCP server, grant browser access, or establish
that an installed GoodQA version supports the native command. GoodQA #15638 tracks
the native integration and actual Mini acceptance.

The fixed command is:

```text
/Applications/goodqa.app/Contents/Resources/agent/goodqa-agentd browser-client mcp-stdio
```

The launcher accepts no operands, requires the fixed helper to be a regular
executable file rather than a symlink, and replaces its own process using exec.
It does not run a shell or a waiting proxy. Its own stdout stays empty; after a
successful exec, the native helper owns MCP protocol output and its exit status.
Invalid operands return 64. Missing, nonregular, nonexecutable or failed helper
handoff returns 69 with a fixed error that omits exception details.

Checking the file type is not code-signature or runtime authentication and does
not atomically bind the later exec to the inspected inode. The native admission
contract must qualify the actual packaged helper, app/runtime and target before
authority. Preserving the original parent chain is evidence to qualify, not proof
that the caller is Codex, Claude, a particular chat, or a main agent.

## Native contract and target

The native helper owns MCP initialization, schemas, cancellation, credentials,
signing, replay protection, freshness, startup policy and connector execution.
The wrapper does not select an agent, registration, key, manifest, URL, SSH command
or endpoint. It does not inspect credentials or implement an MCP/crypto framework.

The intended topology is real Codex and Claude clients on the MacBook, each with
an independently admitted native helper connection, controlling the headed-hidden
browser on the Mini. An existing authenticated byte transport to the Mini is a
transport prerequisite. It does not establish the native installation/server pin
or authenticate the writing harness. The native owner must qualify the fixed
target policy, endpoint pin and caller admission end to end. A localhost fixture
on the MacBook is not evidence that the Mini target was tested.

Missing or unqualified native command, startup policy, caller binding, target pin,
durable safety state or account freshness must refuse before registration,
effects or page output. There is no REST, general desktop lease, manual browser,
headless or alternate-host fallback. The wrapper does not independently verify
those native guarantees; they require the native component's own tests and release
gates. Do not launch the real helper until that candidate is admitted for staging.

## Connection ownership and Stop

An independently enrolled MCP connection is the authority unit. A shared helper
connection remains one principal even if several chats use it. Client labels and
MCP implementation names do not create distinct authenticated agents.

Standing app trust persists until revoked. A qualified new helper process gets a
fresh native-issued child session without another grant prompt. It cannot adopt
an old child's handles, output or uncertain operations. Only the same live helper
may reconnect its existing child, under a new connection generation and the same
bound operation envelopes. A helper restart must not automatically replay work.

**Stop this agent session** ends that exact child and its contexts; another child
may continue. A new helper is a new session under app trust, not the same stopped
logical agent resumed. A context-only Stop remains labelled context-only. Use
**Revoke Codex/Claude access** for existing and future sessions of that app, and
**Stop all background browsing** for all current and future children in the
profile. Those broad fences and installation recovery quarantine survive fresh
children and restarts. Native durable replay, retirement and aggregate limits
still apply; a restart cannot bypass uncertainty or capacity.

## Proposed registration diffs

These fragments are proposals, not configuration changes or instructions to
activate an unqualified helper. First review the exact installed interpreter,
wrapper, native package and startup policy. Replace both placeholder paths with
pinned absolute paths in separately reviewed client configuration diffs.

Codex:

```toml
[mcp_servers.goodqa-local-browser]
command = "/absolute/reviewed/python3"
args = ["/absolute/reviewed/goodqa_browser.py"]
```

Claude:

```json
{
  "goodqa-local-browser": {
    "type": "stdio",
    "command": "/absolute/reviewed/python3",
    "args": ["/absolute/reviewed/goodqa_browser.py"]
  }
}
```

Both use the same wrapper contract. Do not add credential values, auth headers,
caller labels or registration selectors. Native admission determines the actual
qualified app. Client configuration scope is convenience, not authentication.
Supported client reload, installation, enrollment and grant actions remain
separately reviewed effects; this change performs none of them.

Canonical packaging is deliberately absent from this first source step. A later
accepted change needs one filename addition to `install.py`'s `HOOKS` tuple and
one to `install_codex.py`'s `DELIVERY_HELPERS` tuple, plus focused manifest checks.
Their existing copy paths already source `harness/hooks`. Do not claim an
installed launcher from this three-file change.

## Checks and release boundary

Run the local, fake-exec-only contract suite from the repository root:

```sh
python3 -B -m unittest discover -s tests -p test_goodqa_browser.py -v
```

It checks the exact vector, operand refusal, file-type/execute-bit failures,
handoff errors, fixed output and absence of environment-selected targets. Every
exec is replaced by a test double. These checks launch no native helper and do
not prove installed capability, parent authentication, key custody or browser
concurrence.

Before activation, independently qualify two real Codex/Claude connections against
the actual Mini, concurrent isolated tabs, sibling-handle denial, reconnect and
fresh-child behavior, Stop/revoke/recovery persistence, and undisturbed foreground
visibility. Preserve the native component's source, security, code, staging,
installation and live acceptance gates. Source publication is not live delivery.
