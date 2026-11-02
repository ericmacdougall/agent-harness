# Open the Go TUI from a conversation

The optional Harness TUI plugin opens an offline reference view in a compatible
local Go operator executable. You can request it from a local MCP-capable client
or click the Chromium extension while viewing a ChatGPT or Claude conversation.
The conversation is reference data: opening it does not create a task, send a
message, connect to an API, or start the disabled Codex bridge.

## Install the local components

Use Python 3.10+ on macOS. The Go executable is installed separately and must
support `tui --reference-only --reference-file FILE --reference-sha256 HEX`.
This public plugin package does not include the private operator application.
Choose the executable you trust; model-visible tool arguments cannot change it.

Preview all destination paths, then apply the same options:

```sh
python3 install_tui_plugin.py --binary /absolute/path/to/operator --browser chrome --claude-desktop
python3 install_tui_plugin.py --binary /absolute/path/to/operator --browser chrome --claude-desktop --apply
```

Omit `--claude-desktop` when you do not use that client. Repeat `--browser` for
`edge` or `chromium` if needed. No browser registration is written by default.
The installer copies the plugin under `~/.agent-harness/tui-plugin`, writes its
private executable setting to `~/.agent-harness/tui-launcher.json`, and registers
only the browsers you selected. It merges one server into Claude Desktop only
when requested. Existing Claude/Codex permission settings, model choices, hooks,
global instructions and the disabled bridge block are not edited.

Before replacing files, the installer saves private backups and a manifest under
`~/.agent-harness/tui-plugin-backups`. A failed write attempts to restore the
original files; an incomplete rollback names the retained backup. Backups are
recovery evidence, not an automatic crash rollback. Inspect failures before
reapplying. Source or destination symlinks are refused.

## Activate clients

For Codex CLI or its shared local plugin directory:

```sh
codex plugin marketplace add "$HOME/.agent-harness/tui-plugin"
codex plugin add harness-tui@agent-harness-local
```

For Claude Code:

```sh
claude plugin marketplace add "$HOME/.agent-harness/tui-plugin" --scope user
claude plugin install harness-tui@agent-harness-local --scope user
```

Start a new client session after activation. Use the `open-tui` skill or ask
"Open the Go TUI with this conversation as a reference." Client tool approval
settings still apply. Installing this plugin does not approve tools or trust
hooks on your behalf; this package defines no lifecycle hooks.

ChatGPT/Codex desktop can use their supported local plugin/MCP configuration.
Where the desktop app does not discover CLI-installed plugins, add the local
marketplace through its plugin directory, or register this stdio server using
the absolute paths printed by the installer:

```text
command: /absolute/path/to/python3
args: ["/absolute/home/.agent-harness/tui-plugin/plugin/launcher.py", "serve"]
```

`--claude-desktop` adds that local stdio configuration to the supported macOS
Claude Desktop config. Restart Claude Desktop if it has not discovered the new
server. This is separate from a remote web connector, which runs through the
provider's cloud and cannot reach this local stdio process by itself.

## Browser conversations

In Chromium's extensions page, enable developer mode and load this unpacked
directory:

```text
~/.agent-harness/tui-plugin/plugin/browser
```

Pin **Harness TUI** if desired. Open a ChatGPT or Claude conversation and click
the extension, then its capture/open action. The shortcut can be configured in
the browser's extension shortcut settings. The extension uses `activeTab`,
`scripting` and `nativeMessaging`; it does not ask for all-sites access. Its
fixed public key binds the registered native host to extension ID
`gdpiohlkkniinkfhlbhcjoimlcnhnkgj`.

Capture includes only committed, rendered message containers in the active
supported tab, excluding the composer and sidebar. It strips URL queries and
fragments. It labels every browser snapshot as an **excerpt**, because older or
virtualized messages may not exist in the DOM. For long conversations it favors
the most recent messages and marks deliberate clipping. Missing known message
containers fail clearly rather than falling back to the entire page.

There is no background scraping, page-to-native external messaging bridge,
network listener or remote upload. Safari and Firefox adapters are not included.
Direct cloud-to-local tool execution through an authenticated remote route is a
separate deployment choice; this installer does not configure a tunnel/service.

## Context and privacy

The MCP tool accepts a supplied `reference` object. A model-authored handoff
uses `kind: summary`; selected messages use `kind: excerpt`. A tool cannot claim
access to hidden/full history. Use `kind: transcript` only when a current-session
transcript was actually supplied. Client and session metadata are self-reported,
not authenticated provenance. Unknown session IDs should be omitted. MCP callers
may omit `captured_at`; the tool then stamps local UTC receipt time. Persisted
references always have the strict timestamp required by the shared schema.

The complete JSON/native frame limit is 256 KiB, and body text is limited to
128 KiB UTF-8. The shared schema/vectors are under
`plugins/harness-tui/schema/reference-v1-vectors.json`. Schema version is integer
1; unknown/duplicate fields, invalid UTF-8, unpaired surrogate escapes and
oversized data are rejected. The Go reader verifies the SHA-256 of exact file
bytes before showing the text and sanitizes terminal controls.

References are stored in
`~/.agent-harness/tui-references/<random-id>/reference.json` with private
directories (`0700`) and files (`0600`). Obvious credential patterns are filtered
defensively; this does not guarantee removal of all secrets or personal data.
The reference body is not included in process arguments, shell commands, MCP
responses, diagnostic messages or metadata WAL notes. It is deliberately visible
inside the TUI. Nothing captures other chats or scans conversation archives.

Artifacts remain until you explicitly remove the chosen reference directory.
Close its TUI first, inspect the exact directory, and delete only that directory
when no longer needed. There is no automatic retention daemon. Local processes
running as your account can read your files and settings; origin/mode checks are
not isolation from the same user.

## Launch outcomes and terminal use

`LAUNCH_REQUESTED` means macOS Terminal accepted a request. It does not prove the
Go UI initialized. Inspect the new window to confirm display. `NOT_LAUNCHED`
means configuration/platform preflight failed; `DISPATCH_FAILED` records a
nonzero Terminal dispatch. `UNKNOWN` records a timeout or uncertain result:
inspect the window/process before trying again. The reference path and digest
remain available. There is no automatic retry.

Each reference directory can contain `run-intent.json`, `process-started.json`
and `process-exited.json`. A process-start record establishes process creation,
not readiness. Missing exit evidence remains unknown. Re-running the same
generated command is refused after its run-intent reservation. MCP duplicate
request IDs are cached only within the last 64 responses of one server process;
this is not cross-process exactly-once delivery.

To prepare a reference without opening anything, feed strict schema-1 JSON to:

```sh
python3 "$HOME/.agent-harness/tui-plugin/plugin/launcher.py" prepare < reference.json
```

Replace `prepare` with `foreground` to view it in the current terminal, or `open`
to request a macOS Terminal window. CLI input requires `captured_at`; only MCP
fills an omitted timestamp. `foreground` also works where automatic Terminal
opening is unsupported, assuming a compatible local Go executable is available.
Detach using the Go reference view's displayed controls. No account/API token is
needed for this offline view.

## Development and checks

Run the focused local contracts from the repository:

```sh
python3 -m unittest discover -s tests -p 'test_tui_plugin.py' -v
python3 -m unittest discover -s tests -p 'test_tui_browser.py' -v
```

Browser extraction tests require Node.js and distinguish their authored DOM
fixtures from actual provider-page testing. Core tests exercise real stdio and
foreground subprocesses, plus private files, framing, bounds, duplicate IDs,
secret filtering, command quoting, config preservation and rollback. A fake
binary passing an argv test does not prove that the real Go UI was displayed.

Packaging follows the official [OpenAI plugin guide](https://developers.openai.com/plugins/build/plugins)
and [Claude Code plugin manifest reference](https://code.claude.com/docs/en/plugins-reference).
The [Claude local versus web connector guide](https://support.claude.com/en/articles/11725091-when-to-use-desktop-and-web-connectors)
explains the separate client routes. Publication to a public plugin directory is
a separate review process; a Git package or local installation is not directory
approval.
