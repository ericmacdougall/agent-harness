# Open the interactive agent console from a conversation

The Harness TUI plugin name and `open_tui` tool remain compatible with existing
clients. With the current `harness-console` binary, they open the interactive
local web interface with supplied chat context and an optional working directory.
The context is visible reference data and is not automatically submitted as a
provider prompt. The user can then send messages through the console.

An older configured Go operator continues to open its offline reference view.
Install the console binary to select the interactive route. Opening either mode
does not enable the disabled Codex bridge.

## Install the local components

The Python plugin installer supports macOS and Linux with Python 3.10+. The
standalone Go console is a separate cross-platform executable under `console/`.
Windows users can launch that packaged executable directly; this Python
fd-based adapter and Chromium native-host registration are not qualified there.

Choose the executable you trust; model-visible arguments cannot replace it.
The installer reads `--help` for the direct console contract, then falls back
to `tui --help` for the legacy reader. Both probes share a five-second deadline
and each is bounded to 64 KiB. Console help must declare `--reference-file`,
`--reference-sha256`, `--cwd` and `--ready-file`. Legacy help must declare all
three reference flags. Incompatible binaries are refused before destination
writes. Advertised flags are a preflight, while actual application behavior
still requires integration testing.

Preview all destination paths, then apply the same options:

```sh
python3 install_tui_plugin.py --binary /absolute/path/to/harness-console --browser chrome --claude-desktop
python3 install_tui_plugin.py --binary /absolute/path/to/harness-console --browser chrome --claude-desktop --apply
```

Omit `--claude-desktop` when you do not use that client. Repeat `--browser` for
`edge` or `chromium` if needed. No browser registration is written by default.
The installer copies the plugin under `~/.agent-harness/tui-plugin`, writes its
private executable setting to `~/.agent-harness/tui-launcher.json`, and registers
only the browsers you selected. Config schema 2 with `mode: console` selects
the direct GUI contract. Existing schema-1 binary configs retain the legacy
reader contract. Reinstallation accepts either known schema. It merges one server into Claude Desktop only
when requested. Existing Claude/Codex permission settings, model choices, hooks,
global instructions and the disabled bridge block are not edited.
An existing same-name Claude Desktop server is reused only if it exactly matches
the proposed entry. Custom command, environment or disabled-state differences
are refused for explicit resolution instead of being overwritten.

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

This registers the skill package. A successful plugin registration does not
prove that its MCP server is active. On the tested Codex app-server, register
the installed absolute stdio command as well, using the Python path printed by
the installer:

```sh
codex mcp add harness-tui -- /absolute/path/to/python3 "$HOME/.agent-harness/tui-plugin/plugin/launcher.py" serve
```

`codex mcp list` verifies configuration; actual runtime discovery should show
server `agent-harness-tui` and tool `open_tui`. The qualified route uses the
installer's absolute paths, not untested raw-source variable expansion.

For Claude Code:

```sh
claude plugin marketplace add "$HOME/.agent-harness/tui-plugin" --scope user
claude plugin install harness-tui@agent-harness-local --scope user
claude mcp list
```

The tested Claude Code native plugin route reports
`plugin:harness-tui:harness-tui` as connected. Avoid also adding a duplicate
standalone server when that plugin route is healthy.

Start a new client session after activation. Use the `open-tui` skill or ask
"Open the agent console with this conversation and the current working directory." Client tool approval
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

The extension performs no background scraping, external page-to-native bridge
or remote upload. The configured console opens its authenticated loopback web
interface. Safari and Firefox adapters are not included.
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

Go launches and Terminal dispatch receive an explicit environment containing
only `HOME`, a validated `TERM` (or `xterm-256color` fallback), a fixed system
`PATH` and UTF-8 locale. API keys, proxy settings, SSH agents and shell/Python
startup variables are not inherited by those child processes. An already
running Terminal app can have its own environment; the final Go process still
receives the restricted environment. This does not erase credentials from the
parent client or promise that a reference's text contains no secrets.

## Launch outcomes and foreground use

Console mode launches the executable directly with a private path and digest,
validated cwd, and a private readiness-file path. It creates a one-shot intent
before starting the child and records the PID. The console writes a private
`UI_READY` record after its loopback HTTP interface is live. The launcher checks
that record's PID, loopback origin and server header with redirects and proxies
disabled. `LAUNCH_REQUESTED` with `readiness: UI_READY` establishes this HTTP
readiness. Browser rendering and provider operation still need their own checks.

In legacy mode, `LAUNCH_REQUESTED` only confirms macOS Terminal dispatch. Legacy
automatic Terminal opening is macOS-only, while its foreground route is available
on other supported hosts.

`NOT_LAUNCHED` means configuration/preflight failed before a child was started.
`DISPATCH_FAILED` means dispatch failed or the console exited before readiness.
`UNKNOWN` means startup or readiness is uncertain. Inspect the recorded process
and retained reference before retrying. No automatic second launch is made.

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

Add `--cwd /absolute/project` to `prepare`, `open` or `foreground` when the
working directory is known. The directory is validated during preparation and
again before process creation. MCP and native messages accept optional `cwd`
separately from the inert reference object. Unknown cwd can be omitted.

Replace `prepare` with `open` for the configured GUI route, or `foreground` to
keep the child in the current terminal. Legacy `open` requests a Terminal
window. CLI input requires `captured_at`; only MCP fills an omitted timestamp.
Provider authentication is needed for interactive model work, while reading
supplied context remains local. A foreign reference session ID is not passed
as a writable provider session. The console handles explicit imports through
its own session controls.

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
