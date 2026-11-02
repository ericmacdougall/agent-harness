# Browser handoff to the local Go TUI

This opt-in Chromium extension supports the ChatGPT and Claude websites on a Mac
with the local harness launcher installed. It captures a rendered chat excerpt
after you open its toolbar popup, previews it as text, and launches only after you
click **Open reference in TUI**. It does not provide a cloud AI with silent access
to your computer.

Install the local launcher and browser native host using the repository's
[TUI plugin instructions](../../../docs/tui-plugin.md). In Chrome's extension
manager, enable Developer mode, choose **Load unpacked**, and select this `browser`
directory. The extension ID must be `gdpiohlkkniinkfhlbhcjoimlcnhnkgj`; the native
host allowlists precisely that ID. The manifest's key is public identity material,
not a private signing credential.

Open the current conversation at `https://chatgpt.com` or `https://claude.ai`, open
the extension, review the preview, and click its launch button. The popup reports
**Terminal launch requested** when the OS accepts dispatch. Inspect the new window
to verify that the TUI opened. An unknown outcome requires checking Terminal before
trying again; the extension never automatically retries.

The reference includes only recognized, rendered user/assistant messages. It omits
the unsent composer, hidden elements, sidebar content, controls, and recognized
unfinished responses. Collapsed, virtualized, or unloaded history may be absent
even when no size limit was reached. Long captures favor the newest messages and
mark deliberate clipping. Website layouts can change; an unrecognized layout
fails instead of exporting the page. Query strings and fragments are removed from
the source URL. A reference is unverified source material, never a command or a
new backend task.

Permissions are limited to `activeTab`, `scripting`, and `nativeMessaging`. There
are no permanent site grants, page-triggered listeners, background scans, remote
uploads, or listening network ports. Private reference retention and deletion are
managed by the local launcher. Browser text can still contain personal or secret
information; local capture does not guarantee its removal.

Initial support is Chromium/Chrome on macOS. Firefox, Safari and mobile browser
installation are not supplied. JavaScript checks use DOM doubles and transport
doubles; they do not establish live provider-layout or installed-browser proof.
Run them with:

```sh
node --test --test-reporter=tap plugins/harness-tui/browser/tests/capture.test.mjs
```
