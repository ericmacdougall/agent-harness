import {captureCurrentChat} from "./capture.mjs";

const launch = document.getElementById("launch");
const status = document.getElementById("status");
const preview = document.getElementById("preview");
const coverage = document.getElementById("coverage");
let reference;

async function capture() {
  try {
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    if (!tab || !Number.isInteger(tab.id)) throw new Error("NO_ACTIVE_TAB");
    const url = new URL(tab.url);
    if (url.protocol !== "https:" || url.port || !["chatgpt.com", "claude.ai"].includes(url.hostname)) {
      throw new Error("UNSUPPORTED_PAGE");
    }
    const results = await chrome.scripting.executeScript({target: {tabId: tab.id}, func: captureCurrentChat});
    reference = results[0]?.result;
    if (!reference || reference.kind !== "excerpt" || !reference.body) throw new Error("NO_RENDERED_MESSAGES");
    coverage.textContent = "Rendered chat excerpt only; collapsed or unloaded history may be missing." +
      (reference.truncated ? " The capture was clipped or omitted an unfinished response." : "");
    preview.textContent = reference.body.slice(0, 1200) + (reference.body.length > 1200 ? "\n…" : "");
    launch.disabled = false;
  } catch {
    coverage.textContent = "Capture unavailable.";
    status.textContent = "Select a ChatGPT or Claude conversation with visible messages, then reopen this popup. Unknown layouts are not exported.";
  }
}

launch.addEventListener("click", async () => {
  if (!reference || launch.disabled) return;
  launch.disabled = true;
  status.textContent = "Requesting a local Terminal window…";
  try {
    const response = await chrome.runtime.sendNativeMessage("com.agentharness.tui", {action: "open_tui", reference});
    const messages = {
      LAUNCH_REQUESTED: "Terminal launch requested. Check the new window; this does not prove the TUI is ready.",
      NOT_LAUNCHED: "The TUI was not launched. Check the local launcher configuration, then reopen this popup.",
      DISPATCH_FAILED: "Terminal did not accept the request. Check the local installation and permissions.",
      UNKNOWN: "Launch outcome unknown. Check Terminal before trying again.",
    };
    status.textContent = Object.hasOwn(messages, response?.status) ? messages[response.status] :
      "The local launcher returned an unexpected response. Inspect its installation before trying again.";
  } catch {
    status.textContent = "The local launcher is unavailable. Install the harness TUI native host for this browser, then reopen this popup.";
  }
});

capture();
