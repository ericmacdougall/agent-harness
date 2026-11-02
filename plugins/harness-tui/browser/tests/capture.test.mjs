import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";
import {captureCurrentChat} from "../capture.mjs";

// Small DOM doubles exercise rendering policy, not live provider selectors.
// Actual extension/native-host and provider-layout checks belong to live QA.
class Element {
  constructor(tag, attrs = {}, children = []) {
    this.nodeType = 1;
    this.tagName = tag.toUpperCase();
    this.attrs = attrs;
    this.children = children.map(child => typeof child === "string" ? {nodeType: 3, nodeValue: child} : child);
    this.style = {display: "block", visibility: "visible", opacity: "1", ...attrs.style};
    this.children.forEach((child, i) => {
      child.parentElement = this;
      child.previousSibling = this.children[i - 1] || null;
    });
  }
  get hidden() { return Object.hasOwn(this.attrs, "hidden"); }
  get lastChild() { return this.children.at(-1) || null; }
  getAttribute(name) { return this.attrs[name] ?? null; }
  hasAttribute(name) { return Object.hasOwn(this.attrs, name); }
  matches(selectors) {
    return selectors.split(",").some(selector => {
      selector = selector.trim();
      const tag = selector.match(/^[a-z][a-z0-9]*/i)?.[0];
      if (tag && tag.toUpperCase() !== this.tagName) return false;
      const klass = selector.match(/^\.([\w-]+)$/)?.[1];
      if (klass) return (this.attrs.class || "").split(/\s+/).includes(klass);
      for (const [, name, operator, value, insensitive] of selector.matchAll(/\[([\w-]+)([\*$]?=)?(?:"([^"]*)")?(?:\s+(i))?\]/g)) {
        let actual = this.attrs[name];
        if (actual === undefined) return false;
        if (!operator) continue;
        actual = String(actual);
        const expected = insensitive ? value.toLowerCase() : value;
        if (insensitive) actual = actual.toLowerCase();
        if (operator === "=" && actual !== expected) return false;
        if (operator === "*=" && !actual.includes(expected)) return false;
        if (operator === "$=" && !actual.endsWith(expected)) return false;
      }
      return Boolean(tag || selector.startsWith("["));
    });
  }
  closest(selector) {
    for (let current = this; current; current = current.parentElement) if (current.matches(selector)) return current;
    return null;
  }
  contains(node) {
    for (let current = node; current; current = current.parentElement) if (current === this) return true;
    return false;
  }
  querySelectorAll(selector) {
    const result = [];
    const visit = node => {
      if (node.nodeType !== 1) return;
      if (node.matches(selector)) result.push(node);
      node.children.forEach(visit);
    };
    this.children.forEach(visit);
    return result;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}
const el = (tag, attrs, ...children) => new Element(tag, attrs, children);
const user = (...children) => el("div", {"data-message-author-role": "user"}, ...children);
const assistant = (...children) => el("div", {"data-message-author-role": "assistant"}, ...children);

function capture(children, href = "https://chatgpt.com/c/example?private=query#fragment", title = "Synthetic chat") {
  const body = el("body", {}, el("main", {}, ...children));
  return captureBody(body, href, title);
}

function captureBody(body, href = "https://chatgpt.com/c/synthetic", title = "Synthetic Work chat") {
  const document = {
    body, title,
    querySelector: selector => body.querySelectorAll(selector)[0] || null,
    querySelectorAll: selector => body.querySelectorAll(selector),
  };
  const context = vm.createContext({URL, TextEncoder, TextDecoder, Date, document, location: {href},
    Node: {TEXT_NODE: 3, ELEMENT_NODE: 1}, getComputedStyle: node => node.style});
  return vm.runInContext(`(${captureCurrentChat.toString()})()`, context);
}

test("ChatGPT ordered messages exclude hidden children and strip URL secrets", () => {
  const ref = capture([user("Hello 🦆", el("span", {hidden: ""}, "HIDDEN")), assistant(el("pre", {}, ":m do not execute"))]);
  assert.match(ref.body, /^User:\nHello 🦆/);
  assert.match(ref.body, /Assistant:\n:m do not execute$/);
  assert.ok(!ref.body.includes("HIDDEN"));
  assert.equal(ref.source_url, "https://chatgpt.com/c/example");
  assert.equal(ref.client, "chatgpt-browser");
  assert.equal(ref.kind, "excerpt");
  assert.equal(ref.truncated, false);
  assert.equal(ref.schema, 1);
  assert.match(ref.captured_at, /Z$/);
});

const workUnit = (role, ...children) => el("div", {
  "data-chatgpt-search-unit-key": `synthetic-unit:0:${role}`,
  "data-chatgpt-search-message-ids": "synthetic-message",
}, ...children);
const workConversation = (...children) => el("div", {role: "region", "aria-label": "Conversation"}, ...children);
const workTurn = (state, ...children) => el("section", {"data-turn-key": "synthetic-turn"},
  el("span", {"data-talvt-turn-state": state}), ...children);

test("ChatGPT Work region wins over unrelated main and captures explicit role units", () => {
  const body = el("body", {},
    el("main", {}, user("UNRELATED_MAIN_CANARY")),
    el("main", {}, "Other application pane"),
    el("main", {}, workConversation(workTurn("complete",
      el("h4", {"data-conversation-role": "user"}, "USER_ROLE_HEADING"),
      workUnit("user", "WORK_USER_CANARY", el("span", {hidden: ""}, "HIDDEN_CANARY")),
      workUnit("assistant", el("h4", {"data-conversation-role": "assistant"}, "ASSISTANT_ROLE_HEADING"),
        "WORK_ASSISTANT_CANARY", el("form", {}, "DRAFT_CANARY")),
    ))),
  );
  const ref = captureBody(body);
  assert.equal(ref.body, "User:\nWORK_USER_CANARY\n\nAssistant:\nWORK_ASSISTANT_CANARY");
  assert.equal(ref.kind, "excerpt");
  assert.equal(ref.truncated, false);
});

test("Work fallback is limited to the Conversation region and complete assistant turns", () => {
  assert.throws(() => capture([workTurn("complete", workUnit("user", "UNSCOPED_CANARY"))]), /NO_RENDERED_MESSAGES/);
  assert.throws(() => captureBody(el("body", {}, workConversation(
    el("h4", {"data-conversation-role": "user"}, "HEADING_ONLY_CANARY"),
  ))), /NO_RENDERED_MESSAGES/);
  const ref = captureBody(el("body", {}, workConversation(workTurn("running",
    workUnit("user", "COMMITTED_USER_CANARY"), workUnit("assistant", "UNFINISHED_CANARY"),
  ))));
  assert.equal(ref.body, "User:\nCOMMITTED_USER_CANARY");
  assert.equal(ref.truncated, true);
});

test("Claude role selectors and nested assistant containers produce one excerpt", () => {
  const ref = capture([
    el("div", {"data-testid": "user-message"}, "Question"),
    el("div", {"data-testid": "assistant-message"}, el("div", {class: "font-claude-response"}, "Answer")),
  ], "https://claude.ai/chat/example?token=private");
  assert.equal(ref.client, "claude-browser");
  assert.equal(ref.body, "User:\nQuestion\n\nAssistant:\nAnswer");
  assert.equal(ref.source_url, "https://claude.ai/chat/example");
});

test("unsupported origins fail before capture", () => {
  for (const href of ["http://chatgpt.com/c/x", "https://chatgpt.com.evil.invalid/c/x", "https://claude.ai:444/chat/x", "https://example.com/"]) {
    assert.throws(() => capture([user("private")], href), /UNSUPPORTED_PAGE/);
  }
});

test("composer, sidebar, controls and hidden descendants never enter output", () => {
  const ref = capture([
    el("aside", {}, user("sidebar-history")),
    el("form", {}, user("unsent-draft")),
    user("kept", el("span", {"aria-hidden": "true"}, "aria-secret"),
      el("span", {style: {display: "none"}}, "css-secret"),
      el("button", {}, "copy-control"), el("textarea", {}, "nested-draft")),
    assistant("response"),
  ]);
  assert.equal(ref.body, "User:\nkept\n\nAssistant:\nresponse");
});

test("unfinished assistant messages are excluded and marked", () => {
  const ref = capture([user("question"), el("div", {"data-message-author-role": "assistant", "data-is-streaming": "true"}, "unfinished")]);
  assert.equal(ref.body, "User:\nquestion");
  assert.equal(ref.truncated, true);
  const globalStop = capture([user("question"), assistant("unfinished"), el("button", {"data-testid": "stop-button"}, "Stop")]);
  assert.equal(globalStop.body, "User:\nquestion");
  assert.equal(globalStop.truncated, true);
});

test("shell, HTML and terminal control payloads remain inert reference text", () => {
  const payload = '$(touch NEVER) `echo NEVER` <script>NEVER</script>\u001b]52;c;NEVER\u0007';
  const ref = capture([user(payload)]);
  assert.equal(ref.body, `User:\n${payload}`);
});

test("large Unicode bodies clip at UTF-8 boundaries", () => {
  const ref = capture([user("🦆".repeat(50000))]);
  assert.ok(new TextEncoder().encode(ref.body).length <= 131072);
  assert.equal(ref.body.isWellFormed(), true);
  assert.equal(ref.truncated, true);
});

test("bounded captures preserve the newest committed message", () => {
  const ref = capture([user("older history ".repeat(15000)), assistant("LATEST_CANARY")]);
  assert.ok(ref.body.includes("LATEST_CANARY"));
  assert.equal(ref.truncated, true);
});

test("JSON escaping is bounded independently from UTF-8 body size", () => {
  const ref = capture([user("\u0000".repeat(120000))]);
  assert.ok(new TextEncoder().encode(JSON.stringify({action: "open_tui", reference: ref})).length <= 262144);
  assert.equal(ref.truncated, true);
});

test("Unicode title limit uses scalar count and explicit truncation", () => {
  const ref = capture([user("hello")], "https://chatgpt.com/c/x", "🦆".repeat(600));
  assert.equal(Array.from(ref.title).length, 512);
  assert.equal(ref.truncated, true);
});

test("unrecognized layouts and blank messages never fall back to full-page text", () => {
  assert.throws(() => capture([el("div", {}, "unrecognized potentially private page")]), /NO_RENDERED_MESSAGES/);
  assert.throws(() => capture([user(" \n\t ")]), /NO_RENDERED_MESSAGES/);
});

test("oversized source paths fail instead of returning a misleading identity", () => {
  assert.throws(() => capture([user("hello")], `https://chatgpt.com/c/${"x".repeat(2100)}`), /SOURCE_URL_TOO_LONG/);
});

async function popup(nativeResult) {
  const elements = Object.fromEntries(["launch", "status", "preview", "coverage"].map(id => [id, {
    disabled: id === "launch", textContent: "", addEventListener(_, callback) { this.click = callback; },
  }]));
  const ref = capture([user("synthetic context")]);
  const calls = [];
  const chrome = {
    tabs: {query: async () => [{id: 12, url: "https://chatgpt.com/c/example"}]},
    scripting: {executeScript: async () => [{result: ref}]},
    runtime: {sendNativeMessage: async (...args) => { calls.push(args); return nativeResult(); }},
  };
  const source = (await readFile(new URL("../popup.mjs", import.meta.url), "utf8")).replace(/^import .*;\n/, "");
  vm.runInNewContext(source, {chrome, URL, captureCurrentChat, document: {getElementById: id => elements[id]}});
  await new Promise(resolve => setImmediate(resolve));
  return {elements, calls};
}

test("popup sends one strict native request and reports launch acceptance honestly", async () => {
  const {elements, calls} = await popup(() => ({status: "LAUNCH_REQUESTED"}));
  assert.equal(elements.launch.disabled, false);
  await elements.launch.click();
  await elements.launch.click();
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], "com.agentharness.tui");
  assert.deepEqual(Object.keys(calls[0][1]).sort(), ["action", "reference"]);
  assert.equal(calls[0][1].action, "open_tui");
  assert.match(elements.status.textContent, /does not prove the TUI is ready/);
});

test("unknown native completion never retries or claims ready", async () => {
  const {elements, calls} = await popup(() => ({status: "UNKNOWN"}));
  await elements.launch.click();
  assert.match(elements.status.textContent, /outcome unknown/);
  assert.equal(elements.launch.disabled, true);
  assert.equal(calls.length, 1);
});

test("native exception diagnostics never echo untrusted content", async () => {
  const {elements} = await popup(() => { throw new Error("SYNTHETIC_SECRET_MUST_NOT_ECHO"); });
  await elements.launch.click();
  assert.ok(!elements.status.textContent.includes("SYNTHETIC_SECRET"));
  assert.match(elements.status.textContent, /launcher is unavailable/);
});
