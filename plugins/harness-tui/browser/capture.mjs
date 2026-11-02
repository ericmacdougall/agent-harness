// Keep this function self-contained: Chrome serializes it into the isolated world.
export function captureCurrentChat() {
  const maxBody = 131072;
  const maxFrame = 262144;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const page = new URL(location.href);
  if (page.protocol !== "https:" || page.port || page.username || page.password ||
      !["chatgpt.com", "claude.ai"].includes(page.hostname)) {
    throw new Error("UNSUPPORTED_PAGE");
  }
  const chatgpt = page.hostname === "chatgpt.com";
  const classicSelectors = chatgpt
    ? '[data-message-author-role="user"], [data-message-author-role="assistant"]'
    : '[data-testid="user-message"], [data-testid="assistant-message"], .font-claude-response, [data-message-author-role="user"], [data-message-author-role="assistant"]';
  const excluded = 'aside, nav, [role="navigation"], [data-testid*="sidebar" i], form, textarea, input, select, [contenteditable="true"]';
  const ignored = 'script, style, noscript, button, [role="button"], svg, textarea, input, select, form, [contenteditable="true"], h4[data-conversation-role]';
  const blocks = new Set(["DIV", "P", "PRE", "LI", "BR", "H1", "H2", "H3", "H4", "H5", "H6", "SECTION", "ARTICLE", "TR"]);
  let clipped = false;
  let nodesLeft = 20000;

  function wellFormed(value) {
    // DOM text can be programmatically constructed with lone UTF-16 surrogates.
    return String(value).toWellFormed();
  }
  function byteClip(value, limit, keepEnd = false) {
    const bytes = encoder.encode(wellFormed(value));
    if (bytes.length <= limit) return decoder.decode(bytes);
    clipped = true;
    if (keepEnd) {
      let start = bytes.length - limit;
      while (start < bytes.length && (bytes[start] & 0xc0) === 0x80) start++;
      return decoder.decode(bytes.subarray(start));
    }
    let end = limit;
    while (end > 0 && (bytes[end] & 0xc0) === 0x80) end--;
    return decoder.decode(bytes.subarray(0, end));
  }
  function scalarClip(value, limit) {
    const scalars = Array.from(wellFormed(value));
    if (scalars.length > limit) clipped = true;
    return scalars.slice(0, limit).join("");
  }
  function hidden(element) {
    for (let current = element; current; current = current.parentElement) {
      const style = getComputedStyle(current);
      if (current.hidden || current.hasAttribute("inert") || current.getAttribute("aria-hidden") === "true" ||
          style.display === "none" || ["hidden", "collapse"].includes(style.visibility) || style.opacity === "0") return true;
    }
    return false;
  }
  function visibleText(element) {
    const pieces = [];
    const stack = [element];
    let chars = 0;
    while (stack.length) {
      if (--nodesLeft < 0 || chars >= maxBody) { clipped = true; break; }
      const node = stack.pop();
      if (typeof node === "string") { pieces.push(node); chars += node.length; continue; }
      if (node.nodeType === Node.TEXT_NODE) {
        const text = node.nodeValue.slice(0, maxBody - chars);
        if (text.length < node.nodeValue.length) clipped = true;
        pieces.push(text); chars += text.length;
      } else if (node.nodeType === Node.ELEMENT_NODE && !node.matches(ignored) && !hidden(node)) {
        if (blocks.has(node.tagName)) { pieces.push("\n"); stack.push("\n"); }
        for (let child = node.lastChild; child; child = child.previousSibling) stack.push(child);
      }
    }
    return wellFormed(pieces.join("")).trim();
  }
  // Work can have several main panes; only the explicit conversation owns its units.
  const conversations = chatgpt ? Array.from(document.querySelectorAll('[role="region"][aria-label="Conversation"]')).filter(node => !hidden(node)) : [];
  if (conversations.length > 1) throw new Error("AMBIGUOUS_CONVERSATION");
  const workConversation = conversations[0];
  const root = workConversation || document.querySelector("main, [role='main']") || document.body;
  const selectors = workConversation ? classicSelectors +
    ', div[data-chatgpt-search-unit-key$=":user"][data-chatgpt-search-message-ids], div[data-chatgpt-search-unit-key$=":assistant"][data-chatgpt-search-message-ids]' : classicSelectors;
  const selected = root.querySelectorAll(selectors);
  if (selected.length > 500) clipped = true;
  const candidates = Array.from(selected).slice(-500);
  const messages = candidates.filter(node => !node.closest(excluded) && !hidden(node) &&
    !candidates.some(other => other !== node && other.contains(node)));
  const stop = root.querySelector('[data-testid="stop-button"], button[aria-label="Stop generating"], button[aria-label="Stop response"]');
  const streaming = stop && !hidden(stop);
  const parts = [];
  let bodyBytes = 0;
  // Preserve the newest request/response when older rendered history exceeds the cap.
  for (let i = messages.length - 1; i >= 0; i--) {
    if (nodesLeft < 0) { clipped = true; break; }
    const node = messages[i];
    const role = node.matches('[data-message-author-role="user"], [data-testid="user-message"], [data-chatgpt-search-unit-key$=":user"]') ? "User" : "Assistant";
    const workUnit = workConversation && node.hasAttribute("data-chatgpt-search-unit-key") && node.hasAttribute("data-chatgpt-search-message-ids");
    const turnState = workUnit ? node.closest("[data-turn-key]")?.querySelector("[data-talvt-turn-state]")?.getAttribute("data-talvt-turn-state") : null;
    if (node.closest('[data-is-streaming="true"], [aria-busy="true"]') ||
        (workUnit && role === "Assistant" && turnState !== "complete") ||
        (streaming && role === "Assistant" && i === messages.length - 1)) {
      clipped = true;
      continue;
    }
    const text = visibleText(node);
    if (!text) continue;
    const piece = `${role}:\n${text}`;
    const size = encoder.encode(piece).length;
    const remaining = maxBody - bodyBytes - (parts.length ? 2 : 0);
    if (size > remaining) {
      clipped = true;
      if (!parts.length) parts.unshift(byteClip(piece, remaining));
      break;
    }
    parts.unshift(piece);
    bodyBytes += size + (parts.length > 1 ? 2 : 0);
  }
  if (!parts.length) throw new Error("NO_RENDERED_MESSAGES");
  page.search = "";
  page.hash = "";
  if (Array.from(page.href).length > 2048) throw new Error("SOURCE_URL_TOO_LONG");
  const reference = {
    schema: 1,
    client: chatgpt ? "chatgpt-browser" : "claude-browser",
    captured_at: new Date().toISOString(),
    title: scalarClip(document.title.trim() || "Chat reference", 512),
    kind: "excerpt",
    body: byteClip(parts.join("\n\n"), maxBody),
    truncated: clipped,
    source_url: page.href,
  };
  // JSON escaping can exceed the native-frame cap even below the UTF-8 body cap.
  while (encoder.encode(JSON.stringify({action: "open_tui", reference})).length > maxFrame) {
    reference.body = byteClip(reference.body, Math.floor(encoder.encode(reference.body).length * 0.9), true);
    reference.truncated = true;
  }
  if (!reference.body.trim()) throw new Error("NO_RENDERED_MESSAGES");
  return reference;
}
