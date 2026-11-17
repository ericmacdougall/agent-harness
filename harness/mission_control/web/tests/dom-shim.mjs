// A tiny DOM for node --test: enough for the page's el()/button() builders. It records every element tag created, so a
// test can prove hostile text never became markup.
export const created = [];
class Node_ {
  constructor(tag) { this.tagName = String(tag).toUpperCase(); this.children = []; this.attrs = {}; this.dataset = {}; this.className = ''; this._text = ''; this.listeners = {}; this.hidden = false; this.style = { setProperty() {} }; created.push(this.tagName); }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  append(...n) { n.forEach(x => this.children.push(typeof x === 'string' ? Object.assign(new Node_('#text'), { _text: x }) : x)); }
  replaceChildren(...n) { this.children = []; this.append(...n); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k] ?? null; }
  addEventListener(t, f) { (this.listeners[t] ||= []).push(f); }
  click() { (this.listeners.click || []).forEach(f => f({ detail: 1 })); }
  all() { return this.children.flatMap(c => [c, ...c.all()]); }
  get classList() { const s = this; return { add: c => { s.className += ` ${c}`; }, toggle() {}, contains: c => s.className.split(' ').includes(c) }; }
}
globalThis.document = { createElement: tag => new Node_(tag), createDocumentFragment: () => new Node_('#frag'), getElementById: () => null };
export const text = nodes => [].concat(nodes).map(n => n.textContent).join('\n');
export const walk = nodes => [].concat(nodes).flatMap(n => [n, ...n.all()]);
