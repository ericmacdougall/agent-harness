import sys, pathlib
root = pathlib.Path(sys.argv[1])
p = root / "apps/desktop/src/agent-browser/host.ts"
s = p.read_text()

def sub(old, new, count=1):
    global s
    n = s.count(old)
    if n != count:
        raise SystemExit(f"expected {count} got {n}: {old[:80]!r}")
    s = s.replace(old, new)

# 1. Tab fields
sub("""  media: boolean;
  mediaGrants: Map<string, Set<string>>;
  downloads: object[];""", """  media: boolean;
  mediaGrants: Map<string, Set<string>>;
  /** goodqa#15477 F1: the revocation now replacing this document (latest wins), and whether the last one failed. */
  revoking?: symbol;
  revocationFailed?: boolean;
  downloads: object[];""")

# 2. constants before the class
sub("""export class AgentBrowserHost {
""", """/** goodqa#15477 F1: bound on each step of a revocation load (own URL, then about:blank). */
export const REVOKE_STEP_MS = 1500;
/** A Chromium net error code (ERR_ABORTED ...) or a fixed fallback: never page-controlled text in a log line. */
const revokeCode = (error: unknown): string => {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' && /^ERR_[A-Z_]{1,48}$/.test(code) ? code.toLowerCase() : 'load_error';
};
export class AgentBrowserHost {
""")

# 3. freshDocument -> bounded, veto-proof, committed-only replacement
sub("""  private freshDocument(t: Tab): void {
    const contents = t.view.webContents;
    if (contents.isDestroyed()) return;
    void contents.loadURL(contents.getURL()).catch(() => {});
  }
  private dropAgentTab(t: Tab, reason: string): void {
    if (t.debug || t.surface === 'desktop_hidden') { this.close(t.id, reason); return; }
    // A visible tab stays with the person: same hand-over stop() gives it.
    t.stopped = true;
    t.controller = 'user';
    this.dropViewport(t);
    this.freshDocument(t);
  }""", """  /**
   * goodqa#15477 F1 (probe P3, Electron 43 under xvfb): loadURL of the current URL is not enough on its own. A
   * beforeunload handler vetoes it, and a 204, an attachment (download refused) or a GET that never answers leaves the
   * old document, with its live camera and staged inputs, in place. So during this load a beforeunload page cannot veto
   * the unload; each step is bounded; without a committed new document the tab is stopped and sent to about:blank (the
   * request filter always allows it). The media indicator flips only on a commit (the did-navigate handler in open()).
   * Every failure is logged with a fixed code and the tab id. If even about:blank does not commit, a hidden tab closes
   * and a visible one stays with the person showing capture and `revocation: 'failed'`.
   */
  private freshDocument(t: Tab, reason: string): void {
    void this.replaceDocument(t, reason).catch(() => {
      console.error(`[agent-browser] revoke_failed id=${t.id} reason=${reason} step=internal code=exception`);
    });
  }
  /** Test seam: resolves to how the revocation ended. */
  private async replaceDocument(t: Tab, reason: string): Promise<'replaced' | 'blank' | 'failed' | 'gone' | 'superseded'> {
    const contents = t.view.webContents;
    if (contents.isDestroyed()) return 'gone';
    const token = Symbol('revocation');
    t.revoking = token;
    t.revocationFailed = false;
    let committed = false;
    let wake: () => void = () => {};
    const onCommit = () => { committed = true; wake(); };
    const allowUnload = (event: { preventDefault(): void }) => event.preventDefault();
    contents.on('did-navigate', onCommit);
    contents.on('will-prevent-unload', allowUnload);
    const step = (url: string) => new Promise<string>((done) => {
      const timer = setTimeout(() => done('timeout'), REVOKE_STEP_MS);
      wake = () => { clearTimeout(timer); done('committed'); };
      Promise.resolve()
        .then(() => contents.loadURL(url))
        .then(() => done('no_commit'), (error: unknown) => done(revokeCode(error)))
        .finally(() => clearTimeout(timer));
    });
    const outcome = (): 'gone' | 'superseded' | null =>
      contents.isDestroyed() || !this.tabs.has(t.id) ? 'gone' : t.revoking !== token ? 'superseded' : null;
    const log = (at: string, code: string) =>
      console.error(`[agent-browser] revoke_failed id=${t.id} reason=${reason} step=${at} code=${code}`);
    try {
      const first = await step(contents.getURL());
      if (committed) return 'replaced';
      const early = outcome();
      if (early) return early;
      log('load', first === 'committed' ? 'no_commit' : first);
      contents.stop();
      const second = await step('about:blank');
      if (committed) return 'blank';
      const late = outcome();
      if (late) return late;
      log('blank', second === 'committed' ? 'no_commit' : second);
      contents.stop();
      if (t.debug || t.surface === 'desktop_hidden') this.close(t.id, 'revoke_failed');
      else t.revocationFailed = true;
      return 'failed';
    } finally {
      contents.removeListener('did-navigate', onCommit);
      contents.removeListener('will-prevent-unload', allowUnload);
      if (t.revoking === token) {
        t.revoking = undefined;
        if (this.tabs.has(t.id)) this.emit();
      }
    }
  }
  private dropAgentTab(t: Tab, reason: string): void {
    if (t.debug || t.surface === 'desktop_hidden') { this.close(t.id, reason); return; }
    // A visible tab stays with the person: same hand-over stop() gives it.
    t.stopped = true;
    t.controller = 'user';
    this.dropViewport(t);
    this.freshDocument(t, reason);
  }""")

# 4. renew: indicator stays until commit (grants end now)
sub("""      const hadMedia = t.media || t.mediaGrants.size > 0;
      t.media = false;
      t.mediaGrants.clear();
      if (hadMedia) this.dropAgentTab(t, 'media_ended');""", """      // The grants end now; the indicator (t.media) ends only when the replacement document commits.
      const hadMedia = t.media || t.mediaGrants.size > 0;
      t.mediaGrants.clear();
      if (hadMedia) this.dropAgentTab(t, 'media_ended');""")
sub("""        if (freshen) this.freshDocument(t);""", """        if (freshen) this.freshDocument(t, 'scope_narrowed');""")

# 5. park
sub("""        const hadMedia = t.media || t.mediaGrants.size > 0;
        t.media = false;
        t.mediaGrants.clear();
        if (hadMedia && !t.stopped) this.dropAgentTab(t, 'media_ended');""", """        const hadMedia = t.media || t.mediaGrants.size > 0;
        t.mediaGrants.clear();
        if (hadMedia && !t.stopped) this.dropAgentTab(t, 'media_ended');""")

# 6. stop
sub("""        this.dropViewport(t);
        t.media = false;
        t.mediaGrants.clear();
        const contents = t.view.webContents;
        if (contents && !contents.isDestroyed()) contents.stop();
        if (t.debug || t.surface === 'desktop_hidden') this.close(t.id, reason);
        else {
          this.freshDocument(t);
        }""", """        this.dropViewport(t);
        t.mediaGrants.clear();
        const contents = t.view.webContents;
        if (contents && !contents.isDestroyed()) contents.stop();
        if (t.debug || t.surface === 'desktop_hidden') this.close(t.id, reason);
        else {
          this.freshDocument(t, reason);
        }""")

# 7. stopTab
sub("""    this.dropViewport(t);
    t.media = false;
    t.mediaGrants.clear();
    t.view.webContents.stop();
    if (t.debug || t.surface === 'desktop_hidden') this.close(id, "stopped_by_person");
    else this.freshDocument(t);""", """    this.dropViewport(t);
    t.mediaGrants.clear();
    t.view.webContents.stop();
    if (t.debug || t.surface === 'desktop_hidden') this.close(id, "stopped_by_person");
    else this.freshDocument(t, 'stopped_by_person');""")

# 8. state
sub("""          media: t.media,
          offscreen: t.offscreen,""", """          media: t.media,
          revocation: t.revocationFailed ? 'failed' : t.revoking ? 'pending' : null,
          offscreen: t.offscreen,""")

# 9. a committed document clears a failed revocation too
sub("""    view.webContents.on('did-navigate', () => {
      t.mediaGrants.clear();
      t.media = false;
      this.emit();
    });""", """    view.webContents.on('did-navigate', () => {
      // A committed cross-document navigation discarded the old document and what it captured or staged.
      t.mediaGrants.clear();
      t.media = false;
      t.revocationFailed = false;
      this.emit();
    });""")

assert "freshDocument(t)" not in s, "unconverted freshDocument call"
p.write_text(s)

r = root / "apps/desktop/src/agent-browser/renderer.ts"
s = r.read_text()
sub("""    media: boolean;
    stopped: boolean;""", """    media: boolean;
    revocation?: 'pending' | 'failed' | null;
    stopped: boolean;""")
sub("""      : `You are in control${active?.media ? ' · microphone/camera active' : ''} `;""", """      : `You are in control${active?.media ? ' · microphone/camera active' : ''}${active?.revocation === 'failed' ? ' · the agent page could not be closed: close this tab to end capture' : ''} `;""")
r.write_text(s)
print("patched")
