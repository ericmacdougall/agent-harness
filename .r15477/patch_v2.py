import sys, pathlib
root = pathlib.Path(sys.argv[1]) / "apps/desktop"
s = ""

def load(rel):
    global s
    s = (root / rel).read_text()

def save(rel):
    (root / rel).write_text(s)

def sub(old, new, count=1):
    global s
    n = s.count(old)
    if n != count:
        raise SystemExit(f"expected {count} got {n}: {old[:90]!r}")
    s = s.replace(old, new)

# ---------------------------------------------------------------- host.ts
load("src/agent-browser/host.ts")
sub("""  private freshDocument(t: Tab, reason: string): void {
    void this.replaceDocument(t, reason).catch(() => {
      console.error(`[agent-browser] revoke_failed id=${t.id} reason=${reason} step=internal code=exception`);
    });
  }""", """  private freshDocument(t: Tab, reason: string): void {
    void this.replaceDocument(t, reason).catch(() => {
      console.error(`[agent-browser] revoke_failed id=${t.id} reason=${reason} step=internal code=exception`);
      if (this.tabs.get(t.id) === t) this.failClosed(t);
    });
  }
  /**
   * goodqa#15477 final delta F1/F2: a document that could not be replaced may still hold live capture or a staged file,
   * and on the narrowing path the agent still controls it. Fail closed on every surface: crash its renderer (ends the
   * page and its capture at once, even one busy-looping in beforeunload) and close the tab. The person loses that tab.
   */
  private failClosed(t: Tab): void {
    t.revocationFailed = true;
    const contents = t.view.webContents;
    if (!contents.isDestroyed()) {
      try { contents.forcefullyCrashRenderer(); }
      catch { console.error(`[agent-browser] revoke_failed id=${t.id} reason=fail_closed step=crash code=exception`); }
    }
    this.close(t.id, 'revoke_failed');
  }""")
sub("""      log('blank', second === 'committed' ? 'no_commit' : second);
      contents.stop();
      if (t.debug || t.surface === 'desktop_hidden') this.close(t.id, 'revoke_failed');
      else t.revocationFailed = true;
      return 'failed';""", """      log('blank', second === 'committed' ? 'no_commit' : second);
      contents.stop();
      this.failClosed(t);
      return 'failed';""")
sub("""   * Every failure is logged with a fixed code and the tab id. If even about:blank does not commit, a hidden tab closes
   * and a visible one stays with the person showing capture and `revocation: 'failed'`.
   */""", """   * Every failure is logged with a fixed code and the tab id. If even about:blank does not commit, failClosed() crashes
   * the renderer and closes the tab, whatever its surface. Agent commands are refused while a revocation is pending.
   */""")
sub("""  stopTab(id: number): void {
    const t = this.requireTab(id);""", """  /**
   * goodqa#15477 F3 (disclosed, unchanged): on a visible tab this also replaces the document when the person already
   * controls it, so typed but unsent data is lost and the page's beforeunload protection is bypassed. Stop means end
   * everything the agent may have touched in that document.
   */
  stopTab(id: number): void {
    const t = this.requireTab(id);""")
sub("""            if (this.consent !== c || t.controlVersion !== controlVersion || t.documentVersion !== documentVersion || t.controller !== 'agent' || t.stopped || !this.tabs.has(t.id))
              throw new Error('user_in_control');""", """            if (this.consent !== c || t.controlVersion !== controlVersion || t.documentVersion !== documentVersion || t.controller !== 'agent' || t.stopped || !this.tabs.has(t.id))
              throw new Error('user_in_control');
            // goodqa#15477: the old document may still hold what the consent no longer allows until it is replaced.
            if (t.revoking || t.revocationFailed) throw new Error('revocation_pending');""")
save("src/agent-browser/host.ts")

# ---------------------------------------------------------------- renderer.ts
load("src/agent-browser/renderer.ts")
sub("""  element('controlMessage').textContent =
    active?.handoff ? `${active.handoff.instructions} ` : active?.controller === 'agent'
      ? `Agent ${active.agent} is controlling this tab${active.media ? ' · microphone/camera active' : ''} `
      : `You are in control${active?.media ? ' · microphone/camera active' : ''}${active?.revocation === 'failed' ? ' · the agent page could not be closed: close this tab to end capture' : ''} `;""",
"""  // goodqa#15477: shown whoever controls the tab.
  const revocationNote = active?.revocation === 'failed' ? ' · the agent page could not be replaced: this tab is being closed' : '';
  element('controlMessage').textContent =
    active?.handoff ? `${active.handoff.instructions}${revocationNote} ` : active?.controller === 'agent'
      ? `Agent ${active.agent} is controlling this tab${active.media ? ' · microphone/camera active' : ''}${revocationNote} `
      : `You are in control${active?.media ? ' · microphone/camera active' : ''}${revocationNote} `;""")
save("src/agent-browser/renderer.ts")

# ---------------------------------------------------------------- host.test.ts
load("src/agent-browser/host.test.ts")
sub("""    focus = vi.fn();
    stop = vi.fn();
    reload = vi.fn();""", """    focus = vi.fn();
    stop = vi.fn();
    forcefullyCrashRenderer = vi.fn();
    reload = vi.fn();""")
sub("""  it('a visible tab whose about:blank fails too stays with the person showing capture and revocation failed', async () => {
    const { id, wc } = await capturing();
    script(wc, 'reject', 'reject');
    h.stopTab(id);
    await vi.waitFor(() => expect(view(id)?.revocation).toBe('failed'));
    expect(view(id)).toMatchObject({ media: true, controller: 'user' });
    expect(tab(id)).toBeDefined();
    const lines = revokeLines();
    expect(lines).toEqual([
      `[agent-browser] revoke_failed id=${id} reason=stopped_by_person step=load code=err_aborted`,
      `[agent-browser] revoke_failed id=${id} reason=stopped_by_person step=blank code=err_aborted`,
    ]);
    // A fixed code and the tab id only: no URL or page text in the log line.
    expect(lines.join('\\n')).not.toContain('example.com');
    // A later committed document (the person navigates, or Stop again) ends the failed state and the indicator.
    wc.emit('did-navigate', {}, 'https://example.com/next', 200);
    expect(view(id)).toMatchObject({ media: false, revocation: null });
  });""", """  it('a visible tab whose about:blank fails too fails closed: renderer crashed, tab closed, both steps logged', async () => {
    const { id, wc } = await capturing();
    script(wc, 'reject', 'reject');
    h.stopTab(id);
    await vi.waitFor(() => expect(tab(id)).toBeUndefined());
    expect(wc.forcefullyCrashRenderer).toHaveBeenCalledOnce();
    expect(wc.isDestroyed()).toBe(true);
    const lines = revokeLines();
    expect(lines).toEqual([
      `[agent-browser] revoke_failed id=${id} reason=stopped_by_person step=load code=err_aborted`,
      `[agent-browser] revoke_failed id=${id} reason=stopped_by_person step=blank code=err_aborted`,
    ]);
    // A fixed code and the tab id only: no URL or page text in the log line.
    expect(lines.join('\\n')).not.toContain('example.com');
    expect(log.mock.calls.some((c: unknown[]) => String(c[0]).includes(`tab_closed id=${id} reason=revoke_failed`))).toBe(true);
  });

  it('a committed document after a failed flag clears it (did-navigate)', async () => {
    const { id, t, wc } = await capturing();
    t.revocationFailed = true;
    expect(view(id)?.revocation).toBe('failed');
    wc.emit('did-navigate', {}, 'https://example.com/next', 200);
    expect(view(id)).toMatchObject({ media: false, revocation: null });
  });

  it('a visible tab kept by a narrowed renew fails closed when its replacement cannot commit (final delta F1)', async () => {
    h.grant({ ...c(), permissions: { ...c().permissions, uploads: true } });
    const id = await open();
    const wc = tab(id).view.webContents;
    script(wc, 'reject', 'reject');
    h.grant({ ...c(), generation: 3 });
    await vi.waitFor(() => expect(tab(id)).toBeUndefined());
    expect(wc.forcefullyCrashRenderer).toHaveBeenCalledOnce();
  });

  it('agent commands are refused while a revocation is pending on the tab (narrowing keeps agent control)', async () => {
    h.grant({ ...c(), permissions: { ...c().permissions, uploads: true } });
    const id = await open();
    const wc = tab(id).view.webContents;
    script(wc, 'hang', 'hang');
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    h.grant({ ...c(), generation: 3 });
    expect(view(id)).toMatchObject({ controller: 'agent', revocation: 'pending' });
    const click = cmd('browser_click', { tabId: id, x: 1, y: 1, surface: 'desktop_visible' });
    (click.args.scope as Record<string, unknown>).consentGeneration = 3;
    const out = await h.execute(click);
    expect(out.status).toBe('refused');
    expect(out.error?.message).toBe('revocation_pending');
    expect(wc.sendInputEvent).not.toHaveBeenCalled();
    expect(vi.mocked(wc.debugger.sendCommand).mock.calls.map(([m]: [string]) => m)).not.toContain('Input.dispatchMouseEvent');
    await vi.advanceTimersByTimeAsync(3100);
    expect(tab(id)).toBeUndefined();
  });

  it('on the revocation path itself, stop() runs between the failed load and the about:blank load', async () => {
    const { t, wc } = await capturing();
    script(wc, 'reject', 'commit');
    wc.stop.mockClear();
    await expect((h as any).replaceDocument(t, 'scope_narrowed')).resolves.toBe('blank');
    const [first, blank] = wc.loadURL.mock.invocationCallOrder;
    expect(wc.loadURL.mock.calls[1][0]).toBe('about:blank');
    expect(wc.stop.mock.invocationCallOrder.some((o: number) => o > first && o < blank)).toBe(true);
  });

  it('an internal error in the revocation fails closed too, logged', async () => {
    const { id, t, wc } = await capturing();
    wc.getURL = () => { throw new Error('boom'); };
    (h as any).freshDocument(t, 'media_ended');
    await vi.waitFor(() => expect(tab(id)).toBeUndefined());
    expect(revokeLines()).toContain(`[agent-browser] revoke_failed id=${id} reason=media_ended step=internal code=exception`);
    expect(wc.forcefullyCrashRenderer).toHaveBeenCalledOnce();
  });""")
sub("""    await vi.waitFor(() => expect(tab(id)).toBeUndefined());
    expect(log.mock.calls.some((c: unknown[]) => String(c[0]).includes(`tab_closed id=${id} reason=revoke_failed`))).toBe(true);
  });

  it('a renew that drops""", """    await vi.waitFor(() => expect(tab(id)).toBeUndefined());
    expect(wc.forcefullyCrashRenderer).toHaveBeenCalledOnce();
    expect(log.mock.calls.some((c: unknown[]) => String(c[0]).includes(`tab_closed id=${id} reason=revoke_failed`))).toBe(true);
  });

  it('a renew that drops""")
sub("""    await vi.advanceTimersByTimeAsync(1600);
    expect(view(id)).toMatchObject({ media: true, revocation: 'failed' });
    expect(revokeLines()).toHaveLength(2);""", """    await vi.advanceTimersByTimeAsync(1600);
    expect(tab(id)).toBeUndefined();
    expect(wc.forcefullyCrashRenderer).toHaveBeenCalledOnce();
    expect(revokeLines()).toHaveLength(2);""")
save("src/agent-browser/host.test.ts")

# ---------------------------------------------------------------- revocation-capture.cjs
load("test/revocation-capture.cjs")
sub("""    const bu = mode === 'beforeunload' ? '<script>addEventListener("beforeunload", (e) => { e.preventDefault(); e.returnValue = "x"; });</script>' : '';""",
"""    const bu = mode === 'beforeunload' ? '<script>addEventListener("beforeunload", (e) => { e.preventDefault(); e.returnValue = "x"; });</script>'
      // A beforeunload that busy-loops 6 s: the renderer cannot unload within either bounded step.
      : mode === 'busy' ? '<script>addEventListener("beforeunload", () => { const t = Date.now(); while (Date.now() - t < 6000) {} });</script>' : '';""")
sub("""  for (let i = 0; i < 14; i++) { await sleep(400);""", """  const observe = mode === 'busy' ? 25 : 14; // long enough to see a busy page resume after its 6 s loop
  for (let i = 0; i < observe; i++) { await sleep(400);""")
sub("""  if (!wc.debugger.isAttached()) wc.debugger.attach('1.3');
  // Bounded""", """  const gone = wc.isDestroyed();
  if (!gone && !wc.debugger.isAttached()) wc.debugger.attach('1.3');
  // Bounded""")
sub("""  const ev = await Promise.race([timeout, wc.debugger.sendCommand(""", """  const ev = gone ? { result: { value: JSON.stringify({ gone: true }) } } : await Promise.race([timeout, wc.debugger.sendCommand(""")
sub("""urlAfter: wc.getURL(), final""", """urlAfter: gone ? null : wc.getURL(), gone, final""")
save("test/revocation-capture.cjs")

# ---------------------------------------------------------------- revocation-capture.test.ts
load("src/agent-browser/revocation-capture.test.ts")
sub("""  after: { doc: string | null; hasStream: string; state: string | null; input: string | null; files: number | null; cdpError?: string };""",
"""  after: { doc: string | null; hasStream: string; state: string | null; input: string | null; files: number | null; cdpError?: string; gone?: boolean };
  gone: boolean;""")
sub("""function run(mode: string, path = 'stopTab'): Promise<Result> {
  const name = mode + '-' + path;
  const child = spawn(requireFromDesktop('electron'), ['--no-sandbox', '--disable-gpu', resolve('test/revocation-capture.cjs')], {""",
"""function run(mode: string, path = 'stopTab', fixture = 'test/revocation-capture.cjs'): Promise<Result> {
  const name = mode + '-' + path;
  const child = spawn(requireFromDesktop('electron'), ['--no-sandbox', '--disable-gpu', resolve(fixture)], {""")
s = s.rstrip() + """

// goodqa#15477 final delta: a page whose beforeunload busy-loops cannot be replaced within the bounds. Fail closed.
describe.skipIf(skip)('real Electron: a busy beforeunload page fails closed', () => {
  it.each(['stopTab', 'renew'])('media drop (%s): the renderer is crashed, the tab is gone and the camera stops', async (path) => {
    const r = await run('busy', path);
    const why = JSON.stringify(r);
    expect(r.before, why).toMatchObject({ track: 'live', files: 1 });
    expect(r.heartbeatBefore, why).toBe(true);
    expect(r.gone, why).toBe(true);
    expect(r.final, why).toBeNull();
    // The busy page would resume its heartbeat after 6 s if it were still alive.
    expect(r.liveAfterMs ?? -1, why).toBeLessThan(3600);
    expect(r.logs.some((l) => / step=blank code=[a-z_]+$/.test(l)), why).toBe(true);
  }, 90000);

  it('narrowing (uploads off) on a visible agent tab: no agent click lands and no staged file is posted', async () => {
    const r = await run('busy', 'narrow', 'test/revocation-narrow.cjs') as unknown as {
      staged: number; early: { status: string; error?: { message: string } }; late: { status: string; error?: { message: string } };
      posts: Array<{ ms: number; bytes: number }>; final: unknown; logs: string[];
    };
    const why = JSON.stringify(r);
    expect(r.staged, why).toBe(1);
    expect(r.posts, why).toEqual([]);
    expect(r.early.status, why).not.toBe('ok');
    expect(r.late.status, why).not.toBe('ok');
    expect(r.final, why).toBeNull();
  }, 90000);
});
"""
save("src/agent-browser/revocation-capture.test.ts")
print("patched v2")
