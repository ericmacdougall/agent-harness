
// goodqa#15477 F1 rescue: a revocation replaces the document even when the page resists, the indicator holds until the
// replacement commits, the beforeunload override never outlives the revocation, and no failure is silent.
describe('revocation replaces the document or says it could not (F1)', () => {
  const open = async (surface = 'desktop_visible') => {
    const out = await h.execute(cmd('browser_open', { url: 'https://example.com', surface }));
    return (out.result as { data: { tabId: number } }).data.tabId;
  };
  const tab = (id: number) => (h as any).tabs.get(id);
  const view = (id: number) => h.state().tabs.find((t) => t.id === id) as { media: boolean; revocation: string | null; controller: string } | undefined;
  type Load = (url: string) => Promise<void>;
  /** Scripted loads: each call takes the next behaviour; 'commit' emits did-navigate like Electron does. */
  const script = (wc: any, ...steps: Array<'commit' | 'reject' | 'no_commit' | 'hang'>) => {
    const queue = [...steps];
    wc.loadURL.mockImplementation(((url: string) => {
      const step = queue.shift() ?? 'commit';
      if (step === 'commit') { wc.url = url; wc.emit('did-navigate', {}, url, 200); return Promise.resolve(); }
      if (step === 'reject') return Promise.reject(Object.assign(new Error('ERR_ABORTED (-3) loading ' + url), { code: 'ERR_ABORTED', errno: -3 }));
      if (step === 'no_commit') return Promise.resolve();
      return new Promise<void>(() => {});
    }) as Load);
  };
  const capturing = async (surface = 'desktop_visible') => {
    const id = await open(surface);
    const t = tab(id);
    t.media = true;
    t.mediaGrants.set('https://example.com', new Set(['video']));
    t.view.webContents.loadURL.mockClear();
    t.view.webContents.stop.mockClear();
    return { id, t, wc: t.view.webContents };
  };
  let log: ReturnType<typeof vi.spyOn>;
  const revokeLines = () => log.mock.calls.map((c: unknown[]) => String(c[0])).filter((l: string) => l.includes('revoke_failed'));
  beforeEach(() => { log = vi.spyOn(console, 'error').mockImplementation(() => {}); });
  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

  it('a plain page commits on the first load: no fallback, no log, indicator ends on the commit', async () => {
    const { id, t, wc } = await capturing();
    const base = wc.listenerCount('did-navigate');
    script(wc, 'commit');
    await expect((h as any).replaceDocument(t, 'stopped_by_person')).resolves.toBe('replaced');
    expect(wc.loadURL).toHaveBeenCalledTimes(1);
    expect(view(id)?.media).toBe(false);
    expect(revokeLines()).toEqual([]);
    expect(wc.listenerCount('will-prevent-unload')).toBe(0);
    expect(wc.listenerCount('did-navigate')).toBe(base);
  });

  it('stopTab: a rejected load (beforeunload veto, 204, download) falls back to stop() and about:blank, logged', async () => {
    const { id, wc } = await capturing();
    let release!: () => void;
    script(wc, 'reject', 'hang');
    wc.loadURL.mockImplementationOnce(() => Promise.reject(Object.assign(new Error('x'), { code: 'ERR_ABORTED' })));
    wc.loadURL.mockImplementationOnce((url: string) => new Promise<void>((r) => { release = () => { wc.url = url; wc.emit('did-navigate', {}, url, -1); r(); }; }));
    h.stopTab(id);
    await vi.waitFor(() => expect(wc.loadURL).toHaveBeenCalledWith('about:blank'));
    expect(wc.loadURL.mock.calls.map((c: unknown[]) => c[0])).toEqual(['https://example.com/', 'about:blank']);
    expect(wc.stop.mock.invocationCallOrder.at(-1)).toBeLessThan(wc.loadURL.mock.invocationCallOrder[1]);
    // The old document may still be capturing: the person keeps seeing it until about:blank commits.
    expect(view(id)).toMatchObject({ media: true, revocation: 'pending', controller: 'user' });
    expect(revokeLines()).toEqual([`[agent-browser] revoke_failed id=${id} reason=stopped_by_person step=load code=err_aborted`]);
    release();
    await vi.waitFor(() => expect(view(id)).toMatchObject({ media: false, revocation: null }));
    expect(wc.listenerCount('will-prevent-unload')).toBe(0);
  });

  it('a load that resolves without a committed document (204, attachment) also falls back', async () => {
    const { t, wc } = await capturing();
    script(wc, 'no_commit', 'commit');
    await expect((h as any).replaceDocument(t, 'media_ended')).resolves.toBe('blank');
    expect(wc.loadURL).toHaveBeenLastCalledWith('about:blank');
    expect(revokeLines()).toEqual([`[agent-browser] revoke_failed id=${t.id} reason=media_ended step=load code=no_commit`]);
  });

  it('a GET that never answers: indicator holds, then after the bound stop() and about:blank', async () => {
    const { id, wc } = await capturing();
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    script(wc, 'hang', 'commit');
    h.stopTab(id);
    expect(wc.loadURL).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1400);
    expect(view(id)).toMatchObject({ media: true, revocation: 'pending' });
    expect(wc.loadURL).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(200);
    expect(wc.loadURL).toHaveBeenLastCalledWith('about:blank');
    expect(view(id)).toMatchObject({ media: false, revocation: null });
    expect(revokeLines()).toEqual([`[agent-browser] revoke_failed id=${id} reason=stopped_by_person step=load code=timeout`]);
    expect(wc.listenerCount('will-prevent-unload')).toBe(0);
  });

  it('during the revocation a beforeunload page cannot veto the unload; afterwards the override is gone', async () => {
    const { t, wc } = await capturing();
    script(wc, 'hang', 'hang');
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const done = (h as any).replaceDocument(t, 'stopped_by_person');
    const during = { preventDefault: vi.fn() };
    wc.emit('will-prevent-unload', during);
    expect(during.preventDefault).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(3100);
    await expect(done).resolves.toBe('failed');
    const after = { preventDefault: vi.fn() };
    wc.emit('will-prevent-unload', after);
    expect(after.preventDefault).not.toHaveBeenCalled();
  });

  it.each([
    ['commit', ['commit']],
    ['reject then commit', ['reject', 'commit']],
    ['both fail', ['reject', 'reject']],
    ['no commit twice', ['no_commit', 'no_commit']],
  ] as const)('the override and commit listeners are removed on every path: %s', async (_n, steps) => {
    const { t, wc } = await capturing();
    const base = wc.listenerCount('did-navigate');
    script(wc, ...steps);
    await (h as any).replaceDocument(t, 'x');
    expect(wc.listenerCount('will-prevent-unload')).toBe(0);
    expect(wc.listenerCount('did-navigate')).toBe(base);
  });

  it('the override is removed when the tab is closed mid-revocation, and nothing is logged as failed', async () => {
    const { id, t, wc } = await capturing();
    let fail!: (e: unknown) => void;
    wc.loadURL.mockImplementationOnce(() => new Promise<void>((_r, j) => { fail = j; }));
    const done = (h as any).replaceDocument(t, 'x');
    h.close(id);
    fail(Object.assign(new Error('gone'), { code: 'ERR_ABORTED' }));
    await expect(done).resolves.toBe('gone');
    expect(wc.listenerCount('will-prevent-unload')).toBe(0);
    expect(revokeLines()).toEqual([]);
  });

  it('a visible tab whose about:blank fails too stays with the person showing capture and revocation failed', async () => {
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
    expect(lines.join('\n')).not.toContain('example.com');
    // A later committed document (the person navigates, or Stop again) ends the failed state and the indicator.
    wc.emit('did-navigate', {}, 'https://example.com/next', 200);
    expect(view(id)).toMatchObject({ media: false, revocation: null });
  });

  it('a hidden tab kept by a narrowed renew closes when its replacement cannot commit', async () => {
    h.grant({ ...c(), permissions: { ...c().permissions, uploads: true } });
    const out = await h.execute(cmd('browser_open', { url: 'https://example.com' }));
    const id = (out.result as { data: { tabId: number } }).data.tabId;
    const wc = tab(id).view.webContents;
    script(wc, 'reject', 'reject');
    h.grant({ ...c(), generation: 3 });
    await vi.waitFor(() => expect(tab(id)).toBeUndefined());
    expect(log.mock.calls.some((c: unknown[]) => String(c[0]).includes(`tab_closed id=${id} reason=revoke_failed`))).toBe(true);
  });

  it('a renew that drops a capturing visible tab keeps the indicator until the replacement commits', async () => {
    const { id, wc } = await capturing();
    script(wc, 'hang', 'commit');
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    h.grant({ ...c(), generation: 3 });
    expect(tab(id).mediaGrants.size).toBe(0);
    expect(view(id)).toMatchObject({ media: true, revocation: 'pending', controller: 'user' });
    await vi.advanceTimersByTimeAsync(1600);
    expect(view(id)).toMatchObject({ media: false, revocation: null });
  });

  it.each(['park', 'stop'] as const)('%s takes the same path for a capturing visible tab', async (path) => {
    const { id, wc } = await capturing();
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    script(wc, 'reject', 'hang');
    if (path === 'park') h.suspendForRenew(); else h.stop();
    await vi.advanceTimersByTimeAsync(0);
    expect(wc.loadURL.mock.calls.map((c: unknown[]) => c[0])).toEqual(['https://example.com/', 'about:blank']);
    expect(view(id)).toMatchObject({ media: true, revocation: 'pending', controller: 'user' });
    await vi.advanceTimersByTimeAsync(1600);
    expect(view(id)).toMatchObject({ media: true, revocation: 'failed' });
    expect(revokeLines()).toHaveLength(2);
  });

  it('a newer revocation supersedes an older one: the older neither stops the newer load nor logs', async () => {
    const { t, wc } = await capturing();
    let failFirst!: (e: unknown) => void;
    wc.loadURL.mockImplementationOnce(() => new Promise<void>((_r, j) => { failFirst = j; }));
    const first = (h as any).replaceDocument(t, 'a');
    script(wc, 'hang');
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const second = (h as any).replaceDocument(t, 'b');
    wc.stop.mockClear();
    failFirst(Object.assign(new Error('x'), { code: 'ERR_ABORTED' }));
    await expect(first).resolves.toBe('superseded');
    expect(wc.stop).not.toHaveBeenCalled();
    expect(revokeLines()).toEqual([]);
    wc.emit('did-navigate', {}, 'about:blank', -1);
    await expect(second).resolves.toBe('replaced');
  });
});
