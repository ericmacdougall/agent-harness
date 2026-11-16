
describe('receipt pr1372-v1 BLOCK: the 8-byte residue rule counts UTF-8 bytes, not UTF-16 code units', () => {
  // Fake secrets only: short in code units, at least 8 bytes in UTF-8.
  const CJK = '秘密鍵値六字'; // 6 code units, 18 bytes
  const LATIN = 'éèêë'; // 4 code units, 8 bytes
  const prefix = 'docker: Error response from daemon: job-dispatcher-create-guard: refused (';
  const forms: Array<[string, (v: string) => string]> = [
    ['base64', (v) => b64(v)],
    ['base64, other alignment', (v) => b64(`x${v}`)],
    ['hex', (v) => Buffer.from(v, 'utf8').toString('hex')],
    ['HEX', (v) => Buffer.from(v, 'utf8').toString('hex').toUpperCase()],
    ['decimal bytes', (v) => [...Buffer.from(v, 'utf8')].join(' ')],
  ];
  const cases = [CJK, LATIN].flatMap((v) => forms.map(([n, f]) => [`${v.length} units / ${Buffer.byteLength(v)} bytes, ${n}`, v, f(v)] as const));

  it.each(cases)('%s: only the category and the byte count come out', (_name, value, echo) => {
    const stderr = `${prefix}got ${echo})\n`;
    expect(value.length).toBeLessThan(8);
    expect(Buffer.byteLength(value, 'utf8')).toBeGreaterThanOrEqual(8);
    expect(describeDockerFailure(stderr, [value])).toBe(
      `docker run failed: guard_refused (stderr ${Buffer.byteLength(stderr, 'utf8')} bytes)`,
    );
  });

  it('a value under 8 bytes keeps the exact-token rule (short base values never shred a line)', () => {
    const msg = describeDockerFailure(`${prefix}Image must be one of the 1 pre-approved job images, got "abc")\n`, ['éé']);
    expect(msg).toContain('got "abc")');
  });

  it('server: the 422 body for an encoded echo of a short-in-units secret is the category and byte count only', async () => {
    clearExecutionsForTesting();
    const TOKEN = 'shim-token-not-real';
    const logs: string[] = [];
    const app = buildServer({
      ...loadConfig({
        JOB_DISPATCH_TOKEN: TOKEN,
        JOB_IMAGE_SCAN: 'ar/scan:tag',
        JOB_IMAGE_TRANSCODE: 'ar/transcode:tag',
        JOB_IMAGE_INTELLIGENCE_WORKER: 'ar/iw:tag',
        JOB_IMAGE_SUGGEST_FIX_WORKER: 'ar/sf:tag',
      }),
      jobBaseEnv: { scan: {}, transcode: { GCS_BUCKET: CJK }, 'intelligence-worker': {}, 'suggest-fix-worker': {} },
    }, { run: dockerRunDetached, inspect: vi.fn() } as never, { logStream: { write: (line: string) => logs.push(line) } });
    app.addHook('onSend', async (_req, _reply, payload) => {
      logs.push(String(payload));
      return payload;
    });
    for (const [, f] of forms) {
      const stderr = `${prefix}got ${f(CJK)})\n`;
      respondFailure(stderr);
      const res = await app.inject({ method: 'POST', url: '/jobs/transcode/run', headers: { authorization: `Bearer ${TOKEN}` }, payload: {} });
      expect(res.statusCode).toBe(422);
      expect((res.json() as { error: string }).error).toBe(
        `docker run failed: guard_refused (stderr ${Buffer.byteLength(stderr, 'utf8')} bytes)`,
      );
      for (const [, g] of forms) {
        expect(res.body).not.toContain(g(CJK).slice(0, 12));
        for (const l of logs) expect(l).not.toContain(g(CJK).slice(0, 12));
      }
    }
  });
});
