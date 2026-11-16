
describe('F4 (code review goodqa#16148): a huge first line is cut before the residue scan', () => {
  // A PEM-sized fake value, as in the review probe: the scan is per character times the value forms.
  const PEM = 'FAKEpem' + 'Q'.repeat(1700) + 'END';
  const GUARD = 'docker: Error response from daemon: job-dispatcher-create-guard: refused (';

  it('a 1 MiB allow-listed first line returns well inside the event-loop budget', () => {
    const line = GUARD + 'x'.repeat(1024 * 1024) + ')';
    const started = performance.now();
    const msg = describeDockerFailure(line + '\nmore', [MARKER, PEM, 'sk-base-fake-value']);
    const ms = performance.now() - started;
    expect(ms).toBeLessThan(1000);
    expect(msg.startsWith('docker run failed: guard_refused (stderr ')).toBe(true);
    expect(msg.length).toBeLessThanOrEqual(80 + 200);
  }, 30_000);

  it('deterministic: only the first SCAN_LIMIT characters are scanned (a fragment far past it no longer drops the line)', () => {
    const line = GUARD + 'x'.repeat(10_000) + MARKER.slice(0, 20) + ')';
    const msg = describeDockerFailure(line, [MARKER]);
    expect(msg).toBe(`docker run failed: guard_refused (stderr ${Buffer.byteLength(line, 'utf8')} bytes): ${line.slice(0, 200)}`);
  });

  it('a value inside the scanned part of a long line still drops the line', () => {
    const line = GUARD + 'x'.repeat(3000) + MARKER.slice(0, 20) + 'y'.repeat(1024 * 1024) + ')';
    const msg = describeDockerFailure(line, [MARKER]);
    expect(msg).toBe(`docker run failed: guard_refused (stderr ${Buffer.byteLength(line, 'utf8')} bytes)`);
  }, 30_000);

  it('a full value anywhere in the line is still redacted from the whole stderr first', () => {
    const line = GUARD + 'x'.repeat(100) + ' ' + MARKER + ' ' + 'y'.repeat(1024 * 1024) + ')';
    const msg = describeDockerFailure(line, [MARKER]);
    expect(msg).not.toContain(MARKER.slice(0, 8));
    expect(msg).toContain('[redacted]');
  }, 30_000);
});
