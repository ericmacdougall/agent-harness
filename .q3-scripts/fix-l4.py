"""S3a red-team L4: the overlap barrier test must fail if the two handlers never overlapped (poll timeout)."""
import pathlib
p = pathlib.Path('apps/api/test/qac-run-reports-s3a.test.ts')
s = p.read_text()
old = """    for (let i = 0; i < 100; i++) {
      const waiting = ((await ctx.db.execute(sql`select count(*)::int as n from pg_stat_activity where datname = current_database() and wait_event_type = 'Lock'`)) as unknown as { n: number }[])[0]!.n;
      if (waiting + settled.length >= 2) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    release();
"""
new = """    let overlapped = false;
    for (let i = 0; i < 100; i++) {
      const waiting = ((await ctx.db.execute(sql`select count(*)::int as n from pg_stat_activity where datname = current_database() and wait_event_type = 'Lock'`)) as unknown as { n: number }[])[0]!.n;
      // At least one handler must be blocked on the held lock, or the test proves nothing (red-team L4).
      if (waiting >= 1 && waiting + settled.length >= 2) { overlapped = true; break; }
      await new Promise((r) => setTimeout(r, 50));
    }
    expect(overlapped).toBe(true);
    release();
"""
assert s.count(old) == 1, s.count(old)
p.write_text(s.replace(old, new))
print('ok')
