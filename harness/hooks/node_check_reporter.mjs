// Delivery authority comes only from native CLI events, never worker output.
export default async function* (events) {
  for await (const event of events) {
    if (event.type === 'test:summary') {
      const d = event.data;
      yield JSON.stringify({kind: 'summary', file: d.file ?? null,
        success: d.success, counts: d.counts}) + '\n';
    } else if (['test:stdout', 'test:stderr', 'test:diagnostic', 'test:fail'].includes(event.type)) {
      const message = event.type === 'test:fail'
        ? `${event.data.name}: ${event.data.details?.error?.message ?? 'test failed'}`
        : event.data.message;
      if (typeof message === 'string') {
        yield JSON.stringify({kind: 'diagnostic', text: message.slice(0, 2000)}) + '\n';
      }
    }
  }
  yield '{"kind":"end"}\n';
}
