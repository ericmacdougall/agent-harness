// Local presentation state only: a reply counts once while unread, including streaming patches.
// The first server snapshot is history. Counts never change server read/approval state.
export function chatAttention() {
  let previous = null;
  const unread = new Set();
  return {
    observe(messages, reading) {
      const current = new Map(messages.filter(m => ['claude', 'codex'].includes(m.from) && m.status !== 'forged')
        .map(m => [m.id, `${m.status}\n${m.text}`]));
      for (const id of unread) if (!current.has(id)) unread.delete(id);
      if (previous && !reading) {
        for (const [id, signature] of current) if (previous.get(id) !== signature) unread.add(id);
      }
      previous = current;
      if (reading) unread.clear();
      return unread.size;
    },
    clear() { unread.clear(); },
  };
}
