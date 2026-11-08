"""Kimi qac-privacy-001, web half: an AI thread never offers the org-wide Invite people control, whether or not
the threads capability is on (the server now refuses invite links for AI threads). Runs at the q3-kimi root."""
import pathlib

def sub(text, old, new, label):
    assert text.count(old) == 1, f'{label}: anchor count {text.count(old)}'
    return text.replace(old, new)

p = pathlib.Path('apps/web/src/components/messaging/conversation-pane.tsx')
s = p.read_text()
s = sub(s, """  // AI sharing must use the history-choice route (S6), never channel invitations.
  const inviteAvailable =
    !(aiThreadsEnabled && channelSummary?.ai) &&
""", """  // AI sharing must use the history-choice route (S6), never channel invitations, even while the threads
  // capability is off: the thread was created as "Only you can see this thread" (goodqa#14903).
  const inviteAvailable =
    !channelSummary?.ai &&
""", 'pane')
p.write_text(s)

t = pathlib.Path('apps/web/src/components/messaging/channel-header-words.test.tsx')
u = t.read_text()
u = sub(u, "  'gates the %s AI title control and channel invitations on the threads capability',",
        "  'gates the %s AI title control on the threads capability and never offers channel invitations',", 'title')
u = sub(u, """    expect(screen.queryByRole('button', { name: 'Rename thread' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Invite people' })).toBeDefined();
    fireEvent.click(screen.getByRole('button', { name: 'Invite people' }));
    expect(await screen.findByRole('dialog', { name: 'Invite people' })).toBeDefined();
    fireEvent.click(screen.getByRole('button', { name: 'Close dialog' }));
    view.rerender(""", """    expect(screen.queryByRole('button', { name: 'Rename thread' })).toBeNull();
    // goodqa#14903: a private AI thread never offers the org-wide invitation, even with threads off.
    expect(screen.queryByRole('button', { name: 'Invite people' })).toBeNull();
    view.rerender(""", 'body')
t.write_text(u)
print('ok')
