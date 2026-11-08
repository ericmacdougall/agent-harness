"""Kimi qac-privacy-001 / S3a red-team M3: an invite link can neither be minted for, nor admit anyone into, a
private QAC AI thread (stored as kind 'channel'). Runs on t2-dev at the q3-kimi worktree root."""
import pathlib

def sub(text, old, new, label):
    assert text.count(old) == 1, f'{label}: anchor count {text.count(old)}'
    return text.replace(old, new)

r = pathlib.Path('apps/api/src/modules/orgs/routes.ts')
s = r.read_text()
s = sub(s, "  apiKeys,\n  attachments,\n  auditEvents,\n", "  aiThreads,\n  apiKeys,\n  attachments,\n  auditEvents,\n", 'routes-import')
s = sub(s, """          throw Errors.badRequest('Only channels can be joined through an invite link');
        }
""", """          throw Errors.badRequest('Only channels can be joined through an invite link');
        }
        // A QAC AI thread is a private channel row, but it is shared only through its own Share action,
        // which asks how much history to show. An org invite link must never reach into one (goodqa#14903).
        const [aiThread] = await app.db.select({ id: aiThreads.conversationId }).from(aiThreads)
          .where(eq(aiThreads.conversationId, access.conversation.id)).limit(1);
        if (aiThread) {
          throw Errors.badRequest('AI threads are shared from the thread itself, not through an invite link');
        }
""", 'mint')
r.write_text(s)

i = pathlib.Path('apps/api/src/modules/orgs/invite-links.ts')
t = i.read_text()
t = sub(t, "import {\n  auditEvents,\n  chatConversationMembers,\n", "import {\n  aiThreads,\n  auditEvents,\n  chatConversationMembers,\n", 'links-import')
t = sub(t, """      await requireConversationAccess(db, link.createdBy, link.orgId, link.conversationId, {
        min: 'viewer',
      });
    } catch {
      throw DEAD();
    }
  }
}
""", """      await requireConversationAccess(db, link.createdBy, link.orgId, link.conversationId, {
        min: 'viewer',
      });
    } catch {
      throw DEAD();
    }
    // A link minted before goodqa#14903 may point at a private QAC AI thread: it admits nobody.
    const [aiThread] = await db.select({ id: aiThreads.conversationId }).from(aiThreads)
      .where(eq(aiThreads.conversationId, link.conversationId)).limit(1);
    if (aiThread) throw DEAD();
  }
}
""", 'accept')
i.write_text(t)
print('ok')
