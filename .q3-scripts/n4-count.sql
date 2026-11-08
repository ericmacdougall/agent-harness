-- READ-ONLY (PGOPTIONS default_transaction_read_only=on; the first row proves it). Numbers only: no ids, names,
-- tokens or titles. goodqa#14903 N4: invite links that point at a QAC AI thread, and people who joined one that way.
show transaction_read_only;
select
  (select count(*) from invite_links l join ai_threads a on a.conversation_id = l.conversation_id) as ai_links_total,
  (select count(*) from invite_links l join ai_threads a on a.conversation_id = l.conversation_id
     where l.revoked_at is null and l.expires_at > now() and (l.max_uses is null or l.use_count < l.max_uses)) as ai_links_live,
  (select coalesce(sum(l.use_count), 0) from invite_links l join ai_threads a on a.conversation_id = l.conversation_id) as ai_link_uses,
  (select count(*) from audit_events e join ai_threads a on a.conversation_id::text = e.changes->>'conversationId'
     where e.action = 'invite_link.accepted') as ai_link_accept_audits,
  (select count(distinct (e.actor_id, a.conversation_id)) from audit_events e
     join ai_threads a on a.conversation_id::text = e.changes->>'conversationId'
     join chat_conversation_members m on m.conversation_id = a.conversation_id and m.user_id::text = e.actor_id::text and m.is_member
     where e.action = 'invite_link.accepted') as ai_link_joiners_still_member,
  (select count(*) from invite_links where conversation_id is not null) as control_channel_links_total,
  (select count(*) from ai_threads) as control_ai_threads_total;
