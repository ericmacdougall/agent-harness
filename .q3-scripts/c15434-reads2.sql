-- READ-ONLY (PGOPTIONS default_transaction_read_only=on; first row proves it). goodqa#15434 second pass. Counts, dates and booleans only.
show transaction_read_only;
-- 1a. Platform setting.
SELECT coalesce((SELECT value::text FROM platform_settings WHERE key = 'userTokens.sessionActions'), 'absent') AS user_tokens_session_actions;
-- 1b. The three named orgs.
SELECT o.name, CASE WHEN o.entitlement_overrides ? 'userTokens.sessionActions' THEN o.entitlement_overrides->>'userTokens.sessionActions' ELSE 'absent' END AS session_actions_override
FROM organizations o
WHERE o.id IN ('1150f036-83d3-46a3-a9da-84b84e9f69d8','3aa27ca0-8a3e-4b17-91af-63055a75f038','a19d343e-f162-4a05-849d-4565e90e4b3f')
ORDER BY o.name;
-- 2. The same two other orgs as the first pass, labelled only.
WITH enabled AS (
  SELECT DISTINCT c.org_id FROM outreach_config c, jsonb_each(c.channels) ch
  WHERE jsonb_typeof(ch.value) = 'object' AND ch.value->>'enabled' = 'true'
), connected AS (
  SELECT org_id FROM mailbox_connections WHERE can_send AND lower(status::text) NOT IN ('disconnected','revoked','removed','deleted')
  UNION SELECT org_id FROM outreach_gmail_connections WHERE lower(status::text) NOT IN ('disconnected','revoked','removed','deleted')
  UNION SELECT org_id FROM outreach_outlook_mailboxes WHERE lower(status::text) NOT IN ('disconnected','revoked','removed','deleted')
  UNION SELECT org_id FROM outreach_smtp_mailboxes WHERE lower(status::text) NOT IN ('disconnected','revoked','removed','deleted')
  UNION SELECT org_id FROM outreach_zoho_connections WHERE lower(status::text) NOT IN ('disconnected','revoked','removed','deleted')
  UNION SELECT org_id FROM outreach_mailgun_connections WHERE lower(status::text) NOT IN ('disconnected','revoked','removed','deleted')
), scope AS (
  SELECT org_id FROM enabled UNION SELECT org_id FROM connected
), others AS (
  SELECT org_id, chr(64 + row_number() OVER (ORDER BY org_id)::int) AS label FROM scope
  WHERE org_id NOT IN ('1150f036-83d3-46a3-a9da-84b84e9f69d8','3aa27ca0-8a3e-4b17-91af-63055a75f038','a19d343e-f162-4a05-849d-4565e90e4b3f')
)
SELECT 'other ' || x.label AS org,
       coalesce(p.sender_kind::text, 'no_permit') AS sender_kind,
       l.dry_run,
       count(l.id) AS sends,
       count(l.id) FILTER (WHERE l.sent_at > now() - interval '30 days') AS sends_30d,
       (max(l.sent_at))::date AS latest_send
FROM others x
LEFT JOIN outreach_send_ledger l ON l.org_id = x.org_id
LEFT JOIN outreach_permits p ON p.id = l.permit_id AND p.org_id = l.org_id
GROUP BY 1, 2, 3 ORDER BY 1, 2, 3;
