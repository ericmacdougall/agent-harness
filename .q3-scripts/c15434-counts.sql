-- READ-ONLY (PGOPTIONS default_transaction_read_only=on; first row proves it). goodqa#15434. Counts and enum values only.
show transaction_read_only;
-- Q1, as main wrote it.
SELECT consent_mode, count(distinct org_id), count(*) FILTER (WHERE updated_at = created_at) AS never_edited FROM tracking_settings GROUP BY 1;
-- Q2: orgs other than Eric, P51 Media, FrameBright.
SELECT consent_mode, count(distinct org_id) AS other_orgs, count(*) AS other_rows
FROM tracking_settings
WHERE org_id NOT IN ('1150f036-83d3-46a3-a9da-84b84e9f69d8','3aa27ca0-8a3e-4b17-91af-63055a75f038','a19d343e-f162-4a05-849d-4565e90e4b3f')
GROUP BY 1;
SELECT count(distinct org_id) AS other_orgs_total
FROM tracking_settings
WHERE org_id NOT IN ('1150f036-83d3-46a3-a9da-84b84e9f69d8','3aa27ca0-8a3e-4b17-91af-63055a75f038','a19d343e-f162-4a05-849d-4565e90e4b3f');
-- Q3 inputs: connection statuses, so the "connected" filter below can be checked.
SELECT 'mailbox_connections' AS t, status::text, count(*) FROM mailbox_connections WHERE can_send GROUP BY 2
UNION ALL SELECT 'gmail', status::text, count(*) FROM outreach_gmail_connections GROUP BY 2
UNION ALL SELECT 'outlook', status::text, count(*) FROM outreach_outlook_mailboxes GROUP BY 2
UNION ALL SELECT 'smtp', status::text, count(*) FROM outreach_smtp_mailboxes GROUP BY 2
UNION ALL SELECT 'zoho', status::text, count(*) FROM outreach_zoho_connections GROUP BY 2
UNION ALL SELECT 'mailgun', status::text, count(*) FROM outreach_mailgun_connections GROUP BY 2
ORDER BY 1, 2;
-- Q3 proxy: identity exists only per project in marketing_brand_profiles; an org counts as having it when any project has both fields.
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
), identified AS (
  SELECT DISTINCT p.org_id FROM marketing_brand_profiles b JOIN projects p ON p.id = b.project_id
  WHERE btrim(coalesce(b.identity->>'legalName','')) <> '' AND btrim(coalesce(b.identity->>'headquartersAddress','')) <> ''
)
SELECT (SELECT count(*) FROM enabled) AS orgs_outreach_enabled,
       (SELECT count(*) FROM connected) AS orgs_mailbox_connected,
       (SELECT count(*) FROM scope) AS orgs_in_scope,
       (SELECT count(*) FROM scope s WHERE s.org_id NOT IN (SELECT org_id FROM identified)) AS in_scope_no_identity,
       (SELECT count(*) FROM scope s WHERE s.org_id NOT IN (SELECT org_id FROM identified)
          AND s.org_id NOT IN ('1150f036-83d3-46a3-a9da-84b84e9f69d8','3aa27ca0-8a3e-4b17-91af-63055a75f038','a19d343e-f162-4a05-849d-4565e90e4b3f')) AS in_scope_no_identity_other_orgs;
