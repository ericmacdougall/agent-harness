-- READ-ONLY control for goodqa#15434 Q3: are the identity keys real? Counts only.
show transaction_read_only;
SELECT count(*) AS brand_profiles,
       count(*) FILTER (WHERE btrim(coalesce(identity->>'legalName','')) <> '') AS with_legal_name,
       count(*) FILTER (WHERE btrim(coalesce(identity->>'headquartersAddress','')) <> '') AS with_hq_address,
       count(*) FILTER (WHERE identity <> '{}'::jsonb) AS with_any_identity
FROM marketing_brand_profiles;
SELECT count(*) AS other_org_outreach_or_mailbox_channels_live
FROM outreach_config c, jsonb_each(c.channels) ch
WHERE jsonb_typeof(ch.value) = 'object' AND ch.value->>'enabled' = 'true' AND ch.value->>'dryRun' = 'false'
  AND c.org_id NOT IN ('1150f036-83d3-46a3-a9da-84b84e9f69d8','3aa27ca0-8a3e-4b17-91af-63055a75f038','a19d343e-f162-4a05-849d-4565e90e4b3f');
