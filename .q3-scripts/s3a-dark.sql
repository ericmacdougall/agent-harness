-- READ-ONLY (PGOPTIONS default_transaction_read_only=on; the first row proves it). Numbers and the setting value only.
-- goodqa#14903 S3a dark check after deploy.
show transaction_read_only;
select coalesce((select value::text from platform_settings where key = 'automations.qacRunReports'), 'absent') as qac_run_reports_setting;
select
  (select count(*) from workflow_report_threads) as bound_threads,
  (select count(*) from workflow_run_reports) as report_rows,
  (select count(*) from chat_messages where created_at > now() - interval '2 hours'
     and (body like 'Run report:%' or body like 'More runs of %' or body like 'More routine runs finished%')) as report_messages_2h,
  (select count(*) from invite_links l join ai_threads a on a.conversation_id = l.conversation_id) as ai_thread_links;
