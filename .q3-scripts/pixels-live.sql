-- goodqa#14903 release goodqa-14903-kimi-ui1c (6ea39797): pixels default check after deploy (#1307, migration 14912).
-- Run with PGOPTIONS default_transaction_read_only=on; the first row proves it. Enum values, defaults and counts only.
show transaction_read_only;
select column_default from information_schema.columns
 where table_name = 'tracking_settings' and column_name = 'consent_mode';
select consent_mode, count(*) as rows, count(*) filter (where updated_at = created_at) as never_edited
  from tracking_settings group by 1 order by 1;
select count(*) as notice_never_edited from tracking_settings where consent_mode = 'notice' and updated_at = created_at;
