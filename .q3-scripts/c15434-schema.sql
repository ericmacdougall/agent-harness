-- READ-ONLY schema look for goodqa#15434: column names only, no rows.
show transaction_read_only;
select table_name, string_agg(column_name, ' ' order by ordinal_position) as cols
from information_schema.columns
where table_schema = 'public'
  and (table_name = 'tracking_settings'
    or table_name ~ '(outreach|mailbox|mail_account|email_account|smtp|sender)'
    or column_name ~ '(legal_name|postal|physical_address|mailing_address|sender_name|sender_address|business_address)')
group by table_name order by table_name;
