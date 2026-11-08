-- READ-ONLY proof of the t2-dev route. Numbers only.
show transaction_read_only;
select (select count(*) from ai_threads) as ai_threads, (select count(*) from workflow_run_reports) as report_rows;
