-- goodqa#14903 K2-HANG-CAUSE: read-only, numbers only. Statement latency for the AI-thread create path.
select exists(select 1 from pg_extension where extname = 'pg_stat_statements') as has_pgss;
select calls, round(mean_exec_time::numeric, 1) as mean_ms, round(max_exec_time::numeric, 1) as max_ms,
       case when query ilike '%pg_advisory_xact_lock%' then 'advisory_lock'
            when query ilike 'insert into "ai_threads"%' then 'insert_ai_threads'
            when query ilike '%from "ai_threads"%count(%' then 'hourly_count'
            when query ilike 'insert into "qac_turns"%' then 'insert_qac_turns'
            when query ilike '%from "qac_turns"%for update%' then 'qac_turn_for_update'
            else 'other' end as step
from pg_stat_statements
where query ilike '%pg_advisory_xact_lock%' or query ilike 'insert into "ai_threads"%'
   or (query ilike '%from "ai_threads"%' and query ilike '%count(%')
   or query ilike 'insert into "qac_turns"%' or (query ilike '%from "qac_turns"%' and query ilike '%for update%')
order by max_exec_time desc limit 12;
select count(*) as ai_threads_last_7d, count(*) filter (where created_at > now() - interval '1 day') as last_1d
from ai_threads where created_at > now() - interval '7 days';
