select pg_start_trace(0, '/tmp/pg_stat_wait.trace');
select pg_is_in_trace(0);
select pg_stop_trace(0);

