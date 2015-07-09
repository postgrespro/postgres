setup
{
	DROP TABLE IF EXISTS do_write;
    CREATE TABLE do_write(id serial primary key);
	DROP FUNCTION IF EXISTS pg_stat_wait_start_wait(int4, int4, int4, int4, int4, int4, int4);
	DROP FUNCTION IF EXISTS pg_stat_wait_stop_wait();

	CREATE FUNCTION pg_stat_wait_start_wait(
		class_id int4,
		event_id int4,
		p1 int4,
		p2 int4,
		p3 int4,
		p4 int4,
		p5 int4
	)
	RETURNS void
	AS 'pg_stat_wait.so'
	LANGUAGE C VOLATILE STRICT;

	CREATE FUNCTION pg_stat_wait_stop_wait()
	RETURNS void
	AS 'pg_stat_wait.so'
	LANGUAGE C VOLATILE STRICT;
}

teardown
{
	DROP TABLE IF EXISTS do_write;
}

session "s0"
step "start_lwlock" {
	SELECT pg_stat_wait_start_wait(1, 10, 1, 0, 0, 0, 5);
	SELECT pg_sleep(1);
}
step "stop_wait" {
	SELECT pg_stat_wait_stop_wait();
}
step "start_io" {
	SELECT pg_stat_wait_start_wait(3, 1, 1, 2, 3, 4, 5);
	SELECT pg_sleep(1);
}

session "s1"
step "get_current_lwlock" {
	SELECT
		pid > 0,
		(now() - sample_ts) < interval '1 hour',
		class_id,
		class_name,
		event_id,
		event_name,
		p1, p2, p3, p4, p5
	FROM pg_stat_wait_current
	WHERE class_id = 1;
}

step "get_current_io" {
	SELECT
		pid > 0,
		(now() - sample_ts) < interval '1 minute',
		class_id,
		class_name,
		event_id,
		event_name,
		p1, p2, p3, p4, p5
	FROM pg_stat_wait_current
	WHERE class_id = 3;
}

step "get_profile" {
	SELECT pid > 0, class_id, class_name, event_id, event_name, wait_time > 0
	FROM pg_stat_wait_profile
	where class_id = 1 AND event_id = 10 AND wait_count > 0;
}

step "get_history_lwlock" {
	SELECT
		pid > 0,
		(now() - sample_ts) < interval '1 hour',
		class_id,
		class_name,
		event_id,
		event_name,
		wait_time > 0,
		p1, p2, p3, p4, p5
	FROM pg_stat_wait_history
	WHERE class_id=1 AND p5=5;
}

step "get_history_io" {
	SELECT (count(*) > 0) AS io_wait_recorded
	FROM pg_stat_wait_history
	WHERE class_id = 3 AND event_id=1 AND p1=1 AND p2=2 AND p3=3 AND p4=4 AND p5=5;
}

permutation "start_lwlock" "get_current_lwlock" "stop_wait" "get_profile" "get_history_lwlock"
permutation "start_io" "get_current_io" "stop_wait" "get_profile" "get_history_io"
