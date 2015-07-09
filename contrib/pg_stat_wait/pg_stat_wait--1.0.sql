/* contrib/pg_stat_wait/pg_stat_wait--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_stat_wait" to load this file. \quit

CREATE FUNCTION pg_wait_class_list(
    OUT class_id int4,
    OUT name cstring
)
RETURNS SETOF record
AS 'MODULE_PATHNAME'
LANGUAGE C VOLATILE;

CREATE FUNCTION pg_wait_event_list(
    OUT class_id int4,
    OUT event_id int4,
    OUT name cstring
)
RETURNS SETOF record
AS 'MODULE_PATHNAME'
LANGUAGE C VOLATILE;

CREATE VIEW pg_wait_event AS
	SELECT class_id, event_id, CAST(name as text) as name FROM pg_wait_event_list();

CREATE VIEW pg_wait_class AS
	SELECT class_id, CAST(name as text) as name FROM pg_wait_class_list();

CREATE VIEW pg_wait_events AS
	SELECT c.class_id, CAST(c.name as text) as class_name, e.event_id, CAST(e.name as text) as event_name
	FROM pg_wait_class c
	INNER JOIN pg_wait_event e ON c.class_id = e.class_id
	ORDER BY c.class_id, e.event_id;

/* Returns history, parameters count must be equal with WAIT_PARAMS_COUNT in proc.h */
CREATE FUNCTION pg_stat_wait_get_history(
    OUT pid int4,
    OUT sample_ts timestamptz,
    OUT class_id int4,
    OUT event_id int4,
    OUT wait_time int8,
	OUT p1 int4,
	OUT p2 int4,
	OUT p3 int4,
	OUT p4 int4,
	OUT p5 int4
)
RETURNS SETOF record
AS 'MODULE_PATHNAME'
LANGUAGE C VOLATILE STRICT;

CREATE VIEW pg_stat_wait_history AS
	SELECT pid, sample_ts, h.class_id, e.class_name, h.event_id, e.event_name, wait_time, p1, p2, p3, p4, p5
	FROM pg_stat_wait_get_history() h
	INNER JOIN pg_wait_events e
	ON e.class_id = h.class_id and e.event_id = h.event_id;

CREATE FUNCTION pg_stat_wait_get_profile(
    pid int4,
    reset boolean,
    OUT pid int4,
    OUT class_id int4,
    OUT event_id int4,
    OUT wait_time int8,
	OUT wait_count int4
)
RETURNS SETOF record
AS 'MODULE_PATHNAME'
LANGUAGE C VOLATILE CALLED ON NULL INPUT;

CREATE VIEW pg_stat_wait_profile AS
	SELECT pid, p.class_id, e.class_name, p.event_id, e.event_name, wait_time, wait_count
	FROM pg_stat_wait_get_profile(NULL, false) p
	INNER JOIN pg_wait_events e
	ON e.class_id = p.class_id and e.event_id = p.event_id;

CREATE FUNCTION pg_stat_wait_reset_profile()
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pg_stat_wait_get_current(
    pid int4,
    OUT pid int4,
    OUT sample_ts timestamptz,
    OUT class_id int4,
    OUT event_id int4,
    OUT wait_time int8,
	OUT p1 int4,
	OUT p2 int4,
	OUT p3 int4,
	OUT p4 int4,
	OUT p5 int4
)
RETURNS SETOF record
AS 'MODULE_PATHNAME'
LANGUAGE c VOLATILE CALLED on NULL INPUT;

CREATE VIEW pg_stat_wait_current AS
  SELECT pid, sample_ts, c.class_id, e.class_name, c.event_id, e.event_name,
	wait_time, p1, p2, p3, p4, p5
  FROM pg_stat_wait_get_current(null) c
  INNER JOIN pg_wait_events e
  ON e.class_id = c.class_id and e.event_id = c.event_id;

CREATE FUNCTION pg_start_trace(
    backend_pid int4,
    filename cstring
)
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C VOLATILE CALLED ON NULL INPUT;

CREATE FUNCTION pg_is_in_trace(
    backend_pid int4
)
RETURNS bool
AS 'MODULE_PATHNAME'
LANGUAGE C VOLATILE CALLED ON NULL INPUT;

CREATE FUNCTION pg_stop_trace(
    backend_pid int4
)
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C VOLATILE CALLED ON NULL INPUT;

