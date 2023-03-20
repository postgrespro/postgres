/* contrib/toastapi/toastapi--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION toastapi" to load this file. \quit

CREATE TABLE pg_toaster (
	tsroid oid PRIMARY KEY,
	trsname name UNIQUE,
	tsrhandler regproc
);

CREATE INDEX pg_toaster_index ON pg_toaster USING btree (tsroid);

CREATE FUNCTION set_toaster(toaster_name text, tab_name text, col_name text)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;

CREATE FUNCTION reset_toaster(tab_name text, col_name text)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;

CREATE FUNCTION add_toaster(toaster_name text, toaster_handler_func text)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;

CREATE FUNCTION drop_toaster(toaster_name text)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;

CREATE FUNCTION get_toaster(tab_name text, col_name text)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;
