/* contrib/bloom/bloom--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION dummy_toaster" to load this file. \quit

CREATE FUNCTION dummy_toaster_handler(internal)
RETURNS toaster_handler
AS 'MODULE_PATHNAME'
LANGUAGE C;


CREATE TOASTER dummy_toaster  HANDLER dummy_toaster_handler;

COMMENT ON TOASTER dummy_toaster IS 'dummy_toaster is a dummy toaster';

