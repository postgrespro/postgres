/* contrib/bytea_toaster/bytea_toaster--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION bytea_toaster" to load this file. \quit

CREATE FUNCTION bytea_toaster_handler(internal)
RETURNS toaster_handler
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE TOASTER bytea_toaster  HANDLER bytea_toaster_handler;

COMMENT ON TOASTER bytea_toaster IS 'bytea_toaster is a appendable bytea toaster';
