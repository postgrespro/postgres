/* contrib/toastapi/toastapi--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION toastapi" to load this file. \quit

CREATE FUNCTION set_toaster(cstring, cstring, cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION reset_toaster(cstring, cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION add_toaster(cstring, cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION drop_toaster(cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION get_toaster(cstring, cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;
