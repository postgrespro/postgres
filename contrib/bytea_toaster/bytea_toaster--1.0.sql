/* contrib/bytea_toaster/bytea_toaster--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION bytea_toaster" to load this file. \quit

CREATE FUNCTION bytea_toaster_handler(internal)
RETURNS internal
AS 'MODULE_PATHNAME'
LANGUAGE C;

DO
$$
BEGIN
 IF to_regclass('pg_catalog.pg_toaster') IS NOT NULL
 THEN
   EXECUTE 'CREATE TOASTER bytea_toaster  HANDLER bytea_toaster_handler';
   EXECUTE 'COMMENT ON TOASTER bytea_toaster IS ''bytea_toaster is a appendable bytea toaster''';
 ELSE
   PERFORM pgpro_toast.add_toaster('bytea_toaster', 'bytea_toaster_handler');
 END IF;
END
$$;

