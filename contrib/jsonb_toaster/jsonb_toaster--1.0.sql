/* contrib/jsonb_toaster/jsonb_toaster--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION jsonb_toaster" to load this file. \quit

CREATE FUNCTION jsonb_toaster_handler(internal)
RETURNS toaster_handler
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE TOASTER jsonb_toaster HANDLER jsonb_toaster_handler;

COMMENT ON TOASTER jsonb_toaster IS 'jsonb_toaster is a updatable jsonb toaster';

