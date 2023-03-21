CREATE EXTENSION toastapi;

CREATE FUNCTION dummy_toaster_handler(internal)
RETURNS internal
AS '$libdir/toastapi'
LANGUAGE C;
DROP EXTENSION toastapi;
