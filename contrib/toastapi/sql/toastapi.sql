CREATE EXTENSION toastapi;

CREATE FUNCTION dummy_toaster_handler(internal)
RETURNS internal
AS '$libdir/toastapi'
LANGUAGE C;

-- add_toaster()
SELECT add_toaster(NULL, NULL);
SELECT add_toaster(NULL, 'foo');
SELECT add_toaster('bar', NULL);
SELECT add_toaster('', '');
SELECT add_toaster('foo', '');
SELECT add_toaster('foo', 'bar');
SELECT add_toaster('dummy', 'foo');

SELECT add_toaster('dummy', 'dummy_toaster_handler') AS dummy_toaster_oid
\gset

SELECT :dummy_toaster_oid <> 0;
SELECT add_toaster('dummy', 'foo');
SELECT :dummy_toaster_oid = add_toaster('dummy', 'dummy_toaster_handler');

SELECT add_toaster('foo', 'dummy_toaster_handler') AS foo_toaster_oid
\gset

SELECT :foo_toaster_oid <> 0;
SELECT :foo_toaster_oid <> :dummy_toaster_oid;
SELECT :foo_toaster_oid = add_toaster('foo', 'dummy_toaster_handler');

-- drop_toaster()
SELECT drop_toaster(NULL);
SELECT drop_toaster('');
SELECT drop_toaster('bar');
SELECT drop_toaster('foo') = :foo_toaster_oid;
SELECT drop_toaster('foo');

DROP EXTENSION toastapi;
