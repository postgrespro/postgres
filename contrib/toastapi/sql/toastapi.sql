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


CREATE TABLE tab (id int, jb jsonb, b_comp bytea, b_uncomp bytea STORAGE external);

-- set_toaster()
SELECT set_toaster('', '', '');
SELECT set_toaster('foo', 'bar', 'baz');
SELECT set_toaster('foo', 'tab', 'baz');
SELECT set_toaster('dummy', 'tab', 'bar');
SELECT set_toaster('dummy', 'tab', 'id');
SELECT set_toaster('dummy', 'tab', 'jb');
SELECT set_toaster('dummy', 'tab', 'b_uncomp');
SELECT set_toaster('dummy', 'tab', 'b_comp') = :dummy_toaster_oid;

-- get_toaster()
SELECT get_toaster('', '');
SELECT get_toaster('foo', 'bar');
SELECT get_toaster('tab', 'bar');
SELECT get_toaster('tab', 'id');
SELECT get_toaster('tab', 'jb');
SELECT get_toaster('tab', 'b_uncomp');
SELECT get_toaster('tab', 'b_comp') = :dummy_toaster_oid;

-- reset_toaster()
SELECT reset_toaster('', '');
SELECT reset_toaster('foo', 'bar');
SELECT reset_toaster('tab', 'bar');
SELECT reset_toaster('tab', 'id');
SELECT reset_toaster('tab', 'jb');
SELECT reset_toaster('tab', 'b_uncomp');
SELECT reset_toaster('tab', 'b_comp');
SELECT get_toaster('tab', 'b_comp');
SELECT reset_toaster('tab', 'b_comp');
SELECT get_toaster('tab', 'b_comp');

SELECT set_toaster('dummy', 'tab', 'b_comp') = :dummy_toaster_oid;
SELECT get_toaster('tab', 'b_comp') = :dummy_toaster_oid;
SELECT reset_toaster('tab', 'b_comp');
SELECT get_toaster('tab', 'b_comp');
SELECT set_toaster('dummy', 'tab', 'b_comp') = :dummy_toaster_oid;

-- drop_toaster()
SELECT drop_toaster(NULL);
SELECT drop_toaster('');
SELECT drop_toaster('foo');
SELECT drop_toaster('dummy');
SELECT drop_toaster('dummy');
SELECT reset_toaster('tab', 'b_comp');
SELECT drop_toaster('dummy') = :dummy_toaster_oid;
SELECT drop_toaster('dummy');

DROP EXTENSION toastapi;
