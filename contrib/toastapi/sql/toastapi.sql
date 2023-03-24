CREATE SCHEMA pgpro_toast;
CREATE EXTENSION toastapi with SCHEMA pgpro_toast;

CREATE FUNCTION dummy_toaster_handler(internal)
RETURNS internal
AS '$libdir/toastapi'
LANGUAGE C;

-- add_toaster()
SELECT pgpro_toast.add_toaster(NULL, NULL);
SELECT pgpro_toast.add_toaster(NULL, 'foo');
SELECT pgpro_toast.add_toaster('bar', NULL);
SELECT pgpro_toast.add_toaster('', '');
SELECT pgpro_toast.add_toaster('foo', '');
SELECT pgpro_toast.add_toaster('foo', 'bar');
SELECT pgpro_toast.add_toaster('dummy', 'foo');

SELECT pgpro_toast.add_toaster('dummy', 'dummy_toaster_handler') AS dummy_toaster_oid
\gset

SELECT :dummy_toaster_oid <> 0;
SELECT pgpro_toast.add_toaster('dummy', 'foo');
SELECT :dummy_toaster_oid = pgpro_toast.add_toaster('dummy', 'dummy_toaster_handler');

SELECT pgpro_toast.add_toaster('foo', 'dummy_toaster_handler') AS foo_toaster_oid
\gset

SELECT :foo_toaster_oid <> 0;
SELECT :foo_toaster_oid <> :dummy_toaster_oid;
SELECT :foo_toaster_oid = pgpro_toast.add_toaster('foo', 'dummy_toaster_handler');

-- drop_toaster()
SELECT pgpro_toast.drop_toaster(NULL);
SELECT pgpro_toast.drop_toaster('');
SELECT pgpro_toast.drop_toaster('bar');
SELECT pgpro_toast.drop_toaster('foo') = :foo_toaster_oid;
SELECT pgpro_toast.drop_toaster('foo');


CREATE TABLE tab (id int, jb jsonb, b_comp bytea, b_uncomp bytea STORAGE external);

-- set_toaster()
SELECT pgpro_toast.set_toaster('', '', '');
SELECT pgpro_toast.set_toaster('foo', 'bar', 'baz');
SELECT pgpro_toast.set_toaster('foo', 'tab', 'baz');
SELECT pgpro_toast.set_toaster('dummy', 'tab', 'bar');
SELECT pgpro_toast.set_toaster('dummy', 'tab', 'id');
SELECT pgpro_toast.set_toaster('dummy', 'tab', 'jb');
SELECT pgpro_toast.set_toaster('dummy', 'tab', 'b_uncomp');
SELECT pgpro_toast.set_toaster('dummy', 'tab', 'b_comp') = :dummy_toaster_oid;

-- get_toaster()
SELECT pgpro_toast.get_toaster('', '');
SELECT pgpro_toast.get_toaster('foo', 'bar');
SELECT pgpro_toast.get_toaster('tab', 'bar');
SELECT pgpro_toast.get_toaster('tab', 'id');
SELECT pgpro_toast.get_toaster('tab', 'jb');
SELECT pgpro_toast.get_toaster('tab', 'b_uncomp');
SELECT pgpro_toast.get_toaster('tab', 'b_comp') = :dummy_toaster_oid;

-- reset_toaster()
SELECT pgpro_toast.reset_toaster('', '');
SELECT pgpro_toast.reset_toaster('foo', 'bar');
SELECT pgpro_toast.reset_toaster('tab', 'bar');
SELECT pgpro_toast.reset_toaster('tab', 'id');
SELECT pgpro_toast.reset_toaster('tab', 'jb');
SELECT pgpro_toast.reset_toaster('tab', 'b_uncomp');
SELECT pgpro_toast.reset_toaster('tab', 'b_comp');
SELECT pgpro_toast.get_toaster('tab', 'b_comp');
SELECT pgpro_toast.reset_toaster('tab', 'b_comp');
SELECT pgpro_toast.get_toaster('tab', 'b_comp');

SELECT pgpro_toast.set_toaster('dummy', 'tab', 'b_comp') = :dummy_toaster_oid;
SELECT pgpro_toast.get_toaster('tab', 'b_comp') = :dummy_toaster_oid;
SELECT pgpro_toast.reset_toaster('tab', 'b_comp');
SELECT pgpro_toast.get_toaster('tab', 'b_comp');
SELECT pgpro_toast.set_toaster('dummy', 'tab', 'b_comp') = :dummy_toaster_oid;

-- drop_toaster()
SELECT pgpro_toast.drop_toaster(NULL);
SELECT pgpro_toast.drop_toaster('');
SELECT pgpro_toast.drop_toaster('foo');
SELECT pgpro_toast.drop_toaster('dummy');
SELECT pgpro_toast.drop_toaster('dummy');
SELECT pgpro_toast.reset_toaster('tab', 'b_comp');
SELECT pgpro_toast.drop_toaster('dummy') = :dummy_toaster_oid;
SELECT pgpro_toast.drop_toaster('dummy');

DROP EXTENSION toastapi;
