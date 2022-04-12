CREATE EXTENSION dummy_toaster;

CREATE TABLE tst_failed (
	t text TOASTER dummy_toaster TOASTER dummy_toaster
);

CREATE TABLE tst1 (
	t text TOASTER dummy_toaster
);

SELECT attnum, attname, atttypid, attstorage, tsrname
	FROM pg_attribute, pg_toaster t
	WHERE attrelid = 'tst1'::regclass and attnum>0 and t.oid = atttoaster
	ORDER BY attnum;

CREATE TABLE tst2 (
	t	text
);

SELECT attnum, attname, atttypid, attstorage, tsrname
	FROM pg_attribute, pg_toaster t
	WHERE attrelid = 'tst2'::regclass and attnum>0 and t.oid = atttoaster
	ORDER BY attnum;

ALTER TABLE tst2 ALTER COLUMN t SET TOASTER dummy_toaster;

SELECT attnum, attname, atttypid, attstorage, tsrname
	FROM pg_attribute, pg_toaster t
	WHERE attrelid = 'tst2'::regclass and attnum>0 and t.oid = atttoaster
	ORDER BY attnum;

\d+ tst1
\d+ tst2
