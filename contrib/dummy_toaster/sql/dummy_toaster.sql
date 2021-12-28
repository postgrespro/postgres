CREATE EXTENSION dummy_toaster;

CREATE TABLE tst_failed (
	t text TOASTER dummy_toaster TOASTER dummy_toaster
);

CREATE TABLE tst1 (
	f text STORAGE plain,
	t text STORAGE external TOASTER dummy_toaster,
	l int
);

SELECT  setseed(0);

INSERT INTO tst1
	SELECT repeat('a', 2000)::text as f, t.t as t, length(t.t) as l FROM
		(SELECT
			repeat(random()::text, (20+30*random())::int) as t
		 FROM
			generate_series(1, 32) as  i) as t;

SELECT length(t), l, length(t) = l FROM tst1 ORDER BY 1, 3;

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
