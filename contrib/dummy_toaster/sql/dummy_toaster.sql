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
	t text
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

CREATE TABLE tst3 (
	f text STORAGE external TOASTER deftoaster,
	t text STORAGE external TOASTER dummy_toaster,
	l int
);

alter table tst3 add id serial;

INSERT INTO tst3
	SELECT repeat('a', 2000)::text as f, t.t as t, length(t.t) as l FROM
		(SELECT
			repeat(random()::text, (20+30*random())::int) as t
		 FROM
			generate_series(1, 32) as  i) as t;
SELECT length(t), l, length(t) = l FROM tst1 ORDER BY 1, 3;

SELECT attnum, attname, atttypid, attstorage, tsrname
	FROM pg_attribute, pg_toaster t
	WHERE attrelid = 'tst3'::regclass and attnum>0 and t.oid = atttoaster
	ORDER BY attnum;

update tst3 set f = repeat('b', 2000)::text;

update tst3 set t = repeat('c', 2000)::text;

ALTER TABLE tst3 ALTER COLUMN f SET TOASTER dummy_toaster;

update tst3 set f = repeat('d', 2000)::text;

ALTER TABLE tst3 ALTER COLUMN t SET TOASTER deftoaster;

update tst3 set t = repeat('e', 2000)::text;

SELECT l, left(f,20), left(t,20) FROM tst3 ORDER BY 1, 3;

SELECT attnum, attname, atttypid, attstorage, tsrname
	FROM pg_attribute, pg_toaster t
	WHERE attrelid = 'tst3'::regclass and attnum>0 and t.oid = atttoaster
	ORDER BY attnum;

