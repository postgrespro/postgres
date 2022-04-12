

CREATE TOASTER tsttoaster HANDLER default_toaster_handler;
CREATE TOASTER IF NOT EXISTS tsttoaster HANDLER default_toaster_handler;
CREATE TOASTER IF NOT EXISTS tsttoaster1 HANDLER default_toaster_handler;

COMMENT ON TOASTER tsttoaster IS 'tsttoaster is a clone of default toaster';


CREATE TABLE tsttsrtbl_failed (
	t text TOASTER tsttoaster TOASTER tsttoaster;
);

CREATE TABLE tsttsrtbl (
	t1 text TOASTER tsttoaster,
	t2 text,
	t3 int
);

SELECT attnum, attname, atttypid, attstorage, tsrname
    FROM pg_attribute LEFT OUTER JOIN pg_toaster t ON t.oid = atttoaster
    WHERE attrelid = 'tsttsrtbl'::regclass and attnum>0
    ORDER BY attnum;

ALTER TABLE tsttsrtbl ALTER COLUMN t2 SET TOASTER tsttoaster;

SELECT attnum, attname, atttypid, attstorage, tsrname
    FROM pg_attribute LEFT OUTER JOIN pg_toaster t ON t.oid = atttoaster
    WHERE attrelid = 'tsttsrtbl'::regclass and attnum>0
    ORDER BY attnum;

ALTER TABLE tsttsrtbl ALTER COLUMN t3  TYPE text;

SELECT attnum, attname, atttypid, attstorage, tsrname
    FROM pg_attribute LEFT OUTER JOIN pg_toaster t ON t.oid = atttoaster
    WHERE attrelid = 'tsttsrtbl'::regclass and attnum>0
    ORDER BY attnum;

ALTER TABLE tsttsrtbl ALTER COLUMN t3  TYPE int USING t3::int;

\d+ tsttsrtbl

