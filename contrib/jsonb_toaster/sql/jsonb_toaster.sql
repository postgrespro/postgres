CREATE EXTENSION jsonb_toaster;

CREATE TABLE tst_failed (
	t json TOASTER jsonb_toaster
);

CREATE TABLE tst1 (
	t jsonb TOASTER jsonb_toaster
);

CREATE TABLE tst2 (
	t jsonb
);

ALTER TABLE tst2 ALTER COLUMN t SET TOASTER jsonb_toaster;


CREATE TABLE test_jsonb_toaster (id int, jb jsonb);
ALTER TABLE test_jsonb_toaster ALTER jb SET TOASTER jsonb_toaster;

INSERT INTO test_jsonb_toaster
SELECT i, (
	SELECT jsonb_object_agg('key' || j, jsonb_build_array(repeat('a', pow(2, i + j)::int)))
	FROM generate_series(1,10) j
)
FROM generate_series(1, 10) i;


DROP TABLE test_jsonb_toaster;
