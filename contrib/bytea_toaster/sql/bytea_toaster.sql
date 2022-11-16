CREATE EXTENSION bytea_toaster;

CREATE TABLE tst_failed (
	t jsonb TOASTER bytea_toaster
);

CREATE TABLE tst1 (
	t bytea TOASTER bytea_toaster
);

CREATE TABLE tst2 (
	t bytea
);

ALTER TABLE tst2 ALTER COLUMN t SET TOASTER bytea_toaster;



CREATE TABLE test_bytea_append (id int, a bytea STORAGE EXTERNAL);
ALTER TABLE test_bytea_append ALTER a SET TOASTER bytea_toaster;

INSERT INTO test_bytea_append SELECT i, repeat('a', 10000)::bytea FROM generate_series(1, 10) i;

BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ;

SAVEPOINT p1;
UPDATE test_bytea_append SET a = a || repeat('b', 3000)::bytea;
SELECT id, length(convert_from(a, 'UTF8')), convert_from(substr(a, 9990, 20) || substr(a, 12990, 20), 'UTF8') FROM test_bytea_append;

SAVEPOINT p2;
UPDATE test_bytea_append SET a = a || repeat('c', 2000)::bytea;
SELECT id, length(convert_from(a, 'UTF8')), convert_from(substr(a, 9990, 20) || substr(a, 12990, 20) ||  substr(a, 14990, 20), 'UTF8') FROM test_bytea_append;

ROLLBACK TO SAVEPOINT p2;
SELECT id, length(convert_from(a, 'UTF8')), convert_from(substr(a, 9990, 20) || substr(a, 12990, 20), 'UTF8') FROM test_bytea_append;
UPDATE test_bytea_append SET a = a || repeat('d', 4000)::bytea;
SELECT id, length(convert_from(a, 'UTF8')), convert_from(substr(a, 9990, 20) || substr(a, 12990, 20) || substr(a, 16990, 20), 'UTF8') FROM test_bytea_append;

ROLLBACK TO SAVEPOINT p1;
SELECT id, length(convert_from(a, 'UTF8')), convert_from(substr(a, 9990, 20) || substr(a, 12990, 20), 'UTF8') FROM test_bytea_append;
UPDATE test_bytea_append SET a = a || repeat('e', 5000)::bytea;
SELECT id, length(convert_from(a, 'UTF8')), convert_from(substr(a, 9990, 20) || substr(a, 14990, 20), 'UTF8') FROM test_bytea_append;

COMMIT;

SELECT id, length(convert_from(a, 'UTF8')), convert_from(substr(a, 9990, 20) || substr(a, 14990, 20), 'UTF8') FROM test_bytea_append;

UPDATE test_bytea_append SET a = NULL;

TRUNCATE test_bytea_append;
INSERT INTO test_bytea_append SELECT i, repeat('a', 10000)::bytea FROM generate_series(1, 10) i;

BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ;

UPDATE test_bytea_append SET a = a || repeat('b', 3000)::bytea;
SELECT id, convert_from(substr(a, 9990, 20) || substr(a, 12990, 20), 'UTF8') FROM test_bytea_append;

UPDATE test_bytea_append SET a = a || repeat('c', 2000)::bytea;
SELECT id, convert_from(substr(a, 9990, 20) || substr(a, 12990, 20) || substr(a, 14990, 20), 'UTF8') FROM test_bytea_append;

UPDATE test_bytea_append SET a = a || repeat('d', 4000)::bytea;
SELECT id, convert_from(substr(a, 9990, 20) || substr(a, 12990, 20) || substr(a, 14990, 20) || substr(a, 18990, 20), 'UTF8') FROM test_bytea_append;

CREATE FUNCTION test_bytea_append_func() RETURNS void AS
$$
DECLARE
  a0 bytea;
  a1 bytea;
  a2 bytea;
  a3 bytea;
BEGIN
  TRUNCATE test_bytea_append;
  INSERT INTO test_bytea_append SELECT i, repeat('a', 10000)::bytea FROM generate_series(1, 10) i;
  SELECT a INTO a0 FROM test_bytea_append LIMIT 1;

  UPDATE test_bytea_append SET a = a || repeat('b', 3000)::bytea;
  SELECT a INTO a1 FROM test_bytea_append LIMIT 1;

  UPDATE test_bytea_append SET a = a || repeat('c', 2000)::bytea;
  SELECT a INTO a2 FROM test_bytea_append LIMIT 1;

  UPDATE test_bytea_append SET a = a || repeat('d', 4000)::bytea;
  SELECT a INTO a3 FROM test_bytea_append LIMIT 1;

  RAISE NOTICE '%', convert_from(substr(a0, 9990, 20), 'UTF8');
  RAISE NOTICE '%', convert_from(substr(a1, 9990, 20) || substr(a1, 12990, 20), 'UTF8');
  RAISE NOTICE '%', convert_from(substr(a2, 9990, 20) || substr(a2, 12990, 20) || substr(a2, 14990, 20), 'UTF8');
  RAISE NOTICE '%', convert_from(substr(a3, 9990, 20) || substr(a3, 12990, 20) || substr(a3, 14990, 20) || substr(a3, 18990, 20), 'UTF8');
END;
$$ LANGUAGE plpgsql;

SELECT test_bytea_append_func();

COMMIT;

DROP TABLE test_bytea_append;
