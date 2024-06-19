--
-- Copyright (c) 2017-2024, Postgres Professional
--
-- Set of basic regression tests on scanning of a temporary table in parallel
--

-- Load the library. It should be load dynamically
LOAD 'tempscan';

-- Force usage of parallel workers
SET max_parallel_workers_per_gather = 3;
SET parallel_setup_cost = 0.0001;
SET parallel_tuple_cost = 0.0001;

-- Don't need big tables
SET min_parallel_table_scan_size = 0;
SET min_parallel_index_scan_size = 0;

CREATE TABLE parallel_test (x int);
INSERT INTO parallel_test (x) SELECT x FROM generate_series(1,100) AS x;
CREATE TEMP TABLE parallel_test_tmp AS (SELECT * FROM parallel_test);
VACUUM ANALYZE parallel_test, parallel_test_tmp;

SET tempscan.enable = 'on';
EXPLAIN (COSTS OFF)
SELECT count(*) FROM parallel_test;

-- Do not use parallel scan of temporary table so far. As a result, shouldn't
-- find nodeCustomTempScan here
EXPLAIN (COSTS OFF)
SELECT count(*) FROM parallel_test_tmp;

-- Want to see here partial aggregate over parallel join
EXPLAIN (COSTS OFF)
SELECT count(*) FROM parallel_test t1 NATURAL JOIN parallel_test t2;
EXPLAIN (COSTS OFF)
SELECT count(*) FROM parallel_test_tmp t1 NATURAL JOIN parallel_test t2;

-- Just see how merge join manages custom parallel scan path
SET enable_hashjoin = 'off';
EXPLAIN (COSTS OFF)
SELECT count(*) FROM parallel_test t1 NATURAL JOIN parallel_test t2;
EXPLAIN (COSTS OFF)
SELECT count(*) FROM parallel_test_tmp t1 NATURAL JOIN parallel_test t2;

RESET enable_hashjoin;

-- Increase table size and see how indexes work
ALTER TABLE parallel_test ADD COLUMN y text DEFAULT 'none';
INSERT INTO parallel_test (x,y) SELECT x, 'data' || x AS y FROM generate_series(1,10000) AS x;
CREATE INDEX ON parallel_test_tmp (x);
VACUUM ANALYZE;
-- Use IndexScan on temporary table
EXPLAIN (COSTS OFF)
SELECT count(*) FROM parallel_test t1 NATURAL JOIN parallel_test_tmp t2
WHERE t1.x < 10;

CREATE TEMP TABLE parallel_test_tmp_2 AS (SELECT * FROM parallel_test);
CREATE INDEX ON parallel_test_tmp_2 (x);
VACUUM ANALYZE;

-- Can't use parallel workers here: for now temp tables can be used as parallel
-- safe source but not be read concurrently.
EXPLAIN (COSTS OFF)
SELECT count(*) FROM parallel_test_tmp t1 NATURAL JOIN parallel_test_tmp_2 t2
WHERE t2.x < 10;
EXPLAIN (COSTS OFF)
SELECT count(*) FROM parallel_test_tmp_2 t1 NATURAL JOIN parallel_test_tmp_2 t2
WHERE t1.x < 10;

RESET tempscan.enable;
DROP TABLE parallel_test, parallel_test_tmp;
