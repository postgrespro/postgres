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

-- Should also utilise parallel workers like scanning of a plain table
EXPLAIN (COSTS OFF)
SELECT count(*) FROM parallel_test_tmp;

RESET tempscan.enable;
DROP TABLE parallel_test, parallel_test_tmp;
