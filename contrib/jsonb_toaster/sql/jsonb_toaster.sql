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

SELECT id, key, pg_column_size(value::text) FROM test_jsonb_toaster, jsonb_each(jb);

DROP TABLE test_jsonb_toaster;


create table test_jsonbz_arr (id int, js jsonb toaster jsonb_toaster);

insert into test_jsonbz_arr
select
  j id,
  jsonb_build_object(
     'a', jsonb_agg(repeat('a', pow(2, 6 + i)::int)),
     'b', 'foo',
     'c', jsonb_agg(jsonb_build_object('a', repeat('a', pow(2, 6 + i)::int), 'b', 1))
  ) js
from
  generate_series(0, 19) j,
  generate_series(0, j) i
group by j
order by j;

update test_jsonbz_arr set js = jsonb_set(js, '{a,0}', to_jsonb(repeat('b', 64)));
select id, js->'a'->>0 from test_jsonbz_arr order by id;

update test_jsonbz_arr set js = jsonb_set(js, '{a,0}', to_jsonb(repeat('c', 64)));
select id, js->'a'->>0 from test_jsonbz_arr order by id;

update test_jsonbz_arr set js = jsonb_set(js, '{a,0}', to_jsonb(repeat('d', 65)));
select id, js->'a'->>0 from test_jsonbz_arr order by id;

update test_jsonbz_arr set js = jsonb_set(js, '{a,0}', to_jsonb(repeat('e', 65)));
select id, js->'a'->>0 from test_jsonbz_arr order by id;


update test_jsonbz_arr set js = jsonb_set(js, '{c,0,a}', to_jsonb(repeat('b', 64)));
select id, js->'c'->0->>'a' from test_jsonbz_arr order by id;

update test_jsonbz_arr set js = jsonb_set(js, '{c,0,a}', to_jsonb(repeat('c', 64)));
select id, js->'c'->0->>'a' from test_jsonbz_arr order by id;

update test_jsonbz_arr set js = jsonb_set(js, '{c,0,a}', to_jsonb(repeat('d', 65)));
select id, js->'c'->0->>'a' from test_jsonbz_arr order by id;

update test_jsonbz_arr set js = jsonb_set(js, '{c,0,a}', to_jsonb(repeat('e', 65)));
select id, js->'c'->0->>'a' from test_jsonbz_arr order by id;
