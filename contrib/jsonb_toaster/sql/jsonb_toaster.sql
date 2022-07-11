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


create table test_jsonxa_arr (id int, js jsonb toaster jsonb_toaster);

insert into test_jsonxa_arr
select i, (select jsonb_agg(j) from generate_series(1, (2 ^ i)::int) j)
from generate_series(7, 20) i;

select id, pg_column_size(js) from test_jsonxa_arr order by id;
select id, (select count(*) from jsonb_array_elements(js)) from test_jsonxa_arr order by id;

select id, js -> 100 from test_jsonxa_arr order by id;
select id, js -> 200 from test_jsonxa_arr order by id;
select id, js -> (jsonb_array_length(js) - 1) from test_jsonxa_arr order by id;

select id, json_query(js, '$[0 to 10]' with wrapper) from test_jsonxa_arr order by id;

update test_jsonxa_arr set js = jsonb_set(js, '{0}', '0');

select id, (select count(*) from jsonb_array_elements(js)) from test_jsonxa_arr order by id;
select id, js -> 0 from test_jsonxa_arr order by id;
select id, js -> 100 from test_jsonxa_arr order by id;

update test_jsonxa_arr set js = json_modify(js, set '$[LAST+1]' = '0') where id = 10;
select pg_column_size(js) from test_jsonxa_arr where id = 10;
update test_jsonxa_arr set js = json_modify(js, set '$[LAST+1]' = '0') where id = 10;
select pg_column_size(js) from test_jsonxa_arr where id = 10;
update test_jsonxa_arr set js = json_modify(js, set '$[LAST+1]' = '0') where id = 10;
select pg_column_size(js) from test_jsonxa_arr where id = 10;
update test_jsonxa_arr set js = json_modify(js, set '$[LAST+1]' = '0') where id = 10;
select pg_column_size(js) from test_jsonxa_arr where id = 10;

update test_jsonxa_arr set js = json_modify(js, set '$[0 to 3]' = '0');
select id, json_query(js, '$[0 to 10]' with wrapper) from test_jsonxa_arr order by id;

update test_jsonxa_arr set js = json_modify(js, insert '$[200 to 203]' = '0');
select id, json_query(js, '$[200 to 210]' with wrapper) from test_jsonxa_arr order by id;

update test_jsonxa_arr set js = json_modify(js, set '$[0 to 300]' = '0');
select id, json_query(js, '$[290 to 310]' with wrapper) from test_jsonxa_arr order by id;

update test_jsonxa_arr set js = json_modify(js, set '$[100,500,1000]' = '0');
select id, json_query(js, '$[95 to 105, 495 to 505, 995 to 1005]' with wrapper) from test_jsonxa_arr order by id;

update test_jsonxa_arr set js = json_modify(js, insert '$[1000003 to 1000005]' = '0');
select id, json_query(js, '$[1000000 to 1000010]' with wrapper) from test_jsonxa_arr order by id;

truncate test_jsonxa_arr;

insert into test_jsonxa_arr
select i, (select jsonb_agg(j) from generate_series(1, (2 ^ i)::int) j)
from generate_series(7, 20) i;

update test_jsonxa_arr set js = json_modify(js, remove '$[0 to 10]');
select id, json_query(js, '$[0 to 20]' with wrapper) from test_jsonxa_arr order by id;

update test_jsonxa_arr set js = json_modify(js, remove '$[20 to 200]');
select id, json_query(js, '$[0 to 30]' with wrapper) from test_jsonxa_arr order by id;

update test_jsonxa_arr set js = json_modify(js, remove '$[30 to 100000]');
select id, json_query(js, '$[0 to 40]' with wrapper) from test_jsonxa_arr order by id;

-- test vacuum full
truncate test_jsonxa_arr;

insert into test_jsonxa_arr
select i, (select jsonb_agg(j) from generate_series(1, (2 ^ i)::int) j)
from generate_series(7, 20) i;

update test_jsonxa_arr set js = json_modify(js, set '$[1, 101, 201, 301, 401, 501, 1001, 1501, 2001, 3001, 5001]' = '0');

select format('vacuum full pg_toast.pg_toast_%s', 'test_jsonxa_arr'::regclass::oid)
\gexec

vacuum full test_jsonxa_arr;

select id, json_query(js, '$[0 to 2, 100 to 102, 200 to 202, 300 to 302, 400 to 402, 500 to 502, 1000 to 1002, 1500 to 1502, 2000 to 2002, 3000 to 3002, 5000 to 5002]' with wrapper) from test_jsonxa_arr order by id;
