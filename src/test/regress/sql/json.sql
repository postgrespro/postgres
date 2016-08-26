-- Strings.
SELECT '""'::json;				-- OK.
SELECT $$''$$::json;			-- ERROR, single quotes are not allowed
SELECT '"abc"'::json;			-- OK
SELECT '"abc'::json;			-- ERROR, quotes not closed
SELECT '"abc
def"'::json;					-- ERROR, unescaped newline in string constant
SELECT '"\n\"\\"'::json;		-- OK, legal escapes
SELECT '"\v"'::json;			-- ERROR, not a valid JSON escape
-- see json_encoding test for input with unicode escapes

-- Numbers.
SELECT '1'::json;				-- OK
SELECT '0'::json;				-- OK
SELECT '01'::json;				-- ERROR, not valid according to JSON spec
SELECT '0.1'::json;				-- OK
SELECT '9223372036854775808'::json;	-- OK, even though it's too large for int8
SELECT '1e100'::json;			-- OK
SELECT '1.3e100'::json;			-- OK
SELECT '1f2'::json;				-- ERROR
SELECT '0.x1'::json;			-- ERROR
SELECT '1.3ex100'::json;		-- ERROR

-- Arrays.
SELECT '[]'::json;				-- OK
SELECT '[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]'::json;  -- OK
SELECT '[1,2]'::json;			-- OK
SELECT '[1,2,]'::json;			-- ERROR, trailing comma
SELECT '[1,2'::json;			-- ERROR, no closing bracket
SELECT '[1,[2]'::json;			-- ERROR, no closing bracket

-- Objects.
SELECT '{}'::json;				-- OK
SELECT '{"abc"}'::json;			-- ERROR, no value
SELECT '{"abc":1}'::json;		-- OK
SELECT '{1:"abc"}'::json;		-- ERROR, keys must be strings
SELECT '{"abc",1}'::json;		-- ERROR, wrong separator
SELECT '{"abc"=1}'::json;		-- ERROR, totally wrong separator
SELECT '{"abc"::1}'::json;		-- ERROR, another wrong separator
SELECT '{"abc":1,"def":2,"ghi":[3,4],"hij":{"klm":5,"nop":[6]}}'::json; -- OK
SELECT '{"abc":1:2}'::json;		-- ERROR, colon in wrong spot
SELECT '{"abc":1,3}'::json;		-- ERROR, no value

-- Recursion.
SET max_stack_depth = '100kB';
SELECT repeat('[', 10000)::json;
SELECT repeat('{"a":', 10000)::json;
RESET max_stack_depth;

-- Miscellaneous stuff.
SELECT 'true'::json;			-- OK
SELECT 'false'::json;			-- OK
SELECT 'null'::json;			-- OK
SELECT ' true '::json;			-- OK, even with extra whitespace
SELECT 'true false'::json;		-- ERROR, too many values
SELECT 'true, false'::json;		-- ERROR, too many values
SELECT 'truf'::json;			-- ERROR, not a keyword
SELECT 'trues'::json;			-- ERROR, not a keyword
SELECT ''::json;				-- ERROR, no value
SELECT '    '::json;			-- ERROR, no value

-- Multi-line JSON input to check ERROR reporting
SELECT '{
		"one": 1,
		"two":"two",
		"three":
		true}'::json; -- OK
SELECT '{
		"one": 1,
		"two":,"two",  -- ERROR extraneous comma before field "two"
		"three":
		true}'::json;
SELECT '{
		"one": 1,
		"two":"two",
		"averyveryveryveryveryveryveryveryveryverylongfieldname":}'::json;
-- ERROR missing value for last field

--constructors
-- array_to_json

SELECT array_to_json(array(select 1 as a));
SELECT array_to_json(array_agg(q),false) from (select x as b, x * 2 as c from generate_series(1,3) x) q;
SELECT array_to_json(array_agg(q),true) from (select x as b, x * 2 as c from generate_series(1,3) x) q;
SELECT array_to_json(array_agg(q),false)
  FROM ( SELECT $$a$$ || x AS b, y AS c,
               ARRAY[ROW(x.*,ARRAY[1,2,3]),
               ROW(y.*,ARRAY[4,5,6])] AS z
         FROM generate_series(1,2) x,
              generate_series(4,5) y) q;
SELECT array_to_json(array_agg(x),false) from generate_series(5,10) x;
SELECT array_to_json('{{1,5},{99,100}}'::int[]);

-- row_to_json
SELECT row_to_json(row(1,'foo'));

SELECT row_to_json(q)
FROM (SELECT $$a$$ || x AS b,
         y AS c,
         ARRAY[ROW(x.*,ARRAY[1,2,3]),
               ROW(y.*,ARRAY[4,5,6])] AS z
      FROM generate_series(1,2) x,
           generate_series(4,5) y) q;

SELECT row_to_json(q,true)
FROM (SELECT $$a$$ || x AS b,
         y AS c,
         ARRAY[ROW(x.*,ARRAY[1,2,3]),
               ROW(y.*,ARRAY[4,5,6])] AS z
      FROM generate_series(1,2) x,
           generate_series(4,5) y) q;

CREATE TEMP TABLE rows AS
SELECT x, 'txt' || x as y
FROM generate_series(1,3) AS x;

SELECT row_to_json(q,true)
FROM rows q;

SELECT row_to_json(row((select array_agg(x) as d from generate_series(5,10) x)),false);

-- anyarray column

analyze rows;

select attname, to_json(histogram_bounds) histogram_bounds
from pg_stats
where tablename = 'rows' and
      schemaname = pg_my_temp_schema()::regnamespace::text
order by 1;

-- to_json, timestamps

select to_json(timestamp '2014-05-28 12:22:35.614298');

BEGIN;
SET LOCAL TIME ZONE 10.5;
select to_json(timestamptz '2014-05-28 12:22:35.614298-04');
SET LOCAL TIME ZONE -8;
select to_json(timestamptz '2014-05-28 12:22:35.614298-04');
COMMIT;

select to_json(date '2014-05-28');

select to_json(date 'Infinity');
select to_json(date '-Infinity');
select to_json(timestamp 'Infinity');
select to_json(timestamp '-Infinity');
select to_json(timestamptz 'Infinity');
select to_json(timestamptz '-Infinity');

--json_agg

SELECT json_agg(q)
  FROM ( SELECT $$a$$ || x AS b, y AS c,
               ARRAY[ROW(x.*,ARRAY[1,2,3]),
               ROW(y.*,ARRAY[4,5,6])] AS z
         FROM generate_series(1,2) x,
              generate_series(4,5) y) q;

SELECT json_agg(q ORDER BY x, y)
  FROM rows q;

UPDATE rows SET x = NULL WHERE x = 1;

SELECT json_agg(q ORDER BY x NULLS FIRST, y)
  FROM rows q;

-- non-numeric output
SELECT row_to_json(q)
FROM (SELECT 'NaN'::float8 AS "float8field") q;

SELECT row_to_json(q)
FROM (SELECT 'Infinity'::float8 AS "float8field") q;

SELECT row_to_json(q)
FROM (SELECT '-Infinity'::float8 AS "float8field") q;

-- json input
SELECT row_to_json(q)
FROM (SELECT '{"a":1,"b": [2,3,4,"d","e","f"],"c":{"p":1,"q":2}}'::json AS "jsonfield") q;


-- json extraction functions

CREATE TEMP TABLE test_json (
       json_type text,
       test_json json
);

INSERT INTO test_json VALUES
('scalar','"a scalar"'),
('array','["zero", "one","two",null,"four","five", [1,2,3],{"f1":9}]'),
('object','{"field1":"val1","field2":"val2","field3":null, "field4": 4, "field5": [1,2,3], "field6": {"f1":9}}');

SELECT test_json -> 'x'
FROM test_json
WHERE json_type = 'scalar';

SELECT test_json -> 'x'
FROM test_json
WHERE json_type = 'array';

SELECT test_json -> 'x'
FROM test_json
WHERE json_type = 'object';

SELECT test_json->'field2'
FROM test_json
WHERE json_type = 'object';

SELECT test_json->>'field2'
FROM test_json
WHERE json_type = 'object';

SELECT test_json -> 2
FROM test_json
WHERE json_type = 'scalar';

SELECT test_json -> 2
FROM test_json
WHERE json_type = 'array';

SELECT test_json -> -1
FROM test_json
WHERE json_type = 'array';

SELECT test_json -> 2
FROM test_json
WHERE json_type = 'object';

SELECT test_json->>2
FROM test_json
WHERE json_type = 'array';

SELECT test_json ->> 6 FROM test_json WHERE json_type = 'array';
SELECT test_json ->> 7 FROM test_json WHERE json_type = 'array';

SELECT test_json ->> 'field4' FROM test_json WHERE json_type = 'object';
SELECT test_json ->> 'field5' FROM test_json WHERE json_type = 'object';
SELECT test_json ->> 'field6' FROM test_json WHERE json_type = 'object';

SELECT json_object_keys(test_json)
FROM test_json
WHERE json_type = 'scalar';

SELECT json_object_keys(test_json)
FROM test_json
WHERE json_type = 'array';

SELECT json_object_keys(test_json)
FROM test_json
WHERE json_type = 'object';

-- test extending object_keys resultset - initial resultset size is 256

select count(*) from
    (select json_object_keys(json_object(array_agg(g)))
     from (select unnest(array['f'||n,n::text])as g
           from generate_series(1,300) as n) x ) y;

-- nulls

select (test_json->'field3') is null as expect_false
from test_json
where json_type = 'object';

select (test_json->>'field3') is null as expect_true
from test_json
where json_type = 'object';

select (test_json->3) is null as expect_false
from test_json
where json_type = 'array';

select (test_json->>3) is null as expect_true
from test_json
where json_type = 'array';

-- corner cases

select '{"a": [{"b": "c"}, {"b": "cc"}]}'::json -> null::text;
select '{"a": [{"b": "c"}, {"b": "cc"}]}'::json -> null::int;
select '{"a": [{"b": "c"}, {"b": "cc"}]}'::json -> 1;
select '{"a": [{"b": "c"}, {"b": "cc"}]}'::json -> -1;
select '{"a": [{"b": "c"}, {"b": "cc"}]}'::json -> 'z';
select '{"a": [{"b": "c"}, {"b": "cc"}]}'::json -> '';
select '[{"b": "c"}, {"b": "cc"}]'::json -> 1;
select '[{"b": "c"}, {"b": "cc"}]'::json -> 3;
select '[{"b": "c"}, {"b": "cc"}]'::json -> 'z';
select '{"a": "c", "b": null}'::json -> 'b';
select '"foo"'::json -> 1;
select '"foo"'::json -> 'z';

select '{"a": [{"b": "c"}, {"b": "cc"}]}'::json ->> null::text;
select '{"a": [{"b": "c"}, {"b": "cc"}]}'::json ->> null::int;
select '{"a": [{"b": "c"}, {"b": "cc"}]}'::json ->> 1;
select '{"a": [{"b": "c"}, {"b": "cc"}]}'::json ->> 'z';
select '{"a": [{"b": "c"}, {"b": "cc"}]}'::json ->> '';
select '[{"b": "c"}, {"b": "cc"}]'::json ->> 1;
select '[{"b": "c"}, {"b": "cc"}]'::json ->> 3;
select '[{"b": "c"}, {"b": "cc"}]'::json ->> 'z';
select '{"a": "c", "b": null}'::json ->> 'b';
select '"foo"'::json ->> 1;
select '"foo"'::json ->> 'z';

-- array length

SELECT json_array_length('[1,2,3,{"f1":1,"f2":[5,6]},4]');

SELECT json_array_length('[]');

SELECT json_array_length('{"f1":1,"f2":[5,6]}');

SELECT json_array_length('4');

-- each

select json_each('{"f1":[1,2,3],"f2":{"f3":1},"f4":null}');
select * from json_each('{"f1":[1,2,3],"f2":{"f3":1},"f4":null,"f5":99,"f6":"stringy"}') q;

select json_each_text('{"f1":[1,2,3],"f2":{"f3":1},"f4":null,"f5":"null"}');
select * from json_each_text('{"f1":[1,2,3],"f2":{"f3":1},"f4":null,"f5":99,"f6":"stringy"}') q;

-- extract_path, extract_path_as_text

select json_extract_path('{"f2":{"f3":1},"f4":{"f5":99,"f6":"stringy"}}','f4','f6');
select json_extract_path('{"f2":{"f3":1},"f4":{"f5":99,"f6":"stringy"}}','f2');
select json_extract_path('{"f2":["f3",1],"f4":{"f5":99,"f6":"stringy"}}','f2',0::text);
select json_extract_path('{"f2":["f3",1],"f4":{"f5":99,"f6":"stringy"}}','f2',1::text);
select json_extract_path_text('{"f2":{"f3":1},"f4":{"f5":99,"f6":"stringy"}}','f4','f6');
select json_extract_path_text('{"f2":{"f3":1},"f4":{"f5":99,"f6":"stringy"}}','f2');
select json_extract_path_text('{"f2":["f3",1],"f4":{"f5":99,"f6":"stringy"}}','f2',0::text);
select json_extract_path_text('{"f2":["f3",1],"f4":{"f5":99,"f6":"stringy"}}','f2',1::text);

-- extract_path nulls

select json_extract_path('{"f2":{"f3":1},"f4":{"f5":null,"f6":"stringy"}}','f4','f5') is null as expect_false;
select json_extract_path_text('{"f2":{"f3":1},"f4":{"f5":null,"f6":"stringy"}}','f4','f5') is null as expect_true;
select json_extract_path('{"f2":{"f3":1},"f4":[0,1,2,null]}','f4','3') is null as expect_false;
select json_extract_path_text('{"f2":{"f3":1},"f4":[0,1,2,null]}','f4','3') is null as expect_true;

-- extract_path operators

select '{"f2":{"f3":1},"f4":{"f5":99,"f6":"stringy"}}'::json#>array['f4','f6'];
select '{"f2":{"f3":1},"f4":{"f5":99,"f6":"stringy"}}'::json#>array['f2'];
select '{"f2":["f3",1],"f4":{"f5":99,"f6":"stringy"}}'::json#>array['f2','0'];
select '{"f2":["f3",1],"f4":{"f5":99,"f6":"stringy"}}'::json#>array['f2','1'];

select '{"f2":{"f3":1},"f4":{"f5":99,"f6":"stringy"}}'::json#>>array['f4','f6'];
select '{"f2":{"f3":1},"f4":{"f5":99,"f6":"stringy"}}'::json#>>array['f2'];
select '{"f2":["f3",1],"f4":{"f5":99,"f6":"stringy"}}'::json#>>array['f2','0'];
select '{"f2":["f3",1],"f4":{"f5":99,"f6":"stringy"}}'::json#>>array['f2','1'];

-- corner cases for same
select '{"a": {"b":{"c": "foo"}}}'::json #> '{}';
select '[1,2,3]'::json #> '{}';
select '"foo"'::json #> '{}';
select '42'::json #> '{}';
select 'null'::json #> '{}';
select '{"a": {"b":{"c": "foo"}}}'::json #> array['a'];
select '{"a": {"b":{"c": "foo"}}}'::json #> array['a', null];
select '{"a": {"b":{"c": "foo"}}}'::json #> array['a', ''];
select '{"a": {"b":{"c": "foo"}}}'::json #> array['a','b'];
select '{"a": {"b":{"c": "foo"}}}'::json #> array['a','b','c'];
select '{"a": {"b":{"c": "foo"}}}'::json #> array['a','b','c','d'];
select '{"a": {"b":{"c": "foo"}}}'::json #> array['a','z','c'];
select '{"a": [{"b": "c"}, {"b": "cc"}]}'::json #> array['a','1','b'];
select '{"a": [{"b": "c"}, {"b": "cc"}]}'::json #> array['a','z','b'];
select '[{"b": "c"}, {"b": "cc"}]'::json #> array['1','b'];
select '[{"b": "c"}, {"b": "cc"}]'::json #> array['z','b'];
select '[{"b": "c"}, {"b": null}]'::json #> array['1','b'];
select '"foo"'::json #> array['z'];
select '42'::json #> array['f2'];
select '42'::json #> array['0'];

select '{"a": {"b":{"c": "foo"}}}'::json #>> '{}';
select '[1,2,3]'::json #>> '{}';
select '"foo"'::json #>> '{}';
select '42'::json #>> '{}';
select 'null'::json #>> '{}';
select '{"a": {"b":{"c": "foo"}}}'::json #>> array['a'];
select '{"a": {"b":{"c": "foo"}}}'::json #>> array['a', null];
select '{"a": {"b":{"c": "foo"}}}'::json #>> array['a', ''];
select '{"a": {"b":{"c": "foo"}}}'::json #>> array['a','b'];
select '{"a": {"b":{"c": "foo"}}}'::json #>> array['a','b','c'];
select '{"a": {"b":{"c": "foo"}}}'::json #>> array['a','b','c','d'];
select '{"a": {"b":{"c": "foo"}}}'::json #>> array['a','z','c'];
select '{"a": [{"b": "c"}, {"b": "cc"}]}'::json #>> array['a','1','b'];
select '{"a": [{"b": "c"}, {"b": "cc"}]}'::json #>> array['a','z','b'];
select '[{"b": "c"}, {"b": "cc"}]'::json #>> array['1','b'];
select '[{"b": "c"}, {"b": "cc"}]'::json #>> array['z','b'];
select '[{"b": "c"}, {"b": null}]'::json #>> array['1','b'];
select '"foo"'::json #>> array['z'];
select '42'::json #>> array['f2'];
select '42'::json #>> array['0'];

-- array_elements

select json_array_elements('[1,true,[1,[2,3]],null,{"f1":1,"f2":[7,8,9]},false,"stringy"]');
select * from json_array_elements('[1,true,[1,[2,3]],null,{"f1":1,"f2":[7,8,9]},false,"stringy"]') q;
select json_array_elements_text('[1,true,[1,[2,3]],null,{"f1":1,"f2":[7,8,9]},false,"stringy"]');
select * from json_array_elements_text('[1,true,[1,[2,3]],null,{"f1":1,"f2":[7,8,9]},false,"stringy"]') q;

-- populate_record
create type jpop as (a text, b int, c timestamp);

CREATE DOMAIN js_int_not_null  AS int     NOT NULL;
CREATE DOMAIN js_int_array_1d  AS int[]   CHECK(array_length(VALUE, 1) = 3);
CREATE DOMAIN js_int_array_2d  AS int[][] CHECK(array_length(VALUE, 2) = 3);

create type j_unordered_pair as (x int, y int);
create domain j_ordered_pair as j_unordered_pair check((value).x <= (value).y);

CREATE TYPE jsrec AS (
	i	int,
	ia	_int4,
	ia1	int[],
	ia2	int[][],
	ia3	int[][][],
	ia1d	js_int_array_1d,
	ia2d	js_int_array_2d,
	t	text,
	ta	text[],
	c	char(10),
	ca	char(10)[],
	ts	timestamp,
	js	json,
	jsb	jsonb,
	jsa	json[],
	rec	jpop,
	reca	jpop[]
);

CREATE TYPE jsrec_i_not_null AS (
	i	js_int_not_null
);

select * from json_populate_record(null::jpop,'{"a":"blurfl","x":43.2}') q;
select * from json_populate_record(row('x',3,'2012-12-31 15:30:56')::jpop,'{"a":"blurfl","x":43.2}') q;

select * from json_populate_record(null::jpop,'{"a":"blurfl","x":43.2}') q;
select * from json_populate_record(row('x',3,'2012-12-31 15:30:56')::jpop,'{"a":"blurfl","x":43.2}') q;

select * from json_populate_record(null::jpop,'{"a":[100,200,false],"x":43.2}') q;
select * from json_populate_record(row('x',3,'2012-12-31 15:30:56')::jpop,'{"a":[100,200,false],"x":43.2}') q;
select * from json_populate_record(row('x',3,'2012-12-31 15:30:56')::jpop,'{"c":[100,200,false],"x":43.2}') q;

select * from json_populate_record(row('x',3,'2012-12-31 15:30:56')::jpop,'{}') q;

SELECT i FROM json_populate_record(NULL::jsrec_i_not_null, '{"x": 43.2}') q;
SELECT i FROM json_populate_record(NULL::jsrec_i_not_null, '{"i": null}') q;
SELECT i FROM json_populate_record(NULL::jsrec_i_not_null, '{"i": 12345}') q;

SELECT ia FROM json_populate_record(NULL::jsrec, '{"ia": null}') q;
SELECT ia FROM json_populate_record(NULL::jsrec, '{"ia": 123}') q;
SELECT ia FROM json_populate_record(NULL::jsrec, '{"ia": [1, "2", null, 4]}') q;
SELECT ia FROM json_populate_record(NULL::jsrec, '{"ia": [[1, 2], [3, 4]]}') q;
SELECT ia FROM json_populate_record(NULL::jsrec, '{"ia": [[1], 2]}') q;
SELECT ia FROM json_populate_record(NULL::jsrec, '{"ia": [[1], [2, 3]]}') q;
SELECT ia FROM json_populate_record(NULL::jsrec, '{"ia": "{1,2,3}"}') q;

SELECT ia1 FROM json_populate_record(NULL::jsrec, '{"ia1": null}') q;
SELECT ia1 FROM json_populate_record(NULL::jsrec, '{"ia1": 123}') q;
SELECT ia1 FROM json_populate_record(NULL::jsrec, '{"ia1": [1, "2", null, 4]}') q;
SELECT ia1 FROM json_populate_record(NULL::jsrec, '{"ia1": [[1, 2, 3]]}') q;

SELECT ia1d FROM json_populate_record(NULL::jsrec, '{"ia1d": null}') q;
SELECT ia1d FROM json_populate_record(NULL::jsrec, '{"ia1d": 123}') q;
SELECT ia1d FROM json_populate_record(NULL::jsrec, '{"ia1d": [1, "2", null, 4]}') q;
SELECT ia1d FROM json_populate_record(NULL::jsrec, '{"ia1d": [1, "2", null]}') q;

SELECT ia2 FROM json_populate_record(NULL::jsrec, '{"ia2": [1, "2", null, 4]}') q;
SELECT ia2 FROM json_populate_record(NULL::jsrec, '{"ia2": [[1, 2], [null, 4]]}') q;
SELECT ia2 FROM json_populate_record(NULL::jsrec, '{"ia2": [[], []]}') q;
SELECT ia2 FROM json_populate_record(NULL::jsrec, '{"ia2": [[1, 2], [3]]}') q;
SELECT ia2 FROM json_populate_record(NULL::jsrec, '{"ia2": [[1, 2], 3, 4]}') q;

SELECT ia2d FROM json_populate_record(NULL::jsrec, '{"ia2d": [[1, "2"], [null, 4]]}') q;
SELECT ia2d FROM json_populate_record(NULL::jsrec, '{"ia2d": [[1, "2", 3], [null, 5, 6]]}') q;

SELECT ia3 FROM json_populate_record(NULL::jsrec, '{"ia3": [1, "2", null, 4]}') q;
SELECT ia3 FROM json_populate_record(NULL::jsrec, '{"ia3": [[1, 2], [null, 4]]}') q;
SELECT ia3 FROM json_populate_record(NULL::jsrec, '{"ia3": [ [[], []], [[], []], [[], []] ]}') q;
SELECT ia3 FROM json_populate_record(NULL::jsrec, '{"ia3": [ [[1, 2]], [[3, 4]] ]}') q;
SELECT ia3 FROM json_populate_record(NULL::jsrec, '{"ia3": [ [[1, 2], [3, 4]], [[5, 6], [7, 8]] ]}') q;
SELECT ia3 FROM json_populate_record(NULL::jsrec, '{"ia3": [ [[1, 2], [3, 4]], [[5, 6], [7, 8], [9, 10]] ]}') q;

SELECT ta FROM json_populate_record(NULL::jsrec, '{"ta": null}') q;
SELECT ta FROM json_populate_record(NULL::jsrec, '{"ta": 123}') q;
SELECT ta FROM json_populate_record(NULL::jsrec, '{"ta": [1, "2", null, 4]}') q;
SELECT ta FROM json_populate_record(NULL::jsrec, '{"ta": [[1, 2, 3], {"k": "v"}]}') q;

SELECT c FROM json_populate_record(NULL::jsrec, '{"c": null}') q;
SELECT c FROM json_populate_record(NULL::jsrec, '{"c": "aaa"}') q;
SELECT c FROM json_populate_record(NULL::jsrec, '{"c": "aaaaaaaaaa"}') q;
SELECT c FROM json_populate_record(NULL::jsrec, '{"c": "aaaaaaaaaaaaa"}') q;

SELECT ca FROM json_populate_record(NULL::jsrec, '{"ca": null}') q;
SELECT ca FROM json_populate_record(NULL::jsrec, '{"ca": 123}') q;
SELECT ca FROM json_populate_record(NULL::jsrec, '{"ca": [1, "2", null, 4]}') q;
SELECT ca FROM json_populate_record(NULL::jsrec, '{"ca": ["aaaaaaaaaaaaaaaa"]}') q;
SELECT ca FROM json_populate_record(NULL::jsrec, '{"ca": [[1, 2, 3], {"k": "v"}]}') q;

SELECT js FROM json_populate_record(NULL::jsrec, '{"js": null}') q;
SELECT js FROM json_populate_record(NULL::jsrec, '{"js": true}') q;
SELECT js FROM json_populate_record(NULL::jsrec, '{"js": 123.45}') q;
SELECT js FROM json_populate_record(NULL::jsrec, '{"js": "123.45"}') q;
SELECT js FROM json_populate_record(NULL::jsrec, '{"js": "abc"}') q;
SELECT js FROM json_populate_record(NULL::jsrec, '{"js": [123, "123", null, {"key": "value"}]}') q;
SELECT js FROM json_populate_record(NULL::jsrec, '{"js": {"a": "bbb", "b": null, "c": 123.45}}') q;

SELECT jsb FROM json_populate_record(NULL::jsrec, '{"jsb": null}') q;
SELECT jsb FROM json_populate_record(NULL::jsrec, '{"jsb": true}') q;
SELECT jsb FROM json_populate_record(NULL::jsrec, '{"jsb": 123.45}') q;
SELECT jsb FROM json_populate_record(NULL::jsrec, '{"jsb": "123.45"}') q;
SELECT jsb FROM json_populate_record(NULL::jsrec, '{"jsb": "abc"}') q;
SELECT jsb FROM json_populate_record(NULL::jsrec, '{"jsb": [123, "123", null, {"key": "value"}]}') q;
SELECT jsb FROM json_populate_record(NULL::jsrec, '{"jsb": {"a": "bbb", "b": null, "c": 123.45}}') q;

SELECT jsa FROM json_populate_record(NULL::jsrec, '{"jsa": null}') q;
SELECT jsa FROM json_populate_record(NULL::jsrec, '{"jsa": 123}') q;
SELECT jsa FROM json_populate_record(NULL::jsrec, '{"jsa": [1, "2", null, 4]}') q;
SELECT jsa FROM json_populate_record(NULL::jsrec, '{"jsa": ["aaa", null, [1, 2, "3", {}], { "k" : "v" }]}') q;

SELECT rec FROM json_populate_record(NULL::jsrec, '{"rec": 123}') q;
SELECT rec FROM json_populate_record(NULL::jsrec, '{"rec": [1, 2]}') q;
SELECT rec FROM json_populate_record(NULL::jsrec, '{"rec": {"a": "abc", "c": "01.02.2003", "x": 43.2}}') q;
SELECT rec FROM json_populate_record(NULL::jsrec, '{"rec": "(abc,42,01.02.2003)"}') q;

SELECT reca FROM json_populate_record(NULL::jsrec, '{"reca": 123}') q;
SELECT reca FROM json_populate_record(NULL::jsrec, '{"reca": [1, 2]}') q;
SELECT reca FROM json_populate_record(NULL::jsrec, '{"reca": [{"a": "abc", "b": 456}, null, {"c": "01.02.2003", "x": 43.2}]}') q;
SELECT reca FROM json_populate_record(NULL::jsrec, '{"reca": ["(abc,42,01.02.2003)"]}') q;
SELECT reca FROM json_populate_record(NULL::jsrec, '{"reca": "{\"(abc,42,01.02.2003)\"}"}') q;

SELECT rec FROM json_populate_record(
	row(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
		row('x',3,'2012-12-31 15:30:56')::jpop,NULL)::jsrec,
	'{"rec": {"a": "abc", "c": "01.02.2003", "x": 43.2}}'
) q;

-- anonymous record type
SELECT json_populate_record(null::record, '{"x": 0, "y": 1}');
SELECT json_populate_record(row(1,2), '{"f1": 0, "f2": 1}');
SELECT * FROM
  json_populate_record(null::record, '{"x": 776}') AS (x int, y int);

-- composite domain
SELECT json_populate_record(null::j_ordered_pair, '{"x": 0, "y": 1}');
SELECT json_populate_record(row(1,2)::j_ordered_pair, '{"x": 0}');
SELECT json_populate_record(row(1,2)::j_ordered_pair, '{"x": 1, "y": 0}');

-- populate_recordset

select * from json_populate_recordset(null::jpop,'[{"a":"blurfl","x":43.2},{"b":3,"c":"2012-01-20 10:42:53"}]') q;
select * from json_populate_recordset(row('def',99,null)::jpop,'[{"a":"blurfl","x":43.2},{"b":3,"c":"2012-01-20 10:42:53"}]') q;
select * from json_populate_recordset(null::jpop,'[{"a":"blurfl","x":43.2},{"b":3,"c":"2012-01-20 10:42:53"}]') q;
select * from json_populate_recordset(row('def',99,null)::jpop,'[{"a":"blurfl","x":43.2},{"b":3,"c":"2012-01-20 10:42:53"}]') q;
select * from json_populate_recordset(row('def',99,null)::jpop,'[{"a":[100,200,300],"x":43.2},{"a":{"z":true},"b":3,"c":"2012-01-20 10:42:53"}]') q;
select * from json_populate_recordset(row('def',99,null)::jpop,'[{"c":[100,200,300],"x":43.2},{"a":{"z":true},"b":3,"c":"2012-01-20 10:42:53"}]') q;

create type jpop2 as (a int, b json, c int, d int);
select * from json_populate_recordset(null::jpop2, '[{"a":2,"c":3,"b":{"z":4},"d":6}]') q;

select * from json_populate_recordset(null::jpop,'[{"a":"blurfl","x":43.2},{"b":3,"c":"2012-01-20 10:42:53"}]') q;
select * from json_populate_recordset(row('def',99,null)::jpop,'[{"a":"blurfl","x":43.2},{"b":3,"c":"2012-01-20 10:42:53"}]') q;
select * from json_populate_recordset(row('def',99,null)::jpop,'[{"a":[100,200,300],"x":43.2},{"a":{"z":true},"b":3,"c":"2012-01-20 10:42:53"}]') q;

-- anonymous record type
SELECT json_populate_recordset(null::record, '[{"x": 0, "y": 1}]');
SELECT json_populate_recordset(row(1,2), '[{"f1": 0, "f2": 1}]');
SELECT i, json_populate_recordset(row(i,50), '[{"f1":"42"},{"f2":"43"}]')
FROM (VALUES (1),(2)) v(i);
SELECT * FROM
  json_populate_recordset(null::record, '[{"x": 776}]') AS (x int, y int);

-- empty array is a corner case
SELECT json_populate_recordset(null::record, '[]');
SELECT json_populate_recordset(row(1,2), '[]');
SELECT * FROM json_populate_recordset(NULL::jpop,'[]') q;
SELECT * FROM
  json_populate_recordset(null::record, '[]') AS (x int, y int);

-- composite domain
SELECT json_populate_recordset(null::j_ordered_pair, '[{"x": 0, "y": 1}]');
SELECT json_populate_recordset(row(1,2)::j_ordered_pair, '[{"x": 0}, {"y": 3}]');
SELECT json_populate_recordset(row(1,2)::j_ordered_pair, '[{"x": 1, "y": 0}]');

-- negative cases where the wrong record type is supplied
select * from json_populate_recordset(row(0::int),'[{"a":"1","b":"2"},{"a":"3"}]') q (a text, b text);
select * from json_populate_recordset(row(0::int,0::int),'[{"a":"1","b":"2"},{"a":"3"}]') q (a text, b text);
select * from json_populate_recordset(row(0::int,0::int,0::int),'[{"a":"1","b":"2"},{"a":"3"}]') q (a text, b text);
select * from json_populate_recordset(row(1000000000::int,50::int),'[{"b":"2"},{"a":"3"}]') q (a text, b text);

-- test type info caching in json_populate_record()
CREATE TEMP TABLE jspoptest (js json);

INSERT INTO jspoptest
SELECT '{
	"jsa": [1, "2", null, 4],
	"rec": {"a": "abc", "c": "01.02.2003", "x": 43.2},
	"reca": [{"a": "abc", "b": 456}, null, {"c": "01.02.2003", "x": 43.2}]
}'::json
FROM generate_series(1, 3);

SELECT (json_populate_record(NULL::jsrec, js)).* FROM jspoptest;

DROP TYPE jsrec;
DROP TYPE jsrec_i_not_null;
DROP DOMAIN js_int_not_null;
DROP DOMAIN js_int_array_1d;
DROP DOMAIN js_int_array_2d;
DROP DOMAIN j_ordered_pair;
DROP TYPE j_unordered_pair;

--json_typeof() function
select value, json_typeof(value)
  from (values (json '123.4'),
               (json '-1'),
               (json '"foo"'),
               (json 'true'),
               (json 'false'),
               (json 'null'),
               (json '[1, 2, 3]'),
               (json '[]'),
               (json '{"x":"foo", "y":123}'),
               (json '{}'),
               (NULL::json))
      as data(value);

-- json_build_array, json_build_object, json_object_agg

SELECT json_build_array('a',1,'b',1.2,'c',true,'d',null,'e',json '{"x": 3, "y": [1,2,3]}');
SELECT json_build_array('a', NULL); -- ok
SELECT json_build_array(VARIADIC NULL::text[]); -- ok
SELECT json_build_array(VARIADIC '{}'::text[]); -- ok
SELECT json_build_array(VARIADIC '{a,b,c}'::text[]); -- ok
SELECT json_build_array(VARIADIC ARRAY['a', NULL]::text[]); -- ok
SELECT json_build_array(VARIADIC '{1,2,3,4}'::text[]); -- ok
SELECT json_build_array(VARIADIC '{1,2,3,4}'::int[]); -- ok
SELECT json_build_array(VARIADIC '{{1,4},{2,5},{3,6}}'::int[][]); -- ok

SELECT json_build_object('a',1,'b',1.2,'c',true,'d',null,'e',json '{"x": 3, "y": [1,2,3]}');

SELECT json_build_object(
       'a', json_build_object('b',false,'c',99),
       'd', json_build_object('e',array[9,8,7]::int[],
           'f', (select row_to_json(r) from ( select relkind, oid::regclass as name from pg_class where relname = 'pg_class') r)));
SELECT json_build_object('{a,b,c}'::text[]); -- error
SELECT json_build_object('{a,b,c}'::text[], '{d,e,f}'::text[]); -- error, key cannot be array
SELECT json_build_object('a', 'b', 'c'); -- error
SELECT json_build_object(NULL, 'a'); -- error, key cannot be NULL
SELECT json_build_object('a', NULL); -- ok
SELECT json_build_object(VARIADIC NULL::text[]); -- ok
SELECT json_build_object(VARIADIC '{}'::text[]); -- ok
SELECT json_build_object(VARIADIC '{a,b,c}'::text[]); -- error
SELECT json_build_object(VARIADIC ARRAY['a', NULL]::text[]); -- ok
SELECT json_build_object(VARIADIC ARRAY[NULL, 'a']::text[]); -- error, key cannot be NULL
SELECT json_build_object(VARIADIC '{1,2,3,4}'::text[]); -- ok
SELECT json_build_object(VARIADIC '{1,2,3,4}'::int[]); -- ok
SELECT json_build_object(VARIADIC '{{1,4},{2,5},{3,6}}'::int[][]); -- ok

-- empty objects/arrays
SELECT json_build_array();

SELECT json_build_object();

-- make sure keys are quoted
SELECT json_build_object(1,2);

-- keys must be scalar and not null
SELECT json_build_object(null,2);

SELECT json_build_object(r,2) FROM (SELECT 1 AS a, 2 AS b) r;

SELECT json_build_object(json '{"a":1,"b":2}', 3);

SELECT json_build_object('{1,2,3}'::int[], 3);

CREATE TEMP TABLE foo (serial_num int, name text, type text);
INSERT INTO foo VALUES (847001,'t15','GE1043');
INSERT INTO foo VALUES (847002,'t16','GE1043');
INSERT INTO foo VALUES (847003,'sub-alpha','GESS90');

SELECT json_build_object('turbines',json_object_agg(serial_num,json_build_object('name',name,'type',type)))
FROM foo;

SELECT json_object_agg(name, type) FROM foo;

INSERT INTO foo VALUES (999999, NULL, 'bar');
SELECT json_object_agg(name, type) FROM foo;

-- json_object

-- empty object, one dimension
SELECT json_object('{}');

-- empty object, two dimensions
SELECT json_object('{}', '{}');

-- one dimension
SELECT json_object('{a,1,b,2,3,NULL,"d e f","a b c"}');

-- same but with two dimensions
SELECT json_object('{{a,1},{b,2},{3,NULL},{"d e f","a b c"}}');

-- odd number error
SELECT json_object('{a,b,c}');

-- one column error
SELECT json_object('{{a},{b}}');

-- too many columns error
SELECT json_object('{{a,b,c},{b,c,d}}');

-- too many dimensions error
SELECT json_object('{{{a,b},{c,d}},{{b,c},{d,e}}}');

--two argument form of json_object

select json_object('{a,b,c,"d e f"}','{1,2,3,"a b c"}');

-- too many dimensions
SELECT json_object('{{a,1},{b,2},{3,NULL},{"d e f","a b c"}}', '{{a,1},{b,2},{3,NULL},{"d e f","a b c"}}');

-- mismatched dimensions

select json_object('{a,b,c,"d e f",g}','{1,2,3,"a b c"}');

select json_object('{a,b,c,"d e f"}','{1,2,3,"a b c",g}');

-- null key error

select json_object('{a,b,NULL,"d e f"}','{1,2,3,"a b c"}');

-- empty key is allowed

select json_object('{a,b,"","d e f"}','{1,2,3,"a b c"}');


-- json_to_record and json_to_recordset

select * from json_to_record('{"a":1,"b":"foo","c":"bar"}')
    as x(a int, b text, d text);

select * from json_to_recordset('[{"a":1,"b":"foo","d":false},{"a":2,"b":"bar","c":true}]')
    as x(a int, b text, c boolean);

select * from json_to_recordset('[{"a":1,"b":{"d":"foo"},"c":true},{"a":2,"c":false,"b":{"d":"bar"}}]')
    as x(a int, b json, c boolean);

select *, c is null as c_is_null
from json_to_record('{"a":1, "b":{"c":16, "d":2}, "x":8, "ca": ["1 2", 3], "ia": [[1,2],[3,4]], "r": {"a": "aaa", "b": 123}}'::json)
    as t(a int, b json, c text, x int, ca char(5)[], ia int[][], r jpop);

select *, c is null as c_is_null
from json_to_recordset('[{"a":1, "b":{"c":16, "d":2}, "x":8}]'::json)
    as t(a int, b json, c text, x int);

select * from json_to_record('{"ia": null}') as x(ia _int4);
select * from json_to_record('{"ia": 123}') as x(ia _int4);
select * from json_to_record('{"ia": [1, "2", null, 4]}') as x(ia _int4);
select * from json_to_record('{"ia": [[1, 2], [3, 4]]}') as x(ia _int4);
select * from json_to_record('{"ia": [[1], 2]}') as x(ia _int4);
select * from json_to_record('{"ia": [[1], [2, 3]]}') as x(ia _int4);

select * from json_to_record('{"ia2": [1, 2, 3]}') as x(ia2 int[][]);
select * from json_to_record('{"ia2": [[1, 2], [3, 4]]}') as x(ia2 int4[][]);
select * from json_to_record('{"ia2": [[[1], [2], [3]]]}') as x(ia2 int4[][]);

select * from json_to_record('{"out": {"key": 1}}') as x(out json);
select * from json_to_record('{"out": [{"key": 1}]}') as x(out json);
select * from json_to_record('{"out": "{\"key\": 1}"}') as x(out json);
select * from json_to_record('{"out": {"key": 1}}') as x(out jsonb);
select * from json_to_record('{"out": [{"key": 1}]}') as x(out jsonb);
select * from json_to_record('{"out": "{\"key\": 1}"}') as x(out jsonb);

-- json_strip_nulls

select json_strip_nulls(null);

select json_strip_nulls('1');

select json_strip_nulls('"a string"');

select json_strip_nulls('null');

select json_strip_nulls('[1,2,null,3,4]');

select json_strip_nulls('{"a":1,"b":null,"c":[2,null,3],"d":{"e":4,"f":null}}');

select json_strip_nulls('[1,{"a":1,"b":null,"c":2},3]');

-- an empty object is not null and should not be stripped
select json_strip_nulls('{"a": {"b": null, "c": null}, "d": {} }');

-- json to tsvector
select to_tsvector('{"a": "aaa bbb ddd ccc", "b": ["eee fff ggg"], "c": {"d": "hhh iii"}}'::json);

-- json to tsvector with config
select to_tsvector('simple', '{"a": "aaa bbb ddd ccc", "b": ["eee fff ggg"], "c": {"d": "hhh iii"}}'::json);

-- json to tsvector with stop words
select to_tsvector('english', '{"a": "aaa in bbb ddd ccc", "b": ["the eee fff ggg"], "c": {"d": "hhh. iii"}}'::json);

-- json to tsvector with numeric values
select to_tsvector('english', '{"a": "aaa in bbb ddd ccc", "b": 123, "c": 456}'::json);

-- json_to_tsvector
select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, '"all"');
select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, '"key"');
select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, '"string"');
select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, '"numeric"');
select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, '"boolean"');
select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, '["string", "numeric"]');

select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, '"all"');
select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, '"key"');
select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, '"string"');
select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, '"numeric"');
select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, '"boolean"');
select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, '["string", "numeric"]');

-- to_tsvector corner cases
select to_tsvector('""'::json);
select to_tsvector('{}'::json);
select to_tsvector('[]'::json);
select to_tsvector('null'::json);

-- json_to_tsvector corner cases
select json_to_tsvector('""'::json, '"all"');
select json_to_tsvector('{}'::json, '"all"');
select json_to_tsvector('[]'::json, '"all"');
select json_to_tsvector('null'::json, '"all"');

select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, '""');
select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, '{}');
select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, '[]');
select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, 'null');
select json_to_tsvector('english', '{"a": "aaa in bbb", "b": 123, "c": 456, "d": true, "f": false, "g": null}'::json, '["all", null]');

-- ts_headline for json
select ts_headline('{"a": "aaa bbb", "b": {"c": "ccc ddd fff", "c1": "ccc1 ddd1"}, "d": ["ggg hhh", "iii jjj"]}'::json, tsquery('bbb & ddd & hhh'));
select ts_headline('english', '{"a": "aaa bbb", "b": {"c": "ccc ddd fff"}, "d": ["ggg hhh", "iii jjj"]}'::json, tsquery('bbb & ddd & hhh'));
select ts_headline('{"a": "aaa bbb", "b": {"c": "ccc ddd fff", "c1": "ccc1 ddd1"}, "d": ["ggg hhh", "iii jjj"]}'::json, tsquery('bbb & ddd & hhh'), 'StartSel = <, StopSel = >');
select ts_headline('english', '{"a": "aaa bbb", "b": {"c": "ccc ddd fff", "c1": "ccc1 ddd1"}, "d": ["ggg hhh", "iii jjj"]}'::json, tsquery('bbb & ddd & hhh'), 'StartSel = <, StopSel = >');

-- corner cases for ts_headline with json
select ts_headline('null'::json, tsquery('aaa & bbb'));
select ts_headline('{}'::json, tsquery('aaa & bbb'));
select ts_headline('[]'::json, tsquery('aaa & bbb'));

-- equality and inequality
SELECT '{"x":"y"}'::json = '{"x":"y"}'::json;
SELECT '{"x":"y"}'::json = '{"x":"z"}'::json;

SELECT '{"x":"y"}'::json <> '{"x":"y"}'::json;
SELECT '{"x":"y"}'::json <> '{"x":"z"}'::json;

-- containment
SELECT json_contains('{"a":"b", "b":1, "c":null}', '{"a":"b"}');
SELECT json_contains('{"a":"b", "b":1, "c":null}', '{"a":"b", "c":null}');
SELECT json_contains('{"a":"b", "b":1, "c":null}', '{"a":"b", "g":null}');
SELECT json_contains('{"a":"b", "b":1, "c":null}', '{"g":null}');
SELECT json_contains('{"a":"b", "b":1, "c":null}', '{"a":"c"}');
SELECT json_contains('{"a":"b", "b":1, "c":null}', '{"a":"b"}');
SELECT json_contains('{"a":"b", "b":1, "c":null}', '{"a":"b", "c":"q"}');
SELECT '{"a":"b", "b":1, "c":null}'::json @> '{"a":"b"}';
SELECT '{"a":"b", "b":1, "c":null}'::json @> '{"a":"b", "c":null}';
SELECT '{"a":"b", "b":1, "c":null}'::json @> '{"a":"b", "g":null}';
SELECT '{"a":"b", "b":1, "c":null}'::json @> '{"g":null}';
SELECT '{"a":"b", "b":1, "c":null}'::json @> '{"a":"c"}';
SELECT '{"a":"b", "b":1, "c":null}'::json @> '{"a":"b"}';
SELECT '{"a":"b", "b":1, "c":null}'::json @> '{"a":"b", "c":"q"}';

SELECT '[1,2]'::json @> '[1,2,2]'::json;
SELECT '[1,1,2]'::json @> '[1,2,2]'::json;
SELECT '[[1,2]]'::json @> '[[1,2,2]]'::json;
SELECT '[1,2,2]'::json <@ '[1,2]'::json;
SELECT '[1,2,2]'::json <@ '[1,1,2]'::json;
SELECT '[[1,2,2]]'::json <@ '[[1,2]]'::json;

SELECT json_contained('{"a":"b"}', '{"a":"b", "b":1, "c":null}');
SELECT json_contained('{"a":"b", "c":null}', '{"a":"b", "b":1, "c":null}');
SELECT json_contained('{"a":"b", "g":null}', '{"a":"b", "b":1, "c":null}');
SELECT json_contained('{"g":null}', '{"a":"b", "b":1, "c":null}');
SELECT json_contained('{"a":"c"}', '{"a":"b", "b":1, "c":null}');
SELECT json_contained('{"a":"b"}', '{"a":"b", "b":1, "c":null}');
SELECT json_contained('{"a":"b", "c":"q"}', '{"a":"b", "b":1, "c":null}');
SELECT '{"a":"b"}'::json <@ '{"a":"b", "b":1, "c":null}';
SELECT '{"a":"b", "c":null}'::json <@ '{"a":"b", "b":1, "c":null}';
SELECT '{"a":"b", "g":null}'::json <@ '{"a":"b", "b":1, "c":null}';
SELECT '{"g":null}'::json <@ '{"a":"b", "b":1, "c":null}';
SELECT '{"a":"c"}'::json <@ '{"a":"b", "b":1, "c":null}';
SELECT '{"a":"b"}'::json <@ '{"a":"b", "b":1, "c":null}';
SELECT '{"a":"b", "c":"q"}'::json <@ '{"a":"b", "b":1, "c":null}';
-- Raw scalar may contain another raw scalar, array may contain a raw scalar
SELECT '[5]'::json @> '[5]';
SELECT '5'::json @> '5';
SELECT '[5]'::json @> '5';
-- But a raw scalar cannot contain an array
SELECT '5'::json @> '[5]';
-- In general, one thing should always contain itself. Test array containment:
SELECT '["9", ["7", "3"], 1]'::json @> '["9", ["7", "3"], 1]'::json;
SELECT '["9", ["7", "3"], ["1"]]'::json @> '["9", ["7", "3"], ["1"]]'::json;
-- array containment string matching confusion bug
SELECT '{ "name": "Bob", "tags": [ "enim", "qui"]}'::json @> '{"tags":["qu"]}';


-- exists
SELECT json_exists('{"a":null, "b":"qq"}', 'a');
SELECT json_exists('{"a":null, "b":"qq"}', 'b');
SELECT json_exists('{"a":null, "b":"qq"}', 'c');
SELECT json_exists('{"a":"null", "b":"qq"}', 'a');
SELECT json '{"a":null, "b":"qq"}' ? 'a';
SELECT json '{"a":null, "b":"qq"}' ? 'b';
SELECT json '{"a":null, "b":"qq"}' ? 'c';
SELECT json '{"a":"null", "b":"qq"}' ? 'a';
-- array exists - array elements should behave as keys
SELECT count(*) from testjson  WHERE j->'array' ? 'bar';
-- type sensitive array exists - should return no rows (since "exists" only
-- matches strings that are either object keys or array elements)
SELECT count(*) from testjson  WHERE j->'array' ? '5'::text;
-- However, a raw scalar is *contained* within the array
SELECT count(*) from testjson  WHERE j->'array' @> '5'::json;

SELECT json_exists_any('{"a":null, "b":"qq"}', ARRAY['a','b']);
SELECT json_exists_any('{"a":null, "b":"qq"}', ARRAY['b','a']);
SELECT json_exists_any('{"a":null, "b":"qq"}', ARRAY['c','a']);
SELECT json_exists_any('{"a":null, "b":"qq"}', ARRAY['c','d']);
SELECT json_exists_any('{"a":null, "b":"qq"}', '{}'::text[]);
SELECT json '{"a":null, "b":"qq"}' ?| ARRAY['a','b'];
SELECT json '{"a":null, "b":"qq"}' ?| ARRAY['b','a'];
SELECT json '{"a":null, "b":"qq"}' ?| ARRAY['c','a'];
SELECT json '{"a":null, "b":"qq"}' ?| ARRAY['c','d'];
SELECT json '{"a":null, "b":"qq"}' ?| '{}'::text[];

SELECT json_exists_all('{"a":null, "b":"qq"}', ARRAY['a','b']);
SELECT json_exists_all('{"a":null, "b":"qq"}', ARRAY['b','a']);
SELECT json_exists_all('{"a":null, "b":"qq"}', ARRAY['c','a']);
SELECT json_exists_all('{"a":null, "b":"qq"}', ARRAY['c','d']);
SELECT json_exists_all('{"a":null, "b":"qq"}', '{}'::text[]);
SELECT json '{"a":null, "b":"qq"}' ?& ARRAY['a','b'];
SELECT json '{"a":null, "b":"qq"}' ?& ARRAY['b','a'];
SELECT json '{"a":null, "b":"qq"}' ?& ARRAY['c','a'];
SELECT json '{"a":null, "b":"qq"}' ?& ARRAY['c','d'];
SELECT json '{"a":null, "b":"qq"}' ?& ARRAY['a','a', 'b', 'b', 'b'];
SELECT json '{"a":null, "b":"qq"}' ?& '{}'::text[];


-- indexing
SELECT count(*) FROM testjson WHERE j @> '{"wait":null}';
SELECT count(*) FROM testjson WHERE j @> '{"wait":"CC"}';
SELECT count(*) FROM testjson WHERE j @> '{"wait":"CC", "public":true}';
SELECT count(*) FROM testjson WHERE j @> '{"age":25}';
SELECT count(*) FROM testjson WHERE j @> '{"age":25.0}';
SELECT count(*) FROM testjson WHERE j ? 'public';
SELECT count(*) FROM testjson WHERE j ? 'bar';
SELECT count(*) FROM testjson WHERE j ?| ARRAY['public','disabled'];
SELECT count(*) FROM testjson WHERE j ?& ARRAY['public','disabled'];

CREATE INDEX testjson_jidx ON testjson USING gin (j);
SET enable_seqscan = off;

SELECT count(*) FROM testjson WHERE j @> '{"wait":null}';
SELECT count(*) FROM testjson WHERE j @> '{"wait":"CC"}';
SELECT count(*) FROM testjson WHERE j @> '{"wait":"CC", "public":true}';
SELECT count(*) FROM testjson WHERE j @> '{"age":25}';
SELECT count(*) FROM testjson WHERE j @> '{"age":25.0}';
SELECT count(*) FROM testjson WHERE j @> '{"array":["foo"]}';
SELECT count(*) FROM testjson WHERE j @> '{"array":["bar"]}';
-- exercise GIN_SEARCH_MODE_ALL
SELECT count(*) FROM testjson WHERE j @> '{}';
SELECT count(*) FROM testjson WHERE j ? 'public';
SELECT count(*) FROM testjson WHERE j ? 'bar';
SELECT count(*) FROM testjson WHERE j ?| ARRAY['public','disabled'];
SELECT count(*) FROM testjson WHERE j ?& ARRAY['public','disabled'];

-- array exists - array elements should behave as keys (for GIN index scans too)
CREATE INDEX testjson_jidx_array ON testjson USING gin((j->'array'));
SELECT count(*) from testjson  WHERE j->'array' ? 'bar';
-- type sensitive array exists - should return no rows (since "exists" only
-- matches strings that are either object keys or array elements)
SELECT count(*) from testjson  WHERE j->'array' ? '5'::text;
-- However, a raw scalar is *contained* within the array
SELECT count(*) from testjson  WHERE j->'array' @> '5'::json;

RESET enable_seqscan;

SELECT count(*) FROM (SELECT (json_each(j)).key FROM testjson) AS wow;
SELECT key, count(*) FROM (SELECT (json_each(j)).key FROM testjson) AS wow GROUP BY key ORDER BY count DESC, key;

-- sort/hash
SELECT count(distinct j) FROM testjson;
SET enable_hashagg = off;
SELECT count(*) FROM (SELECT j FROM (SELECT * FROM testjson UNION ALL SELECT * FROM testjson) js GROUP BY j) js2;
SET enable_hashagg = on;
SET enable_sort = off;
SELECT count(*) FROM (SELECT j FROM (SELECT * FROM testjson UNION ALL SELECT * FROM testjson) js GROUP BY j) js2;
SELECT distinct * FROM (values (json '{}' || ''::text),('{}')) v(j);
SET enable_sort = on;

RESET enable_hashagg;
RESET enable_sort;

DROP INDEX testjson_jidx;
DROP INDEX testjson_jidx_array;
-- btree
CREATE INDEX testjson_jidx ON testjson USING btree (j);
SET enable_seqscan = off;

SELECT count(*) FROM testjson WHERE j > '{"p": 1}';
SELECT count(*) FROM testjson WHERE j = '{"indexed": true, "line": 371, "pos": 98, "node": "CBA"}';

--gin path opclass
DROP INDEX testjson_jidx;
CREATE INDEX testjson_jidx ON testjson USING gin (j json_path_ops);
SET enable_seqscan = off;

SELECT count(*) FROM testjson WHERE j @> '{"wait":null}';
SELECT count(*) FROM testjson WHERE j @> '{"wait":"CC"}';
SELECT count(*) FROM testjson WHERE j @> '{"wait":"CC", "public":true}';
SELECT count(*) FROM testjson WHERE j @> '{"age":25}';
SELECT count(*) FROM testjson WHERE j @> '{"age":25.0}';
-- exercise GIN_SEARCH_MODE_ALL
SELECT count(*) FROM testjson WHERE j @> '{}';

RESET enable_seqscan;
DROP INDEX testjson_jidx;

-- nested tests
SELECT '{"ff":{"a":12,"b":16}}'::json;
SELECT '{"ff":{"a":12,"b":16},"qq":123}'::json;
SELECT '{"aa":["a","aaa"],"qq":{"a":12,"b":16,"c":["c1","c2"],"d":{"d1":"d1","d2":"d2","d1":"d3"}}}'::json;
SELECT '{"aa":["a","aaa"],"qq":{"a":"12","b":"16","c":["c1","c2"],"d":{"d1":"d1","d2":"d2"}}}'::json;
SELECT '{"aa":["a","aaa"],"qq":{"a":"12","b":"16","c":["c1","c2",["c3"],{"c4":4}],"d":{"d1":"d1","d2":"d2"}}}'::json;
SELECT '{"ff":["a","aaa"]}'::json;

SELECT
  '{"ff":{"a":12,"b":16},"qq":123,"x":[1,2],"Y":null}'::json -> 'ff',
  '{"ff":{"a":12,"b":16},"qq":123,"x":[1,2],"Y":null}'::json -> 'qq',
  ('{"ff":{"a":12,"b":16},"qq":123,"x":[1,2],"Y":null}'::json -> 'Y') IS NULL AS f,
  ('{"ff":{"a":12,"b":16},"qq":123,"x":[1,2],"Y":null}'::json ->> 'Y') IS NULL AS t,
   '{"ff":{"a":12,"b":16},"qq":123,"x":[1,2],"Y":null}'::json -> 'x';

-- nested containment
SELECT '{"a":[1,2],"c":"b"}'::json @> '{"a":[1,2]}';
SELECT '{"a":[2,1],"c":"b"}'::json @> '{"a":[1,2]}';
SELECT '{"a":{"1":2},"c":"b"}'::json @> '{"a":[1,2]}';
SELECT '{"a":{"2":1},"c":"b"}'::json @> '{"a":[1,2]}';
SELECT '{"a":{"1":2},"c":"b"}'::json @> '{"a":{"1":2}}';
SELECT '{"a":{"2":1},"c":"b"}'::json @> '{"a":{"1":2}}';
SELECT '["a","b"]'::json @> '["a","b","c","b"]';
SELECT '["a","b","c","b"]'::json @> '["a","b"]';
SELECT '["a","b","c",[1,2]]'::json @> '["a",[1,2]]';
SELECT '["a","b","c",[1,2]]'::json @> '["b",[1,2]]';

SELECT '{"a":[1,2],"c":"b"}'::json @> '{"a":[1]}';
SELECT '{"a":[1,2],"c":"b"}'::json @> '{"a":[2]}';
SELECT '{"a":[1,2],"c":"b"}'::json @> '{"a":[3]}';

SELECT '{"a":[1,2,{"c":3,"x":4}],"c":"b"}'::json @> '{"a":[{"c":3}]}';
SELECT '{"a":[1,2,{"c":3,"x":4}],"c":"b"}'::json @> '{"a":[{"x":4}]}';
SELECT '{"a":[1,2,{"c":3,"x":4}],"c":"b"}'::json @> '{"a":[{"x":4},3]}';
SELECT '{"a":[1,2,{"c":3,"x":4}],"c":"b"}'::json @> '{"a":[{"x":4},1]}';

-- check some corner cases for indexed nested containment (bug #13756)
create temp table nestjson (j json);
insert into nestjson (j) values ('{"a":[["b",{"x":1}],["b",{"x":2}]],"c":3}');
insert into nestjson (j) values ('[[14,2,3]]');
insert into nestjson (j) values ('[1,[14,2,3]]');
create index on nestjson using gin(j json_path_ops);

set enable_seqscan = on;
set enable_bitmapscan = off;
select * from nestjson where j @> '{"a":[[{"x":2}]]}'::json;
select * from nestjson where j @> '{"c":3}';
select * from nestjson where j @> '[[14]]';
set enable_seqscan = off;
set enable_bitmapscan = on;
select * from nestjson where j @> '{"a":[[{"x":2}]]}'::json;
select * from nestjson where j @> '{"c":3}';
select * from nestjson where j @> '[[14]]';
reset enable_seqscan;
reset enable_bitmapscan;

-- nested object field / array index lookup
SELECT '{"n":null,"a":1,"b":[1,2],"c":{"1":2},"d":{"1":[2,3]}}'::json -> 'n';
SELECT '{"n":null,"a":1,"b":[1,2],"c":{"1":2},"d":{"1":[2,3]}}'::json -> 'a';
SELECT '{"n":null,"a":1,"b":[1,2],"c":{"1":2},"d":{"1":[2,3]}}'::json -> 'b';
SELECT '{"n":null,"a":1,"b":[1,2],"c":{"1":2},"d":{"1":[2,3]}}'::json -> 'c';
SELECT '{"n":null,"a":1,"b":[1,2],"c":{"1":2},"d":{"1":[2,3]}}'::json -> 'd';
SELECT '{"n":null,"a":1,"b":[1,2],"c":{"1":2},"d":{"1":[2,3]}}'::json -> 'd' -> '1';
SELECT '{"n":null,"a":1,"b":[1,2],"c":{"1":2},"d":{"1":[2,3]}}'::json -> 'e';
SELECT '{"n":null,"a":1,"b":[1,2],"c":{"1":2},"d":{"1":[2,3]}}'::json -> 0; --expecting error

SELECT '["a","b","c",[1,2],null]'::json -> 0;
SELECT '["a","b","c",[1,2],null]'::json -> 1;
SELECT '["a","b","c",[1,2],null]'::json -> 2;
SELECT '["a","b","c",[1,2],null]'::json -> 3;
SELECT '["a","b","c",[1,2],null]'::json -> 3 -> 1;
SELECT '["a","b","c",[1,2],null]'::json -> 4;
SELECT '["a","b","c",[1,2],null]'::json -> 5;
SELECT '["a","b","c",[1,2],null]'::json -> -1;
SELECT '["a","b","c",[1,2],null]'::json -> -5;
SELECT '["a","b","c",[1,2],null]'::json -> -6;

--nested path extraction
SELECT '{"a":"b","c":[1,2,3]}'::json #> '{0}';
SELECT '{"a":"b","c":[1,2,3]}'::json #> '{a}';
SELECT '{"a":"b","c":[1,2,3]}'::json #> '{c}';
SELECT '{"a":"b","c":[1,2,3]}'::json #> '{c,0}';
SELECT '{"a":"b","c":[1,2,3]}'::json #> '{c,1}';
SELECT '{"a":"b","c":[1,2,3]}'::json #> '{c,2}';
SELECT '{"a":"b","c":[1,2,3]}'::json #> '{c,3}';
SELECT '{"a":"b","c":[1,2,3]}'::json #> '{c,-1}';
SELECT '{"a":"b","c":[1,2,3]}'::json #> '{c,-3}';
SELECT '{"a":"b","c":[1,2,3]}'::json #> '{c,-4}';

SELECT '[0,1,2,[3,4],{"5":"five"}]'::json #> '{0}';
SELECT '[0,1,2,[3,4],{"5":"five"}]'::json #> '{3}';
SELECT '[0,1,2,[3,4],{"5":"five"}]'::json #> '{4}';
SELECT '[0,1,2,[3,4],{"5":"five"}]'::json #> '{4,5}';

--nested exists
SELECT '{"n":null,"a":1,"b":[1,2],"c":{"1":2},"d":{"1":[2,3]}}'::json ? 'n';
SELECT '{"n":null,"a":1,"b":[1,2],"c":{"1":2},"d":{"1":[2,3]}}'::json ? 'a';
SELECT '{"n":null,"a":1,"b":[1,2],"c":{"1":2},"d":{"1":[2,3]}}'::json ? 'b';
SELECT '{"n":null,"a":1,"b":[1,2],"c":{"1":2},"d":{"1":[2,3]}}'::json ? 'c';
SELECT '{"n":null,"a":1,"b":[1,2],"c":{"1":2},"d":{"1":[2,3]}}'::json ? 'd';
SELECT '{"n":null,"a":1,"b":[1,2],"c":{"1":2},"d":{"1":[2,3]}}'::json ? 'e';



select json_pretty('{"a": "test", "b": [1, 2, 3], "c": "test3", "d":{"dd": "test4", "dd2":{"ddd": "test5"}}}');
select json_pretty('[{"f1":1,"f2":null},2,null,[[{"x":true},6,7],8],3]');
select json_pretty('{"a":["b", "c"], "d": {"e":"f"}}');

select json_concat('{"d": "test", "a": [1, 2]}', '{"g": "test2", "c": {"c1":1, "c2":2}}');

select '{"aa":1 , "b":2, "cq":3}'::json || '{"cq":"l", "b":"g", "fg":false}';
select '{"aa":1 , "b":2, "cq":3}'::json || '{"aq":"l"}';
select '{"aa":1 , "b":2, "cq":3}'::json || '{"aa":"l"}';
select '{"aa":1 , "b":2, "cq":3}'::json || '{}';

select '["a", "b"]'::json || '["c"]';
select '["a", "b"]'::json || '["c", "d"]';
select '["c"]' || '["a", "b"]'::json;

select '["a", "b"]'::json || '"c"';
select '"c"' || '["a", "b"]'::json;

select '[]'::json || '["a"]'::json;
select '[]'::json || '"a"'::json;
select '"b"'::json || '"a"'::json;
select '{}'::json || '{"a":"b"}'::json;
select '[]'::json || '{"a":"b"}'::json;
select '{"a":"b"}'::json || '[]'::json;

select '"a"'::json || '{"a":1}';
select '{"a":1}' || '"a"'::json;

select '["a", "b"]'::json || '{"c":1}';
select '{"c": 1}'::json || '["a", "b"]';

select '{}'::json || '{"cq":"l", "b":"g", "fg":false}';

select pg_column_size('{}'::json || '{}'::json) = pg_column_size('{}'::json);
select pg_column_size('{"aa":1}'::json || '{"b":2}'::json) = pg_column_size('{"aa":1, "b":2}'::json);
select pg_column_size('{"aa":1, "b":2}'::json || '{}'::json) = pg_column_size('{"aa":1, "b":2}'::json);
select pg_column_size('{}'::json || '{"aa":1, "b":2}'::json) = pg_column_size('{"aa":1, "b":2}'::json);

select json_delete('{"a":1 , "b":2, "c":3}'::json, 'a');
select json_delete('{"a":null , "b":2, "c":3}'::json, 'a');
select json_delete('{"a":1 , "b":2, "c":3}'::json, 'b');
select json_delete('{"a":1 , "b":2, "c":3}'::json, 'c');
select json_delete('{"a":1 , "b":2, "c":3}'::json, 'd');
select '{"a":1 , "b":2, "c":3}'::json - 'a';
select '{"a":null , "b":2, "c":3}'::json - 'a';
select '{"a":1 , "b":2, "c":3}'::json - 'b';
select '{"a":1 , "b":2, "c":3}'::json - 'c';
select '{"a":1 , "b":2, "c":3}'::json - 'd';
select pg_column_size('{"a":1 , "b":2, "c":3}'::json - 'b') = pg_column_size('{"a":1, "b":2}'::json);

select '["a","b","c"]'::json - 3;
select '["a","b","c"]'::json - 2;
select '["a","b","c"]'::json - 1;
select '["a","b","c"]'::json - 0;
select '["a","b","c"]'::json - -1;
select '["a","b","c"]'::json - -2;
select '["a","b","c"]'::json - -3;
select '["a","b","c"]'::json - -4;

select json_set('{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}'::json, '{n}', '[1,2,3]');
select json_set('{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}'::json, '{b,-1}', '[1,2,3]');
select json_set('{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}'::json, '{d,1,0}', '[1,2,3]');
select json_set('{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}'::json, '{d,NULL,0}', '[1,2,3]');

select json_set('{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}'::json, '{n}', '{"1": 2}');
select json_set('{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}'::json, '{b,-1}', '{"1": 2}');
select json_set('{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}'::json, '{d,1,0}', '{"1": 2}');
select json_set('{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}'::json, '{d,NULL,0}', '{"1": 2}');

select json_set('{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}'::json, '{b,-1}', '"test"');
select json_set('{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}'::json, '{b,-1}', '{"f": "test"}');

select json_delete_path('{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}', '{n}');
select json_delete_path('{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}', '{b,-1}');
select json_delete_path('{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}', '{d,1,0}');

select '{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}'::json #- '{n}';
select '{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}'::json #- '{b,-1}';
select '{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}'::json #- '{b,-1e}'; -- invalid array subscript
select '{"n":null, "a":1, "b":[1,2], "c":{"1":2}, "d":{"1":[2,3]}}'::json #- '{d,1,0}';


-- empty structure and error conditions for delete and replace

select '"a"'::json - 'a'; -- error
select '{}'::json - 'a';
select '[]'::json - 'a';
select '"a"'::json - 1; -- error
select '{}'::json -  1; -- error
select '[]'::json - 1;
select '"a"'::json #- '{a}'; -- error
select '{}'::json #- '{a}';
select '[]'::json #- '{a}';
select json_set('"a"','{a}','"b"'); --error
select json_set('{}','{a}','"b"', false);
select json_set('[]','{1}','"b"', false);

-- json_set adding instead of replacing

-- prepend to array
select json_set('{"a":1,"b":[0,1,2],"c":{"d":4}}','{b,-33}','{"foo":123}');
-- append to array
select json_set('{"a":1,"b":[0,1,2],"c":{"d":4}}','{b,33}','{"foo":123}');
-- check nesting levels addition
select json_set('{"a":1,"b":[4,5,[0,1,2],6,7],"c":{"d":4}}','{b,2,33}','{"foo":123}');
-- add new key
select json_set('{"a":1,"b":[0,1,2],"c":{"d":4}}','{c,e}','{"foo":123}');
-- adding doesn't do anything if elements before last aren't present
select json_set('{"a":1,"b":[0,1,2],"c":{"d":4}}','{x,-33}','{"foo":123}');
select json_set('{"a":1,"b":[0,1,2],"c":{"d":4}}','{x,y}','{"foo":123}');
-- add to empty object
select json_set('{}','{x}','{"foo":123}');
--add to empty array
select json_set('[]','{0}','{"foo":123}');
select json_set('[]','{99}','{"foo":123}');
select json_set('[]','{-99}','{"foo":123}');
select json_set('{"a": [1, 2, 3]}', '{a, non_integer}', '"new_value"');
select json_set('{"a": {"b": [1, 2, 3]}}', '{a, b, non_integer}', '"new_value"');
select json_set('{"a": {"b": [1, 2, 3]}}', '{a, b, NULL}', '"new_value"');


-- json_insert
select json_insert('{"a": [0,1,2]}', '{a, 1}', '"new_value"');
select json_insert('{"a": [0,1,2]}', '{a, 1}', '"new_value"', true);
select json_insert('{"a": {"b": {"c": [0, 1, "test1", "test2"]}}}', '{a, b, c, 2}', '"new_value"');
select json_insert('{"a": {"b": {"c": [0, 1, "test1", "test2"]}}}', '{a, b, c, 2}', '"new_value"', true);
select json_insert('{"a": [0,1,2]}', '{a, 1}', '{"b": "value"}');
select json_insert('{"a": [0,1,2]}', '{a, 1}', '["value1", "value2"]');

-- edge cases
select json_insert('{"a": [0,1,2]}', '{a, 0}', '"new_value"');
select json_insert('{"a": [0,1,2]}', '{a, 0}', '"new_value"', true);
select json_insert('{"a": [0,1,2]}', '{a, 2}', '"new_value"');
select json_insert('{"a": [0,1,2]}', '{a, 2}', '"new_value"', true);
select json_insert('{"a": [0,1,2]}', '{a, -1}', '"new_value"');
select json_insert('{"a": [0,1,2]}', '{a, -1}', '"new_value"', true);
select json_insert('[]', '{1}', '"new_value"');
select json_insert('[]', '{1}', '"new_value"', true);
select json_insert('{"a": []}', '{a, 1}', '"new_value"');
select json_insert('{"a": []}', '{a, 1}', '"new_value"', true);
select json_insert('{"a": [0,1,2]}', '{a, 10}', '"new_value"');
select json_insert('{"a": [0,1,2]}', '{a, -10}', '"new_value"');

-- json_insert should be able to insert new value for objects, but not to replace
select json_insert('{"a": {"b": "value"}}', '{a, c}', '"new_value"');
select json_insert('{"a": {"b": "value"}}', '{a, c}', '"new_value"', true);

select json_insert('{"a": {"b": "value"}}', '{a, b}', '"new_value"');
select json_insert('{"a": {"b": "value"}}', '{a, b}', '"new_value"', true);
