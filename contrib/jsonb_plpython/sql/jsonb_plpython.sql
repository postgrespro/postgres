CREATE EXTENSION jsonb_plpython3u CASCADE;

-- test jsonb -> python dict
CREATE FUNCTION test1(val jsonb) RETURNS int
LANGUAGE plpython3u
TRANSFORM FOR TYPE jsonb
AS $$
#assert isinstance(val, dict)
assert(val == {'a': 1, 'c': 'NULL'})
return len(val)
$$;

SELECT test1('{"a": 1, "c": "NULL"}'::jsonb);

-- test jsonb -> python dict
-- complex dict with dicts as value
CREATE FUNCTION test1complex(val jsonb) RETURNS int
LANGUAGE plpython3u
TRANSFORM FOR TYPE jsonb
AS $$
#assert isinstance(val, dict)
assert(val == {"d": {"d": 1}})
return len(val)
$$;

SELECT test1complex('{"d": {"d": 1}}'::jsonb);


-- test jsonb[] -> python dict
-- dict with array as value
CREATE FUNCTION test1arr(val jsonb) RETURNS int
LANGUAGE plpython3u
TRANSFORM FOR TYPE jsonb
AS $$
#assert isinstance(val, dict)
assert(val == {"d": [12, 1]})
return len(val)
$$;

SELECT test1arr('{"d":[12, 1]}'::jsonb);

-- test jsonb[] -> python list
-- simple list
CREATE FUNCTION test2arr(val jsonb) RETURNS int
LANGUAGE plpython3u
TRANSFORM FOR TYPE jsonb
AS $$
#assert isinstance(val, list)
assert(val == [12, 1])
return len(val)
$$;

SELECT test2arr('[12, 1]'::jsonb);

-- test jsonb[] -> python list
-- array of dicts
CREATE FUNCTION test3arr(val jsonb) RETURNS int
LANGUAGE plpython3u
TRANSFORM FOR TYPE jsonb
AS $$
#assert isinstance(val, list)
assert(val == [{"a": 1,"b": 2}, {"c": 3,"d": 4}])
return len(val)
$$;

SELECT test3arr('[{"a": 1, "b": 2}, {"c": 3,"d": 4}]'::jsonb);

-- test jsonb int -> python int
CREATE FUNCTION test1int(val jsonb) RETURNS int
LANGUAGE plpython3u
TRANSFORM FOR TYPE jsonb
AS $$
assert(val == 1)
return val
$$;

SELECT test1int('1'::jsonb);

-- test jsonb string -> python string
CREATE FUNCTION test1string(val jsonb) RETURNS text
LANGUAGE plpython3u
TRANSFORM FOR TYPE jsonb
AS $$
assert(val == "a")
return val
$$;

SELECT test1string('"a"'::jsonb);

-- test jsonb null -> python None
CREATE FUNCTION test1null(val jsonb) RETURNS int
LANGUAGE plpython3u
TRANSFORM FOR TYPE jsonb
AS $$
assert(val == None)
return 1
$$;

SELECT test1null('null'::jsonb);

-- test python -> jsonb
CREATE FUNCTION roundtrip(val jsonb) RETURNS jsonb
LANGUAGE plpython3u
TRANSFORM FOR TYPE jsonb
as $$
return val
$$;

SELECT roundtrip('null'::jsonb);
SELECT roundtrip('1'::jsonb);
SELECT roundtrip('1234567890.0987654321'::jsonb);
SELECT roundtrip('-1234567890.0987654321'::jsonb);
SELECT roundtrip('true'::jsonb);
SELECT roundtrip('false'::jsonb);
SELECT roundtrip('"string"'::jsonb);

SELECT roundtrip('{"1": null}'::jsonb);
SELECT roundtrip('{"1": 1}'::jsonb);
SELECT roundtrip('{"1": true}'::jsonb);
SELECT roundtrip('{"1": "string"}'::jsonb);

SELECT roundtrip('[null]'::jsonb);
SELECT roundtrip('[1]'::jsonb);
SELECT roundtrip('[true]'::jsonb);
SELECT roundtrip('["string"]'::jsonb);
SELECT roundtrip('[null, 1]'::jsonb);
SELECT roundtrip('[1, true]'::jsonb);
SELECT roundtrip('[true, "string"]'::jsonb);
SELECT roundtrip('["string", "string2"]'::jsonb);

-- complex numbers -> jsonb
CREATE FUNCTION testComplexNumbers() RETURNS jsonb
LANGUAGE plpython3u
TRANSFORM FOR TYPE jsonb
AS $$
x = 1 + 2j
return x
$$;

SELECT testComplexNumbers();

-- range -> jsonb
CREATE FUNCTION testRange() RETURNS jsonb
LANGUAGE plpython3u
TRANSFORM FOR TYPE jsonb
AS $$
x = range(3)
return x
$$;

SELECT testRange();

-- 0xff -> jsonb
CREATE FUNCTION testDecimal() RETURNS jsonb
LANGUAGE plpython3u
TRANSFORM FOR TYPE jsonb
AS $$
x = 0xff
return x
$$;

SELECT testDecimal();

-- tuple -> jsonb
CREATE FUNCTION testTuple() RETURNS jsonb
LANGUAGE plpython3u
TRANSFORM FOR TYPE jsonb
AS $$
x = (1, 'String', None)
return x
$$;

SELECT testTuple();

-- interesting dict -> jsonb
CREATE FUNCTION test_dict1() RETURNS jsonb
LANGUAGE plpython3u
TRANSFORM FOR TYPE jsonb
AS $$
x = {"a": 1, None: 2, 33: 3}
return x
$$;

SELECT test_dict1();

-- eval arbitrary Python code on jsonb
CREATE OR REPLACE FUNCTION jsonb_plpy_eval(js jsonb, code text) RETURNS jsonb
LANGUAGE plpythonu
TRANSFORM FOR TYPE jsonb
AS $$
  try:
    return eval(code, { '_' : js })
  except Exception as ex:
    raise ex
$$;

-- test array type
SELECT jsonb_plpy_eval('[]', 'type(_)');

-- test len() for arrays
SELECT jsonb_plpy_eval('[]', 'len(_)');
SELECT jsonb_plpy_eval('[1, "2", {"a": 1}]', 'len(_)');

-- test array subscripting
SELECT jsonb_plpy_eval('[]', '_[0]');
SELECT jsonb_plpy_eval('[1]', '_["0"]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[0]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[1]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[2]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[3]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[-1]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[-2]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[-3]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[-4]');

-- test array slicing
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[:]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[:1]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[:5]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[1:]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[5:]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[0:0]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[1:3]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[0:-1]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[0:4:2]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[::-1]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[1::-1]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[-2::-1]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[:-3:-1]');
SELECT jsonb_plpy_eval('[1, "2", {"a": 3}]', '_[-1:1:-1]');

-- test array .count() method
SELECT jsonb_plpy_eval('[1, 2, null, 1, [1, 5], 1, "1"]', '_.count(1)');
SELECT jsonb_plpy_eval('[1, 2, null, 1, [1, 5], 1, "1"]', '_.count("x")');
SELECT jsonb_plpy_eval('[1, 2, null, 1, [1, 5], 1, "1"]', '_.count([1, 5])');
SELECT jsonb_plpy_eval('[1, 2, null, 1, [1, 5], 1, "1"]', '_.count([5, 1])');

-- test array .index() method
SELECT jsonb_plpy_eval('[1, 2, null, 1, [1, 5], 1, "1"]', '_.index(0)');
SELECT jsonb_plpy_eval('[1, 2, null, 1, [1, 5], 1, "1"]', '_.index(1)');
SELECT jsonb_plpy_eval('[1, 2, null, 1, [1, 5], 1, "1"]', '_.index(2)');
SELECT jsonb_plpy_eval('[1, 2, null, 1, [1, 5], 1, "1"]', '_.index(None)');
SELECT jsonb_plpy_eval('[1, 2, null, 1, [1, 5], 1, "1"]', '_.index("1")');
SELECT jsonb_plpy_eval('[1, 2, null, 1, [1, 5], 1, "1"]', '_.index([1, 5])');

-- test array iteration
SELECT jsonb_plpy_eval('[]', 'type(iter(_))');
SELECT jsonb_plpy_eval('[1, 2, null, 1, [1, 5], 1, "1"]', 'iter(_)');
SELECT jsonb_plpy_eval('[1, 2, null, 1, [1, 5], 1, "1"]', '[x for x in _]');
SELECT jsonb_plpy_eval('[1, 2, null, 1, [1, 5], 1, "1"]', '[x for x in iter(_)]');
SELECT jsonb_plpy_eval('[1, 2, null, 1, [1, 5], 1, "1"]', '[x for x in _ if x > 1]');


-- test object subscription
SELECT jsonb_plpy_eval('{}', '_[0]');
SELECT jsonb_plpy_eval('{}', '_["a"]');
SELECT jsonb_plpy_eval('{"a": 123}', '_["a"]');

-- test '"key" in object'
SELECT jsonb_plpy_eval('{"a": 123}', '"a" in _');
SELECT jsonb_plpy_eval('{"a": 123}', '"b" in _');
SELECT jsonb_plpy_eval('{"a": 123}', '123 in _');

-- test object .get() method
SELECT jsonb_plpy_eval('{"a": 123}', '_.get("a")');
SELECT jsonb_plpy_eval('{"a": 123}', '_.get(1)');
SELECT jsonb_plpy_eval('{"a": 123}', '_.get(1) == None');
SELECT jsonb_plpy_eval('{"a": 123}', '_.get(1)');
SELECT jsonb_plpy_eval('{"a": 123}', '_.get(1, "default")');

-- test object .keys() methods
SELECT jsonb_plpy_eval('{"a": 1, "aa": ["x", false], "b": {"y": "aaa", "z": 2.3}}', '_.keys()');
-- test object .values() methods
SELECT jsonb_plpy_eval('{"a": 1, "aa": ["x", false], "b": {"y": "aaa", "z": 2.3}}', '_.values()');
-- test object .items() methods
SELECT jsonb_plpy_eval('{"a": 1, "aa": ["x", false], "b": {"y": "aaa", "z": 2.3}}', '_.items()');


-- test object iteration by keys
SELECT jsonb_plpy_eval('{}', 'type(iter(_))');
SELECT jsonb_plpy_eval('{}', 'iter(_)');
SELECT jsonb_plpy_eval('{"a": 1, "b": null, "c": "xyz", "d": [4, 5], "e": {"x": 1, "y": "aaa"}}', 'iter(_)');
SELECT jsonb_plpy_eval('{"a": 1, "b": null, "c": "xyz", "d": [4, 5], "e": {"x": 1, "y": "aaa"}}', '[k for k in _]');

-- test object .iterkeys() method
SELECT jsonb_plpy_eval('{}', 'type(_.iterkeys())');
SELECT jsonb_plpy_eval('{"a": 1, "aaa": null, "b": "xyz", "cc": [4, 5], "d": {"x": 1, "y": "aaa"}}', '_.iterkeys()');

-- test object .itervalues() method
SELECT jsonb_plpy_eval('{}', 'type(_.itervalues())');
SELECT jsonb_plpy_eval('{"a": 1, "aaa": null, "b": "xyz", "cc": [4, 5], "d": {"x": 1, "y": "aaa"}}', '_.itervalues()');

-- test object .iteritems() method
SELECT jsonb_plpy_eval('{}', 'type(_.iteritems())');
SELECT jsonb_plpy_eval('{"a": 1, "aaa": null, "b": "xyz", "cc": [4, 5], "d": {"x": 1, "y": "aaa"}}', '_.iteritems()');
SELECT jsonb_plpy_eval('{"a": 1, "aaa": null, "b": "xyz", "cc": [4, 5], "d": {"x": 1, "y": "aaa"}}', '[str(i) for i in _.iteritems()]');
SELECT jsonb_plpy_eval('{"a": 1, "aaa": null, "b": "xyz", "cc": [4, 5], "d": {"x": 1, "y": "aaa"}}', '[(v, k) for (k, v) in _.iteritems()]');

-- test comparison
SELECT jsonb_plpy_eval('{"a": 1}', '_ == _');

SELECT a, jsonb_plpy_eval('1.25', 'next([cmp(_, a), _ > a, _ >= a, _ == a, _ != a,  _ <= a, _ < a] for a in [' || a || '])')
FROM (VALUES ('1'), ('1.25'), ('"1.25"'), ('{}'), ('[]')) a(a);

SELECT a, jsonb_plpy_eval('[1, 2, 3]', 'next([cmp(_, a), _ > a, _ >= a, _ == a, _ != a,  _ <= a, _ < a] for a in [' || a || '])')
FROM (VALUES ('1'), ('[]'), ('{}'), ('[1]'), ('[2]'), ('[1,2,3]'), ('[1,2,4]'), ('[1,2,2]'), ('[1,2,2,5]')) a(a);

SELECT a, jsonb_plpy_eval('{"a": 1}', 'next([cmp(_, a), _ > a, _ >= a, _ == a, _ != a,  _ <= a, _ < a] for a in [' || a || '])')
FROM (VALUES ('1'), ('[]'), ('{}'), ('{None : 1}'), ('{"a" : 0}'), ('{"a": 1}'), ('{"a": 2}'), ('{"b": 1}'), ('{"0": 1}'), ('{"a": 0, "b": 0}')) a(a);

SELECT a, jsonb_plpy_eval('{"a": 1}', 'next([cmp(_, a), a > _, a >= _, a == _, a != _, a <= _, a < _] for a in [' || a || '])')
FROM (VALUES ('1'), ('[]'), ('{}'), ('{"a" : 0}'), ('{"a": 1}'), ('{"a": 2}'), ('{"a": 0, "b": 0}')) a(a);

SELECT a, jsonb_plpy_eval('{"b": 1, "d": 2}', 'next([cmp(_, a), _ > a, _ >= a, _ == a, _ != a, _ <= a, _ < a] for a in [' || a || '])')
FROM (VALUES
  ('{}'),
  ('{"x" : 3}'),
  ('{"b": 1, "d": 2}'),
  ('{"b": 0, "d": 3}'),
  ('{"b": 1, "d": 3}'),
  ('{"b": 1, "e": 2}'),
  ('{"b": 0, "e": 2}'),
  ('{"b": 1, "c": 1}'),
  ('{"b": 0, "c": 1}'),
  ('{"a": 3, "d": 2}'),
  ('{"c": 0, "d": 2}')
) a(a);
