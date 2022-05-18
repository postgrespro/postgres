ALTER OPERATOR FAMILY gist__ltree_ops USING gist ADD
		OPERATOR	1  &&(anyarray, anyarray);

--GIN

CREATE FUNCTION ginltree_extract(ltree, internal)
	RETURNS internal AS 'MODULE_PATHNAME'
	LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION ginltree_queryextract(ltree, internal, int2, internal, internal, internal, internal)
	RETURNS internal AS 'MODULE_PATHNAME'
	LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION ginltree_cmp_prefix(ltree, ltree, smallint,internal)
	RETURNS int4 AS 'MODULE_PATHNAME'
	LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION ginltree_consistent(internal, int2, ltree, int4, internal, internal)
	RETURNS bool AS 'MODULE_PATHNAME'
	LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE OPERATOR CLASS gin_ltree_ops
DEFAULT FOR TYPE ltree USING gin AS
	OPERATOR	3   =,
	OPERATOR	10  @>,
	OPERATOR	11  <@,
	OPERATOR	12	~ (ltree, lquery),
	OPERATOR	13	~ (lquery, ltree),
	FUNCTION	1	ltree_cmp(ltree,ltree),
	FUNCTION	2 	ginltree_extract(ltree, internal),
	FUNCTION	3	ginltree_queryextract(ltree, internal, int2, internal,
										  internal, internal, internal),
	FUNCTION	4	ginltree_consistent(internal, int2, ltree, int4, internal, internal),
	FUNCTION	5	ginltree_cmp_prefix(ltree, ltree, smallint,internal),
	STORAGE		ltree;

CREATE FUNCTION ginltree_queryextract(_ltree, internal, int2, internal, internal, internal, internal)
	RETURNS internal AS 'MODULE_PATHNAME'
	LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION ginltree_consistent(internal, smallint, _ltree, int4, internal, internal)
	RETURNS bool AS 'MODULE_PATHNAME'
	LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE OPERATOR CLASS gin__ltree_ops
DEFAULT FOR TYPE _ltree USING gin AS
	OPERATOR	1  &&(anyarray, anyarray),
	OPERATOR	10  @>(_ltree, ltree),
	OPERATOR	11  <@ (_ltree,ltree),
	OPERATOR	12  ~ (_ltree, lquery),
	OPERATOR	13  ~ (lquery, _ltree),
	FUNCTION	1   ltree_cmp(ltree,ltree),
	FUNCTION	2   ginarrayextract(anyarray, internal),
	FUNCTION	3   ginltree_queryextract(_ltree, internal, int2, internal,
										  internal, internal, internal),
	FUNCTION	4   ginltree_consistent(internal, smallint, _ltree, int4, internal, internal),
	FUNCTION	5   ginltree_cmp_prefix(ltree, ltree, smallint,internal),
	STORAGE	 ltree;

--SP-GiST

CREATE FUNCTION spg_ltree_config(internal, internal)
	RETURNS void AS 'MODULE_PATHNAME'
	LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION spg_ltree_choose(internal, internal)
	RETURNS void AS 'MODULE_PATHNAME'
	LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION spg_ltree_picksplit(internal, internal)
	RETURNS void AS 'MODULE_PATHNAME'
	LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION spg_ltree_inner_consistent(internal, internal)
	RETURNS void AS 'MODULE_PATHNAME'
	LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION spg_ltree_leaf_consistent(internal, internal)
	RETURNS bool AS 'MODULE_PATHNAME'
	LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE OPERATOR CLASS spgist_ltree_ops
	DEFAULT FOR TYPE ltree USING spgist AS
	OPERATOR	3   = (ltree, ltree),
	OPERATOR	10  @>(ltree, ltree),
	OPERATOR	11  <@ (ltree,ltree),
	FUNCTION	1   spg_ltree_config(internal, internal),
	FUNCTION	2   spg_ltree_choose(internal, internal),
	FUNCTION	3   spg_ltree_picksplit(internal, internal),
	FUNCTION	4   spg_ltree_inner_consistent(internal, internal),
	FUNCTION	5   spg_ltree_leaf_consistent(internal, internal),
	STORAGE	 ltree;

