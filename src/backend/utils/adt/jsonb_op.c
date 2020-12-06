/*-------------------------------------------------------------------------
 *
 * jsonb_op.c
 *	 Special operators for jsonb only, used by various index access methods
 *
 * Copyright (c) 2014-2021, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/utils/adt/jsonb_op.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/jsonb.h"
#include "utils/json_generic.h"

static bool
json_exists_internal(Json *jb, text *key)
{
	JsonbValue	kval;
	JsonbValue *v = NULL;

	/*
	 * We only match Object keys (which are naturally always Strings), or
	 * string elements in arrays.  In particular, we do not match non-string
	 * scalar elements.  Existence of a key/element is only considered at the
	 * top level.  No recursion occurs.
	 */
	kval.type = jbvString;
	kval.val.string.val = VARDATA_ANY(key);
	kval.val.string.len = VARSIZE_ANY_EXHDR(key);

	v = findJsonbValueFromContainer(&jb->root,
									JB_FOBJECT | JB_FARRAY,
									&kval);

	return v != NULL;
}

Datum
jsonb_exists(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(json_exists_internal(PG_GETARG_JSONB_P(0),
										PG_GETARG_TEXT_PP(1)));
}

Datum
json_exists(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(json_exists_internal(PG_GETARG_JSONT_P(0),
										PG_GETARG_TEXT_PP(1)));
}

static bool
json_exists_any_internal(Jsonb *jb, ArrayType *keys)
{
	int			i;
	Datum	   *key_datums;
	bool	   *key_nulls;
	int			elem_count;

	deconstruct_array(keys, TEXTOID, -1, false, TYPALIGN_INT,
					  &key_datums, &key_nulls, &elem_count);

	for (i = 0; i < elem_count; i++)
	{
		JsonbValue	strVal;

		if (key_nulls[i])
			continue;

		strVal.type = jbvString;
		strVal.val.string.val = VARDATA(key_datums[i]);
		strVal.val.string.len = VARSIZE(key_datums[i]) - VARHDRSZ;

		if (findJsonbValueFromContainer(&jb->root,
										JB_FOBJECT | JB_FARRAY,
										&strVal) != NULL)
			return true;
	}

	return false;
}

Datum
jsonb_exists_any(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(json_exists_any_internal(PG_GETARG_JSONB_P(0),
											PG_GETARG_ARRAYTYPE_P(1)));
}

Datum
json_exists_any(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(json_exists_any_internal(PG_GETARG_JSONT_P(0),
											PG_GETARG_ARRAYTYPE_P(1)));
}

static bool
json_exists_all_internal(Jsonb *jb, ArrayType *keys)
{
	int			i;
	Datum	   *key_datums;
	bool	   *key_nulls;
	int			elem_count;

	deconstruct_array(keys, TEXTOID, -1, false, TYPALIGN_INT,
					  &key_datums, &key_nulls, &elem_count);

	for (i = 0; i < elem_count; i++)
	{
		JsonbValue	strVal;

		if (key_nulls[i])
			continue;

		strVal.type = jbvString;
		strVal.val.string.val = VARDATA(key_datums[i]);
		strVal.val.string.len = VARSIZE(key_datums[i]) - VARHDRSZ;

		if (findJsonbValueFromContainer(&jb->root,
										JB_FOBJECT | JB_FARRAY,
										&strVal) == NULL)
			return false;
	}

	return true;
}

Datum
jsonb_exists_all(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(json_exists_all_internal(PG_GETARG_JSONB_P(0),
											PG_GETARG_ARRAYTYPE_P(1)));
}

Datum
json_exists_all(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(json_exists_all_internal(PG_GETARG_JSONT_P(0),
											PG_GETARG_ARRAYTYPE_P(1)));
}

static bool
json_contains_internal(Json *val, Json *tmpl)
{
	if (JB_ROOT_IS_OBJECT(val) != JB_ROOT_IS_OBJECT(tmpl))
		return false;

	return JsonbDeepContains(JsonRoot(val), JsonRoot(tmpl));
}

Datum
jsonb_contains(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(json_contains_internal(PG_GETARG_JSONB_P(0),
										  PG_GETARG_JSONB_P(1)));
}

Datum
json_contains(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(json_contains_internal(PG_GETARG_JSONT_P(0),
										  PG_GETARG_JSONT_P(1)));
}

/* Commutator of "contains" */
Datum
jsonb_contained(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(json_contains_internal(PG_GETARG_JSONB_P(1),
										  PG_GETARG_JSONB_P(0)));
}

Datum
json_contained(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(json_contains_internal(PG_GETARG_JSONT_P(1),
										  PG_GETARG_JSONT_P(0)));
}

static int
jsonb_cmp_internal(FunctionCallInfo fcinfo)
{
	Jsonb	   *jba = PG_GETARG_JSONB_P(0);
	Jsonb	   *jbb = PG_GETARG_JSONB_P(1);
	int			res;

	res = compareJsonbContainers(&jba->root, &jbb->root);

	PG_FREE_IF_COPY_JSONB(jba, 0);
	PG_FREE_IF_COPY_JSONB(jbb, 1);

	return res;
}

static int
json_cmp_internal(FunctionCallInfo fcinfo)
{
	Json	   *jba = PG_GETARG_JSONT_P(0);
	Json	   *jbb = PG_GETARG_JSONT_P(1);
	int			res;

	res = compareJsonbContainers(&jba->root, &jbb->root);

	PG_FREE_IF_COPY_JSONB(jba, 0);
	PG_FREE_IF_COPY_JSONB(jbb, 1);

	return res;
}

Datum
jsonb_ne(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(jsonb_cmp_internal(fcinfo) != 0);
}

Datum
json_ne(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(json_cmp_internal(fcinfo) != 0);
}

/*
 * B-Tree operator class operators, support function
 */
Datum
jsonb_lt(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(jsonb_cmp_internal(fcinfo) < 0);
}

Datum
json_lt(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(json_cmp_internal(fcinfo) < 0);
}

Datum
jsonb_gt(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(jsonb_cmp_internal(fcinfo) > 0);
}

Datum
json_gt(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(json_cmp_internal(fcinfo) > 0);
}

Datum
jsonb_le(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(jsonb_cmp_internal(fcinfo) <= 0);
}

Datum
json_le(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(json_cmp_internal(fcinfo) <= 0);
}

Datum
jsonb_ge(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(jsonb_cmp_internal(fcinfo) >= 0);
}

Datum
json_ge(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(json_cmp_internal(fcinfo) >= 0);
}

Datum
jsonb_eq(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(jsonb_cmp_internal(fcinfo) == 0);
}

Datum
json_eq(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(json_cmp_internal(fcinfo) == 0);
}

Datum
jsonb_cmp(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT32(jsonb_cmp_internal(fcinfo));
}

Datum
json_cmp(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT32(json_cmp_internal(fcinfo));
}

static Datum
json_hash_internal(FunctionCallInfo fcinfo, bool is_jsonb)
{
	Json	   *jb = is_jsonb ? PG_GETARG_JSONB_P(0) : PG_GETARG_JSONT_P(0);
	JsonbIterator *it;
	JsonbValue	v;
	JsonbIteratorToken r;
	uint32		hash = 0;

	if (JB_ROOT_COUNT(jb) == 0)
	{
		PG_FREE_IF_COPY_JSONB(jb, 0);
		PG_RETURN_INT32(0);
	}

	it = JsonbIteratorInit(&jb->root);

	while ((r = JsonbIteratorNext(&it, &v, false)) != WJB_DONE)
	{
		switch (r)
		{
				/* Rotation is left to JsonbHashScalarValue() */
			case WJB_BEGIN_ARRAY:
				hash ^= JB_TARRAY;
				break;
			case WJB_BEGIN_OBJECT:
				hash ^= JB_TOBJECT;
				break;
			case WJB_KEY:
			case WJB_VALUE:
			case WJB_ELEM:
				JsonbHashScalarValue(&v, &hash);
				break;
			case WJB_END_ARRAY:
			case WJB_END_OBJECT:
				break;
			default:
				elog(ERROR, "invalid JsonbIteratorNext rc: %d", (int) r);
		}
	}

	PG_FREE_IF_COPY_JSONB(jb, 0);
	PG_RETURN_INT32(hash);
}

/*
 * Hash operator class jsonb hashing function
 */
Datum
jsonb_hash(PG_FUNCTION_ARGS)
{
	return json_hash_internal(fcinfo, true);
}

Datum
json_hash(PG_FUNCTION_ARGS)
{
	return json_hash_internal(fcinfo, false);
}

static Datum
json_hash_extended_internal(FunctionCallInfo fcinfo, bool is_jsonb)
{
	Json	   *jb = is_jsonb ? PG_GETARG_JSONB_P(0) : PG_GETARG_JSONT_P(0);
	uint64		seed = PG_GETARG_INT64(1);
	JsonbIterator *it;
	JsonbValue	v;
	JsonbIteratorToken r;
	uint64		hash = 0;

	if (JB_ROOT_COUNT(jb) == 0)
		PG_RETURN_UINT64(seed);

	it = JsonbIteratorInit(&jb->root);

	while ((r = JsonbIteratorNext(&it, &v, false)) != WJB_DONE)
	{
		switch (r)
		{
				/* Rotation is left to JsonbHashScalarValueExtended() */
			case WJB_BEGIN_ARRAY:
				hash ^= ((uint64) JB_TARRAY) << 32 | JB_TARRAY;
				break;
			case WJB_BEGIN_OBJECT:
				hash ^= ((uint64) JB_TOBJECT) << 32 | JB_TOBJECT;
				break;
			case WJB_KEY:
			case WJB_VALUE:
			case WJB_ELEM:
				JsonbHashScalarValueExtended(&v, &hash, seed);
				break;
			case WJB_END_ARRAY:
			case WJB_END_OBJECT:
				break;
			default:
				elog(ERROR, "invalid JsonbIteratorNext rc: %d", (int) r);
		}
	}

	PG_FREE_IF_COPY_JSONB(jb, 0);
	PG_RETURN_UINT64(hash);
}

Datum
jsonb_hash_extended(PG_FUNCTION_ARGS)
{
	return json_hash_extended_internal(fcinfo, true);
}

Datum
json_hash_extended(PG_FUNCTION_ARGS)
{
	return json_hash_extended_internal(fcinfo, false);
}
