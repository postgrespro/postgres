/*
 * json_generic.c
 *
 * Copyright (c) 2014-2016, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/utils/adt/json_generic.c
 *
 */

#include "postgres.h"

#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/json_generic.h"
#include "utils/memutils.h"

static Json *JsonExpand(Json *tmp, Datum value, bool freeValue,
						JsonContainerOps *ops);

JsonValue *
JsonValueCopy(JsonValue *res, const JsonValue *val)
{
	check_stack_depth();

	if (!res)
		res = (JsonValue *) palloc(sizeof(JsonValue));

	res->type = val->type;

	switch (val->type)
	{
		case jbvNull:
			break;

		case jbvBool:
			res->val.boolean = val->val.boolean;
			break;

		case jbvString:
		{	/* copy string values in the current context */
			char *buf = palloc(val->val.string.len + 1);
			memcpy(buf, val->val.string.val, val->val.string.len);
			buf[val->val.string.len] = 0;
			res->val.string.val = buf;
			res->val.string.len = val->val.string.len;
			break;
		}

		case jbvNumeric:
			/* same for numeric */
			res->val.numeric =
					DatumGetNumeric(DirectFunctionCall1(numeric_uplus,
											NumericGetDatum(val->val.numeric)));
			break;

		case jbvArray:
		{
			int i;

			res->val.array = val->val.array;
			res->val.array.elems = (JsonValue *)
							palloc(sizeof(JsonValue) * val->val.array.nElems);

			for (i = 0; i < val->val.array.nElems; i++)
				JsonValueCopy(&res->val.array.elems[i],
							  &val->val.array.elems[i]);

			break;
		}

		case jbvObject:
		{
			int i;

			res->val.object = val->val.object;
			res->val.object.pairs = (JsonPair *)
							palloc(sizeof(JsonPair) * val->val.object.nPairs);

			for (i = 0; i < val->val.object.nPairs; i++)
			{
				res->val.object.pairs[i].order = val->val.object.pairs[i].order;
				JsonValueCopy(&res->val.object.pairs[i].key,
							  &val->val.object.pairs[i].key);
				JsonValueCopy(&res->val.object.pairs[i].value,
							  &val->val.object.pairs[i].value);
			}

			break;
		}

		case jbvBinary:
			res->val.binary = val->val.binary;
			res->val.binary.data = JsonCopy(val->val.binary.data);
			break;

		default:
			elog(ERROR, "unknown json value type %d", val->type);
	}

	return res;
}

JsonValue *
JsonExtractScalar(JsonContainer *jc, JsonValue *scalar)
{
	JsonIterator   *it;
	JsonValue		val;

	Assert(JsonContainerIsScalar(jc));

	it = JsonIteratorInit(jc);

	if (JsonIteratorNext(&it, &val, false) != WJB_BEGIN_ARRAY ||
		JsonIteratorNext(&it, scalar, false) != WJB_ELEM ||
		JsonIteratorNext(&it, &val, false) != WJB_END_ARRAY)
		elog(ERROR, "unexpected structure of scalar json container");

	return scalar;
}

const JsonValue *
JsonValueUnwrap(const JsonValue *val, JsonValue *valbuf)
{
	if (val->type == jbvBinary)
	{
		JsonContainer *jc = val->val.binary.data;

		if (JsonContainerIsScalar(jc))
		{
			val = JsonExtractScalar(jc, valbuf);
			Assert(IsAJsonbScalar(val));
		}
	}

	if (val->type == jbvArray && val->val.array.rawScalar)
	{
		val = &val->val.array.elems[0];
		Assert(IsAJsonbScalar(val));
	}

	return val;
}

static inline JsonValue *
jsonFindKeyInObjectInternal(JsonContainer *obj, const char *key, int len,
							bool last)
{
	JsonValue		   *res = NULL;
	JsonValue			jbv;
	JsonIterator	   *it;
	JsonIteratorToken	tok;

	Assert(JsonContainerIsObject(obj));

	it = JsonIteratorInit(obj);

	while ((tok = JsonIteratorNext(&it, &jbv, true)) != WJB_DONE)
	{
		if (tok == WJB_KEY &&
			!lengthCompareJsonbString(key, len,
									  jbv.val.string.val, jbv.val.string.len))
		{
			if (!last || !res)
				res = palloc(sizeof(JsonValue));

			tok = JsonIteratorNext(&it, res, true);
			Assert(tok == WJB_VALUE);

			if (last)
				continue;

			JsonIteratorFree(it);
			break;
		}
	}

	return res;
}

JsonValue *
jsonFindKeyInObject(JsonContainer *obj, const char *key, int len)
{
	return jsonFindKeyInObjectInternal(obj, key, len, false);
}

JsonValue *
jsonFindLastKeyInObject(JsonContainer *obj, const char *key, int len)
{
	return jsonFindKeyInObjectInternal(obj, key, len, true);
}

JsonValue *
jsonFindValueInArray(JsonContainer *array, const JsonValue *elem)
{
	JsonValue		   *val = palloc(sizeof(JsonValue));
	JsonIterator	   *it;
	JsonIteratorToken	tok;

	Assert(JsonContainerIsArray(array));
	Assert(IsAJsonbScalar(elem));

	it = JsonIteratorInit(array);

	while ((tok = JsonIteratorNext(&it, val, true)) != WJB_DONE)
	{
		if (tok == WJB_ELEM && val->type == elem->type &&
			equalsJsonbScalarValue(val, elem))
		{
			JsonIteratorFree(it);
			return val;
		}
	}

	pfree(val);
	return NULL;
}

JsonValue *
jsonGetArrayElement(JsonContainer *array, uint32 index)
{
	JsonValue		   *val = palloc(sizeof(JsonValue));
	JsonIterator	   *it;
	JsonIteratorToken	tok;

	Assert(JsonContainerIsArray(array));

	it = JsonIteratorInit(array);

	while ((tok = JsonIteratorNext(&it, val, true)) != WJB_DONE)
	{
		if (tok == WJB_ELEM)
		{
			if (index-- == 0)
			{
				JsonIteratorFree(it);
				return val;
			}
		}
	}

	pfree(val);

	return NULL;
}

uint32
jsonGetArraySize(JsonContainer *array)
{
	JsonValue		    val;
	JsonIterator	   *it;
	JsonIteratorToken	tok;
	uint32				size = 0;

	Assert(JsonContainerIsArray(array));

	it = JsonIteratorInit(array);

	while ((tok = JsonIteratorNext(&it, &val, true)) != WJB_DONE)
	{
		if (tok == WJB_ELEM)
			size++;
	}

	return size;
}

JsonValue *
JsonToJsonValue(Json *json, JsonValue *jv)
{
	if (!jv)
		jv = palloc(sizeof(JsonValue));

	jv->type = jbvBinary;
	jv->val.binary.data = &json->root;

	return jv;
}

static void
JsonInit(Json *json)
{
	const void *data = DatumGetPointer(json->obj.value);
	struct varlena *detoasted_data;

	Assert(json->root.data || data);

	if (json->root.data || !data)
		return;

	detoasted_data = PG_DETOAST_DATUM(json->obj.value);
	json->obj.value = PointerGetDatum(detoasted_data);
	json->obj.freeValue |= data != detoasted_data;

	json->root.ops->init(&json->root, json->obj.value);
}

static Json *
JsonExpand(Json *tmp, Datum value, bool freeValue, JsonContainerOps *ops)
{
	Json		   *json = tmp ? tmp : (Json *) palloc(sizeof(Json));

	json->obj.value = value;
	json->obj.freeValue = freeValue;
	json->obj.isTemporary = tmp != NULL;
	json->root.data = NULL;
	json->root.len = 0;
	json->root.ops = ops;
	json->root.size = -1;
	json->root.type = jbvBinary;
	json->is_json = false;

	return json;
}

static Json *
JsonExpandDatum(Datum value, JsonContainerOps *ops, Json *tmp)
{
	struct varlena *toasted = (struct varlena *) DatumGetPointer(value);
	struct varlena *detoasted = pg_detoast_datum(toasted);
	Json	   *json = JsonExpand(tmp, PointerGetDatum(detoasted),
								  toasted != detoasted, ops);

	return json;
}

Json *
DatumGetJson(Datum value, JsonContainerOps *ops, Json *tmp)
{
	Json	   *json = JsonExpandDatum(value, ops, tmp);

	JsonInit(json);

	return json;
}

void
JsonFree(Json *json)
{
	if (json->obj.freeValue)
		pfree(DatumGetPointer(json->obj.value));

	if (!JsonIsTemporary(json))
		pfree(json);
}

Json *
JsonCopyTemporary(Json *tmp)
{
	Json *json = (Json *) palloc(sizeof(Json));

	memcpy(json, tmp, sizeof(Json));
	tmp->obj.freeValue = false;
	json->obj.isTemporary = false;

	return json;
}

Json *
JsonValueToJson(JsonValue *val)
{
	if (val->type == jbvBinary)
	{
		JsonContainer *jc = val->val.binary.data;
		Json	   *json = JsonExpand(NULL, PointerGetDatum(NULL), false,
									  jc->ops);

		json->root = *jc;
		return json;
	}
	else
	{
		void	   *jsonb = JsonValueToJsonb(val);

		return DatumGetJsonbP(PointerGetDatum(jsonb));
	}
}

JsonContainer *
JsonCopyFlat(JsonContainer *jc)
{
	JsonContainerData *res = JsonContainerAlloc();

	*res = *jc;
	res->data = palloc(jc->len);
	memcpy(res->data, jc->data, jc->len);

	return res;
}

JsonValue *
JsonContainerExtractKeys(JsonContainer *jsc)
{
	JsonIterator	   *it;
	JsonbParseState	   *state = NULL;
	JsonValue		   *res = NULL;
	JsonValue			val;
	JsonIteratorToken	tok;

	Assert(JsonContainerIsObject(jsc));

	it = JsonIteratorInit(jsc);

	while ((tok = JsonIteratorNext(&it, &val, false)) != WJB_DONE)
	{
		res = pushJsonbValue(&state, tok, tok < WJB_BEGIN_ARRAY ? &val : NULL);

		if (tok == WJB_KEY)
		{
			tok = JsonIteratorNext(&it, &val, true);
			Assert(tok == WJB_VALUE);
			pushJsonbValueScalar(&state, tok, &val);
		}
	}

	return res;
}
