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
#include "utils/jsonb.h"
#include "utils/memutils.h"

static Json *JsonExpand(Json *tmp, Datum value, bool freeValue,
						JsonContainerOps *ops);

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

JsonValue *
JsonToJsonValue(Json *json, JsonValue *jv)
{
	if (!jv)
		jv = palloc(sizeof(JsonValue));

	return JsonValueInitBinary(jv, &json->root);
}

static void
JsonInit(Json *json)
{
	const void *data = DatumGetPointer(json->obj.value);
	struct varlena *detoasted_data;

	Assert(JsonContainerDataPtr(&json->root) || data);

	if (JsonContainerDataPtr(&json->root) || !data) /* FIXME */
		return;

	detoasted_data = PG_DETOAST_DATUM(json->obj.value);
	json->obj.value = PointerGetDatum(detoasted_data);
	json->obj.freeValue |= data != detoasted_data;

	json->root.ops->init(&json->root, json->obj.value);
}

static Json *
JsonExpand(Json *tmp, Datum value, bool freeValue, JsonContainerOps *ops)
{
	Json		   *json = tmp ? tmp : (Json *) palloc(JsonAllocSize(ops->data_size));

	json->obj.value = value;
	json->obj.freeValue = freeValue;
	json->obj.isTemporary = tmp != NULL;
	json->root.len = 0;
	json->root.ops = ops;
	json->root.size = -1;
	json->root.type = jbvBinary;
	json->is_json = false;

	memset(json->root._data, 0, ops->data_size);

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
JsonValueToJson(JsonValue *val)
{
	if (val->type == jbvBinary)
	{
		JsonContainer *jc = val->val.binary.data;
		Json	   *json = JsonExpand(NULL, PointerGetDatum(NULL), false,
									  jc->ops);

		json->root = *jc;
		memcpy(json->root._data, jc->_data, jc->ops->data_size);

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
	JsonContainerData *res = JsonContainerAlloc(jc->ops);

	*res = *jc;
	JsonContainerDataPtr(res) = palloc(jc->len);
	memcpy(JsonContainerDataPtr(res), JsonContainerDataPtr(jc), jc->len);

	return res;
}
