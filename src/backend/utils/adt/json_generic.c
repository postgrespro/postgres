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
