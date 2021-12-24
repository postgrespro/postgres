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

#include "access/toasterapi.h"
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
	json->root.toasterid = InvalidOid;
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
	Json	   *json;

	if (VARATT_IS_CUSTOM(value))
	{
		Oid			toasterid = VARATT_CUSTOM_GET_TOASTERID(value);
		TsrRoutine *toaster = SearchTsrCache(toasterid);
		JsonToastRoutine *routine = toaster->get_vtable(toasterid);

		if (routine->magic == JSON_TOASTER_MAGIC)
		{
			json = JsonExpand(tmp, value, false, routine->ops);
			routine->ops->init(JsonRoot(json), value);

			return json;
		}
	}

	json = JsonExpandDatum(value, ops, tmp);
	json->root.ops->init(&json->root, json->obj.value);

	return json;
}

void
JsonFree(Json *json)
{
	JsonContainerFree(&json->root);

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

Datum
JsonbValueToOrigJsonbDatum(JsonValue *val, Json *orig_json)
{
	if (val->type != jbvBinary &&
		JsonRoot(orig_json)->ops->encode)
	{
		void	   *res = JsonRoot(orig_json)->ops->encode(val, &jsonbContainerOps);

		if (res)
			return PointerGetDatum(res);
	}

	return JsonValueToJsonbDatum(val);
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
