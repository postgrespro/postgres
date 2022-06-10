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

Json *
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
JsonbValueToOrigJsonbDatum2(JsonValue *val, JsonContainer *orig_json)
{
	if (val->type != jbvBinary && orig_json && orig_json->ops->encode)
	{
		void	   *res =
			orig_json->ops->encode(val, &jsonbContainerOps, orig_json->toasterid);

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

typedef struct JsonbMutatorCommon
{
	JsonbParseState **ps;
	JsonbParseState *pstate;
	JsonbIterator *iter;
} JsonbMutatorCommon;

typedef struct JsonbObjectMutator
{
	JsonObjectMutator mutator;
	JsonbMutatorCommon common;
	JsonbValue	cur_key;
} JsonbObjectMutator;

typedef struct JsonbArrayMutator
{
	JsonArrayMutator mutator;
	JsonbMutatorCommon common;
	int			cur_index;
} JsonbArrayMutator;

static JsonArrayMutator *
JsonArrayMutatorInitGenericExt(JsonbContainer *jc, JsonbParseState **ps, JsonMutator *parent);

static JsonObjectMutator *
JsonObjectMutatorInitGenericExt(JsonbContainer *jc, JsonbParseState **ps, JsonMutator *parent);

static JsonbValue *
jsonbMutatorReplaceCurrent(JsonMutator *mut, JsonbValue *val)
{
	JsonbParseState **ps = mut->cur_key
		? ((JsonbObjectMutator *) mut)->common.ps
		: ((JsonbArrayMutator *) mut)->common.ps;

	mut->cur_exists = false;

	if (val)
		return pushJsonbKeyValue(ps, mut->cur_key, val);
	else
		return NULL;
}

static void
jsonbObjectMutatorInsert(JsonObjectMutator *mut, JsonbValue *key, JsonbValue *val)
{
	pushJsonbKeyValue(((JsonbObjectMutator *) mut)->common.ps, key, val);
}

static void
jsonbArrayMutatorInsert(JsonArrayMutator *mut, JsonbValue *val)
{
	pushJsonbKeyValue(((JsonbArrayMutator *) mut)->common.ps, NULL, val);
}

static JsonObjectMutator *
jsonbObjectMutatorOpen(JsonMutator *mut)
{
	JsonbContainer *jc = mut->cur_exists ? mut->cur_val.val.binary.data : NULL;
	JsonbParseState **ps = mut->cur_key
		? ((JsonbObjectMutator *) mut)->common.ps
		: ((JsonbArrayMutator *) mut)->common.ps;

	Assert(!mut->cur_exists || mut->cur_val.type == jbvBinary);

	if (!jc || jc->ops->initObjectMutator == JsonObjectMutatorInitGeneric)
	{
		if (mut->cur_key)
			pushJsonbValue(ps, WJB_KEY, mut->cur_key);

		mut->cur_exists = false;

		return JsonObjectMutatorInitGenericExt(jc, ps, NULL);
	}

	return JsonObjectMutatorInit(jc, mut);
}

static JsonArrayMutator *
jsonbArrayMutatorOpen(JsonMutator *mut)
{
	JsonbContainer *jc = mut->cur_exists ? mut->cur_val.val.binary.data : NULL;
	JsonbParseState **ps = mut->cur_key
		? ((JsonbObjectMutator *) mut)->common.ps
		: ((JsonbArrayMutator *) mut)->common.ps;

	if (mut->cur_exists && mut->cur_val.type != jbvBinary)
	{
		Assert(mut->cur_val.type != jbvArray);
		elog(ERROR, "invalid jsonb array value type: %d", mut->cur_val.type);
	}

	if (!jc || jc->ops->initArrayMutator == JsonArrayMutatorInitGeneric)
	{
		mut->cur_exists = false;

		if (mut->cur_key)
			pushJsonbValue(ps, WJB_KEY, mut->cur_key);

		return JsonArrayMutatorInitGenericExt(jc, ps, NULL);
	}

	return JsonArrayMutatorInit(jc, mut);
}

static JsonbValue *
jsonbRootMutatorReplaceCurrent(JsonMutator *mut, JsonbValue *val)
{
	mut->cur_exists = val != NULL;

	if (val)
	{
		JsonbParseState *ps = NULL;

		mut->cur_val = *val;

		return pushJsonbKeyValue(&ps, NULL, val);
	}
	else
	{
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE), /* XXX */
				 errmsg("cannor remove root jsonb value")));

		return NULL;
	}
}

static JsonObjectMutator *
jsonbRootObjectMutatorOpen(JsonMutator *mut)
{
	Assert(mut->cur_exists);

	if (mut->cur_val.type != jbvBinary)
	{
		Assert(mut->cur_val.type != jbvObject);
		elog(ERROR, "invalid jsonb object value type: %d", mut->cur_val.type);
	}

	return JsonObjectMutatorInit(mut->cur_val.val.binary.data, mut);
}

static JsonArrayMutator *
jsonbRootArrayMutatorOpen(JsonMutator *mut)
{
	Assert(mut->cur_exists);

	if (mut->cur_val.type != jbvBinary)
	{
		Assert(mut->cur_val.type != jbvArray);
		elog(ERROR, "invalid jsonb array value type: %d", mut->cur_val.type);
	}

	return JsonArrayMutatorInit(mut->cur_val.val.binary.data, mut);
}

JsonMutator *
JsonMutatorInit(JsonValue *jbv)
{
	JsonMutator *mutator = palloc0(sizeof(*mutator));

	mutator->parent = NULL;
	mutator->type = JsonbType(jbv);
	mutator->cur_val = *jbv;
	mutator->cur_key = NULL;
	mutator->cur_exists = true;
	mutator->replace = jsonbRootMutatorReplaceCurrent;
	mutator->openObject = jsonbRootObjectMutatorOpen;
	mutator->openArray = jsonbRootArrayMutatorOpen;

	return mutator;
}

static bool
jsonbObjectMutatorNext(JsonObjectMutator *mut, JsonbValue *key)
{
	JsonbObjectMutator *jbmut = (JsonbObjectMutator *) mut;
	JsonbIteratorToken tok;

	if (mut->mutator.cur_exists)
		pushJsonbKeyValue(jbmut->common.ps, &jbmut->cur_key, &mut->mutator.cur_val);

	tok = JsonbIteratorNext(&jbmut->common.iter, &jbmut->cur_key, true);

	if (tok != WJB_KEY)
	{
		Assert(tok == WJB_END_OBJECT);
		tok = JsonbIteratorNext(&jbmut->common.iter, &jbmut->cur_key, true);
		Assert(tok == WJB_DONE);

		jbmut->common.iter = NULL;
		mut->mutator.cur_exists = false;

		return false;
	}

	tok = JsonbIteratorNext(&jbmut->common.iter, &mut->mutator.cur_val, true);
	Assert(tok == WJB_VALUE);

	mut->mutator.cur_exists = true;
	*key = jbmut->cur_key;

	return true;
}

static bool
jsonbArrayMutatorNext(JsonArrayMutator *mut)
{
	JsonbArrayMutator *jbmut = (JsonbArrayMutator *) mut;
	JsonbIteratorToken tok;

	if (!jbmut->common.iter)
		return false;

	if (mut->mutator.cur_exists)
		pushJsonbKeyValue(jbmut->common.ps, NULL, &mut->mutator.cur_val);

	mut->cur_index++;

	tok = JsonbIteratorNext(&jbmut->common.iter, &mut->mutator.cur_val, true);

	if (tok != WJB_ELEM)
	{
		Assert(tok == WJB_END_ARRAY);
		tok = JsonbIteratorNext(&jbmut->common.iter, &mut->mutator.cur_val, true);
		Assert(tok == WJB_DONE);

		jbmut->common.iter = NULL;
		mut->mutator.cur_exists = false;

		return false;
	}

	mut->mutator.cur_exists = true;

	return true;
}

static bool
jsonbObjectMutatorFindKey(JsonObjectMutator *mut, JsonbValue *key)
{
	JsonbObjectMutator *jbmut = (JsonbObjectMutator *) mut;
	JsonbValue	jbv_key;

	while (jsonbObjectMutatorNext(mut, &jbv_key))
	{
		int			cmp = lengthCompareJsonbString(jbv_key.val.string.val,
												   jbv_key.val.string.len,
												   key->val.string.val,
												   key->val.string.len);
		if (!cmp)
			return true;
	}

	jbmut->cur_key = *key;
	mut->mutator.cur_exists = false;

	return false;
}

static bool
jsonbArrayMutatorFind(JsonArrayMutator *mut, int index)
{
	if (mut->cur_index > index)
		return false;

	while (mut->cur_index < index)
	{
		if (!JsonArrayMutatorNext(mut))
			return false;
	}

	return true;
}

static void
jsonbArrayMutatorFindLast(JsonArrayMutator *mut)
{
	while (JsonArrayMutatorNext(mut))
		continue;
}

static JsonbValue *
jsonbObjectMutatorClose(JsonObjectMutator *mut)
{
	JsonbObjectMutator *jbmut = (JsonbObjectMutator *) mut;
	JsonbValue *res;

	if (mut->mutator.cur_exists)
	{
		pushJsonbKeyValue(jbmut->common.ps, &jbmut->cur_key, &mut->mutator.cur_val);
		mut->mutator.cur_exists = false;
	}

	if (jbmut->common.iter)
		while (jsonbObjectMutatorNext(mut, &jbmut->cur_key))
			continue;

	res = pushJsonbValue(jbmut->common.ps, WJB_END_OBJECT, NULL);

	if (mut->mutator.parent)
		JsonMutatorReplaceCurrent(mut->mutator.parent, res);

	return res;
}

static JsonbValue *
jsonbArrayMutatorClose(JsonArrayMutator *mut)
{
	JsonbArrayMutator *jbmut = (JsonbArrayMutator *) mut;
	JsonbValue *res;

	if (mut->mutator.cur_exists)
	{
		pushJsonbKeyValue(jbmut->common.ps, NULL, &mut->mutator.cur_val);
		mut->mutator.cur_exists = false;
	}

	if (jbmut->common.iter)
		while (jsonbArrayMutatorNext(mut))
			continue;

	res = pushJsonbValue(jbmut->common.ps, WJB_END_ARRAY, NULL);

	if (mut->mutator.parent)
		JsonMutatorReplaceCurrent(mut->mutator.parent, res);

	return res;
}

static JsonObjectMutator *
JsonObjectMutatorInitGenericExt(JsonbContainer *jc, JsonbParseState **ps,
								JsonMutator *parent)
{
	JsonbObjectMutator *mut = palloc0(sizeof(*mut));

	mut->mutator.mutator.parent = parent;
	mut->mutator.mutator.type = jbvObject;
	mut->mutator.mutator.cur_key = &mut->cur_key;
	mut->mutator.mutator.cur_exists = false;
	mut->mutator.mutator.replace = jsonbMutatorReplaceCurrent;
	mut->mutator.mutator.openObject = jsonbObjectMutatorOpen;
	mut->mutator.mutator.openArray = jsonbArrayMutatorOpen;

	mut->mutator.next = jsonbObjectMutatorNext;
	mut->mutator.find = jsonbObjectMutatorFindKey;
	mut->mutator.insert = jsonbObjectMutatorInsert;
	mut->mutator.close = jsonbObjectMutatorClose;

	if (!ps)
		ps = &mut->common.pstate;

	mut->common.ps = ps;
	mut->common.iter = NULL;

	if (jc)
	{
		JsonbIteratorToken tok PG_USED_FOR_ASSERTS_ONLY;
		JsonbValue jbv;

		mut->common.iter = JsonbIteratorInit(jc);
		tok = JsonbIteratorNext(&mut->common.iter, &jbv, true);
		Assert(tok == WJB_BEGIN_OBJECT);
	}

	pushJsonbValue(mut->common.ps, WJB_BEGIN_OBJECT, NULL);

	return &mut->mutator;
}

JsonObjectMutator *
JsonObjectMutatorInitGeneric(JsonbContainer *jc, JsonMutator *parent)
{
	return JsonObjectMutatorInitGenericExt(jc, NULL, parent);
}

static JsonArrayMutator *
JsonArrayMutatorInitGenericExt(JsonbContainer *jc, JsonbParseState **ps, JsonMutator *parent)
{
	JsonbArrayMutator *mut = palloc0(sizeof(*mut));

	mut->mutator.mutator.parent = parent;
	mut->mutator.mutator.type = jbvArray;
	mut->mutator.mutator.cur_key = NULL;
	mut->mutator.mutator.cur_exists = false;
	mut->mutator.mutator.replace = jsonbMutatorReplaceCurrent;
	mut->mutator.mutator.openObject = jsonbObjectMutatorOpen;
	mut->mutator.mutator.openArray = jsonbArrayMutatorOpen;

	mut->mutator.next = jsonbArrayMutatorNext;
	mut->mutator.find = jsonbArrayMutatorFind;
	mut->mutator.last = jsonbArrayMutatorFindLast;
	mut->mutator.insert = jsonbArrayMutatorInsert;
	mut->mutator.close = jsonbArrayMutatorClose;
	mut->mutator.cur_index = -1;

	if (!ps)
		ps = &mut->common.pstate;

	mut->common.ps = ps;
	mut->common.iter = NULL;

	if (jc)
	{
		JsonbIteratorToken tok PG_USED_FOR_ASSERTS_ONLY;
		JsonbValue	jbv;

		mut->common.iter = JsonbIteratorInit(jc);
		tok = JsonbIteratorNext(&mut->common.iter, &jbv, true);
		Assert(tok == WJB_BEGIN_ARRAY);
	}

	pushJsonbValue(ps, WJB_BEGIN_ARRAY, NULL);

	return &mut->mutator;
}

JsonArrayMutator *
JsonArrayMutatorInitGeneric(JsonbContainer *jc, JsonMutator *parent)
{
	return JsonArrayMutatorInitGenericExt(jc, NULL, parent);
}
