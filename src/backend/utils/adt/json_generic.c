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

static JsonContainerOps jsonvContainerOps;

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

static void
jsonvInitContainer(JsonContainerData *jc, const JsonValue *val)
{
	jc->ops = &jsonvContainerOps;
	jc->data = (void *) val;
	jc->len = 0;
	jc->size = val->type == jbvBinary ? val->val.binary.data->size :
			   val->type == jbvObject ? val->val.object.nPairs :
			   val->type == jbvArray  ? val->val.array.nElems : 1;
	jc->type = val->type == jbvBinary ? val->val.binary.data->type :
			   val->type == jbvObject ? jbvObject :
			   val->type == jbvArray && !val->val.array.rawScalar ? jbvArray :
										jbvArray | jbvScalar;
}

JsonContainer *
JsonValueToContainer(const JsonValue *val)
{
	if (val->type == jbvBinary)
		return val->val.binary.data;
	else
	{
		JsonContainerData *jc = palloc(sizeof(JsonContainerData));
		jsonvInitContainer(jc, val);
		return jc;
	}
}

typedef struct JsonvScalarIterator
{
	JsonIterator		ji;
	JsonIteratorToken	next;
} JsonvScalarIterator;

typedef struct JsonvArrayIterator
{
	JsonIterator	ji;
	int				index;
} JsonvArrayIterator;

typedef struct JsonvObjectIterator
{
	JsonIterator	ji;
	int				index;
	bool			value;
} JsonvObjectIterator;

static JsonIterator *
jsonvIteratorInitFromValue(JsonValue *val, JsonContainer *jsc);

static JsonIteratorToken
jsonvScalarIteratorNext(JsonIterator **it, JsonValue *res, bool skipNested)
{
	JsonvScalarIterator	*sit = (JsonvScalarIterator *) *it;
	JsonValue			*val = (*it)->container->data;

	Assert(IsAJsonbScalar(val));

	switch (sit->next)
	{
		case WJB_BEGIN_ARRAY:
			res->type = jbvArray;
			res->val.array.rawScalar = true;
			res->val.array.nElems = 1;
			res->val.array.elems = NULL;
			sit->next = WJB_ELEM;
			return WJB_BEGIN_ARRAY;

		case WJB_ELEM:
			*res = *val;
			sit->next = WJB_END_ARRAY;
			return WJB_ELEM;

		case WJB_END_ARRAY:
			sit->next = WJB_DONE;
			*it = JsonIteratorFreeAndGetParent(*it);
			return WJB_END_ARRAY;

		default:
			return WJB_DONE;
	}
}

static JsonIteratorToken
jsonvArrayIteratorNext(JsonIterator **it, JsonValue *res, bool skipNested)
{
	JsonvArrayIterator	*ait = (JsonvArrayIterator *) *it;
	JsonValue			*arr = (*it)->container->data;
	JsonValue			*val;

	Assert(arr->type == jbvArray);

	if (ait->index == -1)
	{
		ait->index = 0;
		*res = *arr;
		return WJB_BEGIN_ARRAY;
	}

	if (ait->index >= arr->val.array.nElems)
	{
		*it = JsonIteratorFreeAndGetParent(*it);
		return WJB_END_ARRAY;
	}

	val = &arr->val.array.elems[ait->index++]; /* FIXME palloced copy */
	*res = *val;

	if (!IsAJsonbScalar(res))
	{
		if (!skipNested)
		{
			JsonIterator *child = jsonvIteratorInitFromValue(val, NULL);
			child->parent = *it;
			*it = child;
			return WJB_RECURSE;
		}
		else if (res->type != jbvBinary)
		{
			Assert(res->type == jbvArray || res->type == jbvObject);
			res->val.binary.data = JsonValueToContainer(val);
			res->val.binary.len = 0;
			res->type = jbvBinary;
		}
	}

	return WJB_ELEM;
}

static JsonIteratorToken
jsonvObjectIteratorNext(JsonIterator **it, JsonValue *res, bool skipNested)
{
	JsonvObjectIterator	*oit = (JsonvObjectIterator *) *it;
	JsonValue			*obj = (*it)->container->data;
	JsonPair			*pair;

	Assert(obj->type == jbvObject);

	if (oit->index == -1)
	{
		oit->index = 0;
		*res = *obj;
		return WJB_BEGIN_OBJECT;
	}

	if (oit->index >= obj->val.object.nPairs)
	{
		*it = JsonIteratorFreeAndGetParent(*it);
		return WJB_END_OBJECT;
	}

	pair = &obj->val.object.pairs[oit->index];

	if (oit->value)
	{
		*res = pair->value;
		oit->value = false;
		oit->index++;

		if (!IsAJsonbScalar(res))
		{
			if (!skipNested)
			{
				JsonIterator *chld =
						jsonvIteratorInitFromValue(&pair->value, NULL);
				chld->parent = *it;
				*it = chld;
				return WJB_RECURSE;
			}
			else if (res->type != jbvBinary)
			{
				Assert(res->type == jbvArray || res->type == jbvObject);
				res->val.binary.data = JsonValueToContainer(&pair->value);
				res->val.binary.len = 0;
				res->type = jbvBinary;
			}
		}

		return WJB_VALUE;
	}
	else
	{
		*res = pair->key;
		oit->value = true;
		return WJB_KEY;
	}
}

static JsonIterator *
JsonIteratorCreate(Size size, JsonContainer *jsc, JsonIteratorNextFunc next)
{
	JsonIterator *it = (JsonIterator *) palloc(size);

	it->container = jsc;
	it->parent = NULL;
	it->next = next;

	return it;
}

static JsonIterator *
JsonvArrayIteratorInit(JsonValue *val, JsonContainer *jsc)
{
	JsonvArrayIterator *it = (JsonvArrayIterator *)
			JsonIteratorCreate(sizeof(JsonvArrayIterator),
							   jsc ? jsc : JsonValueToContainer(val),
							   jsonvArrayIteratorNext);
	it->index = -1;

	return &it->ji;

}

static JsonIterator *
JsonvObjectIteratorInit(JsonValue *val, JsonContainer *jsc)
{
	JsonvObjectIterator *it = (JsonvObjectIterator *)
			JsonIteratorCreate(sizeof(JsonvObjectIterator),
							   jsc ? jsc : JsonValueToContainer(val),
							   jsonvObjectIteratorNext);
	it->index = -1;
	it->value = false;

	return &it->ji;
}

static JsonIterator *
JsonvScalarIteratorInit(JsonValue *val, JsonContainer *jsc)
{
	JsonvScalarIterator *it = (JsonvScalarIterator *)
			JsonIteratorCreate(sizeof(JsonvScalarIterator),
							   jsc ? jsc : JsonValueToContainer(val),
							   jsonvScalarIteratorNext);

	it->next = WJB_BEGIN_ARRAY;

	return &it->ji;
}

static JsonIterator *
jsonvIteratorInitFromValue(JsonValue *val, JsonContainer *jsc)
{
	if (val->type == jbvObject)
		return JsonvObjectIteratorInit(val, jsc);
	else if (val->type == jbvArray)
		return JsonvArrayIteratorInit(val, jsc);
	else if (val->type == jbvBinary)
		return JsonIteratorInit(val->val.binary.data);
	else if (IsAJsonbScalar(val))
		return JsonvScalarIteratorInit(val, jsc);
	else
	{
		elog(ERROR, "unexpected json value container type: %d", val->type);
		return NULL;
	}
}

static JsonIterator *
jsonvIteratorInit(JsonContainer *jsc)
{
	return jsonvIteratorInitFromValue(jsc->data, jsc);
}

static JsonValue *
jsonvFindKeyInObject(JsonContainer *objc, const char *key, int len,
					 JsonValue *res)
{
	JsonValue  *obj = (JsonValue *) objc->data;
	int			i;

	Assert(JsonContainerIsObject(objc));

	if (obj->type == jbvBinary)
	{
		JsonContainer *jsc = obj->val.binary.data;
		Assert(jsc->type == jbvObject);
		return JsonFindKeyInObject(jsc, key, len, res);
	}

	Assert(obj->type == jbvObject);

	for (i = 0; i < obj->val.object.nPairs; i++)
	{
		JsonPair *pair = &obj->val.object.pairs[i];
		if (!lengthCompareJsonbString(key, len,
									  pair->key.val.string.val,
									  pair->key.val.string.len))
		{
			JsonValue  *jv = res ? res : palloc(sizeof(JsonValue));

			if (pair->value.type == jbvObject ||
				pair->value.type == jbvArray)
			{	/* FIXME need to wrap containers into binary JsonValue */
				JsonContainer *jc = JsonValueToContainer(&pair->value);

				jv->type = jbvBinary;
				jv->val.binary.data = jc;
				jv->val.binary.len = jc->len;
			}
			else
				*jv = pair->value;

			return jv;		/* XXX palloced copy? */
		}
	}

	return NULL;
}

static JsonValue *
jsonvFindValueInArray(JsonContainer *arrc, const JsonValue *val)
{
	JsonValue  *arr = (JsonValue *) arrc->data;

	Assert(JsonContainerIsArray(arrc));
	Assert(IsAJsonbScalar(val));

	if (arr->type == jbvBinary)
	{
		JsonContainer *jsc = arr->val.binary.data;
		Assert(JsonContainerIsArray(jsc));
		return (*jsc->ops->findValueInArray)(jsc, val);
	}
	else if (arr->type == jbvArray)
	{
		int	i;

		for (i = 0; i < arr->val.array.nElems; i++)
		{
			JsonValue *elem = &arr->val.array.elems[i];
			if (val->type == elem->type && equalsJsonbScalarValue(val, elem))
				return elem; /* FIXME palloced copy */
		}
	}
	else
	{
		Assert(IsAJsonbScalar(arr));
		if (arr->type == val->type && equalsJsonbScalarValue(val, arr))
			return arr;
	}

	return NULL;
}

static JsonValue *
jsonvGetArrayElement(JsonContainer *arrc, uint32 index)
{
	JsonValue  *arr = (JsonValue *) arrc->data;

	Assert(JsonContainerIsArray(arrc));

	if (arr->type == jbvBinary)
	{
		JsonContainer *jsc = arr->val.binary.data;
		Assert(jsc->type == jbvArray);
		return (*jsc->ops->getArrayElement)(jsc, index);
	}
	else if (arr->type == jbvArray)
	{
		if (index >= arr->val.array.nElems)
			return NULL;

		return &arr->val.array.elems[index]; /* FIXME palloced copy */
	}
	else
	{
		Assert(IsAJsonbScalar(arr));
		Assert(!index);
		return index ? NULL : arr;
	}
}

static uint32
jsonvGetArraySize(JsonContainer *arrc)
{
	JsonValue  *arr = (JsonValue *) arrc->data;

	Assert(JsonContainerIsArray(arrc));

	if (arr->type == jbvBinary)
	{
		JsonContainer *jsc = arr->val.binary.data;
		Assert(jsc->type == jbvArray);
		if (jsc->size < 0)
			((JsonContainerData *) jsc)->size = (*jsc->ops->getArraySize)(jsc);
		return jsc->size;
	}
	else if (arr->type == jbvArray)
		return arr->val.array.nElems;
	else
	{
		Assert(IsAJsonbScalar(arr));
		return 1;
	}
}

static JsonContainer *
jsonvCopy(JsonContainer *jc)
{
	JsonContainerData *res = JsonContainerAlloc();

	*res = *jc;
	res->data = JsonValueCopy(NULL, (JsonValue *) jc->data);

	return res;
}

static JsonContainerOps
jsonvContainerOps =
{
	NULL,
	jsonvIteratorInit,
	jsonvFindKeyInObject,
	jsonvFindValueInArray,
	jsonvGetArrayElement,
	jsonvGetArraySize,
	JsonbToCStringRaw,
	jsonvCopy,
};

JsonValue *
JsonToJsonValue(Json *json, JsonValue *jv)
{
	if (JsonRoot(json)->ops == &jsonvContainerOps)
		return (JsonValue *) JsonRoot(json)->data;

	if (!jv)
		jv = palloc(sizeof(JsonValue));

	jv->type = jbvBinary;
	jv->val.binary.data = &json->root;
	jv->val.binary.len = json->root.len;

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
		Json	   *json = JsonExpand(NULL, PointerGetDatum(NULL), false,
									  &jsonvContainerOps);

		jsonvInitContainer(&json->root, val);

		return json;
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
