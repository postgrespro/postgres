/*-------------------------------------------------------------------------
 *
 * json_generic.h
 *	  Declarations for generic json data type support.
 *
 * Copyright (c) 2014-2016, PostgreSQL Global Development Group
 *
 * src/include/utils/json_generic.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef UTILS_JSON_GENERIC_H
#define UTILS_JSON_GENERIC_H

#include "postgres.h"
#include "lib/stringinfo.h"
#include "utils/builtins.h"
#include "utils/expandeddatum.h"
#include "utils/jsonb.h"

typedef JsonbPair JsonPair;
typedef JsonbValue JsonValue;
typedef JsonbValueType JsonValueType;
typedef JsonbIteratorToken JsonIteratorToken;

typedef struct JsonContainerOps JsonContainerOps;

typedef struct JsonContainerData
{
	JsonContainerOps   *ops;
	void			   *data;
	int					len;
	int					size;
	JsonValueType		type;
} JsonContainerData;

typedef const JsonContainerData JsonContainer;

typedef struct JsonIteratorData JsonIterator;

typedef JsonIteratorToken (*JsonIteratorNextFunc)(JsonIterator **iterator,
												  JsonValue *value,
												  bool skipNested);

struct JsonIteratorData
{
	JsonIterator		   *parent;
	JsonContainer		   *container;
	JsonIteratorNextFunc	next;
};

typedef enum JsonContainerTypes
{
	JsonContainerUnknown = 0,
	JsonContainerJsont = -1,
	JsonContainerJsonb = -2,
	JsonContainerJsonv = -3,
} JsonContainerTypes;

typedef Oid JsonContainerType;

struct JsonContainerOps
{
	JsonContainerType type;
	void			(*init)(JsonContainerData *jc, Datum value);
	JsonIterator   *(*iteratorInit)(JsonContainer *jc);
	JsonValue	   *(*findKeyInObject)(JsonContainer *object,
									   const char *key, int len);
	JsonValue	   *(*findValueInArray)(JsonContainer *array,
										const JsonValue *value);
	JsonValue	   *(*getArrayElement)(JsonContainer *array, uint32 index);
	uint32			(*getArraySize)(JsonContainer *array);
	char		   *(*toString)(StringInfo out, JsonContainer *jc,
								int estimated_len);
	JsonContainer  *(*copy)(JsonContainer *jc);
};

typedef struct CompressedObject
{
	ExpandedObjectHeader	eoh;
	Datum					value;
	bool					freeValue;
} CompressedObject;

typedef struct Json
{
	CompressedObject	obj;
	JsonContainerData	root;
	bool				is_json;	/* json or jsonb */
} Json;

#define JsonIsTemporary(json) \
		((json)->obj.eoh.vl_len_ != EOH_HEADER_MAGIC)

#ifndef JSONXOID
# define JSONXOID JSONBOID
#endif

#ifndef JsonxContainerOps
# define JsonxContainerOps			(&jsonbContainerOps)
#endif

#define JsonFlattenToJsonbDatum(json) \
		PointerGetDatum(JsonFlatten(json, JsonbEncode, &jsonbContainerOps))

#define JsonGetEOHDatum(json)		EOHPGetRODatum(&JsonGetNonTemporary(json)->obj.eoh)

#define JSON_FLATTEN_INTO_TARGET
/*
#define JSON_FLATTEN_INTO_JSONEXT
#define JSON_FLATTEN_INTO_JSONB
#define flatContainerOps &jsonbContainerOps
*/

#undef JsonbPGetDatum
#ifdef JSON_FLATTEN_INTO_TARGET
# define JsonbPGetDatum(json)		JsonFlattenToJsonbDatum(JsonGetUniquified(json))
#else
# define JsonbPGetDatum(json)		JsonGetEOHDatum(JsonGetUniquified(json))
#endif

#ifdef JSON_FLATTEN_INTO_TARGET
# define JsontPGetDatum(json)	\
		PointerGetDatum(cstring_to_text(JsonToCString(JsonRoot(json))))
#else
static inline Datum
JsontPGetDatum(Json *json)
{
	json->is_json = true;
	return JsonGetEOHDatum(json);
}
#endif

#ifdef JsonxPGetDatum
# define JsonGetDatum(json)			JsonxPGetDatum(json)
#elif defined(JsonxGetUniquified)
# define JsonGetDatum(json)			JsonGetEOHDatum(JsonxGetUniquified(json))
#else
# define JsonGetDatum(json)			JsonbPGetDatum(json)
#endif

#undef DatumGetJsonbP
#define DatumGetJsonbP(datum)		DatumGetJson(datum, &jsonbContainerOps, NULL)
#define DatumGetJsontP(datum)		DatumGetJson(datum, &jsontContainerOps, NULL)
#define DatumGetJsonxP(datum)		DatumGetJson(datum, JsonxContainerOps, NULL)
#define DatumGetJsonxTmp(datum,tmp)	DatumGetJson(datum, JsonxContainerOps, tmp)

#undef DatumGetJsonbPCopy
#define DatumGetJsonbPCopy(datum)	DatumGetJsonbP(PointerGetDatum(PG_DETOAST_DATUM_COPY(datum)))
#define DatumGetJsontPCopy(datum)	DatumGetJsontP(PointerGetDatum(PG_DETOAST_DATUM_COPY(datum)))
#define DatumGetJsonxPCopy(datum)	DatumGetJsonxP(PointerGetDatum(PG_DETOAST_DATUM_COPY(datum)))

#undef PG_RETURN_JSONB_P
#define PG_RETURN_JSONB_P(x)		PG_RETURN_DATUM(JsonGetDatum(x))
#define PG_RETURN_JSONT_P(x)		PG_RETURN_DATUM(JsontPGetDatum(x))

#define PG_GETARG_JSONX_TMP(n, tmp)	DatumGetJsonxTmp(PG_GETARG_DATUM(n), tmp)

#undef	PG_GETARG_JSONB_P
#define PG_GETARG_JSONB_P(n)		PG_GETARG_JSONX_TMP(n, alloca(sizeof(Json))) /* FIXME conditional alloca() */
#define PG_GETARG_JSONT_P(n)		DatumGetJsontP(PG_GETARG_DATUM(n))

#undef	PG_GETARG_JSONB_P_COPY
#define PG_GETARG_JSONB_P_COPY(x)	DatumGetJsonxPCopy(PG_GETARG_DATUM(x))
#define PG_GETARG_JSONT_P_COPY(x)	DatumGetJsontPCopy(PG_GETARG_DATUM(x))

#define JsonFreeIfCopy(json, datum) \
		do { \
			if (!VARATT_IS_EXTERNAL_EXPANDED(DatumGetPointer(datum))) \
				JsonFree(json); \
			else \
				Assert(DatumGetEOHP(datum) == &(json)->obj.eoh); \
		} while (0)

#define PG_FREE_IF_COPY_JSONB(json, n) \
		JsonFreeIfCopy(json, PG_GETARG_DATUM(n))

#define JsonRoot(json)				(&(json)->root)
#define JsonGetSize(json)			(JsonRoot(json)->len)
#undef JsonbRoot
#undef JsonbGetSize
#define JsonbRoot(json)				JsonRoot(json)
#define JsonbGetSize(json)			JsonGetSize(json)

#define JsonContainerIsArray(c)		(((c)->type & ~jbvScalar) == jbvArray)
#define JsonContainerIsScalar(c)	((c)->type == (jbvArray | jbvScalar))
#define JsonContainerIsObject(c)	((c)->type == jbvObject)
#define JsonContainerSize(c)		((c)->size)
#define JsonContainerIsEmpty(c)		((c)->size == 0)

#define JsonContainerIsUniquified(jc) \
		((jc)->ops != &jsontContainerOps && \
		 ((jc)->ops != &jsonvContainerOps || \
		  JsonValueIsUniquified((JsonValue *) jc->data)))

#define JsonIsUniquified(json)		JsonContainerIsUniquified(JsonRoot(json))

#define JsonValueIsScalar(jsval)	IsAJsonbScalar(jsval)

#define JsonContainerGetType(jc) ((jc)->ops->type)
#define JsonContainerGetOpsByType(type) \
		((type) == JsonContainerJsont ? &jsontContainerOps : \
		 (type) == JsonContainerJsonb ? &jsonbContainerOps : NULL)

#ifdef JSONB_UTIL_C
#define JsonbValueToJsonb JsonValueToJsonb
#else
#define Jsonb Json
#define JsonbIterator JsonIterator
#define JsonbContainer JsonContainer
#define JsonbIteratorInit JsonIteratorInit
#define JsonbIteratorNext JsonIteratorNext
#define JsonbValueToJsonb JsonValueToJson

#undef JB_ROOT_COUNT
#undef JB_ROOT_IS_SCALAR
#undef JB_ROOT_IS_OBJECT
#undef JB_ROOT_IS_ARRAY
#define JB_ROOT_COUNT(json)		JsonContainerSize(JsonRoot(json))
#define JB_ROOT_IS_SCALAR(json)	JsonContainerIsScalar(JsonRoot(json))
#define JB_ROOT_IS_OBJECT(json)	JsonContainerIsObject(JsonRoot(json))
#define JB_ROOT_IS_ARRAY(json)	JsonContainerIsArray(JsonRoot(json))
#endif

#define JsonOp(op, jscontainer) \
		(*(jscontainer)->ops->op)

#define JsonOp0(op, jscontainer) \
		JsonOp(op, jscontainer)(jscontainer)

#define JsonOp1(op, jscontainer, arg) \
		JsonOp(op, jscontainer)(jscontainer, arg)

#define JsonOp2(op, jscontainer, arg1, arg2) \
		JsonOp(op, jscontainer)(jscontainer, arg1, arg2)

#define JsonIteratorInit(jscontainer) \
		JsonOp0(iteratorInit, jscontainer)

#define JsonFindValueInArray(jscontainer, key) \
		JsonOp1(findValueInArray, jscontainer, key)

#define JsonFindKeyInObject(jscontainer, key, len) \
		JsonOp2(findKeyInObject, jscontainer, key, len)

#define JsonGetArrayElement(jscontainer, index) \
		JsonOp1(getArrayElement, jscontainer, index)

#define JsonGetArraySize(json) \
		JsonOp0(getArraySize, json)

#define JsonCopy(jscontainer) \
		JsonOp0(copy, jscontainer)

static inline JsonIteratorToken
JsonIteratorNext(JsonIterator **it, JsonValue *val, bool skipNested)
{
	JsonIteratorToken tok;

	if (!*it)
		return WJB_DONE;

	do
		tok = (*it)->next(it, val, skipNested);
	while (tok == WJB_RECURSE);

	return tok;
}

#define getIthJsonbValueFromContainer	JsonGetArrayElement
#define findJsonbValueFromContainer		JsonFindValueInContainer
#define findJsonbValueFromContainerLen	JsonFindValueInContainerLen
#define compareJsonbContainers			JsonCompareContainers
#define equalsJsonbScalarValue			JsonValueScalarEquals

extern PGDLLIMPORT JsonContainerOps jsonbContainerOps;
extern PGDLLIMPORT JsonContainerOps jsontContainerOps;
extern PGDLLIMPORT JsonContainerOps jsonvContainerOps;

extern Json *DatumGetJson(Datum val, JsonContainerOps *ops, Json *tmp);

extern void JsonFree(Json *json);
extern Json *JsonCopyTemporary(Json *tmp);
extern Json *JsonUniquify(Json *json);

#define JsonContainerAlloc() \
	((JsonContainerData *) palloc(sizeof(JsonContainerData)))

extern JsonValue *JsonFindValueInContainer(JsonContainer *json, uint32 flags,
										   JsonValue *key);

static inline JsonValue *
JsonFindValueInContainerLen(JsonContainer *json, uint32 flags,
							const char *key, uint32 keylen)
{
	JsonValue	k;

	k.type = jbvString;
	k.val.string.val = key;
	k.val.string.len = keylen;

	return JsonFindValueInContainer(json, flags, &k);
}

static inline JsonIterator *
JsonIteratorFreeAndGetParent(JsonIterator *it)
{
	JsonIterator *parent = it->parent;
	pfree(it);
	return parent;
}

static inline void
JsonIteratorFree(JsonIterator *it)
{
	while (it)
		it = JsonIteratorFreeAndGetParent(it);
}

static inline Json *
JsonGetNonTemporary(Json *json)
{
	return JsonIsTemporary(json) ? JsonCopyTemporary(json) : json;
}

static inline Json *
JsonGetUniquified(Json *json)
{
	return JsonIsUniquified(json) ? json : JsonUniquify(json);
}

static inline JsonValue *
JsonValueInitObject(JsonValue *val, int nPairs, int nPairsAllocated,
					bool uniquified)
{
	val->type = jbvObject;
	val->val.object.nPairs = nPairs;
	val->val.object.pairs = nPairsAllocated ?
							palloc(sizeof(JsonPair) * nPairsAllocated) : NULL;
	val->val.object.uniquified = uniquified;
	val->val.object.valuesUniquified = uniquified;
	val->val.object.fieldSeparator[0] = ' ';
	val->val.object.fieldSeparator[1] = '\0';
	val->val.object.braceSeparator = '\0';
	val->val.object.colonSeparator.before = '\0';
	val->val.object.colonSeparator.after = ' ';

	return val;
}

static inline JsonValue *
JsonValueInitArray(JsonValue *val, int nElems, int nElemsAllocated,
				   bool rawScalar, bool uniquified)
{
	val->type = jbvArray;
	val->val.array.nElems = nElems;
	val->val.array.elems = nElemsAllocated ?
							palloc(sizeof(JsonValue) * nElemsAllocated) : NULL;
	val->val.array.rawScalar = rawScalar;
	if (!rawScalar)
	{
		val->val.array.uniquified = uniquified;
		val->val.array.elemsUniquified = uniquified;
		val->val.array.elementSeparator[0] = ' ';
		val->val.array.elementSeparator[1] = 0;
		val->val.array.elementSeparator[2] = 0;
	}

	return val;
}

static inline JsonValue *
JsonValueInitBinary(JsonValue *val, JsonContainer *cont)
{
	val->type = jbvBinary;
	val->val.binary.data = cont;
	val->val.binary.uniquified = JsonContainerIsUniquified(cont);

	return val;
}

static inline JsonbValue *
JsonValueInitString(JsonbValue *jbv, const char *str)
{
	jbv->type = jbvString;
	jbv->val.string.len = strlen(str);
	jbv->val.string.val = memcpy(palloc(jbv->val.string.len + 1), str,
								 jbv->val.string.len + 1);
	return jbv;
}

static inline JsonbValue *
JsonValueInitStringWithLen(JsonbValue *jbv, const char *str, int len)
{
	jbv->type = jbvString;
	jbv->val.string.val = str;
	jbv->val.string.len = len;
	return jbv;
}

static inline JsonbValue *
JsonValueInitText(JsonbValue *jbv, text *txt)
{
	jbv->type = jbvString;
	jbv->val.string.val = VARDATA_ANY(txt);
	jbv->val.string.len = VARSIZE_ANY_EXHDR(txt);
	return jbv;
}

static inline JsonbValue *
JsonValueInitNumeric(JsonbValue *jbv, Numeric num)
{
	jbv->type = jbvNumeric;
	jbv->val.numeric = num;
	return jbv;
}

static inline JsonbValue *
JsonValueInitInteger(JsonbValue *jbv, int64 i)
{
	jbv->type = jbvNumeric;
	jbv->val.numeric = DatumGetNumeric(DirectFunctionCall1(
											int8_numeric, Int64GetDatum(i)));
	return jbv;
}

static inline JsonbValue *
JsonValueInitFloat(JsonbValue *jbv, float4 f)
{
	jbv->type = jbvNumeric;
	jbv->val.numeric = DatumGetNumeric(DirectFunctionCall1(
											float4_numeric, Float4GetDatum(f)));
	return jbv;
}

static inline JsonbValue *
JsonValueInitDouble(JsonbValue *jbv, float8 f)
{
	jbv->type = jbvNumeric;
	jbv->val.numeric = DatumGetNumeric(DirectFunctionCall1(
											float8_numeric, Float8GetDatum(f)));
	return jbv;
}

#define pushJsonbKey(pstate, jbv, key) \
		pushJsonbValue(pstate, WJB_KEY, JsonValueInitString(jbv, key))

#define pushJsonbValueGeneric(Type, pstate, jbv, val) \
		pushJsonbValue(pstate, WJB_VALUE, JsonValueInit##Type(jbv, val))

#define pushJsonbElemGeneric(Type, pstate, jbv, val) \
		pushJsonbValue(pstate, WJB_ELEM, JsonValueInit##Type(jbv, val))

#define pushJsonbValueInteger(pstate, jbv, i) \
		pushJsonbValueGeneric(Integer, pstate, jbv, i)

#define pushJsonbValueFloat(pstate, jbv, f) \
		pushJsonbValueGeneric(Float, pstate, jbv, f)

#define pushJsonbElemFloat(pstate, jbv, f) \
		pushJsonbElemGeneric(Float, pstate, jbv, f)

#define pushJsonbElemString(pstate, jbv, txt) \
		pushJsonbElemGeneric(String, pstate, jbv, txt)

#define pushJsonbElemText(pstate, jbv, txt) \
		pushJsonbElemGeneric(Text, pstate, jbv, txt)

#define pushJsonbElemNumeric(pstate, jbv, num) \
		pushJsonbElemGeneric(Numeric, pstate, jbv, num)

#define pushJsonbElemInteger(pstate, jbv, num) \
		pushJsonbElemGeneric(Integer, pstate, jbv, num)

#define pushJsonbElemBinary(pstate, jbv, jbcont) \
		pushJsonbElemGeneric(Binary, pstate, jbv, jbcont)

#define pushJsonbKeyValueGeneric(Type, pstate, jbv, key, val) ( \
		pushJsonbKey(pstate, jbv, key), \
		pushJsonbValueGeneric(Type, pstate, jbv, val) \
	)

#define pushJsonbKeyValueString(pstate, jbv, key, val) \
		pushJsonbKeyValueGeneric(String, pstate, jbv, key, val)

#define pushJsonbKeyValueFloat(pstate, jbv, key, val) \
		pushJsonbKeyValueGeneric(Float, pstate, jbv, key, val)

#define pushJsonbKeyValueInteger(pstate, jbv, key, val) \
		pushJsonbKeyValueGeneric(Integer, pstate, jbv, key, val)

extern Json *JsonValueToJson(JsonValue *val);
extern JsonValue *JsonToJsonValue(Json *json, JsonValue *jv);
extern JsonValue *JsonValueUnpackBinary(const JsonValue *jbv);
extern JsonContainer *JsonValueToContainer(const JsonValue *val);
extern JsonValue *JsonValueCopy(JsonValue *res, const JsonValue *val);
extern const JsonValue *JsonValueUnwrap(const JsonValue *val, JsonValue *buf);
extern JsonValue *JsonValueWrapInBinary(const JsonValue *val, JsonValue *bin);
extern JsonContainer *JsonCopyFlat(JsonContainer *flatContainer);
extern JsonValue *JsonExtractScalar(JsonContainer *jc, JsonValue *scalar);

extern bool JsonbExtractScalar(JsonbContainer *jbc, JsonbValue *res);
extern const char *JsonbTypeName(JsonbValue *jb);

extern int JsonCompareContainers(JsonContainer *a, JsonContainer *b);

extern bool JsonbDeepContains(JsonContainer *val, JsonContainer *mContained);

extern JsonValue *JsonContainerExtractKeys(JsonContainer *jsc);

/* jsonb.c support functions */
extern JsonValue *JsonValueFromCString(char *json, int len);


extern char *JsonbToCStringRaw(StringInfo out, JsonContainer *in,
			   int estimated_len);
extern char *JsonbToCStringIndent(StringInfo out, JsonContainer *in,
					 int estimated_len);
extern char *JsonbToCStringCanonical(StringInfo out, JsonContainer *in,
					 int estimated_len);

#define JsonToCString(jc)	JsonToCStringExt(NULL, jc, (jc)->len)

#define JsonToCStringExt(out, in, estimated_len) \
	((*(in)->ops->toString)(out, in, estimated_len))

#define JsonbToCString(out, in, estimated_len) \
		JsonToCStringExt(out, in, estimated_len)

extern JsonValue   *jsonFindKeyInObject(JsonContainer *obj, const char *key, int len);
extern JsonValue   *jsonFindLastKeyInObject(JsonContainer *obj, const char *key, int len);
extern JsonValue   *jsonFindValueInArray(JsonContainer *array, const JsonValue *elem);
extern uint32		jsonGetArraySize(JsonContainer *array);
extern JsonValue   *jsonGetArrayElement(JsonContainer *array, uint32 index);
extern uint32		JsonGetObjectSize(JsonContainer *object);

extern bool JsonValueScalarEquals(const JsonValue *aScalar,
								  const JsonValue *bScalar);

typedef void (*JsonValueEncoder)(StringInfo, const JsonValue *);

extern void *JsonContainerFlatten(JsonContainer *jc, JsonValueEncoder encoder,
								  JsonContainerOps *ops, const JsonValue *binary);

extern void *JsonValueFlatten(const JsonValue *val, JsonValueEncoder encoder,
							  JsonContainerOps *ops);

static inline void *
JsonFlatten(Json *json, JsonValueEncoder encoder, JsonContainerOps *ops)
{
	return JsonContainerFlatten(JsonRoot(json), encoder, ops, NULL);
}

extern void JsonbEncode(StringInfo, const JsonValue *);

#define JsonValueToJsonb(val) \
		JsonValueFlatten(val, JsonbEncode, &jsonbContainerOps)

extern int lengthCompareJsonbStringValue(const void *a, const void *b);
extern int lengthCompareJsonbString(const char *val1, int len1,
									const char *val2, int len2);

#endif /* UTILS_JSON_GENERIC_H */
