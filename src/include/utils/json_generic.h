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

#define JSON_GENERIC

#include "postgres.h"
#include "lib/stringinfo.h"
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
};

typedef struct CompressedObject
{
	ExpandedObjectHeader	eoh;
	Datum					compressed;
} CompressedObject;

typedef struct Json
{
	CompressedObject	obj;
	JsonContainerData	root;
	bool				is_json;	/* json or jsonb */
} Json;


#ifndef JSONXOID
# define JSONXOID JSONBOID
#endif

#ifndef JsonxContainerOps
# define JsonxContainerOps			(&jsonbContainerOps)
#endif

#define JsonFlattenToJsonbDatum(json) \
		PointerGetDatum(JsonFlatten(json, JsonbEncode, &jsonbContainerOps))

#define JsonGetEOHDatum(json)		EOHPGetRODatum(&(json)->obj.eoh)

#define JSON_FLATTEN_INTO_TARGET
/*
#define JSON_FLATTEN_INTO_JSONEXT
#define JSON_FLATTEN_INTO_JSONB
#define flatContainerOps &jsonbContainerOps
*/

#undef JsonbPGetDatum
#define JsonbPGetDatum(json)		JsonFlattenToJsonbDatum(json)

#ifndef JsonxPGetDatum
# ifdef JSON_FLATTEN_INTO_TARGET
#  define JsonxPGetDatum(json)		JsonbPGetDatum(json)
# else
#  define JsonxPGetDatum(json)		JsonGetEOHDatum(json)
# endif
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

#define JsonGetDatum(json)			JsonxPGetDatum(json)

#undef DatumGetJsonbP
#define DatumGetJsonbP(datum)		DatumGetJson(datum, &jsonbContainerOps)
#define DatumGetJsontP(datum)		DatumGetJson(datum, &jsontContainerOps)
#define DatumGetJsonxP(datum)		DatumGetJson(datum, JsonxContainerOps)

#undef DatumGetJsonbPCopy
#define DatumGetJsonbPCopy(datum)	DatumGetJsonbP(PointerGetDatum(PG_DETOAST_DATUM_COPY(datum)))
#define DatumGetJsontPCopy(datum)	DatumGetJsontP(PointerGetDatum(PG_DETOAST_DATUM_COPY(datum)))
#define DatumGetJsonxPCopy(datum)	DatumGetJsonxP(PointerGetDatum(PG_DETOAST_DATUM_COPY(datum)))

#undef PG_RETURN_JSONB_P
#define PG_RETURN_JSONB_P(x)		PG_RETURN_DATUM(JsonGetDatum(x))

#define PG_RETURN_JSONT_P(x)		PG_RETURN_DATUM(JsontPGetDatum(x))

#undef	PG_GETARG_JSONB_P
#define PG_GETARG_JSONB_P(n)		DatumGetJsonxP(PG_GETARG_DATUM(n))
#define PG_GETARG_JSONT_P(n)		DatumGetJsontP(PG_GETARG_DATUM(n))

#undef	PG_GETARG_JSONB_P_COPY
#define PG_GETARG_JSONB_P_COPY(x)	DatumGetJsonxPCopy(PG_GETARG_DATUM(x))
#define PG_GETARG_JSONT_P_COPY(x)	DatumGetJsontPCopy(PG_GETARG_DATUM(x))

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

extern Json *DatumGetJson(Datum value, JsonContainerOps *ops);

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

extern Json *JsonValueToJson(JsonValue *val);
extern JsonValue *JsonToJsonValue(Json *json, JsonValue *jv);
extern JsonValue *JsonValueUnpackBinary(const JsonValue *jbv);
extern JsonContainer *JsonValueToContainer(const JsonValue *val);

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

extern JsonContainerOps jsonbContainerOps;
extern JsonContainerOps jsontContainerOps;

#endif /* UTILS_JSON_GENERIC_H */
