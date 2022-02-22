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
#include "utils/jsonb.h"

typedef JsonbPair JsonPair;
typedef JsonbValue JsonValue;
typedef JsonbIteratorToken JsonIteratorToken;

typedef struct JsonContainerOps JsonContainerOps;

typedef struct JsonContainerData
{
	JsonContainerOps   *ops;
	int					len;
	int					size;
	JsonbValueType		type;
	Oid					toasterid;
	void			   *_data[FLEXIBLE_ARRAY_MEMBER];
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

struct JsonContainerOps
{
	int				data_size;
	void			(*init)(JsonContainerData *jc, Datum value);
	JsonIterator   *(*iteratorInit)(JsonContainer *jc);
	JsonValue	   *(*findKeyInObject)(JsonContainer *object,
									   const char *key, int len,
									   JsonValue *res);
	JsonValue	   *(*findValueInArray)(JsonContainer *array,
										const JsonValue *value);
	JsonValue	   *(*getArrayElement)(JsonContainer *array, uint32 index);
	uint32			(*getArraySize)(JsonContainer *array);
	char		   *(*toString)(StringInfo out, JsonContainer *jc,
								int estimated_len);
	JsonContainer  *(*copy)(JsonContainer *jc);
	void			(*free)(JsonContainer *jc);
	void		   *(*encode)(JsonValue *jc, JsonContainerOps *ops, Oid toasterid);
};

typedef struct CompressedObject
{
	Datum		value;
	bool		freeValue;
	bool		isTemporary;
} CompressedObject;

typedef struct Json
{
	CompressedObject obj;
	bool		is_json;		/* json or jsonb */
	JsonContainerData root;
} Json;

typedef Json Jsonb;
typedef JsonContainer JsonbContainer;

#define JsonContainerDataPtr(jc)	((jc)->_data[0])

#define JsonIsTemporary(json)		((json)->obj.isTemporary)

#define JsonFlattenToJsonbDatum(json) \
		PointerGetDatum(JsonFlatten(json, JsonbEncode, &jsonbContainerOps))

#define JsonValueToJsonbDatum(jv) \
	PointerGetDatum(JsonValueFlatten(jv, JsonbEncode, &jsonbContainerOps, NULL, NULL))

#define JsonValueToJsonbDatumSafe(jv, escontext) \
	PointerGetDatum(JsonValueFlatten(jv, JsonbEncode, &jsonbContainerOps, NULL, escontext))

#define JsonbPGetDatum(json)		JsonFlattenToJsonbDatum(json)

#define DatumGetJsonbP(datum)		DatumGetJson(datum, &jsonbContainerOps, NULL)
#define DatumGetJsontP(datum)		DatumGetJson(datum, &jsontContainerOps, NULL)

#define DatumGetJsonbPCopy(datum)	DatumGetJsonbP(PointerGetDatum(PG_DETOAST_DATUM_COPY(datum)))
#define DatumGetJsontPCopy(datum)	DatumGetJsontP(PointerGetDatum(PG_DETOAST_DATUM_COPY(datum)))

#define PG_RETURN_JSONB_P(x)		PG_RETURN_DATUM(JsonbPGetDatum(x))
#define PG_RETURN_JSONB_VALUE_P(x)	PG_RETURN_DATUM(JsonValueToJsonbDatum(x))
#define PG_RETURN_JSONB_VALUE_P_SAFE(x, escontext)	PG_RETURN_DATUM(JsonValueToJsonbDatumSafe(x, escontext))

#define PG_GETARG_JSONB_P(n)		DatumGetJson(PG_GETARG_DATUM(n), &jsonbContainerOps, alloca(sizeof(Json))) /* FIXME conditional alloca() */
#define PG_GETARG_JSONB_P_COPY(x)	DatumGetJsonbPCopy(PG_GETARG_DATUM(x))

#define PG_FREE_IF_COPY_JSONB(json, n) JsonFree(json)

#define JsonRoot(json)				(&(json)->root)
#define JsonGetSize(json)			(JsonRoot(json)->len)
#define JsonbRoot(json)				JsonRoot(json)
#define JsonbGetSize(json)			JsonGetSize(json)

#define JsonContainerIsArray(c)		(((c)->type & ~jbvScalar) == jbvArray)
#define JsonContainerIsScalar(c)	((c)->type == (jbvArray | jbvScalar))
#define JsonContainerIsObject(c)	((c)->type == jbvObject)
#define JsonContainerSize(c)		((c)->size)
#define JsonContainerIsEmpty(c)		((c)->size == 0)

#define JsonValueIsScalar(jsval)	IsAJsonbScalar(jsval)

#define JsonbIterator JsonIterator
#define JsonbIteratorInit JsonIteratorInit
#define JsonbIteratorNext JsonIteratorNext

#define JsonbValueToJsonb JsonValueToJson

#define JB_ROOT_COUNT(json)		JsonContainerSize(JsonRoot(json))
#define JB_ROOT_IS_SCALAR(json)	JsonContainerIsScalar(JsonRoot(json))
#define JB_ROOT_IS_OBJECT(json)	JsonContainerIsObject(JsonRoot(json))
#define JB_ROOT_IS_ARRAY(json)	JsonContainerIsArray(JsonRoot(json))

#define JsonOp(op, jscontainer) \
		(*(jscontainer)->ops->op)

#define JsonOp0(op, jscontainer) \
		JsonOp(op, jscontainer)(jscontainer)

#define JsonOp1(op, jscontainer, arg) \
		JsonOp(op, jscontainer)(jscontainer, arg)

#define JsonOp2(op, jscontainer, arg1, arg2) \
		JsonOp(op, jscontainer)(jscontainer, arg1, arg2)

#define JsonOp3(op, jscontainer, arg1, arg2, arg3) \
		JsonOp(op, jscontainer)(jscontainer, arg1, arg2, arg3)

#define JsonIteratorInit(jscontainer) \
		JsonOp0(iteratorInit, jscontainer)

#define JsonFindValueInArray(jscontainer, key) \
		JsonOp1(findValueInArray, jscontainer, key)

#define JsonFindKeyInObject(jscontainer, key, len, res) \
		JsonOp3(findKeyInObject, jscontainer, key, len, res)

#define JsonGetArrayElement(jscontainer, index) \
		JsonOp1(getArrayElement, jscontainer, index)

#define JsonGetArraySize(json) \
		JsonOp0(getArraySize, json)

#define JsonCopy(jscontainer) \
		JsonOp0(copy, jscontainer)

#define	JsonContainerFree(jc) do { \
		if ((jc)->ops->free) \
			(jc)->ops->free(jc); \
	} while (0)


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
#define getKeyJsonValueFromContainer	JsonFindKeyInObject
#define compareJsonbContainers			JsonCompareContainers
#define equalsJsonbScalarValue			JsonValueScalarEquals

extern Json *DatumGetJson(Datum val, JsonContainerOps *ops, Json *tmp);

extern void JsonFree(Json *json);
extern Json *JsonCopyTemporary(Json *tmp);

#define JsonAllocSize(data_size) \
	(offsetof(Json, root._data) + (data_size))

#define JsonContainerAllocSize(data_size) \
	(offsetof(JsonContainerData, _data) + (data_size))

#define JsonContainerAlloc(ops) \
	((JsonContainerData *) palloc(JsonContainerAllocSize((ops)->data_size)))

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

static inline JsonValue *
JsonValueInitBinary(JsonValue *val, JsonContainer *cont)
{
	val->type = jbvBinary;
	val->val.binary.data = cont;

	return val;
}

extern Json *JsonValueToJson(JsonValue *val);
extern Datum JsonbValueToOrigJsonbDatum(JsonValue *val, Json *origjs);
extern JsonValue *JsonToJsonValue(Json *json, JsonValue *jv);
extern JsonValue *JsonValueUnpackBinary(const JsonValue *jbv);
extern JsonValue *JsonValueCopy(JsonValue *res, const JsonValue *val);
extern const JsonValue *JsonValueUnwrap(const JsonValue *val, JsonValue *buf);
extern JsonContainer *JsonCopyFlat(JsonContainer *flatContainer);
extern JsonValue *JsonExtractScalar(JsonContainer *jc, JsonValue *scalar);

extern Jsonb *JsonbMakeEmptyArray(void);
extern Jsonb *JsonbMakeEmptyObject(void);
extern char *JsonbUnquote(Jsonb *jb);
extern bool JsonbExtractScalar(JsonbContainer *jbc, JsonbValue *res);
extern const char *JsonbTypeName(JsonbValue *jb);

extern int JsonCompareContainers(JsonContainer *a, JsonContainer *b);

extern bool JsonbDeepContains(JsonContainer *val, JsonContainer *mContained);

/* jsonb.c support functions */
extern JsonValue *JsonValueFromCString(char *json, int len, Node *escontext /* XXX SQL/JSON bool unique_keys */);


extern char *JsonbToCStringRaw(StringInfo out, JsonContainer *in,
			   int estimated_len);
extern char *JsonbToCStringIndent(StringInfo out, JsonContainer *in,
					 int estimated_len);

#define JsonToCString(jc, buf)	((jc)->ops->toString(buf, jc, (jc)->len))

#define JsonToCStringExt(out, in, estimated_len) \
	((*(in)->ops->toString)(out, in, estimated_len))

#define JsonbToCString(out, in, estimated_len) \
		JsonToCStringExt(out, in, estimated_len)

extern bool JsonValueScalarEquals(const JsonValue *aScalar,
								  const JsonValue *bScalar);

typedef bool (*JsonValueEncoder)(StringInfo, const JsonValue *, void *cxt, Node *escontext);

extern void *JsonContainerFlatten(JsonContainer *jc, JsonValueEncoder encoder,
								  JsonContainerOps *ops, const JsonValue *binary,
								  Node *escontext);

extern void *JsonValueFlatten(const JsonValue *val, JsonValueEncoder encoder,
							  JsonContainerOps *ops, void *cxt, Node *escontext);
extern void *JsonEncode(const JsonbValue *val, JsonValueEncoder encoder, void *cxt, Node *escontext);

static inline void *
JsonFlatten(Json *json, JsonValueEncoder encoder, JsonContainerOps *ops)
{
	return JsonContainerFlatten(JsonRoot(json), encoder, ops, NULL, NULL);
}

extern bool JsonbEncode(StringInfo, const JsonValue *, void *cxt, Node *escontext);

#define JsonValueToJsonbSafe(val, escontext) \
		JsonValueFlatten(val, JsonbEncode, &jsonbContainerOps, NULL, escontext)

#define JsonValueToJsonb(val) \
		JsonValueToJsonbSafe(val, NULL)

extern int lengthCompareJsonbStringValue(const void *a, const void *b);
extern int lengthCompareJsonbString(const char *val1, int len1,
									const char *val2, int len2);

extern JsonContainerOps jsonbContainerOps;

#define JSON_TOASTER_MAGIC 0x20211223

typedef struct JsonToastRoutine
{
	uint32		magic;
	JsonContainerOps *ops;
} JsonToastRoutine;

#endif /* UTILS_JSON_GENERIC_H */
