/*-------------------------------------------------------------------------
 *
 * jsonb_util.c
 *	  converting between Jsonb and JsonbValues, and iterating.
 *
 * Copyright (c) 2014-2023, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/utils/adt/jsonb_util.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/detoast.h"
#include "access/toast_helper.h"
#include "access/toast_internals.h"
#include "catalog/pg_collation.h"
#include "catalog/pg_type.h"
#include "common/hashfn.h"
#include "common/jsonapi.h"
#include "common/pg_lzcompress.h"
#include "miscadmin.h"
#include "port/pg_bitutils.h"
#include "utils/builtins.h"
#include "utils/datetime.h"
#include "utils/json.h"
#include "utils/jsonb.h"
#include "utils/jsonb_internals.h"
#include "utils/memutils.h"
#include "utils/varlena.h"

#define JSONB_DETOAST_ITERATOR

/*
 * Maximum number of elements in an array (or key/value pairs in an object).
 * This is limited by two things: the size of the JEntry array must fit
 * in MaxAllocSize, and the number of elements (or pairs) must fit in the bits
 * reserved for that in the JsonbContainerHeader.header field.
 *
 * (The total size of an array's or object's elements is also limited by
 * JENTRY_OFFLENMASK, but we're not concerned about that here.)
 */
#define JSONB_MAX_ELEMS (Min(MaxAllocSize / sizeof(JsonbValue), JBC_CMASK))
#define JSONB_MAX_PAIRS (Min(MaxAllocSize / sizeof(JsonbPair), JBC_CMASK))

/* Conversion state used when parsing Jsonb from text, or for type coercion */
struct JsonbParseState
{
	JsonbValue	contVal;
	Size		size;
	struct JsonbParseState *next;
#if 0 /* XXX SQL/JSON */
	bool		unique_keys;	/* Check object key uniqueness */
	bool		skip_nulls;		/* Skip null object fields */
#endif
};

typedef struct CompressedDatum
{
	struct varlena *compressed;
	void	   *data;
	void	   *state;
	int			total_len;
	int			decompressed_len;
} CompressedDatum;

typedef struct CompressedJsonb
{
#ifndef JSONB_DETOAST_ITERATOR
	CompressedDatum *datum;
#else
	DetoastIterator iter;
#endif
	int			offset;
} CompressedJsonb;

typedef struct JsonbKVMap
{
	union
	{
		const uint8 *entries1;
		const uint16 *entries2;
		const int32 *entries4;
		const void *entries;
	}			map;
	int			entry_size;
} JsonbKVMap;

#define JSONB_KVMAP_ENTRY_SIZE(nPairs) \
	((nPairs) < 256 ? 1 : (nPairs) < 65536 ? 2 : 4)

#define JSONB_KVMAP_ENTRY(kvmap, index) \
	(!(kvmap)->entry_size ? (index) : \
	 (kvmap)->entry_size == 1 ? (int32) (kvmap)->map.entries1[index] : \
	 (kvmap)->entry_size == 2 ? (int32) (kvmap)->map.entries2[index] : \
	 (kvmap)->map.entries4[index])

typedef struct jsonbIterator
{
	JsonIterator	ji;

	/* Container being iterated */
	const JsonbContainerHeader *container;

	CompressedJsonb *compressed;	/* compressed jsonb container, if any */

	uint32		nElems;			/* Number of elements in children array (will
								 * be nPairs for objects) */
	bool		isScalar;		/* Pseudo-array scalar value? */
	const JEntry *children;		/* JEntrys for child nodes */
	/* Data proper.  This points to the beginning of the variable-length data */
	char	   *dataProper;
	JsonbKVMap	kvmap;

	/* Current item in buffer (up to nElems) */
	int			curIndex;

	/* Data offset corresponding to current item */
	uint32		curDataOffset;

	/*
	 * If the container is an object, we want to return keys and values
	 * alternately; so curDataOffset points to the current key, and
	 * curValueOffset points to the current value.
	 */
	uint32		curValueOffset;

	/* Private state */
	JsonbIterState state;
} jsonbIterator;

void fillJsonbValue(const JsonbContainerHeader *container, int index,
					char *base_addr, uint32 offset,
					JsonbValue *result);
static int	compareJsonbScalarValue(const JsonbValue *a, const JsonbValue *b);
static bool convertJsonbValue(StringInfo buffer, JEntry *header, const JsonbValue *val, int level, Node *escontext);
static bool convertJsonbArray(StringInfo buffer, JEntry *header, const JsonbValue *val, int level, Node *escontext);
static bool convertJsonbObject(StringInfo buffer, JEntry *header, const JsonbValue *val, int level, Node *escontext);
static bool convertJsonbBinary(StringInfo buffer, JEntry *header, const JsonbValue *val, int level, Node *escontext);
static bool convertJsonbScalar(StringInfo buffer, JEntry *header, const JsonbValue *scalarVal, Node *escontext);

static void copyToBuffer(StringInfo buffer, int offset, const char *data, int len);
static short padBufferToInt(StringInfo buffer);

static jsonbIterator *iteratorFromContainer(JsonContainer *container, jsonbIterator *parent);
static JsonbParseState *pushState(JsonbParseState **pstate);
static void appendKey(JsonbParseState *pstate, const JsonbValue *string);
static void appendValue(JsonbParseState *pstate, const JsonbValue *scalarVal);
static void appendElement(JsonbParseState *pstate, const JsonbValue *scalarVal);
int	lengthCompareJsonbStringValue(const void *a, const void *b);
static int	lengthCompareJsonbPair(const void *a, const void *b, void *binequal);
static void uniqueifyJsonbObject(JsonbValue *object /* XXX SQL/JSON bool unique_keys, bool skip_nulls */);
static JsonbValue *pushSingleScalarJsonbValue(JsonbParseState **pstate,
											  const JsonbValue *jbval,
											  bool unpackBinary);
static void jsonbInitContainer(JsonContainerData *jc, JsonbContainerHeader *jbc, int len);

static void CompressedDatumDecompress(CompressedDatum *cd, Size offset);
static JsonbValue *fillCompressedJsonbValue(CompressedJsonb *cjb,
											const JsonbContainerHeader *container,
											int index, char *base_addr,
											uint32 offset, JsonValue *result);
static JsonbContainerHeader *jsonbzDecompress(JsonContainer *jc);

bool jsonb_sort_field_values = true;		/* GUC */
bool jsonb_partial_decompression = true;	/* GUC */
bool jsonb_partial_detoast = true;			/* GUC */

JsonValue *
JsonValueUnpackBinary(const JsonValue *jbv)
{
	JsonbParseState	   *state = NULL;

	return pushJsonbValue(&state, WJB_VALUE, jbv);
}

void *
JsonContainerFlatten(JsonContainer *jc, JsonValueEncoder encoder,
					 JsonContainerOps *ops, const JsonValue *binary,
					 Node *escontext)
{
	JsonbValue jbv;

	if (jc->ops->encode)
	{
		JsonbValue bin;
		void	   *res;

		JsonValueInitBinary(&bin, jc);
		res = jc->ops->encode(&bin, ops, jc->toasterid);

		if (res)
			return res;
	}

	if (jc->ops == ops)
	{
		int			size = jc->len;
		void       *out = palloc(VARHDRSZ + size);

		SET_VARSIZE(out, VARHDRSZ + size);
		memcpy(VARDATA(out), JsonContainerDataPtr(jc), size);

		return out;
	}

	if (binary)
		Assert(binary->type == jbvBinary);
	else
		binary = JsonValueInitBinary(&jbv, jc);

	return JsonEncode(binary, encoder, NULL, escontext);
}

/*
 * Turn an in-memory JsonbValue into a Jsonb for on-disk storage.
 *
 * Generally we find it more convenient to directly iterate through the Jsonb
 * representation and only really convert nested scalar values.
 * JsonbIteratorNext() does this, so that clients of the iteration code don't
 * have to directly deal with the binary representation (JsonbDeepContains() is
 * a notable exception, although all exceptions are internal to this module).
 * In general, functions that accept a JsonbValue argument are concerned with
 * the manipulation of scalar values, or simple containers of scalar values,
 * where it would be inconvenient to deal with a great amount of other state.
 */
void *
JsonValueFlatten(const JsonValue *val, JsonValueEncoder encoder,
				 JsonContainerOps *ops, void *cxt, Node *escontext)
{
	if (val->type == jbvBinary)
		return JsonContainerFlatten(val->val.binary.data, encoder, ops, val, escontext);

	if (IsAJsonbScalar(val))
	{
		JsonbParseState *pstate = NULL;

		val = pushSingleScalarJsonbValue(&pstate, val, true);
	}
	else
	{
		Assert(val->type == jbvObject || val->type == jbvArray);
	}

	return JsonEncode(val, encoder, cxt, escontext);
}

/*
 * Get the offset of the variable-length portion of a Jsonb node within
 * the variable-length-data part of its container.  The node is identified
 * by index within the container's JEntry array.
 */
static uint32
getJsonbOffset(const JsonbContainerHeader *jc, int index)
{
	uint32		offset = 0;
	int			i;

	/*
	 * Start offset of this entry is equal to the end offset of the previous
	 * entry.  Walk backwards to the most recent entry stored as an end
	 * offset, returning that offset plus any lengths in between.
	 */
	for (i = index - 1; i >= 0; i--)
	{
		offset += JBE_OFFLENFLD(jc->children[i]);
		if (JBE_HAS_OFF(jc->children[i]))
			break;
	}

	return offset;
}

/*
 * Get the length of the variable-length portion of a Jsonb node.
 * The node is identified by index within the container's JEntry array.
 */
static uint32
getJsonbLength(const JsonbContainerHeader *jc, int index)
{
	uint32		off;
	uint32		len;

	/*
	 * If the length is stored directly in the JEntry, just return it.
	 * Otherwise, get the begin offset of the entry, and subtract that from
	 * the stored end+1 offset.
	 */
	if (JBE_HAS_OFF(jc->children[index]))
	{
		off = getJsonbOffset(jc, index);
		len = JBE_OFFLENFLD(jc->children[index]) - off;
	}
	else
		len = JBE_OFFLENFLD(jc->children[index]);

	return len;
}

/*
 * BT comparator worker function.  Returns an integer less than, equal to, or
 * greater than zero, indicating whether a is less than, equal to, or greater
 * than b.  Consistent with the requirements for a B-Tree operator class
 *
 * Strings are compared lexically, in contrast with other places where we use a
 * much simpler comparator logic for searching through Strings.  Since this is
 * called from B-Tree support function 1, we're careful about not leaking
 * memory here.
 */
int
compareJsonbContainers(JsonContainer *a, JsonContainer *b)
{
	JsonIterator *ita,
			   *itb;
	int			res = 0;

	ita = JsonbIteratorInit(a);
	itb = JsonbIteratorInit(b);

	do
	{
		JsonbValue	va,
					vb;
		JsonbIteratorToken ra,
					rb;

		ra = JsonbIteratorNext(&ita, &va, false);
		rb = JsonbIteratorNext(&itb, &vb, false);

		if (ra == rb)
		{
			if (ra == WJB_DONE)
			{
				/* Decisively equal */
				break;
			}

			if (ra == WJB_END_ARRAY || ra == WJB_END_OBJECT)
			{
				/*
				 * There is no array or object to compare at this stage of
				 * processing.  jbvArray/jbvObject values are compared
				 * initially, at the WJB_BEGIN_ARRAY and WJB_BEGIN_OBJECT
				 * tokens.
				 */
				continue;
			}

			if (va.type == vb.type)
			{
				switch (va.type)
				{
					case jbvString:
					case jbvNull:
					case jbvNumeric:
					case jbvBool:
						res = compareJsonbScalarValue(&va, &vb);
						break;
					case jbvArray:

						/*
						 * This could be a "raw scalar" pseudo array.  That's
						 * a special case here though, since we still want the
						 * general type-based comparisons to apply, and as far
						 * as we're concerned a pseudo array is just a scalar.
						 */
						if (va.val.array.rawScalar != vb.val.array.rawScalar)
							res = (va.val.array.rawScalar) ? -1 : 1;
						if (va.val.array.nElems >= 0 &&
							vb.val.array.nElems >= 0 &&
							va.val.array.nElems != vb.val.array.nElems)
							res = (va.val.array.nElems > vb.val.array.nElems) ? 1 : -1;
						break;
					case jbvObject:
						if (va.val.object.nPairs >= 0 &&
							vb.val.object.nPairs >= 0 &&
							va.val.object.nPairs != vb.val.object.nPairs)
							res = (va.val.object.nPairs > vb.val.object.nPairs) ? 1 : -1;
						break;
					case jbvBinary:
						elog(ERROR, "unexpected jbvBinary value");
						break;
					case jbvDatetime:
						elog(ERROR, "unexpected jbvDatetime value");
						break;
					default:
						elog(ERROR, "unexpected jsonb value type %d", va.type);
						break;
				}
			}
			else
			{
				/* Type-defined order */
				res = (va.type > vb.type) ? 1 : -1;
			}
		}
		else if (ra == WJB_END_ARRAY || ra == WJB_END_OBJECT)
			return -1;
		else if (rb == WJB_END_ARRAY || rb == WJB_END_OBJECT)
			return 1;
		else
		{
			/*
			 * It's safe to assume that the types differed, and that the va
			 * and vb values passed were set.
			 *
			 * If the two values were of the same container type, then there'd
			 * have been a chance to observe the variation in the number of
			 * elements/pairs (when processing WJB_BEGIN_OBJECT, say). They're
			 * either two heterogeneously-typed containers, or a container and
			 * some scalar type.
			 *
			 * We don't have to consider the WJB_END_ARRAY and WJB_END_OBJECT
			 * cases here, because we would have seen the corresponding
			 * WJB_BEGIN_ARRAY and WJB_BEGIN_OBJECT tokens first, and
			 * concluded that they don't match.
			 */
			Assert(ra != WJB_END_ARRAY && ra != WJB_END_OBJECT);
			Assert(rb != WJB_END_ARRAY && rb != WJB_END_OBJECT);

			Assert(va.type != vb.type);
			Assert(va.type != jbvBinary);
			Assert(vb.type != jbvBinary);
			/* Type-defined order */
			res = (va.type > vb.type) ? 1 : -1;
		}
	}
	while (res == 0);

	while (ita != NULL)
	{
		JsonIterator *i = ita->parent;

		pfree(ita);
		ita = i;
	}
	while (itb != NULL)
	{
		JsonIterator *i = itb->parent;

		pfree(itb);
		itb = i;
	}

	return res;
}

typedef struct JsonbArrayIterator
{
	const JsonbContainerHeader *container;
	char			   *base_addr;
	int					index;
	int					count;
	uint32				offset;
} JsonbArrayIterator;

static void
JsonbArrayIteratorInit(JsonbArrayIterator *it, const JsonbContainerHeader *container)
{
	it->container = container;
	it->index = 0;
	it->count = (container->header & JBC_CMASK);
	it->offset = 0;
	it->base_addr = (char *) (container->children + it->count);
}

static bool
JsonbArrayIteratorNext(JsonbArrayIterator *it, JsonbValue *result)
{
	if (it->index >= it->count)
		return false;

	fillJsonbValue(it->container, it->index, it->base_addr, it->offset, result);

	JBE_ADVANCE_OFFSET(it->offset, it->container->children[it->index]);

	it->index++;

	return true;
}

static JsonbValue *
JsonbArrayIteratorGetIth(JsonbArrayIterator *it, uint32 i)
{
	JsonbValue *result;

	if (i >= it->count)
		return NULL;

	result = palloc(sizeof(JsonbValue));

	fillJsonbValue(it->container, i, it->base_addr,
				   getJsonbOffset(it->container, i),
				   result);

	return result;
}

static JsonbValue *
jsonbFindValueInArrayContainer(const JsonbContainerHeader *container,
							   const JsonbValue *key)
{
	JsonbArrayIterator	it;
	JsonbValue		   *result = palloc(sizeof(JsonbValue));

	JsonbArrayIteratorInit(&it, container);

	while (JsonbArrayIteratorNext(&it, result))
	{
		if (key->type == result->type)
		{
			if (equalsJsonbScalarValue(key, result))
				return result;
		}
	}

	pfree(result);
	return NULL;
}

static JsonbValue *
jsonbFindValueInArray(JsonContainer *jsc, const JsonbValue *key)
{
	return jsonbFindValueInArrayContainer(JsonContainerDataPtr(jsc), key);
}

/*
 * Find value in object (i.e. the "value" part of some key/value pair in an
 * object), or find a matching element if we're looking through an array.  Do
 * so on the basis of equality of the object keys only, or alternatively
 * element values only, with a caller-supplied value "key".  The "flags"
 * argument allows the caller to specify which container types are of interest.
 *
 * This exported utility function exists to facilitate various cases concerned
 * with "containment".  If asked to look through an object, the caller had
 * better pass a Jsonb String, because their keys can only be strings.
 * Otherwise, for an array, any type of JsonbValue will do.
 *
 * In order to proceed with the search, it is necessary for callers to have
 * both specified an interest in exactly one particular container type with an
 * appropriate flag, as well as having the pointed-to Jsonb container be of
 * one of those same container types at the top level. (Actually, we just do
 * whichever makes sense to save callers the trouble of figuring it out - at
 * most one can make sense, because the container either points to an array
 * (possibly a "raw scalar" pseudo array) or an object.)
 *
 * Note that we can return a jbvBinary JsonbValue if this is called on an
 * object, but we never do so on an array.  If the caller asks to look through
 * a container type that is not of the type pointed to by the container,
 * immediately fall through and return NULL.  If we cannot find the value,
 * return NULL.  Otherwise, return palloc()'d copy of value.
 */
JsonbValue *
JsonFindValueInContainer(JsonContainer *json, uint32 flags, JsonValue *key)
{
	Assert((flags & ~(JB_FARRAY | JB_FOBJECT)) == 0);

	/* Quick out without a palloc cycle if object/array is empty */
	if (JsonContainerIsEmpty(json))
		return NULL;

	if ((flags & JB_FARRAY) && JsonContainerIsArray(json))
		return JsonFindValueInArray(json, key);

	if ((flags & JB_FOBJECT) && JsonContainerIsObject(json))
	{
		/* Object key passed by caller must be a string */
		Assert(key->type == jbvString);
		return JsonFindKeyInObject(json, key->val.string.val,
								   key->val.string.len, NULL);
	}

	/* Not found */
	return NULL;
}

static void *
initKVMap(JsonbKVMap *kvmap, void *pentries, int field_count, bool sorted)
{
	if (sorted)
	{
		kvmap->map.entries = pentries;
		kvmap->entry_size = JSONB_KVMAP_ENTRY_SIZE(field_count);

		return (char *) pentries + INTALIGN(field_count * kvmap->entry_size);
	}
	else
	{
		kvmap->entry_size = 0;
		kvmap->map.entries = NULL;

		return pentries;
	}
}

/*
 * Find value by key in Jsonb object and fetch it into 'res', which is also
 * returned.
 *
 * 'res' can be passed in as NULL, in which case it's newly palloc'ed here.
 */
static JsonbValue *
jsonbFindKeyInObject(JsonContainer *jsc, const char *keyVal, int keyLen,
					 JsonValue *res)
{
	const JsonbContainerHeader *container = JsonContainerDataPtr(jsc);
	const JEntry *children = container->children;
	int			count = JsonContainerSize(jsc);
	char	   *baseAddr = (char *) (children + count * 2);
	bool		sorted_values = (container->header & JBC_TMASK) == JBC_TOBJECT_SORTED;
	JsonbKVMap	kvmap;
	uint32		stopLow,
				stopHigh;

	Assert(JsonContainerIsObject(jsc));

	/* Quick out without a palloc cycle if object is empty */
	if (count <= 0)
		return NULL;

	/*
	 * Binary search the container. Since we know this is an object, account
	 * for *Pairs* of Jentrys
	 */
	baseAddr = initKVMap(&kvmap, baseAddr, count, sorted_values);

	stopLow = 0;
	stopHigh = count;
	while (stopLow < stopHigh)
	{
		uint32		stopMiddle;
		int			difference;
		const char *candidateVal;
		int			candidateLen;

		stopMiddle = stopLow + (stopHigh - stopLow) / 2;

		candidateVal = baseAddr + getJsonbOffset(container, stopMiddle);
		candidateLen = getJsonbLength(container, stopMiddle);

		difference = lengthCompareJsonbString(candidateVal, candidateLen,
											  keyVal, keyLen);

		if (difference == 0)
		{
			/* Found our key, return corresponding value */
			int			index = JSONB_KVMAP_ENTRY(&kvmap, stopMiddle) + count;

			if (!res)
				res = palloc(sizeof(JsonbValue));

			fillJsonbValue(container, index, baseAddr,
						   getJsonbOffset(container, index),
						   res);

			return res;
		}
		else
		{
			if (difference < 0)
				stopLow = stopMiddle + 1;
			else
				stopHigh = stopMiddle;
		}
	}

	/* Not found */
	return NULL;
}

/*
 * Get i-th value of a Jsonb array.
 *
 * Returns palloc()'d copy of the value, or NULL if it does not exist.
 */
static JsonbValue *
jsonbGetArrayElement(JsonContainer *jsc, uint32 i)
{
	JsonbArrayIterator	it;

	if (!JsonContainerIsArray(jsc))
		elog(ERROR, "not a jsonb array");

	JsonbArrayIteratorInit(&it, JsonContainerDataPtr(jsc));

	return JsonbArrayIteratorGetIth(&it, i);
}

/*
 * A helper function to fill in a JsonbValue to represent an element of an
 * array, or a key or value of an object.
 *
 * The node's JEntry is at container->children[index], and its variable-length
 * data is at base_addr + offset.  We make the caller determine the offset
 * since in many cases the caller can amortize that work across multiple
 * children.  When it can't, it can just call getJsonbOffset().
 *
 * A nested array or object will be returned as jbvBinary, ie. it won't be
 * expanded.
 */
void
fillJsonbValue(const JsonbContainerHeader *container, int index,
			   char *base_addr, uint32 offset,
			   JsonbValue *result)
{
	JEntry		entry = container->children[index];

	if (JBE_ISNULL(entry))
	{
		result->type = jbvNull;
	}
	else if (JBE_ISSTRING(entry))
	{
		result->type = jbvString;
		result->val.string.val = base_addr + offset;
		result->val.string.len = getJsonbLength(container, index);
		Assert(result->val.string.len >= 0);
	}
	else if (JBE_ISNUMERIC(entry))
	{
		result->type = jbvNumeric;
		result->val.numeric = (Numeric) (base_addr + INTALIGN(offset));
	}
	else if (JBE_ISBOOL_TRUE(entry))
	{
		result->type = jbvBool;
		result->val.boolean = true;
	}
	else if (JBE_ISBOOL_FALSE(entry))
	{
		result->type = jbvBool;
		result->val.boolean = false;
	}
	else
	{
		JsonContainerData *cont = JsonContainerAlloc(&jsonbContainerOps);

		Assert(JBE_ISCONTAINER(entry));

		jsonbInitContainer(cont,
			/* Remove alignment padding from data pointer and length */
						   (JsonbContainerHeader *)(base_addr + INTALIGN(offset)),
						   getJsonbLength(container, index) -
						   (INTALIGN(offset) - offset));

		JsonValueInitBinary(result, cont);
	}
}

/*
 * shallow clone of a parse state, suitable for use in aggregate
 * final functions that will only append to the values rather than
 * change them.
 */
JsonbParseState *
JsonbParseStateClone(JsonbParseState *state)
{
	JsonbParseState	   *result,
					   *icursor,
					   *ocursor,
					  **pocursor = &result;

	for (icursor = state; icursor; icursor = icursor->next)
	{
		*pocursor = ocursor = palloc(sizeof(JsonbParseState));
		ocursor->contVal = icursor->contVal;
		ocursor->size = icursor->size;
		pocursor = &ocursor->next;
	}

	*pocursor = NULL;

	return result;
}

#if 0 /* XXX SQL/JSON */
void
JsonbParseStateSetUniqueKeys(JsonbParseState *state, bool unique_keys)
{
	state->unique_keys = unique_keys;
}

void
JsonbParseStateSetSkipNulls(JsonbParseState *state, bool skip_nulls)
{
	state->skip_nulls = skip_nulls;
}
#endif

/*
 * Push JsonbValue into JsonbParseState.
 *
 * Used when parsing JSON tokens to form Jsonb, or when converting an in-memory
 * JsonbValue to a Jsonb.
 *
 * Initial state of *JsonbParseState is NULL, since it'll be allocated here
 * originally (caller will get JsonbParseState back by reference).
 *
 * Only sequential tokens pertaining to non-container types should pass a
 * JsonbValue.  There is one exception -- WJB_BEGIN_ARRAY callers may pass a
 * "raw scalar" pseudo array to append it - the actual scalar should be passed
 * next and it will be added as the only member of the array.
 *
 * Values of type jbvBinary, which are rolled up arrays and objects,
 * are unpacked before being added to the result.
 */
JsonbValue *
pushJsonbValueExt(JsonbParseState **pstate, JsonbIteratorToken seq,
			   const JsonbValue *jbval, bool unpackBinary)
{
	JsonIterator *it;
	JsonbValue *res = NULL;
	JsonbValue	v;
	JsonbIteratorToken tok;
	int			i;

	if (jbval && (seq == WJB_ELEM || seq == WJB_VALUE) && jbval->type == jbvObject)
	{
		pushJsonbValue(pstate, WJB_BEGIN_OBJECT, NULL);
		for (i = 0; i < jbval->val.object.nPairs; i++)
		{
			pushJsonbValue(pstate, WJB_KEY, &jbval->val.object.pairs[i].key);
			pushJsonbValueExt(pstate, WJB_VALUE, &jbval->val.object.pairs[i].value, unpackBinary);
		}

		return pushJsonbValue(pstate, WJB_END_OBJECT, NULL);
	}

	if (jbval && (seq == WJB_ELEM || seq == WJB_VALUE) && jbval->type == jbvArray)
	{
		if (jbval->val.array.rawScalar)
			return pushJsonbValue(pstate, seq, &jbval->val.array.elems[0]);

		pushJsonbValue(pstate, WJB_BEGIN_ARRAY, NULL);

		for (i = 0; i < jbval->val.array.nElems; i++)
		{
			pushJsonbValueExt(pstate, WJB_ELEM, &jbval->val.array.elems[i], unpackBinary);
		}

		return pushJsonbValue(pstate, WJB_END_ARRAY, NULL);
	}

	if (!jbval || (seq != WJB_ELEM && seq != WJB_VALUE) ||
		jbval->type != jbvBinary || !unpackBinary)
	{
		/* drop through */
		if (jbval && (seq == WJB_ELEM || seq == WJB_VALUE))
			jbval = JsonValueUnwrap(jbval, &v);

		return pushJsonbValueScalar(pstate, seq, jbval);
	}

	if (*pstate && JsonContainerIsScalar(jbval->val.binary.data))
	{
		jbval = JsonExtractScalar(jbval->val.binary.data, &v);
		Assert(IsAJsonbScalar(jbval));
		return pushJsonbValueScalar(pstate, seq, jbval);
	}

	/* unpack the binary and add each piece to the pstate */
	it = JsonbIteratorInit(jbval->val.binary.data);

	if (JsonContainerIsScalar(jbval->val.binary.data) && *pstate)
	{
		tok = JsonbIteratorNext(&it, &v, true);
		Assert(tok == WJB_BEGIN_ARRAY);
		Assert(v.type == jbvArray && v.val.array.rawScalar);

		tok = JsonbIteratorNext(&it, &v, true);
		Assert(tok == WJB_ELEM);

		res = pushJsonbValueScalar(pstate, seq, &v);

		tok = JsonbIteratorNext(&it, &v, true);
		Assert(tok == WJB_END_ARRAY);
		Assert(it == NULL);

		return res;
	}

	while ((tok = JsonbIteratorNext(&it, &v, false)) != WJB_DONE)
		res = pushJsonbValueScalar(pstate, tok,
								   tok < WJB_BEGIN_ARRAY ||
								   (tok == WJB_BEGIN_ARRAY &&
									v.val.array.rawScalar) ? &v : NULL);

	return res;
}

/*
 * Do the actual pushing, with only scalar or pseudo-scalar-array values
 * accepted.
 */
JsonbValue *
pushJsonbValueScalar(JsonbParseState **pstate, JsonbIteratorToken seq,
					 const JsonbValue *scalarVal)
{
	JsonbValue *result = NULL;

	switch (seq)
	{
		case WJB_BEGIN_ARRAY:
			Assert(!scalarVal || scalarVal->val.array.rawScalar);
			*pstate = pushState(pstate);
			result = &(*pstate)->contVal;
			(*pstate)->contVal.type = jbvArray;
			(*pstate)->contVal.val.array.nElems = 0;
			(*pstate)->contVal.val.array.rawScalar = (scalarVal &&
													  scalarVal->val.array.rawScalar);
			if (scalarVal && scalarVal->val.array.nElems > 0)
			{
				/* Assume that this array is still really a scalar */
				Assert(scalarVal->type == jbvArray);
				(*pstate)->size = scalarVal->val.array.nElems;
			}
			else
			{
				(*pstate)->size = 4;
			}
			(*pstate)->contVal.val.array.elems = palloc(sizeof(JsonbValue) *
														(*pstate)->size);
			break;
		case WJB_BEGIN_OBJECT:
			Assert(!scalarVal);
			*pstate = pushState(pstate);
			result = &(*pstate)->contVal;
			(*pstate)->contVal.type = jbvObject;
			(*pstate)->contVal.val.object.nPairs = 0;
			(*pstate)->size = 4;
			(*pstate)->contVal.val.object.pairs = palloc(sizeof(JsonbPair) *
														 (*pstate)->size);
			break;
		case WJB_KEY:
			Assert(scalarVal->type == jbvString);
			appendKey(*pstate, scalarVal);
			break;
		case WJB_VALUE:
			/* Assert(IsAJsonbScalar(scalarVal)); */
			appendValue(*pstate, scalarVal);
			break;
		case WJB_ELEM:
			/* Assert(IsAJsonbScalar(scalarVal)); */
			appendElement(*pstate, scalarVal);
			break;
		case WJB_END_OBJECT:
			uniqueifyJsonbObject(&(*pstate)->contVal);
			/* fall through! */
		case WJB_END_ARRAY:
			/* Steps here common to WJB_END_OBJECT case */
			Assert(!scalarVal);
			result = &(*pstate)->contVal;

			/*
			 * Pop stack and push current array/object as value in parent
			 * array/object
			 */
			*pstate = (*pstate)->next;
			if (*pstate)
			{
				switch ((*pstate)->contVal.type)
				{
					case jbvArray:
						appendElement(*pstate, result);
						break;
					case jbvObject:
						appendValue(*pstate, result);
						break;
					default:
						elog(ERROR, "invalid jsonb container type");
				}
			}
			break;
		default:
			elog(ERROR, "unrecognized jsonb sequential processing token");
	}

	return result;
}

static JsonbValue *
pushSingleScalarJsonbValue(JsonbParseState **pstate, const JsonbValue *jbval,
						   bool unpackBinary)
{
	/* single root scalar */
	JsonbValue	va;

	va.type = jbvArray;
	va.val.array.rawScalar = true;
	va.val.array.nElems = 1;

	pushJsonbValue(pstate, WJB_BEGIN_ARRAY, &va);
	pushJsonbValueExt(pstate, WJB_ELEM, jbval, unpackBinary);
	return pushJsonbValue(pstate, WJB_END_ARRAY, NULL);
}

static JsonbValue *
pushNestedScalarJsonbValue(JsonbParseState **pstate, const JsonbValue *jbval,
						   bool isKey, bool unpackBinary)
{
	switch ((*pstate)->contVal.type)
	{
		case jbvArray:
			return pushJsonbValueExt(pstate, WJB_ELEM, jbval, unpackBinary);
		case jbvObject:
			return pushJsonbValueExt(pstate, isKey ? WJB_KEY : WJB_VALUE, jbval,
									 unpackBinary);
		default:
			elog(ERROR, "unexpected parent of nested structure");
			return NULL;
	}
}

JsonbValue *
pushScalarJsonbValue(JsonbParseState **pstate, const JsonbValue *jbval,
					 bool isKey, bool unpackBinary)
{
	return *pstate == NULL
			? pushSingleScalarJsonbValue(pstate, jbval, unpackBinary)
			: pushNestedScalarJsonbValue(pstate, jbval, isKey, unpackBinary);

}

/*
 * pushJsonbValue() worker:  Iteration-like forming of Jsonb
 */
static JsonbParseState *
pushState(JsonbParseState **pstate)
{
	JsonbParseState *ns = palloc(sizeof(JsonbParseState));

	ns->next = *pstate;
	return ns;
}

/*
 * pushJsonbValue() worker:  Append a pair key to state when generating a Jsonb
 */
static void
appendKey(JsonbParseState *pstate, const JsonbValue *string)
{
	JsonbValue *object = &pstate->contVal;

	Assert(object->type == jbvObject);
	Assert(string->type == jbvString);

	if (object->val.object.nPairs >= JSONB_MAX_PAIRS)
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("number of jsonb object pairs exceeds the maximum allowed (%zu)",
						JSONB_MAX_PAIRS)));

	if (object->val.object.nPairs >= pstate->size)
	{
		pstate->size *= 2;
		object->val.object.pairs = repalloc(object->val.object.pairs,
											sizeof(JsonbPair) * pstate->size);
	}

	object->val.object.pairs[object->val.object.nPairs].key = *string;
	object->val.object.pairs[object->val.object.nPairs].order = object->val.object.nPairs;
}

/*
 * pushJsonbValue() worker:  Append a pair value to state when generating a
 * Jsonb
 */
static void
appendValue(JsonbParseState *pstate, const JsonbValue *scalarVal)
{
	JsonbValue *object = &pstate->contVal;

	Assert(object->type == jbvObject);

	object->val.object.pairs[object->val.object.nPairs++].value = *scalarVal;
}

/*
 * pushJsonbValue() worker:  Append an element to state when generating a Jsonb
 */
static void
appendElement(JsonbParseState *pstate, const JsonbValue *scalarVal)
{
	JsonbValue *array = &pstate->contVal;

	Assert(array->type == jbvArray);

	if (array->val.array.nElems >= JSONB_MAX_ELEMS)
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("number of jsonb array elements exceeds the maximum allowed (%zu)",
						JSONB_MAX_ELEMS)));

	if (array->val.array.nElems >= pstate->size)
	{
		pstate->size *= 2;
		array->val.array.elems = repalloc(array->val.array.elems,
										  sizeof(JsonbValue) * pstate->size);
	}

	array->val.array.elems[array->val.array.nElems++] = *scalarVal;
}

/*
 * Get next JsonbValue while iterating
 *
 * Caller should initially pass their own, original iterator.  They may get
 * back a child iterator palloc()'d here instead.  The function can be relied
 * on to free those child iterators, lest the memory allocated for highly
 * nested objects become unreasonable, but only if callers don't end iteration
 * early (by breaking upon having found something in a search, for example).
 *
 * Callers in such a scenario, that are particularly sensitive to leaking
 * memory in a long-lived context may walk the ancestral tree from the final
 * iterator we left them with to its oldest ancestor, pfree()ing as they go.
 * They do not have to free any other memory previously allocated for iterators
 * but not accessible as direct ancestors of the iterator they're last passed
 * back.
 *
 * Returns "Jsonb sequential processing" token value.  Iterator "state"
 * reflects the current stage of the process in a less granular fashion, and is
 * mostly used here to track things internally with respect to particular
 * iterators.
 *
 * Clients of this function should not have to handle any jbvBinary values
 * (since recursive calls will deal with this), provided skipNested is false.
 * It is our job to expand the jbvBinary representation without bothering them
 * with it.  However, clients should not take it upon themselves to touch array
 * or Object element/pair buffers, since their element/pair pointers are
 * garbage.  Also, *val will not be set when returning WJB_END_ARRAY or
 * WJB_END_OBJECT, on the assumption that it's only useful to access values
 * when recursing in.
 */
static JsonbIteratorToken
jsonbIteratorNext(JsonIterator **jsit, JsonbValue *val, bool skipNested)
{
	jsonbIterator **it = (jsonbIterator **) jsit;
	int			entry_index;

	if (*it == NULL)
		return WJB_DONE;

	/*
	 * When stepping into a nested container, we jump back here to start
	 * processing the child. We will not recurse further in one call, because
	 * processing the child will always begin in JBI_ARRAY_START or
	 * JBI_OBJECT_START state.
	 */
recurse:
	switch ((*it)->state)
	{
		case JBI_ARRAY_START:
			/* Set v to array on first array call */
			val->type = jbvArray;
			val->val.array.nElems = (*it)->nElems;

			/*
			 * v->val.array.elems is not actually set, because we aren't doing
			 * a full conversion
			 */
			val->val.array.rawScalar = (*it)->isScalar;
			(*it)->curIndex = 0;
			(*it)->curDataOffset = 0;
			(*it)->curValueOffset = 0;	/* not actually used */
			/* Set state for next call */
			(*it)->state = JBI_ARRAY_ELEM;
			return WJB_BEGIN_ARRAY;

		case JBI_ARRAY_ELEM:
			if ((*it)->curIndex >= (*it)->nElems)
			{
				/*
				 * All elements within array already processed.  Report this
				 * to caller, and give it back original parent iterator (which
				 * independently tracks iteration progress at its level of
				 * nesting).
				 */
				*it = (jsonbIterator *)
						JsonIteratorFreeAndGetParent((JsonIterator *) *it);
				return WJB_END_ARRAY;
			}

			fillCompressedJsonbValue((*it)->compressed, (*it)->container,
									 (*it)->curIndex, (*it)->dataProper,
									 (*it)->curDataOffset, val);

			JBE_ADVANCE_OFFSET((*it)->curDataOffset,
							   (*it)->children[(*it)->curIndex]);
			(*it)->curIndex++;

			if (!IsAJsonbScalar(val) && !skipNested)
			{
				/* Recurse into container. */
				*it = iteratorFromContainer(val->val.binary.data, *it);
				goto recurse;
			}
			else
			{
				/*
				 * Scalar item in array, or a container and caller didn't want
				 * us to recurse into it.
				 */
				return WJB_ELEM;
			}

		case JBI_OBJECT_START:
			/* Set v to object on first object call */
			val->type = jbvObject;
			val->val.object.nPairs = (*it)->nElems;

			/*
			 * v->val.object.pairs is not actually set, because we aren't
			 * doing a full conversion
			 */
			(*it)->curIndex = 0;
			(*it)->curDataOffset = 0;
			(*it)->curValueOffset = getJsonbOffset((*it)->container,
												   (*it)->nElems);
			/* Set state for next call */
			(*it)->state = JBI_OBJECT_KEY;
			return WJB_BEGIN_OBJECT;

		case JBI_OBJECT_KEY:
			if ((*it)->curIndex >= (*it)->nElems)
			{
				/*
				 * All pairs within object already processed.  Report this to
				 * caller, and give it back original containing iterator
				 * (which independently tracks iteration progress at its level
				 * of nesting).
				 */
				*it = (jsonbIterator *)
						JsonIteratorFreeAndGetParent((JsonIterator *) *it);
				return WJB_END_OBJECT;
			}
			else
			{
				/* Return key of a key/value pair.  */
				fillCompressedJsonbValue((*it)->compressed, (*it)->container,
										 (*it)->curIndex, (*it)->dataProper,
										 (*it)->curDataOffset, val);

				if (val->type != jbvString)
					elog(ERROR, "unexpected jsonb type as object key");

				/* Set state for next call */
				(*it)->state = JBI_OBJECT_VALUE;
				return WJB_KEY;
			}

		case JBI_OBJECT_VALUE:
			/* Set state for next call */
			(*it)->state = JBI_OBJECT_KEY;

			entry_index = JSONB_KVMAP_ENTRY(&(*it)->kvmap, (*it)->curIndex) + (*it)->nElems;

			fillCompressedJsonbValue((*it)->compressed, (*it)->container,
									 entry_index,
									 (*it)->dataProper,
									 (*it)->kvmap.entry_size ?
									 getJsonbOffset((*it)->container, entry_index) :
									 (*it)->curValueOffset,
									 val);

			JBE_ADVANCE_OFFSET((*it)->curDataOffset,
							   (*it)->children[(*it)->curIndex]);
			if (!(*it)->kvmap.entry_size)
				JBE_ADVANCE_OFFSET((*it)->curValueOffset,
								   (*it)->children[(*it)->curIndex + (*it)->nElems]);
			(*it)->curIndex++;

			/*
			 * Value may be a container, in which case we recurse with new,
			 * child iterator (unless the caller asked not to, by passing
			 * skipNested).
			 */
			if (!IsAJsonbScalar(val) && !skipNested)
			{
				*it = iteratorFromContainer(val->val.binary.data, *it);
				goto recurse;
			}
			else
				return WJB_VALUE;
	}

	elog(ERROR, "invalid iterator state");
	return -1;
}

static jsonbIterator *
iteratorFromContainer(JsonContainer *container, jsonbIterator *parent)
{
	jsonbIterator *it = (jsonbIterator *) JsonbIteratorInit(container);
	it->ji.parent = &parent->ji;
	return it;
}

/*
 * Given a JsonContainer, expand to jsonbIterator to iterate over items
 * fully expanded to in-memory representation for manipulation.
 *
 * See jsonbIteratorNext() for notes on memory management.
 */
static JsonIterator *
jsonbIteratorInitExt(JsonContainer *cont,
					 const JsonbContainerHeader *container,
					 struct CompressedJsonb *cjb)
{
	jsonbIterator *it;
	int			type = container->header & JBC_TMASK;

	it = palloc0(sizeof(jsonbIterator));
	it->ji.container = cont;
	it->ji.parent = NULL;
	it->ji.next = jsonbIteratorNext;
	it->container = container;
	it->nElems = container->header & JBC_CMASK;
	it->compressed = cjb;

	/* Array starts just after header */
	it->children = container->children;

	switch (type)
	{
		case JBC_TSCALAR:
			it->isScalar = true;
			/* FALLTHROUGH */
		case JBC_TARRAY:
			it->dataProper =
				(char *) it->children + it->nElems * sizeof(JEntry);
			/* This is either a "raw scalar", or an array */
			Assert(!it->isScalar || it->nElems == 1);

			it->state = JBI_ARRAY_START;
			break;

		case JBC_TOBJECT:
		case JBC_TOBJECT_SORTED:
			it->dataProper =
				(char *) it->children + it->nElems * sizeof(JEntry) * 2;
			it->dataProper = initKVMap(&it->kvmap, it->dataProper, it->nElems,
									   type == JBC_TOBJECT_SORTED);

			it->state = JBI_OBJECT_START;
			break;

		default:
			elog(ERROR, "unknown type of jsonb container");
	}

	if (it->dataProper && cjb)
#ifndef JSONB_DETOAST_ITERATOR
		CompressedDatumDecompress(cjb->datum,
								  it->dataProper - (char *) cjb->datum->data);
#else
		PG_DETOAST_ITERATE(cjb->iter, it->dataProper);
#endif

	return (JsonIterator *) it;
}

static JsonIterator *
jsonbIteratorInit(JsonContainer *cont)
{
	return jsonbIteratorInitExt(cont, (const JsonbContainerHeader *) JsonContainerDataPtr(cont), NULL);
}

/*
 * Worker for "contains" operator's function
 *
 * Formally speaking, containment is top-down, unordered subtree isomorphism.
 *
 * Takes iterators that belong to some container type.  These iterators
 * "belong" to those values in the sense that they've just been initialized in
 * respect of them by the caller (perhaps in a nested fashion).
 *
 * "val" is lhs Jsonb, and mContained is rhs Jsonb when called from top level.
 * We determine if mContained is contained within val.
 */

bool
JsonbDeepContains(JsonContainer *cval, JsonContainer *ccont)
{
	JsonbIterator	   *icont;
	JsonbValue			vcont;
	JsonbIteratorToken	rcont;

	/*
	 * Guard against stack overflow due to overly complex Jsonb.
	 *
	 * Functions called here independently take this precaution, but that
	 * might not be sufficient since this is also a recursive function.
	 */
	check_stack_depth();

	if (JsonContainerIsObject(cval) != JsonContainerIsObject(ccont))
	{
		/*
		 * The differing return values can immediately be taken as indicating
		 * two differing container types at this nesting level, which is
		 * sufficient reason to give up entirely (but it should be the case
		 * that they're both some container type).
		 */
		return false;
	}
	else if (JsonContainerIsObject(cval))
	{
		/*
		 * If the lhs has fewer pairs than the rhs, it can't possibly contain
		 * the rhs.  (This conclusion is safe only because we de-duplicate
		 * keys in all Jsonb objects; thus there can be no corresponding
		 * optimization in the array case.)  The case probably won't arise
		 * often, but since it's such a cheap check we may as well make it.
		 */
		if (JsonContainerSize(cval) >= 0 &&
			JsonContainerSize(ccont) >= 0 &&
			JsonContainerSize(cval) < JsonContainerSize(ccont))
			return false;

		icont = JsonbIteratorInit(ccont);
		rcont = JsonbIteratorNext(&icont, &vcont, false);
		Assert(rcont == WJB_BEGIN_OBJECT);

		/*
		 * Work through rhs "is it contained within?" object.
		 *
		 * When we get through caller's rhs "is it contained within?"
		 * object without failing to find one of its values, it's
		 * contained.
		 */
		while ((rcont = JsonbIteratorNext(&icont, &vcont, false)) == WJB_KEY)
		{
			/* First, find value by key in lhs object ... */
			JsonbValue	lhsValBuf;
			JsonbValue *lhsVal = JsonFindKeyInObject(cval,
													 vcont.val.string.val,
													 vcont.val.string.len,
													 &lhsValBuf);

			if (!lhsVal)
				return false;

			/*
			 * ...at this stage it is apparent that there is at least a key
			 * match for this rhs pair.
			 */
			rcont = JsonbIteratorNext(&icont, &vcont, true);
			Assert(rcont == WJB_VALUE);

			/*
			 * Compare rhs pair's value with lhs pair's value just found using
			 * key
			 */
			if (lhsVal->type != vcont.type)
			{
				return false;
			}
			else if (IsAJsonbScalar(lhsVal))
			{
				if (!equalsJsonbScalarValue(lhsVal, &vcont))
					return false;
			}
			else
			{
				/* Nested container value (object or array) */
				Assert(lhsVal->type == jbvBinary);
				Assert(vcont.type == jbvBinary);

				/*
				 * Match "value" side of rhs datum object's pair recursively.
				 * It's a nested structure.
				 *
				 * Note that nesting still has to "match up" at the right
				 * nesting sub-levels.  However, there need only be zero or
				 * more matching pairs (or elements) at each nesting level
				 * (provided the *rhs* pairs/elements *all* match on each
				 * level), which enables searching nested structures for a
				 * single String or other primitive type sub-datum quite
				 * effectively (provided the user constructed the rhs nested
				 * structure such that we "know where to look").
				 *
				 * In other words, the mapping of container nodes in the rhs
				 * "vcontained" Jsonb to internal nodes on the lhs is
				 * injective, and parent-child edges on the rhs must be mapped
				 * to parent-child edges on the lhs to satisfy the condition
				 * of containment (plus of course the mapped nodes must be
				 * equal).
				 */
				if (!JsonbDeepContains(lhsVal->val.binary.data,
									   vcont.val.binary.data))
					return false;
			}
		}

		Assert(rcont == WJB_END_OBJECT);
		Assert(icont == NULL);
	}
	else
	{
		JsonbValue		   *lhsConts = NULL;
		uint32				nLhsElems = JsonContainerSize(cval);

		/*
		 * Handle distinction between "raw scalar" pseudo arrays, and real
		 * arrays.
		 *
		 * A raw scalar may contain another raw scalar, and an array may
		 * contain a raw scalar, but a raw scalar may not contain an array. We
		 * don't do something like this for the object case, since objects can
		 * only contain pairs, never raw scalars (a pair is represented by an
		 * rhs object argument with a single contained pair).
		 */
		if (JsonContainerIsScalar(cval) && !JsonContainerIsScalar(ccont))
			return false;

		icont = JsonbIteratorInit(ccont);
		rcont = JsonbIteratorNext(&icont, &vcont, false);
		Assert(rcont == WJB_BEGIN_ARRAY);

		/*
		 * Work through rhs "is it contained within?" array.
		 *
		 * When we get through caller's rhs "is it contained within?"
		 * array without failing to find one of its values, it's
		 * contained.
		 */
		while ((rcont = JsonbIteratorNext(&icont, &vcont, true)) == WJB_ELEM)
		{
			if (IsAJsonbScalar(&vcont))
			{
				if (!findJsonbValueFromContainer(cval, JB_FARRAY, &vcont))
					return false;
			}
			else
			{
				uint32		i;

				/*
				 * If this is first container found in rhs array (at this
				 * depth), initialize temp lhs array of containers
				 */
				if (lhsConts == NULL)
				{
					uint32			j = 0;
					JsonbIterator  *ival;
					JsonbValue		vval;

					if ((int32) nLhsElems < 0)
						nLhsElems = JsonGetArraySize(cval);

					if (nLhsElems == 0)
						return false;

					/* Make room for all possible values */
					lhsConts = palloc(sizeof(JsonbValue) * nLhsElems);

					ival = JsonbIteratorInit(cval);
					rcont = JsonbIteratorNext(&ival, &vval, true);
					Assert(rcont == WJB_BEGIN_ARRAY);

					for (i = 0; i < nLhsElems; i++)
					{
						/* Store all lhs elements in temp array */
						rcont = JsonbIteratorNext(&ival, &vval, true);
						Assert(rcont == WJB_ELEM);

						if (vval.type == jbvBinary)
							lhsConts[j++] = vval;
					}

					rcont = JsonbIteratorNext(&ival, &vval, true);
					Assert(rcont == WJB_END_ARRAY);
					Assert(ival == NULL);

					/* No container elements in temp array, so give up now */
					if (j == 0)
						return false;

					/* We may have only partially filled array */
					nLhsElems = j;
				}

				/* XXX: Nested array containment is O(N^2) */
				for (i = 0; i < nLhsElems; i++)
				{
					/* Nested container value (object or array) */
					if (JsonbDeepContains(lhsConts[i].val.binary.data,
										  vcont.val.binary.data))
						break;
				}

				/*
				 * Report rhs container value is not contained if couldn't
				 * match rhs container to *some* lhs cont
				 */
				if (i == nLhsElems)
					return false;
			}
		}

		Assert(rcont == WJB_END_ARRAY);
		Assert(icont == NULL);

		if (lhsConts != NULL)
			pfree(lhsConts);
	}

	return true;
}

/*
 * Hash a JsonbValue scalar value, mixing the hash value into an existing
 * hash provided by the caller.
 *
 * Some callers may wish to independently XOR in JB_FOBJECT and JB_FARRAY
 * flags.
 */
void
JsonbHashScalarValue(const JsonbValue *scalarVal, uint32 *hash)
{
	uint32		tmp;

	/* Compute hash value for scalarVal */
	switch (scalarVal->type)
	{
		case jbvNull:
			tmp = 0x01;
			break;
		case jbvString:
			tmp = DatumGetUInt32(hash_any((const unsigned char *) scalarVal->val.string.val,
										  scalarVal->val.string.len));
			break;
		case jbvNumeric:
			/* Must hash equal numerics to equal hash codes */
			tmp = DatumGetUInt32(DirectFunctionCall1(hash_numeric,
													 NumericGetDatum(scalarVal->val.numeric)));
			break;
		case jbvBool:
			tmp = scalarVal->val.boolean ? 0x02 : 0x04;

			break;
		default:
			elog(ERROR, "invalid jsonb scalar type");
			tmp = 0;			/* keep compiler quiet */
			break;
	}

	/*
	 * Combine hash values of successive keys, values and elements by rotating
	 * the previous value left 1 bit, then XOR'ing in the new
	 * key/value/element's hash value.
	 */
	*hash = pg_rotate_left32(*hash, 1);
	*hash ^= tmp;
}

/*
 * Hash a value to a 64-bit value, with a seed. Otherwise, similar to
 * JsonbHashScalarValue.
 */
void
JsonbHashScalarValueExtended(const JsonbValue *scalarVal, uint64 *hash,
							 uint64 seed)
{
	uint64		tmp;

	switch (scalarVal->type)
	{
		case jbvNull:
			tmp = seed + 0x01;
			break;
		case jbvString:
			tmp = DatumGetUInt64(hash_any_extended((const unsigned char *) scalarVal->val.string.val,
												   scalarVal->val.string.len,
												   seed));
			break;
		case jbvNumeric:
			tmp = DatumGetUInt64(DirectFunctionCall2(hash_numeric_extended,
													 NumericGetDatum(scalarVal->val.numeric),
													 UInt64GetDatum(seed)));
			break;
		case jbvBool:
			if (seed)
				tmp = DatumGetUInt64(DirectFunctionCall2(hashcharextended,
														 BoolGetDatum(scalarVal->val.boolean),
														 UInt64GetDatum(seed)));
			else
				tmp = scalarVal->val.boolean ? 0x02 : 0x04;

			break;
		default:
			elog(ERROR, "invalid jsonb scalar type");
			break;
	}

	*hash = ROTATE_HIGH_AND_LOW_32BITS(*hash);
	*hash ^= tmp;
}

/*
 * Are two scalar JsonbValues of the same type a and b equal?
 */
bool
equalsJsonbScalarValue(const JsonbValue *a, const JsonbValue *b)
{
	if (a->type == b->type)
	{
		switch (a->type)
		{
			case jbvNull:
				return true;
			case jbvString:
				return lengthCompareJsonbStringValue(a, b) == 0;
			case jbvNumeric:
				return DatumGetBool(DirectFunctionCall2(numeric_eq,
														PointerGetDatum(a->val.numeric),
														PointerGetDatum(b->val.numeric)));
			case jbvBool:
				return a->val.boolean == b->val.boolean;

			default:
				elog(ERROR, "invalid jsonb scalar type");
		}
	}
	elog(ERROR, "jsonb scalar type mismatch");
	return false;
}

/*
 * Compare two scalar JsonbValues, returning -1, 0, or 1.
 *
 * Strings are compared using the default collation.  Used by B-tree
 * operators, where a lexical sort order is generally expected.
 */
static int
compareJsonbScalarValue(const JsonbValue *a, const JsonbValue *b)
{
	if (a->type == b->type)
	{
		switch (a->type)
		{
			case jbvNull:
				return 0;
			case jbvString:
				return varstr_cmp(a->val.string.val,
								  a->val.string.len,
								  b->val.string.val,
								  b->val.string.len,
								  DEFAULT_COLLATION_OID);
			case jbvNumeric:
				return DatumGetInt32(DirectFunctionCall2(numeric_cmp,
														 PointerGetDatum(a->val.numeric),
														 PointerGetDatum(b->val.numeric)));
			case jbvBool:
				if (a->val.boolean == b->val.boolean)
					return 0;
				else if (a->val.boolean > b->val.boolean)
					return 1;
				else
					return -1;
			default:
				elog(ERROR, "invalid jsonb scalar type");
		}
	}
	elog(ERROR, "jsonb scalar type mismatch");
	return -1;
}


/*
 * Functions for manipulating the resizable buffer used by convertJsonb and
 * its subroutines.
 */

/*
 * Reserve 'len' bytes, at the end of the buffer, enlarging it if necessary.
 * Returns the offset to the reserved area. The caller is expected to fill
 * the reserved area later with copyToBuffer().
 */
int
reserveFromBuffer(StringInfo buffer, int len)
{
	int			offset;

	/* Make more room if needed */
	enlargeStringInfo(buffer, len);

	/* remember current offset */
	offset = buffer->len;

	/* reserve the space */
	buffer->len += len;

	/*
	 * Keep a trailing null in place, even though it's not useful for us; it
	 * seems best to preserve the invariants of StringInfos.
	 */
	buffer->data[buffer->len] = '\0';

	return offset;
}

/*
 * Copy 'len' bytes to a previously reserved area in buffer.
 */
static void
copyToBuffer(StringInfo buffer, int offset, const char *data, int len)
{
	memcpy(buffer->data + offset, data, len);
}

/*
 * A shorthand for reserveFromBuffer + copyToBuffer.
 */
void
appendToBuffer(StringInfo buffer, const char *data, int len)
{
	int			offset;

	offset = reserveFromBuffer(buffer, len);
	copyToBuffer(buffer, offset, data, len);
}


/*
 * Append padding, so that the length of the StringInfo is int-aligned.
 * Returns the number of padding bytes appended.
 */
static short
padBufferToInt(StringInfo buffer)
{
	int			padlen,
				p,
				offset;

	padlen = INTALIGN(buffer->len) - buffer->len;

	offset = reserveFromBuffer(buffer, padlen);

	/* padlen must be small, so this is probably faster than a memset */
	for (p = 0; p < padlen; p++)
		buffer->data[offset + p] = '\0';

	return padlen;
}

bool
JsonbEncode(StringInfoData *buffer, const JsonbValue *val, void *cxt, Node *escontext)
{
	JEntry	jentry;

	/* Make room for the varlena header */
	reserveFromBuffer(buffer, VARHDRSZ);

	if (!convertJsonbValue(buffer, &jentry, val, 0, escontext))
		return false;

	SET_VARSIZE(buffer->data, buffer->len);

	return true;
}

/*
 * Given a JsonbValue, convert to Jsonb. The result is palloc'd.
 */
void *
JsonEncode(const JsonbValue *val, JsonValueEncoder encoder, void *cxt, Node *escontext)
{
	StringInfoData	buffer;
#if 0
	MemoryContext	tmpcxt,
					oldcxt;
#endif

	/* Allocate an output buffer. It will be enlarged as needed */
	initStringInfo(&buffer);

#if 0
	tmpcxt = AllocSetContextCreate(CurrentMemoryContext,
								   "Json Encoding Context",
								   ALLOCSET_DEFAULT_MINSIZE,
								   ALLOCSET_DEFAULT_INITSIZE,
								   ALLOCSET_DEFAULT_MAXSIZE);
	oldcxt = MemoryContextSwitchTo(tmpcxt);
#endif

	if (!encoder(&buffer, val, cxt, escontext))
	{
		pfree(buffer.data);
		return NULL;
	}

#if 0
	MemoryContextSwitchTo(oldcxt);
	MemoryContextDelete(tmpcxt);
#endif
	/*
	 * Note: the JEntry of the root is discarded. Therefore the root
	 * JsonbContainer struct must contain enough information to tell what kind
	 * of value it is.
	 */

	return buffer.data;
}

/*
 * Subroutine of convertJsonb: serialize a single JsonbValue into buffer.
 *
 * The JEntry header for this node is returned in *header.  It is filled in
 * with the length of this value and appropriate type bits.  If we wish to
 * store an end offset rather than a length, it is the caller's responsibility
 * to adjust for that.
 *
 * If the value is an array or an object, this recurses. 'level' is only used
 * for debugging purposes.
 */
static bool
convertJsonbValue(StringInfo buffer, JEntry *header, const JsonbValue *val, int level, Node *escontext)
{
	check_stack_depth();

	if (!val)
		return true;

	/*
	 * A JsonbValue passed as val should never have a type of jbvBinary, and
	 * neither should any of its sub-components. Those values will be produced
	 * by convertJsonbArray and convertJsonbObject, the results of which will
	 * not be passed back to this function as an argument.
	 */

	if (IsAJsonbScalar(val))
		return convertJsonbScalar(buffer, header, val, escontext);
	else if (val->type == jbvArray)
		return convertJsonbArray(buffer, header, val, level, escontext);
	else if (val->type == jbvObject)
		return convertJsonbObject(buffer, header, val, level, escontext);
	else if (val->type == jbvBinary)
		return convertJsonbBinary(buffer, header, val, level, escontext);
	else
	{
		elog(ERROR, "unknown type of jsonb container to convert");
		return false;
	}
}

static bool
convertJsonbArray(StringInfo buffer, JEntry *header, const JsonbValue *val, int level, Node *escontext)
{
	int			base_offset;
	int			jentry_offset;
	int			i;
	int			totallen;
	uint32		containerhead;
	int			nElems = val->val.array.nElems;

	Assert(nElems >= 0);

	/* Remember where in the buffer this array starts. */
	base_offset = buffer->len;

	/* Align to 4-byte boundary (any padding counts as part of my data) */
	padBufferToInt(buffer);

	/*
	 * Construct the header Jentry and store it in the beginning of the
	 * variable-length payload.
	 */
	if (val->val.array.rawScalar)
	{
		Assert(nElems == 1);
		Assert(level == 0);
		containerhead = nElems | JBC_TSCALAR;
	}
	else
		containerhead = nElems | JBC_TARRAY;

	appendToBuffer(buffer, (char *) &containerhead, sizeof(uint32));

	/* Reserve space for the JEntries of the elements. */
	jentry_offset = reserveFromBuffer(buffer, sizeof(JEntry) * nElems);

	totallen = 0;
	for (i = 0; i < nElems; i++)
	{
		JsonbValue *elem = &val->val.array.elems[i];
		int			len;
		JEntry		meta;

		/*
		 * Convert element, producing a JEntry and appending its
		 * variable-length data to buffer
		 */
		if (!convertJsonbValue(buffer, &meta, elem, level + 1, escontext))
			return false;

		len = JBE_OFFLENFLD(meta);
		totallen += len;

		/*
		 * Bail out if total variable-length data exceeds what will fit in a
		 * JEntry length field.  We check this in each iteration, not just
		 * once at the end, to forestall possible integer overflow.
		 */
		if (totallen > JENTRY_OFFLENMASK)
			ereturn(escontext, false,
					(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
					 errmsg("total size of jsonb array elements exceeds the maximum of %u bytes",
							JENTRY_OFFLENMASK)));

		/*
		 * Convert each JB_OFFSET_STRIDE'th length to an offset.
		 */
		if ((i % JB_OFFSET_STRIDE) == 0)
			meta = (meta & JENTRY_TYPEMASK) | totallen | JENTRY_HAS_OFF;

		copyToBuffer(buffer, jentry_offset, (char *) &meta, sizeof(JEntry));
		jentry_offset += sizeof(JEntry);
	}

	/* Total data size is everything we've appended to buffer */
	totallen = buffer->len - base_offset;

	/* Check length again, since we didn't include the metadata above */
	if (totallen > JENTRY_OFFLENMASK)
		ereturn(escontext, false,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("total size of jsonb array elements exceeds the maximum of %u bytes",
						JENTRY_OFFLENMASK)));

	/* Initialize the header of this node in the container's JEntry array */
	*header = JENTRY_ISCONTAINER | totallen;

	return true;
}

static int
int_cmp(const void *a, const void *b)
{
	int			x = *(const int *) a;
	int			y = *(const int *) b;

	return x == y ? 0 : x > y ? 1 : -1;
}

static int
estimateJsonbValueSize(const JsonbValue *jbv)
{
	int			size;

	switch (jbv->type)
	{
		case jbvNull:
		case jbvBool:
			return 0;
		case jbvString:
			return jbv->val.string.len;
		case jbvNumeric:
			return VARSIZE_ANY(jbv->val.numeric);
		case jbvArray:
			size = offsetof(JsonbContainerHeader, children[jbv->val.array.nElems]);
			for (int i = 0; i < jbv->val.array.nElems; i++)
				size += estimateJsonbValueSize(&jbv->val.array.elems[i]);
			return size;
		case jbvObject:
			size = offsetof(JsonbContainerHeader, children[jbv->val.object.nPairs * 2]);
			for (int i = 0; i < jbv->val.object.nPairs; i++)
			{
				size += estimateJsonbValueSize(&jbv->val.object.pairs[i].key);
				size += estimateJsonbValueSize(&jbv->val.object.pairs[i].value);
			}
			return size;
		default:
			elog(ERROR, "invalid jsonb value type: %d", jbv->type);
			return 0;
	}
}

static bool
convertJsonbObject(StringInfo buffer, JEntry *header, const JsonbValue *val, int level, Node *escontext)
{
	int			base_offset;
	int			jentry_offset;
	int			i;
	int			totallen;
	uint32		containerheader;
	int			nPairs = val->val.object.nPairs;
	int			reserved_size;
	int			kvmap_entry_size;
	bool		sorted_values = jsonb_sort_field_values && nPairs > 1;
	struct
	{
		int			size;
		int32		index;
	}		   *values = sorted_values ? palloc(sizeof(*values) * nPairs) : NULL;

	Assert(nPairs >= 0);

	if (sorted_values)
	{
		for (i = 0; i < nPairs; i++)
		{
			values[i].index = i;
			values[i].size = estimateJsonbValueSize(&val->val.object.pairs[i].value);
		}

		qsort(values, nPairs, sizeof(*values), int_cmp);

		/* check if keys were really moved */
		sorted_values = false;

		for (i = 0; i < nPairs; i++)
		{
			if (values[i].index != i)
			{
				kvmap_entry_size = JSONB_KVMAP_ENTRY_SIZE(nPairs);
				sorted_values = true;
				break;
			}
		}
	}

	/* Remember where in the buffer this object starts. */
	base_offset = buffer->len;

	/* Align to 4-byte boundary (any padding counts as part of my data) */
	padBufferToInt(buffer);

	/*
	 * Construct the header Jentry and store it in the beginning of the
	 * variable-length payload.
	 */
	containerheader = nPairs | (sorted_values ? JBC_TOBJECT_SORTED : JBC_TOBJECT);
	appendToBuffer(buffer, (char *) &containerheader, sizeof(uint32));

	/* Reserve space for the JEntries of the keys and values. */
	reserved_size = sizeof(JEntry) * nPairs * 2;
	if (sorted_values)
		reserved_size += INTALIGN(kvmap_entry_size * nPairs);

	jentry_offset = reserveFromBuffer(buffer, reserved_size);

	/* Write key-value map */
	if (sorted_values)
	{
		int			kvmap_offset = jentry_offset + sizeof(JEntry) * nPairs * 2;

		for (i = 0; i < nPairs; i++)
		{
			uint8		entry1;
			uint16		entry2;
			uint32		entry4;
			void	   *pentry;

			if (kvmap_entry_size == 1)
			{
				entry1 = (uint8) i;
				pentry = &entry1;
			}
			else if (kvmap_entry_size == 2)
			{
				entry2 = (uint16) i;
				pentry = &entry2;
			}
			else
			{
				entry4 = (int32) i;
				pentry = &entry4;
			}

			copyToBuffer(buffer, kvmap_offset + values[i].index * kvmap_entry_size,
						 pentry, kvmap_entry_size);
		}

		if ((kvmap_entry_size * nPairs) % ALIGNOF_INT)
			memset(buffer->data + kvmap_offset + kvmap_entry_size * nPairs, 0,
				   ALIGNOF_INT - (kvmap_entry_size * nPairs) % ALIGNOF_INT);
	}

	/*
	 * Iterate over the keys, then over the values, since that is the ordering
	 * we want in the on-disk representation.
	 */
	totallen = 0;

	for (i = 0; i < nPairs; i++)
	{
		JsonbPair  *pair = &val->val.object.pairs[i];
		int			len;
		JEntry		meta;

		/*
		 * Convert key, producing a JEntry and appending its variable-length
		 * data to buffer
		 */
		if (!convertJsonbScalar(buffer, &meta, &pair->key, escontext))
			return false;

		len = JBE_OFFLENFLD(meta);
		totallen += len;

		/*
		 * Bail out if total variable-length data exceeds what will fit in a
		 * JEntry length field.  We check this in each iteration, not just
		 * once at the end, to forestall possible integer overflow.
		 */
		if (totallen > JENTRY_OFFLENMASK)
			ereturn(escontext, false,
					(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
					 errmsg("total size of jsonb object elements exceeds the maximum of %u bytes",
							JENTRY_OFFLENMASK)));

		/*
		 * Convert each JB_OFFSET_STRIDE'th length to an offset.
		 */
		if ((i % JB_OFFSET_STRIDE) == 0)
			meta = (meta & JENTRY_TYPEMASK) | totallen | JENTRY_HAS_OFF;

		copyToBuffer(buffer, jentry_offset, (char *) &meta, sizeof(JEntry));
		jentry_offset += sizeof(JEntry);
	}

	for (i = 0; i < nPairs; i++)
	{
		int			val_index = sorted_values ? values[i].index : i;
		JsonbPair  *pair = &val->val.object.pairs[val_index];
		int			len;
		JEntry		meta;

		/*
		 * Convert value, producing a JEntry and appending its variable-length
		 * data to buffer
		 */
		if (!convertJsonbValue(buffer, &meta, &pair->value, level + 1, escontext))
			return false;

		len = JBE_OFFLENFLD(meta);
		totallen += len;

		/*
		 * Bail out if total variable-length data exceeds what will fit in a
		 * JEntry length field.  We check this in each iteration, not just
		 * once at the end, to forestall possible integer overflow.
		 */
		if (totallen > JENTRY_OFFLENMASK)
			ereturn(escontext, false,
					(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
					 errmsg("total size of jsonb object elements exceeds the maximum of %u bytes",
							JENTRY_OFFLENMASK)));

		/*
		 * Convert each JB_OFFSET_STRIDE'th length to an offset.
		 */
		if (((i + nPairs) % JB_OFFSET_STRIDE) == 0)
			meta = (meta & JENTRY_TYPEMASK) | totallen | JENTRY_HAS_OFF;

		copyToBuffer(buffer, jentry_offset, (char *) &meta, sizeof(JEntry));
		jentry_offset += sizeof(JEntry);
	}

	if (values)
		pfree(values);

	/* Total data size is everything we've appended to buffer */
	totallen = buffer->len - base_offset;

	/* Check length again, since we didn't include the metadata above */
	if (totallen > JENTRY_OFFLENMASK)
		ereturn(escontext, false,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("total size of jsonb object elements exceeds the maximum of %u bytes",
						JENTRY_OFFLENMASK)));

	/* Initialize the header of this node in the container's JEntry array */
	*header = JENTRY_ISCONTAINER | totallen;

	return true;
}

static bool
convertJsonbScalar(StringInfo buffer, JEntry *header, const JsonbValue *scalarVal, Node *escontext)
{
	int			numlen;
	short		padlen;

	switch (scalarVal->type)
	{
		case jbvNull:
			*header = JENTRY_ISNULL;
			break;

		case jbvString:
			if (scalarVal->val.string.len > JENTRY_OFFLENMASK)
				ereturn(escontext, false,
						(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
						 errmsg("string too long to represent as jsonb string"),
						 errdetail("Due to an implementation restriction, jsonb strings cannot exceed %d bytes.",
								   JENTRY_OFFLENMASK)));

			appendToBuffer(buffer, scalarVal->val.string.val,
							scalarVal->val.string.len);

			*header = scalarVal->val.string.len;
			break;

		case jbvNumeric:
			numlen = VARSIZE_ANY(scalarVal->val.numeric);
			padlen = padBufferToInt(buffer);

			appendToBuffer(buffer, (char *) scalarVal->val.numeric, numlen);

			*header = JENTRY_ISNUMERIC | (padlen + numlen);
			break;

		case jbvBool:
			*header = (scalarVal->val.boolean) ?
				JENTRY_ISBOOL_TRUE : JENTRY_ISBOOL_FALSE;
			break;

		case jbvDatetime:
			{
				char		buf[MAXDATELEN + 1];
				size_t		len;

				JsonEncodeDateTime(buf,
								   scalarVal->val.datetime.value,
								   scalarVal->val.datetime.typid,
								   &scalarVal->val.datetime.tz);
				len = strlen(buf);
				appendToBuffer(buffer, buf, len);

				*header = len;
			}
			break;

		default:
			elog(ERROR, "invalid jsonb scalar type");
	}

	return true;
}

static bool
convertJsonbBinary(StringInfo buffer, JEntry *pheader, const JsonbValue *val,
				   int level, Node *escontext)
{
	JsonContainer *jc = val->val.binary.data;

	Assert(val->type == jbvBinary);

	if ((jc->ops == &jsonbContainerOps ||
		 jc->ops == &jsonbzContainerOps) && !JsonContainerIsScalar(jc))
	{
		JsonbContainerHeader *jbc;
		int			base_offset = buffer->len;

		jbc = jc->ops == &jsonbzContainerOps ?
			jsonbzDecompress(jc) : JsonContainerDataPtr(jc);

		padBufferToInt(buffer);
		appendToBuffer(buffer, (void *) jbc, jc->len);
		*pheader = JENTRY_ISCONTAINER | (buffer->len - base_offset);

		return true;
	}
	else
		return convertJsonbValue(buffer, pheader, JsonValueUnpackBinary(val), level, escontext);
}

/*
 * Compare two jbvString JsonbValue values, a and b.
 *
 * This is a special qsort() comparator used to sort strings in certain
 * internal contexts where it is sufficient to have a well-defined sort order.
 * In particular, object pair keys are sorted according to this criteria to
 * facilitate cheap binary searches where we don't care about lexical sort
 * order.
 *
 * a and b are first sorted based on their length.  If a tie-breaker is
 * required, only then do we consider string binary equality.
 */
int
lengthCompareJsonbStringValue(const void *a, const void *b)
{
	const JsonbValue *va = (const JsonbValue *) a;
	const JsonbValue *vb = (const JsonbValue *) b;

	Assert(va->type == jbvString);
	Assert(vb->type == jbvString);

	return lengthCompareJsonbString(va->val.string.val, va->val.string.len,
									vb->val.string.val, vb->val.string.len);
}

/*
 * Subroutine for lengthCompareJsonbStringValue
 *
 * This is also useful separately to implement binary search on
 * JsonbContainers.
 */
int
lengthCompareJsonbString(const char *val1, int len1, const char *val2, int len2)
{
	if (len1 == len2)
		return memcmp(val1, val2, len1);
	else
		return len1 > len2 ? 1 : -1;
}

/*
 * qsort_arg() comparator to compare JsonbPair values.
 *
 * Third argument 'binequal' may point to a bool. If it's set, *binequal is set
 * to true iff a and b have full binary equality, since some callers have an
 * interest in whether the two values are equal or merely equivalent.
 *
 * N.B: String comparisons here are "length-wise"
 *
 * Pairs with equals keys are ordered such that the order field is respected.
 */
static int
lengthCompareJsonbPair(const void *a, const void *b, void *binequal)
{
	const JsonbPair *pa = (const JsonbPair *) a;
	const JsonbPair *pb = (const JsonbPair *) b;
	int			res;

	res = lengthCompareJsonbStringValue(&pa->key, &pb->key);
	if (res == 0 && binequal)
		*((bool *) binequal) = true;

	/*
	 * Guarantee keeping order of equal pair.  Unique algorithm will prefer
	 * first element as value.
	 */
	if (res == 0)
		res = (pa->order > pb->order) ? -1 : 1;

	return res;
}

/*
 * Sort and unique-ify pairs in JsonbValue object
 */
static void
uniqueifyJsonbObject(JsonbValue *object)
{
	bool		hasNonUniq = false;

	Assert(object->type == jbvObject);
	Assert(object->val.object.nPairs >= 0);

	if (object->val.object.nPairs > 1)
		qsort_arg(object->val.object.pairs, object->val.object.nPairs, sizeof(JsonbPair),
				  lengthCompareJsonbPair, &hasNonUniq);

	if (hasNonUniq)
	{
		JsonbPair  *ptr = object->val.object.pairs + 1,
				   *res = object->val.object.pairs;

		while (ptr - object->val.object.pairs < object->val.object.nPairs)
		{
			/* Avoid copying over duplicate */
			if (lengthCompareJsonbStringValue(ptr, res) != 0)
			{
				res++;
				if (ptr != res)
					memcpy(res, ptr, sizeof(JsonbPair));
			}
			ptr++;
		}

		object->val.object.nPairs = res + 1 - object->val.object.pairs;
	}
}

static void
jsonbInitContainerFromHeader(JsonContainerData *jc, JsonbContainerHeader *jbc)
{
	jc->size = jbc->header & JBC_CMASK;
	switch (jbc->header & JBC_TMASK)
	{
		case JBC_TOBJECT:
		case JBC_TOBJECT_SORTED:
			jc->type = jbvObject;
			break;
		case JBC_TARRAY:
			jc->type = jbvArray;
			break;
		case JBC_TSCALAR:
			jc->type = jbvArray | jbvScalar;
			break;
		default:
			elog(ERROR, "invalid jsonb container type: %d",
				 jbc->header & JBC_TMASK);
	}
}

static void
jsonbInitContainer(JsonContainerData *jc, JsonbContainerHeader *jbc, int len)
{
	jc->ops = &jsonbContainerOps;
	JsonContainerDataPtr(jc) = jbc;
	jc->len = len;
	jc->toasterid = InvalidOid;
	jsonbInitContainerFromHeader(jc, jbc);
}

static void
jsonbInit(JsonContainerData *jc, Datum value)
{
	JsonbDatum *jb = (JsonbDatum *) DatumGetPointer(value);

	jsonbInitContainer(jc, &jb->root, VARSIZE_ANY_EXHDR(jb));
}

JsonContainerOps
jsonbContainerOps =
{
	sizeof(JsonbContainerHeader *),
	jsonbInit,
	jsonbIteratorInit,
	jsonbFindKeyInObject,
	jsonbFindValueInArray,
	jsonbGetArrayElement,
	NULL,
	JsonbToCStringRaw,
	JsonCopyFlat,
	NULL,
	NULL
};

#ifndef JSONB_DETOAST_ITERATOR
static void
CompressedDatumInit(CompressedDatum *cd, Datum d)
{
	struct varlena *data = detoast_external_attr((struct varlena *) DatumGetPointer(d));

	if (VARATT_IS_COMPRESSED(data))
	{
		cd->compressed = data;
		cd->data = NULL;
		cd->state = NULL;
		cd->decompressed_len = 0;
		cd->total_len = TOAST_COMPRESS_EXTSIZE(data) + VARHDRSZ;
	}
	else
	{
		if (VARATT_IS_SHORT(data))
		{
			struct varlena *short_data = data;

			data = detoast_attr(data);

			if (DatumGetPointer(d) != (Pointer) short_data)
				pfree(short_data);
		}

		cd->compressed = NULL;
		cd->data = data;
		cd->state = NULL;
		cd->total_len = cd->decompressed_len = VARSIZE(data);
	}
}

static void
CompressedDatumDecompress(CompressedDatum *cd, Size offset)
{
	int			res;

	if (!cd->compressed || offset <= cd->decompressed_len)
		return;

#if 0
	cd->data = detoast_attr_slice(cd->compressed, 0, offset - VARHDRSZ);
#else
	if (!cd->data)
	{
		cd->data = palloc(cd->total_len);
		SET_VARSIZE(cd->data, cd->total_len);
	}

	res = pglz_decompress_state(VARDATA(cd->compressed) + VARHDRSZ_COMPRESSED,
								VARSIZE(cd->compressed) - VARHDRSZ_COMPRESSED,
								VARDATA(cd->data), offset - VARHDRSZ,
								false, &cd->state);

	if (res < 0)
		elog(ERROR, "corrupt compressed data");

	if (res != offset - VARHDRSZ)
		elog(ERROR, "premature end of compressed data");
#endif

	cd->decompressed_len = offset;
}

static void
CompressedDatumDecompressAll(CompressedDatum *cd)
{
	if (!cd->compressed || cd->decompressed_len >= cd->total_len)
		return;

	if (cd->data)
		CompressedDatumDecompress(cd, cd->total_len);
	else
	{
		cd->data = detoast_attr(cd->compressed);
		cd->decompressed_len = cd->total_len;
	}
}
#endif

static void
jsonbzInitContainer(JsonContainerData *jc, CompressedJsonb *cjb, int len)
{
#ifndef JSONB_DETOAST_ITERATOR
	JsonbDatum *jb = (JsonbDatum *) cjb->datum->data;
#else
	JsonbDatum *jb = (JsonbDatum *) cjb->iter->buf->buf;
#endif
	JsonbContainerHeader *jbc = (JsonbContainerHeader *)((char *) jb + cjb->offset);

	*(CompressedJsonb *) &jc->_data = *cjb;

	jc->ops = &jsonbzContainerOps;
	jc->len = len;
	jc->toasterid = InvalidOid;
	jsonbInitContainerFromHeader(jc, jbc);
}

static JsonbContainerHeader *
jsonbzDecompress(JsonContainer *jc)
{
	CompressedJsonb *cjb = (CompressedJsonb *) &jc->_data;
#ifndef JSONB_DETOAST_ITERATOR
	JsonbDatum *jb = (JsonbDatum *) cjb->datum->data;
#else
	JsonbDatum *jb = (JsonbDatum *) cjb->iter->buf->buf;
#endif
	JsonbContainerHeader *container = (JsonbContainerHeader *)((char *) jb + cjb->offset);

#ifndef JSONB_DETOAST_ITERATOR
	CompressedDatumDecompress(cjb->datum, cjb->offset + jc->len);
#else
	PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + cjb->offset + jc->len);
#endif

	return container;
}

static JsonbValue *
fillCompressedJsonbValue(CompressedJsonb *cjb,
						 const JsonbContainerHeader *container,
						 int index, char *base_addr, uint32 offset,
						 JsonValue *result)
{
	JEntry		entry = container->children[index];
	uint32		len = getJsonbLength(container, index);
	Size		base_offset;

	if (!cjb)
	{
		fillJsonbValue(container, index, base_addr, offset, result);
		return result;
	}

#ifndef JSONB_DETOAST_ITERATOR
	base_offset = base_addr - (char *) cjb->datum->data;
#else
	base_offset = base_addr - (char *) cjb->iter->buf->buf;
#endif

	if (JBE_ISCONTAINER(entry) /* && len > JSONBZ_MIN_CONTAINER_LEN */)
	{
		JsonContainerData *cont = JsonContainerAlloc(&jsonbzContainerOps);
		CompressedJsonb cjb2;

#ifndef JSONB_DETOAST_ITERATOR
		cjb2.datum = cjb->datum;
#else
		cjb2.iter = cjb->iter;
		//cjb2.iter->nrefs++;
#endif

		/* Remove alignment padding from data pointer and length */
		cjb2.offset = base_offset + INTALIGN(offset);

		len -= INTALIGN(offset) - offset;

#ifndef JSONB_DETOAST_ITERATOR
		CompressedDatumDecompress(cjb->datum, cjb2.offset +
								  offsetof(JsonbContainerHeader, children));
#else
		PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + cjb2.offset +
						   offsetof(JsonbContainerHeader, children));
#endif

		jsonbzInitContainer(cont, &cjb2, len);
		JsonValueInitBinary(result, cont);
	}
	else
	{
#ifndef JSONB_DETOAST_ITERATOR
		//CompressedDatumDecompressAll(cjb->datum);
		CompressedDatumDecompress(cjb->datum, base_offset + offset + len);
#else
		PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + base_offset + offset + len);
#endif
		fillJsonbValue(container, index, base_addr, offset, result);
	}

	return result;
}

static JsonbValue *
findValueInCompressedJsonbObject(CompressedJsonb *cjb, const char *keystr, int keylen,
								 JsonValue *res)
{
#ifndef JSONB_DETOAST_ITERATOR
	JsonbDatum *jb = (JsonbDatum *) cjb->datum->data;
#else
	JsonbDatum *jb = (JsonbDatum *) cjb->iter->buf->buf;
#endif
	JsonbContainerHeader *container = (JsonbContainerHeader *)((char *) jb + cjb->offset);
	JsonbValue	key;
	JEntry	   *children = container->children;
	int			count = container->header & JBC_CMASK;
	/* Since this is an object, account for *Pairs* of Jentrys */
	bool		sorted_values = (container->header & JBC_TMASK) == JBC_TOBJECT_SORTED;
	char	   *base_addr = (char *) (children + count * 2);
	JsonbKVMap	kvmap;
	Size		base_offset;
	uint32		stopLow = 0,
				stopHigh = count;

	Assert((jb->root.header & JBC_TMASK) == JBC_TOBJECT ||
		   (jb->root.header & JBC_TMASK) == JBC_TOBJECT_SORTED);

	/* Quick out if object/array is empty */
	if (count <= 0)
		return NULL;

	base_addr = initKVMap(&kvmap, base_addr, count, sorted_values);
	base_offset = base_addr - (char *) jb;

	key.type = jbvString;
	key.val.string.val = keystr;
	key.val.string.len = keylen;

#ifndef JSONB_DETOAST_ITERATOR
	Assert(cjb->datum->compressed);
		//return findJsonbValueFromContainer(container, JB_FOBJECT, &key);

	CompressedDatumDecompress(cjb->datum, base_offset);
#else
	PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + base_offset);
#endif

	/* Binary search on object/pair keys *only* */
	while (stopLow < stopHigh)
	{
		uint32		stopMiddle;
		int			difference;
		uint32		offset;
		uint32		len;

		stopMiddle = stopLow + (stopHigh - stopLow) / 2;

		offset = getJsonbOffset(container, stopMiddle);
		len = getJsonbLength(container, stopMiddle);

#ifndef JSONB_DETOAST_ITERATOR
		CompressedDatumDecompress(cjb->datum, base_offset + offset + len);
#else
		PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + base_offset + offset + len);
#endif

		difference = lengthCompareJsonbString(base_addr + offset, len,
											  key.val.string.val,
											  key.val.string.len);

		if (difference == 0)
		{
			/* Found our key, return corresponding value */
			int			index = JSONB_KVMAP_ENTRY(&kvmap, stopMiddle) + count;

			if (!res)
				res = palloc(sizeof(*res));

			return fillCompressedJsonbValue(cjb, container, index, base_addr,
											getJsonbOffset(container, index),
											res);
		}
		else
		{
			if (difference < 0)
				stopLow = stopMiddle + 1;
			else
				stopHigh = stopMiddle;
		}
	}

	return NULL;
}

static JsonValue *
jsonbzFindKeyInObject(JsonContainer *jc, const char *key, int len,
					  JsonValue *res)
{
	CompressedJsonb *cjb = (void *) &jc->_data;
#ifndef JSONB_DETOAST_ITERATOR	/* FIXME */
	JsonbDatum *jb = (JsonbDatum *) cjb->datum->data;
	JsonbContainerHeader *jbc = (JsonbContainerHeader *)((char *) jb + cjb->offset);

	if (!cjb->datum->compressed)
	{
		JsonContainerData jcd;

		jsonbInitContainer(&jcd, jbc, jc->len);

		return jsonbFindKeyInObject(&jcd, key, len, res);
	}
#endif

	return findValueInCompressedJsonbObject(cjb, key, len, res);
}

typedef struct JsonbzArrayIterator
{
	CompressedJsonb *cjb;
	const JsonbContainerHeader *container;
	char	   *base_addr;
	int			index;
	int			count;
	uint32		offset;
} JsonbzArrayIterator;

static void
JsonbzArrayIteratorInit(JsonbzArrayIterator *it, CompressedJsonb *cjb)
{
#ifndef JSONB_DETOAST_ITERATOR
	JsonbDatum *jb = (JsonbDatum *) cjb->datum->data;
#else
	JsonbDatum *jb = (JsonbDatum *) cjb->iter->buf->buf;
#endif
	const JsonbContainerHeader *jbc = (const JsonbContainerHeader *)((char *) jb + cjb->offset);

	it->cjb = cjb;
	it->container = jbc;
	it->index = 0;
	it->count = (jbc->header & JBC_CMASK);
	it->offset = 0;
	it->base_addr = (char *) &jbc->children[it->count];
}

static bool
JsonbzArrayIteratorNext(JsonbzArrayIterator *it, JsonValue *result)
{
	if (it->index >= it->count)
		return false;

	fillCompressedJsonbValue(it->cjb, it->container, it->index, it->base_addr,
							 it->offset, result);

	JBE_ADVANCE_OFFSET(it->offset, it->container->children[it->index]);
	it->index++;

	return true;
}

static JsonValue *
JsonbzArrayIteratorGetIth(JsonbzArrayIterator *it, uint32 index)
{
	if (index >= it->count)
		return NULL;

	return fillCompressedJsonbValue(it->cjb, it->container, index,
									it->base_addr,
									getJsonbOffset(it->container, index),
									palloc(sizeof(JsonValue)));
}

static JsonValue *
jsonbzFindValueInArray(JsonContainer *jc, const JsonValue *val)
{
	CompressedJsonb *cjb = (void *) &jc->_data;
	JsonbzArrayIterator it;
	JsonValue  *result = palloc(sizeof(JsonValue));

	JsonbzArrayIteratorInit(&it, cjb);

	while (JsonbzArrayIteratorNext(&it, result))
	{
		if (val->type == result->type &&
			equalsJsonbScalarValue(val, result))
			return result;
	}

	pfree(result);
	return NULL;
}

static JsonValue *
jsonbzGetArrayElement(JsonContainer *jc, uint32 index)
{
	CompressedJsonb *cjb = (void *) &jc->_data;
	JsonbzArrayIterator it;

	if (!JsonContainerIsArray(jc))
		elog(ERROR, "not a jsonb array");

	JsonbzArrayIteratorInit(&it, cjb);

	return JsonbzArrayIteratorGetIth(&it, index);
}

static JsonIterator *
jsonbzIteratorInit(JsonContainer *jc)
{
	CompressedJsonb *cjb = (void *) &jc->_data;
#ifndef JSONB_DETOAST_ITERATOR
	JsonbDatum *jb = (JsonbDatum *) cjb->datum->data;
#else
	JsonbDatum *jb = (JsonbDatum *) cjb->iter->buf->buf;
#endif
	JsonbContainerHeader *jbc = (JsonbContainerHeader *)((char *) jb + cjb->offset);

	if (!jsonb_partial_decompression)
#ifndef JSONB_DETOAST_ITERATOR
		CompressedDatumDecompressAll(cjb->datum);
#else
		PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->capacity);
#endif

	return jsonbIteratorInitExt(jc, jbc, cjb);
}

static void
#ifndef JSONB_DETOAST_ITERATOR
jsonbzInitFromCompresedDatum(JsonContainerData *jc, CompressedDatum *cd)
#else
jsonbzInitFromDetoastIterator(JsonContainerData *jc, DetoastIterator iter)
#endif
{
	CompressedJsonb *cjb = palloc(sizeof(*cjb));
#ifndef JSONB_DETOAST_ITERATOR
	CompressedDatum *cd = palloc(sizeof(*cd));

	cjb->datum = cd;
	cjb->offset = offsetof(JsonbDatum, root);

	if (!jsonb_partial_decompression)
		CompressedDatumDecompressAll(cd);
	else
		CompressedDatumDecompress(cd, 256);

	jsonbzInitContainer(jc, cjb, VARSIZE_ANY_EXHDR(cd->data)); // cd->total_len - VARHDRSZ
#else
	cjb->iter = iter;
	cjb->offset = offsetof(JsonbDatum, root);

	if (!jsonb_partial_decompression)
		PG_DETOAST_ITERATE(iter, iter->buf->capacity);
	else
		PG_DETOAST_ITERATE(iter, Min(iter->buf->buf + 256, iter->buf->capacity));

	jsonbzInitContainer(jc, cjb, VARSIZE_ANY_EXHDR(iter->buf->buf)); // cd->total_len - VARHDRSZ
#endif
}

static void
jsonbzFree(JsonContainer *jc)
{
	CompressedJsonb *cjb = (CompressedJsonb *) &jc->_data;

#ifdef JSONB_DETOAST_ITERATOR
	if (cjb->iter)
		free_detoast_iterator(cjb->iter);
#endif
}

static void
jsonbzInit(JsonContainerData *jc, Datum value)
{
#ifndef JSONB_DETOAST_ITERATOR
	CompressedDatum *cd = palloc(sizeof(*cd));

	CompressedDatumInit(cd, value);

	jsonbzInitFromCompresedDatum(jc, cd);
#else
	DetoastIterator iter = create_detoast_iterator((struct varlena *) DatumGetPointer(value));

	jsonbzInitFromDetoastIterator(jc, iter);
#endif
}

JsonContainerOps
jsonbzContainerOps =
{
	sizeof(CompressedJsonb),
	jsonbzInit,
	jsonbzIteratorInit,
	jsonbzFindKeyInObject,
	jsonbzFindValueInArray,
	jsonbzGetArrayElement,
	NULL,
	JsonbToCStringRaw,
	JsonCopyFlat,	// FIXME
	jsonbzFree,
	NULL
};

Json *
DatumGetJsonbPC(Datum datum, Json *tmp, bool copy)
{
#ifndef JSONB_DETOAST_ITERATOR
	CompressedDatum cd;
#else
	DetoastIterator iter;
#endif
	Json	   *js;
	struct varlena *src = (struct varlena *) DatumGetPointer(datum);

	if (copy)
	{
		if (VARATT_IS_EXTERNAL_ONDISK(src) || VARATT_IS_COMPRESSED(src))
		{
			Size		len = VARSIZE_ANY(src);
			struct varlena *result = (struct varlena *) palloc(len);

			memcpy(result, src, len);
			src = result;
		}
		else
		{
			src = pg_detoast_datum_copy(src);
		}

		datum = PointerGetDatum(src);
	}

	if (!jsonb_partial_decompression)
		return DatumGetJson(datum, &jsonbContainerOps, tmp);

#ifndef JSONB_DETOAST_ITERATOR
	CompressedDatumInit(&cd, datum);

	if (!cd.compressed)
		return DatumGetJson(PointerGetDatum(cd.data), &jsonbContainerOps, tmp);
#else
	if (!jsonb_partial_detoast)
		src = detoast_external_attr(src);

	iter = create_detoast_iterator(src);

	if (!iter)
		return DatumGetJson(PointerGetDatum(src), &jsonbContainerOps, tmp);
#endif

	js = JsonExpand(tmp, (Datum) 0, false, &jsonbzContainerOps);

#ifndef JSONB_DETOAST_ITERATOR
	jsonbzInitFromCompresedDatum(&js->root,
								 memcpy(palloc(sizeof(cd)), &cd, sizeof(cd)));
#else
	jsonbzInitFromDetoastIterator(&js->root, iter);
#endif
	return js;
}
