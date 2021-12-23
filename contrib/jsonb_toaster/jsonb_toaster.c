/*-------------------------------------------------------------------------
 *
 * jsonb_toaster.c
 *		Updatable jsonb toaster.
 *
 * Portions Copyright (c) 2014-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 2021-2022, PostgrePro
 *
 * IDENTIFICATION
 *	  contrib/jsonb_toaster/jsonb_toaster.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#define JSONB_UTIL_C

#include "access/detoast.h"
#include "access/heaptoast.h"
#include "access/table.h"
#include "access/tableam.h"
#include "access/toasterapi.h"
#include "access/toast_internals.h"
#include "catalog/pg_collation.h"
#include "catalog/pg_type.h"
#include "common/hashfn.h"
#include "common/jsonapi.h"
#include "common/pg_lzcompress.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/builtins.h"
#include "utils/datetime.h"
#include "utils/json.h"
#include "utils/jsonb.h"
#include "utils/json_generic.h"
#include "utils/memutils.h"
#include "utils/varlena.h"

PG_MODULE_MAGIC;

void _PG_init(void);

/*
 * Maximum number of elements in an array (or key/value pairs in an object).
 * This is limited by two things: the size of the JEntry array must fit
 * in MaxAllocSize, and the number of elements (or pairs) must fit in the bits
 * reserved for that in the JsonbContainer.header field.
 *
 * (The total size of an array's or object's elements is also limited by
 * JENTRY_OFFLENMASK, but we're not concerned about that here.)
 */
#define JSONB_MAX_ELEMS (Min(MaxAllocSize / sizeof(JsonbValue), JB_CMASK))
#define JSONB_MAX_PAIRS (Min(MaxAllocSize / sizeof(JsonbPair), JB_CMASK))

#define JENTRY_ISCONTAINER_PTR	0x60000000	/* pointer to toasted array or object */
#define JBE_ISCONTAINER_PTR(je_)(((je_) & JENTRY_TYPEMASK) == JENTRY_ISCONTAINER_PTR)

#define JB_TOBJECT_TOASTED		0x10000000	/* object with toasted keys */

#undef JB_ROOT_IS_OBJECT /* FIXME */
#define JB_ROOT_IS_OBJECT(jbp_) ((JB_HEADER(jbp_) & JB_TMASK) == JB_TOBJECT || \
								 (JB_HEADER(jbp_) & JB_TMASK) == JB_TOBJECT_SORTED || \
								 (JB_HEADER(jbp_) & JB_TMASK) == JB_TOBJECT_TOASTED)

typedef struct varatt_external JsonbToastPointer;

typedef struct JsonbToastedContainerPointer
{
	JsonbContainerHeader header;
	JsonbToastPointer ptr;
} JsonbToastedContainerPointer;

/* Conversion state used when parsing Jsonb from text, or for type coercion */
struct JsonbParseState
{
	JsonbValue	contVal;
	Size		size;
	struct JsonbParseState *next;
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
	DetoastIterator iter;
	int			offset;
	JsonbContainerHeader header;
} CompressedJsonb;

#define jsonbzGetCompressedJsonb(jc) ((CompressedJsonb *) &(jc)->_data)

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

struct JsonbIterator
{
	JsonIterator	ji;

	/* Container being iterated */
	const JsonbContainer *container;

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
};

void fillJsonbValue(const JsonbContainer *container, int index,
						   char *base_addr, uint32 offset,
						   JsonbValue *result);
static void convertJsonbValue(StringInfo buffer, JEntry *header, const JsonbValue *val, int level);
static void convertJsonbArray(StringInfo buffer, JEntry *header, const JsonbValue *val, int level);
static void convertJsonbObject(StringInfo buffer, JEntry *header, const JsonbValue *val, int level);
static void convertJsonbBinary(StringInfo buffer, JEntry *header, const JsonbValue *val, int level);
static void convertJsonbScalar(StringInfo buffer, JEntry *header, const JsonbValue *scalarVal);

static void copyToBuffer(StringInfo buffer, int offset, const void *data, int len);
static short padBufferToInt(StringInfo buffer);

static JsonbIterator *iteratorFromContainer(JsonContainer *container, JsonbIterator *parent);
int	lengthCompareJsonbStringValue(const void *a, const void *b);
static void jsonbInitContainer(JsonContainerData *jc, JsonbContainer *jbc, int len, Oid toasterid);
static void jsonbzInitWithHeader(JsonContainerData *jc, Datum value, JsonbContainerHeader *header);

static JsonbValue *fillCompressedJsonbValue(CompressedJsonb *cjb,
											const JsonbContainer *container,
											int index, char *base_addr,
											uint32 offset, JsonValue *result);
static JsonbContainer *jsonbzDecompress(JsonContainer *jc);
static bool JsonContainerIsToasted(JsonContainer *jc,
								   JsonbToastedContainerPointer *jbcptr);
static bool JsonValueContainsToasted(const JsonValue *jv);

static bool jsonb_toast_fields = true;				/* GUC */

static JsonContainerOps myjsonbContainerOps;
static JsonContainerOps myjsonbzContainerOps;

static struct varlena *
jsonbMakeToastPointer(struct varatt_external *ptr)
{
	struct varlena *toast_ptr = palloc(TOAST_POINTER_SIZE);

	SET_VARTAG_EXTERNAL(toast_ptr, VARTAG_ONDISK);
	memcpy(VARDATA_EXTERNAL(toast_ptr), ptr, sizeof(*ptr));

	return toast_ptr;
}

/*
 * Get the offset of the variable-length portion of a Jsonb node within
 * the variable-length-data part of its container.  The node is identified
 * by index within the container's JEntry array.
 */
static uint32
getJsonbOffset(const JsonbContainer *jc, int index)
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
getJsonbLength(const JsonbContainer *jc, int index)
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

static JsonbValue *
jsonbFindKeyInObject(JsonContainer *jsc, const char *key, int len)
{
	return getKeyJsonValueFromContainer(jsc, key, len, NULL);
}

typedef struct JsonbArrayIterator
{
	const JsonbContainer *container;
	char			   *base_addr;
	int					index;
	int					count;
	uint32				offset;
} JsonbArrayIterator;

static void
JsonbArrayIteratorInit(JsonbArrayIterator *it, const JsonbContainer *container)
{
	it->container = container;
	it->index = 0;
	it->count = (container->header & JB_CMASK);
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
jsonbFindValueInArrayContainer(const JsonbContainer *container,
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
JsonbValue *
getKeyJsonValueFromContainer(JsonContainer *jsc,
							 const char *keyVal, int keyLen, JsonbValue *res)
{
	const JsonbContainer *container = JsonContainerDataPtr(jsc);
	const JEntry *children = container->children;
	int			count = JsonContainerSize(jsc);
	char	   *baseAddr = (char *) (children + count * 2);
	bool		sorted_values = (container->header & JB_TMASK) == JB_TOBJECT_SORTED;
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
fillJsonbValue(const JsonbContainer *container, int index,
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
	else if (JBE_ISCONTAINER(entry))
	{
		JsonContainerData *cont = JsonContainerAlloc(&jsonbContainerOps);

		jsonbInitContainer(cont,
			/* Remove alignment padding from data pointer and length */
						   (JsonbContainer *)(base_addr + INTALIGN(offset)),
						   getJsonbLength(container, index) -
						   (INTALIGN(offset) - offset),
						   InvalidOid);

		JsonValueInitBinary(result, cont);
	}
	else if (JBE_ISCONTAINER_PTR(entry))
	{
		JsonContainerData *cont = JsonContainerAlloc(&jsonbzContainerOps);
		JsonbToastedContainerPointer *jbcptr = (JsonbToastedContainerPointer *)(base_addr + INTALIGN(offset));
		struct varlena *toast_ptr = jsonbMakeToastPointer(&jbcptr->ptr);

		jsonbzInitWithHeader(cont, PointerGetDatum(toast_ptr), &jbcptr->header);
		JsonValueInitBinary(result, cont);

		pfree(toast_ptr);
	}
	else
		elog(ERROR, "invalid JEntry type: %x", entry);
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
JsonbIteratorToken
JsonbIteratorNext(JsonIterator **jsit, JsonbValue *val, bool skipNested)
{
	JsonbIterator **it = (JsonbIterator **) jsit;
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
			/*
			 * Set v to array on first array call
			 * v->val.array.elems is not actually set, because we aren't doing
			 * a full conversion
			 */
			JsonValueInitArray(val, (*it)->nElems, 0, (*it)->isScalar /* XXX, true */);

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
				*it = (JsonbIterator *)
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
			/* Set v to object on first object call
			 * v->val.object.pairs is not actually set, because we aren't
			 * doing a full conversion
			 */
			JsonValueInitObject(val, (*it)->nElems, 0 /* XXX, true*/);

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
				*it = (JsonbIterator *)
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

static JsonbIterator *
iteratorFromContainer(JsonContainer *container, JsonbIterator *parent)
{
	JsonbIterator *it = (JsonbIterator *) JsonIteratorInit(container);
	it->ji.parent = &parent->ji;
	return it;
}

/*
 * Given a JsonbContainer, expand to JsonbIterator to iterate over items
 * fully expanded to in-memory representation for manipulation.
 *
 * See JsonbIteratorNext() for notes on memory management.
 */
static JsonIterator *
jsonbIteratorInit(JsonContainer *cont, const JsonbContainer *container,
				  struct CompressedJsonb *cjb)
{
	JsonbIterator *it;
	int			type;

	/* decompress container header */
	if (cjb)
		PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + cjb->offset + offsetof(Jsonb, root));

	type = container->header & JB_TMASK;

	it = palloc0(sizeof(JsonbIterator));
	it->ji.container = cont;
	it->ji.parent = NULL;
	it->ji.next = JsonbIteratorNext;
	it->container = container;
	it->nElems = container->header & JB_CMASK;
	it->compressed = cjb;

	/* Array starts just after header */
	it->children = container->children;

	switch (type)
	{
		case JB_TSCALAR:
			it->isScalar = true;
			/* FALLTHROUGH */
		case JB_TARRAY:
			it->dataProper =
				(char *) it->children + it->nElems * sizeof(JEntry);
			/* This is either a "raw scalar", or an array */
			Assert(!it->isScalar || it->nElems == 1);

			it->state = JBI_ARRAY_START;
			break;

		case JB_TOBJECT:
		case JB_TOBJECT_SORTED:
		case JB_TOBJECT_TOASTED:
			it->dataProper =
				(char *) it->children + it->nElems * sizeof(JEntry) * 2;
			it->dataProper = initKVMap(&it->kvmap, it->dataProper, it->nElems,
									   type == JB_TOBJECT_SORTED);

			it->state = JBI_OBJECT_START;
			break;

		default:
			elog(ERROR, "unknown type of jsonb container");
	}

	if (it->dataProper && cjb)
		PG_DETOAST_ITERATE(cjb->iter, it->dataProper);

	return (JsonIterator *) it;
}

static JsonIterator *
JsonbIteratorInit(JsonContainer *cont)
{
	return jsonbIteratorInit(cont, (const JsonbContainer *) JsonContainerDataPtr(cont), NULL);
}

/*
 * Copy 'len' bytes to a previously reserved area in buffer.
 */
static void
copyToBuffer(StringInfo buffer, int offset, const void *data, int len)
{
	memcpy(buffer->data + offset, data, len);
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

static void
MyJsonbEncode(StringInfoData *buffer, const JsonbValue *val, void *cxt)
{
	JEntry		jentry;
	varatt_custom va_custom;
	int32		header_len;

	/* Make room for the varlena header */
	reserveFromBuffer(buffer, VARATT_CUSTOM_SIZE(VARHDRSZ));
	header_len = buffer->len;

	convertJsonbValue(buffer, &jentry, val, 0);

	va_custom.va_toasterid.oid_val = (Oid)(intptr_t) cxt;
	va_custom.va_rawsize.int_val = buffer->len - header_len;	/* FIXME */
	va_custom.va_toasterdatalen.int_val = buffer->len - header_len + VARHDRSZ;

	SET_VARTAG_EXTERNAL(buffer->data, VARTAG_CUSTOM);
	memcpy(VARDATA_EXTERNAL(buffer->data), &va_custom, sizeof(va_custom));
}

static void *
myjsonbEncode(JsonContainer *jc, JsonContainerOps *ops)
{
	if (ops == &jsonbContainerOps)
	{
		JsonValue bin;

		JsonValueInitBinary(&bin, jc);

		return JsonEncode(&bin, MyJsonbEncode, (void *)(intptr_t) jc->toasterid);
	}

	return NULL;
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
static void
convertJsonbValue(StringInfo buffer, JEntry *header, const JsonbValue *val, int level)
{
	check_stack_depth();

	if (!val)
		return;

	Assert(JsonValueIsUniquified(val));

	if (IsAJsonbScalar(val))
		convertJsonbScalar(buffer, header, val);
	else if (val->type == jbvArray)
		convertJsonbArray(buffer, header, val, level);
	else if (val->type == jbvObject)
		convertJsonbObject(buffer, header, val, level);
	else if (val->type == jbvBinary)
		convertJsonbBinary(buffer, header, val, level);
	else
		elog(ERROR, "unknown type of jsonb container to convert");
}

static void
convertJsonbArray(StringInfo buffer, JEntry *pheader, const JsonbValue *val, int level)
{
	int			base_offset;
	int			jentry_offset;
	int			i;
	int			totallen;
	uint32		header;
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
		header = nElems | JB_TSCALAR;
	}
	else
		header = nElems | JB_TARRAY;

	appendToBuffer(buffer, (char *) &header, sizeof(uint32));

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
		convertJsonbValue(buffer, &meta, elem, level + 1);

		len = JBE_OFFLENFLD(meta);
		totallen += len;

		/*
		 * Bail out if total variable-length data exceeds what will fit in a
		 * JEntry length field.  We check this in each iteration, not just
		 * once at the end, to forestall possible integer overflow.
		 */
		if (totallen > JENTRY_OFFLENMASK)
			ereport(ERROR,
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
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("total size of jsonb array elements exceeds the maximum of %u bytes",
						JENTRY_OFFLENMASK)));

	/* Initialize the header of this node in the container's JEntry array */
	*pheader = JENTRY_ISCONTAINER | totallen;
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
			size = offsetof(JsonbContainer, children[jbv->val.array.nElems]);
			for (int i = 0; i < jbv->val.array.nElems; i++)
				size += estimateJsonbValueSize(&jbv->val.array.elems[i]);
			return size;
		case jbvObject:
			size = offsetof(JsonbContainer, children[jbv->val.object.nPairs * 2]);
			for (int i = 0; i < jbv->val.object.nPairs; i++)
			{
				size += estimateJsonbValueSize(&jbv->val.object.pairs[i].key);
				size += estimateJsonbValueSize(&jbv->val.object.pairs[i].value);
			}
			return size;
		case jbvBinary:
			if (jbv->val.binary.data->ops == &jsonvContainerOps)
				return estimateJsonbValueSize((const JsonbValue *) JsonContainerDataPtr(jbv->val.binary.data));
			return jbv->val.binary.data->len;	/* FIXME */
		default:
			elog(ERROR, "invalid jsonb value type: %d", jbv->type);
			return 0;
	}
}

static void
jsonbInitToastedContainerPointer(JsonbToastedContainerPointer *jbcptr,
								 JsonContainer *jc,
								 struct varatt_external *toast_ptr)
{
	jbcptr->header =
		(JsonContainerIsArray(jc) ? JB_TARRAY : JB_TOBJECT) |
		JsonContainerSize(jc);
	jbcptr->ptr = *toast_ptr;
}

static bool
JsonContainerIsToasted(JsonContainer *jc, JsonbToastedContainerPointer *jbcptr)
{
	if (jc->ops == &jsonbzContainerOps)
	{
		CompressedJsonb *cjb = jsonbzGetCompressedJsonb(jc);
		FetchDatumIterator fetch_iter = cjb->iter->fetch_datum_iterator;

		if (fetch_iter->toast_pointer.va_rawsize > 0 &&
			cjb->offset == offsetof(Jsonb, root))
		{
			if (jbcptr)
				jsonbInitToastedContainerPointer(jbcptr, jc, &fetch_iter->toast_pointer);

			return true;
		}
	}

	return false;
}

static bool
JsonContainerContainsToasted(JsonContainer *jc)
{
	if (jc->ops == &myjsonbContainerOps)
	{
		JsonbContainer *jbc = JsonContainerDataPtr(jc);

		return (jbc->header & JB_TMASK) == JB_TOBJECT_TOASTED;
	}
	else if (jc->ops == &jsonbzContainerOps)
	{
		CompressedJsonb *cjb = jsonbzGetCompressedJsonb(jc);

		return (cjb->header & JB_TMASK) == JB_TOBJECT_TOASTED;
	}
	else if (jc->ops == &jsonvContainerOps)
		return JsonValueContainsToasted(JsonContainerDataPtr(jc));
	else
		return false;	/* XXX other container types */
}

static bool
JsonValueIsToasted(JsonValue *jv)
{
	return jv->type == jbvBinary &&
		JsonContainerIsToasted(jv->val.binary.data, NULL);
}

static bool
JsonValueContainsToasted(const JsonValue *jv)
{
	if (jv->type == jbvBinary)
		return JsonContainerContainsToasted(jv->val.binary.data);

	if (jv->type == jbvObject)
	{
		int			nPairs = jv->val.object.nPairs;

		for (int i = 0; i < nPairs; i++)
		{
			JsonValue *val = &jv->val.object.pairs[i].value;

			if (JsonValueIsToasted(val) ||
				JsonValueContainsToasted(val))
				return true;
		}
	}
	else if (jv->type == jbvArray)
	{
		int			nElems = jv->val.array.nElems;

		for (int i = 0; i < nElems; i++)
		{
			JsonValue *val = &jv->val.array.elems[i];

			if (JsonValueIsToasted(val) ||
				JsonValueContainsToasted(val))
				return true;
		}
	}

	return false;
}

static void
convertJsonbObject(StringInfo buffer, JEntry *pheader, const JsonbValue *val, int level)
{
	int			base_offset;
	int			jentry_offset;
	int			i;
	int			totallen;
	uint32		header;
	int			nPairs = val->val.object.nPairs;
	int			reserved_size;
	int			kvmap_entry_size;
	bool		sorted_values = jsonb_sort_field_values && nPairs > 1;
	bool		have_toasted_values = false;
	struct
	{
		int			size;
		int32		index;
	}		   *values = sorted_values ? palloc(sizeof(*values) * nPairs) : NULL;

	Assert(nPairs >= 0);

	if (JsonValueContainsToasted(val))
	{
		have_toasted_values = true;
		sorted_values = false;	/* FIXME */
	}

	values = sorted_values ? palloc(sizeof(*values) * nPairs) : NULL;

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
	header = nPairs |
		(sorted_values ? JB_TOBJECT_SORTED :
		have_toasted_values ? JB_TOBJECT_TOASTED : JB_TOBJECT);
	appendToBuffer(buffer, (char *) &header, sizeof(uint32));

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
		convertJsonbScalar(buffer, &meta, &pair->key);

		len = JBE_OFFLENFLD(meta);
		totallen += len;

		/*
		 * Bail out if total variable-length data exceeds what will fit in a
		 * JEntry length field.  We check this in each iteration, not just
		 * once at the end, to forestall possible integer overflow.
		 */
		if (totallen > JENTRY_OFFLENMASK)
			ereport(ERROR,
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
		convertJsonbValue(buffer, &meta, &pair->value, level + 1);

		len = JBE_OFFLENFLD(meta);
		totallen += len;

		/*
		 * Bail out if total variable-length data exceeds what will fit in a
		 * JEntry length field.  We check this in each iteration, not just
		 * once at the end, to forestall possible integer overflow.
		 */
		if (totallen > JENTRY_OFFLENMASK)
			ereport(ERROR,
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
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("total size of jsonb object elements exceeds the maximum of %u bytes",
						JENTRY_OFFLENMASK)));

	/* Initialize the header of this node in the container's JEntry array */
	*pheader = JENTRY_ISCONTAINER | totallen;
}

static void
convertJsonbScalar(StringInfo buffer, JEntry *jentry, const JsonbValue *scalarVal)
{
	int			numlen;
	short		padlen;

	switch (scalarVal->type)
	{
		case jbvNull:
			*jentry = JENTRY_ISNULL;
			break;

		case jbvString:
			if (scalarVal->val.string.len > JENTRY_OFFLENMASK)
					ereport(ERROR,
							(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
							 errmsg("string too long to represent as jsonb string"),
							 errdetail("Due to an implementation restriction, jsonb strings cannot exceed %d bytes.",
									   JENTRY_OFFLENMASK)));

			appendToBuffer(buffer, scalarVal->val.string.val,
							scalarVal->val.string.len);

			*jentry = scalarVal->val.string.len;
			break;

		case jbvNumeric:
			numlen = VARSIZE_ANY(scalarVal->val.numeric);
			padlen = padBufferToInt(buffer);

			appendToBuffer(buffer, (char *) scalarVal->val.numeric, numlen);

			*jentry = JENTRY_ISNUMERIC | (padlen + numlen);
			break;

		case jbvBool:
			*jentry = (scalarVal->val.boolean) ?
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

				*jentry = len;
			}
			break;

		default:
			elog(ERROR, "invalid jsonb scalar type");
	}
}

static void
convertJsonbBinary(StringInfo buffer, JEntry *pheader, const JsonbValue *val,
				   int level)
{
	JsonContainer *jc = val->val.binary.data;

	Assert(val->type == jbvBinary);

	if ((jc->ops == &jsonbContainerOps ||
		 jc->ops == &jsonbzContainerOps) && !JsonContainerIsScalar(jc))
		 /* FIXME myjsonbContainerOps */
	{
		JsonbContainer *jbc;
		int			base_offset = buffer->len;

		if (jsonb_toast_fields)
		{
			JsonbToastedContainerPointer jbcptr;

			if (JsonContainerIsToasted(jc, &jbcptr))
			{
				padBufferToInt(buffer);
				appendToBuffer(buffer, &jbcptr, sizeof(jbcptr));
				*pheader = JENTRY_ISCONTAINER_PTR | (buffer->len - base_offset);
				return;
			}
		}

		jbc = jc->ops == &jsonbzContainerOps ?
			jsonbzDecompress(jc) : JsonContainerDataPtr(jc);

		padBufferToInt(buffer);
		appendToBuffer(buffer, jbc, jc->len);
		*pheader = JENTRY_ISCONTAINER | (buffer->len - base_offset);
	}
	else if (jc->ops == &jsonvContainerOps && !JsonContainerIsScalar(jc))
		convertJsonbValue(buffer, pheader,
						  (const JsonValue *) JsonContainerDataPtr(jc), level);
	else
		convertJsonbValue(buffer, pheader, JsonValueUnpackBinary(val), level);
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

static void
jsonbInitContainerFromHeader(JsonContainerData *jc, JsonbContainerHeader header)
{
	jc->size = header & JB_CMASK;
	switch (header & JB_TMASK)
	{
		case JB_TOBJECT:
		case JB_TOBJECT_SORTED:
		case JB_TOBJECT_TOASTED:
			jc->type = jbvObject;
			break;
		case JB_TARRAY:
			jc->type = jbvArray;
			break;
		case JB_TSCALAR:
			jc->type = jbvArray | jbvScalar;
			break;
		default:
			elog(ERROR, "invalid jsonb container type: %d", header & JB_TMASK);
	}
}

static void
jsonbInitContainer(JsonContainerData *jc, JsonbContainer *jbc, int len, Oid toasterid)
{
	jc->ops = &myjsonbContainerOps;
	JsonContainerDataPtr(jc) = jbc;
	jc->len = len;
	jc->toasterid = toasterid;
	jsonbInitContainerFromHeader(jc, jbc->header);
}

static void
jsonbInit(JsonContainerData *jc, Datum value)
{
	Jsonb	   *jb;

	Assert(VARATT_IS_CUSTOM(value));
	jb = (void *) VARATT_CUSTOM_GET_DATA(value);	/* FIXME alignment */

	jsonbInitContainer(jc, &jb->root, VARSIZE_ANY_EXHDR(jb),
					   VARATT_CUSTOM_GET_TOASTERID(value));
}

static void
jsonbzInitContainer(JsonContainerData *jc, CompressedJsonb *cjb,
					JsonbContainerHeader *pheader, int len)
{
	Jsonb	   *jb = (Jsonb *) cjb->iter->buf->buf;
	JsonbContainer *jbc = (JsonbContainer *)((char *) jb + cjb->offset);
	JsonbContainerHeader header = pheader ? *pheader : jbc->header;

	*(CompressedJsonb *) &jc->_data = *cjb;
	((CompressedJsonb *) &jc->_data)->header = header;

	jc->ops = &myjsonbzContainerOps;
	jc->len = len;
	jsonbInitContainerFromHeader(jc, header);
}

static JsonbContainer *
jsonbzDecompress(JsonContainer *jc)
{
	CompressedJsonb *cjb = jsonbzGetCompressedJsonb(jc);
	Jsonb	   *jb = (Jsonb *) cjb->iter->buf->buf;
	JsonbContainer *container = (JsonbContainer *)((char *) jb + cjb->offset);

	PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + cjb->offset + jc->len);

	return container;
}

static JsonbValue *
fillCompressedJsonbValue(CompressedJsonb *cjb, const JsonbContainer *container,
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

	base_offset = base_addr - (char *) cjb->iter->buf->buf;

	if (JBE_ISCONTAINER(entry) /* && len > JSONBZ_MIN_CONTAINER_LEN */)
	{
		JsonContainerData *cont = JsonContainerAlloc(&jsonbzContainerOps);
		CompressedJsonb cjb2;

		cjb2.iter = cjb->iter;
		//cjb2.iter->nrefs++;

		/* Remove alignment padding from data pointer and length */
		cjb2.offset = base_offset + INTALIGN(offset);

		len -= INTALIGN(offset) - offset;

		PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + cjb2.offset +
						   offsetof(JsonbContainer, children));

		jsonbzInitContainer(cont, &cjb2, NULL, len);
		JsonValueInitBinary(result, cont);
	}
	else
	{
		PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + base_offset + offset + len);
		fillJsonbValue(container, index, base_addr, offset, result);
	}

	return result;
}

static JsonbValue *
findValueInCompressedJsonbObject(CompressedJsonb *cjb, const char *keystr, int keylen)
{
	Jsonb	   *jb = (Jsonb *) cjb->iter->buf->buf;
	JsonbContainer *container = (JsonbContainer *)((char *) jb + cjb->offset);
	JsonbValue	key;
	JEntry	   *children = container->children;
	int			count = container->header & JB_CMASK;
	/* Since this is an object, account for *Pairs* of Jentrys */
	bool		sorted_values = (container->header & JB_TMASK) == JB_TOBJECT_SORTED;
	char	   *base_addr = (char *) (children + count * 2);
	JsonbKVMap	kvmap;
	Size		base_offset;
	uint32		stopLow = 0,
				stopHigh = count;

	Assert(JB_ROOT_IS_OBJECT(jb));

	/* Quick out if object/array is empty */
	if (count <= 0)
		return NULL;

	base_addr = initKVMap(&kvmap, base_addr, count, sorted_values);
	base_offset = base_addr - (char *) jb;

	key.type = jbvString;
	key.val.string.val = keystr;
	key.val.string.len = keylen;

	PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + base_offset);

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

		PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + base_offset + offset + len);

		difference = lengthCompareJsonbString(base_addr + offset, len,
											  key.val.string.val,
											  key.val.string.len);

		if (difference == 0)
		{
			/* Found our key, return corresponding value */
			int			index = JSONB_KVMAP_ENTRY(&kvmap, stopMiddle) + count;

			return fillCompressedJsonbValue(cjb, container, index, base_addr,
											getJsonbOffset(container, index),
											palloc(sizeof(JsonbValue)));
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
jsonbzFindKeyInObject(JsonContainer *jc, const char *key, int len)
{
	CompressedJsonb *cjb = jsonbzGetCompressedJsonb(jc);
#ifdef JSONB_OWN_DETOAST_ITERATOR	/* FIXME */
	Jsonb	   *jb = (Jsonb *) cjb->datum->data;

	JsonbContainer *jbc = (JsonbContainer *)((char *) jb + cjb->offset);

	if (!cjb->datum->compressed)
	{
		JsonContainerData jcd;

		jsonbInitContainer(&jcd, jbc, jc->len, InvalidOid);

		return jsonbFindKeyInObject(&jcd, key, len);
	}

	CompressedDatumDecompress(cjb->datum, cjb->offset + offsetof(JsonbContainer, header));
#else
	PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + cjb->offset + offsetof(JsonbContainer, header));
#endif

	return findValueInCompressedJsonbObject(cjb, key, len);
}

typedef struct JsonbzArrayIterator
{
	CompressedJsonb *cjb;
	const JsonbContainer *container;
	char	   *base_addr;
	int			index;
	int			count;
	uint32		offset;
} JsonbzArrayIterator;

static void
JsonbzArrayIteratorInit(JsonbzArrayIterator *it, CompressedJsonb *cjb)
{
	Jsonb	   *jb = (Jsonb *) cjb->iter->buf->buf;
	const JsonbContainer *jbc = (const JsonbContainer *)((char *) jb + cjb->offset);

	PG_DETOAST_ITERATE(cjb->iter, (const char *) &jbc->children);

	it->count = (cjb->header & JB_CMASK);

	PG_DETOAST_ITERATE(cjb->iter, (const char *) &jbc->children[it->count]);

	it->cjb = cjb;
	it->container = jbc;
	it->index = 0;
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
	CompressedJsonb *cjb = jsonbzGetCompressedJsonb(jc);
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
	CompressedJsonb *cjb = jsonbzGetCompressedJsonb(jc);
	JsonbzArrayIterator it;

	if (!JsonContainerIsArray(jc))
		elog(ERROR, "not a jsonb array");

	JsonbzArrayIteratorInit(&it, cjb);

	return JsonbzArrayIteratorGetIth(&it, index);
}

static JsonIterator *
jsonbzIteratorInit(JsonContainer *jc)
{
	CompressedJsonb *cjb = jsonbzGetCompressedJsonb(jc);
	Jsonb	   *jb = (Jsonb *) cjb->iter->buf->buf;
	JsonbContainer *jbc = (JsonbContainer *)((char *) jb + cjb->offset);

	if (!jsonb_partial_decompression)
		PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->capacity);

	return jsonbIteratorInit(jc, jbc, cjb);
}

static void
jsonbzInitFromDetoastIterator(JsonContainerData *jc, DetoastIterator iter, JsonbContainerHeader *header)
{
	CompressedJsonb *cjb = palloc(sizeof(*cjb));
	cjb->iter = iter;
	cjb->offset = offsetof(Jsonb, root);

	if (!jsonb_partial_decompression)
		PG_DETOAST_ITERATE(iter, iter->buf->capacity);
	else if (!header)
		PG_DETOAST_ITERATE(iter, Min(iter->buf->buf + offsetof(Jsonb, root.children), iter->buf->capacity));

	jsonbzInitContainer(jc, cjb, header, VARSIZE_ANY_EXHDR(iter->buf->buf)); // cd->total_len - VARHDRSZ
}

static void
jsonbzFree(JsonContainer *jc)
{
	CompressedJsonb *cjb = jsonbzGetCompressedJsonb(jc);

	if (cjb->iter)
		free_detoast_iterator(cjb->iter);
}

static void
jsonbzInitWithHeader(JsonContainerData *jc, Datum value, JsonbContainerHeader *header)
{
	DetoastIterator iter = create_detoast_iterator((struct varlena *) DatumGetPointer(value));

	jsonbzInitFromDetoastIterator(jc, iter, header);
}

static void
jsonbzInit(JsonContainerData *jc, Datum value)
{
	jsonbzInitWithHeader(jc, value, NULL);
}

static JsonContainerOps
myjsonbzContainerOps =
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
};

static JsonContainerOps
myjsonbContainerOps =
{
	sizeof(CompressedJsonb),
	jsonbInit,
	JsonbIteratorInit,
	jsonbFindKeyInObject,
	jsonbFindValueInArray,
	jsonbGetArrayElement,
	NULL,
	JsonbToCStringRaw,
	JsonCopyFlat,	// FIXME
	NULL,
	myjsonbEncode
};

static Datum
jsonb_toaster_save(Relation rel, Json *js, int max_size, char cmethod)
{
	JsonContainer *root = JsonRoot(js);
	JsonIterator *it;
	JsonValue	jsv;
	JsonIteratorToken tok;
	Size		total_key_names_length = 0;
	Size		min_values_length = 0;
	Size		header_size;
	Size		total_size;
	const void **values;
	int			nkeys;
	int		   *sizes;
	int			i = 0;
	JsonValue	object;
	JsonbPair  *pairs;
	Datum		jb = (Datum) 0;

	if (!jsonb_toast_fields || max_size <= 0)
		return (Datum) 0;

	if (!JsonContainerIsObject(root))
		return (Datum) 0;

	nkeys = JsonContainerSize(root);

	header_size = offsetof(Jsonb, root.children) + sizeof(JEntry) * nkeys * 2;
	total_size = header_size;

	if (header_size > max_size)
		return (Datum) 0;

	sizes = palloc(sizeof(*sizes) * nkeys);
	values = palloc(sizeof(*values) * nkeys);
	pairs = palloc(sizeof(*pairs) * nkeys);

	JsonValueInitObject(&object, nkeys, 0, JsonIsUniquified(js));
	object.val.object.pairs = pairs;

	it = JsonIteratorInit(root);

	while ((tok = JsonIteratorNext(&it, &jsv, true)) != WJB_DONE)
	{
		if (tok == WJB_KEY)
		{
			if (i >= nkeys)
				elog(ERROR, "invalid jsonb keys count");

			total_key_names_length += jsv.val.string.len;

			pairs[i].key = jsv;
		}
		else if (tok == WJB_VALUE)
		{
			if (i >= nkeys)
				elog(ERROR, "invalid jsonb keys count");

			if (JsonValueIsToasted(&jsv))
			{
				values[i] = NULL;
				sizes[i] = sizeof(JsonbToastedContainerPointer);
				min_values_length += sizeof(JsonbToastedContainerPointer);
			}
			else
			{
				switch (jsv.type)
				{
					case jbvBinary:
						values[i] = jsv.val.binary.data;
						sizes[i] = jsv.val.binary.data->len;
						min_values_length += INTALIGN(sizeof(JsonbToastedContainerPointer) + 3);
						break;
					case jbvString:
						values[i] = jsv.val.string.val;
						sizes[i] = jsv.val.string.len;
						min_values_length += INTALIGN(sizes[i] + 3);
						//min_values_length += sizeof(JsonbToastPointer);
						break;
					case jbvNumeric:
						values[i] = jsv.val.numeric;
						sizes[i] = VARSIZE(jsv.val.numeric);
						min_values_length += INTALIGN(sizes[i] + 3);
						//min_values_length += sizeof(JsonbToastPointer);
						break;
					default:
						sizes[i] = 0;
						values[i] = NULL;
						break;
				}
			}

			total_size += INTALIGN(sizes[i] + 3);
			pairs[i].value = jsv;
			i++;
		}
	}

	if (i != nkeys)
		elog(ERROR, "invalid jsonb keys count");

	total_size += INTALIGN(total_key_names_length);

	if (header_size + INTALIGN(total_key_names_length) + min_values_length > max_size)
		goto exit;

	while (total_size > max_size)
	{
		int			max_key_idx = -1;
		Size		max_key_size = 0;
		Datum		val;
		Datum		compressed_val;
		Datum		toasted_val;
		JsonContainer *jc;
		JsonContainerData *tjc;
		JsonbContainer *jbc;
		JsonbContainerHeader header;

		for (i = 0; i < nkeys; i++)
		{
			if (pairs[i].value.type == jbvBinary &&
				sizes[i] > max_key_size)
			{
				max_key_idx = i;
				max_key_size = sizes[i];
			}
		}

		if (max_key_idx < 0 ||
			max_key_size <= sizeof(JsonbToastedContainerPointer))
			goto exit;	/* FIXME */

		jc = values[max_key_idx];
		jbc = jc->ops == &jsonbzContainerOps ?
			jsonbzDecompress(jc) : JsonContainerDataPtr(jc);

		val = PointerGetDatum(palloc(max_key_size + sizeof(struct varlena)));
		memcpy(VARDATA(val), jbc, max_key_size);
		SET_VARSIZE(val, max_key_size + sizeof(struct varlena));

		compressed_val = toast_compress_datum(val, cmethod);
		toasted_val = toast_save_datum(rel,
									   compressed_val != (Datum) 0 ? compressed_val : val,
									   NULL, 0);

		pfree(DatumGetPointer(val));
		if (DatumGetPointer(compressed_val))
			pfree(DatumGetPointer(compressed_val));

		Assert(VARATT_IS_EXTERNAL_ONDISK(toasted_val));

		header =
			(JsonContainerIsArray(jc) ? JB_TARRAY : JB_TOBJECT) |
			JsonContainerSize(jc);

		tjc = JsonContainerAlloc(&jsonbzContainerOps);	/* FIXME optimize */
		jsonbzInitWithHeader(tjc, toasted_val, &header);

		pairs[max_key_idx].value.val.binary.data = tjc;

		total_size -= INTALIGN(max_key_size + 3);
		sizes[max_key_idx] = sizeof(JsonbToastedContainerPointer);
		total_size += INTALIGN(sizes[max_key_idx] + 3);
	}

	jb = JsonValueGetJsonbDatum(&object);

exit:
	pfree(sizes);
	pfree(values);
	pfree(pairs);

	return jb;
}

static uint32
JsonbIteratorGetCurOffset(JsonbIterator *it)
{
	if (it->state == JBI_ARRAY_ELEM)
		return it->curDataOffset;
	else if (it->state == JBI_OBJECT_VALUE)
	{
		int32		entry_index = JSONB_KVMAP_ENTRY(&it->kvmap, it->curIndex) + it->nElems;

		return it->kvmap.entry_size ? getJsonbOffset(it->container, entry_index) : it->curValueOffset;
	}
	else
		return 0;
}

static void *
JsonbIteratorGetValuePtr(JsonbIterator *it, uint32 offset)
{
	return it->dataProper + offset;
}

static Datum
jsonb_toaster_copy(Relation rel, JsonContainer *jc, char cmethod);

static void
jsonb_toaster_copy_recursive(Relation rel, JsonContainer *jc, char cmethod);

static bool
jsonb_toaster_replace_toasted(Relation rel, JsonValue *jsv,
							  JsonbIterator *it, uint32 offset, char cmethod)
{
	JsonContainer *jc;

	if (jsv->type != jbvBinary)
		return false;

	jc = jsv->val.binary.data;

	if (JsonContainerIsToasted(jc, NULL))
	{
		Datum		copied = jsonb_toaster_copy(rel, jc, cmethod);
		Datum		compressed;
		Datum		toasted;
		JsonbToastedContainerPointer *jbcptr;

		Assert(copied != (Datum) 0);
		compressed = toast_compress_datum(copied, cmethod);
		toasted = toast_save_datum(rel, compressed != (Datum) 0 ? compressed : copied, NULL, 0);
		Assert(VARATT_IS_EXTERNAL_ONDISK(toasted));

		jbcptr = JsonbIteratorGetValuePtr(it, offset);

		memcpy(&jbcptr->ptr, VARDATA_EXTERNAL(toasted), sizeof(jbcptr->ptr));

		if (compressed != (Datum) 0)
			pfree(DatumGetPointer(compressed));
		pfree(DatumGetPointer(toasted));
	}
	else if (JsonContainerContainsToasted(jc))
	{
		jsonb_toaster_copy_recursive(rel, jc, cmethod);
	}

	return true;
}

static void
jsonb_toaster_copy_recursive(Relation rel, JsonContainer *jc, char cmethod)
{
	JsonIterator *it;
	JsonIteratorToken tok;
	JsonValue	jsv;
	uint32		offset = 0;

	check_stack_depth();

	Assert(jc->ops == &jsonbContainerOps);

	for (it = JsonIteratorInit(jc);
		 (tok = JsonIteratorNext(&it, &jsv, true)) != WJB_DONE;
		 offset = it ? JsonbIteratorGetCurOffset((JsonbIterator *) it) : 0)
	{
		if (tok != WJB_VALUE && tok != WJB_ELEM)
			continue;

		jsonb_toaster_replace_toasted(rel, &jsv, (JsonbIterator *) it, offset, cmethod);
	}
}

static Datum
jsonb_toaster_copy(Relation rel, JsonContainer *jc, char cmethod)
{
	JsonbContainer *jbc;
	Jsonb	   *jb;

	if (!JsonContainerIsToasted(jc, NULL) &&
		!JsonContainerContainsToasted(jc))
		return (Datum) 0;

	jbc = jc->ops == &jsonbzContainerOps ?
		jsonbzDecompress(jc) : JsonContainerDataPtr(jc);

	jb = palloc(sizeof(VARHDRSZ) + jc->len);
	memcpy(VARDATA(jb), jbc, jc->len);
	SET_VARSIZE(jb, sizeof(VARHDRSZ) + jc->len);

	if (JsonContainerContainsToasted(jc))
	{
		Json	   *js = DatumGetJson(PointerGetDatum(jb), &jsonbContainerOps, NULL);

		jsonb_toaster_copy_recursive(rel, JsonRoot(js), cmethod);
	}

	return PointerGetDatum(jb);
}

static void
jsonb_toaster_delete_container(Relation rel, JsonContainer *jc)
{
	JsonbToastedContainerPointer jbcptr;

	if (JsonContainerIsToasted(jc, &jbcptr))
	{
		struct varlena *ptr = jsonbMakeToastPointer(&jbcptr.ptr);

		toast_delete_datum(rel, PointerGetDatum(ptr), false);
		pfree(ptr);
	}
}

static void
jsonb_toaster_delete_recursive(Relation rel, JsonContainer *jc, bool delete_self)
{
	check_stack_depth();

	if (JsonContainerContainsToasted(jc))
	{
		JsonIterator *it = JsonIteratorInit(jc);
		JsonIteratorToken tok;
		JsonValue jsv;

		while ((tok = JsonIteratorNext(&it, &jsv, true)) != WJB_DONE)
		{
			JsonContainer *jc;

			if (tok != WJB_VALUE && tok != WJB_ELEM)
				continue;

			if (jsv.type != jbvBinary)
				continue;

			jc = jsv.val.binary.data;

			jsonb_toaster_delete_recursive(rel, jc, true);
		}
	}

	if (delete_self)
		jsonb_toaster_delete_container(rel, jc);
}

static bool
jsonb_toaster_cmp_recursive(Relation rel, JsonContainer *old_jc, JsonContainer *new_jc, char cmethod)
{
	JsonbToastedContainerPointer new_jbcptr;
	JsonbToastedContainerPointer old_jbcptr;
	JsonIterator *old_it;
	JsonIterator *new_it;
	JsonValue	old_jbv;
	JsonValue	new_jbv;
	bool		changed = false;
	bool		old_end;
	bool		new_end;

	check_stack_depth();

	old_it = JsonIteratorInit(old_jc);
	new_it = JsonIteratorInit(new_jc);

	JsonIteratorNext(&old_it, &old_jbv, true);
	JsonIteratorNext(&new_it, &new_jbv, true);

	old_end = JsonIteratorNext(&old_it, &old_jbv, true) != WJB_KEY;
	new_end = JsonIteratorNext(&new_it, &new_jbv, true) != WJB_KEY;

	while (!old_end || !new_end)
	{
		int			cmp =
			old_end ? 1 :
			new_end ? -1 : lengthCompareJsonbStringValue(&old_jbv, &new_jbv);

		if (!cmp)
		{
			uint32		offset = JsonbIteratorGetCurOffset((JsonbIterator *) new_it);

			if (JsonIteratorNext(&new_it, &new_jbv, true) != WJB_VALUE)
				break;

			if (JsonIteratorNext(&old_it, &old_jbv, true) != WJB_VALUE)
				break;

			if (new_jbv.type == jbvBinary)
			{
				if (old_jbv.type == jbvBinary)
				{
					JsonContainer *newjc = new_jbv.val.binary.data;
					JsonContainer *oldjc = old_jbv.val.binary.data;

					if (JsonContainerIsToasted(newjc, &new_jbcptr))
					{
						if (!JsonContainerIsToasted(oldjc, &old_jbcptr) ||
							memcmp(&new_jbcptr, &old_jbcptr, sizeof(new_jbcptr)))
						{
							changed |= jsonb_toaster_replace_toasted(rel, &new_jbv, (JsonbIterator *) new_it, offset, cmethod);
							jsonb_toaster_delete_recursive(rel, oldjc, true);
						}
					}
					else if (newjc->type != oldjc->type ||
							 newjc->type != jbvObject)
					{
						changed |= jsonb_toaster_replace_toasted(rel, &new_jbv, (JsonbIterator *) new_it, offset, cmethod);
						jsonb_toaster_delete_recursive(rel, oldjc, true);
					}
					else if (!JsonContainerContainsToasted(newjc))
					{
						jsonb_toaster_delete_recursive(rel, oldjc, false);
					}
					else if (!JsonContainerContainsToasted(oldjc))
						changed |= jsonb_toaster_replace_toasted(rel, &new_jbv, (JsonbIterator *) new_it, offset, cmethod);
					else
						changed |= jsonb_toaster_cmp_recursive(rel, oldjc, newjc, cmethod);
				}
				else
				{
					changed |=
						jsonb_toaster_replace_toasted(rel, &new_jbv,
													  (JsonbIterator *) new_it,
													  offset, cmethod);
				}
			}
			else if (old_jbv.type == jbvBinary)
			{
				jsonb_toaster_delete_recursive(rel, old_jbv.val.binary.data, true);
			}

			old_end = JsonIteratorNext(&old_it, &old_jbv, true) != WJB_KEY;
			new_end = JsonIteratorNext(&new_it, &new_jbv, true) != WJB_KEY;
		}
		else if (cmp < 0)
		{
			if (JsonIteratorNext(&old_it, &old_jbv, true) != WJB_VALUE)
				break;

			if (old_jbv.type == jbvBinary &&
				JsonContainerIsToasted(old_jbv.val.binary.data, NULL))
				jsonb_toaster_delete_recursive(rel, old_jbv.val.binary.data, true);

			old_end = JsonIteratorNext(&old_it, &old_jbv, true) != WJB_KEY;
		}
		else
		{
			uint32		offset = JsonbIteratorGetCurOffset((JsonbIterator *) new_it);

			if (JsonIteratorNext(&new_it, &new_jbv, true) != WJB_VALUE)
				break;

			changed |= jsonb_toaster_replace_toasted(rel, &new_jbv, (JsonbIterator *) new_it, offset, cmethod);

			new_end = JsonIteratorNext(&new_it, &new_jbv, true) != WJB_KEY;
		}
	}

	return changed;
}

static Datum
jsonb_toaster_cmp(Relation rel, JsonContainer *new_jc, JsonContainer *old_jc, char cmethod)
{
	JsonbToastedContainerPointer new_jbcptr;
	JsonbToastedContainerPointer old_jbcptr;
	Datum		res;
	Jsonb	   *jb;
	JsonbContainer *new_jbc;
	bool		changed = false;

	if (JsonContainerIsToasted(new_jc, &new_jbcptr))
	{
		if (JsonContainerIsToasted(old_jc, &old_jbcptr) &&
			!memcmp(&new_jbcptr, &old_jbcptr, sizeof(new_jbcptr)))
			return (Datum) 0;

		res = jsonb_toaster_copy(rel, new_jc, cmethod);
		jsonb_toaster_delete_recursive(rel, old_jc, false);

		return res;
	}

	if (new_jc->type != old_jc->type ||
		new_jc->type != jbvObject)
	{
		res = jsonb_toaster_copy(rel, new_jc, cmethod);
		jsonb_toaster_delete_recursive(rel, old_jc, false);
		return res;
	}

	if (!JsonContainerContainsToasted(new_jc))
	{
		jsonb_toaster_delete_recursive(rel, old_jc, false);
		return (Datum) 0;
	}

	if (!JsonContainerContainsToasted(old_jc))
		return jsonb_toaster_copy(rel, new_jc, cmethod);

	new_jbc = new_jc->ops == &jsonbzContainerOps ?
		jsonbzDecompress(new_jc) : JsonContainerDataPtr(new_jc);

	jb = palloc(sizeof(VARHDRSZ) + new_jc->len);
	memcpy(VARDATA(jb), new_jbc, new_jc->len);
	SET_VARSIZE(jb, sizeof(VARHDRSZ) + new_jc->len);

	changed = jsonb_toaster_cmp_recursive(rel, old_jc, new_jc, cmethod);

	return PointerGetDatum(changed ? jb : NULL);
}

typedef Jsonb JsonbToastData;

static bool
jsonb_toaster_validate(Oid toasteroid)
{
	return true;
}

static struct varlena *
jsonb_toaster_make_pointer(Oid toasterid, Jsonb *jsonb)
{
	Size		size = VARATT_CUSTOM_SIZE(VARSIZE_ANY(jsonb));
	struct varlena *result = palloc(size);
	varatt_custom va_custom;

	SET_VARTAG_EXTERNAL(result, VARTAG_CUSTOM);

	va_custom.va_toasterid.oid_val = toasterid;
	va_custom.va_rawsize.int_val = VARSIZE_ANY_EXHDR(jsonb);	/* FIXME */
	va_custom.va_toasterdatalen.int_val = VARSIZE_ANY(jsonb);
	memcpy(VARDATA_EXTERNAL(result), &va_custom, sizeof(va_custom));

	memcpy(VARATT_CUSTOM_GET_DATA(result), jsonb, VARSIZE_ANY(jsonb));

	return result;
}

static Datum
jsonb_toaster_toast(Relation rel, Oid toasterid,
					Datum new_val, Datum old_val,
					int max_inline_size, char cmethod)
{
	jsonbInitIterators();

	Json	   *new_js = new_val != (Datum) 0 ? DatumGetJsonbPC(new_val, NULL, false) : NULL;
	Json	   *old_js = old_val != (Datum) 0 ? DatumGetJsonbPC(old_val, NULL, false) : NULL;
	Datum		res = (Datum) 0;

	//js = DatumGetJsonbPC(jb, NULL /* FIXME alloca */, false);
	//js = DatumGetJson(jb, &jsonbContainerOps, NULL /* FIXME alloca */);

	if (new_js)
	{
		if (old_js)
			jsonb_toaster_cmp(rel, JsonRoot(new_js), JsonRoot(old_js), cmethod);
		else if (max_inline_size > 0)
		{
			res = jsonb_toaster_save(rel, new_js, max_inline_size, cmethod);
			res = res == (Datum) 0 ? new_val : res;
		}
		else
		{
			res = jsonb_toaster_copy(rel, JsonRoot(new_js), cmethod);
		}
	}
	else
	{
		if (old_js)
			jsonb_toaster_delete_recursive(rel, JsonRoot(old_js), false);
	}

	if (res != (Datum) 0)
		res = PointerGetDatum(jsonb_toaster_make_pointer(toasterid, (Jsonb *) DatumGetPointer(res)));

	jsonbFreeIterators();

	return res;
}

static Datum
jsonb_toaster_detoast(Relation toastrel, Datum toastptr,
					  int sliceoffset, int slicelength)
{
	struct varlena *result;
	Json		jsbuf;
	Json	   *js;
	void	   *detoasted;
	int			len;

	Assert(VARATT_IS_CUSTOM(toastptr));

	js = DatumGetJson(toastptr, &myjsonbContainerOps, &jsbuf);

	detoasted = JsonFlatten(js, JsonbEncode, &jsonbContainerOps);
	len = VARSIZE_ANY_EXHDR(detoasted);

	if (sliceoffset == 0 && (slicelength < 0 || slicelength >= len))
		return PointerGetDatum(detoasted);

	if (sliceoffset < 0)
		sliceoffset = 0;
	else if (sliceoffset > len)
		sliceoffset = len;

	if (slicelength < 0 || sliceoffset + slicelength > len)
		slicelength = len - sliceoffset;

	result = palloc(VARHDRSZ + slicelength);
	SET_VARSIZE(result, VARHDRSZ + slicelength);
	memcpy(VARDATA(result), (char *) VARDATA_ANY(detoasted) + sliceoffset, slicelength);

	pfree(detoasted);

	return PointerGetDatum(result);
}

static void *
jsonb_toaster_vtable(Datum toast_ptr)
{
	JsonToastRoutine *routine = palloc0(sizeof(*routine));

	routine->magic = JSON_TOASTER_MAGIC;
	routine->ops = &myjsonbContainerOps;

	return routine;
}

PG_FUNCTION_INFO_V1(jsonb_toaster_handler);
Datum
jsonb_toaster_handler(PG_FUNCTION_ARGS)
{
	TsrRoutine *tsr = makeNode(TsrRoutine);

	tsr->toasterversion = 1;
	tsr->toastercompressed = false;

	tsr->toast = jsonb_toaster_toast;
	tsr->detoast = jsonb_toaster_detoast;
	tsr->toastervalidate = jsonb_toaster_validate;
	tsr->get_vtable = jsonb_toaster_vtable;

	PG_RETURN_POINTER(tsr);
}

void
_PG_init(void)
{
	DefineCustomBoolVariable("jsonb_toaster.toast_fields",
							 "TOAST jsonb object fields.",
							 NULL,
							 &jsonb_toast_fields,
							 true,
							 PGC_USERSET,
							 0,
							 NULL,
							 NULL,
							 NULL);
}
