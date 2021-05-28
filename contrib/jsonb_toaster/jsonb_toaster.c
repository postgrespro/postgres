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
#include "access/toast_helper.h"
#include "catalog/pg_collation.h"
#include "catalog/pg_type.h"
#include "catalog/toasting.h"
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
#include "utils/jsonb_internals.h"
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
#define JSONB_MAX_ELEMS (Min(MaxAllocSize / sizeof(JsonbValue), JBC_CMASK))
#define JSONB_MAX_PAIRS (Min(MaxAllocSize / sizeof(JsonbPair), JBC_CMASK))

#define JENTRY_ISCONTAINER_PTR	0x60000000	/* pointer to toasted array or object */
#define JBE_ISCONTAINER_PTR(je_)(((je_) & JENTRY_TYPEMASK) == JENTRY_ISCONTAINER_PTR)

#define JBC_TOBJECT_TOASTED		0x10000000	/* object with toasted keys */

#define JB_HEADER(jb) ((jb)->root.header)
#define JX_HEADER_IS_OBJECT(hdr) (((hdr) & JBC_TMASK) == JBC_TOBJECT || \
								  ((hdr) & JBC_TMASK) == JBC_TOBJECT_SORTED || \
								  ((hdr) & JBC_TMASK) == JBC_TOBJECT_TOASTED)
#define JX_ROOT_IS_OBJECT(jbp_)	JX_HEADER_IS_OBJECT(JB_HEADER(jbp_))

typedef struct varatt_external JsonbToastPointer;

typedef struct JsonbToastedContainerPointer
{
	JsonbContainerHdr header;
	struct varlena data;
} JsonbToastedContainerPointer;

typedef struct JsonbToastedContainerPointerData
{
	struct varlena *toast_ptr;
	struct varatt_external ptr;
	uint32		container_offset;
} JsonbToastedContainerPointerData;

typedef struct JsonbCompressedContainerData
{
	struct varlena *compressed_data;
	ToastCompressionId compression_method;
} JsonbCompressedContainerData;

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
	JsonbContainerHdr header;
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

static void jsonxFillValue(const JsonbContainerHeader *container, int index,
						   char *base_addr, uint32 offset,
						   JsonbValue *result);
static void convertJsonbValue(StringInfo buffer, JEntry *header, const JsonbValue *val, int level);
static void convertJsonbArray(StringInfo buffer, JEntry *header, const JsonbValue *val, int level);
static void convertJsonbObject(StringInfo buffer, JEntry *header, const JsonbValue *val, int level);
static void convertJsonbBinary(StringInfo buffer, JEntry *header, const JsonbValue *val, int level);
static void convertJsonbScalar(StringInfo buffer, JEntry *header, const JsonbValue *scalarVal);

static void copyToBuffer(StringInfo buffer, int offset, const void *data, int len);
static short padBufferToInt(StringInfo buffer);

static jsonbIterator *iteratorFromContainer(JsonContainer *container, jsonbIterator *parent);
static void jsonxInitContainer(JsonContainerData *jc, JsonbContainerHeader *jbc, int len, Oid toasterid);
static void jsonxzInitWithHeader(JsonContainerData *jc, Datum value, JsonbContainerHdr *header);

static JsonbValue *fillCompressedJsonbValue(CompressedJsonb *cjb,
											const JsonbContainerHeader *container,
											int index, char *base_addr,
											uint32 offset, JsonValue *result);
static JsonbContainerHeader *jsonxzDecompress(JsonContainer *jc);
static bool JsonContainerIsToasted(JsonContainer *jc,
								   JsonbToastedContainerPointerData *jbcptr);
static bool JsonContainerIsCompressed(JsonContainer *jc,
									  JsonbCompressedContainerData *jbcptr);
static bool JsonValueContainsToasted(const JsonValue *jv);
static bool JsonValueIsToasted(JsonValue *jv, JsonbToastedContainerPointerData *jbcptr);
static bool JsonValueIsCompressed(JsonValue *jv, JsonbCompressedContainerData *jbcptr);


static bool jsonb_toast_fields = true;				/* GUC */
static bool jsonb_toast_fields_recursively = true;	/* GUC */
static bool jsonb_compress_fields = true;			/* GUC */

static JsonContainerOps jsonxContainerOps;
static JsonContainerOps jsonxzContainerOps;

static struct varlena *
jsonxMakeToastPointer(JsonbToastedContainerPointerData *ptr)
{
	struct varlena *toast_ptr = palloc(TOAST_POINTER_SIZE);

	SET_VARTAG_EXTERNAL(toast_ptr, VARTAG_ONDISK);
	memcpy(VARDATA_EXTERNAL(toast_ptr), &ptr->ptr, sizeof(ptr->ptr));

	return toast_ptr;
}

static void
jsonxWriteToastPointer(StringInfo buffer, JsonbToastedContainerPointerData *ptr)
{
	char		toast_ptr[TOAST_POINTER_SIZE];

	SET_VARTAG_EXTERNAL(toast_ptr, VARTAG_ONDISK);
	memcpy(VARDATA_EXTERNAL(toast_ptr), &ptr->ptr, sizeof(ptr->ptr));
	appendToBuffer(buffer, toast_ptr, sizeof(toast_ptr));
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

	jsonxFillValue(it->container, it->index, it->base_addr, it->offset, result);

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

	jsonxFillValue(it->container, i, it->base_addr,
				   getJsonbOffset(it->container, i),
				   result);

	return result;
}

static JsonbValue *
jsonxFindValueInArrayContainer(const JsonbContainerHeader *container,
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
jsonxFindValueInArray(JsonContainer *jsc, const JsonbValue *key)
{
	return jsonxFindValueInArrayContainer(JsonContainerDataPtr(jsc), key);
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
jsonxFindKeyInObject(JsonContainer *jsc,
					 const char *keyVal, int keyLen, JsonbValue *res)
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

			jsonxFillValue(container, index, baseAddr,
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
jsonxGetArrayElement(JsonContainer *jsc, uint32 i)
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
static void
jsonxFillValue(const JsonbContainerHeader *container, int index,
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
		JsonContainerData *cont = JsonContainerAlloc(&jsonxContainerOps);

		jsonxInitContainer(cont,
			/* Remove alignment padding from data pointer and length */
						   (JsonbContainerHeader *)(base_addr + INTALIGN(offset)),
						   getJsonbLength(container, index) -
						   (INTALIGN(offset) - offset),
						   InvalidOid);

		JsonValueInitBinary(result, cont);
	}
	else if (JBE_ISCONTAINER_PTR(entry))
	{
		JsonbToastedContainerPointer *jbcptr = (JsonbToastedContainerPointer *)(base_addr + INTALIGN(offset));
		struct varlena *toast_ptr = &jbcptr->data;
		bool			is_jsonx = (jbcptr->header & JBC_TOBJECT_TOASTED) != 0;
		JsonContainerData *cont =
			JsonContainerAlloc(is_jsonx ? &jsonxzContainerOps : &jsonbzContainerOps);

		jsonxzInitWithHeader(cont, PointerGetDatum(toast_ptr), &jbcptr->header);
		JsonValueInitBinary(result, cont);
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
static JsonbIteratorToken
JsonxIteratorNext(JsonIterator **jsit, JsonbValue *val, bool skipNested)
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
	jsonbIterator *it = (jsonbIterator *) JsonIteratorInit(container);
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
JsonxIteratorInit(JsonContainer *cont, const JsonbContainerHeader *container,
				  struct CompressedJsonb *cjb)
{
	jsonbIterator *it;
	int			type;

	/* decompress container header */
	if (cjb)
		PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + cjb->offset + offsetof(JsonbDatum, root.children));

	type = container->header & JBC_TMASK;

	it = palloc0(sizeof(jsonbIterator));
	it->ji.container = cont;
	it->ji.parent = NULL;
	it->ji.next = JsonxIteratorNext;
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
		case JBC_TOBJECT_TOASTED:
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
		PG_DETOAST_ITERATE(cjb->iter, it->dataProper);

	return (JsonIterator *) it;
}

static JsonIterator *
jsonxIteratorInit(JsonContainer *cont)
{
	return JsonxIteratorInit(cont, (const JsonbContainerHeader *) JsonContainerDataPtr(cont), NULL);
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
JsonxEncode(StringInfoData *buffer, const JsonbValue *val, void *cxt)
{
	JEntry		jentry;
	int32		header_len;
	int32		jsonb_offset;

	/* Make room for the varlena header */
	reserveFromBuffer(buffer, VARATT_CUSTOM_SIZE(VARHDRSZ));
	header_len = buffer->len;

	padBufferToInt(buffer);
	jsonb_offset = buffer->len;

	convertJsonbValue(buffer, &jentry, val, 0);

	SET_VARTAG_EXTERNAL(buffer->data, VARTAG_CUSTOM);

	VARATT_CUSTOM_SET_TOASTERID(buffer->data, (Oid)(intptr_t) cxt);
	VARATT_CUSTOM_SET_DATA_RAW_SIZE(buffer->data, buffer->len - jsonb_offset + VARHDRSZ);
	VARATT_CUSTOM_SET_DATA_SIZE(buffer->data, buffer->len - header_len + VARHDRSZ);

	SET_VARSIZE(buffer->data + jsonb_offset - VARHDRSZ, buffer->len - jsonb_offset + VARHDRSZ);
}

static void *
jsonxEncode(JsonValue *jv, JsonContainerOps *ops, Oid toasterid)
{
	if (ops == &jsonbContainerOps)
		return JsonEncode(jv, JsonxEncode, (void *)(intptr_t) toasterid);

	return NULL;
}

static void *
jsonxzEncode(JsonValue *jv, JsonContainerOps *ops, Oid toasterid)
{
	if (ops == &jsonbContainerOps)
	{
		JsonbToastedContainerPointerData jbcptr;
		JsonbCompressedContainerData jbccomp;

		if (JsonValueIsToasted(jv, &jbcptr))
			return jsonxMakeToastPointer(&jbcptr);

		if (JsonValueIsCompressed(jv, &jbccomp))
		{
			int			size = VARSIZE_ANY(jbccomp.compressed_data);

			return memcpy(palloc(size), jbccomp.compressed_data, size);
		}
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

	/* XXX Assert(JsonValueIsUniquified(val)); */

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
		header = nElems | JBC_TSCALAR;
	}
	else
		header = nElems | JBC_TARRAY;

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
		case jbvBinary:
#if 0 /* XXX jsonv */
			if (jbv->val.binary.data->ops == &jsonvContainerOps)
				return estimateJsonbValueSize((const JsonbValue *) JsonContainerDataPtr(jbv->val.binary.data));
#endif
			return jbv->val.binary.data->len;	/* FIXME */
		default:
			elog(ERROR, "invalid jsonb value type: %d", jbv->type);
			return 0;
	}
}

static void
jsonxInitToastedContainerPointer(JsonbToastedContainerPointerData *jbcptr,
								 varatt_external *toast_ptr,
								 uint32 container_offset)
{
	/*
	jbcptr->header =
		(JsonContainerIsArray(jc) ? JBC_TARRAY : JBC_TOBJECT) |
		(jc->ops == &jsonxzContainerOps ? JBC_TOBJECT_TOASTED : 0) |
		JsonContainerSize(jc);*/
	jbcptr->ptr = *toast_ptr;
	jbcptr->container_offset = container_offset;
}

static bool
JsonContainerIsToasted(JsonContainer *jc, JsonbToastedContainerPointerData *jbcptr)
{
	if (jc->ops == &jsonbzContainerOps ||
		jc->ops == &jsonxzContainerOps)
	{
		CompressedJsonb *cjb = jsonbzGetCompressedJsonb(jc);
		FetchDatumIterator fetch_iter = cjb->iter->fetch_datum_iterator;

		if (fetch_iter->toast_pointer.va_rawsize > 0 &&
			cjb->offset == offsetof(JsonbDatum, root))
		{
			if (jbcptr)
				jsonxInitToastedContainerPointer(jbcptr,
												 &fetch_iter->toast_pointer,
												 cjb->offset);
			return true;
		}
	}

	return false;
}

static bool
JsonContainerIsCompressed(JsonContainer *jc,
						  JsonbCompressedContainerData *jbcptr)
{
	if (jc->ops == &jsonbzContainerOps ||
		jc->ops == &jsonxzContainerOps)
	{
		CompressedJsonb *cjb = jsonbzGetCompressedJsonb(jc);
		FetchDatumIterator fetch_iter = cjb->iter->fetch_datum_iterator;

		if (fetch_iter->toast_pointer.va_rawsize <= 0 &&
			cjb->offset == offsetof(JsonbDatum, root))
		{
			Assert(cjb->iter->compressed);

			if (jbcptr)
			{
				jbcptr->compression_method = cjb->iter->compression_method;
				jbcptr->compressed_data = (struct varlena *) fetch_iter->buf->buf;
			}

			return true;
		}
	}

	return false;
}

static bool
JsonContainerContainsToasted(JsonContainer *jc)
{
	if (jc->ops == &jsonxContainerOps)
	{
		JsonbContainerHeader *jbc = JsonContainerDataPtr(jc);

		return (jbc->header & JBC_TMASK) == JBC_TOBJECT_TOASTED;
	}
	else if (jc->ops == &jsonxzContainerOps)
	{
		CompressedJsonb *cjb = jsonbzGetCompressedJsonb(jc);

		return (cjb->header & JBC_TMASK) == JBC_TOBJECT_TOASTED;
	}
#if 0 /* XXX jsonv */
	else if (jc->ops == &jsonvContainerOps)
		return JsonValueContainsToasted(JsonContainerDataPtr(jc));
#endif
	else
		return false;	/* XXX other container types */
}

static bool
JsonValueIsToasted(JsonValue *jv, JsonbToastedContainerPointerData *jbcptr)
{
	return jv->type == jbvBinary &&
		JsonContainerIsToasted(jv->val.binary.data, jbcptr);
}

static bool
JsonValueIsCompressed(JsonValue *jv, JsonbCompressedContainerData *jbcptr)
{
	return jv->type == jbvBinary &&
		JsonContainerIsCompressed(jv->val.binary.data, jbcptr);
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

			if (JsonValueIsToasted(val, NULL) ||
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

			if (JsonValueIsToasted(val, NULL) ||
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
		(sorted_values ? JBC_TOBJECT_SORTED :
		have_toasted_values ? JBC_TOBJECT_TOASTED : JBC_TOBJECT);
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

static int
jsonxToastPointerSize(JsonbToastedContainerPointerData *jbcptr_data)
{
	return TOAST_POINTER_SIZE; /* TOAST_INLINE_POINTER_SIZE + jbcptr_data->tail_size; */
}

static JsonbContainerHdr
jsonxContainerHeader(JsonContainer *jc)
{
	bool		is_jsonx =
		jc->ops == &jsonxContainerOps || jc->ops == &jsonxzContainerOps;

	return JsonContainerSize(jc) |
		(JsonContainerIsArray(jc) ? JBC_TARRAY :
			JBC_TOBJECT | (is_jsonx ? JBC_TOBJECT_TOASTED : 0));
}

static void
convertJsonbBinary(StringInfo buffer, JEntry *pheader, const JsonbValue *val,
				   int level)
{
	JsonContainer *jc = val->val.binary.data;

	Assert(val->type == jbvBinary);

	if (!JsonContainerIsScalar(jc) &&
		(jc->ops == &jsonbContainerOps ||
		 jc->ops == &jsonbzContainerOps ||
		 jc->ops == &jsonxContainerOps ||
		 jc->ops == &jsonxzContainerOps))
	{
		JsonbContainerHeader *jbc;
		int			base_offset = buffer->len;

		if (jsonb_toast_fields)
		{
			JsonbToastedContainerPointerData jbcptr_data;

			if (JsonContainerIsToasted(jc, &jbcptr_data) &&
				offsetof(JsonbToastedContainerPointer, data) + jsonxToastPointerSize(&jbcptr_data) < (JENTRY_OFFLENMASK >> 1)) /* FIXME */
			{
				JsonbToastedContainerPointer jbcptr;

				jbcptr.header = jsonxContainerHeader(jc);

				padBufferToInt(buffer);
				appendToBuffer(buffer, (void *) &jbcptr, offsetof(JsonbToastedContainerPointer, data));
				jsonxWriteToastPointer(buffer, &jbcptr_data);

				*pheader = JENTRY_ISCONTAINER_PTR | (buffer->len - base_offset);
				return;
			}
		}

		if (jsonb_compress_fields)
		{
			JsonbCompressedContainerData jbccomp_data;

			if (JsonContainerIsCompressed(jc, &jbccomp_data) &&
				offsetof(JsonbToastedContainerPointer, data) + VARSIZE_ANY(jbccomp_data.compressed_data) < (JENTRY_OFFLENMASK >> 1)) /* FIXME */
			{
				JsonbToastedContainerPointer jbccomp;

				jbccomp.header = jsonxContainerHeader(jc);

				padBufferToInt(buffer);
				appendToBuffer(buffer, (void *) &jbccomp, offsetof(JsonbToastedContainerPointer, data));
				appendToBuffer(buffer, (void *) jbccomp_data.compressed_data, VARSIZE_ANY(jbccomp_data.compressed_data));

				*pheader = JENTRY_ISCONTAINER_PTR | (buffer->len - base_offset);
				return;
			}
		}

		jbc = jc->ops == &jsonbzContainerOps || jc->ops == &jsonxzContainerOps ?
			jsonxzDecompress(jc) : JsonContainerDataPtr(jc);

		padBufferToInt(buffer);
		appendToBuffer(buffer, (void *) jbc, jc->len);
		*pheader = JENTRY_ISCONTAINER | (buffer->len - base_offset);
	}
#if 0 /* XXX jsonv */
	else if (jc->ops == &jsonvContainerOps && !JsonContainerIsScalar(jc))
		convertJsonbValue(buffer, pheader,
						  (const JsonValue *) JsonContainerDataPtr(jc), level);
#endif
	else
		convertJsonbValue(buffer, pheader, JsonValueUnpackBinary(val), level);
}

static void
jsonxInitContainerFromHeader(JsonContainerData *jc, JsonbContainerHdr header)
{
	jc->size = header & JBC_CMASK;
	switch (header & JBC_TMASK)
	{
		case JBC_TOBJECT:
		case JBC_TOBJECT_SORTED:
		case JBC_TOBJECT_TOASTED:
			jc->type = jbvObject;
			break;
		case JBC_TARRAY:
			jc->type = jbvArray;
			break;
		case JBC_TSCALAR:
			jc->type = jbvArray | jbvScalar;
			break;
		default:
			elog(ERROR, "invalid jsonb container type: %d", header & JBC_TMASK);
	}
}

static void
jsonxInitContainer(JsonContainerData *jc, JsonbContainerHeader *jbc, int len, Oid toasterid)
{
	jc->ops = &jsonxContainerOps;
	JsonContainerDataPtr(jc) = jbc;
	jc->len = len;
	jc->toasterid = toasterid;
	jsonxInitContainerFromHeader(jc, jbc->header);
}

static void
jsonxInit(JsonContainerData *jc, Datum value)
{
	JsonbDatum	   *jb;

	Assert(VARATT_IS_CUSTOM(value));
	jb = (void *) VARATT_CUSTOM_GET_DATA(value);
	jb = (void *) INTALIGN((intptr_t) jb);		/* FIXME alignment */

	jsonxInitContainer(jc, &jb->root, VARSIZE_ANY_EXHDR(jb),
					   VARATT_CUSTOM_GET_TOASTERID(value));
}

static void
jsonxzInitContainer(JsonContainerData *jc, CompressedJsonb *cjb,
					JsonbContainerHdr *pheader, int len)
{
	JsonbDatum	   *jb = (JsonbDatum *) cjb->iter->buf->buf;
	JsonbContainerHeader *jbc = (JsonbContainerHeader *)((char *) jb + cjb->offset);
	JsonbContainerHdr header = pheader ? *pheader : jbc->header;

	*(CompressedJsonb *) &jc->_data = *cjb;
	((CompressedJsonb *) &jc->_data)->header = header;

	jc->ops = &jsonxzContainerOps;
	jc->len = len;
	jsonxInitContainerFromHeader(jc, header);
}

static JsonbContainerHeader *
jsonxzDecompress(JsonContainer *jc)
{
	CompressedJsonb *cjb = jsonbzGetCompressedJsonb(jc);
	JsonbDatum	   *jb = (JsonbDatum *) cjb->iter->buf->buf;
	JsonbContainerHeader *container = (JsonbContainerHeader *)((char *) jb + cjb->offset);

	PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + cjb->offset + jc->len);

	return container;
}

static JsonbValue *
fillCompressedJsonbValue(CompressedJsonb *cjb, const JsonbContainerHeader *container,
						 int index, char *base_addr, uint32 offset,
						 JsonValue *result)
{
	JEntry		entry = container->children[index];
	uint32		len = getJsonbLength(container, index);
	Size		base_offset;

	if (!cjb)
	{
		jsonxFillValue(container, index, base_addr, offset, result);
		return result;
	}

	base_offset = base_addr - (char *) cjb->iter->buf->buf;

	if (JBE_ISCONTAINER(entry) /* && len > JSONBZ_MIN_CONTAINER_LEN */)
	{
		JsonContainerData *cont = JsonContainerAlloc(&jsonxzContainerOps);
		CompressedJsonb cjb2;

		cjb2.iter = cjb->iter;
		//cjb2.iter->nrefs++;

		/* Remove alignment padding from data pointer and length */
		cjb2.offset = base_offset + INTALIGN(offset);

		len -= INTALIGN(offset) - offset;

		PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + cjb2.offset +
						   offsetof(JsonbContainerHeader, children));

		jsonxzInitContainer(cont, &cjb2, NULL, len);
		JsonValueInitBinary(result, cont);
	}
	else
	{
		PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + base_offset + offset + len);
		jsonxFillValue(container, index, base_addr, offset, result);
	}

	return result;
}

static JsonbValue *
findValueInCompressedJsonbObject(CompressedJsonb *cjb, const char *keystr, int keylen, JsonValue *res)
{
	JsonbDatum	   *jb = (JsonbDatum *) cjb->iter->buf->buf;
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

	Assert(JX_HEADER_IS_OBJECT(container->header));

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
jsonxzFindKeyInObject(JsonContainer *jc, const char *key, int len, JsonValue *res)
{
	CompressedJsonb *cjb = jsonbzGetCompressedJsonb(jc);
#ifdef JSONB_OWN_DETOAST_ITERATOR	/* FIXME */
	JsonbDatum	   *jb = (JsonbDatum *) cjb->datum->data;

	JsonbContainerHeader *jbc = (JsonbContainerHeader *)((char *) jb + cjb->offset);

	if (!cjb->datum->compressed)
	{
		JsonContainerData jcd;

		jsonxInitContainer(&jcd, jbc, jc->len, InvalidOid);

		return jsonbFindKeyInObject(&jcd, key, len, res);
	}

	CompressedDatumDecompress(cjb->datum, cjb->offset + offsetof(JsonbContainerHeader, header));
#else
	PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->buf + cjb->offset + offsetof(JsonbContainerHeader, header));
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
	JsonbDatum	   *jb = (JsonbDatum *) cjb->iter->buf->buf;
	const JsonbContainerHeader *jbc = (const JsonbContainerHeader *)((char *) jb + cjb->offset);

	PG_DETOAST_ITERATE(cjb->iter, (const char *) &jbc->children);

	it->count = (cjb->header & JBC_CMASK);

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
jsonxzFindValueInArray(JsonContainer *jc, const JsonValue *val)
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
jsonxzGetArrayElement(JsonContainer *jc, uint32 index)
{
	CompressedJsonb *cjb = jsonbzGetCompressedJsonb(jc);
	JsonbzArrayIterator it;

	if (!JsonContainerIsArray(jc))
		elog(ERROR, "not a jsonb array");

	JsonbzArrayIteratorInit(&it, cjb);

	return JsonbzArrayIteratorGetIth(&it, index);
}

static JsonIterator *
jsonxzIteratorInit(JsonContainer *jc)
{
	CompressedJsonb *cjb = jsonbzGetCompressedJsonb(jc);
	JsonbDatum	   *jb = (JsonbDatum *) cjb->iter->buf->buf;
	JsonbContainerHeader *jbc = (JsonbContainerHeader *)((char *) jb + cjb->offset);

	if (!jsonb_partial_decompression)
		PG_DETOAST_ITERATE(cjb->iter, cjb->iter->buf->capacity);

	return JsonxIteratorInit(jc, jbc, cjb);
}

static void
jsonxzInitFromDetoastIterator(JsonContainerData *jc, DetoastIterator iter, JsonbContainerHdr *header)
{
	CompressedJsonb *cjb = palloc(sizeof(*cjb));
	cjb->iter = iter;
	cjb->offset = offsetof(JsonbDatum, root);

	if (!jsonb_partial_decompression)
		PG_DETOAST_ITERATE(iter, iter->buf->capacity);
	else if (!header)
		PG_DETOAST_ITERATE(iter, Min(iter->buf->buf + offsetof(JsonbDatum, root.children), iter->buf->capacity));

	jsonxzInitContainer(jc, cjb, header, VARSIZE_ANY_EXHDR(iter->buf->buf)); // cd->total_len - VARHDRSZ
}

static void
jsonxzFree(JsonContainer *jc)
{
	CompressedJsonb *cjb = jsonbzGetCompressedJsonb(jc);

	if (cjb->iter)
		free_detoast_iterator(cjb->iter);
}

static void
jsonxzInitWithHeader(JsonContainerData *jc, Datum value, JsonbContainerHdr *header)
{
	DetoastIterator iter;
#ifdef JSONB_FREE_ITERATORS
	MemoryContext mcxt = jsonbGetIteratorContext();
	MemoryContext oldcxt;

	if (mcxt)
		oldcxt = MemoryContextSwitchTo(mcxt);
#endif

	iter = create_detoast_iterator((struct varlena *) DatumGetPointer(value));

#ifdef JSONB_FREE_ITERATORS
	if (mcxt)
	{
		jsonbRegisterIterator(&iter->gen);
		MemoryContextSwitchTo(oldcxt);
	}
#else
	jsonbRegisterIterator(&iter->gen);
#endif

	jsonxzInitFromDetoastIterator(jc, iter, header);
}

static void
jsonxzInit(JsonContainerData *jc, Datum value)
{
	jsonxzInitWithHeader(jc, value, NULL);
}

static JsonContainer *
jsonxzCopy(JsonContainer *jc)
{
	JsonContainerData *res;
	JsonbContainerHeader *jbc;
	JsonbContainerHeader *jbc_copy;

	jbc = jsonxzDecompress(jc);

	jbc_copy = palloc(jc->len);
	memcpy(jbc_copy, jbc, jc->len);

	res = JsonContainerAlloc(&jsonxContainerOps);
	jsonxInitContainer(res, jbc_copy, jc->len, jc->toasterid);

	return res;
}

static JsonContainerOps
jsonxzContainerOps =
{
	sizeof(CompressedJsonb),
	jsonxzInit,
	jsonxzIteratorInit,
	jsonxzFindKeyInObject,
	jsonxzFindValueInArray,
	jsonxzGetArrayElement,
	NULL,
	JsonbToCStringRaw,
	jsonxzCopy,
	jsonxzFree,
	jsonxzEncode
};

static JsonContainerOps
jsonxContainerOps =
{
	sizeof(CompressedJsonb),
	jsonxInit,
	jsonxIteratorInit,
	jsonxFindKeyInObject,
	jsonxFindValueInArray,
	jsonxGetArrayElement,
	NULL,
	JsonbToCStringRaw,
	JsonCopyFlat,
	NULL,
	jsonxEncode
};

static JsonContainer *
jsonxzInitContainerFromDatum(JsonContainer *jc, Datum toasted_val)
{
	JsonContainerData *tjc;
	JsonbContainerHdr header;
	bool		is_jsonx;

	Assert(VARATT_IS_EXTERNAL_ONDISK(toasted_val) ||
		   VARATT_IS_COMPRESSED(toasted_val));

	is_jsonx = jc->ops == &jsonxContainerOps || jc->ops == &jsonxzContainerOps;

	header =
		(JsonContainerIsArray(jc) ? JBC_TARRAY : JBC_TOBJECT) |
		(is_jsonx ? JBC_TOBJECT_TOASTED : 0) |
		JsonContainerSize(jc);

	tjc = JsonContainerAlloc(is_jsonx ? &jsonxzContainerOps : &jsonbzContainerOps);	/* FIXME optimize */
	jsonxzInitWithHeader(tjc, toasted_val, &header);

	return tjc;
}

static bool
jsonb_toaster_save_object(Relation rel, JsonContainer *root,
						  /* XXX bool uniquified, */ Size max_size, char cmethod,
						  JsonValue	*object)
{
	JsonIterator *it;
	JsonValue	jsv;
	JsonIteratorToken tok;
	Size		total_key_names_length = 0;
	Size		min_values_length = 0;
	Size		header_size;
	Size		total_size;
	struct
	{
		const void *value;
		int			size;
		char		status;
	}		   *fields;
	JsonbPair  *pairs;
	int			nkeys;
	int			i = 0;
	int			pass = 1;
	bool		res = false;

	nkeys = JsonContainerSize(root);

	header_size = offsetof(JsonbDatum, root.children) + sizeof(JEntry) * nkeys * 2;
	total_size = header_size;

	if (header_size > max_size)
		return false;

	fields = palloc0(sizeof(*fields) * nkeys);
	pairs = palloc(sizeof(*pairs) * nkeys);

	JsonValueInitObject(object, nkeys, 0 /* XXX, uniquified */);
	object->val.object.pairs = pairs;

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

			if (JsonValueIsToasted(&jsv, NULL))
			{
				Size		size = offsetof(JsonbToastedContainerPointer, data) + TOAST_POINTER_SIZE;

				fields[i].value = NULL;
				fields[i].size = size;
				fields[i].status = 't';
				min_values_length += INTALIGN(size + 3);
			}
			else
			{
				switch (jsv.type)
				{
					case jbvBinary:
						{
							JsonbCompressedContainerData jbccomp;

							if (JsonContainerIsCompressed(jsv.val.binary.data, &jbccomp))
							{
								fields[i].value = jbccomp.compressed_data;
								fields[i].size = offsetof(JsonbToastedContainerPointer, data) + VARSIZE_ANY(jbccomp.compressed_data);
								fields[i].status = 'c';
							}
							else
							{
								fields[i].value = jsv.val.binary.data;
								fields[i].size = jsv.val.binary.data->len;
							}

							min_values_length += INTALIGN(offsetof(JsonbToastedContainerPointer, data) + TOAST_POINTER_SIZE + 3);
							break;
						}
						break;
					case jbvString:
						fields[i].value = jsv.val.string.val;
						fields[i].size = jsv.val.string.len;
						min_values_length += INTALIGN(fields[i].size + 3);
						//min_values_length += sizeof(JsonbToastPointer);
						break;
					case jbvNumeric:
						fields[i].value = jsv.val.numeric;
						fields[i].size = VARSIZE_ANY(jsv.val.numeric);
						min_values_length += INTALIGN(fields[i].size + 3);
						//min_values_length += sizeof(JsonbToastPointer);
						break;
					default:
						fields[i].value = NULL;
						fields[i].size = 0;
						break;
				}
			}

			total_size += INTALIGN(fields[i].size + 3);
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
		Datum		val = (Datum) 0;
		Datum		compressed_val;
		Datum		toasted_val;
		JsonContainer *jc;
		JsonbContainerHeader *jbc;

		for (i = 0; i < nkeys; i++)
		{
			if (pairs[i].value.type == jbvBinary &&
				fields[i].size > max_key_size &&
				fields[i].status != 't' && /* FIXME inline */
				(pass != 1 ||
				 (fields[i].status != 'c' || fields[i].size >= max_size)))
			{
				max_key_idx = i;
				max_key_size = fields[i].size;
			}
		}

		if (max_key_idx < 0 ||
			max_key_size <= offsetof(JsonbToastedContainerPointer, data) + TOAST_POINTER_SIZE)
		{
			if (pass == 1)
			{
				pass = 2;
				continue;
			}

			goto exit;	/* FIXME */
		}

		total_size -= INTALIGN(max_key_size + 3);
		jc = fields[max_key_idx].value;

		if (fields[max_key_idx].status == 'c')
		{
			compressed_val = PointerGetDatum(fields[max_key_idx].value);
		}
		else
		{
			if (jsonb_toast_fields_recursively &&
				total_size < max_size)
			{
				JsonValue	jv;

				if (JsonContainerIsObject(jc) &&
					jsonb_toaster_save_object(rel, jc, /* XXX uniquified,*/ max_size - total_size, cmethod, &jv))
				{
					pairs[max_key_idx].value = jv;
					break;
				}
			}

			jbc = jc->ops == &jsonbzContainerOps || jc->ops == &jsonxzContainerOps ?
				jsonxzDecompress(jc) : JsonContainerDataPtr(jc);

			val = PointerGetDatum(palloc(max_key_size + sizeof(struct varlena)));
			memcpy(VARDATA(val), jbc, max_key_size);
			SET_VARSIZE(val, max_key_size + sizeof(struct varlena));

			compressed_val = toast_compress_datum(val, cmethod);

			if (compressed_val == (Datum) 0)
				compressed_val = val;
			else if (jsonb_compress_fields &&
					 pass == 1 &&
					 VARSIZE_ANY(compressed_val) + min_values_length < max_size)
				//total_size + INTALIGN(offsetof(JsonbToastedContainerPointer, data) + VARSIZE_ANY(compressed_val) + 3) <= max_size)
			{
				Assert(fields[max_key_idx].status != 'c');

				fields[max_key_idx].value = DatumGetPointer(compressed_val);
				fields[max_key_idx].size = offsetof(JsonbToastedContainerPointer, data) + VARSIZE_ANY(compressed_val);
				fields[max_key_idx].status = 'c';

				pairs[max_key_idx].value.val.binary.data = jsonxzInitContainerFromDatum(jc, compressed_val);

				pfree(DatumGetPointer(val));
				total_size += INTALIGN(fields[max_key_idx].size + 3);

				continue;
			}
		}

		toasted_val = toast_save_datum(rel, compressed_val, NULL, 0);

		if (fields[max_key_idx].status != 'c' &&	/* FIXME free compressed at pass 1 */
			compressed_val != val)
			pfree(DatumGetPointer(compressed_val));

		Assert(VARSIZE_ANY(toasted_val) == TOAST_POINTER_SIZE);

		fields[max_key_idx].size = offsetof(JsonbToastedContainerPointer, data) + TOAST_POINTER_SIZE;
		fields[max_key_idx].status = 't';
		pairs[max_key_idx].value.val.binary.data = jsonxzInitContainerFromDatum(jc, toasted_val);

		if (DatumGetPointer(val))
			pfree(DatumGetPointer(val));

		total_size += INTALIGN(fields[max_key_idx].size + 3);
	}

	res = true;

exit:
	pfree(fields);
	if (!res)
		pfree(pairs);

	return res;
}

static Datum
jsonb_toaster_save(Relation rel, Oid toasterid, Json *js,
				   int max_size, char cmethod)
{
	JsonContainer *root = JsonRoot(js);
	JsonValue	object;
	Datum		jb = (Datum) 0;

	if (!jsonb_toast_fields || max_size <= 0)
		return (Datum) 0;

	if (!JsonContainerIsObject(root))
		return (Datum) 0;

	if (!jsonb_toaster_save_object(rel, root, /* XXX JsonIsUniquified(js), */
								   max_size, cmethod, &object))
		return (Datum) 0;

	jb = PointerGetDatum(JsonValueFlatten(&object, JsonxEncode,
										  &jsonxContainerOps,
										  (void *)(intptr_t) toasterid));

	pfree(object.val.object.pairs);

	return jb;
}

static uint32
JsonbIteratorGetCurOffset(jsonbIterator *it)
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
JsonbIteratorGetValuePtr(jsonbIterator *it, uint32 offset)
{
	return it->dataProper + offset;
}

static Datum
jsonb_toaster_copy(Relation rel, JsonContainer *jc, char cmethod);

static void
jsonb_toaster_copy_recursive(Relation rel, JsonContainer *jc, char cmethod);

static bool
jsonb_toaster_replace_toasted(Relation rel, JsonValue *jsv,
							  jsonbIterator *it, uint32 offset, char cmethod)
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
		Assert(VARSIZE_ANY(toasted) == TOAST_POINTER_SIZE);

		jbcptr = JsonbIteratorGetValuePtr(it, offset);

		memcpy(&jbcptr->data, DatumGetPointer(toasted), VARSIZE_ANY(toasted));

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
		 offset = it ? JsonbIteratorGetCurOffset((jsonbIterator *) it) : 0)
	{
		if (tok != WJB_VALUE && tok != WJB_ELEM)
			continue;

		jsonb_toaster_replace_toasted(rel, &jsv, (jsonbIterator *) it, offset, cmethod);
	}
}

static struct varlena *
jsonb_toaster_make_pointer(Oid toasterid, JsonbContainerHeader *jbc, int len)
{
	Size		hdrsize = VARATT_CUSTOM_SIZE(0);
	Size		aligned_hdrsize = INTALIGN(hdrsize);
	Size		size = aligned_hdrsize + VARHDRSZ + len;
	struct varlena *result = palloc(size);

	SET_VARTAG_EXTERNAL(result, VARTAG_CUSTOM);

	VARATT_CUSTOM_SET_TOASTERID(result, toasterid);
	VARATT_CUSTOM_SET_DATA_RAW_SIZE(result, len + VARHDRSZ);
	VARATT_CUSTOM_SET_DATA_SIZE(result, size - hdrsize);

	memset((char *) result + hdrsize, 0, aligned_hdrsize - hdrsize);
	memcpy((char *) result + aligned_hdrsize + VARHDRSZ, jbc, len);
	SET_VARSIZE((char *) result + aligned_hdrsize, VARHDRSZ + len);

	return result;
}

static Datum
jsonb_toaster_copy(Relation rel, JsonContainer *jc, char cmethod)
{
	JsonbContainerHeader *jbc;
	void	   *jb;

	if (!JsonContainerIsToasted(jc, NULL) &&
		!JsonContainerContainsToasted(jc))
		return (Datum) 0;

	jbc = jc->ops == &jsonbzContainerOps || jc->ops == &jsonxzContainerOps ?
		jsonxzDecompress(jc) : JsonContainerDataPtr(jc);

	if (jc->ops == &jsonxContainerOps)
	{
		jb = jsonb_toaster_make_pointer(jc->toasterid, jbc, jc->len);

		if (JsonContainerContainsToasted(jc))
		{
			//Json	   *js = DatumGetJson(PointerGetDatum(jb), &jsonxContainerOps, NULL);
			Json		jsbuf;
			Json	   *js = JsonExpand(&jsbuf, PointerGetDatum(jb), false, &jsonxContainerOps);

			jsonxInit(JsonRoot(js), PointerGetDatum(jb));

			jsonb_toaster_copy_recursive(rel, JsonRoot(js), cmethod);
		}
	}
	else
	{
		jb = palloc(VARHDRSZ + jc->len);
		memcpy(VARDATA(jb), jbc, jc->len);
		SET_VARSIZE(jb, VARHDRSZ + jc->len);

		Assert(!JsonContainerContainsToasted(jc));
	}

	return PointerGetDatum(jb);
}

static void
jsonb_toaster_delete_container(Relation rel, JsonContainer *jc)
{
	JsonbToastedContainerPointerData jbcptr;

	if (JsonContainerIsToasted(jc, &jbcptr))
	{
		struct varlena *ptr = jsonxMakeToastPointer(&jbcptr);

		toast_delete_datum(PointerGetDatum(ptr), false);
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
	JsonbToastedContainerPointerData new_jbcptr;
	JsonbToastedContainerPointerData old_jbcptr;
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
			uint32		offset = JsonbIteratorGetCurOffset((jsonbIterator *) new_it);

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
							memcmp(&new_jbcptr.ptr, &old_jbcptr.ptr, sizeof(new_jbcptr.ptr)))
						{
							changed |= jsonb_toaster_replace_toasted(rel, &new_jbv, (jsonbIterator *) new_it, offset, cmethod);
							jsonb_toaster_delete_recursive(rel, oldjc, true);
						}
					}
					else if (newjc->type != oldjc->type ||
							 newjc->type != jbvObject)
					{
						changed |= jsonb_toaster_replace_toasted(rel, &new_jbv, (jsonbIterator *) new_it, offset, cmethod);
						jsonb_toaster_delete_recursive(rel, oldjc, true);
					}
					else if (!JsonContainerContainsToasted(newjc))
					{
						jsonb_toaster_delete_recursive(rel, oldjc, false);
					}
					else if (!JsonContainerContainsToasted(oldjc))
						changed |= jsonb_toaster_replace_toasted(rel, &new_jbv, (jsonbIterator *) new_it, offset, cmethod);
					else
						changed |= jsonb_toaster_cmp_recursive(rel, oldjc, newjc, cmethod);
				}
				else
				{
					changed |=
						jsonb_toaster_replace_toasted(rel, &new_jbv,
													  (jsonbIterator *) new_it,
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
			uint32		offset = JsonbIteratorGetCurOffset((jsonbIterator *) new_it);

			if (JsonIteratorNext(&new_it, &new_jbv, true) != WJB_VALUE)
				break;

			changed |= jsonb_toaster_replace_toasted(rel, &new_jbv, (jsonbIterator *) new_it, offset, cmethod);

			new_end = JsonIteratorNext(&new_it, &new_jbv, true) != WJB_KEY;
		}
	}

	return changed;
}

static Datum
jsonb_toaster_cmp(Relation rel, JsonContainer *new_jc, JsonContainer *old_jc, char cmethod)
{
	JsonbToastedContainerPointerData new_jbcptr;
	JsonbToastedContainerPointerData old_jbcptr;
	Datum		res;
	void	   *jb;
	JsonbContainerHeader *new_jbc;
	bool		changed = false;

	if (JsonContainerIsToasted(new_jc, &new_jbcptr))
	{
		if (JsonContainerIsToasted(old_jc, &old_jbcptr) &&
			!memcmp(&new_jbcptr.ptr, &old_jbcptr.ptr, sizeof(new_jbcptr.ptr)))
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

	new_jbc =
		new_jc->ops == &jsonbzContainerOps ||
		new_jc->ops == &jsonxzContainerOps ?
		jsonxzDecompress(new_jc) : JsonContainerDataPtr(new_jc);

	jb = jsonb_toaster_make_pointer(new_jc->toasterid, new_jbc, new_jc->len);

#if 0
	jb = palloc(sizeof(VARHDRSZ) + new_jc->len);
	memcpy(VARDATA(jb), new_jbc, new_jc->len);
	SET_VARSIZE(jb, sizeof(VARHDRSZ) + new_jc->len);
#endif
	{
		//Json	   *js = DatumGetJson(PointerGetDatum(jb), &jsonxContainerOps, NULL);
		Json		jsbuf;
		Json	   *js = JsonExpand(&jsbuf, PointerGetDatum(jb), false, &jsonxContainerOps);

		jsonxInit(JsonRoot(js), PointerGetDatum(jb));

		changed = jsonb_toaster_cmp_recursive(rel, old_jc, JsonRoot(js), cmethod);
	}

	return PointerGetDatum(changed ? jb : NULL);
}

typedef JsonbDatum JsonbToastData;

static bool
jsonb_toaster_validate(Oid typeoid, char storage, char compression,
					   Oid amoid, bool false_ok)
{
	bool		ok = typeoid == JSONBOID; /* && storage == TYPSTORAGE_EXTERNAL */

	return ok;
}

static struct varlena *
jsonb_toaster_toast(Relation rel, Oid toasterid,
					Datum new_val, Datum old_val,
					int max_inline_size, int options)
{

	Json	   *new_js;
	Datum		res;
	char		cmethod = TOAST_PGLZ_COMPRESSION;

	jsonbInitIterators();

	new_js = DatumGetJsonbPC(new_val, NULL /* FIXME alloca */, false);

	res = jsonb_toaster_save(rel, toasterid, new_js, max_inline_size, cmethod);

	if (res == (Datum) 0)
	{
		Datum compressed_val = (Datum) 0;

		if (!VARATT_IS_COMPRESSED(new_val))
			compressed_val = toast_compress_datum(new_val, cmethod);

		if (compressed_val == (Datum) 0)
			compressed_val = new_val;

		res = jsonx_toast_save_datum_ext(rel, toasterid, compressed_val, NULL, options, NULL, false);
	}

	res = res == (Datum) 0 ? new_val : res;

	jsonbFreeIterators();

	return (struct varlena *) DatumGetPointer(res);
}

static struct varlena *
jsonb_toaster_update_toast(Relation rel, Oid toasterid,
						   Datum new_val, Datum old_val,
						   int options)
{
	Json	   *new_js;
	Json	   *old_js;
	Datum		res;
	char		cmethod = TOAST_PGLZ_COMPRESSION;

	jsonbInitIterators();

	new_js = DatumGetJsonbPC(new_val, NULL, false);
	old_js = DatumGetJsonbPC(old_val, NULL, false);
	res = jsonb_toaster_cmp(rel, JsonRoot(new_js), JsonRoot(old_js), cmethod);

	jsonbFreeIterators();

	return (struct varlena *) DatumGetPointer(res);
}

static struct varlena *
jsonb_toaster_copy_toast(Relation rel, Oid toasterid,
						 Datum new_val, int options)
{
	Json	   *new_js;
	Datum		res;
	char		cmethod = TOAST_PGLZ_COMPRESSION;

	jsonbInitIterators();

	new_js = DatumGetJsonbPC(new_val, NULL, false);
	res = jsonb_toaster_copy(rel, JsonRoot(new_js), cmethod);

	jsonbFreeIterators();

	return (struct varlena *) DatumGetPointer(res);
}

static void
jsonb_toaster_delete_toast(Datum val, bool is_speculative)
{
	Json	   *js;

	jsonbInitIterators();

	js = DatumGetJsonbPC(val, NULL, false);
	jsonb_toaster_delete_recursive(NULL /* XXX rel */, JsonRoot(js), false);

	jsonbFreeIterators();
}

static struct varlena *
jsonb_toaster_detoast(Datum toastptr, int sliceoffset, int slicelength)
{
	struct varlena *result;
	Json		jsbuf;
	Json	   *js;
	JsonValue	bin;
	void	   *detoasted;
	int			len;

	Assert(VARATT_IS_CUSTOM(toastptr));

	jsonbInitIterators();

	//js = DatumGetJson(toastptr, &jsonxContainerOps, &jsbuf);
	js = JsonExpand(NULL /* FIXME &jsbuf */, toastptr, false, &jsonxContainerOps);
	jsonxInit(JsonRoot(js), toastptr);

	JsonValueInitBinary(&bin, JsonRoot(js));
	detoasted = JsonEncode(&bin, JsonbEncode, NULL);
	len = VARSIZE_ANY_EXHDR(detoasted);

	jsonbFreeIterators();

	if (sliceoffset == 0 && (slicelength < 0 || slicelength >= len))
		return detoasted;

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

	return result;
}

static void *
jsonb_toaster_vtable(Datum toast_ptr)
{
	JsonToastRoutine *routine = palloc0(sizeof(*routine));

	routine->magic = JSON_TOASTER_MAGIC;
	routine->ops = &jsonxContainerOps;

	return routine;
}

static void
jsonb_toaster_init(Relation rel, Datum reloptions, LOCKMODE lockmode,
				   bool check, Oid OIDOldToast)
{
	(void) create_toast_table(rel, InvalidOid, InvalidOid, reloptions,
							  lockmode, check, OIDOldToast);
}

PG_FUNCTION_INFO_V1(jsonb_toaster_handler);
Datum
jsonb_toaster_handler(PG_FUNCTION_ARGS)
{
	TsrRoutine *tsr = makeNode(TsrRoutine);

	tsr->init = jsonb_toaster_init;
	tsr->toast = jsonb_toaster_toast;
	tsr->deltoast = jsonb_toaster_delete_toast;
	tsr->copy_toast = jsonb_toaster_copy_toast;
	tsr->update_toast = jsonb_toaster_update_toast;
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

	DefineCustomBoolVariable("jsonb_toaster.toast_fields_recursively",
							 "Recursively TOAST jsonb fields.",
							 NULL,
							 &jsonb_toast_fields_recursively,
							 true,
							 PGC_USERSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	DefineCustomBoolVariable("jsonb_toaster.compress_fields",
							 "Compress jsonb fields.",
							 NULL,
							 &jsonb_compress_fields,
							 true,
							 PGC_USERSET,
							 0,
							 NULL,
							 NULL,
							 NULL);
}
