/*-------------------------------------------------------------------------
 *
 * jsonb_typanalyze.c
 *	  Functions for gathering statistics from jsonb columns
 *
 * Copyright (c) 2016-2022, PostgreSQL Global Development Group
 *
 * Functions in this module are used to analyze contents of JSONB columns
 * and build optimizer statistics. In principle we extract paths from all
 * sampled documents and calculate the usual statistics (MCV, histogram)
 * for each path - in principle each path is treated as a column.
 *
 * Because we're not enforcing any JSON schema, the documents may differ
 * a lot - the documents may contain large number of different keys, the
 * types of values may be entirely different, etc. This makes it more
 * challenging than building stats for regular columns. For example not
 * only do we need to decide which values to keep in the MCV, but also
 * which paths to keep (in case the documents are so variable we can't
 * keep all paths).
 *
 * The statistics is stored in pg_statistic, in a slot with a new stakind
 * value (STATISTIC_KIND_JSON). The statistics is serialized as an array
 * of JSONB values, eash element storing statistics for one path.
 *
 * For each path, we store the following keys:
 *
 * - path         - path this stats is for, serialized as jsonpath
 * - freq         - frequency of documents containing this path
 * - json         - the regular per-column stats (MCV, histogram, ...)
 * - freq_null    - frequency of JSON null values
 * - freq_array   - frequency of JSON array values
 * - freq_object  - frequency of JSON object values
 * - freq_string  - frequency of JSON string values
 * - freq_numeric - frequency of JSON numeric values
 *
 * This is stored in the stavalues array.
 *
 * The first element of stavalues is a path prefix.  It is used for avoiding
 * path transformations when the derived statistics for the chains of ->
 * operators is computed.
 *
 * The per-column stats (stored in the "json" key) have additional internal
 * structure, to allow storing multiple stakind types (histogram, mcv). See
 * jsonAnalyzeMakeScalarStats for details.
 *
 *
 * XXX It's a bit weird the "regular" stats are stored in the "json" key,
 * while the JSON stats (frequencies of different JSON types) are right
 * at the top level.
 *
 *
 * IDENTIFICATION
 *	  src/backend/utils/adt/jsonb_typanalyze.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "fmgr.h"
#include "access/hash.h"
#include "access/detoast.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_type.h"
#include "commands/vacuum.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/hsearch.h"
#include "utils/json.h"
#include "utils/jsonb.h"
#include "utils/json_selfuncs.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"

typedef struct JsonPathEntry JsonPathEntry;

/*
 * Element of a path in the JSON document (i.e. not jsonpath). Elements
 * are linked together to build longer paths.
 *
 * 'entry' can be not zero-terminated when it is pointing to JSONB keys, so
 * 'len' is necessary.  'len' is also used for faster entry comparison, to
 * distinguish array entries ('len' == -1).
 */
typedef struct JsonPathEntry
{
	JsonPathEntry  *parent;
	const char	   *entry;		/* element of the path as a string */
	int				len;		/* length of entry string (may be 0 or -1) */
	uint32			hash;		/* hash of the whole path (with parent) */
	char	   *pathstr;		/* full path string */
	int			depth;			/* nesting level, i.e. path length */
} JsonPathEntry;

#define JsonPathEntryIsArray(entry) ((entry)->len == -1)

/*
 * An array containing a dynamic number of values extracted from JSON documents.
 * All values should have the same data type:
 *		jsonb   - ordinary path stats, values of different JSON types
 *		int32   - array/object length stats
 *		text    - separate stats fro strings
 *		numeric - separate stats fro numbers
 */
typedef struct JsonValues
{
	Datum	   *buf;
	int			count;
	int			allocated;
} JsonValues;

/*
 * Scalar statistics built for an array of values, extracted from a JSON
 * document (for one particular path).
 */
typedef struct JsonScalarStats
{
	JsonValues		values;
	VacAttrStats	stats;
} JsonScalarStats;

/*
 * Statistics calculated for a set of values.
 *
 *
 * XXX This seems rather complicated and needs simplification. We're not
 * really using all the various JsonScalarStats bits, there's a lot of
 * duplication (e.g. each JsonScalarStats contains it's own array, which
 * has a copy of data from the one in "jsons").
 */
typedef struct JsonValueStats
{
	JsonScalarStats	jsons;		/* stats for all JSON types together */

#ifdef JSON_ANALYZE_SCALARS		/* XXX */
	JsonScalarStats	strings;	/* stats for JSON strings */
	JsonScalarStats	numerics;	/* stats for JSON numerics */
#endif

	JsonScalarStats	arrlens;	/* stats of array lengths */
	JsonScalarStats	objlens;	/* stats of object lengths */

	int				nnulls;		/* number of JSON null values */
	int				ntrue;		/* number of JSON true values */
	int				nfalse;		/* number of JSON false values */
	int				nobjects;	/* number of JSON objects */
	int				narrays;	/* number of JSON arrays */
	int				nstrings;	/* number of JSON strings */
	int				nnumerics;	/* number of JSON numerics */

	int64			narrelems;	/* total number of array elements
								 * (for avg. array length) */
} JsonValueStats;

typedef struct JsonPathDocBitmap
{
	bool		is_list;
	int			size;
	int			allocated;
	union
	{
		int32	   *list;
		uint8	   *bitmap;
	}			data;
} JsonPathDocBitmap;

/* JSON path and list of documents containing it */
typedef struct JsonPathAnlDocs
{
	JsonPathEntry path;
	JsonPathDocBitmap bitmap;
} JsonPathAnlDocs;

/* Main structure for analyzed JSON path  */
typedef struct JsonPathAnlStats
{
	JsonPathEntry path;
	double		freq;		/* frequence of the path */
	JsonValueStats vstats;	/* collected values and raw computed stats */
	Jsonb	   *stats;		/* stats converted into jsonb form */
} JsonPathAnlStats;

/* Some parent path stats counters that used for frequency calculations */
typedef struct JsonPathParentStats
{
	double		freq;
	int			count;
	int			narrays;
} JsonPathParentStats;

/* various bits needed while analyzing JSON */
typedef struct JsonAnalyzeContext
{
	VacAttrStats		   *stats;
	MemoryContext			mcxt;
	AnalyzeAttrFetchFunc	fetchfunc;
	HTAB				   *pathshash;
	JsonPathAnlStats	   *root;
	double					totalrows;
	double					total_width;
	int						samplerows;
	int						current_rownum;
	int						target;
	int						null_cnt;
	int						analyzed_cnt;
	int						maxdepth;
	bool					scalarsOnly;
	bool					single_pass;
} JsonAnalyzeContext;

/*
 * JsonPathMatch
 *		Determine when two JSON paths (list of JsonPathEntry) match.
 *
 * Returned int instead of bool, because it is an implementation of
 * HashCompareFunc.
 */
static int
JsonPathEntryMatch(const void *key1, const void *key2, Size keysize)
{
	const JsonPathEntry *path1 = key1;
	const JsonPathEntry *path2 = key2;

	return path1->parent != path2->parent ||
		   path1->len != path2->len ||
		   (path1->len > 0 &&
			strncmp(path1->entry, path2->entry, path1->len));
}

/*
 * JsonPathHash
 *		Calculate hash of the path entry.
 *
 * Parent hash should be already calculated.
 */
static uint32
JsonPathEntryHash(const void *key, Size keysize)
{
	const JsonPathEntry	   *path = key;
	uint32					hash = path->parent ? path->parent->hash : 0;

	hash = (hash << 1) | (hash >> 31);
	hash ^= path->len < 0 ? 0 :
		DatumGetUInt32(hash_any((const unsigned char *) path->entry, path->len));

	return hash;
}

static void
jsonStatsBitmapInit(JsonPathDocBitmap *bitmap)
{
	memset(bitmap, 0, sizeof(*bitmap));
	bitmap->is_list = true;
}

static void
jsonStatsBitmapAdd(JsonAnalyzeContext *cxt, JsonPathDocBitmap *bitmap, int doc)
{
	/* Use more compact list representation if not too many bits set */
	if (bitmap->is_list)
	{
		int		   *list = bitmap->data.list;

#if 1	/* Enable list representation */
		if (bitmap->size > 0 && list[bitmap->size - 1] == doc)
			return;

		if (bitmap->size < cxt->samplerows / sizeof(list[0]) / 8)
		{
			if (bitmap->size >= bitmap->allocated)
			{
				MemoryContext oldcxt = MemoryContextSwitchTo(cxt->mcxt);

				if (bitmap->allocated)
				{
					bitmap->allocated *= 2;
					list = repalloc(list, sizeof(list[0]) * bitmap->allocated);
				}
				else
				{
					bitmap->allocated = 8;
					list = palloc(sizeof(list[0]) * bitmap->allocated);
				}

				bitmap->data.list = list;

				MemoryContextSwitchTo(oldcxt);
			}

			list[bitmap->size++] = doc;
			return;
		}
#endif
		/* convert list to bitmap */
		bitmap->allocated = (cxt->samplerows + 7) / 8;
		bitmap->data.bitmap = MemoryContextAllocZero(cxt->mcxt, bitmap->allocated);
		bitmap->is_list = false;

		if (list)
		{
			for (int i = 0; i < bitmap->size; i++)
			{
				int			d = list[i];

				bitmap->data.bitmap[d / 8] |= (1 << (d % 8));
			}

			pfree(list);
		}
	}

	/* set bit in bitmap */
	if (doc < cxt->samplerows &&
		!(bitmap->data.bitmap[doc / 8] & (1 << (doc % 8))))
	{
		bitmap->data.bitmap[doc / 8] |= (1 << (doc % 8));
		bitmap->size++;
	}
}

static bool
jsonStatsBitmapNext(JsonPathDocBitmap *bitmap, int *pbit)
{
	uint8	   *bmp = bitmap->data.bitmap;
	uint8	   *pb;
	uint8	   *pb_end = &bmp[bitmap->allocated];
	int			bit = *pbit;

	Assert(!bitmap->is_list);

	if (bit < 0)
	{
		pb = bmp;
		bit = 0;
	}
	else
	{
		++bit;
		pb = &bmp[bit / 8];
		bit %= 8;
	}

	for (; pb < pb_end; pb++, bit = 0)
	{
		uint8		b;

		/* Skip zero bytes */
		if (!bit)
		{
			while (!*pb)
			{
				if (++pb >= pb_end)
					return false;
			}
		}

		b = *pb;

		/* Skip zero bits */
		while (bit < 8 && !(b & (1 << bit)))
			bit++;

		if (bit >= 8)
			continue;	/* Non-zero bit not found, go to next byte */

		/* Output next non-zero bit */
		*pbit = (pb - bmp) * 8 + bit;
		return true;
	}

	return false;
}

static void
jsonStatsAnlInit(JsonPathAnlStats *stats)
{
	/* initialize the stats counter for this path entry */
	memset(&stats->vstats, 0, sizeof(JsonValueStats));
	stats->stats = NULL;
	stats->freq = 0.0;
}

/*
 * jsonAnalyzeAddPath
 *		Add an entry for a JSON path to the working list of statistics.
 *
 * Returns a pointer to JsonPathAnlStats (which might have already existed
 * if the path was in earlier document), which can then be populated or
 * updated.
 */
static inline JsonPathEntry *
jsonAnalyzeAddPath(JsonAnalyzeContext *ctx, JsonPathEntry *parent,
				   const char *entry, int len)
{
	JsonPathEntry path;
	JsonPathEntry *stats;
	bool		found;

	/* Init path entry */
	path.parent = parent;
	path.entry = entry;
	path.len = len;
	path.hash = JsonPathEntryHash(&path, 0);

	/* See if we already saw this path earlier. */
	stats = hash_search_with_hash_value(ctx->pathshash, &path, path.hash,
										HASH_ENTER, &found);

	/*
	 * Nope, it's the first time we see this path, so initialize all the
	 * fields (path string, counters, ...).
	 */
	if (!found)
	{
		JsonPathEntry *parent = stats->parent;
		const char *ppath = parent->pathstr;
		StringInfoData si;
		MemoryContext oldcxt;

		oldcxt = MemoryContextSwitchTo(ctx->mcxt);

		/* NULL entries are treated as wildcard array accessors "[*]" */
		if (stats->entry)
			/* Copy path entry name into the right MemoryContext */
			stats->entry = pnstrdup(stats->entry, stats->len);

		MemoryContextSwitchTo(oldcxt);

		/* Initialze full path string */
		initStringInfo(&si);
		appendStringInfoString(&si, ppath);
		jsonPathAppendEntry(&si, stats->entry);

		MemoryContextSwitchTo(ctx->mcxt);
		stats->pathstr = pstrdup(si.data);
		MemoryContextSwitchTo(oldcxt);

		pfree(si.data);

		if (ctx->single_pass)
			jsonStatsAnlInit((JsonPathAnlStats *) stats);
		else
			jsonStatsBitmapInit(&((JsonPathAnlDocs *) stats)->bitmap);

		stats->depth = parent->depth + 1;

		/* update maximal depth */
		if (ctx->maxdepth < stats->depth)
			ctx->maxdepth = stats->depth;
	}

	return stats;
}

/*
 * JsonValuesAppend
 *		Add a JSON value to the dynamic array (enlarge it if needed).
 *
 * XXX This is likely one of the problems - the documents may be pretty
 * large, with a lot of different values for each path. At that point
 * it's problematic to keep all of that in memory at once. So maybe we
 * need to introduce some sort of compaction (e.g. we could try
 * deduplicating the values), limit on size of the array or something.
 */
static inline void
JsonValuesAppend(JsonValues *values, Datum value, int initialSize)
{
	if (values->count >= values->allocated)
	{
		if (values->allocated)
		{
			values->allocated = values->allocated * 2;
			values->buf = repalloc(values->buf,
									sizeof(values->buf[0]) * values->allocated);
		}
		else
		{
			values->allocated = initialSize;
			values->buf = palloc(sizeof(values->buf[0]) * values->allocated);
		}
	}

	values->buf[values->count++] = value;
}

/*
 * jsonAnalyzeJsonValue
 *		Process a value extracted from the document (for a given path).
 */
static inline void
jsonAnalyzeJsonValue(JsonAnalyzeContext *ctx, JsonValueStats *vstats,
					 JsonbValue *jv)
{
	JsonbValue *jbv;
	JsonbValue	jbvtmp;
	Jsonb	   *jb;
	Datum		value;
	MemoryContext oldcxt = NULL;

	/* XXX if analyzing only scalar values, make containers empty */
	if (ctx->scalarsOnly && jv->type == jbvBinary)
	{
		if (JsonContainerIsObject(jv->val.binary.data))
			jbv = JsonValueInitObject(&jbvtmp, 0, 0);
		else
		{
			Assert(JsonContainerIsArray(jv->val.binary.data));
			jbv = JsonValueInitArray(&jbvtmp, 0, 0, false);
		}
	}
	else
		jbv = jv;

	jb = JsonbValueToJsonb(jbv);

	if (ctx->single_pass)
	{
		oldcxt = MemoryContextSwitchTo(ctx->stats->anl_context);
		jb = memcpy(palloc(VARSIZE(jb)), jb, VARSIZE(jb));
	}

	/* always add it to the "global" JSON stats, shared by all types */
	JsonValuesAppend(&vstats->jsons.values,
					 JsonbPGetDatum(jb),
					 ctx->target);

	/* also update the type-specific counters */
	switch (jv->type)
	{
		case jbvNull:
			vstats->nnulls++;
			break;

		case jbvBool:
			if (jv->val.boolean)
				vstats->ntrue++;
			else
				vstats->nfalse++;
			break;

		case jbvString:
			vstats->nstrings++;
#ifdef JSON_ANALYZE_SCALARS
			value = PointerGetDatum(
						cstring_to_text_with_len(jv->val.string.val,
												 jv->val.string.len));
			JsonValuesAppend(&vstats->strings.values, value, ctx->target);
#endif
			break;

		case jbvNumeric:
			vstats->nnumerics++;
#ifdef JSON_ANALYZE_SCALARS
			value = PointerGetDatum(jv->val.numeric);
			JsonValuesAppend(&vstats->numerics.values, value, ctx->target);
#endif
			break;

		case jbvBinary:
			if (JsonContainerIsObject(jv->val.binary.data))
			{
				uint32		size = JsonContainerSize(jv->val.binary.data);

				value = DatumGetInt32(size);
				vstats->nobjects++;
				JsonValuesAppend(&vstats->objlens.values, value, ctx->target);
			}
			else if (JsonContainerIsArray(jv->val.binary.data))
			{
				uint32		size = JsonContainerSize(jv->val.binary.data);

				value = DatumGetInt32(size);
				vstats->narrays++;
				JsonValuesAppend(&vstats->arrlens.values, value, ctx->target);
				vstats->narrelems += size;
			}
			break;

		default:
			elog(ERROR, "invalid scalar json value type %d", jv->type);
			break;
	}

	if (ctx->single_pass)
		MemoryContextSwitchTo(oldcxt);
}

/*
 * jsonAnalyzeCollectPaths
 *		Parse the JSON document and collect all paths and their values.
 */
static void
jsonAnalyzeCollectPaths(JsonAnalyzeContext *ctx, Jsonb *jb, void *param)
{
	JsonbValue			jv;
	JsonbIterator	   *it;
	JsonbIteratorToken	tok;
	JsonPathEntry	   *stats = &ctx->root->path;
	int					doc = ctx->current_rownum;
	bool				collect_values = (bool)(intptr_t) param;
	bool				scalar = false;

	if (collect_values && !JB_ROOT_IS_SCALAR(jb))
		jsonAnalyzeJsonValue(ctx, &((JsonPathAnlStats *) stats)->vstats,
							 JsonValueInitBinary(&jv, jb));

	it = JsonbIteratorInit(&jb->root);

	while ((tok = JsonbIteratorNext(&it, &jv, true)) != WJB_DONE)
	{
		switch (tok)
		{
			case WJB_BEGIN_OBJECT:
				/*
				 * Read next token to see if the object is empty or not.
				 * If not, make stats for the first key.  Subsequent WJB_KEYs
				 * and WJB_END_OBJECT will expect that stats will be pointing
				 * to the key of current object.
				 */
				tok = JsonbIteratorNext(&it, &jv, true);

				if (tok == WJB_END_OBJECT)
					/* Empty object, simply skip stats initialization. */
					break;

				if (tok != WJB_KEY)
					elog(ERROR, "unexpected jsonb iterator token: %d", tok);

				stats = jsonAnalyzeAddPath(ctx, stats,
										   jv.val.string.val,
										   jv.val.string.len);
				break;

			case WJB_BEGIN_ARRAY:
				/* Make stats for non-scalar array and use it for all elements */
				if (!(scalar = jv.val.array.rawScalar))
					stats = jsonAnalyzeAddPath(ctx, stats, NULL, -1);
				break;

			case WJB_END_ARRAY:
				if (scalar)
					break;
				/* FALLTHROUGH */
			case WJB_END_OBJECT:
				/* Reset to parent stats */
				stats = stats->parent;
				break;

			case WJB_KEY:
				/*
				 * Stats should point to the previous key of current object,
				 * use its parent path as a base path.
				 */
				stats = jsonAnalyzeAddPath(ctx, stats->parent,
										   jv.val.string.val,
										   jv.val.string.len);
				break;

			case WJB_VALUE:
			case WJB_ELEM:
				if (collect_values)
					jsonAnalyzeJsonValue(ctx,
										 &((JsonPathAnlStats *) stats)->vstats,
										 &jv);
				else if (stats != &ctx->root->path)
					jsonStatsBitmapAdd(ctx,
									   &((JsonPathAnlDocs *) stats)->bitmap,
									   doc);

				/*
				 * Manually recurse into container by creating child iterator.
				 * We use skipNested=true to give jsonAnalyzeJsonValue()
				 * ability to access jbvBinary containers.
				 */
				if (jv.type == jbvBinary)
				{
					JsonbIterator *it2 = JsonbIteratorInit(jv.val.binary.data);

					it2->parent = it;
					it = it2;
				}
				break;

			default:
				break;
		}
	}
}

/*
 * jsonAnalyzeCollectSubpath
 *		Recursively extract trailing part of a path and collect its values.
 */
static void
jsonAnalyzeCollectSubpath(JsonAnalyzeContext *ctx, JsonPathAnlStats *pstats,
						  JsonbValue *jbv, JsonPathEntry **entries,
						  int start_entry)
{
	JsonbValue	scalar;
	int			i;

	for (i = start_entry; i < pstats->path.depth; i++)
	{
		JsonPathEntry  *entry = entries[i];
		JsonbContainer *jbc = jbv->val.binary.data;
		JsonbValueType	type = jbv->type;

		if (i > start_entry)
			pfree(jbv);

		if (type != jbvBinary)
			return;

		if (JsonPathEntryIsArray(entry))
		{
			JsonbIterator	   *it;
			JsonbIteratorToken	r;
			JsonbValue			elem;

			if (!JsonContainerIsArray(jbc) || JsonContainerIsScalar(jbc))
				return;

			it = JsonbIteratorInit(jbc);

			while ((r = JsonbIteratorNext(&it, &elem, true)) != WJB_DONE)
			{
				if (r == WJB_ELEM)
					jsonAnalyzeCollectSubpath(ctx, pstats, &elem, entries, i + 1);
			}

			return;
		}
		else
		{
			if (!JsonContainerIsObject(jbc))
				return;

			jbv = findJsonbValueFromContainerLen(jbc, JB_FOBJECT,
												 entry->entry, entry->len);

			if (!jbv)
				return;
		}
	}

	if (i == start_entry &&
		jbv->type == jbvBinary &&
		JsonbExtractScalar(jbv->val.binary.data, &scalar))
		jbv = &scalar;

	jsonAnalyzeJsonValue(ctx, &pstats->vstats, jbv);

	if (i > start_entry)
		pfree(jbv);
}

/*
 * jsonAnalyzeCollectPath
 *		Extract a single path from JSON documents and collect its values.
 */
static void
jsonAnalyzeCollectPath(JsonAnalyzeContext *ctx, Jsonb *jb, void *param)
{
	JsonPathAnlStats *pstats = (JsonPathAnlStats *) param;
	JsonbValue	jbvtmp;
	JsonbValue *jbv = JsonValueInitBinary(&jbvtmp, jb);
	JsonPathEntry *path;
	JsonPathEntry **entries;
	int			i;

	entries = palloc(sizeof(*entries) * pstats->path.depth);

	/* Build entry array in direct order */
	for (path = &pstats->path, i = pstats->path.depth - 1;
		 path->parent && i >= 0;
		 path = path->parent, i--)
		entries[i] = path;

	jsonAnalyzeCollectSubpath(ctx, pstats, jbv, entries, 0);

	pfree(entries);
}

static Datum
jsonAnalyzePathFetch(VacAttrStatsP stats, int rownum, bool *isnull)
{
	*isnull = false;
	return stats->exprvals[rownum];
}

/*
 * jsonAnalyzePathValues
 *		Calculate per-column statistics for values for a single path.
 *
 * We have already accumulated all the values for the path, so we simply
 * call the typanalyze function for the proper data type, and then
 * compute_stats (which points to compute_scalar_stats or so).
 */
static void
jsonAnalyzePathValues(JsonAnalyzeContext *ctx, JsonScalarStats *sstats,
					  Oid typid, double freq, bool use_anl_context)
{
	JsonValues			   *values = &sstats->values;
	VacAttrStats		   *stats = &sstats->stats;
	FormData_pg_attribute	attr;
	FormData_pg_type		type;
	int						i;

	if (!sstats->values.count)
		return;

	get_typlenbyvalalign(typid, &type.typlen, &type.typbyval, &type.typalign);

	attr.attstattarget = ctx->target;

	stats->attr = &attr;
	stats->attrtypid = typid;
	stats->attrtypmod = -1;
	stats->attrtype = &type;
	stats->anl_context = use_anl_context ? ctx->stats->anl_context : CurrentMemoryContext;

	stats->exprvals = values->buf;

	/*
	 * The fields describing the stats->stavalues[n] element types default to
	 * the type of the data being analyzed, but the type-specific typanalyze
	 * function can change them if it wants to store something else.
	 */
	for (i = 0; i < STATISTIC_NUM_SLOTS; i++)
	{
		stats->statypid[i] = stats->attrtypid;
		stats->statyplen[i] = stats->attrtype->typlen;
		stats->statypbyval[i] = stats->attrtype->typbyval;
		stats->statypalign[i] = stats->attrtype->typalign;
	}

	std_typanalyze(stats);

	stats->compute_stats(stats, jsonAnalyzePathFetch,
						 values->count,
						 ctx->totalrows / ctx->samplerows * values->count);

	/*
	 * We've only kept the non-null values, so compute_stats will always
	 * leave this as 1.0. But we have enough info to calculate the correct
	 * value.
	 */
	stats->stanullfrac = (float4)(1.0 - freq);

	/*
	 * Similarly, we need to correct the MCV frequencies, becuse those are
	 * also calculated only from the non-null values. All we need to do is
	 * simply multiply that with the non-NULL frequency.
	 */
	for (i = 0; i < STATISTIC_NUM_SLOTS; i++)
	{
		if (stats->stakind[i] == STATISTIC_KIND_MCV)
		{
			int j;
			for (j = 0; j < stats->numnumbers[i]; j++)
				stats->stanumbers[i][j] *= freq;
		}
	}
}

/*
 * jsonAnalyzeMakeScalarStats
 *		Serialize scalar stats into a JSON representation.
 *
 * We simply produce a JSON document with a list of predefined keys:
 *
 * - nullfrac
 * - distinct
 * - width
 * - correlation
 * - mcv or histogram
 *
 * For the mcv / histogram, we store a nested values / numbers.
 */
static JsonbValue *
jsonAnalyzeMakeScalarStats(JsonbParseState **ps, const char *name,
							const VacAttrStats *stats)
{
	JsonbValue	val;
	int			i;
	int			j;

	pushJsonbKey(ps, &val, name);

	pushJsonbValue(ps, WJB_BEGIN_OBJECT, NULL);

	pushJsonbKeyValueFloat(ps, &val, "nullfrac", stats->stanullfrac);
	pushJsonbKeyValueFloat(ps, &val, "distinct", stats->stadistinct);
	pushJsonbKeyValueInteger(ps, &val, "width", stats->stawidth);

	for (i = 0; i < STATISTIC_NUM_SLOTS; i++)
	{
		if (!stats->stakind[i])
			break;

		switch (stats->stakind[i])
		{
			case STATISTIC_KIND_MCV:
				pushJsonbKey(ps, &val, "mcv");
				break;

			case STATISTIC_KIND_HISTOGRAM:
				pushJsonbKey(ps, &val, "histogram");
				break;

			case STATISTIC_KIND_CORRELATION:
				pushJsonbKeyValueFloat(ps, &val, "correlation",
									   stats->stanumbers[i][0]);
				continue;

			default:
				elog(ERROR, "unexpected stakind %d", stats->stakind[i]);
				break;
		}

		pushJsonbValue(ps, WJB_BEGIN_OBJECT, NULL);

		if (stats->numvalues[i] > 0)
		{
			pushJsonbKey(ps, &val, "values");
			pushJsonbValue(ps, WJB_BEGIN_ARRAY, NULL);
			for (j = 0; j < stats->numvalues[i]; j++)
			{
				Datum v = stats->stavalues[i][j];
				if (stats->attrtypid == JSONBOID)
					pushJsonbElemBinary(ps, &val, DatumGetJsonbP(v));
				else if (stats->attrtypid == TEXTOID)
					pushJsonbElemText(ps, &val, DatumGetTextP(v));
				else if (stats->attrtypid == NUMERICOID)
					pushJsonbElemNumeric(ps, &val, DatumGetNumeric(v));
				else if (stats->attrtypid == INT4OID)
					pushJsonbElemInteger(ps, &val, DatumGetInt32(v));
				else
					elog(ERROR, "unexpected stat value type %d",
						 stats->attrtypid);
			}
			pushJsonbValue(ps, WJB_END_ARRAY, NULL);
		}

		if (stats->numnumbers[i] > 0)
		{
			pushJsonbKey(ps, &val, "numbers");
			pushJsonbValue(ps, WJB_BEGIN_ARRAY, NULL);
			for (j = 0; j < stats->numnumbers[i]; j++)
				pushJsonbElemFloat(ps, &val, stats->stanumbers[i][j]);
			pushJsonbValue(ps, WJB_END_ARRAY, NULL);
		}

		pushJsonbValue(ps, WJB_END_OBJECT, NULL);
	}

	return pushJsonbValue(ps, WJB_END_OBJECT, NULL);
}

static void
pushJsonbKeyValueFloatNonZero(JsonbParseState **ps, JsonbValue *jbv,
							  const char *field, double val)
{
	if (val != 0.0)
		pushJsonbKeyValueFloat(ps, jbv, field, val);
}

/*
 * jsonAnalyzeBuildPathStats
 *		Serialize statistics for a particular json path.
 *
 * This includes both the per-column stats (stored in "json" key) and the
 * JSON specific stats (like frequencies of different object types).
 */
static Jsonb *
jsonAnalyzeBuildPathStats(JsonPathAnlStats *pstats)
{
	const JsonValueStats *vstats = &pstats->vstats;
	float4				freq = pstats->freq;
	bool				fullstats = true;	/* pstats->path.parent != NULL */
	JsonbValue			val;
	JsonbValue		   *jbv;
	JsonbParseState	   *ps = NULL;

	pushJsonbValue(&ps, WJB_BEGIN_OBJECT, NULL);

	pushJsonbKeyValueString(&ps, &val, "path", pstats->path.pathstr);

	pushJsonbKeyValueFloat(&ps, &val, "freq", freq);

	pushJsonbKeyValueFloatNonZero(&ps, &val, "freq_null",
								  freq * vstats->nnulls /
								  vstats->jsons.values.count);

	pushJsonbKeyValueFloatNonZero(&ps, &val, "freq_boolean",
								  freq * (vstats->nfalse + vstats->ntrue) /
								  vstats->jsons.values.count);

	pushJsonbKeyValueFloatNonZero(&ps, &val, "freq_string",
								  freq * vstats->nstrings /
								  vstats->jsons.values.count);

	pushJsonbKeyValueFloatNonZero(&ps, &val, "freq_numeric",
								  freq * vstats->nnumerics /
								  vstats->jsons.values.count);

	pushJsonbKeyValueFloatNonZero(&ps, &val, "freq_array",
								  freq * vstats->narrays /
								  vstats->jsons.values.count);

	pushJsonbKeyValueFloatNonZero(&ps, &val, "freq_object",
								  freq * vstats->nobjects /
								  vstats->jsons.values.count);

	/*
	 * We keep array length stats here for queries like jsonpath '$.size() > 5'.
	 * Object lengths stats can be useful for other query lanuages.
	 */
	if (vstats->arrlens.values.count)
		jsonAnalyzeMakeScalarStats(&ps, "array_length", &vstats->arrlens.stats);

	if (vstats->objlens.values.count)
		jsonAnalyzeMakeScalarStats(&ps, "object_length", &vstats->objlens.stats);

	if (vstats->narrays)
		pushJsonbKeyValueFloat(&ps, &val, "avg_array_length",
							   (float4) vstats->narrelems / vstats->narrays);

	if (fullstats)
	{
#ifdef JSON_ANALYZE_SCALARS
		jsonAnalyzeMakeScalarStats(&ps, "string", &vstats->strings.stats);
		jsonAnalyzeMakeScalarStats(&ps, "numeric", &vstats->numerics.stats);
#endif
		jsonAnalyzeMakeScalarStats(&ps, "json", &vstats->jsons.stats);
	}

	jbv = pushJsonbValue(&ps, WJB_END_OBJECT, NULL);

	return JsonbValueToJsonb(jbv);
}

/*
 * jsonAnalyzeCalcPathFreq
 *		Calculate path frequency, i.e. how many documents contain this path.
 */
static void
jsonAnalyzeCalcPathFreq(JsonAnalyzeContext *ctx, JsonPathAnlStats *pstats,
						JsonPathParentStats *parent)
{
	if (pstats->path.parent)
	{
		int			count = JsonPathEntryIsArray(&pstats->path)	?
			parent->narrays : pstats->vstats.jsons.values.count;

		pstats->freq = parent->freq * count / parent->count;

		CLAMP_PROBABILITY(pstats->freq);
	}
	else
		pstats->freq = (double) ctx->analyzed_cnt / ctx->samplerows;
}

/*
 * jsonAnalyzePath
 *		Build statistics for values accumulated for this path.
 *
 * We're done with accumulating values for this path, so calculate the
 * statistics for the various arrays.
 *
 * XXX I wonder if we could introduce some simple heuristict on which
 * paths to keep, similarly to what we do for MCV lists. For example a
 * path that occurred just once is not very interesting, so we could
 * decide to ignore it and not build the stats. Although that won't
 * save much, because there'll be very few values accumulated.
 */
static Jsonb *
jsonAnalyzePath(JsonAnalyzeContext *ctx, JsonPathAnlStats *pstats,
				JsonPathParentStats *parent_stats)
{
	JsonValueStats	   *vstats = &pstats->vstats;
	Jsonb			   *stats;

	jsonAnalyzeCalcPathFreq(ctx, pstats, parent_stats);

	/* values combining all object types */
	jsonAnalyzePathValues(ctx, &vstats->jsons, JSONBOID, pstats->freq,
						  /* store root stats in analyze context */
						  !parent_stats);

	/*
	 * Lengths and array lengths.  We divide counts by the total number of json
	 * values to compute correct nullfrac (i.e. not all jsons have lengths).
	 */
	jsonAnalyzePathValues(ctx, &vstats->arrlens, INT4OID,
						  pstats->freq * vstats->arrlens.values.count /
						  vstats->jsons.values.count, false);
	jsonAnalyzePathValues(ctx, &vstats->objlens, INT4OID,
						  pstats->freq * vstats->objlens.values.count /
						  vstats->jsons.values.count, false);

#ifdef JSON_ANALYZE_SCALARS
	/* stats for values of string/numeric types only */
	jsonAnalyzePathValues(ctx, &vstats->strings, TEXTOID, pstats->freq, false);
	jsonAnalyzePathValues(ctx, &vstats->numerics, NUMERICOID, pstats->freq, false);
#endif

	/* Build jsonb with path stats */
	stats = jsonAnalyzeBuildPathStats(pstats);

	/* Copy stats to non-temporary context */
	return memcpy(MemoryContextAlloc(ctx->stats->anl_context, VARSIZE(stats)),
				  stats, VARSIZE(stats));
}

/*
 * JsonPathStatsCompare
 *		Compare two path stats (by path string).
 *
 * We store the stats sorted by path string, and this is the comparator.
 */
static int
JsonPathStatsCompare(const void *pv1, const void *pv2)
{
	return strcmp((*((const JsonPathEntry **) pv1))->pathstr,
				  (*((const JsonPathEntry **) pv2))->pathstr);
}

/*
 * jsonAnalyzeSortPaths
 *		Reads all stats stored in the hash table and sorts them.
 */
static JsonPathEntry **
jsonAnalyzeSortPaths(JsonAnalyzeContext *ctx, int *p_npaths)
{
	HASH_SEQ_STATUS	hseq;
	JsonPathEntry *path;
	JsonPathEntry **paths;
	int			npaths;

	npaths = hash_get_num_entries(ctx->pathshash) + 1;
	paths = MemoryContextAlloc(ctx->mcxt, sizeof(*paths) * npaths);

	paths[0] = &ctx->root->path;

	hash_seq_init(&hseq, ctx->pathshash);

	for (int i = 1; (path = hash_seq_search(&hseq)) != NULL; i++)
		paths[i] = path;

	pg_qsort(paths, npaths, sizeof(*paths), JsonPathStatsCompare);

	*p_npaths = npaths;
	return paths;
}

/*
 * jsonAnalyzeBuildPathStatsArray
 *		Build jsonb datum array for path stats, that will be used as stavalues.
 *
 * The first element is a path prefix.
 */
static Datum *
jsonAnalyzeBuildPathStatsArray(Jsonb **pstats, int npaths, int *nvals,
							   const char *prefix, int prefixlen)
{
	Datum	   *values = palloc(sizeof(Datum) * (npaths + 1));
	JsonbValue *jbvprefix = palloc(sizeof(JsonbValue));
	int			i;

	JsonValueInitStringWithLen(jbvprefix,
							   memcpy(palloc(prefixlen), prefix, prefixlen),
							   prefixlen);

	values[0] = JsonbPGetDatum(JsonbValueToJsonb(jbvprefix));

	for (i = 0; i < npaths; i++)
		values[i + 1] = JsonbPGetDatum(pstats[i]);

	*nvals = npaths + 1;

	return values;
}

/*
 * jsonAnalyzeMakeStats
 *		Build stavalues jsonb array for the root path prefix.
 */
static Datum *
jsonAnalyzeMakeStats(JsonAnalyzeContext *ctx, Jsonb **paths,
					 int npaths, int *numvalues)
{
	Datum	   *values;
	MemoryContext oldcxt = MemoryContextSwitchTo(ctx->stats->anl_context);

	values = jsonAnalyzeBuildPathStatsArray(paths, npaths, numvalues,
											JSON_PATH_ROOT, JSON_PATH_ROOT_LEN);

	MemoryContextSwitchTo(oldcxt);

	return values;
}

/*
 * jsonAnalyzeBuildSubPathsData
 *		Build statvalues and stanumbers arrays for the subset of paths starting
 *		from a given prefix.
 *
 * pathsDatums[index] should point to the desired path.
 */
bool
jsonAnalyzeBuildSubPathsData(Datum *pathsDatums, int npaths, int index,
							 const char	*path, int pathlen,
							 bool includeSubpaths, float4 nullfrac,
							 Datum *pvals, Datum *pnums)
{
	Jsonb	  **pvalues = palloc(sizeof(*pvalues) * npaths);
	Datum	   *values;
	Datum		numbers[1];
	JsonbValue	pathkey;
	int			nsubpaths = 0;
	int			nvalues;
	int			i;

	JsonValueInitStringWithLen(&pathkey, "path", 4);

	for (i = index; i < npaths; i++)
	{
		/* Extract path name */
		Jsonb	   *jb = DatumGetJsonbP(pathsDatums[i]);
		JsonbValue *jbv = findJsonbValueFromContainer(&jb->root, JB_FOBJECT,
													  &pathkey);

		/* Check if path name starts with a given prefix */
		if (!jbv || jbv->type != jbvString ||
			jbv->val.string.len < pathlen ||
			memcmp(jbv->val.string.val, path, pathlen))
			break;

		pfree(jbv);

		/* Collect matching path */
		pvalues[nsubpaths] = jb;

		nsubpaths++;

		/*
		 * The path should go before its subpaths, so if subpaths are not
		 * needed the loop is broken after the first matching path.
		 */
		if (!includeSubpaths)
			break;
	}

	if (!nsubpaths)
	{
		pfree(pvalues);
		return false;
	}

	/* Construct new array from the selected paths */
	values = jsonAnalyzeBuildPathStatsArray(pvalues, nsubpaths, &nvalues,
											path, pathlen);
	*pvals = PointerGetDatum(construct_array(values, nvalues, JSONBOID, -1,
											 false, 'i'));

	pfree(pvalues);
	pfree(values);

	numbers[0] = Float4GetDatum(nullfrac);
	*pnums = PointerGetDatum(construct_array(numbers, 1, FLOAT4OID, 4,
											 true /*FLOAT4PASSBYVAL*/, 'i'));

	return true;
}

/*
 * jsonAnalyzeInit
 *		Initialize the analyze context so that we can start adding paths.
 */
static void
jsonAnalyzeInit(JsonAnalyzeContext *ctx, VacAttrStats *stats,
				AnalyzeAttrFetchFunc fetchfunc,
				int samplerows, double totalrows, bool single_pass)
{
	HASHCTL	hash_ctl;

	memset(ctx, 0, sizeof(*ctx));

	ctx->stats = stats;
	ctx->fetchfunc = fetchfunc;
	ctx->mcxt = CurrentMemoryContext;
	ctx->samplerows = samplerows;
	ctx->totalrows = totalrows;
	ctx->target = stats->attr->attstattarget;
	ctx->scalarsOnly = false;
	ctx->single_pass = single_pass;

	MemSet(&hash_ctl, 0, sizeof(hash_ctl));
	hash_ctl.keysize = sizeof(JsonPathEntry);
	hash_ctl.entrysize = ctx->single_pass ? sizeof(JsonPathAnlStats) : sizeof(JsonPathAnlDocs);
	hash_ctl.hash = JsonPathEntryHash;
	hash_ctl.match = JsonPathEntryMatch;
	hash_ctl.hcxt = ctx->mcxt;

	ctx->pathshash = hash_create("JSON analyze path table", 100, &hash_ctl,
					HASH_ELEM | HASH_FUNCTION | HASH_COMPARE | HASH_CONTEXT);

	ctx->root = MemoryContextAllocZero(ctx->mcxt, sizeof(JsonPathAnlStats));
	ctx->root->path.pathstr = JSON_PATH_ROOT;
}

/*
 * jsonAnalyzePass
 *		One analysis pass over the JSON column.
 *
 * Performs one analysis pass on the JSON documents, and passes them to the
 * custom analyzefunc.
 */
static void
jsonAnalyzePass(JsonAnalyzeContext *ctx,
				void (*analyzefunc)(JsonAnalyzeContext *, Jsonb *, void *),
				void *analyzearg,
				JsonPathDocBitmap *bitmap)
{
	MemoryContext	tmpcxt = AllocSetContextCreate(CurrentMemoryContext,
												"Json Analyze Pass Context",
												ALLOCSET_DEFAULT_MINSIZE,
												ALLOCSET_DEFAULT_INITSIZE,
												ALLOCSET_DEFAULT_MAXSIZE);
	MemoryContext	oldcxt = MemoryContextSwitchTo(tmpcxt);
	int			row_num = -1;

	ctx->null_cnt = 0;
	ctx->analyzed_cnt = 0;
	ctx->total_width = 0;

	/* Loop over the jsonbs. */
	for (int i = 0; i < (bitmap ? bitmap->size : ctx->samplerows); i++)
	{
		Datum		value;
		Jsonb	   *jb;
		Size		width;
		bool		isnull;

		vacuum_delay_point();

		if (bitmap)
		{
			if (bitmap->is_list)
				row_num = bitmap->data.list[i];
			else if (!jsonStatsBitmapNext(bitmap, &row_num))
				break;
		}
		else
			row_num = i;

		value = ctx->fetchfunc(ctx->stats, row_num, &isnull);

		if (isnull)
		{
			/* json is null, just count that */
			ctx->null_cnt++;
			continue;
		}

		width = toast_raw_datum_size(value);

		ctx->total_width += VARSIZE_ANY(DatumGetPointer(value)); /* FIXME raw width? */

		/* Skip too-large values. */
#define JSON_WIDTH_THRESHOLD (100 * 1024)

		if (width > JSON_WIDTH_THRESHOLD)
			continue;

		ctx->analyzed_cnt++;

		jb = DatumGetJsonbP(value);

		if (!ctx->single_pass)
			MemoryContextSwitchTo(oldcxt);

		ctx->current_rownum = row_num;
		analyzefunc(ctx, jb, analyzearg);

		if (!ctx->single_pass)
			oldcxt = MemoryContextSwitchTo(tmpcxt);

		MemoryContextReset(tmpcxt);
	}

	MemoryContextSwitchTo(oldcxt);
}

/*
 * compute_json_stats() -- compute statistics for a json column
 */
static void
compute_json_stats(VacAttrStats *stats, AnalyzeAttrFetchFunc fetchfunc,
				   int samplerows, double totalrows)
{
	JsonAnalyzeContext	ctx;
	JsonPathEntry **paths;
	Jsonb	  **pstats;
	int			npaths;
	int			root_analyzed_cnt;
	int			root_null_cnt;
	double		root_total_width;

	jsonAnalyzeInit(&ctx, stats, fetchfunc, samplerows, totalrows,
					false /* FIXME make GUC or simply remove */);

	/*
	 * Collect and analyze JSON path values in single or multiple passes.
	 * Sigle-pass collection is faster but consumes much more memory than
	 * collecting and analyzing by the one path at pass.
	 */
	if (ctx.single_pass)
	{
		/* Collect all values of all paths */
		jsonAnalyzePass(&ctx, jsonAnalyzeCollectPaths, (void *)(intptr_t) true, NULL);

		root_analyzed_cnt = ctx.analyzed_cnt;
		root_null_cnt = ctx.null_cnt;
		root_total_width = ctx.total_width;

		/*
		 * Now that we're done with processing the documents, we sort the paths
		 * we extracted and calculate stats for each of them.
		 *
		 * XXX I wonder if we could do this in two phases, to maybe not collect
		 * (or even accumulate) values for paths that are not interesting.
		 */
		paths = jsonAnalyzeSortPaths(&ctx, &npaths);
		pstats = palloc(sizeof(*pstats) * npaths);

		for (int i = 0; i < npaths; i++)
		{
			JsonPathAnlStats *astats = (JsonPathAnlStats *) paths[i];
			JsonPathAnlStats *parent = (JsonPathAnlStats *) paths[i]->parent;
			JsonPathParentStats parent_stats;

			if (parent)
			{
				parent_stats.freq = parent->freq;
				parent_stats.count = parent->vstats.jsons.values.count;
				parent_stats.narrays = parent->vstats.narrays;
			}

			pstats[i] = jsonAnalyzePath(&ctx, astats,
										parent ? &parent_stats : NULL);
		}
	}
	else
	{
		MemoryContext	oldcxt;
		MemoryContext	tmpcxt = AllocSetContextCreate(CurrentMemoryContext,
													"Json Analyze Tmp Context",
													ALLOCSET_DEFAULT_MINSIZE,
													ALLOCSET_DEFAULT_INITSIZE,
													ALLOCSET_DEFAULT_MAXSIZE);
		JsonPathParentStats *stack;

		elog(DEBUG1, "analyzing %s attribute \"%s\"",
			stats->attrtypid == JSONBOID ? "jsonb" : "json",
			NameStr(stats->attr->attname));

		elog(DEBUG1, "collecting json paths");

		oldcxt = MemoryContextSwitchTo(tmpcxt);

		/* Collect all paths first without accumulating any Values, sort them */
		jsonAnalyzePass(&ctx, jsonAnalyzeCollectPaths, (void *)(intptr_t) false, NULL);
		paths = jsonAnalyzeSortPaths(&ctx, &npaths);
		pstats = MemoryContextAlloc(oldcxt, sizeof(*pstats) * npaths);
		stack = MemoryContextAlloc(oldcxt, sizeof(*stack) * (ctx.maxdepth + 1));

		root_analyzed_cnt = ctx.analyzed_cnt;
		root_null_cnt = ctx.null_cnt;
		root_total_width = ctx.total_width;

		/*
		 * Next, process each path independently to save memory (we don't want
		 * to accumulate all values for all paths, with a lot of duplicities).
		 */
		MemoryContextReset(tmpcxt);

		for (int i = 0; i < npaths; i++)
		{
			JsonPathEntry *path = paths[i];
			JsonPathAnlStats astats_tmp;
			JsonPathAnlStats *astats;

			if (!i)
				astats = ctx.root;
			else
			{
				astats = &astats_tmp;
				jsonStatsAnlInit(astats);
				astats->path = *path;
			}

			elog(DEBUG1, "analyzing json path (%d/%d) %s",
				 i + 1, npaths, path->pathstr);

			jsonAnalyzePass(&ctx, jsonAnalyzeCollectPath, astats,
							/* root has no bitmap */
							i > 0 ? &((JsonPathAnlDocs *) path)->bitmap : NULL);

			pstats[i] = jsonAnalyzePath(&ctx, astats,
										path->depth ? &stack[path->depth - 1] : NULL);

			/* Save parent stats in the stack */
			stack[path->depth].freq = astats->freq;
			stack[path->depth].count = astats->vstats.jsons.values.count;
			stack[path->depth].narrays = astats->vstats.narrays;

			MemoryContextReset(tmpcxt);
		}

		MemoryContextSwitchTo(oldcxt);

		MemoryContextDelete(tmpcxt);
	}

	/* We can only compute real stats if we found some non-null values. */
	if (root_null_cnt >= samplerows)
	{
		/* We found only nulls; assume the column is entirely null */
		stats->stats_valid = true;
		stats->stanullfrac = 1.0;
		stats->stawidth = 0;		/* "unknown" */
		stats->stadistinct = 0.0;	/* "unknown" */
	}
	else if (!root_analyzed_cnt)
	{
		int	nonnull_cnt = samplerows - root_null_cnt;

		/* We found some non-null values, but they were all too wide */
		stats->stats_valid = true;
		/* Do the simple null-frac and width stats */
		stats->stanullfrac = (double) root_null_cnt / (double) samplerows;
		stats->stawidth = root_total_width / (double) nonnull_cnt;
		/* Assume all too-wide values are distinct, so it's a unique column */
		stats->stadistinct = -1.0 * (1.0 - stats->stanullfrac);
	}
	else
	{
		VacAttrStats   *jsstats = &ctx.root->vstats.jsons.stats;
		int				i;
		int				empty_slot = -1;

		stats->stats_valid = true;

		stats->stanullfrac	= jsstats->stanullfrac;
		stats->stawidth		= jsstats->stawidth;
		stats->stadistinct	= jsstats->stadistinct;

		/*
		 * We need to store the statistics the statistics slots. We simply
		 * store the regular stats in the first slots, and then we put the
		 * JSON stats into the first empty slot.
		 */
		for (i = 0; i < STATISTIC_NUM_SLOTS; i++)
		{
			/* once we hit an empty slot, we're done */
			if (!jsstats->staop[i])
			{
				empty_slot = i;		/* remember the empty slot */
				break;
			}

			stats->stakind[i] 		= jsstats->stakind[i];
			stats->staop[i] 		= jsstats->staop[i];
			stats->stanumbers[i] 	= jsstats->stanumbers[i];
			stats->stavalues[i] 	= jsstats->stavalues[i];
			stats->statypid[i] 		= jsstats->statypid[i];
			stats->statyplen[i] 	= jsstats->statyplen[i];
			stats->statypbyval[i] 	= jsstats->statypbyval[i];
			stats->statypalign[i] 	= jsstats->statypalign[i];
			stats->numnumbers[i] 	= jsstats->numnumbers[i];
			stats->numvalues[i] 	= jsstats->numvalues[i];
		}

		Assert((empty_slot >= 0) && (empty_slot < STATISTIC_NUM_SLOTS));

		stats->stakind[empty_slot] = STATISTIC_KIND_JSON;
		stats->staop[empty_slot] = InvalidOid;
		stats->numnumbers[empty_slot] = 1;
		stats->stanumbers[empty_slot] = MemoryContextAlloc(stats->anl_context,
														   sizeof(float4));
		stats->stanumbers[empty_slot][0] = 0.0; /* nullfrac */
		stats->stavalues[empty_slot] =
			jsonAnalyzeMakeStats(&ctx, pstats, npaths,
								 &stats->numvalues[empty_slot]);

		/* We are storing jsonb values */
		stats->statypid[empty_slot] = JSONBOID;
		get_typlenbyvalalign(stats->statypid[empty_slot],
							 &stats->statyplen[empty_slot],
							 &stats->statypbyval[empty_slot],
							 &stats->statypalign[empty_slot]);
	}
}

/*
 * json_typanalyze -- typanalyze function for jsonb
 */
Datum
jsonb_typanalyze(PG_FUNCTION_ARGS)
{
	VacAttrStats *stats = (VacAttrStats *) PG_GETARG_POINTER(0);
	Form_pg_attribute attr = stats->attr;

	/* If the attstattarget column is negative, use the default value */
	/* NB: it is okay to scribble on stats->attr since it's a copy */
	if (attr->attstattarget < 0)
		attr->attstattarget = default_statistics_target;

	stats->compute_stats = compute_json_stats;
	/* see comment about the choice of minrows in commands/analyze.c */
	stats->minrows = 300 * attr->attstattarget;

	PG_RETURN_BOOL(true);
}
