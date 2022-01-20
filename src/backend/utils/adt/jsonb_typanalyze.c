/*-------------------------------------------------------------------------
 *
 * jsonb_typanalyze.c
 *	  Functions for gathering statistics from jsonb columns
 *
 * Copyright (c) 2016, PostgreSQL Global Development Group
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
 * The per-column stats (stored in the "json" key) have additional internal
 * structure, to allow storing multiple stakind types (histogram, mcv). See
 * jsonAnalyzeMakeScalarStats for details.
 *
 *
 * XXX There's additional stuff (prefix, length stats) stored in the first
 * two elements, I think.
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
} JsonPathEntry;

#define JsonPathEntryIsArray(entry) ((entry)->len == -1)

/* An array containing a dynamic number of JSON values. */
typedef struct JsonValues
{
	Datum	   *buf;
	int			count;
	int			allocated;
} JsonValues;

/*
 * Scalar statistics built for an array of values, extracted from a JSON
 * document (for one particular path).
 *
 * XXX The array can contain values of different JSON type, probably?
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
 * has a copy of data from the one in "jsons"). Some of it is defined as
 * a typedef, but booleans have inline struct.
 */
typedef struct JsonValueStats
{
	JsonScalarStats	jsons;		/* stats for all JSON types together */

#ifdef JSON_ANALYZE_SCALARS		/* XXX */
	JsonScalarStats	strings;	/* stats for JSON strings */
	JsonScalarStats	numerics;	/* stats for JSON numerics */
#endif

	JsonScalarStats	lens;		/* stats of object/array lengths */
	JsonScalarStats	arrlens;	/* stats of array lengths */

	/* stats for booleans */
	struct
	{
		int		ntrue;
		int		nfalse;
	}				booleans;

	int				nnulls;		/* number of JSON null values */
	int				nobjects;	/* number of JSON objects */
	int				narrays;	/* number of JSON arrays */
	int				nstrings;	/* number of JSON strings */
	int				nnumerics;	/* number of JSON numerics */
} JsonValueStats;

/* ??? */
typedef struct JsonPathAnlStats
{
	JsonPathEntry		path;
	JsonValueStats		vstats;
	Jsonb			   *stats;
	char			   *pathstr;
	double				freq;
	int					depth;

	JsonPathEntry	  **entries;
	int					nentries;
} JsonPathAnlStats;

/* various bits needed while analyzing JSON */
typedef struct JsonAnalyzeContext
{
	VacAttrStats		   *stats;
	MemoryContext			mcxt;
	AnalyzeAttrFetchFunc	fetchfunc;
	HTAB				   *pathshash;
	JsonPathAnlStats	   *root;
	JsonPathAnlStats	  **paths;
	int						npaths;
	double					totalrows;
	double					total_width;
	int						samplerows;
	int						target;
	int						null_cnt;
	int						analyzed_cnt;
	int						maxdepth;
	bool					scalarsOnly;
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

/*
 * jsonAnalyzeAddPath
 *		Add an entry for a JSON path to the working list of statistics.
 *
 * Returns a pointer to JsonPathAnlStats (which might have already existed
 * if the path was in earlier document), which can then be populated or
 * updated.
 */
static inline JsonPathAnlStats *
jsonAnalyzeAddPath(JsonAnalyzeContext *ctx, JsonPathEntry *parent,
				   const char *entry, int len)
{
	JsonPathEntry path;
	JsonPathAnlStats *stats;
	bool		found;

	/* Init path entry */
	path.parent = parent;
	path.entry = entry;
	path.len = len;
	path.hash = JsonPathEntryHash(&path, 0);

	/* XXX See if we already saw this path earlier. */
	stats = hash_search_with_hash_value(ctx->pathshash, &path, path.hash,
										HASH_ENTER, &found);

	/*
	 * Nope, it's the first time we see this path, so initialize all the
	 * fields (path string, counters, ...).
	 */
	if (!found)
	{
		JsonPathAnlStats *parent = (JsonPathAnlStats *) stats->path.parent;
		JsonPathEntry *path = &stats->path;
		const char *ppath = parent->pathstr;
		StringInfoData si;
		MemoryContext oldcxt = MemoryContextSwitchTo(ctx->mcxt);

		/* NULL entries are treated as wildcard array accessors "[*]" */
		if (path->entry)
			/* Copy path entry name into the right MemoryContext */
			path->entry = pnstrdup(path->entry, path->len);

		/* Initialze full path string */
		initStringInfo(&si);
		appendStringInfoString(&si, ppath);
		jsonPathAppendEntry(&si, path->entry);
		stats->pathstr = si.data;

		MemoryContextSwitchTo(oldcxt);

		/* initialize the stats counter for this path entry */
		memset(&stats->vstats, 0, sizeof(JsonValueStats));
		stats->stats = NULL;
		stats->freq = 0.0;
		stats->depth = parent->depth + 1;
		stats->entries = NULL;
		stats->nentries = 0;

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
	JsonbValue		   *jbv;
	JsonbValue			jbvtmp;
	Datum				value;

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

	/* always add it to the "global" JSON stats, shared by all types */
	JsonValuesAppend(&vstats->jsons.values,
					 JsonbPGetDatum(JsonbValueToJsonb(jbv)),
					 ctx->target);

	/* also update the type-specific counters */
	switch (jv->type)
	{
		case jbvNull:
			vstats->nnulls++;
			break;

		case jbvBool:
			if (jv->val.boolean)
				vstats->booleans.ntrue++;
			else
				vstats->booleans.nfalse++;
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
				uint32 size = JsonContainerSize(jv->val.binary.data);

				value = DatumGetInt32(size);
				vstats->nobjects++;
				JsonValuesAppend(&vstats->lens.values, value, ctx->target);
			}
			else if (JsonContainerIsArray(jv->val.binary.data))
			{
				uint32 size = JsonContainerSize(jv->val.binary.data);

				value = DatumGetInt32(size);
				vstats->narrays++;
				JsonValuesAppend(&vstats->arrlens.values, value, ctx->target);
				JsonValuesAppend(&vstats->lens.values, value, ctx->target);
			}
			break;

		default:
			elog(ERROR, "invalid scalar json value type %d", jv->type);
			break;
	}
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
	JsonPathAnlStats   *stats = ctx->root;
	bool				collect_values = (bool)(intptr_t) param;
	bool				scalar = false;

	if (collect_values && !JB_ROOT_IS_SCALAR(jb))
		jsonAnalyzeJsonValue(ctx, &stats->vstats, JsonValueInitBinary(&jv, jb));

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

				stats = jsonAnalyzeAddPath(ctx, &stats->path,
										   jv.val.string.val,
										   jv.val.string.len);
				break;

			case WJB_BEGIN_ARRAY:
				/* Make stats for non-scalar array and use it for all elements */
				if (!(scalar = jv.val.array.rawScalar))
					stats = jsonAnalyzeAddPath(ctx, &stats->path, NULL, -1);
				break;

			case WJB_END_ARRAY:
				if (scalar)
					break;
				/* FALLTHROUGH */
			case WJB_END_OBJECT:
				/* Reset to parent stats */
				stats = (JsonPathAnlStats *) stats->path.parent;
				break;

			case WJB_KEY:
				/*
				 * Stats should point to the previous key of current object,
				 * use its parent path as a base path.
				 */
				stats = jsonAnalyzeAddPath(ctx, stats->path.parent,
										   jv.val.string.val,
										   jv.val.string.len);
				break;

			case WJB_VALUE:
			case WJB_ELEM:
				if (collect_values)
					jsonAnalyzeJsonValue(ctx, &stats->vstats, &jv);

				/* XXX not sure why we're doing this? */
				if (jv.type == jbvBinary)
				{
					/* recurse into container */
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
						  JsonbValue *jbv, int n)
{
	JsonbValue	scalar;
	int			i;

	for (i = n; i < pstats->depth; i++)
	{
		JsonPathEntry  *entry = pstats->entries[i];
		JsonbContainer *jbc = jbv->val.binary.data;
		JsonbValueType	type = jbv->type;

		if (i > n)
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
					jsonAnalyzeCollectSubpath(ctx, pstats, &elem, i + 1);
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

	if (i == n &&
		jbv->type == jbvBinary &&
		JsonbExtractScalar(jbv->val.binary.data, &scalar))
		jbv = &scalar;

	jsonAnalyzeJsonValue(ctx, &pstats->vstats, jbv);

	if (i > n)
		pfree(jbv);
}

/*
 * jsonAnalyzeCollectPath
 *		Extract a single path from JSON documents and collect its values.
 */
static void
jsonAnalyzeCollectPath(JsonAnalyzeContext *ctx, Jsonb *jb, void *param)
{
	JsonPathAnlStats   *pstats = (JsonPathAnlStats *) param;
	JsonbValue			jbvtmp;
	JsonbValue		   *jbv = JsonValueInitBinary(&jbvtmp, jb);
	JsonPathEntry *path;

	if (!pstats->entries)
	{
		int i;

		pstats->entries = MemoryContextAlloc(ctx->mcxt,
									sizeof(*pstats->entries) * pstats->depth);

		for (path = &pstats->path, i = pstats->depth - 1;
			 path->parent && i >= 0;
			 path = path->parent, i--)
			pstats->entries[i] = path;
	}

	jsonAnalyzeCollectSubpath(ctx, pstats, jbv, 0);
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
					  Oid typid, double freq)
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
	stats->anl_context = ctx->stats->anl_context;

	stats->exprvals = values->buf;

	/* XXX Do we need to initialize all slots? */
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
	bool				full = !!pstats->path.parent;
	JsonbValue			val;
	JsonbValue		   *jbv;
	JsonbParseState	   *ps = NULL;

	pushJsonbValue(&ps, WJB_BEGIN_OBJECT, NULL);

	pushJsonbKeyValueString(&ps, &val, "path", pstats->pathstr);

	pushJsonbKeyValueFloat(&ps, &val, "freq", freq);

	pushJsonbKeyValueFloat(&ps, &val, "freq_null",
						   freq * vstats->nnulls /
								  vstats->jsons.values.count);

	pushJsonbKeyValueFloat(&ps, &val, "freq_boolean",
						   freq * (vstats->booleans.nfalse +
								   vstats->booleans.ntrue) /
								  vstats->jsons.values.count);

	pushJsonbKeyValueFloat(&ps, &val, "freq_string",
						   freq * vstats->nstrings /
								  vstats->jsons.values.count);

	pushJsonbKeyValueFloat(&ps, &val, "freq_numeric",
						   freq * vstats->nnumerics /
								  vstats->jsons.values.count);

	pushJsonbKeyValueFloat(&ps, &val, "freq_array",
						   freq * vstats->narrays /
								  vstats->jsons.values.count);

	pushJsonbKeyValueFloat(&ps, &val, "freq_object",
						   freq * vstats->nobjects /
								  vstats->jsons.values.count);

	/*
	 * XXX not sure why we keep length and array length stats at this level.
	 * Aren't those covered by the per-column stats? We certainly have
	 * frequencies for array elements etc.
	 */
	if (pstats->vstats.lens.values.count)
		jsonAnalyzeMakeScalarStats(&ps, "length", &vstats->lens.stats);

	if (JsonPathEntryIsArray(&pstats->path))
	{
		JsonPathAnlStats *parent = (JsonPathAnlStats *) pstats->path.parent;

		pushJsonbKeyValueFloat(&ps, &val, "avg_array_length",
							   (float4) vstats->jsons.values.count /
										parent->vstats.narrays);

		jsonAnalyzeMakeScalarStats(&ps, "array_length",
									&parent->vstats.arrlens.stats);
	}

	if (full)
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
jsonAnalyzeCalcPathFreq(JsonAnalyzeContext *ctx, JsonPathAnlStats *pstats)
{
	JsonPathAnlStats  *parent = (JsonPathAnlStats *) pstats->path.parent;

	if (parent)
	{
		int			count = JsonPathEntryIsArray(&pstats->path)	?
			parent->vstats.narrays : pstats->vstats.jsons.values.count;

		pstats->freq = parent->freq * count / parent->vstats.jsons.values.count;

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
static void
jsonAnalyzePath(JsonAnalyzeContext *ctx, JsonPathAnlStats *pstats)
{
	MemoryContext		oldcxt;
	JsonValueStats	   *vstats = &pstats->vstats;

	jsonAnalyzeCalcPathFreq(ctx, pstats);

	/* values combining all object types */
	jsonAnalyzePathValues(ctx, &vstats->jsons, JSONBOID, pstats->freq);

	/*
	 * lengths and array lengths
	 *
	 * XXX Not sure why we divide it by the number of json values?
	 */
	jsonAnalyzePathValues(ctx, &vstats->lens, INT4OID,
						  pstats->freq * vstats->lens.values.count /
										 vstats->jsons.values.count);
	jsonAnalyzePathValues(ctx, &vstats->arrlens, INT4OID,
						  pstats->freq * vstats->arrlens.values.count /
										 vstats->jsons.values.count);

#ifdef JSON_ANALYZE_SCALARS
	/* stats for values of string/numeric types only */
	jsonAnalyzePathValues(ctx, &vstats->strings, TEXTOID, pstats->freq);
	jsonAnalyzePathValues(ctx, &vstats->numerics, NUMERICOID, pstats->freq);
#endif

	oldcxt = MemoryContextSwitchTo(ctx->stats->anl_context);
	pstats->stats = jsonAnalyzeBuildPathStats(pstats);
	MemoryContextSwitchTo(oldcxt);
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
	return strcmp((*((const JsonPathAnlStats **) pv1))->pathstr,
				  (*((const JsonPathAnlStats **) pv2))->pathstr);
}

/*
 * jsonAnalyzeSortPaths
 *		Reads all stats stored in the hash table and sorts them.
 *
 * XXX It's a bit strange we simply store the result in the context instead
 * of just returning it.
 */
static void
jsonAnalyzeSortPaths(JsonAnalyzeContext *ctx)
{
	HASH_SEQ_STATUS		hseq;
	JsonPathAnlStats   *path;
	int					i;

	ctx->npaths = hash_get_num_entries(ctx->pathshash) + 1;
	ctx->paths = MemoryContextAlloc(ctx->mcxt,
									sizeof(*ctx->paths) * ctx->npaths);

	ctx->paths[0] = ctx->root;

	hash_seq_init(&hseq, ctx->pathshash);

	for (i = 1; (path = hash_seq_search(&hseq)); i++)
		ctx->paths[i] = path;

	pg_qsort(ctx->paths, ctx->npaths, sizeof(*ctx->paths),
			 JsonPathStatsCompare);
}

/*
 * jsonAnalyzeBuildPathStatsArray
 *		???
 */
static Datum *
jsonAnalyzeBuildPathStatsArray(JsonPathAnlStats **paths, int npaths, int *nvals,
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
		values[i + 1] = JsonbPGetDatum(paths[i]->stats);

	*nvals = npaths + 1;

	return values;
}

/*
 * jsonAnalyzeMakeStats
 *		???
 */
static Datum *
jsonAnalyzeMakeStats(JsonAnalyzeContext *ctx, int *numvalues)
{
	Datum		   *values;
	MemoryContext	oldcxt = MemoryContextSwitchTo(ctx->stats->anl_context);

	values = jsonAnalyzeBuildPathStatsArray(ctx->paths, ctx->npaths, numvalues,
											JSON_PATH_ROOT, JSON_PATH_ROOT_LEN);

	MemoryContextSwitchTo(oldcxt);

	return values;
}

/*
 * jsonAnalyzeBuildSubPathsData
 *		???
 */
bool
jsonAnalyzeBuildSubPathsData(Datum *pathsDatums, int npaths, int index,
							 const char	*path, int pathlen,
							 bool includeSubpaths, float4 nullfrac,
							 Datum *pvals, Datum *pnums)
{
	JsonPathAnlStats  **pvalues = palloc(sizeof(*pvalues) * npaths);
	Datum			   *values;
	Datum				numbers[1];
	JsonbValue			pathkey;
	int					nsubpaths = 0;
	int					nvalues;
	int					i;

	JsonValueInitStringWithLen(&pathkey, "path", 4);

	for (i = index; i < npaths; i++)
	{
		Jsonb	   *jb = DatumGetJsonbP(pathsDatums[i]);
		JsonbValue *jbv = findJsonbValueFromContainer(&jb->root, JB_FOBJECT,
													  &pathkey);

		if (!jbv || jbv->type != jbvString ||
			jbv->val.string.len < pathlen ||
			memcmp(jbv->val.string.val, path, pathlen))
			break;

		pfree(jbv);

		pvalues[nsubpaths] = palloc(sizeof(**pvalues));
		pvalues[nsubpaths]->stats = jb;

		nsubpaths++;

		if (!includeSubpaths)
			break;
	}

	if (!nsubpaths)
	{
		pfree(pvalues);
		return false;
	}

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
				int samplerows, double totalrows)
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

	MemSet(&hash_ctl, 0, sizeof(hash_ctl));
	hash_ctl.keysize = sizeof(JsonPathEntry);
	hash_ctl.entrysize = sizeof(JsonPathAnlStats);
	hash_ctl.hash = JsonPathEntryHash;
	hash_ctl.match = JsonPathEntryMatch;
	hash_ctl.hcxt = ctx->mcxt;

	ctx->pathshash = hash_create("JSON analyze path table", 100, &hash_ctl,
					HASH_ELEM | HASH_FUNCTION | HASH_COMPARE | HASH_CONTEXT);

	ctx->root = MemoryContextAllocZero(ctx->mcxt, sizeof(JsonPathAnlStats));
	ctx->root->pathstr = JSON_PATH_ROOT;
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
				void *analyzearg)
{
	int	row_num;

	MemoryContext	tmpcxt = AllocSetContextCreate(CurrentMemoryContext,
												"Json Analyze Pass Context",
												ALLOCSET_DEFAULT_MINSIZE,
												ALLOCSET_DEFAULT_INITSIZE,
												ALLOCSET_DEFAULT_MAXSIZE);

	MemoryContext	oldcxt = MemoryContextSwitchTo(tmpcxt);

	ctx->null_cnt = 0;
	ctx->analyzed_cnt = 0;
	ctx->total_width = 0;

	/* Loop over the arrays. */
	for (row_num = 0; row_num < ctx->samplerows; row_num++)
	{
		Datum		value;
		Jsonb	   *jb;
		Size		width;
		bool		isnull;

		vacuum_delay_point();

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

		MemoryContextSwitchTo(oldcxt);

		analyzefunc(ctx, jb, analyzearg);

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
	bool		sigle_pass = false;	/* FIXME make GUC or simply remove */

	jsonAnalyzeInit(&ctx, stats, fetchfunc, samplerows, totalrows);

	/*
	 * Collect and analyze JSON path values in single or multiple passes.
	 * Sigle-pass collection is faster but consumes much more memory than
	 * collecting and analyzing by the one path at pass.
	 */
	if (sigle_pass)
	{
		/* Collect all values of all paths */
		jsonAnalyzePass(&ctx, jsonAnalyzeCollectPaths, (void *)(intptr_t) true);

		/*
		 * Now that we're done with processing the documents, we sort the paths
		 * we extracted and calculate stats for each of them.
		 *
		 * XXX I wonder if we could do this in two phases, to maybe not collect
		 * (or even accumulate) values for paths that are not interesting.
		 */
		jsonAnalyzeSortPaths(&ctx);

		for (int i = 0; i < ctx.npaths; i++)
			jsonAnalyzePath(&ctx, ctx.paths[i]);
	}
	else
	{
		int				i;
		MemoryContext	oldcxt;
		MemoryContext	tmpcxt = AllocSetContextCreate(CurrentMemoryContext,
													"Json Analyze Tmp Context",
													ALLOCSET_DEFAULT_MINSIZE,
													ALLOCSET_DEFAULT_INITSIZE,
													ALLOCSET_DEFAULT_MAXSIZE);

		elog(DEBUG1, "analyzing %s attribute \"%s\"",
			stats->attrtypid == JSONBOID ? "jsonb" : "json",
			NameStr(stats->attr->attname));

		elog(DEBUG1, "collecting json paths");

		oldcxt = MemoryContextSwitchTo(tmpcxt);

		/* Collect all paths first without accumulating any Values, sort them */
		jsonAnalyzePass(&ctx, jsonAnalyzeCollectPaths, (void *)(intptr_t) false);
		jsonAnalyzeSortPaths(&ctx);

		/*
		 * Next, process each path independently to save memory (we don't want
		 * to accumulate all values for all paths, with a lot of duplicities).
		 */
		MemoryContextReset(tmpcxt);

		for (i = 0; i < ctx.npaths; i++)
		{
			JsonPathAnlStats *path = ctx.paths[i];

			elog(DEBUG1, "analyzing json path (%d/%d) %s",
				 i + 1, ctx.npaths, path->pathstr);

			jsonAnalyzePass(&ctx, jsonAnalyzeCollectPath, path);
			jsonAnalyzePath(&ctx, path);

			MemoryContextReset(tmpcxt);
		}

		MemoryContextSwitchTo(oldcxt);

		MemoryContextDelete(tmpcxt);
	}

	/* We can only compute real stats if we found some non-null values. */
	if (ctx.null_cnt >= samplerows)
	{
		/* We found only nulls; assume the column is entirely null */
		stats->stats_valid = true;
		stats->stanullfrac = 1.0;
		stats->stawidth = 0;		/* "unknown" */
		stats->stadistinct = 0.0;	/* "unknown" */
	}
	else if (!ctx.analyzed_cnt)
	{
		int	nonnull_cnt = samplerows - ctx.null_cnt;

		/* We found some non-null values, but they were all too wide */
		stats->stats_valid = true;
		/* Do the simple null-frac and width stats */
		stats->stanullfrac = (double) ctx.null_cnt / (double) samplerows;
		stats->stawidth = ctx.total_width / (double) nonnull_cnt;
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
				jsonAnalyzeMakeStats(&ctx, &stats->numvalues[empty_slot]);

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
