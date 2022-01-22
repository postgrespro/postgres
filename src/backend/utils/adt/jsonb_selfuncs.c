/*-------------------------------------------------------------------------
 *
 * jsonb_selfuncs.c
 *	  Functions for selectivity estimation of jsonb operators
 *
 * Copyright (c) 2016-2022, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/utils/adt/jsonb_selfuncs.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <math.h>

#include "fmgr.h"
#include "access/heapam.h"
#include "access/htup_details.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_statistic.h"
#include "catalog/pg_type.h"
#include "common/string.h"
#include "nodes/primnodes.h"
#include "utils/builtins.h"
#include "utils/json.h"
#include "utils/jsonb.h"
#include "utils/json_selfuncs.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/selfuncs.h"

#define DEFAULT_JSON_CONTAINS_SEL	0.001

/*
 * jsonGetField
 *		Given a JSONB document and a key, extract the JSONB value for the key.
 */
static inline Datum
jsonGetField(Datum obj, const char *field)
{
	Jsonb 	   *jb = DatumGetJsonbP(obj);
	JsonbValue *jbv = findJsonbValueFromContainerLen(&jb->root, JB_FOBJECT,
													 field, strlen(field));
	return jbv ? JsonbPGetDatum(JsonbValueToJsonb(jbv)) : PointerGetDatum(NULL);
}

/*
 * jsonGetFloat4
 *		Given a JSONB value, interpret it as a float4 value.
 *
 * This expects the JSONB value to be a numeric, because that's how we store
 * floats in JSONB, and we cast it to float4.
 */
static inline float4
jsonGetFloat4(Datum jsonb, float4 default_val)
{
	Jsonb	   *jb;
	JsonbValue	jv;

	if (!DatumGetPointer(jsonb))
		return default_val;

	jb = DatumGetJsonbP(jsonb);

	if (!JsonbExtractScalar(&jb->root, &jv) || jv.type != jbvNumeric)
		return default_val;

	return DatumGetFloat4(DirectFunctionCall1(numeric_float4,
											  NumericGetDatum(jv.val.numeric)));
}

/*
 * jsonStatsInit
 *		Given a pg_statistic tuple, expand STATISTIC_KIND_JSON into JsonStats.
 */
bool
jsonStatsInit(JsonStats data, const VariableStatData *vardata)
{
	Jsonb	   *jb;
	JsonbValue	prefix;

	if (!vardata->statsTuple)
		return false;

	data->statsTuple = vardata->statsTuple;
	memset(&data->attslot, 0, sizeof(data->attslot));

	/* Were there just NULL values in the column? No JSON stats, but still useful. */
	if (((Form_pg_statistic) GETSTRUCT(data->statsTuple))->stanullfrac >= 1.0)
	{
		data->nullfrac = 1.0;
		return true;
	}

	/* Do we have the JSON stats built in the pg_statistic? */
	if (!get_attstatsslot(&data->attslot, data->statsTuple,
						  STATISTIC_KIND_JSON, InvalidOid,
						  ATTSTATSSLOT_NUMBERS | ATTSTATSSLOT_VALUES))
		return false;

	/*
	 * Valid JSON stats should have at least 2 elements in values:
	 *  0th - root path prefix
	 *  1st - root path stats
	 */
	if (data->attslot.nvalues < 2)
	{
		free_attstatsslot(&data->attslot);
		return false;
	}

	/* XXX If the ACL check was not OK, would we even get here? */
	data->acl_ok = vardata->acl_ok;
	data->rel = vardata->rel;
	data->nullfrac =
		data->attslot.nnumbers > 0 ? data->attslot.numbers[0] : 0.0;
	data->pathdatums = data->attslot.values + 1;
	data->npaths = data->attslot.nvalues - 1;

	/* Extract root path prefix */
	jb = DatumGetJsonbP(data->attslot.values[0]);
	if (!JsonbExtractScalar(&jb->root, &prefix) || prefix.type != jbvString)
	{
		free_attstatsslot(&data->attslot);
		return false;
	}

	data->prefix = prefix.val.string.val;
	data->prefixlen = prefix.val.string.len;

	/* Create path cache, initialze only two fields that acting as flags */
	data->paths = palloc(sizeof(*data->paths) * data->npaths);

	for (int i = 0; i < data->npaths; i++)
	{
		data->paths[i].data = NULL;
		data->paths[i].path = NULL;
	}

	return true;
}

/*
 * jsonStatsRelease
 *		Release resources (statistics slot) associated with the JsonStats value.
 */
void
jsonStatsRelease(JsonStats data)
{
	free_attstatsslot(&data->attslot);
}

/*
 * jsonPathStatsAllocSpecialStats
 *		Allocate a copy of JsonPathStats for accessing special (length etc.)
 *		stats for a given JSON path.
 */
static JsonPathStats
jsonPathStatsAllocSpecialStats(JsonPathStats pstats, JsonPathStatsType type)
{
	JsonPathStats stats;

	if (!pstats)
		return NULL;

	/* copy and replace stats type */
	stats = palloc(sizeof(*stats));
	*stats = *pstats;
	stats->type = type;

	return stats;
}

/*
 * jsonPathStatsGetArrayLengthStats
 *		Extract statistics of array lengths for the path.
 */
JsonPathStats
jsonPathStatsGetArrayLengthStats(JsonPathStats pstats)
{
	/*
	 * The array length statistics is relevant only for values that are arrays.
	 * So if we observed no such values, we know there can't be such
	 * statistics and so we simply return NULL.
	 */
	if (jsonPathStatsGetTypeFreq(pstats, jbvArray, 0.0) <= 0.0)
		return NULL;

	return jsonPathStatsAllocSpecialStats(pstats, JsonPathStatsArrayLength);
}

/*
 * jsonPathStatsGetObjectLengthStats
 *		Extract statistics of object length for the path.
 */
JsonPathStats
jsonPathStatsGetObjectLengthStats(JsonPathStats pstats)
{
	/*
	 * The object length statistics is relevant only for values that are arrays.
	 * So if we observed no such values, we know there can't be such
	 * statistics and so we simply return NULL.
	 */
	if (jsonPathStatsGetTypeFreq(pstats, jbvObject, 0.0) <= 0.0)
		return NULL;

	return jsonPathStatsAllocSpecialStats(pstats, JsonPathStatsObjectLength);
}

/*
 * jsonPathStatsGetPath
 *		Try to use cached path name or extract it from per-path stats datum.
 *
 * Returns true on succces, false on error.
 */
static inline bool
jsonPathStatsGetPath(JsonPathStats stats, Datum pathdatum,
					 const char **path, int *pathlen)
{
	*path = stats->path;

	if (*path)
		/* use cached path name */
		*pathlen = stats->pathlen;
	else
	{
		Jsonb	   *jsonb = DatumGetJsonbP(pathdatum);
		JsonbValue	pathkey;
		JsonbValue *pathval;

		/* extract path from the statistics represented as jsonb document */
		JsonValueInitStringWithLen(&pathkey, "path", 4);
		pathval = findJsonbValueFromContainer(&jsonb->root, JB_FOBJECT, &pathkey);

		if (!pathval || pathval->type != jbvString)
			return false;	/* XXX invalid stats data, maybe throw error */

		/* cache extracted path name */
		*path = stats->path = pathval->val.string.val;
		*pathlen = stats->pathlen = pathval->val.string.len;
	}

	return true;
}

/* Context for bsearch()ing paths */
typedef struct JsonPathStatsSearchContext
{
	JsonStats	stats;
	const char *path;
	int			pathlen;
} JsonPathStatsSearchContext;

/*
 * jsonPathStatsCompare
 *		Compare two JsonPathStats structs, so that we can sort them.
 *
 * We do this so that we can search for stats for a given path simply by
 * bsearch().
 *
 * XXX We never build two structs for the same path, so we know the paths
 * are different - one may be a prefix of the other, but then we sort the
 * strings by length.
 */
static int
jsonPathStatsCompare(const void *pv1, const void *pv2)
{
	JsonPathStatsSearchContext const *cxt = pv1;
	Datum const *pathdatum = (Datum const *) pv2;
	int			index = pathdatum - cxt->stats->pathdatums;
	JsonPathStats stats = &cxt->stats->paths[index];
	const char *path;
	int			pathlen;
	int			res;

	if (!jsonPathStatsGetPath(stats, *pathdatum, &path, &pathlen))
		return 1;	/* XXX invalid stats data */

	/* compare the shared part first, then compare by length */
	res = strncmp(cxt->path, path, Min(cxt->pathlen, pathlen));

	return res ? res : cxt->pathlen - pathlen;
}

/*
 * jsonStatsFindPath
 *		Find stats for a given path.
 *
 * The stats are sorted by path, so we can simply do bsearch().
 * This is low-level function and jsdata->prefix is not considered, the caller
 * should handle it by itself.
 */
static JsonPathStats
jsonStatsFindPath(JsonStats jsdata, const char *path, int pathlen)
{
	JsonPathStatsSearchContext cxt;
	JsonPathStats stats;
	Datum	   *pdatum;
	int			index;

	cxt.stats = jsdata;
	cxt.path = path;
	cxt.pathlen = pathlen;

	pdatum = bsearch(&cxt, jsdata->pathdatums, jsdata->npaths,
					 sizeof(*jsdata->pathdatums), jsonPathStatsCompare);

	if (!pdatum)
		return NULL;

	index = pdatum - jsdata->pathdatums;
	stats = &jsdata->paths[index];

	Assert(stats->path);
	Assert(stats->pathlen == pathlen);

	/* Init all fields if needed (stats->data == NULL means uninitialized) */
	if (!stats->data)
	{
		stats->data = jsdata;
		stats->datum = pdatum;
		stats->type = JsonPathStatsValues;
	}

	return stats;
}

/*
 * jsonStatsGetPathByStr
 *		Find stats for a given path string considering jsdata->prefix.
 */
JsonPathStats
jsonStatsGetPathByStr(JsonStats jsdata, const char *subpath, int subpathlen)
{
	JsonPathStats stats;
	char	   *path;
	int			pathlen;

	if (jsdata->nullfrac >= 1.0)
		return NULL;

	pathlen = jsdata->prefixlen + subpathlen - 1;
	path = palloc(pathlen);

	memcpy(path, jsdata->prefix, jsdata->prefixlen);
	memcpy(&path[jsdata->prefixlen], &subpath[1], subpathlen - 1);

	stats = jsonStatsFindPath(jsdata, path, pathlen);

	if (!stats)
		pfree(path);

	return stats;
}

/*
 * jsonStatsGetRootPath
 *		Find JSON stats for root prefix path.
 */
static JsonPathStats
jsonStatsGetRootPath(JsonStats jsdata)
{
	if (jsdata->nullfrac >= 1.0)
		return NULL;

	return jsonStatsFindPath(jsdata, jsdata->prefix, jsdata->prefixlen);
}

#define jsonStatsGetRootArrayPath(jsdata) \
		jsonStatsGetPathByStr(jsdata, JSON_PATH_ROOT_ARRAY, JSON_PATH_ROOT_ARRAY_LEN)

/*
 * jsonPathAppendEntry
 *		Append entry (represented as simple string) to a path.
 *
 * NULL entry is treated as wildcard array accessor "[*]".
 */
void
jsonPathAppendEntry(StringInfo path, const char *entry)
{
	if (entry)
	{
		appendStringInfoCharMacro(path, '.');
		escape_json(path, entry);
	}
	else
		appendStringInfoString(path, "[*]");
}

/*
 * jsonPathAppendEntryWithLen
 *		Append string (represented as string + length) to a path.
 */
static void
jsonPathAppendEntryWithLen(StringInfo path, const char *entry, int len)
{
	char *tmpentry = pnstrdup(entry, len);
	jsonPathAppendEntry(path, tmpentry);
	pfree(tmpentry);
}

/*
 * jsonPathStatsGetSubpath
 *		Find JSON path stats for object key or array elements (if 'key' = NULL).
 */
JsonPathStats
jsonPathStatsGetSubpath(JsonPathStats pstats, const char *key)
{
	JsonPathStats spstats;
	StringInfoData str;

	initStringInfo(&str);
	appendBinaryStringInfo(&str, pstats->path, pstats->pathlen);
	jsonPathAppendEntry(&str, key);

	spstats = jsonStatsFindPath(pstats->data, str.data, str.len);
	if (!spstats)
		pfree(str.data);

	return spstats;
}

/*
 * jsonPathStatsGetArrayIndexSelectivity
 *		Given stats for a path, determine selectivity for an array index.
 */
Selectivity
jsonPathStatsGetArrayIndexSelectivity(JsonPathStats pstats, int index)
{
	JsonPathStats lenstats = jsonPathStatsGetArrayLengthStats(pstats);
	JsonbValue	tmpjbv;
	Jsonb	   *jb;

	/*
	 * If we have no array length stats, assume all documents match.
	 *
	 * XXX Shouldn't this use a default smaller than 1.0? What do the selfuncs
	 * for regular arrays use?
	 */
	if (!lenstats)
		return 1.0;

	jb = JsonbValueToJsonb(JsonValueInitInteger(&tmpjbv, index));

	/* calculate fraction of elements smaller than the index */
	return jsonSelectivity(lenstats, JsonbPGetDatum(jb), JsonbGtOperator);
}

/*
 * jsonStatsGetPath
 *		Find JSON statistics for a given path.
 *
 * 'path' is an array of text datums of length 'pathlen' (can be zero).
 */
static JsonPathStats
jsonStatsGetPath(JsonStats jsdata, Datum *path, int pathlen,
				 bool try_arrays_indexes, float4 *nullfrac)
{
	JsonPathStats pstats = jsonStatsGetRootPath(jsdata);
	Selectivity	sel = 1.0;

	for (int i = 0; pstats && i < pathlen; i++)
	{
		char	   *key = TextDatumGetCString(path[i]);
		char	   *tail;
		int			index;

		if (!try_arrays_indexes)
		{
			/* Find object key stats */
			pstats = jsonPathStatsGetSubpath(pstats, key);
			pfree(key);
			continue;
		}

		/* Try to interpret path entry as integer array index */
		errno = 0;
		index = strtoint(key, &tail, 10);

		if (tail == key || *tail != '\0' || errno != 0)
		{
			/* Find object key stats */
			pstats = jsonPathStatsGetSubpath(pstats, key);
		}
		else
		{
			/* Find array index stats */
			/* FIXME consider object key "index" also */
			JsonPathStats arrstats = jsonPathStatsGetSubpath(pstats, NULL);

			if (arrstats)
			{
				float4		arrfreq = jsonPathStatsGetFreq(pstats, 0.0);

				sel *= jsonPathStatsGetArrayIndexSelectivity(pstats, index);

				if (arrfreq > 0.0)
					sel /= arrfreq;
			}

			pstats = arrstats;
		}

		pfree(key);
	}

	*nullfrac = 1.0 - sel;

	return pstats;
}

/*
 * jsonPathStatsGetNextSubpathStats
 *		Iterate all collected subpaths of a given path.
 *
 * This function can be useful for estimation of selectivity of jsonpath
 * '.*' and  '.**' operators.
 *
 * The next found subpath is written into *pkeystats, which should be set to
 * NULL before the first call.
 *
 * If keysOnly is true, emit only top-level object-key subpaths.
 *
 * Returns false on the end of iteration and true otherwise.
 */
bool
jsonPathStatsGetNextSubpathStats(JsonPathStats stats, JsonPathStats *pkeystats,
								 bool keysOnly)
{
	JsonPathStats keystats = *pkeystats;
	/* compute next index */
	int			index =
		(keystats ? keystats->datum : stats->datum) - stats->data->pathdatums + 1;

	if (stats->type != JsonPathStatsValues)
		return false;	/* length stats doe not have subpaths */

	for (; index < stats->data->npaths; index++)
	{
		Datum	   *pathdatum = &stats->data->pathdatums[index];
		const char *path;
		int			pathlen;

		keystats = &stats->data->paths[index];

		if (!jsonPathStatsGetPath(keystats, *pathdatum, &path, &pathlen))
			break;	/* invalid path stats */

		/* Break, if subpath does not start from a desired prefix */
		if (pathlen <= stats->pathlen ||
			memcmp(path, stats->path, stats->pathlen))
			break;

		if (keysOnly)
		{
			const char *c = &path[stats->pathlen];

			if (*c == '[')
			{
				Assert(c[1] == '*' && c[2] == ']');

#if 0	/* TODO add separate flag for requesting top-level array accessors */
				/* skip if it is not last key in the path */
				if (pathlen > stats->pathlen + 3)
#endif
					continue;	/* skip array accessors */
			}
			else if (*c == '.')
			{
				/* find end of '."key"' */
				const char *pathend = path + pathlen;

				if (++c >= pathend || *c != '"')
					break;		/* invalid path */

				while (++c <= pathend && *c != '"')
					if (*c == '\\')	/* handle escaped chars */
						c++;

				if (c > pathend)
					break;		/* invalid path */

				/* skip if it is not last key in the path */
				if (c < pathend)
					continue;
			}
			else
				continue;	/* invalid path */
		}

		/* Init path stats if needed */
		if (!stats->data)
		{
			keystats->data = stats->data;
			keystats->datum = pathdatum;
			keystats->type = JsonPathStatsValues;
		}

		*pkeystats = keystats;

		return true;
	}

	return false;
}

/*
 * jsonStatsConvertArray
 *		Convert a JSONB array into an array of some regular data type.
 *
 * The "type" identifies what elements are in the input JSONB array, while
 * typid determines the target type.
 */
static Datum
jsonStatsConvertArray(Datum jsonbValueArray, JsonStatType type, Oid typid,
					  float4 multiplier)
{
	Datum	   *values;
	Jsonb	   *jbvals;
	JsonbValue	jbv;
	JsonbIterator *it;
	JsonbIteratorToken r;
	int			nvalues;
	int			i;
	int16		typlen;
	bool		typbyval;
	char		typalign;

	if (!DatumGetPointer(jsonbValueArray))
		return PointerGetDatum(NULL);

	jbvals = DatumGetJsonbP(jsonbValueArray);

	nvalues = JsonContainerSize(&jbvals->root);

	values = palloc(sizeof(Datum) * nvalues);

	for (i = 0, it = JsonbIteratorInit(&jbvals->root);
		(r = JsonbIteratorNext(&it, &jbv, true)) != WJB_DONE;)
	{
		if (r == WJB_ELEM)
		{
			Datum value;

			switch (type)
			{
				case JsonStatJsonb:
				case JsonStatJsonbWithoutSubpaths:
					value = JsonbPGetDatum(JsonbValueToJsonb(&jbv));
					break;

				case JsonStatText:
				case JsonStatString:
					Assert(jbv.type == jbvString);
					value = PointerGetDatum(
								cstring_to_text_with_len(jbv.val.string.val,
														 jbv.val.string.len));
					break;

				case JsonStatNumeric:
					Assert(jbv.type == jbvNumeric);
					value = NumericGetDatum(jbv.val.numeric);
					break;

				case JsonStatFloat4:
					Assert(jbv.type == jbvNumeric);
					value = DirectFunctionCall1(numeric_float4,
												NumericGetDatum(jbv.val.numeric));
					value = Float4GetDatum(DatumGetFloat4(value) * multiplier);
					break;

				default:
					elog(ERROR, "invalid json stat type %d", type);
					value = (Datum) 0;
					break;
			}

			Assert(i < nvalues);
			values[i++] = value;
		}
	}

	Assert(i == nvalues);

	get_typlenbyvalalign(typid, &typlen, &typbyval, &typalign);

	return PointerGetDatum(
		construct_array(values, nvalues, typid, typlen, typbyval, typalign));
}

/*
 * jsonPathStatsExtractData
 *		Extract pg_statistics values from statistics for a single path.
 *
 * Extract ordinary MCV, Histogram, Correlation slots for a requested stats
 * type. If requested stats for JSONB, include also transformed JSON slot for
 * a path and possibly for its subpaths.
 */
static bool
jsonPathStatsExtractData(JsonPathStats pstats, JsonStatType stattype,
						 float4 nullfrac, StatsData *statdata)
{
	Datum		data;
	Datum		nullf;
	Datum		dist;
	Datum		width;
	Datum		mcv;
	Datum		hst;
	Datum		corr;
	Oid			type;
	Oid			eqop;
	Oid			ltop;
	const char *key;
	StatsSlot  *slot = statdata->slots;

	nullfrac = 1.0 - (1.0 - pstats->data->nullfrac) * (1.0 - nullfrac);

	/*
	 * Depending on requested statistics type, select:
	 *	- stavalues data type
	 *	- corresponding eq/lt operators
	 *	- JSONB field, containing stats slots for this statistics type
	 */
	switch (stattype)
	{
		case JsonStatJsonb:
		case JsonStatJsonbWithoutSubpaths:
			key = pstats->type == JsonPathStatsArrayLength ? "array_length" :
				  pstats->type == JsonPathStatsObjectLength ? "object_length" :
				  "json";
			type = JSONBOID;
			eqop = JsonbEqOperator;
			ltop = JsonbLtOperator;
			break;
		case JsonStatText:
			key = "text";
			type = TEXTOID;
			eqop = TextEqualOperator;
			ltop = TextLessOperator;
			break;
		case JsonStatString:
			key = "string";
			type = TEXTOID;
			eqop = TextEqualOperator;
			ltop = TextLessOperator;
			break;
		case JsonStatNumeric:
			key = "numeric";
			type = NUMERICOID;
			eqop = NumericEqOperator;
			ltop = NumericLtOperator;
			break;
		case JsonStatFloat4:	/* special internal stats type */
		default:
			elog(ERROR, "invalid json statistic type %d", stattype);
			break;
	}

	/* Extract object containing slots */
	data = jsonGetField(*pstats->datum, key);

	if (!DatumGetPointer(data))
		return false;

	nullf = jsonGetField(data, "nullfrac");
	dist = jsonGetField(data, "distinct");
	width = jsonGetField(data, "width");
	mcv = jsonGetField(data, "mcv");
	hst = jsonGetField(data, "histogram");
	corr = jsonGetField(data, "correlation");

	statdata->nullfrac = jsonGetFloat4(nullf, 0);
	statdata->distinct = jsonGetFloat4(dist, 0);
	statdata->width = (int32) jsonGetFloat4(width, 0);

	statdata->nullfrac += (1.0 - statdata->nullfrac) * nullfrac;

	/* Include MCV slot if exists */
	if (DatumGetPointer(mcv))
	{
		slot->kind = STATISTIC_KIND_MCV;
		slot->opid = eqop;
		slot->numbers = jsonStatsConvertArray(jsonGetField(mcv, "numbers"),
											  JsonStatFloat4, FLOAT4OID,
											  1.0 - nullfrac);
		slot->values  = jsonStatsConvertArray(jsonGetField(mcv, "values"),
											  stattype, type, 0);
		slot++;
	}

	/* Include Histogram slot if exists */
	if (DatumGetPointer(hst))
	{
		slot->kind = STATISTIC_KIND_HISTOGRAM;
		slot->opid = ltop;
		slot->numbers = jsonStatsConvertArray(jsonGetField(hst, "numbers"),
											  JsonStatFloat4, FLOAT4OID, 1.0);
		slot->values  = jsonStatsConvertArray(jsonGetField(hst, "values"),
											  stattype, type, 0);
		slot++;
	}

	/* Include Correlation slot if exists */
	if (DatumGetPointer(corr))
	{
		Datum		correlation = Float4GetDatum(jsonGetFloat4(corr, 0));

		slot->kind = STATISTIC_KIND_CORRELATION;
		slot->opid = ltop;
		slot->numbers = PointerGetDatum(construct_array(&correlation, 1,
														FLOAT4OID, 4, true,
														'i'));
		slot++;
	}

	/* Include JSON statistics for a given path and possibly for its subpaths */
	if ((stattype == JsonStatJsonb ||
		 stattype == JsonStatJsonbWithoutSubpaths) &&
		jsonAnalyzeBuildSubPathsData(pstats->data->pathdatums,
									 pstats->data->npaths,
									 pstats->datum - pstats->data->pathdatums,
									 pstats->path,
									 pstats->pathlen,
									 stattype == JsonStatJsonb,
									 nullfrac,
									 &slot->values,
									 &slot->numbers))
	{
		slot->kind = STATISTIC_KIND_JSON;
		slot++;
	}

	return true;
}

static float4
jsonPathStatsGetFloat(JsonPathStats pstats, const char *key, float4 defaultval)
{
	if (!pstats)
		return defaultval;

	return jsonGetFloat4(jsonGetField(*pstats->datum, key), defaultval);
}

float4
jsonPathStatsGetFreq(JsonPathStats pstats, float4 defaultfreq)
{
	return jsonPathStatsGetFloat(pstats, "freq", defaultfreq);
}

float4
jsonPathStatsGetAvgArraySize(JsonPathStats pstats)
{
	return jsonPathStatsGetFloat(pstats, "avg_array_length", 1.0);
}

/*
 * jsonPathStatsGetTypeFreq
 *		Get frequency of different JSON object types for a given path.
 *
 * JSON documents don't have any particular schema, and the same path may point
 * to values with different types in multiple documents. Consider for example
 * two documents {"a" : "b"} and {"a" : 100} which have both a string and int
 * for the same path. So we track the frequency of different JSON types for
 * each path, so that we can consider this later.
 */
float4
jsonPathStatsGetTypeFreq(JsonPathStats pstats, JsonbValueType type,
						 float4 defaultfreq)
{
	const char *key;

	if (!pstats)
		return defaultfreq;

	/*
	 * When dealing with (object/array) length stats, we only really care about
	 * objects and arrays.
	 *
	 * Lengths are always numeric, so simply return 0 if requested frequency
	 * of non-numeric values.
	 */
	if (pstats->type == JsonPathStatsArrayLength)
	{
		if (type != jbvNumeric)
			return 0.0;

		return jsonPathStatsGetFloat(pstats, "freq_array", defaultfreq);
	}

	if (pstats->type == JsonPathStatsObjectLength)
	{
		if (type != jbvNumeric)
			return 0.0;

		return jsonPathStatsGetFloat(pstats, "freq_object", defaultfreq);
	}

	/* Which JSON type are we interested in? Pick the right freq_type key. */
	switch (type)
	{
		case jbvNull:
			key = "freq_null";
			break;
		case jbvString:
			key = "freq_string";
			break;
		case jbvNumeric:
			key = "freq_numeric";
			break;
		case jbvBool:
			key = "freq_boolean";
			break;
		case jbvObject:
			key = "freq_object";
			break;
		case jbvArray:
			key = "freq_array";
			break;
		default:
			elog(ERROR, "Invalid jsonb value type: %d", type);
			break;
	}

	return jsonPathStatsGetFloat(pstats, key, defaultfreq);
}

/*
 * jsonPathStatsFormTuple
 *		For a pg_statistic tuple representing JSON statistics.
 *
 * XXX Maybe it's a bit expensive to first build StatsData and then transform it
 * again while building the tuple. Could it be done in a single step? Would it be
 * more efficient? Not sure how expensive it actually is, though.
 */
static HeapTuple
jsonPathStatsFormTuple(JsonPathStats pstats, JsonStatType type, float4 nullfrac)
{
	StatsData	statdata;

	if (!pstats || !pstats->datum)
		return NULL;

	/*
	 * If it is the ordinary root path stats, there is no need to transform
	 * the tuple, it can be simply copied.
	 */
	if (pstats->datum == &pstats->data->pathdatums[0] &&
		pstats->type == JsonPathStatsValues)
		return heap_copytuple(pstats->data->statsTuple);

	MemSet(&statdata, 0, sizeof(statdata));

	if (!jsonPathStatsExtractData(pstats, type, nullfrac, &statdata))
		return NULL;

	return stats_form_tuple(&statdata);
}

/*
 * jsonStatsGetPathTuple
 *		Extract JSON statistics for a text[] path and form pg_statistics tuple.
 */
static HeapTuple
jsonStatsGetPathTuple(JsonStats jsdata, JsonStatType type,
					  Datum *path, int pathlen, bool try_arrays_indexes)
{
	float4			nullfrac;
	JsonPathStats	pstats = jsonStatsGetPath(jsdata, path, pathlen,
											  try_arrays_indexes, &nullfrac);

	return jsonPathStatsFormTuple(pstats, type, nullfrac);
}

/*
 * jsonStatsGetArrayIndexStatsTuple
 *		Extract JSON statistics for a array index and form pg_statistics tuple.
 */
static HeapTuple
jsonStatsGetArrayIndexStatsTuple(JsonStats jsdata, JsonStatType type, int32 index)
{
	/* Extract statistics for root array elements */
	JsonPathStats arrstats = jsonStatsGetRootArrayPath(jsdata);
	JsonPathStats rootstats;
	Selectivity	index_sel;

	if (!arrstats)
		return NULL;

	/* Compute relative selectivity of 'EXISTS($[index])' */
	rootstats = jsonStatsGetRootPath(jsdata);
	index_sel = jsonPathStatsGetArrayIndexSelectivity(rootstats, index);
	index_sel /= jsonPathStatsGetFreq(arrstats, 0.0);

	/* Form pg_statistics tuple, taking into account array index selectivity */
	return jsonPathStatsFormTuple(arrstats, type, 1.0 - index_sel);
}

/*
 * jsonStatsGetPathFreq
 *		Return frequency of a path (fraction of documents containing it).
 */
static float4
jsonStatsGetPathFreq(JsonStats jsdata, Datum *path, int pathlen,
					 bool try_array_indexes)
{
	float4		nullfrac;
	JsonPathStats pstats = jsonStatsGetPath(jsdata, path, pathlen,
											try_array_indexes, &nullfrac);
	float4		freq = (1.0 - nullfrac) * jsonPathStatsGetFreq(pstats, 0.0);

	CLAMP_PROBABILITY(freq);
	return freq;
}

/*
 * jsonbStatsVarOpConst
 *		Prepare optimizer statistics for a given operator, from JSON stats.
 *
 * This handles only OpExpr expressions, with variable and a constant. We get
 * the constant as is, and the variable is represented by statistics fetched
 * by get_restriction_variable().
 *
 * opid    - OID of the operator (input parameter)
 * resdata - pointer to calculated statistics for result of operator
 * vardata - statistics for the restriction variable
 * cnst    - constant from the operator expression
 *
 * Returns true when useful optimizer statistics have been calculated.
 */
static bool
jsonbStatsVarOpConst(Oid opid, VariableStatData *resdata,
					 const VariableStatData *vardata, Const *cnst)
{
	JsonStatData jsdata;
	JsonStatType statype = JsonStatJsonb;

	if (!jsonStatsInit(&jsdata, vardata))
		return false;

	switch (opid)
	{
		case JsonbObjectFieldTextOperator:
			statype = JsonStatText;
			/* FALLTHROUGH */
		case JsonbObjectFieldOperator:
		{
			if (cnst->consttype != TEXTOID)
			{
				jsonStatsRelease(&jsdata);
				return false;
			}

			resdata->statsTuple = jsonStatsGetPathTuple(&jsdata, statype,
														&cnst->constvalue, 1,
														false);
			break;
		}

		case JsonbArrayElementTextOperator:
			statype = JsonStatText;
			/* FALLTHROUGH */
		case JsonbArrayElementOperator:
		{
			if (cnst->consttype != INT4OID)
			{
				jsonStatsRelease(&jsdata);
				return false;
			}

			resdata->statsTuple =
				jsonStatsGetArrayIndexStatsTuple(&jsdata, statype,
												 DatumGetInt32(cnst->constvalue));
			break;
		}

		case JsonbExtractPathTextOperator:
			statype = JsonStatText;
			/* FALLTHROUGH */
		case JsonbExtractPathOperator:
		{
			Datum	   *path;
			bool	   *nulls;
			int			pathlen;
			bool		have_nulls = false;

			if (cnst->consttype != TEXTARRAYOID)
			{
				jsonStatsRelease(&jsdata);
				return false;
			}

			deconstruct_array(DatumGetArrayTypeP(cnst->constvalue), TEXTOID,
							  -1, false, 'i', &path, &nulls, &pathlen);

			for (int i = 0; i < pathlen; i++)
			{
				if (nulls[i])
				{
					have_nulls = true;
					break;
				}
			}

			if (!have_nulls)
				resdata->statsTuple = jsonStatsGetPathTuple(&jsdata, statype,
															path, pathlen,
															true);

			pfree(path);
			pfree(nulls);
			break;
		}

		default:
			jsonStatsRelease(&jsdata);
			return false;
	}

	if (!resdata->statsTuple)
		resdata->statsTuple = stats_form_tuple(NULL);	/* form all-NULL tuple */

	resdata->acl_ok = vardata->acl_ok;
	resdata->freefunc = heap_freetuple;
	Assert(resdata->rel == vardata->rel);
	Assert(resdata->atttype ==
		(statype == JsonStatJsonb ? JSONBOID :
		 statype == JsonStatText ? TEXTOID :
		 /* statype == JsonStatFreq */ BOOLOID));

	jsonStatsRelease(&jsdata);
	return true;
}

/*
 * jsonb_stats
 *		Statistics estimation procedure for JSONB data type.
 *
 * This only supports OpExpr expressions, with (Var op Const) shape.
 *
 * Var really can be a chain of OpExprs with derived statistics
 * (jsonb_column -> 'key1' -> key2'), because get_restriction_variable()
 * already handles this case.
 */
Datum
jsonb_stats(PG_FUNCTION_ARGS)
{
	PlannerInfo *root = (PlannerInfo *) PG_GETARG_POINTER(0);
	OpExpr	   *opexpr = (OpExpr *) PG_GETARG_POINTER(1);
	int			varRelid = PG_GETARG_INT32(2);
	VariableStatData *resdata	= (VariableStatData *) PG_GETARG_POINTER(3);
	VariableStatData vardata;
	Node	   *constexpr;
	bool		varonleft;

	/* should only be called for OpExpr expressions */
	Assert(IsA(opexpr, OpExpr));

	/* Is the expression simple enough? (Var op Const) or similar? */
	if (!get_restriction_variable(root, opexpr->args, varRelid,
								  &vardata, &constexpr, &varonleft))
		PG_RETURN_VOID();

	/* XXX Could we also get varonleft=false in useful cases? */
	if (IsA(constexpr, Const) && varonleft)
		jsonbStatsVarOpConst(opexpr->opno, resdata, &vardata,
							 (Const *) constexpr);

	ReleaseVariableStats(vardata);

	PG_RETURN_VOID();
}

/*
 * jsonSelectivity
 *		Use JSON statistics to estimate selectivity for (in)equalities.
 *
 * The statistics is represented as (arrays of) JSON values etc. so we
 * need to pass the right operators to the functions.
 */
Selectivity
jsonSelectivity(JsonPathStats stats, Datum scalar, Oid operator)
{
	VariableStatData vardata;
	Selectivity sel;

	if (!stats)
		return 0.0;

	vardata.atttype = JSONBOID;
	vardata.atttypmod = -1;
	vardata.isunique = false;
	vardata.rel = stats->data->rel;
	vardata.var = NULL;
	vardata.vartype = JSONBOID;
	vardata.acl_ok = stats->data->acl_ok;
	vardata.statsTuple = jsonPathStatsFormTuple(stats,
												JsonStatJsonbWithoutSubpaths, 0.0);

	if (operator == JsonbEqOperator)
		sel = var_eq_const(&vardata, operator, InvalidOid, scalar, false, true, false);
	else
		sel = scalarineqsel(NULL, operator,
							/* is it greater or greater-or-equal? */
							operator == JsonbGtOperator ||
							operator == JsonbGeOperator,
							/* is it equality? */
							operator == JsonbLeOperator ||
							operator == JsonbGeOperator,
							InvalidOid,
							&vardata, scalar, JSONBOID);

	if (vardata.statsTuple)
		heap_freetuple(vardata.statsTuple);

	return sel;
}

/*
 * jsonAccumulateSubPathSelectivity
 *		Transform absolute subpath selectivity into relative and accumulate it
 *		into parent path simply by multiplication of relative selectivities.
 */
static void
jsonAccumulateSubPathSelectivity(Selectivity subpath_abs_sel,
								 Selectivity path_freq,
								 Selectivity *path_relative_sel,
								 JsonPathStats array_path_stats)
{
	Selectivity sel = subpath_abs_sel / path_freq;	/* relative selectivity */

	/* XXX Try to take into account array length */
	if (array_path_stats)
		sel = 1.0 - pow(1.0 - sel,
						jsonPathStatsGetAvgArraySize(array_path_stats));

	/* Accumulate selectivity of subpath into parent path */
	*path_relative_sel *= sel;
}

/*
 * jsonSelectivityContains
 *		Estimate selectivity for containment operator on JSON.
 *
 * Iterate through query jsonb elements, build paths to its leaf elements,
 * calculate selectivies of 'path == scalar' in leaves, multiply relative
 * selectivities of subpaths at each path level, propagate computed
 * selectivities to the root.
 */
static Selectivity
jsonSelectivityContains(JsonStats stats, Jsonb *jb)
{
	JsonbValue		v;
	JsonbIterator  *it;
	JsonbIteratorToken r;
	StringInfoData	pathstr;	/* path string */
	struct Path					/* path stack entry */
	{
		struct Path *parent;	/* parent entry */
		int			len;		/* associated length of pathstr */
		Selectivity	freq;		/* absolute frequence of path */
		Selectivity	sel;		/* relative selectivity of subpaths */
		JsonPathStats stats;	/* statistics for the path */
		bool		is_array_accesor;	/* is it '[*]' ? */
	}			root,			/* root path entry */
			   *path = &root;	/* path entry stack */
	Selectivity	sel;			/* resulting selectivity */
	Selectivity	scalarSel;		/* selectivity of 'jsonb == scalar' */

	/* Initialize root path string */
	initStringInfo(&pathstr);
	appendBinaryStringInfo(&pathstr, stats->prefix, stats->prefixlen);

	/* Initialize root path entry */
	root.parent = NULL;
	root.len = pathstr.len;
	root.stats = jsonStatsFindPath(stats, pathstr.data, pathstr.len);
	root.freq = jsonPathStatsGetFreq(root.stats, 0.0);
	root.sel = 1.0;
	root.is_array_accesor = pathstr.data[pathstr.len - 1] == ']';

	/* Return 0, if NULL fraction is 1. */
	if (root.freq <= 0.0)
		return 0.0;

	/*
	 * Selectivity of query 'jsonb @> scalar' consists of  selectivities of
	 * 'jsonb == scalar' and 'jsonb[*] == scalar'.  Selectivity of
	 * 'jsonb[*] == scalar' will be computed in root.sel, but for
	 * 'jsonb == scalar' we need additional computation.
	 */
	if (JsonContainerIsScalar(&jb->root))
		scalarSel = jsonSelectivity(root.stats, JsonbPGetDatum(jb),
									JsonbEqOperator);
	else
		scalarSel = 0.0;

	it = JsonbIteratorInit(&jb->root);

	while ((r = JsonbIteratorNext(&it, &v, false)) != WJB_DONE)
	{
		switch (r)
		{
			case WJB_BEGIN_OBJECT:
			{
				struct Path *p;
				Selectivity freq =
					jsonPathStatsGetTypeFreq(path->stats, jbvObject, 0.0);

				/* If there are no objects, selectivity is 0. */
				if (freq <= 0.0)
					return 0.0;

				/*
				 * Push path entry for object keys, actual key names are
				 * appended later in WJB_KEY case.
				 */
				p = palloc(sizeof(*p));
				p->len = pathstr.len;
				p->parent = path;
				p->stats = NULL;
				p->freq = freq;
				p->sel = 1.0;
				p->is_array_accesor = false;
				path = p;
				break;
			}

			case WJB_BEGIN_ARRAY:
			{
				struct Path *p;
				JsonPathStats pstats;
				Selectivity freq;

				/*
				 * First, find stats for the parent path if needed, it will be
				 * used in jsonAccumulateSubPathSelectivity().
				 */
				if (!path->stats)
					path->stats = jsonStatsFindPath(stats, pathstr.data,
													pathstr.len);

				/* Appeend path string entry for array elements, get stats. */
				jsonPathAppendEntry(&pathstr, NULL);
				pstats = jsonStatsFindPath(stats, pathstr.data, pathstr.len);
				freq = jsonPathStatsGetFreq(pstats, 0.0);

				/* If there are no arrays, return 0 or scalar selectivity */
				if (freq <= 0.0)
					return scalarSel;

				/* Push path entry for array elements. */
				p = palloc(sizeof(*p));
				p->len = pathstr.len;
				p->parent = path;
				p->stats = pstats;
				p->freq = freq;
				p->sel = 1.0;
				p->is_array_accesor = true;
				path = p;
				break;
			}

			case WJB_END_OBJECT:
			case WJB_END_ARRAY:
			{
				struct Path *p = path;
				/* Absoulte selectivity of the path with its all subpaths */
				Selectivity abs_sel = p->sel * p->freq;

				/* Pop last path entry */
				path = path->parent;
				pfree(p);
				pathstr.len = path->len;
				pathstr.data[pathstr.len] = '\0';

				/* Accumulate selectivity into parent path */
				jsonAccumulateSubPathSelectivity(abs_sel, path->freq,
												 &path->sel,
												 path->is_array_accesor ?
												 path->parent->stats : NULL);
				break;
			}

			case WJB_KEY:
			{
				/* Remove previous key in the path string */
				pathstr.len = path->parent->len;
				pathstr.data[pathstr.len] = '\0';

				/* Append current key to path string */
				jsonPathAppendEntryWithLen(&pathstr, v.val.string.val,
										   v.val.string.len);
				path->len = pathstr.len;
				break;
			}

			case WJB_VALUE:
			case WJB_ELEM:
			{
				/*
				 * Extract statistics for a path.  Array elements share the
				 * same statistics that was extracted in WJB_BEGIN_ARRAY.
				 */
				JsonPathStats pstats = r == WJB_ELEM ? path->stats :
					jsonStatsFindPath(stats, pathstr.data, pathstr.len);
				Selectivity abs_sel;	/* Absolute selectivity of 'path == scalar' */

				if (pstats)
				{
					/* Make scalar jsonb datum and compute selectivity */
					Datum		scalar = JsonbPGetDatum(JsonbValueToJsonb(&v));

					abs_sel = jsonSelectivity(pstats, scalar, JsonbEqOperator);
				}
				else
					abs_sel = 0.0;

				/* Accumulate selectivity into parent path */
				jsonAccumulateSubPathSelectivity(abs_sel, path->freq,
												 &path->sel,
												 path->is_array_accesor ?
												 path->parent->stats : NULL);
				break;
			}

			default:
				break;
		}
	}

	/* Compute absolute selectivity for root, including raw scalar case. */
	sel = root.sel * root.freq + scalarSel;
	CLAMP_PROBABILITY(sel);
	return sel;
}

/*
 * jsonSelectivityExists
 *		Estimate selectivity for JSON "exists" operator.
 */
static Selectivity
jsonSelectivityExists(JsonStats stats, Datum key)
{
	JsonPathStats rootstats;
	JsonPathStats arrstats;
	JsonbValue	jbvkey;
	Datum		jbkey;
	Selectivity keysel;
	Selectivity scalarsel;
	Selectivity arraysel;
	Selectivity sel;

	JsonValueInitStringWithLen(&jbvkey,
							   VARDATA_ANY(key), VARSIZE_ANY_EXHDR(key));

	jbkey = JsonbPGetDatum(JsonbValueToJsonb(&jbvkey));

	keysel = jsonStatsGetPathFreq(stats, &key, 1, false);

	rootstats = jsonStatsGetRootPath(stats);
	scalarsel = jsonSelectivity(rootstats, jbkey, JsonbEqOperator);

	arrstats = jsonStatsGetRootArrayPath(stats);
	arraysel = jsonSelectivity(arrstats, jbkey, JsonbEqOperator);
	arraysel = 1.0 - pow(1.0 - arraysel,
						 jsonPathStatsGetAvgArraySize(rootstats));

	sel = keysel + scalarsel + arraysel;
	CLAMP_PROBABILITY(sel);
	return sel;
}

static Selectivity
jsonb_sel_internal(JsonStats stats, Oid operator, Const *cnst, bool varonleft)
{
	switch (operator)
	{
		case JsonbExistsOperator:
			if (!varonleft || cnst->consttype != TEXTOID)
				break;

			return jsonSelectivityExists(stats, cnst->constvalue);

		case JsonbExistsAnyOperator:
		case JsonbExistsAllOperator:
		{
			Datum	   *keys;
			bool	   *nulls;
			Selectivity	freq = 1.0;
			int			nkeys;
			int			i;
			bool		all = operator == JsonbExistsAllOperator;

			if (!varonleft || cnst->consttype != TEXTARRAYOID)
				break;

			deconstruct_array(DatumGetArrayTypeP(cnst->constvalue), TEXTOID,
							  -1, false, 'i', &keys, &nulls, &nkeys);

			for (i = 0; i < nkeys; i++)
				if (!nulls[i])
				{
					Selectivity pathfreq = jsonSelectivityExists(stats,
																 keys[i]);
					freq *= all ? pathfreq : (1.0 - pathfreq);
				}

			pfree(keys);
			pfree(nulls);

			if (!all)
				freq = 1.0 - freq;

			return freq;
		}

		case JsonbContainedOperator:
			if (varonleft || cnst->consttype != JSONBOID)
				break;

			return jsonSelectivityContains(stats,
										   DatumGetJsonbP(cnst->constvalue));

		case JsonbContainsOperator:
			if (!varonleft || cnst->consttype != JSONBOID)
				break;

			return jsonSelectivityContains(stats,
										   DatumGetJsonbP(cnst->constvalue));

		default:
			break;
	}

	return DEFAULT_JSON_CONTAINS_SEL;
}

/*
 * jsonb_sel
 *		The main procedure estimating selectivity for all JSONB operators.
 */
Datum
jsonb_sel(PG_FUNCTION_ARGS)
{
	PlannerInfo *root = (PlannerInfo *) PG_GETARG_POINTER(0);
	Oid			operator = PG_GETARG_OID(1);
	List	   *args = (List *) PG_GETARG_POINTER(2);
	int			varRelid = PG_GETARG_INT32(3);
	double		sel = DEFAULT_JSON_CONTAINS_SEL;
	Node	   *other;
	bool		varonleft;
	VariableStatData vardata;

	if (get_restriction_variable(root, args, varRelid,
								  &vardata, &other, &varonleft))
	{
		if (IsA(other, Const))
		{
			Const	   *cnst = (Const *) other;

			if (cnst->constisnull)
				sel = 0.0;
			else
			{
				JsonStatData stats;

				if (jsonStatsInit(&stats, &vardata))
				{
					sel = jsonb_sel_internal(&stats, operator, cnst, varonleft);
					jsonStatsRelease(&stats);
				}
			}
		}

		ReleaseVariableStats(vardata);
	}

	PG_RETURN_FLOAT8((float8) sel);
}
