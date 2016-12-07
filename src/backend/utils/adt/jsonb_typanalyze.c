/*-------------------------------------------------------------------------
 *
 * jsonb_typanalyze.c
 *	  Functions for gathering statistics from jsonb columns
 *
 * Copyright (c) 2016, PostgreSQL Global Development Group
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
#include "utils/syscache.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"

typedef struct JsonPathEntry JsonPathEntry;

struct JsonPathEntry
{
	JsonPathEntry  *parent;
	const char	   *entry;
	int				len;
	uint32			hash;
};

typedef JsonPathEntry *JsonPath;

typedef struct JsonValues
{
	Datum	   *buf;
	int			count;
	int			allocated;
} JsonValues;

typedef struct JsonScalarStats
{
	JsonValues		values;
	VacAttrStats	stats;
} JsonScalarStats;

typedef struct JsonValueStats
{
	JsonScalarStats	jsons;
	JsonScalarStats	strings;
	JsonScalarStats	numerics;
	struct
	{
		int		ntrue;
		int		nfalse;
	}				booleans;
	int				nnulls;
	int				nobjects;
	int				narrays;
	JsonScalarStats	lens;
	JsonScalarStats	arrlens;
} JsonValueStats;

typedef struct JsonPathAnlStats
{
	JsonPathEntry		path;
	JsonValueStats		vstats;
	Jsonb			   *stats;
	char			   *pathstr;
	double				freq;
	int					depth;
	JsonPathCollectStatus	collected;

	JsonPathEntry	  **entries;
	int					nentries;
} JsonPathAnlStats;

typedef struct JsonAnalyzeContext
{
	VacAttrStats		   *stats;
	MemoryContext			mcxt;
	AnalyzeAttrFetchFunc	fetchfunc;
	HTAB				   *pathshash;
	JsonPathAnlStats	   *root;
	JsonPathAnlStats	  **paths;
	const char			  **collectedPaths;
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

static int
JsonPathMatch(const void *key1, const void *key2, Size keysize)
{
	const JsonPathEntry *path1 = key1;
	const JsonPathEntry *path2 = key2;

	return path1->parent != path2->parent ||
		   path1->len != path2->len ||
		   (path1->len > 0 &&
			strncmp(path1->entry, path2->entry, path1->len));
}

static uint32
JsonPathHash(const void *key, Size keysize)
{
	const JsonPathEntry	   *path = key;
	uint32					hash = path->parent ? path->parent->hash : 0;

	hash = (hash << 1) | (hash >> 31);
	hash ^= path->len < 0 ? 0 : DatumGetUInt32(
					hash_any((const unsigned char *) path->entry, path->len));

	return hash;
}

static inline void
jsonAnalyzeReportInvalidPath(const char *path)
{
	elog(ERROR, "invalid json path '%s'", path);
}

static inline const char *
jsonAnalyzeNormalizePathEntry(StringInfo str, const char *c)
{
	if (*c == '$' || *c == '.')
		return NULL;

	if (*c == '*' || *c == '%' || *c == '#')
	{
		appendStringInfoCharMacro(str, *c);
		return *c != '#' && c[1] ? NULL : c + 1;
	}

	appendStringInfoCharMacro(str, '"');

	if (*c == '"')
	{
		for (c++; *c && *c != '"'; c++)
		{
			if (*c == '\\')
			{
				appendStringInfoCharMacro(str, '\\');
				if (!*c++)
					return NULL;
			}
			appendStringInfoCharMacro(str, *c);
		}

		if (*c++ != '"')
			return NULL;
	}
	else
	{
		for (; *c && *c != '.'; c++)
			if (isalnum(*c) || *c == '_')
				appendStringInfoCharMacro(str, *c);
			else
				return NULL;
	}

	appendStringInfoCharMacro(str, '"');

	return c;
}

static char *
jsonAnalyzeNormalizePath(const char *path)
{
	StringInfoData	str;
	const char	   *c;

	str.maxlen = strlen(path) + 10;
	str.data = (char *) palloc(str.maxlen);

	resetStringInfo(&str);

	c = path;

	if (*c == '$')
	{
		c++;
		if (*c && *c++ != '.')
			jsonAnalyzeReportInvalidPath(path);
	}

	appendStringInfoCharMacro(&str, '$');

	while (*c)
	{
		appendStringInfoCharMacro(&str, '.');

		if (!(c = jsonAnalyzeNormalizePathEntry(&str, c)))
			jsonAnalyzeReportInvalidPath(path);

		if (*c)
		{
			if (c[0] != '.' || !c[1])
				jsonAnalyzeReportInvalidPath(path);
			c++;
		}
	}

	return str.data;
}

typedef enum
{
	JSPM_NOT_MATCHED,
	JSPM_MATCHED,
	JSPM_SUPERPATH,
} JsonPathMatchResult;

static JsonPathMatchResult
jsonAnalyzeComparePath(const char *pattern, const char *path, int pathlen)
{
	const char	   *c1;
	const char	   *c2;
	const char	   *c2end = path + pathlen;
	bool			entry = false;

	for (c1 = pattern, c2 = path; *c1 && c2 < c2end && *c1 == *c2; c1++, c2++)
	{
		if (*c1 == '"')
			entry ^= true;
		else if (entry && *c1 == '\\' && *++c1 != *++c2)
			break;
	}

	if (entry)
		return JSPM_NOT_MATCHED;

	if (!*c1)
		return c2 < c2end ? JSPM_NOT_MATCHED : JSPM_MATCHED;

	if (*c1 == '*')
		return JSPM_MATCHED;

	if (c1[0] == '.' && c1[1] == '*' && c2 >= c2end)
		return JSPM_MATCHED;

	if (*c1 == '%')
	{
		if (*c2++ != '"')
			return JSPM_NOT_MATCHED;

		while (c2 < c2end && *c2 != '"')
		{
			if (*c2 == '\\')
				c2++;
			c2++;
		}

		return *c2 == '"' && c2 == c2end ? JSPM_MATCHED : JSPM_NOT_MATCHED;
	}

	if (*c1 == '.' && c2 == c2end)
		return JSPM_SUPERPATH;

	return JSPM_NOT_MATCHED;
}

JsonPathCollectStatus
jsonAnalyzePathIsCollected(const char **paths, const char *path, int pathlen)
{
	const char			  **ppath;
	JsonPathCollectStatus	result = JSPCS_NOT_COLLECTED;

	for (ppath = paths; *ppath; ppath++)
	{
		switch (jsonAnalyzeComparePath(*ppath, path, pathlen))
		{
			case JSPM_NOT_MATCHED:
				break;
			case JSPM_MATCHED:
				return JSPCS_COLLECTED;
			case JSPM_SUPERPATH:
				result = JSPCS_COLLECTED_SUPERPATH;
				break;
		}
	}

	return result;
}

static inline JsonPathAnlStats *
jsonAnalyzeAddPath(JsonAnalyzeContext *ctx, JsonPath path)
{
	JsonPathAnlStats   *stats;
	bool				found;

	path->hash = JsonPathHash(path, 0);

	stats = hash_search_with_hash_value(ctx->pathshash, path, path->hash,
										HASH_ENTER, &found);

	if (!found)
	{
		JsonPathAnlStats   *parent = (JsonPathAnlStats *) stats->path.parent;
		const char		   *ppath = parent->pathstr;

		path = &stats->path;

		if (path->len >= 0)
		{
			StringInfoData	si;
			MemoryContext	oldcxt = MemoryContextSwitchTo(ctx->mcxt);

			initStringInfo(&si);

			path->entry = pnstrdup(path->entry, path->len);

			appendStringInfo(&si, "%s.", ppath);
			escape_json(&si, path->entry);

			stats->pathstr = si.data;

			MemoryContextSwitchTo(oldcxt);
		}
		else
		{
			int pathstrlen = strlen(ppath) + 3;
			stats->pathstr = MemoryContextAlloc(ctx->mcxt, pathstrlen);
			snprintf(stats->pathstr, pathstrlen, "%s.#", ppath);
		}

		memset(&stats->vstats, 0, sizeof(JsonValueStats));
		stats->stats = NULL;
		stats->freq = 0.0;
		stats->depth = parent->depth + 1;
		stats->entries = NULL;
		stats->nentries = 0;

		if (stats->depth > ctx->maxdepth)
			ctx->maxdepth = stats->depth;

		stats->collected = jsonAnalyzePathIsCollected(ctx->collectedPaths,
													  stats->pathstr,
													  strlen(stats->pathstr));
	}

	return stats;
}

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

static inline void
jsonAnalyzeJsonValue(JsonAnalyzeContext *ctx, JsonPathAnlStats *stats,
					 JsonbValue *jv)
{
	JsonValueStats	   *vstats = &stats->vstats;
	JsonScalarStats	   *sstats;
	JsonbValue		   *jbv;
	JsonbValue			jbvtmp;
	Datum				value;

	if (stats->collected == JSPCS_NOT_COLLECTED)
		return;

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

	if (stats->collected == JSPCS_COLLECTED)
		JsonValuesAppend(&vstats->jsons.values,
						JsonbPGetDatum(JsonbValueToJsonb(jbv)),
						ctx->target);
	else
		vstats->jsons.values.count++;

	switch (jv->type)
	{
		case jbvNull:
			++vstats->nnulls;
			return;

		case jbvBool:
			++*(jv->val.boolean ? &vstats->booleans.ntrue
								: &vstats->booleans.nfalse);
			return;

		case jbvString:
#ifdef JSON_ANALYZE_SCALARS
			sstats = &vstats->strings;
			value = PointerGetDatum(
						cstring_to_text_with_len(jv->val.string.val,
												 jv->val.string.len));
			break;
#else
			vstats->strings.values.count++;
			return;
#endif

		case jbvNumeric:
#ifdef JSON_ANALYZE_SCALARS
			sstats = &vstats->numerics;
			value = PointerGetDatum(jv->val.numeric);
			break;
#else
			vstats->numerics.values.count++;
			return;
#endif

		case jbvBinary:
			if (JsonContainerIsObject(jv->val.binary.data))
			{
				uint32 size = JsonContainerSize(jv->val.binary.data);
				value = DatumGetInt32(size);
				sstats = &vstats->lens;
				vstats->nobjects++;
				break;
			}
			else if (JsonContainerIsArray(jv->val.binary.data))
			{
				uint32 size = JsonContainerSize(jv->val.binary.data);
				value = DatumGetInt32(size);
				sstats = &vstats->lens;
				vstats->narrays++;
				JsonValuesAppend(&vstats->arrlens.values, value, ctx->target);
				break;
			}
			return;

		default:
			elog(ERROR, "invalid scalar json value type %d", jv->type);
			break;
	}

	if (stats->collected == JSPCS_COLLECTED)
		JsonValuesAppend(&sstats->values, value, ctx->target);
}

static void
jsonAnalyzeJson(JsonAnalyzeContext *ctx, Jsonb *jb, void *param)
{
	JsonbValue			jv;
	JsonbIterator	   *it;
	JsonbIteratorToken	tok;
	JsonPathAnlStats   *target = (JsonPathAnlStats *) param;
	JsonPathAnlStats   *stats = ctx->root;
	JsonPath			path = &stats->path;
	JsonPathEntry		entry;
	bool				scalar = false;

	if ((!target || target == stats) &&
		!JB_ROOT_IS_SCALAR(jb))
		jsonAnalyzeJsonValue(ctx, stats, JsonValueInitBinary(&jv, jb));

	it = JsonbIteratorInit(&jb->root);

	while ((tok = JsonbIteratorNext(&it, &jv, true)) != WJB_DONE)
	{
		switch (tok)
		{
			case WJB_BEGIN_OBJECT:
				entry.entry = NULL;
				entry.len = -1;
				entry.parent = path;
				path = &entry;

				break;

			case WJB_END_OBJECT:
				stats = (JsonPathAnlStats *)(path = path->parent);
				break;

			case WJB_BEGIN_ARRAY:
				if (!(scalar = jv.val.array.rawScalar))
				{
					entry.entry = NULL;
					entry.len = -1;
					entry.parent = path;
					path = &(stats = jsonAnalyzeAddPath(ctx, &entry))->path;
				}
				break;

			case WJB_END_ARRAY:
				if (!scalar)
					stats = (JsonPathAnlStats *)(path = path->parent);
				break;

			case WJB_KEY:
				entry.entry = jv.val.string.val;
				entry.len = jv.val.string.len;
				entry.parent = path->parent;
				path = &(stats = jsonAnalyzeAddPath(ctx, &entry))->path;
				break;

			case WJB_VALUE:
			case WJB_ELEM:
				if (!target || target == stats)
					jsonAnalyzeJsonValue(ctx, stats, &jv);

				if (stats->collected != JSPCS_NOT_COLLECTED &&
					jv.type == jbvBinary)
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

static void
jsonAnalyzeJsonSubpath(JsonAnalyzeContext *ctx, JsonPathAnlStats *pstats,
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

		if (entry->len == -1)
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
					jsonAnalyzeJsonSubpath(ctx, pstats, &elem, i + 1);
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

	jsonAnalyzeJsonValue(ctx, pstats, jbv);

	if (i > n)
		pfree(jbv);
}

static void
jsonAnalyzeJsonPath(JsonAnalyzeContext *ctx, Jsonb *jb, void *param)
{
	JsonPathAnlStats   *pstats = (JsonPathAnlStats *) param;
	JsonbValue			jbvtmp;
	JsonbValue		   *jbv = JsonValueInitBinary(&jbvtmp, jb);
	JsonPath			path;

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

	jsonAnalyzeJsonSubpath(ctx, pstats, jbv, 0);
}

static Datum
jsonAnalyzePathFetch(VacAttrStatsP stats, int rownum, bool *isnull)
{
	*isnull = false;
	return stats->exprvals[rownum];
}

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

	stats->stanullfrac = (float4)(1.0 - freq);

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
						   freq * vstats->strings.values.count /
								  vstats->jsons.values.count);

	pushJsonbKeyValueFloat(&ps, &val, "freq_numeric",
						   freq * vstats->numerics.values.count /
								  vstats->jsons.values.count);

	pushJsonbKeyValueFloat(&ps, &val, "freq_array",
						   freq * vstats->narrays /
								  vstats->jsons.values.count);

	pushJsonbKeyValueFloat(&ps, &val, "freq_object",
						   freq * vstats->nobjects /
								  vstats->jsons.values.count);

	if (pstats->vstats.lens.values.count)
		jsonAnalyzeMakeScalarStats(&ps, "length", &vstats->lens.stats);

	if (pstats->path.len == -1)
	{
		JsonPathAnlStats *parent = (JsonPathAnlStats *) pstats->path.parent;

		pushJsonbKeyValueFloat(&ps, &val, "avg_array_length",
							   (float4) vstats->jsons.values.count /
										parent->vstats.narrays);

		if (parent->vstats.arrlens.values.count)
			jsonAnalyzeMakeScalarStats(&ps, "array_length",
									   &parent->vstats.arrlens.stats);
	}

	if (full)
	{
		if (pstats->collected == JSPCS_COLLECTED)
		{
#ifdef JSON_ANALYZE_SCALARS
			jsonAnalyzeMakeScalarStats(&ps, "string", &vstats->strings.stats);
			jsonAnalyzeMakeScalarStats(&ps, "numeric", &vstats->numerics.stats);
#endif
			jsonAnalyzeMakeScalarStats(&ps, "json", &vstats->jsons.stats);
		}
		else
		{
			pushJsonbKey(&ps, &val, "json");
			pushJsonbValue(&ps, WJB_BEGIN_OBJECT, NULL);
			pushJsonbKeyValueFloat(&ps, &val, "nullfrac", 1.0 - pstats->freq);
			pushJsonbKeyValueFloat(&ps, &val, "distinct", 0.0);
			pushJsonbKeyValueInteger(&ps, &val, "width", 0.0);
			pushJsonbValue(&ps, WJB_END_OBJECT, NULL);
		}
	}

	jbv = pushJsonbValue(&ps, WJB_END_OBJECT, NULL);

	return JsonbValueToJsonb(jbv);
}

static void
jsonAnalyzeCalcPathFreq(JsonAnalyzeContext *ctx, JsonPathAnlStats *pstats)
{
	JsonPathAnlStats  *parent = (JsonPathAnlStats *) pstats->path.parent;

	if (parent)
	{
		pstats->freq = parent->freq *
			(pstats->path.len == -1 ? parent->vstats.narrays
									: pstats->vstats.jsons.values.count) /
			parent->vstats.jsons.values.count;

		CLAMP_PROBABILITY(pstats->freq);
	}
	else
		pstats->freq = (double) ctx->analyzed_cnt / ctx->samplerows;
}

static void
jsonAnalyzePath(JsonAnalyzeContext *ctx, JsonPathAnlStats *pstats)
{
	MemoryContext		oldcxt;

	jsonAnalyzeCalcPathFreq(ctx, pstats);

	if (pstats->collected == JSPCS_NOT_COLLECTED)
		return;

	if (pstats->collected == JSPCS_COLLECTED)
	{
		JsonValueStats	   *vstats = &pstats->vstats;

		jsonAnalyzePathValues(ctx, &vstats->jsons, JSONBOID, pstats->freq);
		jsonAnalyzePathValues(ctx, &vstats->lens, INT4OID,
							  pstats->freq * vstats->lens.values.count /
											 vstats->jsons.values.count);
		jsonAnalyzePathValues(ctx, &vstats->arrlens, INT4OID,
							  pstats->freq * vstats->arrlens.values.count /
											 vstats->jsons.values.count);
#ifdef JSON_ANALYZE_SCALARS
		jsonAnalyzePathValues(ctx, &vstats->strings, TEXTOID, pstats->freq);
		jsonAnalyzePathValues(ctx, &vstats->numerics, NUMERICOID, pstats->freq);
#endif
	}

	oldcxt = MemoryContextSwitchTo(ctx->stats->anl_context);
	pstats->stats = jsonAnalyzeBuildPathStats(pstats);
	MemoryContextSwitchTo(oldcxt);
}

static int
JsonPathStatsCompare(const void *pv1, const void *pv2)
{
	return strcmp((*((const JsonPathAnlStats **) pv1))->pathstr,
				  (*((const JsonPathAnlStats **) pv2))->pathstr);
}

static void
jsonAnalyzeSortPaths(JsonAnalyzeContext *ctx)
{
	HASH_SEQ_STATUS		hseq;
	JsonPathAnlStats   *path;
	int					i = 0;

	ctx->npaths = hash_get_num_entries(ctx->pathshash) + 1;
	ctx->paths = MemoryContextAlloc(ctx->mcxt,
									sizeof(*ctx->paths) * ctx->npaths);

	ctx->paths[i++] = ctx->root;

	hash_seq_init(&hseq, ctx->pathshash);

	while ((path = hash_seq_search(&hseq)))
		if (path->collected != JSPCS_NOT_COLLECTED)
			ctx->paths[i++] = path;

	ctx->npaths = i;

	pg_qsort(ctx->paths, ctx->npaths, sizeof(*ctx->paths),
			 JsonPathStatsCompare);
}

static void
jsonAnalyzePaths(JsonAnalyzeContext	*ctx)
{
	int	i;

	jsonAnalyzeSortPaths(ctx);

	for (i = 0; i < ctx->npaths; i++)
		jsonAnalyzePath(ctx, ctx->paths[i]);
}

static Datum
jsonAnalyzeBuildPathStatsHeader(const char *prefix, int prefixlen,
								const char **collectedPaths)
{
	JsonbParseState	   *ps = NULL;
	JsonbValue		   *res;
	JsonbValue			jbv;

	pushJsonbValue(&ps, WJB_BEGIN_OBJECT, NULL);

	pushJsonbKey(&ps, &jbv, "prefix");
	JsonValueInitStringWithLen(&jbv,
							   memcpy(palloc(prefixlen), prefix, prefixlen),
							   prefixlen);
	pushJsonbValue(&ps, WJB_VALUE, &jbv);

	pushJsonbKey(&ps, &jbv, "paths");
	pushJsonbValue(&ps, WJB_BEGIN_ARRAY, NULL);
	while (*collectedPaths)
		pushJsonbElemString(&ps, &jbv, *collectedPaths++);
	pushJsonbValue(&ps, WJB_END_ARRAY, NULL);

	res = pushJsonbValue(&ps, WJB_END_OBJECT, NULL);

	return JsonbPGetDatum(JsonbValueToJsonb(res));
}

static Datum *
jsonAnalyzeBuildPathStatsArray(JsonPathAnlStats **paths, int npaths, int *nvals,
								const char *prefix, int prefixlen,
								const char **collectedPaths)
{
	Datum	   *values = palloc(sizeof(Datum) * (npaths + 1));
	int			i;
	int			j = 0;

	values[j++] = jsonAnalyzeBuildPathStatsHeader(prefix, prefixlen,
												  collectedPaths);

	for (i = 0; i < npaths; i++)
		if (paths[i]->collected != JSPCS_NOT_COLLECTED)
			values[j++] = JsonbPGetDatum(paths[i]->stats);

	*nvals = j;

	return values;
}

static Datum *
jsonAnalyzeMakeStats(JsonAnalyzeContext *ctx, int *numvalues)
{
	Datum		   *values;
	MemoryContext	oldcxt = MemoryContextSwitchTo(ctx->stats->anl_context);

	values = jsonAnalyzeBuildPathStatsArray(ctx->paths, ctx->npaths,
											numvalues, "$", 1,
											ctx->collectedPaths);

	MemoryContextSwitchTo(oldcxt);

	return values;
}

bool
jsonAnalyzeBuildSubPathsData(Datum *pathsDatums, int npaths, int index,
							 const char	*path, int pathlen,
							 bool includeSubpaths, float4 nullfrac,
							 Datum *pvals, Datum *pnums,
							 const char **collectedPaths)
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
		pvalues[nsubpaths]->collected = JSPCS_COLLECTED;

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
											path, pathlen, collectedPaths);
	*pvals = PointerGetDatum(construct_array(values, nvalues, JSONBOID, -1,
											 false, 'i'));

	pfree(pvalues);
	pfree(values);

	numbers[0] = Float4GetDatum(nullfrac);
	*pnums = PointerGetDatum(construct_array(numbers, 1, FLOAT4OID, 4,
											 true /*FLOAT4PASSBYVAL*/, 'i'));

	return true;
}

static void
jsonInitCollectedPaths(JsonAnalyzeContext *ctx, VacAttrStats *stats)
{
	const char	  **collectedPaths = NULL;
	List		   *newPaths;
	HeapTuple		tuple = SearchSysCache3(STATRELATTINH,
										ObjectIdGetDatum(stats->attr->attrelid),
										Int16GetDatum(stats->attr->attnum),
										BoolGetDatum(false));

	if (HeapTupleIsValid(tuple))
	{
		VariableStatData	vardata;
		JsonStatData		jsdata;

		vardata.statsTuple = tuple;
		vardata.rel = NULL;

		if (jsonStatsInit(&jsdata, &vardata))
			collectedPaths = jsdata.collectedPaths;

		ReleaseSysCache(tuple);
	}

	newPaths = stats->options ? stats->options :
				collectedPaths ? NULL : list_make1("$");

	if (newPaths)
	{
		ListCell	   *lc;
		const char	  **p = collectedPaths;
		int				i = 0;
		Size			size;

		if (collectedPaths)
			while (*p++)
				i++;

		size = sizeof(char *) * (list_length(newPaths) + i + 1);

		collectedPaths = collectedPaths ? repalloc(collectedPaths, size)
										: palloc(size);

		foreach(lc, newPaths)
		{
			const char	   *path = jsonAnalyzeNormalizePath(lfirst(lc));
			int				j;

			for (j = 0; j < i; j++)
				if (!strcmp(collectedPaths[j], path))
					break;

			if (j >= i)
				collectedPaths[i++] = path;
		}

		collectedPaths[i] = NULL;
	}

	ctx->collectedPaths = collectedPaths;
}

static void
jsonAnalyzeInit(JsonAnalyzeContext *ctx, VacAttrStats *stats,
				AnalyzeAttrFetchFunc fetchfunc,
				int samplerows, double totalrows)
{
	HASHCTL			hash_ctl;

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
	hash_ctl.hash = JsonPathHash;
	hash_ctl.match = JsonPathMatch;
	hash_ctl.hcxt = ctx->mcxt;
	ctx->pathshash = hash_create("JSON analyze path table", 100, &hash_ctl,
					HASH_ELEM | HASH_FUNCTION | HASH_COMPARE | HASH_CONTEXT);

	ctx->root = MemoryContextAllocZero(ctx->mcxt, sizeof(JsonPathAnlStats));
	ctx->root->pathstr = "$";

	jsonInitCollectedPaths(ctx, stats);

	ctx->root->collected = jsonAnalyzePathIsCollected(ctx->collectedPaths,
													  ctx->root->pathstr,
													  strlen(ctx->root->pathstr));
}

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

	jsonAnalyzeInit(&ctx, stats, fetchfunc, samplerows, totalrows);

	if (false)
	{
		jsonAnalyzePass(&ctx, jsonAnalyzeJson, NULL);
		jsonAnalyzePaths(&ctx);
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

		jsonAnalyzePass(&ctx, jsonAnalyzeJson, (void *) -1);
		jsonAnalyzeSortPaths(&ctx);

		MemoryContextReset(tmpcxt);

		for (i = 0; i < ctx.npaths; i++)
		{
			JsonPathAnlStats *path = ctx.paths[i];

			if (path->collected == JSPCS_NOT_COLLECTED)
				continue;

			elog(DEBUG1, "analyzing json path (%d/%d) %s",
				 i + 1, ctx.npaths, path->pathstr);

			jsonAnalyzePass(&ctx, jsonAnalyzeJsonPath, path);
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

		stats->stats_valid = true;

		stats->stanullfrac	= jsstats->stanullfrac;
		stats->stawidth		= jsstats->stawidth;
		stats->stadistinct	= jsstats->stadistinct;

		for (i = 0; i < STATISTIC_NUM_SLOTS; i++)
		{
			if ((stats->stakind[i] = jsstats->stakind[i]))
			{
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
			else
			{
				stats->stakind[i] = STATISTIC_KIND_JSON;
				stats->staop[i] = InvalidOid;
				stats->numnumbers[i] = 1;
				stats->stanumbers[i] = MemoryContextAlloc(stats->anl_context,
														  sizeof(float4));
				stats->stanumbers[i][0] = 0.0; /* nullfrac */
				stats->stavalues[i] =
						jsonAnalyzeMakeStats(&ctx, &stats->numvalues[i]);

				/* We are storing jsonb values */
				stats->statypid[i] = JSONBOID;
				stats->statyplen[i] = -1;
				stats->statypbyval[i] = false;
				stats->statypalign[i] = 'i';
				break;
			}
		}
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
