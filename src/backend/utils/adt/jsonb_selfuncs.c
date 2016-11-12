/*-------------------------------------------------------------------------
 *
 * jsonb_selfuncs.c
 *	  Functions for selectivity estimation of jsonb operators
 *
 * Copyright (c) 2016, PostgreSQL Global Development Group
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
#include "nodes/primnodes.h"
#include "utils/builtins.h"
#include "utils/json.h"
#include "utils/jsonb.h"
#include "utils/json_selfuncs.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/selfuncs.h"

#define DEFAULT_JSON_CONTAINS_SEL	0.001

static inline Datum
jsonGetField(Datum obj, const char *field)
{
	Jsonb 	   *jb = DatumGetJsonbP(obj);
	JsonbValue *jbv = findJsonbValueFromContainerLen(&jb->root, JB_FOBJECT,
													 field, strlen(field));
	return jbv ? JsonbPGetDatum(JsonbValueToJsonb(jbv)) : PointerGetDatum(NULL);
}

static inline Datum
jsonGetFloat4(Datum jsonb)
{
	Jsonb	   *jb = DatumGetJsonbP(jsonb);
	JsonbValue	jv;

	JsonbExtractScalar(&jb->root, &jv);
	Assert(jv.type == jbvNumeric);

	return DirectFunctionCall1(numeric_float4, NumericGetDatum(jv.val.numeric));
}

bool
jsonStatsInit(JsonStats data, const VariableStatData *vardata)
{
	Jsonb	   *jb;
	JsonbValue	prefix;

	memset(&data->attslot, 0, sizeof(data->attslot));
	data->statsTuple = vardata->statsTuple;

	if (!data->statsTuple)
		return false;

	if (((Form_pg_statistic) GETSTRUCT(data->statsTuple))->stanullfrac >= 1.0)
	{
		data->nullfrac = 1.0;
		return true;
	}

	if (!get_attstatsslot(&data->attslot, data->statsTuple,
						  STATISTIC_KIND_JSON, InvalidOid,
						  ATTSTATSSLOT_NUMBERS | ATTSTATSSLOT_VALUES))
		return false;

	if (data->attslot.nvalues < 2)
	{
		free_attstatsslot(&data->attslot);
		return false;
	}

	data->acl_ok = vardata->acl_ok;
	data->rel = vardata->rel;
	data->nullfrac =
		data->attslot.nnumbers > 0 ? data->attslot.numbers[0] : 0.0;
	data->values = data->attslot.values;
	data->nvalues = data->attslot.nvalues;

	jb = DatumGetJsonbP(data->values[0]);
	JsonbExtractScalar(&jb->root, &prefix);
	Assert(prefix.type == jbvString);
	data->prefix = prefix.val.string.val;
	data->prefixlen = prefix.val.string.len;

	return true;
}

void
jsonStatsRelease(JsonStats data)
{
	free_attstatsslot(&data->attslot);
}

static JsonPathStats
jsonPathStatsGetSpecialStats(JsonPathStats pstats, JsonPathStatsType type)
{
	JsonPathStats stats;

	if (!pstats)
		return NULL;

	stats = palloc(sizeof(*stats));
	*stats = *pstats;
	stats->path = memcpy(palloc(stats->pathlen), stats->path, stats->pathlen);
	stats->type = type;

	return stats;
}

JsonPathStats
jsonPathStatsGetLengthStats(JsonPathStats pstats)
{
	if (jsonPathStatsGetTypeFreq(pstats, jbvObject, 0.0) <= 0.0 &&
		jsonPathStatsGetTypeFreq(pstats, jbvArray, 0.0) <= 0.0)
		return NULL;

	return jsonPathStatsGetSpecialStats(pstats, JsonPathStatsLength);
}

static JsonPathStats
jsonPathStatsGetArrayLengthStats(JsonPathStats pstats)
{
	return jsonPathStatsGetSpecialStats(pstats, JsonPathStatsArrayLength);
}

static int
jsonPathStatsCompare(const void *pv1, const void *pv2)
{
	JsonbValue	pathkey;
	JsonbValue *path2;
	JsonbValue const *path1 = pv1;
	Datum const *pdatum = pv2;
	Jsonb	   *jsonb = DatumGetJsonbP(*pdatum);
	int			res;

	JsonValueInitStringWithLen(&pathkey, "path", 4);
	path2 = findJsonbValueFromContainer(&jsonb->root, JB_FOBJECT, &pathkey);

	if (!path2 || path2->type != jbvString)
		return 1;

	res = strncmp(path1->val.string.val, path2->val.string.val,
				  Min(path1->val.string.len, path2->val.string.len));

	return res ? res : path1->val.string.len - path2->val.string.len;
}

static JsonPathStats
jsonStatsFindPathStats(JsonStats jsdata, char *path, int pathlen)
{
	JsonPathStats stats;
	JsonbValue	jbvkey;
	Datum	   *pdatum;

	JsonValueInitStringWithLen(&jbvkey, path, pathlen);

	pdatum = bsearch(&jbvkey, jsdata->values + 1, jsdata->nvalues - 1,
					 sizeof(*jsdata->values), jsonPathStatsCompare);

	if (!pdatum)
		return NULL;

	stats = palloc(sizeof(*stats));
	stats->datum = pdatum;
	stats->data = jsdata;
	stats->path = path;
	stats->pathlen = pathlen;
	stats->type = JsonPathStatsValues;

	return stats;
}

JsonPathStats
jsonStatsGetPathStatsStr(JsonStats jsdata, const char *subpath, int subpathlen)
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

	stats = jsonStatsFindPathStats(jsdata, path, pathlen);

	if (!stats)
		pfree(path);

	return stats;
}

static void
jsonPathAppendEntry(StringInfo path, const char *entry)
{
	appendStringInfoCharMacro(path, '.');
	escape_json(path, entry);
}

static void
jsonPathAppendEntryWithLen(StringInfo path, const char *entry, int len)
{
	char *tmpentry = pnstrdup(entry, len);
	jsonPathAppendEntry(path, tmpentry);
	pfree(tmpentry);
}

JsonPathStats
jsonPathStatsGetSubpath(JsonPathStats pstats, const char *key, int keylen)
{
	JsonPathStats spstats;
	char	   *path;
	int			pathlen;

	if (key)
	{
		StringInfoData str;

		initStringInfo(&str);
		appendBinaryStringInfo(&str, pstats->path, pstats->pathlen);
		jsonPathAppendEntryWithLen(&str, key, keylen);

		path = str.data;
		pathlen = str.len;
	}
	else
	{
		pathlen = pstats->pathlen + 2;
		path = palloc(pathlen + 1);
		snprintf(path, pstats->pathlen + pathlen, "%.*s.#",
				 pstats->pathlen, pstats->path);
	}

	spstats = jsonStatsFindPathStats(pstats->data, path, pathlen);
	if (!spstats)
		pfree(path);

	return spstats;
}

Selectivity
jsonPathStatsGetArrayIndexSelectivity(JsonPathStats pstats, int index)
{
	JsonPathStats lenstats = jsonPathStatsGetArrayLengthStats(pstats);
	JsonbValue	tmpjbv;
	Jsonb	   *jb;

	if (!lenstats)
		return 1.0;

	jb = JsonbValueToJsonb(JsonValueInitInteger(&tmpjbv, index));

	return jsonSelectivity(lenstats, JsonbPGetDatum(jb), JsonbGtOperator);
}

static JsonPathStats
jsonStatsGetPathStats(JsonStats jsdata, Datum *pathEntries, int pathLen,
					  float4 *nullfrac)
{
	JsonPathStats pstats;
	Selectivity	sel = 1.0;
	int			i;

	if (!pathEntries && pathLen < 0)
	{
		if ((pstats = jsonStatsGetPathStatsStr(jsdata, "$.#", 3)))
		{
			sel = jsonPathStatsGetArrayIndexSelectivity(pstats, -1 - pathLen);
			sel /= jsonPathStatsGetFreq(pstats, 0.0);
		}
	}
	else
	{
		pstats = jsonStatsGetPathStatsStr(jsdata, "$", 1);

		for (i = 0; pstats && i < pathLen; i++)
		{
			char	   *key = text_to_cstring(DatumGetTextP(pathEntries[i]));
			int			keylen = strlen(key);

			if (key[0] >= '0' && key[0] <= '9' &&
				key[strspn(key, "0123456789")] == '\0')
			{
				char	   *tail;
				long		index;

				errno = 0;
				index = strtol(key, &tail, 10);

				if (*tail || errno || index > INT_MAX || index < 0)
					pstats = jsonPathStatsGetSubpath(pstats, key, keylen);
				else
				{
					float4	arrfreq;

					/* FIXME consider key also */
					pstats = jsonPathStatsGetSubpath(pstats, NULL, 0);
					sel *= jsonPathStatsGetArrayIndexSelectivity(pstats, index);
					arrfreq = jsonPathStatsGetFreq(pstats, 0.0);

					if (arrfreq > 0.0)
						sel /= arrfreq;
				}
			}
			else
				pstats = jsonPathStatsGetSubpath(pstats, key, keylen);

			pfree(key);
		}
	}

	*nullfrac = 1.0 - sel;

	return pstats;
}

bool
jsonPathStatsGetNextKeyStats(JsonPathStats stats, JsonPathStats *pkeystats,
							 bool keysOnly)
{
	JsonPathStats keystats = *pkeystats;
	int			index =
		(keystats ? keystats->datum : stats->datum) - stats->data->values + 1;

	for (; index < stats->data->nvalues; index++)
	{
		JsonbValue	pathkey;
		JsonbValue *jbvpath;
		Jsonb	   *jb = DatumGetJsonbP(stats->data->values[index]);

		JsonValueInitStringWithLen(&pathkey, "path", 4);
		jbvpath = findJsonbValueFromContainer(&jb->root, JB_FOBJECT, &pathkey);

		if (jbvpath->type != jbvString ||
			jbvpath->val.string.len <= stats->pathlen ||
			memcmp(jbvpath->val.string.val, stats->path, stats->pathlen))
			break;

		if (keysOnly)
		{
			const char *c = &jbvpath->val.string.val[stats->pathlen];

			Assert(*c == '.');
			c++;

			if (*c == '#')
			{
				if (keysOnly || jbvpath->val.string.len > stats->pathlen + 2)
					continue;
			}
			else
			{
				Assert(*c == '"');

				while (*++c != '"')
					if (*c == '\\')
						c++;

				if (c - jbvpath->val.string.val < jbvpath->val.string.len - 1)
					continue;
			}
		}

		if (!keystats)
			keystats = palloc(sizeof(*keystats));

		keystats->datum = &stats->data->values[index];
		keystats->data = stats->data;
		keystats->pathlen = jbvpath->val.string.len;
		keystats->path = memcpy(palloc(keystats->pathlen),
								jbvpath->val.string.val, keystats->pathlen);
		keystats->type = JsonPathStatsValues;

		*pkeystats = keystats;

		return true;
	}

	return false;
}

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

	return PointerGetDatum(
			construct_array(values, nvalues,
							typid,
							typid == FLOAT4OID ? 4 : -1,
							typid == FLOAT4OID ? true /* FLOAT4PASSBYVAL */ : false,
							'i'));
}

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

	switch (stattype)
	{
		case JsonStatJsonb:
		case JsonStatJsonbWithoutSubpaths:
			key = pstats->type == JsonPathStatsArrayLength ? "array_length" :
				  pstats->type == JsonPathStatsLength ? "length" : "json";
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
		default:
			elog(ERROR, "invalid json statistic type %d", stattype);
			break;
	}

	data = jsonGetField(*pstats->datum, key);

	if (!DatumGetPointer(data))
		return false;

	nullf = jsonGetField(data, "nullfrac");
	dist = jsonGetField(data, "distinct");
	width = jsonGetField(data, "width");
	mcv = jsonGetField(data, "mcv");
	hst = jsonGetField(data, "histogram");
	corr = jsonGetField(data, "correlation");

	statdata->nullfrac = DatumGetPointer(nullf) ?
							DatumGetFloat4(jsonGetFloat4(nullf)) : 0.0;
	statdata->distinct = DatumGetPointer(dist) ?
							DatumGetFloat4(jsonGetFloat4(dist)) : 0.0;
	statdata->width = DatumGetPointer(width) ?
							(int32) DatumGetFloat4(jsonGetFloat4(width)) : 0;

	statdata->nullfrac += (1.0 - statdata->nullfrac) * nullfrac;

	if (DatumGetPointer(mcv))
	{
		slot->kind = STATISTIC_KIND_MCV;
		slot->opid = eqop;
		slot->numbers = jsonStatsConvertArray(jsonGetField(mcv, "numbers"),
											  JsonStatNumeric, FLOAT4OID,
											  1.0 - nullfrac);
		slot->values  = jsonStatsConvertArray(jsonGetField(mcv, "values"),
											  stattype, type, 0);
		slot++;
	}

	if (DatumGetPointer(hst))
	{
		slot->kind = STATISTIC_KIND_HISTOGRAM;
		slot->opid = ltop;
		slot->numbers = jsonStatsConvertArray(jsonGetField(hst, "numbers"),
											  JsonStatNumeric, FLOAT4OID, 1.0);
		slot->values  = jsonStatsConvertArray(jsonGetField(hst, "values"),
											  stattype, type, 0);
		slot++;
	}

	if (DatumGetPointer(corr))
	{
		Datum	correlation = jsonGetFloat4(corr);
		slot->kind = STATISTIC_KIND_CORRELATION;
		slot->opid = ltop;
		slot->numbers = PointerGetDatum(construct_array(&correlation, 1,
														FLOAT4OID, 4, true,
														'i'));
		slot++;
	}

	if ((stattype == JsonStatJsonb ||
		 stattype == JsonStatJsonbWithoutSubpaths) &&
		jsonAnalyzeBuildSubPathsData(pstats->data->values,
									 pstats->data->nvalues,
									 pstats->datum - pstats->data->values,
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
jsonPathStatsGetFloat(JsonPathStats pstats, const char *key,
					float4 defaultval)
{
	Datum		freq;

	if (!pstats || !(freq = jsonGetField(*pstats->datum, key)))
		return defaultval;

	return DatumGetFloat4(jsonGetFloat4(freq));
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

float4
jsonPathStatsGetTypeFreq(JsonPathStats pstats, JsonbValueType type,
						 float4 defaultfreq)
{
	const char *key;

	if (!pstats)
		return defaultfreq;

	if (pstats->type == JsonPathStatsLength ||
		pstats->type == JsonPathStatsArrayLength)
	{
		if (type != jbvNumeric)
			return 0.0;

		return pstats->type == JsonPathStatsArrayLength
				? jsonPathStatsGetFreq(pstats, defaultfreq)
				: jsonPathStatsGetFloat(pstats, "freq_array", defaultfreq) +
				  jsonPathStatsGetFloat(pstats, "freq_object", defaultfreq);
	}

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

static HeapTuple
jsonPathStatsFormTuple(JsonPathStats pstats, JsonStatType type, float4 nullfrac)
{
	StatsData	statdata;

	if (!pstats || !pstats->datum)
		return NULL;

	if (pstats->datum == &pstats->data->values[1] &&
		pstats->type == JsonPathStatsValues)
		return heap_copytuple(pstats->data->statsTuple);

	MemSet(&statdata, 0, sizeof(statdata));

	if (!jsonPathStatsExtractData(pstats, type, nullfrac, &statdata))
		return NULL;

	return stats_form_tuple(&statdata);
}

static HeapTuple
jsonStatsGetPathStatsTuple(JsonStats jsdata, JsonStatType type,
						   Datum *path, int pathlen)
{
	float4			nullfrac;
	JsonPathStats	pstats = jsonStatsGetPathStats(jsdata, path, pathlen,
												   &nullfrac);

	return jsonPathStatsFormTuple(pstats, type, nullfrac);
}

static float4
jsonStatsGetPathFreq(JsonStats jsdata, Datum *path, int pathlen)
{
	float4			nullfrac;
	JsonPathStats	pstats = jsonStatsGetPathStats(jsdata, path, pathlen,
												   &nullfrac);
	float4			freq = (1.0 - nullfrac) * jsonPathStatsGetFreq(pstats, 0.0);

	CLAMP_PROBABILITY(freq);
	return freq;
}

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
			/* fall through */
		case JsonbObjectFieldOperator:
		{
			if (cnst->consttype != TEXTOID)
			{
				jsonStatsRelease(&jsdata);
				return false;
			}

			resdata->statsTuple =
				jsonStatsGetPathStatsTuple(&jsdata, statype,
										  &cnst->constvalue, 1);
			break;
		}

		case JsonbArrayElementTextOperator:
			statype = JsonStatText;
			/* fall through */
		case JsonbArrayElementOperator:
		{
			if (cnst->consttype != INT4OID)
			{
				jsonStatsRelease(&jsdata);
				return false;
			}

			resdata->statsTuple =
				jsonStatsGetPathStatsTuple(&jsdata, statype, NULL,
										   -1 - DatumGetInt32(cnst->constvalue));
			break;
		}

		case JsonbExtractPathTextOperator:
			statype = JsonStatText;
			/* fall through */
		case JsonbExtractPathOperator:
		{
			Datum	   *path;
			bool	   *nulls;
			int			pathlen;
			int			i;

			if (cnst->consttype != TEXTARRAYOID)
			{
				jsonStatsRelease(&jsdata);
				return false;
			}

			deconstruct_array(DatumGetArrayTypeP(cnst->constvalue), TEXTOID,
							  -1, false, 'i', &path, &nulls, &pathlen);

			for (i = 0; i < pathlen; i++)
			{
				if (nulls[i])
				{
					pfree(path);
					pfree(nulls);
					PG_RETURN_VOID();
				}
			}

			resdata->statsTuple =
				jsonStatsGetPathStatsTuple(&jsdata, statype, path, pathlen);

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

Datum
jsonb_stats(PG_FUNCTION_ARGS)
{
	PlannerInfo *root = (PlannerInfo *) PG_GETARG_POINTER(0);
	OpExpr	   *opexpr = (OpExpr *) PG_GETARG_POINTER(1);
	int			varRelid = PG_GETARG_INT32(2);
	VariableStatData *resdata	= (VariableStatData *) PG_GETARG_POINTER(3);
	VariableStatData vardata;
	Node	   *constexpr;
	bool		result;
	bool		varonleft;

	if (!get_restriction_variable(root, opexpr->args, varRelid,
								  &vardata, &constexpr, &varonleft))
		return false;

	result = IsA(constexpr, Const) && varonleft &&
		jsonbStatsVarOpConst(opexpr->opno, resdata, &vardata,
							 (Const *) constexpr);

	ReleaseVariableStats(vardata);

	return result;
}

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
							operator == JsonbGtOperator ||
							operator == JsonbGeOperator,
							operator == JsonbLeOperator ||
							operator == JsonbGeOperator,
							InvalidOid,
							&vardata, scalar, JSONBOID);

	if (vardata.statsTuple)
		heap_freetuple(vardata.statsTuple);

	return sel;
}

static Selectivity
jsonSelectivityContains(JsonStats stats, Jsonb *jb)
{
	JsonbValue		v;
	JsonbIterator  *it;
	JsonbIteratorToken r;
	StringInfoData	pathstr;
	struct Path
	{
		struct Path *parent;
		int			len;
		JsonPathStats stats;
		Selectivity	freq;
		Selectivity	sel;
	}			root,
			   *path = &root;
	Selectivity	scalarSel = 0.0;
	Selectivity	sel;
	bool		rawScalar = false;

	initStringInfo(&pathstr);

	appendStringInfo(&pathstr, "$");

	root.parent = NULL;
	root.len = pathstr.len;
	root.stats = jsonStatsGetPathStatsStr(stats, pathstr.data, pathstr.len);
	root.freq = jsonPathStatsGetFreq(root.stats, 0.0);
	root.sel = 1.0;

	if (root.freq <= 0.0)
		return 0.0;

	it = JsonbIteratorInit(&jb->root);

	while ((r = JsonbIteratorNext(&it, &v, false)) != WJB_DONE)
	{
		switch (r)
		{
			case WJB_BEGIN_OBJECT:
			{
				struct Path *p = palloc(sizeof(*p));

				p->len = pathstr.len;
				p->parent = path;
				p->stats = NULL;
				p->freq = jsonPathStatsGetTypeFreq(path->stats, jbvObject, 0.0);
				if (p->freq <= 0.0)
					return 0.0;
				p->sel = 1.0;
				path = p;
				break;
			}

			case WJB_BEGIN_ARRAY:
			{
				struct Path *p = palloc(sizeof(*p));

				rawScalar = v.val.array.rawScalar;

				appendStringInfo(&pathstr, ".#");
				p->len = pathstr.len;
				p->parent = path;
				p->stats = jsonStatsGetPathStatsStr(stats, pathstr.data,
													pathstr.len);
				p->freq = jsonPathStatsGetFreq(p->stats, 0.0);
				if (p->freq <= 0.0 && !rawScalar)
					return 0.0;
				p->sel = 1.0;
				path = p;

				break;
			}

			case WJB_END_OBJECT:
			case WJB_END_ARRAY:
			{
				struct Path *p = path;

				path = path->parent;
				sel = p->sel * p->freq / path->freq;
				pfree(p);
				pathstr.data[pathstr.len = path->len] = '\0';
				if (pathstr.data[pathstr.len - 1] == '#')
					sel = 1.0 - pow(1.0 - sel,
								jsonPathStatsGetAvgArraySize(path->stats));
				path->sel *= sel;
				break;
			}

			case WJB_KEY:
			{
				pathstr.data[pathstr.len = path->parent->len] = '\0';
				jsonPathAppendEntryWithLen(&pathstr, v.val.string.val,
										   v.val.string.len);
				path->len = pathstr.len;
				break;
			}

			case WJB_VALUE:
			case WJB_ELEM:
			{
				JsonPathStats	pstats = r == WJB_ELEM ? path->stats :
					jsonStatsGetPathStatsStr(stats, pathstr.data, pathstr.len);
				Datum			scalar = JsonbPGetDatum(JsonbValueToJsonb(&v));

				if (path->freq <= 0.0)
					sel = 0.0;
				else
				{
					sel = jsonSelectivity(pstats, scalar, JsonbEqOperator);
					sel /= path->freq;
					if (pathstr.data[pathstr.len - 1] == '#')
						sel = 1.0 - pow(1.0 - sel,
										jsonPathStatsGetAvgArraySize(path->stats));
				}

				path->sel *= sel;

				if (r == WJB_ELEM && path->parent == &root && rawScalar)
					scalarSel = jsonSelectivity(root.stats, scalar,
												JsonbEqOperator);
				break;
			}

			default:
				break;
		}
	}

	sel = scalarSel + root.sel * root.freq;
	CLAMP_PROBABILITY(sel);
	return sel;
}

static Selectivity
jsonSelectivityExists(JsonStats stats, Datum key)
{
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

	keysel = jsonStatsGetPathFreq(stats, &key, 1);

	scalarsel = jsonSelectivity(jsonStatsGetPathStatsStr(stats, "$", 1),
								jbkey, JsonbEqOperator);

	arrstats = jsonStatsGetPathStatsStr(stats, "$.#", 3);
	arraysel = jsonSelectivity(arrstats, jbkey, JsonbEqOperator);
	arraysel = 1.0 - pow(1.0 - arraysel,
						 jsonPathStatsGetAvgArraySize(arrstats));

	sel = keysel + scalarsel + arraysel;
	CLAMP_PROBABILITY(sel);
	return sel;
}

Datum
jsonb_sel(PG_FUNCTION_ARGS)
{
	PlannerInfo *root = (PlannerInfo *) PG_GETARG_POINTER(0);
	Oid			operator = PG_GETARG_OID(1);
	List	   *args = (List *) PG_GETARG_POINTER(2);
	int			varRelid = PG_GETARG_INT32(3);
	double		sel = DEFAULT_JSON_CONTAINS_SEL;
	Node	   *other;
	Const	   *cnst;
	bool		varonleft;
	JsonStatData stats;
	VariableStatData vardata;

	if (!get_restriction_variable(root, args, varRelid,
								  &vardata, &other, &varonleft))
		PG_RETURN_FLOAT8(sel);

	if (!IsA(other, Const))
		goto out;

	cnst = (Const *) other;

	if (cnst->constisnull)
	{
		sel = 0.0;
		goto out;
	}

	if (!jsonStatsInit(&stats, &vardata))
		goto out;

	switch (operator)
	{
		case JsonbExistsOperator:
			if (!varonleft || cnst->consttype != TEXTOID)
				goto out;

			sel = jsonSelectivityExists(&stats, cnst->constvalue);
			break;

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
				goto out;

			deconstruct_array(DatumGetArrayTypeP(cnst->constvalue), TEXTOID,
							  -1, false, 'i', &keys, &nulls, &nkeys);

			for (i = 0; i < nkeys; i++)
				if (!nulls[i])
				{
					Selectivity pathfreq = jsonSelectivityExists(&stats,
																 keys[i]);
					freq *= all ? pathfreq : (1.0 - pathfreq);
				}

			pfree(keys);
			pfree(nulls);

			if (!all)
				freq = 1.0 - freq;

			sel = freq;
			break;
		}

		case JsonbContainedOperator:
			/* TODO */
			break;

		case JsonbContainsOperator:
		{
			if (cnst->consttype != JSONBOID)
				goto out;

			sel = jsonSelectivityContains(&stats,
										  DatumGetJsonbP(cnst->constvalue));
			break;
		}
	}

out:
	jsonStatsRelease(&stats);
	ReleaseVariableStats(vardata);

	PG_RETURN_FLOAT8((float8) sel);
}
