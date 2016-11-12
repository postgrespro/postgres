/*-------------------------------------------------------------------------
 *
 * json_selfuncs.h
 *	  JSON cost estimation functions.
 *
 *
 * Portions Copyright (c) 2016, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *    src/include/utils/json_selfuncs.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef JSON_SELFUNCS_H_
#define JSON_SELFUNCS_H 1

#include "postgres.h"
#include "access/htup.h"
#include "utils/jsonb.h"
#include "utils/lsyscache.h"
#include "utils/selfuncs.h"

typedef struct JsonStatData
{
	AttStatsSlot	attslot;
	HeapTuple		statsTuple;
	RelOptInfo	   *rel;
	Datum		   *values;
	int				nvalues;
	float4			nullfrac;
	const char	   *prefix;
	int				prefixlen;
	bool			acl_ok;
} JsonStatData, *JsonStats;

typedef enum
{
	JsonPathStatsValues,
	JsonPathStatsLength,
	JsonPathStatsArrayLength,
} JsonPathStatsType;

typedef struct JsonPathStatsData
{
	Datum			   *datum;
	JsonStats		   	data;
	char			   *path;
	int					pathlen;
	JsonPathStatsType	type;
} JsonPathStatsData, *JsonPathStats;

typedef enum JsonStatType
{
	JsonStatJsonb,
	JsonStatJsonbWithoutSubpaths,
	JsonStatText,
	JsonStatString,
	JsonStatNumeric,
	JsonStatFreq,
} JsonStatType;

extern bool jsonStatsInit(JsonStats stats, const VariableStatData *vardata);
extern void jsonStatsRelease(JsonStats data);

extern JsonPathStats jsonStatsGetPathStatsStr(JsonStats stats,
												const char *path, int pathlen);

extern JsonPathStats jsonPathStatsGetSubpath(JsonPathStats stats,
										const char *subpath, int subpathlen);

extern bool jsonPathStatsGetNextKeyStats(JsonPathStats stats,
										JsonPathStats *keystats, bool keysOnly);

extern JsonPathStats jsonPathStatsGetLengthStats(JsonPathStats pstats);

extern float4 jsonPathStatsGetFreq(JsonPathStats pstats, float4 defaultfreq);

extern float4 jsonPathStatsGetTypeFreq(JsonPathStats pstats,
									JsonbValueType type, float4 defaultfreq);

extern float4 jsonPathStatsGetAvgArraySize(JsonPathStats pstats);

extern Selectivity jsonPathStatsGetArrayIndexSelectivity(JsonPathStats pstats,
														 int index);

extern Selectivity jsonSelectivity(JsonPathStats stats, Datum scalar, Oid oper);


extern bool jsonAnalyzeBuildSubPathsData(Datum *pathsDatums,
										 int npaths, int index,
										 const char	*path, int pathlen,
										 bool includeSubpaths, float4 nullfrac,
										 Datum *pvals, Datum *pnums);

extern Datum jsonb_typanalyze(PG_FUNCTION_ARGS);
extern Datum jsonb_stats(PG_FUNCTION_ARGS);
extern Datum jsonb_sel(PG_FUNCTION_ARGS);

#endif /* JSON_SELFUNCS_H */
