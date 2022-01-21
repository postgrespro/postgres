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

#define JSON_PATH_ROOT "$"
#define JSON_PATH_ROOT_LEN 1

#define JSON_PATH_ROOT_ARRAY "$[*]"
#define JSON_PATH_ROOT_ARRAY_LEN 4

typedef enum
{
	JsonPathStatsValues,
	JsonPathStatsLength,
	JsonPathStatsArrayLength,
} JsonPathStatsType;

typedef struct JsonStatData JsonStatData, *JsonStats;

/* Per-path JSON stats */
typedef struct JsonPathStatsData
{
	JsonStats	data;			/* pointer to per-column control structure */
	Datum	   *datum;			/* pointer to JSONB datum with stats data */
	const char *path;			/* path string, points directly to JSONB data */
	int			pathlen;		/* path length */
	JsonPathStatsType type;		/* type of stats (values, lengths etc.) */
} JsonPathStatsData, *JsonPathStats;

/* Per-column JSON stats */
struct JsonStatData
{
	HeapTuple	statsTuple;		/* original pg_statistic tuple */
	AttStatsSlot attslot;		/* data extracted from STATISTIC_KIND_JSON
								 * slot of statsTuple */
	RelOptInfo *rel;			/* Relation, or NULL if not identifiable */
	Datum	   *pathdatums;		/* path JSONB datums */
	JsonPathStatsData *paths;	/* cached paths */
	int			npaths;			/* number of paths */
	float4		nullfrac;		/* NULL fraction */
	const char *prefix;			/* global path prefix which needs to be used
								 * for searching in pathdatums */
	int			prefixlen;		/* path prefix length */
	bool		acl_ok;			/* ACL check is Ok */
};

typedef enum JsonStatType
{
	JsonStatJsonb,
	JsonStatJsonbWithoutSubpaths,
	JsonStatText,
	JsonStatFloat4,
	JsonStatString,
	JsonStatNumeric,
	JsonStatFreq,
} JsonStatType;

extern bool jsonStatsInit(JsonStats stats, const VariableStatData *vardata);
extern void jsonStatsRelease(JsonStats data);

extern JsonPathStats jsonStatsGetPathByStr(JsonStats stats,
										   const char *path, int pathlen);

extern JsonPathStats jsonPathStatsGetSubpath(JsonPathStats stats,
											 const char *subpath);

extern bool jsonPathStatsGetNextSubpathStats(JsonPathStats stats,
											 JsonPathStats *keystats,
											 bool keysOnly);

extern JsonPathStats jsonPathStatsGetLengthStats(JsonPathStats pstats);

extern float4 jsonPathStatsGetFreq(JsonPathStats pstats, float4 defaultfreq);

extern float4 jsonPathStatsGetTypeFreq(JsonPathStats pstats,
									JsonbValueType type, float4 defaultfreq);

extern float4 jsonPathStatsGetAvgArraySize(JsonPathStats pstats);

extern Selectivity jsonPathStatsGetArrayIndexSelectivity(JsonPathStats pstats,
														 int index);

extern Selectivity jsonSelectivity(JsonPathStats stats, Datum scalar, Oid oper);

extern void jsonPathAppendEntry(StringInfo path, const char *entry);

extern bool jsonAnalyzeBuildSubPathsData(Datum *pathsDatums,
										 int npaths, int index,
										 const char	*path, int pathlen,
										 bool includeSubpaths, float4 nullfrac,
										 Datum *pvals, Datum *pnums);

#endif /* JSON_SELFUNCS_H */
