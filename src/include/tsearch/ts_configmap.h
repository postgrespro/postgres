/*-------------------------------------------------------------------------
 *
 * ts_configmap.h
 *	  internal represtation of text search configuration and utilities for it
 *
 * Copyright (c) 1998-2017, PostgreSQL Global Development Group
 *
 * src/include/tsearch/ts_utils.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef _PG_TS_CONFIGMAP_H_
#define _PG_TS_CONFIGMAP_H_

#include "utils/jsonb.h"
#include "catalog/pg_ts_config_map.h"

/*
 * Configuration storage functions
 * Provide interface to convert ts_configuration into JSONB and vice versa
 */

extern Jsonb *TSMapToJsonb(TSMapRuleList *rules);
extern TSMapRuleList *JsonbToTSMap(Jsonb *json);
extern void TSMapReplaceDictionary(TSMapRuleList *rules, Oid oldDict, Oid newDict);
extern Oid *TSMapGetDictionariesList(TSMapRuleList *rules);
extern ListDictionary *TSMapGetListDictionary(TSMapRuleList *rules);
extern TSMapRuleList *TSMapMoveToMemoryContext(TSMapRuleList *rules, MemoryContext context);
extern void TSMapFree(TSMapRuleList *rules);
extern void TSMapPrintRule(TSMapRule *rule, StringInfo result, int depth);
extern void TSMapPrintRuleList(TSMapRuleList *rules, StringInfo result, int depth);

#endif   /* _PG_TS_CONFIGMAP_H_ */
