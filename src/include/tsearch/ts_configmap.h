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

/* Convert TSMapRuleList structure into JSONB */
extern Jsonb *TSMapToJsonb(TSMapRuleList *rules);

/* Extract TSMapRuleList from JSONB formated data */
extern TSMapRuleList * JsonbToTSMap(Jsonb *json);
/* Replace all occurances of oldDict by newDict */
extern void TSMapReplaceDictionary(TSMapRuleList *rules, Oid oldDict, Oid newDict);

/* Return list of all dictionries in rule list in order they are defined in the lsit as array of Oids */
extern Oid *TSMapGetDictionariesList(TSMapRuleList *rules);

/* Return list of all dictionries in rule list in order they are defined in the list as ListDictionary structure */
extern ListDictionary *TSMapGetListDictionary(TSMapRuleList *rules);

/* Move rule list into specified memory context */
extern TSMapRuleList * TSMapMoveToMemoryContext(TSMapRuleList *rules, MemoryContext context);
/* Free all nodes of the rule list */
extern void TSMapFree(TSMapRuleList *rules);

/* Print rule in human-readable format */
extern void TSMapPrintRule(TSMapRule *rule, StringInfo result, int depth);

/* Print rule list in human-readable format */
extern void TSMapPrintRuleList(TSMapRuleList *rules, StringInfo result, int depth);

#endif							/* _PG_TS_CONFIGMAP_H_ */
