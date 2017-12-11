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

/* Convert TSMapElement structure into JSONB */
extern Jsonb *TSMapToJsonb(TSMapElement *config);

/* Extract TSMapElement from JSONB formated data */
extern TSMapElement * JsonbToTSMap(Jsonb *json);
/* Replace all occurances of oldDict by newDict */
extern void TSMapReplaceDictionary(TSMapElement *config, Oid oldDict, Oid newDict);

/* Move rule list into specified memory context */
extern TSMapElement * TSMapMoveToMemoryContext(TSMapElement *config, MemoryContext context);
/* Free all nodes of the rule list */
extern void TSMapElementFree(TSMapElement *element);

/* Print map in human-readable format */
extern void TSMapPrintElement(TSMapElement *config, StringInfo result);

/* Return all dictionaries used in config */
extern Oid *TSMapGetDictionaries(TSMapElement *config);

#endif							/* _PG_TS_CONFIGMAP_H_ */
